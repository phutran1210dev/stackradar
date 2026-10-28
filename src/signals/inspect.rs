//! Deeper checks per candidate repo, fetched with batched GraphQL queries (token needed):
//! - health: latest release (and executables it ships), commits, issues;
//! - stars: are the recent stargazers mostly throwaway accounts (bought stars)?

use std::collections::HashMap;
use std::fmt::Write;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::sources::github::{GitHub, Repo};
use crate::util::par_map;

/// Below this, buying stars is rare and the sample would be tiny anyway.
pub const STAR_CHECK_MIN_STARS: u64 = 100;
/// Recent stargazers sampled per repo.
const SAMPLE: usize = 30;
/// Fewer resolved stargazers than this is too little to judge.
const MIN_SAMPLE: usize = 15;
/// Repos per GraphQL query (each brings up to SAMPLE user lookups, which are cheap).
const REPOS_PER_QUERY: usize = 5;
/// Release assets that run directly on a machine — the usual malware payloads.
const EXECUTABLE_EXTS: &[&str] = &[
    ".exe",
    ".msi",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".dmg",
    ".pkg",
    ".apk",
    ".jar",
    ".appimage",
    ".deb",
    ".rpm",
];

// `releases { totalCount }` is avoided on purpose: it makes a query ~4x slower.
const REPO_FIELDS: &str = "latestRelease { tagName publishedAt releaseAssets(first: 50) { nodes { name } } } \
    openIssues: issues(states: OPEN) { totalCount } closedIssues: issues(states: CLOSED) { totalCount } \
    defaultBranchRef { target { ... on Commit { history { totalCount } } } }";
const USER_FIELDS: &str = "createdAt followers { totalCount }";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StarCheck {
    /// Recent stargazers looked at
    pub sampled: usize,
    /// …of which look like throwaway accounts
    pub ghosts: usize,
}

impl StarCheck {
    /// At least half of the recent stars come from throwaway accounts. Organic repos
    /// measured 0–33%; repos with bought stars 50%+.
    pub fn suspicious(&self) -> bool {
        self.sampled >= MIN_SAMPLE && self.ghosts * 2 >= self.sampled
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Health {
    /// Tag and date of the latest release
    pub release: Option<(String, DateTime<Utc>)>,
    /// Executable assets in the latest release
    pub executables: Vec<String>,
    pub commits: Option<u64>,
    pub open_issues: u64,
    pub closed_issues: u64,
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Inspection {
    pub health: Option<Health>,
    pub stars: Option<StarCheck>,
    /// When the stargazers in `stars` were sampled (missing in older caches)
    #[serde(default)]
    pub stars_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
struct Count {
    #[serde(rename = "totalCount")]
    total: u64,
}

#[derive(Deserialize)]
struct Nodes<T> {
    nodes: Vec<T>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RepoNode {
    latest_release: Option<Release>,
    open_issues: Count,
    closed_issues: Count,
    default_branch_ref: Option<BranchRef>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Release {
    tag_name: String,
    published_at: Option<DateTime<Utc>>,
    release_assets: Nodes<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
}

#[derive(Deserialize)]
struct BranchRef {
    target: Option<Target>,
}

#[derive(Deserialize)]
struct Target {
    history: Option<Count>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct User {
    created_at: DateTime<Utc>,
    followers: Count,
}

/// A brand-new account (under a year) that nobody follows: cheap to mass-create, and
/// what star-selling services use. Real newcomers exist, so only a majority counts.
fn is_ghost(user: &User, now: DateTime<Utc>) -> bool {
    user.followers.total <= 1 && now - user.created_at < Duration::days(365)
}

fn executables(release: &Release) -> Vec<String> {
    release
        .release_assets
        .nodes
        .iter()
        .map(|a| a.name.clone())
        .filter(|n| EXECUTABLE_EXTS.iter().any(|ext| n.to_ascii_lowercase().ends_with(ext)))
        .collect()
}

/// GraphQL string literal (same escaping as JSON).
fn lit(s: &str) -> String {
    serde_json::to_string(s).expect("string serializes")
}

/// Inspect `repos`, keyed by `Repo::key`. A repo given with an earlier inspection keeps
/// its star check and only its health is fetched. Repos whose query failed are left out; the returned count
/// says how many.
pub fn run(
    gh: &GitHub,
    repos: &[(&Repo, Option<&Inspection>)],
    now: DateTime<Utc>,
) -> (HashMap<String, Inspection>, usize) {
    let (checked, rest): (Vec<_>, Vec<_>) =
        repos.iter().partition(|(r, known)| known.is_none() && r.stargazers_count >= STAR_CHECK_MIN_STARS);
    let checked: Vec<&Repo> = checked.into_iter().map(|&(r, _)| r).collect();
    // The rest need no stargazer sample, so their queries run while the others' event
    // feeds (one REST call each) are fetched.
    let ((mut out, failed_rest), (more, failed)) = std::thread::scope(|s| {
        let rest = s.spawn(|| query_all(gh, rest.iter().map(|&&(r, _)| (r, Vec::new())).collect(), now));
        let samples = par_map(&checked, 24, |r| gh.recent_stargazers(&r.full_name, SAMPLE).unwrap_or_default());
        let checked = query_all(gh, checked.into_iter().zip(samples).collect(), now);
        (rest.join().expect("inspect thread panicked"), checked)
    });
    for (repo, earlier) in repos {
        if let (Some(earlier), Some(ins)) = (earlier, out.get_mut(&repo.key())) {
            (ins.stars, ins.stars_at) = (earlier.stars.clone(), earlier.stars_at);
        }
    }
    out.extend(more);
    (out, failed + failed_rest)
}

fn query_all(gh: &GitHub, jobs: Vec<(&Repo, Vec<String>)>, now: DateTime<Utc>) -> (HashMap<String, Inspection>, usize) {
    let batches: Vec<&[(&Repo, Vec<String>)]> = jobs.chunks(REPOS_PER_QUERY).collect();
    let mut out = HashMap::new();
    let mut failed = 0;
    for (batch, result) in batches.iter().zip(par_map(&batches, 10, |b| gh.graphql(&query(b)))) {
        match result {
            Ok(data) => out.extend(parse(batch, data, now)),
            Err(_) => failed += batch.len(),
        }
    }
    (out, failed)
}

fn query(batch: &[(&Repo, Vec<String>)]) -> String {
    let mut q = String::from("{");
    for (i, (repo, logins)) in batch.iter().enumerate() {
        let (owner, name) = repo.full_name.split_once('/').unwrap_or_default();
        let _ = write!(q, " r{i}: repository(owner: {}, name: {}) {{ {REPO_FIELDS} }}", lit(owner), lit(name));
        for (j, login) in logins.iter().enumerate() {
            let _ = write!(q, " r{i}u{j}: user(login: {}) {{ {USER_FIELDS} }}", lit(login));
        }
    }
    q.push_str(" }");
    q
}

fn parse(
    batch: &[(&Repo, Vec<String>)],
    mut data: HashMap<String, serde_json::Value>,
    now: DateTime<Utc>,
) -> Vec<(String, Inspection)> {
    let mut take = |alias: String| data.remove(&alias).filter(|v| !v.is_null());
    batch
        .iter()
        .enumerate()
        .map(|(i, (repo, logins))| {
            let health =
                take(format!("r{i}")).and_then(|v| serde_json::from_value::<RepoNode>(v).ok()).map(|n| Health {
                    executables: n.latest_release.as_ref().map(executables).unwrap_or_default(),
                    release: n.latest_release.and_then(|r| Some((r.tag_name, r.published_at?))),
                    commits: n.default_branch_ref.and_then(|b| b.target?.history).map(|c| c.total),
                    open_issues: n.open_issues.total,
                    closed_issues: n.closed_issues.total,
                });
            let users: Vec<User> =
                (0..logins.len()).filter_map(|j| serde_json::from_value(take(format!("r{i}u{j}"))?).ok()).collect();
            let stars = (!logins.is_empty())
                .then(|| StarCheck { sampled: users.len(), ghosts: users.iter().filter(|u| is_ghost(u, now)).count() });
            let stars_at = stars.as_ref().map(|_| now);
            (repo.key(), Inspection { health, stars, stars_at })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suspicious_needs_a_sample_and_a_majority() {
        assert!(StarCheck { sampled: 30, ghosts: 16 }.suspicious());
        assert!(StarCheck { sampled: 20, ghosts: 10 }.suspicious());
        assert!(!StarCheck { sampled: 30, ghosts: 10 }.suspicious());
        assert!(!StarCheck { sampled: 6, ghosts: 6 }.suspicious());
    }

    #[test]
    fn ghost_is_new_and_unfollowed() {
        let now = Utc::now();
        let user = |days: i64, followers: u64| User {
            created_at: now - Duration::days(days),
            followers: Count { total: followers },
        };
        assert!(is_ghost(&user(10, 0), now));
        assert!(!is_ghost(&user(10, 5), now));
        assert!(!is_ghost(&user(800, 0), now));
    }

    #[test]
    fn finds_executable_assets() {
        let release = Release {
            tag_name: "v1".into(),
            published_at: None,
            release_assets: Nodes {
                nodes: ["Setup.EXE", "src.tar.gz", "app.dmg", "notes.txt"].map(|n| Asset { name: n.into() }).into(),
            },
        };
        assert_eq!(executables(&release), vec!["Setup.EXE", "app.dmg"]);
    }

    #[test]
    fn parses_partial_graphql_data() {
        let repo = Repo::test("A/b", 200, &[]);
        let batch = [(&repo, vec!["x".to_string(), "gone".to_string()])];
        let data = serde_json::from_value(serde_json::json!({
            "r0": { "latestRelease": { "tagName": "v2", "publishedAt": "2026-01-01T00:00:00Z", "releaseAssets": { "nodes": [] } },
                    "openIssues": { "totalCount": 1 }, "closedIssues": { "totalCount": 9 },
                    "defaultBranchRef": { "target": { "history": { "totalCount": 42 } } } },
            "r0u0": { "createdAt": "2020-01-01T00:00:00Z", "followers": { "totalCount": 3 } },
            "r0u1": null
        }))
        .unwrap();
        let out = parse(&batch, data, Utc::now());
        let (key, ins) = &out[0];
        assert_eq!(key, "a/b");
        assert_eq!(ins.stars, Some(StarCheck { sampled: 1, ghosts: 0 }));
        let h = ins.health.as_ref().unwrap();
        assert_eq!((h.release.as_ref().map(|r| r.0.as_str()), h.commits, h.closed_issues), (Some("v2"), Some(42), 9));
    }
}
