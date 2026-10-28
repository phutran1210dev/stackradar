//! Whether a dependency is still maintained: its GitHub repo is archived, or has had no
//! push for `STALE_YEARS`. No advisory says so, but no fix will come for the next one.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// No push for this long counts as abandoned.
pub const STALE_YEARS: i64 = 2;

/// What GitHub says about a dependency's repo.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepoState {
    /// `owner/name`
    pub repo: String,
    pub archived: bool,
    /// RFC 3339
    pub pushed_at: String,
}

impl RepoState {
    pub fn is_unmaintained(&self, now: DateTime<Utc>) -> bool {
        let pushed = DateTime::parse_from_rfc3339(&self.pushed_at).map(|d| d.with_timezone(&Utc));
        self.archived || pushed.is_ok_and(|p| now - p > Duration::days(365 * STALE_YEARS))
    }
}

/// GraphQL for the state of `repos` (`owner/name`, plain names only), aliased `r0`, `r1`, ….
pub fn query(repos: &[&str]) -> String {
    let fields: String = repos
        .iter()
        .enumerate()
        .filter_map(|(i, r)| {
            let (owner, name) = r.split_once('/')?;
            Some(format!(
                "r{i}: repository(owner: \"{owner}\", name: \"{name}\") {{ nameWithOwner isArchived pushedAt }}\n"
            ))
        })
        .collect();
    format!("query {{\n{fields}}}")
}

/// The reply to `query`: each repo's state, None if it no longer exists.
pub fn parse(repos: &[&str], data: &std::collections::HashMap<String, serde_json::Value>) -> Vec<Option<RepoState>> {
    (0..repos.len())
        .map(|i| {
            let r = data.get(&format!("r{i}"))?;
            Some(RepoState {
                repo: r.get("nameWithOwner")?.as_str()?.to_string(),
                archived: r.get("isArchived")?.as_bool()?,
                pushed_at: r.get("pushedAt")?.as_str()?.to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_archived_and_quiet_repos() {
        let now = DateTime::parse_from_rfc3339("2026-10-26T00:00:00Z").unwrap().with_timezone(&Utc);
        let state = |archived, pushed: &str| RepoState { repo: "a/b".into(), archived, pushed_at: pushed.into() };
        assert!(state(true, "2026-10-01T00:00:00Z").is_unmaintained(now));
        assert!(state(false, "2024-01-01T00:00:00Z").is_unmaintained(now));
        assert!(!state(false, "2025-06-01T00:00:00Z").is_unmaintained(now));
        let q = query(&["expressjs/express", "a/b"]);
        assert!(q.contains("r1: repository(owner: \"a\", name: \"b\")"), "{q}");
        let data = serde_json::from_str(
            r#"{"r0":{"nameWithOwner":"expressjs/express","isArchived":false,"pushedAt":"2026-10-01T00:00:00Z"},"r1":null}"#,
        )
        .unwrap();
        assert_eq!(parse(&["expressjs/express", "a/b"], &data)[1], None);
    }
}
