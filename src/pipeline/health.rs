//! The maintenance step: which of your projects' direct dependencies live in an archived
//! or abandoned GitHub repo. Registries say where each package's source is; one GraphQL
//! query per batch of repos says how it's doing. Both are cached for a few days.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};

use super::Warnings;
use crate::deps::{Ecosystem, Project};
use crate::model::Unmaintained;
use crate::signals::maintenance::{self, RepoState};
use crate::sources::github::GitHub;
use crate::sources::{http, registry};
use crate::store::cache::Cache;
use crate::util::par_map;

const CACHE: &str = "deps-health-cache.json";
const TTL_DAYS: i64 = 3;
/// Repos per GraphQL query.
const BATCH: usize = 50;

/// Direct dependencies of `projects` whose repo is archived or quiet. Needs a token.
pub(super) fn unmaintained(
    gh: &GitHub,
    projects: &[Project],
    now: DateTime<Utc>,
    warnings: &Warnings,
) -> Vec<Unmaintained> {
    if !gh.is_authenticated() {
        return Vec::new();
    }
    // (ecosystem, package) → projects using it directly
    let mut packages: BTreeMap<(Ecosystem, &str), BTreeSet<String>> = BTreeMap::new();
    for p in projects {
        for d in p.deps.iter().filter(|d| d.is_direct()) {
            packages.entry((p.ecosystem, &d.name)).or_default().insert(p.label());
        }
    }
    let key = |eco: Ecosystem, name: &str| format!("{}:{name}", eco.advisory_name());
    let mut cache: Cache<Option<RepoState>> = Cache::load(CACHE, Duration::days(TTL_DAYS), now);
    let todo: Vec<(Ecosystem, &str)> =
        packages.keys().copied().filter(|&(e, n)| cache.get(&key(e, n)).is_none()).collect();
    if !todo.is_empty() {
        eprintln!(
            "→ Checking whether {} dependencies are still maintained ({} cached)…",
            todo.len(),
            packages.len() - todo.len()
        );
        let failed = check(gh, &todo, &mut cache, now, |e, n| key(e, n));
        if failed > 0 {
            warnings.add(format!("Could not check whether {failed} dependencies are still maintained."));
        }
        if let Err(e) = cache.save() {
            eprintln!("⚠  Could not save cache {}: {e}", cache.path().display());
        }
    }
    let mut out: Vec<Unmaintained> = packages
        .into_iter()
        .filter_map(|((ecosystem, package), projects)| {
            let state = cache.get(&key(ecosystem, package))?.as_ref().filter(|s| s.is_unmaintained(now))?;
            Some(Unmaintained {
                ecosystem,
                package: package.to_string(),
                repo: state.repo.clone(),
                archived: state.archived,
                pushed: state.pushed_at.chars().take(10).collect(),
                projects: projects.into_iter().collect(),
            })
        })
        .collect();
    out.sort_by(|a, b| b.archived.cmp(&a.archived).then_with(|| a.pushed.cmp(&b.pushed)));
    out
}

/// Look `todo` up and cache what's found (None: no GitHub repo); the number that failed,
/// which aren't cached so the next run retries them.
fn check(
    gh: &GitHub,
    todo: &[(Ecosystem, &str)],
    cache: &mut Cache<Option<RepoState>>,
    now: DateTime<Utc>,
    key: impl Fn(Ecosystem, &str) -> String,
) -> usize {
    let client = http::client();
    let found = par_map(todo, 8, |&(eco, name)| registry::source_urls(&client, eco, name));
    let mut failed = 0;
    let mut by_repo: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (&(eco, name), urls) in todo.iter().zip(found) {
        match urls.map(|u| u.and_then(|u| registry::github_repo(&u))) {
            Ok(Some(repo)) => by_repo.entry(repo).or_default().push(key(eco, name)),
            Ok(None) => cache.insert(key(eco, name), None, now),
            Err(_) => failed += 1,
        }
    }
    let repos: Vec<&str> = by_repo.keys().map(String::as_str).collect();
    let batches: Vec<&[&str]> = repos.chunks(BATCH).collect();
    let states = par_map(&batches, 4, |b| gh.graphql(&maintenance::query(b)).map(|d| maintenance::parse(b, &d)));
    for (batch, states) in batches.iter().zip(states) {
        let Ok(states) = states else {
            failed += batch.iter().map(|r| by_repo[*r].len()).sum::<usize>();
            continue;
        };
        for (repo, state) in batch.iter().zip(states) {
            for k in &by_repo[*repo] {
                cache.insert(k.clone(), state.clone(), now);
            }
        }
    }
    failed
}
