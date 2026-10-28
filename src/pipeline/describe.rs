//! Per-repo signals and the buzz score, computed once for every candidate.

use std::collections::HashMap;

use chrono::{DateTime, Duration, NaiveDate, Utc};

use super::Warnings;
use crate::model::RepoInfo;
use crate::signals::buzz;
use crate::signals::inspect::{self, Health, Inspection, StarCheck};
use crate::sources::github::{GitHub, Repo};
use crate::sources::hn::HnBuzz;
use crate::store::cache::Cache;
use crate::store::history::History;

/// Health (releases, issues, commits) is reused for this long (scheduled runs are 12h
/// apart, so they refresh it).
const INSPECT_TTL_HOURS: i64 = 11;
/// A stargazer sample costs a request per repo plus one lookup per stargazer, and the
/// share of throwaway accounts changes slowly, so it is reused for longer.
const STARS_TTL_DAYS: i64 = 3;
const INSPECT_CACHE: &str = "inspect-cache.json";

/// What the per-repo signals are computed against.
pub(super) struct Context<'a> {
    pub(super) trending: &'a HashMap<String, u64>,
    pub(super) hn: &'a HashMap<String, HnBuzz>,
    /// The previous run's date and star counts (by full name)
    pub(super) prev: Option<(NaiveDate, &'a HashMap<String, u64>)>,
    pub(super) history: &'a History,
    pub(super) now: DateTime<Utc>,
}

fn stars_per_day(repo: &Repo, now: DateTime<Utc>) -> f64 {
    let created = DateTime::parse_from_rfc3339(&repo.created_at).map(|d| d.with_timezone(&Utc)).unwrap_or(now);
    // At least one day, so brand-new repos don't divide by ~0.
    let days = ((now - created).num_seconds() as f64 / 86_400.0).max(1.0);
    repo.stargazers_count as f64 / days
}

/// Released on or after the previous run's day (history keeps days, not times).
fn released_since(health: Option<&Health>, prev: Option<NaiveDate>) -> bool {
    matches!((health.and_then(|h| h.release.as_ref()), prev), (Some((_, at)), Some(day)) if at.date_naive() >= day)
}

/// Per-repo signals and buzz score, keyed like `repos`.
pub(super) fn describe(
    gh: &GitHub,
    repos: HashMap<String, Repo>,
    ctx: &Context,
    warnings: &Warnings,
) -> HashMap<String, RepoInfo> {
    let mut inspected = inspections(gh, &repos, ctx.now, warnings);
    let trend = ctx.history.trend(ctx.now.date_naive());
    let prev_stars = ctx.prev.map(|(_, s)| s);
    repos
        .into_iter()
        .map(|(key, repo)| {
            let ins = inspected.remove(&key).unwrap_or_default();
            let suspicious_stars = ins.stars.as_ref().is_some_and(StarCheck::suspicious);
            let mut info = RepoInfo {
                stars_per_day: stars_per_day(&repo, ctx.now),
                stars_delta: prev_stars
                    .and_then(|p| p.get(&repo.full_name))
                    .map(|&old| repo.stargazers_count as i64 - old as i64),
                is_new: prev_stars.is_some_and(|p| !p.contains_key(&repo.full_name)),
                trending_today: ctx.trending.get(&key).copied(),
                hn: ctx.hn.get(&key).cloned(),
                low_engagement: buzz::low_engagement(&repo),
                star_check: ins.stars,
                suspicious_stars,
                new_release: released_since(ins.health.as_ref(), ctx.prev.map(|(d, _)| d)),
                health: ins.health,
                trend: trend(&repo.full_name),
                buzz: 0.0,
                repo,
            };
            info.buzz = buzz::score(&buzz::Signals {
                trending_today: info.trending_today,
                hn_points: info.hn.as_ref().map(|h| h.points),
                stars_delta: info.stars_delta,
                stars_per_day: info.stars_per_day,
                low_engagement: info.low_engagement,
                suspicious_stars,
            });
            (key, info)
        })
        .collect()
}

/// Health and star checks (token required), from the cache where still fresh.
fn inspections(
    gh: &GitHub,
    repos: &HashMap<String, Repo>,
    now: DateTime<Utc>,
    warnings: &Warnings,
) -> HashMap<String, Inspection> {
    if !gh.is_authenticated() {
        return HashMap::new();
    }
    let mut cache: Cache<Inspection> = Cache::load(INSPECT_CACHE, Duration::days(STARS_TTL_DAYS), now);
    let fresh = Duration::hours(INSPECT_TTL_HOURS);
    // A stale entry still lends its star check while that is under `STARS_TTL_DAYS` old.
    let sampled =
        |i: &&Inspection| i.stars.is_some() && i.stars_at.is_some_and(|at| now - at < Duration::days(STARS_TTL_DAYS));
    let todo: Vec<(&Repo, Option<&Inspection>)> = repos
        .iter()
        .filter(|(k, _)| cache.get_within(k, fresh, now).is_none())
        .map(|(k, r)| (r, cache.get(k).filter(sampled)))
        .collect();
    let to_sample = todo
        .iter()
        .filter(|(r, earlier)| earlier.is_none() && r.stargazers_count >= inspect::STAR_CHECK_MIN_STARS)
        .count();
    eprintln!(
        "→ Checking health of {} repos ({} cached) and recent stargazers of {to_sample}…",
        todo.len(),
        repos.len() - todo.len()
    );
    let (found, failed) = inspect::run(gh, &todo, now);
    if failed > 0 {
        warnings.add(format!("Health/star check failed for {failed} repos."));
    }
    for (key, ins) in found {
        cache.insert(key, ins, now);
    }
    if let Err(e) = cache.save() {
        eprintln!("⚠  Could not save cache {}: {e}", cache.path().display());
    }
    repos.keys().filter_map(|k| Some((k.clone(), cache.get(k)?.clone()))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_release_is_on_or_after_the_previous_run() {
        let at = |d: &str| DateTime::parse_from_rfc3339(d).unwrap().with_timezone(&Utc);
        let health = Health {
            release: Some(("v2".into(), at("2026-10-24T09:00:00Z"))),
            executables: vec![],
            commits: None,
            open_issues: 0,
            closed_issues: 0,
        };
        let day = |d: &str| NaiveDate::parse_from_str(d, "%Y-%m-%d").ok();
        assert!(released_since(Some(&health), day("2026-10-24")));
        assert!(!released_since(Some(&health), day("2026-10-25")));
        assert!(!released_since(Some(&health), None));
        assert!(!released_since(None, day("2026-10-01")));
    }
}
