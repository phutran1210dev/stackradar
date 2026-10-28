//! Candidate repos: topic searches, GitHub Trending, Hacker News and watched repos,
//! fetched concurrently.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Duration, Utc};

use super::Warnings;
use crate::cli::Args;
use crate::sources::github::{GitHub, Repo};
use crate::sources::hn::{HackerNews, HnBuzz};
use crate::store::config::Config;
use crate::util::par_map;

/// github.com/trending pages scanned ("" = all languages).
const TRENDING_LANGUAGES: &[&str] = &["", "typescript", "javascript", "python"];
/// Only HN stories this recent count as current buzz.
const HN_WINDOW_DAYS: i64 = 30;
/// Topic searches in flight at once: more trips GitHub's secondary rate limit.
const SEARCH_WORKERS: usize = 8;

/// Repos found for the configured categories.
#[derive(Default)]
pub(super) struct Candidates {
    /// Repo key → repo, for every repo in at least one category
    pub(super) repos: HashMap<String, Repo>,
    /// Per category: repo key → matched topics
    pub(super) by_cat: Vec<HashMap<String, Vec<String>>>,
    /// Hidden by the exclude list
    pub(super) excluded: HashSet<String>,
    /// Keys of the watched repos that could be fetched, in config order
    pub(super) watched: Vec<String>,
}

/// Everything fetched for one run.
pub(super) struct Gathered {
    pub(super) candidates: Candidates,
    /// Repo key → stars today on github.com/trending
    pub(super) trending: HashMap<String, u64>,
    /// Repo key → Hacker News buzz
    pub(super) hn: HashMap<String, HnBuzz>,
}

impl Candidates {
    fn add(&mut self, config: &Config, cat: usize, topic: &str, repo: &Repo) {
        if config.is_excluded(&repo.full_name) {
            self.excluded.insert(repo.key());
            return;
        }
        let key = repo.key();
        let matched = self.by_cat[cat].entry(key.clone()).or_default();
        if !matched.iter().any(|t| t == topic) {
            matched.push(topic.to_string());
        }
        self.repos.entry(key).or_insert_with(|| repo.clone());
    }
}

/// Topic searches, GitHub Trending, Hacker News and watched repos, all fetched
/// concurrently (config caps topics under the 30/min search limit). Fails only if every
/// search failed.
pub(super) fn gather(
    gh: &GitHub,
    config: &Config,
    args: &Args,
    since: &str,
    now: DateTime<Utc>,
    warnings: &Warnings,
) -> Result<Gathered, String> {
    let jobs: Vec<(usize, &str)> =
        config.categories.iter().enumerate().flat_map(|(i, c)| c.topics.iter().map(move |t| (i, t.as_str()))).collect();
    eprintln!("→ Searching {} topics since {since}, reading GitHub Trending and Hacker News…", jobs.len());
    let hn_since = (now - Duration::days(HN_WINDOW_DAYS)).timestamp();
    let (searched, pages, hn, watched) = std::thread::scope(|s| {
        let pages = s.spawn(|| par_map(TRENDING_LANGUAGES, TRENDING_LANGUAGES.len(), |l| gh.trending(l)));
        let hn = s.spawn(|| HackerNews::new().github_stories(hn_since));
        let watched = s.spawn(|| par_map(&config.watch, 8, |name| gh.repo(name)));
        let searched =
            par_map(&jobs, SEARCH_WORKERS, |&(_, topic)| gh.search_topic(topic, since, args.min_stars, args.limit));
        (
            searched,
            pages.join().expect("trending thread"),
            hn.join().expect("HN thread"),
            watched.join().expect("watch thread"),
        )
    });

    let failures = searched.iter().filter(|r| r.is_err()).count();
    for (r, (_, topic)) in searched.iter().zip(&jobs) {
        if let Err(e) = r {
            eprintln!("  ✗ topic:{topic} — {e}");
        }
    }
    if failures == jobs.len() {
        return Err("All GitHub searches failed.".into());
    }
    if failures > 0 {
        warnings.add(format!("{failures}/{} topic searches failed; categories are partial.", jobs.len()));
    }
    let hn = hn.unwrap_or_else(|e| {
        warnings.add(format!("Hacker News unavailable ({e}); the HN signal is missing."));
        HashMap::new()
    });

    let mut trending: HashMap<String, u64> = HashMap::new();
    for (page, lang) in pages.into_iter().zip(TRENDING_LANGUAGES) {
        match page {
            Ok(rows) => trending.extend(rows.into_iter().map(|(n, t)| (n.to_ascii_lowercase(), t))),
            Err(e) => warnings
                .add(format!("GitHub Trending ({}) unavailable: {e}", if lang.is_empty() { "all" } else { lang })),
        }
    }

    let mut c = Candidates { by_cat: vec![HashMap::new(); config.categories.len()], ..Default::default() };
    for (result, &(cat, topic)) in searched.into_iter().zip(&jobs) {
        for repo in result.unwrap_or_default() {
            c.add(config, cat, topic, &repo);
        }
    }
    // Watched repos are shown even if excluded: watching is the more explicit choice.
    for (result, name) in watched.into_iter().zip(&config.watch) {
        match result {
            Ok(repo) => {
                c.watched.push(repo.key());
                c.repos.entry(repo.key()).or_insert(repo);
            }
            Err(e) => warnings.add(format!("Watched repo {name} unavailable: {e}")),
        }
    }

    // Trending repos the searches didn't return (often older, established ones): fetch
    // them for their topics. Every trending repo is filed under each matching category.
    let missing: Vec<&String> = trending.keys().filter(|k| !c.repos.contains_key(*k)).collect();
    let fetched: Vec<Repo> = par_map(&missing, 8, |k| gh.repo(k)).into_iter().flatten().collect();
    let trending_repos: Vec<Repo> = trending.keys().filter_map(|k| c.repos.get(k).cloned()).chain(fetched).collect();
    for repo in &trending_repos {
        for (i, cat) in config.categories.iter().enumerate() {
            for topic in cat.topics.iter().filter(|t| repo.topics.contains(t)) {
                c.add(config, i, topic, repo);
            }
        }
    }
    Ok(Gathered { candidates: c, trending, hn })
}
