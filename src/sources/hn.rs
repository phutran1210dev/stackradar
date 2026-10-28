//! Hacker News discussion of repos, via the public Algolia HN search API.
//!
//! Instead of one search per repo, every story linking to github.com in the window is
//! fetched once (a few pages) and indexed by repo, so lookups are free afterwards.

use std::collections::{HashMap, HashSet};

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

use super::http;

/// Algolia's maximum page size, and the most hits one query can return.
const PAGE: usize = 1000;
/// Guard against a misbehaving API looping forever (~3k stories/month today).
const MAX_PAGES: usize = 20;

/// The best-scoring recent HN story linking to the repo (or a page inside it).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HnBuzz {
    pub points: u64,
    pub comments: u64,
    /// Number of matching stories in the window
    pub stories: usize,
    /// news.ycombinator.com discussion link of the best story
    pub url: String,
}

#[derive(Deserialize)]
struct Search {
    hits: Vec<Hit>,
}

#[derive(Deserialize)]
struct Hit {
    #[serde(rename = "objectID")]
    id: String,
    url: Option<String>,
    points: Option<u64>,
    num_comments: Option<u64>,
    created_at_i: i64,
}

pub struct HackerNews {
    client: Client,
}

impl HackerNews {
    pub fn new() -> Self {
        Self { client: http::client() }
    }

    /// HN buzz per repo (lowercase `owner/repo`) for stories submitted after `since_ts`.
    pub fn github_stories(&self, since_ts: i64) -> Result<HashMap<String, HnBuzz>, String> {
        let mut hits = Vec::new();
        let mut ids = HashSet::new();
        let mut until = i64::MAX;
        // Newest first; each page continues from the oldest story of the previous one
        // (inclusive, then de-duplicated, so stories sharing that second aren't lost).
        for _ in 0..MAX_PAGES {
            let filter = format!("created_at_i>{since_ts},created_at_i<={until}");
            let resp = self.client.get("https://hn.algolia.com/api/v1/search_by_date").query(&[
                ("query", "github.com"),
                ("restrictSearchableAttributes", "url"),
                ("tags", "story"),
                ("numericFilters", filter.as_str()),
                ("hitsPerPage", &PAGE.to_string()),
            ]);
            let page: Search = http::json(http::checked(http::send(resp)?)?)?;
            let full = page.hits.len() == PAGE;
            let before = ids.len();
            for hit in page.hits {
                until = until.min(hit.created_at_i);
                if ids.insert(hit.id.clone()) {
                    hits.push(hit);
                }
            }
            if !full || ids.len() == before {
                break;
            }
        }
        Ok(summarize(hits))
    }
}

/// Group stories by the repo they link to; keep the best story and the count.
fn summarize(hits: Vec<Hit>) -> HashMap<String, HnBuzz> {
    let mut out: HashMap<String, HnBuzz> = HashMap::new();
    for hit in hits {
        let Some(repo) = hit.url.as_deref().and_then(repo_of) else { continue };
        let points = hit.points.unwrap_or(0);
        let entry = out.entry(repo).or_insert(HnBuzz { points: 0, comments: 0, stories: 0, url: String::new() });
        entry.stories += 1;
        if entry.url.is_empty() || points > entry.points {
            entry.points = points;
            entry.comments = hit.num_comments.unwrap_or(0);
            entry.url = format!("https://news.ycombinator.com/item?id={}", hit.id);
        }
    }
    out
}

/// Lowercase `owner/repo` of a github.com/<owner>/<repo>[/...|?...|#...] URL.
fn repo_of(url: &str) -> Option<String> {
    let url = url.to_ascii_lowercase();
    let path = url.split_once("github.com/")?.1;
    let end = path.find(['?', '#']).unwrap_or(path.len());
    let mut parts = path[..end].split('/');
    let (owner, name) = (parts.next()?, parts.next()?.trim_end_matches(".git"));
    let valid = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    (valid(owner) && valid(name)).then(|| format!("{owner}/{name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(id: &str, url: &str, points: u64) -> Hit {
        Hit {
            id: id.into(),
            url: Some(url.into()),
            points: Some(points),
            num_comments: Some(points / 2),
            created_at_i: 0,
        }
    }

    #[test]
    fn extracts_repo_from_urls() {
        assert_eq!(repo_of("https://github.com/Vercel/Next.js").as_deref(), Some("vercel/next.js"));
        assert_eq!(repo_of("https://github.com/vercel/next.js/issues/1").as_deref(), Some("vercel/next.js"));
        assert_eq!(repo_of("https://github.com/vercel/next.js?tab=readme").as_deref(), Some("vercel/next.js"));
        assert_eq!(repo_of("https://github.com/a/b.git").as_deref(), Some("a/b"));
        assert_eq!(repo_of("https://github.com/vercel").as_deref(), None);
        assert_eq!(repo_of("https://example.com/"), None);
    }

    #[test]
    fn picks_best_story_per_repo() {
        let hits = vec![
            hit("1", "https://github.com/a/b", 10),
            hit("2", "https://github.com/a/b/discussions/3", 300),
            hit("3", "https://github.com/a/bc", 999),
        ];
        let by_repo = summarize(hits);
        let buzz = &by_repo["a/b"];
        assert_eq!((buzz.points, buzz.stories), (300, 2));
        assert_eq!(buzz.url, "https://news.ycombinator.com/item?id=2");
        assert_eq!(by_repo["a/bc"].stories, 1);
    }
}
