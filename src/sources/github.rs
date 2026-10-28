use std::collections::{HashMap, HashSet};
use std::process::Command;

use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::ACCEPT;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::http;

const API: &str = "https://api.github.com";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Owner {
    pub avatar_url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct License {
    pub spdx_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Repo {
    pub full_name: String,
    pub html_url: String,
    pub description: Option<String>,
    pub stargazers_count: u64,
    pub forks_count: u64,
    pub open_issues_count: u64,
    pub language: Option<String>,
    #[serde(default)]
    pub topics: Vec<String>,
    pub created_at: String,
    pub pushed_at: String,
    pub owner: Owner,
    pub license: Option<License>,
}

impl Repo {
    /// Case-insensitive identity: GitHub names are, and trending pages may differ in case.
    pub fn key(&self) -> String {
        self.full_name.to_ascii_lowercase()
    }

    #[cfg(test)]
    pub fn test(full_name: &str, stars: u64, topics: &[&str]) -> Self {
        Repo {
            full_name: full_name.into(),
            html_url: format!("https://github.com/{full_name}"),
            description: None,
            stargazers_count: stars,
            forks_count: 0,
            open_issues_count: 0,
            language: None,
            topics: topics.iter().map(|t| t.to_string()).collect(),
            created_at: "2026-01-01T00:00:00Z".into(),
            pushed_at: "2026-01-01T00:00:00Z".into(),
            owner: Owner { avatar_url: String::new() },
            license: None,
        }
    }
}

#[derive(Deserialize)]
struct SearchResponse {
    items: Vec<Repo>,
}

/// The latest published release of a repo (not a draft or pre-release).
#[derive(Debug, Deserialize)]
pub struct LatestRelease {
    pub tag_name: String,
    pub assets: Vec<Asset>,
}

#[derive(Debug, Deserialize)]
pub struct Asset {
    pub name: String,
    pub browser_download_url: String,
}

/// Times a request waits out a short rate limit before giving up: enough for 30 topic
/// searches at the unauthenticated 10 a minute.
const MAX_WAITS: usize = 3;

pub struct GitHub {
    client: Client,
    token: Option<String>,
    /// `API`, or a local stand-in in tests
    api: String,
}

impl GitHub {
    /// Token lookup: GITHUB_TOKEN env var, then the GitHub CLI (`gh auth token`).
    pub fn new() -> Self {
        let token = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty()).or_else(|| {
            let out = Command::new("gh").args(["auth", "token"]).output().ok()?;
            let t = String::from_utf8(out.stdout).ok()?.trim().to_string();
            (out.status.success() && !t.is_empty()).then_some(t)
        });
        Self { client: http::client(), token, api: API.into() }
    }

    /// A client for a stand-in of the API at `api`, without a token.
    #[cfg(test)]
    pub fn at(api: &str) -> Self {
        Self { client: http::client(), token: None, api: api.into() }
    }

    /// `path` (`/search/repositories`) on the API.
    pub(super) fn url(&self, path: &str) -> String {
        format!("{}{path}", self.api)
    }

    pub fn is_authenticated(&self) -> bool {
        self.token.is_some()
    }

    /// Successful response to an API request, sent with auth. When a rate limit is hit
    /// that resets within a minute (the search limit is per minute, and so are secondary
    /// limits), waits for the reset and retries, up to `MAX_WAITS` times. A limit that
    /// lasts longer fails at once, saying for how long.
    pub(super) fn request(&self, req: RequestBuilder) -> Result<Response, String> {
        let mut req = req.header(ACCEPT, "application/vnd.github+json");
        if let Some(t) = &self.token {
            req = req.bearer_auth(t);
        }
        let template = req.try_clone();
        let mut resp = http::send(req)?;
        for _ in 0..MAX_WAITS {
            let Some(limit) = rate_limit(&resp) else { break };
            let Some(retry) = template.as_ref().and_then(RequestBuilder::try_clone) else { break };
            match limit {
                Ok(wait) => std::thread::sleep(wait),
                Err(secs) => return Err(self.exhausted(secs)),
            }
            resp = http::send(retry)?;
        }
        http::checked(resp)
    }

    fn exhausted(&self, secs: u64) -> String {
        let hint = if self.token.is_some() { "" } else { "; set GITHUB_TOKEN or run `gh auth login` for a higher one" };
        format!("GitHub rate limit reached, resets in {} min{hint}", secs.div_ceil(60))
    }

    fn api<T: DeserializeOwned>(&self, req: RequestBuilder) -> Result<T, String> {
        http::json(self.request(req)?)
    }

    pub(super) fn get(&self, url: &str) -> RequestBuilder {
        self.client.get(url)
    }

    /// Repos tagged with `topic`, created after `since` (YYYY-MM-DD), most-starred first.
    pub fn search_topic(&self, topic: &str, since: &str, min_stars: u64, limit: u8) -> Result<Vec<Repo>, String> {
        let q = format!("topic:{topic} created:>{since} stars:>={min_stars} archived:false");
        let per_page = limit.to_string();
        let req = self.client.get(self.url("/search/repositories")).query(&[
            ("q", q.as_str()),
            ("sort", "stars"),
            ("order", "desc"),
            ("per_page", &per_page),
        ]);
        self.api::<SearchResponse>(req).map(|r| r.items)
    }

    /// `owner/name`'s latest release.
    pub fn latest_release(&self, full_name: &str) -> Result<LatestRelease, String> {
        self.api(self.client.get(self.url(&format!("/repos/{full_name}/releases/latest"))))
    }

    /// Full repo record (needed for topics of repos found only on the trending page).
    pub fn repo(&self, full_name: &str) -> Result<Repo, String> {
        self.api(self.client.get(self.url(&format!("/repos/{full_name}"))))
    }

    /// Logins of up to `max` recent stargazers, newest first. The stargazer list itself is
    /// only readable by a repo's owner, but stars still show up in its public event feed.
    pub fn recent_stargazers(&self, full_name: &str, max: usize) -> Result<Vec<String>, String> {
        #[derive(Deserialize)]
        struct Event {
            #[serde(rename = "type")]
            kind: String,
            actor: Actor,
        }
        #[derive(Deserialize)]
        struct Actor {
            login: String,
        }
        let req = self.client.get(self.url(&format!("/repos/{full_name}/events"))).query(&[("per_page", "100")]);
        let events: Vec<Event> = self.api(req)?;
        let mut seen = HashSet::new();
        Ok(events
            .into_iter()
            .filter(|e| e.kind == "WatchEvent" && seen.insert(e.actor.login.clone()))
            .map(|e| e.actor.login)
            .take(max)
            .collect())
    }

    /// Run a GraphQL query (token required) and return `data` by alias. Partial data is
    /// returned as is: one missing alias (say, a deleted user) shouldn't sink the batch.
    pub fn graphql(&self, query: &str) -> Result<HashMap<String, serde_json::Value>, String> {
        #[derive(Deserialize)]
        struct Reply {
            data: Option<HashMap<String, serde_json::Value>>,
            #[serde(default)]
            errors: Vec<serde_json::Value>,
        }
        let req = self.client.post(self.url("/graphql")).json(&serde_json::json!({ "query": query }));
        let reply: Reply = self.api(req)?;
        reply.data.ok_or_else(|| {
            format!("GraphQL error: {}", reply.errors.first().map(|e| e.to_string()).unwrap_or_default())
        })
    }

    /// github.com/trending for `language` ("" = all languages): (full_name, stars today).
    /// There is no API for this page, so it is scraped; an empty parse is reported as an
    /// error so a markup change doesn't silently drop the signal.
    pub fn trending(&self, language: &str) -> Result<Vec<(String, u64)>, String> {
        let url = format!("https://github.com/trending/{language}?since=daily");
        let html = http::checked(http::send(self.client.get(&url))?)?.text().map_err(|e| e.to_string())?;
        let repos = parse_trending(&html);
        if repos.is_empty() {
            return Err(format!("no repos parsed from {url} (page layout changed?)"));
        }
        Ok(repos)
    }
}

/// For a rate-limited response: how long to wait before retrying if that's at most ~a
/// minute, else (as the error) the seconds until the limit resets.
fn rate_limit(resp: &Response) -> Option<Result<std::time::Duration, u64>> {
    let header = |name: &str| resp.headers().get(name)?.to_str().ok()?.parse::<u64>().ok();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    limit_wait(resp.status().as_u16(), header, now)
}

fn limit_wait(status: u16, header: impl Fn(&str) -> Option<u64>, now: u64) -> Option<Result<std::time::Duration, u64>> {
    if !matches!(status, 403 | 429) {
        return None;
    }
    // Secondary limits (too many requests at once) say how long in `retry-after`.
    let secs = match header("retry-after") {
        Some(secs) => secs.max(1),
        None if header("x-ratelimit-remaining")? == 0 => header("x-ratelimit-reset")?.saturating_sub(now) + 1,
        None => return None,
    };
    Some(if secs <= 65 { Ok(std::time::Duration::from_secs(secs)) } else { Err(secs) })
}

/// Each repo is an `<article class="Box-row">` whose `<h2>` links to `/owner/repo`,
/// followed by "1,234 stars today".
fn parse_trending(html: &str) -> Vec<(String, u64)> {
    html.split(r#"<article class="Box-row">"#)
        .skip(1)
        .filter_map(|block| {
            let h2 = &block[block.find("<h2")?..];
            let href = &h2[h2.find(r#"href="/"#)? + 7..];
            let name = &href[..href.find('"')?];
            if name.matches('/').count() != 1 {
                return None;
            }
            let before = &block[..block.find(" stars today").or_else(|| block.find(" star today"))?];
            let num = before.rsplit(|c: char| c.is_whitespace() || c == '>').next()?;
            Some((name.to_string(), num.replace(',', "").parse().ok()?))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{limit_wait, parse_trending};

    #[test]
    fn waits_out_short_rate_limits_only() {
        let headers = |pairs: &'static [(&'static str, u64)]| {
            move |name: &str| pairs.iter().find(|(n, _)| *n == name).map(|&(_, v)| v)
        };
        let secs = |d: std::time::Duration| d.as_secs();
        let search = headers(&[("x-ratelimit-remaining", 0), ("x-ratelimit-reset", 1030)]);
        assert_eq!(limit_wait(403, search, 1000).map(|r| r.map(secs)), Some(Ok(31)));
        let core = headers(&[("x-ratelimit-remaining", 0), ("x-ratelimit-reset", 4600)]);
        assert_eq!(limit_wait(403, core, 1000), Some(Err(3601)));
        assert_eq!(limit_wait(429, headers(&[("retry-after", 20)]), 1000).map(|r| r.map(secs)), Some(Ok(20)));
        assert_eq!(limit_wait(403, headers(&[("x-ratelimit-remaining", 4)]), 1000), None, "forbidden, not limited");
        assert_eq!(limit_wait(200, search, 1000), None);
    }

    #[test]
    fn retries_after_a_short_limit_and_explains_a_long_one() {
        use super::super::mock::{Mock, Reply};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = AtomicUsize::new(0);
        let mock = Mock::start(move |_, _| match calls.fetch_add(1, Ordering::SeqCst) {
            0 => Reply::json(403, serde_json::json!({})).header("retry-after", "1"),
            1 => Reply::json(200, serde_json::json!({ "tag_name": "v1.0.0", "assets": [] })),
            _ => Reply::json(403, serde_json::json!({}))
                .header("x-ratelimit-remaining", "0")
                .header("x-ratelimit-reset", "99999999999"),
        });
        let gh = super::GitHub::at(&mock.base);
        assert_eq!(gh.latest_release("a/b").unwrap().tag_name, "v1.0.0");
        let err = gh.latest_release("a/b").err().unwrap();
        assert!(err.contains("rate limit") && err.contains("GITHUB_TOKEN"), "{err}");
        assert_eq!(mock.requests().len(), 3, "a long limit isn't retried");
    }

    #[test]
    fn parses_a_real_trending_page() {
        let html = include_str!("../../tests/fixtures/trending-page.html");
        assert_eq!(
            parse_trending(html),
            vec![
                ("cloudflare/security-audit-skill".to_string(), 2271),
                ("NVIDIA/OpenShell".to_string(), 893),
                ("aws/agent-toolkit-for-aws".to_string(), 11),
            ]
        );
    }

    #[test]
    fn parses_trending_rows() {
        let html = r#"<html><article class="Box-row">
            <h2 class="h3 lh-condensed"><a data-x="{&quot;a&quot;}" href="/vercel/next.js" class="Link">x</a></h2>
            <span class="d-inline-block float-sm-right"><svg></svg>
                1,234 stars today
            </span></article>
            <article class="Box-row"><h2><a href="/a/b">b</a></h2><svg></svg>
                1 star today</article>
            <article class="Box-row"><h2><a href="/broken">x</a></h2> 5 stars today</article>"#;
        assert_eq!(parse_trending(html), vec![("vercel/next.js".to_string(), 1234), ("a/b".to_string(), 1)]);
    }
}
