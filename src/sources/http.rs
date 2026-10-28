//! HTTP plumbing shared by the sources.

use std::path::Path;
use std::time::Duration;

use reqwest::blocking::{Client, RequestBuilder, Response};
use serde::de::DeserializeOwned;

/// One client setup for every service: identifies the tool and never hangs forever.
pub fn client() -> Client {
    client_with(Duration::from_secs(30))
}

fn client_with(timeout: Duration) -> Client {
    Client::builder().user_agent("stackradar").timeout(timeout).build().expect("HTTP client builds")
}

/// Save the body at `url` to `path`. Allows longer than an API call: it's a release archive.
pub fn download(url: &str, path: &Path) -> Result<(), String> {
    let mut resp = checked(send(client_with(Duration::from_secs(300)).get(url))?)?;
    let mut file = std::fs::File::create(path).map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    resp.copy_to(&mut file).map(|_| ()).map_err(|e| format!("download failed: {e}"))
}

pub fn send(req: RequestBuilder) -> Result<Response, String> {
    req.send().map_err(|e| format!("request failed: {e}"))
}

/// The response if it succeeded, else an error carrying the start of the body.
pub fn checked(resp: Response) -> Result<Response, String> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let body = resp.text().unwrap_or_default();
    Err(format!("HTTP {status}: {}", body.chars().take(200).collect::<String>()))
}

pub fn json<T: DeserializeOwned>(resp: Response) -> Result<T, String> {
    resp.json().map_err(|e| format!("invalid response: {e}"))
}

/// The `rel="next"` URL of a paginated response's `Link` header.
pub fn next_page(resp: &Response) -> Option<String> {
    next_link(resp.headers().get("link")?.to_str().ok()?)
}

fn next_link(header: &str) -> Option<String> {
    header.split(',').find_map(|part| {
        let (url, params) = part.split_once(';')?;
        params.contains(r#"rel="next""#).then(|| url.trim().trim_start_matches('<').trim_end_matches('>').to_string())
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn finds_next_link() {
        let h = r#"<https://api.github.com/x?after=Y2==&per_page=2>; rel="next", <https://api.github.com/x?page=1>; rel="prev""#;
        assert_eq!(super::next_link(h).as_deref(), Some("https://api.github.com/x?after=Y2==&per_page=2"));
        assert_eq!(super::next_link(r#"<https://x>; rel="prev""#), None);
    }
}
