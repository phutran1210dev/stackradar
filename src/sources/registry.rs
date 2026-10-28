//! Package registries, asked where a package's source lives. Only the package name is
//! sent. NuGet and Maven are not asked (their metadata rarely names a repo).

use reqwest::blocking::Client;
use serde_json::Value;

use super::http;
use crate::deps::Ecosystem;

/// The URLs a registry gives for `name`'s source, homepage and the like; None if the
/// ecosystem isn't looked up. Go modules are their own URL, so nothing is fetched.
pub fn source_urls(client: &Client, ecosystem: Ecosystem, name: &str) -> Result<Option<Vec<String>>, String> {
    let (url, pointers): (String, &[&str]) = match ecosystem {
        Ecosystem::Go => return Ok(Some(vec![format!("https://{name}")])),
        Ecosystem::Npm => (
            format!("https://registry.npmjs.org/{}/latest", name.replace('/', "%2F")),
            &["/repository/url", "/repository", "/homepage"],
        ),
        Ecosystem::Cargo => {
            (format!("https://crates.io/api/v1/crates/{name}"), &["/crate/repository", "/crate/homepage"])
        }
        Ecosystem::Pip => (
            format!("https://pypi.org/pypi/{name}/json"),
            &[
                "/info/project_urls/Source",
                "/info/project_urls/Repository",
                "/info/project_urls/Source Code",
                "/info/project_urls/Homepage",
                "/info/home_page",
            ],
        ),
        Ecosystem::Composer => (format!("https://repo.packagist.org/p2/{name}.json"), &[]),
        Ecosystem::RubyGems => {
            (format!("https://rubygems.org/api/v1/gems/{name}.json"), &["/source_code_uri", "/homepage_uri"])
        }
        Ecosystem::Pub => (
            format!("https://pub.dev/api/packages/{name}"),
            &["/latest/pubspec/repository", "/latest/pubspec/homepage"],
        ),
        Ecosystem::NuGet | Ecosystem::Maven => return Ok(None),
    };
    let resp = http::send(client.get(&url))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(Some(Vec::new()));
    }
    let body: Value = http::json(http::checked(resp)?)?;
    let mut urls: Vec<String> = pointers.iter().filter_map(|p| body.pointer(p)?.as_str().map(String::from)).collect();
    if ecosystem == Ecosystem::Composer {
        // `packages.<name>[0].source.url`
        let source = body.get("packages").and_then(|p| p.get(name)).and_then(|v| v.pointer("/0/source/url"));
        urls.extend(source.and_then(Value::as_str).map(String::from));
    }
    Ok(Some(urls))
}

/// `owner/name` of the first GitHub repo among `urls` (`git+https://github.com/a/b.git`,
/// `https://github.com/a/b/tree/main/pkg`, `github.com/a/b/v2`).
pub fn github_repo(urls: &[String]) -> Option<String> {
    let valid = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c));
    urls.iter().find_map(|u| {
        let rest = &u[u.find("github.com/")? + "github.com/".len()..];
        let mut parts = rest.split(['/', '#', '?']);
        let owner = parts.next()?;
        let name = parts.next()?.trim_end_matches(".git");
        (valid(owner) && valid(name)).then(|| format!("{owner}/{name}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_github_repos_in_urls() {
        let r = |u: &str| github_repo(&[u.to_string()]);
        assert_eq!(r("git+https://github.com/expressjs/express.git").as_deref(), Some("expressjs/express"));
        assert_eq!(r("https://github.com/a/b/tree/main/packages/x").as_deref(), Some("a/b"));
        assert_eq!(r("https://github.com/jackc/pgx/v5").as_deref(), Some("jackc/pgx"));
        assert_eq!(r("https://gitlab.com/a/b"), None);
        assert_eq!(r("https://github.com/a\"){x}/b"), None, "only plain names reach GraphQL");
    }
}
