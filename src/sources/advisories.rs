//! Security advisories affecting given package versions: the model the checks use, the
//! `AdvisoryDb` a source of them implements, and GitHub's global advisory database (GHSA)
//! as that source. GitHub matches versions itself (`affects=name@version`).

use serde::{Deserialize, Serialize};

use super::github::GitHub;
use super::http;
use crate::deps::Ecosystem;
use crate::util::par_map;

/// Most pages read for one query (100 advisories each).
const MAX_PAGES: usize = 10;

/// Somewhere to look up advisories, so the checks don't depend on one database.
pub trait AdvisoryDb: Sync {
    /// As shown in reports, e.g. "the GitHub Advisory Database"
    fn name(&self) -> &'static str;

    /// Advisories (vulnerabilities and malware) affecting any of `specs` (`name@version`)
    /// in `ecosystem`. A batch is at most a few hundred specs.
    fn lookup(&self, ecosystem: Ecosystem, specs: &[String]) -> Result<Vec<Advisory>, String>;
}

/// One advisory, whichever database it came from.
#[derive(Debug, Clone)]
pub struct Advisory {
    /// e.g. `GHSA-xxxx-xxxx-xxxx`
    pub id: String,
    /// The same advisory's ids in other databases (`CVE-…`, `GHSA-…`, `PYSEC-…`)
    pub aliases: Vec<String>,
    pub cve: Option<String>,
    pub summary: String,
    /// critical, high, medium, low or unknown
    pub severity: String,
    pub cvss: Option<f64>,
    pub url: String,
    /// When it was published (RFC 3339)
    pub published: String,
    pub cwes: Vec<Cwe>,
    pub affected: Vec<Affected>,
    /// A malicious package rather than a vulnerability
    pub malware: bool,
}

/// One affected package (an advisory can cover several, or one with several ranges).
#[derive(Debug, Clone)]
pub struct Affected {
    pub ecosystem: Ecosystem,
    pub name: String,
    /// e.g. `>= 4.0.0, < 4.17.21`; none means every version
    pub range: Option<String>,
    pub patched: Option<String>,
}

/// A weakness class, e.g. `CWE-79` "Improper Neutralization of Input During Web Page Generation".
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Cwe {
    pub cwe_id: String,
    pub name: String,
}

/// Advisory types queried: vulnerabilities GitHub reviewed, and malicious packages.
const TYPES: [&str; 2] = ["reviewed", MALWARE];
const MALWARE: &str = "malware";

/// An advisory as GitHub's REST API returns it.
#[derive(Deserialize)]
struct Ghsa {
    ghsa_id: String,
    cve_id: Option<String>,
    summary: String,
    severity: String,
    cvss: Option<Cvss>,
    html_url: String,
    published_at: String,
    withdrawn_at: Option<String>,
    cwes: Option<Vec<Cwe>>,
    #[serde(default)]
    vulnerabilities: Vec<GhsaAffected>,
    /// `reviewed` or `malware`; older responses leave it out
    #[serde(rename = "type", default)]
    kind: String,
}

#[derive(Deserialize)]
struct Cvss {
    score: Option<f64>,
}

#[derive(Deserialize)]
struct GhsaAffected {
    package: GhsaPackage,
    vulnerable_version_range: Option<String>,
    first_patched_version: Option<String>,
}

#[derive(Deserialize)]
struct GhsaPackage {
    ecosystem: String,
    name: String,
}

impl Ghsa {
    /// The advisory, with `kind` (the type queried) when the response leaves it out, and
    /// only the packages in ecosystems stackradar reads.
    fn into_advisory(self, kind: &str) -> Advisory {
        let kind = if self.kind.is_empty() { kind } else { &self.kind };
        Advisory {
            malware: kind == MALWARE,
            id: self.ghsa_id,
            aliases: self.cve_id.iter().cloned().collect(),
            cve: self.cve_id,
            summary: self.summary,
            severity: self.severity,
            cvss: self.cvss.and_then(|c| c.score),
            url: self.html_url,
            published: self.published_at,
            cwes: self.cwes.unwrap_or_default(),
            affected: self
                .vulnerabilities
                .into_iter()
                .filter_map(|a| {
                    Some(Affected {
                        ecosystem: Ecosystem::from_advisory_name(&a.package.ecosystem)?,
                        name: a.package.name,
                        range: a.vulnerable_version_range,
                        patched: a.first_patched_version,
                    })
                })
                .collect(),
        }
    }
}

impl AdvisoryDb for GitHub {
    fn name(&self) -> &'static str {
        "the GitHub Advisory Database"
    }

    fn lookup(&self, ecosystem: Ecosystem, specs: &[String]) -> Result<Vec<Advisory>, String> {
        let found = par_map(&TYPES, TYPES.len(), |kind| self.advisories(kind, ecosystem.advisory_name(), specs));
        Ok(found.into_iter().collect::<Result<Vec<_>, _>>()?.concat())
    }
}

impl GitHub {
    /// Non-withdrawn advisories of type `kind` (one of `TYPES`) affecting any of `affects`
    /// (`name@version`) in `ecosystem` (GitHub's name for it: npm, rust, go, pip, …).
    fn advisories(&self, kind: &str, ecosystem: &str, affects: &[String]) -> Result<Vec<Advisory>, String> {
        let affects = affects.join(",");
        let mut req = self.get(&self.url("/advisories")).query(&[
            ("type", kind),
            ("ecosystem", ecosystem),
            ("affects", affects.as_str()),
            ("per_page", "100"),
        ]);
        let mut out = Vec::new();
        for _ in 0..MAX_PAGES {
            let resp = self.request(req)?;
            let next = http::next_page(&resp);
            let page = http::json::<Vec<Ghsa>>(resp)?;
            out.extend(page.into_iter().filter(|a| a.withdrawn_at.is_none()).map(|a| a.into_advisory(kind)));
            match next {
                Some(url) => req = self.get(&url),
                None => break,
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::super::mock::{Mock, Reply};
    use super::*;

    fn ghsa(id: &str, withdrawn: bool) -> serde_json::Value {
        serde_json::json!({
            "ghsa_id": id, "cve_id": null, "summary": "s", "severity": "high", "cvss": { "score": 7.5 },
            "html_url": format!("https://github.com/advisories/{id}"), "published_at": "2026-01-01T00:00:00Z",
            "withdrawn_at": if withdrawn { serde_json::json!("2026-02-01T00:00:00Z") } else { serde_json::Value::Null },
            "cwes": null,
            "vulnerabilities": [
                { "package": { "ecosystem": "npm", "name": "lodash" }, "vulnerable_version_range": "< 4.17.21",
                  "first_patched_version": "4.17.21" },
                { "package": { "ecosystem": "actions", "name": "x" }, "vulnerable_version_range": null,
                  "first_patched_version": null }
            ]
        })
    }

    #[test]
    fn follows_pages_and_asks_for_vulnerabilities_and_malware() {
        let mock = Mock::start(|req, base| {
            if req.contains("page=2") {
                return Reply::json(200, serde_json::json!([ghsa("GHSA-2", false)]));
            }
            if req.contains("type=malware") {
                return Reply::json(200, serde_json::json!([]));
            }
            let next = format!("<{base}/advisories?type=reviewed&page=2>; rel=\"next\"");
            Reply::json(200, serde_json::json!([ghsa("GHSA-1", false), ghsa("GHSA-W", true)])).header("link", &next)
        });
        let found = GitHub::at(&mock.base).lookup(Ecosystem::Npm, &["lodash@4.17.15".into()]).unwrap();
        let ids: Vec<&str> = found.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, ["GHSA-1", "GHSA-2"], "withdrawn ones are left out");
        assert_eq!(found[0].affected.len(), 1, "only ecosystems stackradar reads");
        assert_eq!((found[0].cvss, found[0].malware), (Some(7.5), false));
        let requests = mock.requests();
        assert_eq!(requests.len(), 3);
        assert!(requests.iter().any(|r| r.contains("affects=lodash%404.17.15") && r.contains("ecosystem=npm")));
    }

    #[test]
    fn a_failed_query_fails_the_lookup() {
        let mock = Mock::start(|req, _| {
            if req.contains("type=malware") {
                Reply::json(502, serde_json::json!({}))
            } else {
                Reply::json(200, serde_json::json!([]))
            }
        });
        let err = GitHub::at(&mock.base).lookup(Ecosystem::Npm, &["a@1".into()]).unwrap_err();
        assert!(err.contains("502"), "{err}");
    }
}
