//! OSV.dev: Google's open vulnerability database, which merges GitHub's reviewed
//! advisories with the ecosystems' own (RustSec, PyPA, the Go database) and OpenSSF's
//! malicious packages. It needs no token and has no rate limit. A batch query returns
//! ids only, so each advisory is then fetched, once per run.

use std::collections::HashMap;
use std::sync::Mutex;

use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::{Value, json};

use super::advisories::{Advisory, AdvisoryDb, Affected, Cwe};
use super::http;
use crate::deps::Ecosystem;
use crate::util::{par_map, truncate};

const API: &str = "https://api.osv.dev";
/// Advisories fetched at once (OSV has no rate limit; a big scan fetches hundreds).
const FETCH_WORKERS: usize = 16;
/// Most extra pages read for one package version (a page holds up to 1000 ids).
const MAX_PAGES: usize = 10;

pub struct Osv {
    client: Client,
    /// `API`, or a local stand-in in tests
    api: String,
    /// Advisories already fetched, by id: batches share many
    fetched: Mutex<HashMap<String, Option<Advisory>>>,
}

impl Osv {
    pub fn new() -> Self {
        Self::at(API)
    }

    pub fn at(api: &str) -> Self {
        Self { client: http::client(), api: api.into(), fetched: Mutex::default() }
    }

    /// Ids of the advisories affecting `name@version`, following pages from `token`.
    fn more_ids(&self, query: &Value, mut token: String) -> Result<Vec<String>, String> {
        #[derive(Deserialize)]
        struct Page {
            #[serde(default)]
            vulns: Vec<Id>,
            next_page_token: Option<String>,
        }
        let mut ids = Vec::new();
        for _ in 0..MAX_PAGES {
            let mut body = query.clone();
            body["page_token"] = token.into();
            let page: Page = http::json(http::checked(http::send(
                self.client.post(format!("{}/v1/query", self.api)).json(&body),
            )?)?)?;
            ids.extend(page.vulns.into_iter().map(|v| v.id));
            match page.next_page_token {
                Some(next) => token = next,
                None => break,
            }
        }
        Ok(ids)
    }

    /// The advisory with `id`; None if it was withdrawn or covers nothing stackradar reads.
    fn advisory(&self, id: &str) -> Result<Option<Advisory>, String> {
        if let Some(done) = self.fetched.lock().unwrap().get(id) {
            return Ok(done.clone());
        }
        let url = format!("{}/v1/vulns/{id}", self.api);
        let vuln: Vuln = http::json(http::checked(http::send(self.client.get(&url))?)?)?;
        let advisory = vuln.into_advisory();
        self.fetched.lock().unwrap().insert(id.to_string(), advisory.clone());
        Ok(advisory)
    }
}

impl AdvisoryDb for Osv {
    fn name(&self) -> &'static str {
        "OSV.dev"
    }

    fn lookup(&self, ecosystem: Ecosystem, specs: &[String]) -> Result<Vec<Advisory>, String> {
        #[derive(Deserialize)]
        struct Batch {
            results: Vec<Found>,
        }
        #[derive(Deserialize)]
        struct Found {
            #[serde(default)]
            vulns: Vec<Id>,
            next_page_token: Option<String>,
        }
        let queries: Vec<Value> = specs
            .iter()
            .filter_map(|s| s.rsplit_once('@'))
            .map(|(name, version)| {
                json!({ "package": { "name": name, "ecosystem": ecosystem_name(ecosystem) }, "version": version })
            })
            .collect();
        let req = self.client.post(format!("{}/v1/querybatch", self.api)).json(&json!({ "queries": queries }));
        let batch: Batch = http::json(http::checked(http::send(req)?)?)?;
        let mut ids = Vec::new();
        for (found, query) in batch.results.into_iter().zip(&queries) {
            ids.extend(found.vulns.into_iter().map(|v| v.id));
            if let Some(token) = found.next_page_token {
                ids.extend(self.more_ids(query, token)?);
            }
        }
        ids.sort();
        ids.dedup();
        let advisories = par_map(&ids, FETCH_WORKERS, |id| self.advisory(id));
        Ok(advisories.into_iter().collect::<Result<Vec<_>, _>>()?.into_iter().flatten().collect())
    }
}

/// OSV's name for an ecosystem.
fn ecosystem_name(eco: Ecosystem) -> &'static str {
    match eco {
        Ecosystem::Npm => "npm",
        Ecosystem::Cargo => "crates.io",
        Ecosystem::Go => "Go",
        Ecosystem::Pip => "PyPI",
        Ecosystem::Composer => "Packagist",
        Ecosystem::RubyGems => "RubyGems",
        Ecosystem::Pub => "Pub",
        Ecosystem::NuGet => "NuGet",
        Ecosystem::Maven => "Maven",
    }
}

#[derive(Deserialize)]
struct Id {
    id: String,
}

/// An advisory in the OSV schema (https://ossf.github.io/osv-schema/).
#[derive(Deserialize)]
struct Vuln {
    id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    details: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    published: String,
    withdrawn: Option<String>,
    /// GitHub's advisories carry `severity` and `cwe_ids` here
    database_specific: Option<Value>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

#[derive(Deserialize)]
struct OsvAffected {
    package: OsvPackage,
    #[serde(default)]
    ranges: Vec<Range>,
    /// Exact versions, for records without usable ranges
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(Deserialize)]
struct OsvPackage {
    ecosystem: String,
    name: String,
}

#[derive(Deserialize)]
struct Range {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    events: Vec<Event>,
}

#[derive(Deserialize)]
struct Event {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
}

impl Vuln {
    fn into_advisory(self) -> Option<Advisory> {
        if self.withdrawn.is_some() {
            return None;
        }
        let specific = |key: &str| self.database_specific.as_ref().and_then(|d| d.get(key).cloned());
        let affected: Vec<Affected> = self
            .affected
            .iter()
            .filter_map(|a| {
                let ecosystem = Ecosystem::ALL.into_iter().find(|&e| ecosystem_name(e) == a.package.ecosystem)?;
                let affected =
                    move |(range, patched)| Affected { ecosystem, name: a.package.name.clone(), range, patched };
                Some(spans(a).into_iter().map(affected))
            })
            .flatten()
            .collect();
        if affected.is_empty() {
            return None;
        }
        let summary = if self.summary.is_empty() {
            truncate(self.details.lines().next().unwrap_or_default(), 200)
        } else {
            self.summary
        };
        Some(Advisory {
            url: format!("https://osv.dev/vulnerability/{}", self.id),
            malware: self.id.starts_with("MAL-"),
            cve: std::iter::once(&self.id).chain(&self.aliases).find(|a| a.starts_with("CVE-")).cloned(),
            severity: specific("severity").and_then(|s| s.as_str().map(String::from)).unwrap_or("unknown".into()),
            // Only a CVSS vector is given, not its score.
            cvss: None,
            cwes: specific("cwe_ids")
                .and_then(|c| serde_json::from_value::<Vec<String>>(c).ok())
                .unwrap_or_default()
                .into_iter()
                .map(|cwe_id| Cwe { cwe_id, name: String::new() })
                .collect(),
            published: self.published,
            summary,
            aliases: self.aliases,
            id: self.id,
            affected,
        })
    }
}

/// An affected package's versions as GitHub-style ranges (`>= 1.0.0, < 1.2.3`) with the
/// version that fixes each. A range left open from `0` is every version (None).
fn spans(a: &OsvAffected) -> Vec<(Option<String>, Option<String>)> {
    let mut out = Vec::new();
    for range in a.ranges.iter().filter(|r| r.kind != "GIT") {
        let mut start: Option<&str> = None;
        let span = |start: Option<&str>, end: String| match start {
            Some(s) if s != "0" => format!(">= {s}, {end}"),
            _ => end,
        };
        for e in &range.events {
            if let Some(s) = &e.introduced {
                start = Some(s);
            } else if let Some(fixed) = &e.fixed {
                out.push((Some(span(start.take(), format!("< {fixed}"))), Some(fixed.clone())));
            } else if let Some(last) = &e.last_affected {
                out.push((Some(span(start.take(), format!("<= {last}"))), None));
            }
        }
        if let Some(s) = start {
            out.push(((s != "0").then(|| format!(">= {s}")), None));
        }
    }
    if out.is_empty() {
        out = a.versions.iter().map(|v| (Some(format!("= {v}")), None)).collect();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::mock::{Mock, Reply};
    use super::*;

    fn record(id: &str, aliases: &[&str], events: Value) -> Value {
        json!({
            "id": id, "summary": format!("{id} summary"), "aliases": aliases, "published": "2026-01-01T00:00:00Z",
            "database_specific": { "severity": "HIGH", "cwe_ids": ["CWE-79"] },
            "affected": [
                { "package": { "ecosystem": "npm", "name": "lodash" }, "ranges": [{ "type": "SEMVER", "events": events }] },
                { "package": { "ecosystem": "Debian:12", "name": "node-lodash" }, "versions": ["1"] }
            ]
        })
    }

    #[test]
    fn turns_events_into_ranges() {
        let affected = |events: Value| {
            let v: Vuln = serde_json::from_value(record("GHSA-1", &[], events)).unwrap();
            v.into_advisory().unwrap().affected.into_iter().map(|a| (a.range, a.patched)).collect::<Vec<_>>()
        };
        let s = |s: &str| Some(s.to_string());
        assert_eq!(
            affected(
                json!([{ "introduced": "0" }, { "fixed": "4.17.21" }, { "introduced": "5.0.0" }, { "last_affected": "5.1.0" }])
            ),
            [(s("< 4.17.21"), s("4.17.21")), (s(">= 5.0.0, <= 5.1.0"), None)]
        );
        assert_eq!(affected(json!([{ "introduced": "0" }])), [(None, None)], "every version");
        assert_eq!(affected(json!([{ "introduced": "2.0.0" }])), [(s(">= 2.0.0"), None)]);
    }

    #[test]
    fn looks_up_ids_then_each_advisory_once() {
        let mock = Mock::start(|target, _| match target {
            "/v1/querybatch" => Reply::json(
                200,
                json!({ "results": [{ "vulns": [{ "id": "GHSA-1" }, { "id": "MAL-1" }] }, { "vulns": [{ "id": "GHSA-1" }] }] }),
            ),
            "/v1/vulns/GHSA-1" => Reply::json(
                200,
                record("GHSA-1", &["CVE-2026-1"], json!([{ "introduced": "0" }, { "fixed": "4.17.21" }])),
            ),
            "/v1/vulns/MAL-1" => Reply::json(200, record("MAL-1", &[], json!([{ "introduced": "0" }]))),
            _ => Reply::json(404, json!({})),
        });
        let osv = Osv::at(&mock.base);
        let found = osv.lookup(Ecosystem::Npm, &["lodash@4.17.15".into(), "@scope/x@1.0.0".into()]).unwrap();
        let summary: Vec<(&str, bool, Option<&str>, &str)> =
            found.iter().map(|a| (a.id.as_str(), a.malware, a.cve.as_deref(), a.severity.as_str())).collect();
        assert_eq!(summary, [("GHSA-1", false, Some("CVE-2026-1"), "HIGH"), ("MAL-1", true, None, "HIGH")]);
        assert_eq!(found[0].affected.len(), 1, "only ecosystems stackradar reads");
        assert_eq!(found[0].url, "https://osv.dev/vulnerability/GHSA-1");
        osv.lookup(Ecosystem::Npm, &["lodash@4.17.15".into()]).unwrap();
        let fetches = mock.requests().iter().filter(|r| r.starts_with("/v1/vulns/")).count();
        assert_eq!(fetches, 2, "each advisory is fetched once");
    }
}
