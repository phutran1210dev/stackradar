//! SARIF 2.1.0, for GitHub code scanning (`audit --sarif`): one rule per advisory and
//! one result per affected package version in each project, located at the line of its
//! manifest that declares it (the first line for a transitive one).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use super::{fix_label, kind_label, severity_label};
use crate::model::{Report, Severity, Usage, Vulnerability};

const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

/// GitHub's `security-severity` (0.1–10): the CVSS score, else the middle of the band.
fn security_severity(v: &Vulnerability) -> Option<f64> {
    if v.malware {
        return Some(10.0);
    }
    v.cvss.or(match v.severity {
        Severity::Critical => Some(9.5),
        Severity::High => Some(8.0),
        Severity::Medium => Some(5.5),
        Severity::Low => Some(2.0),
        Severity::Unknown => None,
    })
}

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Unknown => "note",
    }
}

/// `report`'s vulnerabilities as a SARIF log. Paths are relative to `base` (the
/// repository checkout) when inside it.
pub fn sarif(report: &Report, base: &Path) -> String {
    let items: &[Vulnerability] = report.vulnerabilities.as_ref().map_or(&[], |v| &v.items);
    let mut rules: BTreeMap<&str, Value> = BTreeMap::new();
    let mut manifests: HashMap<PathBuf, Option<String>> = HashMap::new();
    let mut results = Vec::new();
    for v in items {
        rules.entry(&v.id).or_insert_with(|| rule(v));
        for u in &v.uses {
            let text = manifests.entry(u.manifest.clone()).or_insert_with(|| std::fs::read_to_string(&u.manifest).ok());
            let line = text.as_deref().and_then(|t| line_of(t, &u.name)).filter(|_| u.is_direct()).unwrap_or(1);
            results.push(result(v, u, &uri(&u.manifest, base), line));
        }
    }
    let log = json!({
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "stackradar",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": env!("CARGO_PKG_REPOSITORY"),
                "rules": rules.into_values().collect::<Vec<_>>(),
            }},
            "results": results,
        }],
    });
    serde_json::to_string_pretty(&log).expect("SARIF serializes")
}

fn rule(v: &Vulnerability) -> Value {
    let mut tags = vec!["security".to_string(), "dependency".into(), v.ecosystem.advisory_name().into()];
    if v.malware {
        tags.push("malware".into());
    }
    if v.exploited {
        tags.push("known-exploited".into());
    }
    tags.extend(v.cwes.iter().map(|c| c.cwe_id.clone()));
    let mut properties = json!({ "tags": tags });
    if let Some(s) = security_severity(v) {
        properties["security-severity"] = json!(format!("{s:.1}"));
    }
    let title = format!("{} in {}: {}", severity_label(v.severity, v.malware), v.package, v.summary);
    json!({
        "id": v.id,
        "name": if v.malware { "MaliciousPackage" } else { "VulnerableDependency" },
        "shortDescription": { "text": title },
        "fullDescription": { "text": v.summary },
        "helpUri": v.url,
        "help": { "text": format!("{} ({}). Affected: {}. {}", v.summary, v.id, v.vulnerable, fix_label(v)) },
        "defaultConfiguration": { "level": level(v.severity) },
        "properties": properties,
    })
}

fn result(v: &Vulnerability, u: &Usage, uri: &str, line: usize) -> Value {
    let kind = kind_label(u.kind, u.via.as_deref()).map(|k| format!(" ({k})")).unwrap_or_default();
    let message = format!("{} {}{kind} is affected by {}: {} {}", v.package, u.version, v.id, v.summary, fix_label(v));
    json!({
        "ruleId": v.id,
        "level": level(v.severity),
        "message": { "text": message },
        "locations": [{ "physicalLocation": {
            "artifactLocation": { "uri": uri },
            "region": { "startLine": line },
        }}],
        "partialFingerprints": { "stackradar/v1": format!("{}:{}:{}:{uri}", v.id, v.package, u.version) },
    })
}

/// `path` relative to `base` with `/` separators, else as a `file://` URI.
fn uri(path: &Path, base: &Path) -> String {
    match path.strip_prefix(base) {
        Ok(rel) => rel.to_string_lossy().replace('\\', "/"),
        Err(_) => format!("file://{}", path.to_string_lossy().replace('\\', "/")),
    }
}

/// The first line (from 1) naming package `name` as a whole word.
fn line_of(text: &str, name: &str) -> Option<usize> {
    let part = |c: char| c.is_alphanumeric() || "-_./@:".contains(c);
    text.lines()
        .position(|line| {
            line.match_indices(name).any(|(i, _)| {
                !line[..i].chars().next_back().is_some_and(part)
                    && !line[i + name.len()..].chars().next().is_some_and(part)
            })
        })
        .map(|i| i + 1)
}

#[cfg(test)]
mod tests {
    use super::super::fixture;
    use super::*;

    #[test]
    fn one_result_per_use_at_the_declaring_line() {
        let dir = std::env::temp_dir().join(format!("stackradar-sarif-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("package.json"),
            "{\n  \"dependencies\": {\n    \"lodash-es\": \"1\",\n    \"lodash\": \"^4\"\n  }\n}\n",
        )
        .unwrap();
        let mut report = fixture::report();
        for v in &mut report.vulnerabilities.as_mut().unwrap().items {
            v.uses[0].manifest = dir.join("package.json");
        }
        let log: Value = serde_json::from_str(&sarif(&report, &dir)).unwrap();
        let run = &log["runs"][0];
        assert_eq!(run["tool"]["driver"]["rules"].as_array().unwrap().len(), 2);
        assert_eq!(run["tool"]["driver"]["rules"][0]["properties"]["security-severity"], "8.1");
        let r = &run["results"][0];
        assert_eq!(r["level"], "error");
        assert_eq!(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "package.json");
        assert_eq!(r["locations"][0]["physicalLocation"]["region"]["startLine"], 4, "not lodash-es on line 3");
        assert_eq!(run["results"][1]["level"], "note");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
