//! Every presentation of a `Report`: terminal tables, Markdown digest, notification
//! summary, webhook digest and the HTML page. Shared labels live here so the formats agree.

mod digest;
mod html;
mod markdown;
mod sarif;
mod terminal;

use std::collections::HashSet;
use std::fmt::Write;

use crate::deps::DepKind;
use crate::model::{Entry, Fix, Report, Section, Severity, Unmaintained, VulnScan, Vulnerability};

pub use digest::digest;
pub use html::html;
pub use markdown::markdown;
pub use sarif::sarif;
pub use terminal::terminal;

/// `Frontend (react, nextjs)`, or just the title for tabs without topics.
fn heading(s: &Section) -> String {
    if s.topics.is_empty() { s.title.clone() } else { format!("{} ({})", s.title, s.topics.join(", ")) }
}

/// "NEW", "Δ+12", or empty.
fn change_label(e: &Entry) -> String {
    match (e.is_new, e.stars_delta) {
        (true, _) => "NEW".to_string(),
        (_, Some(d)) => format!("Δ{d:+}"),
        _ => String::new(),
    }
}

/// Human-readable buzz reasons and warnings.
fn signal_labels(e: &Entry) -> Vec<String> {
    let mut v = Vec::new();
    if let Some(t) = e.trending_today {
        v.push(format!("🔥 Trending +{t}★ today"));
    }
    if let Some(h) = &e.hn {
        v.push(format!("💬 HN {} pts, {} comments", h.points, h.comments));
    }
    if let Some((tag, _)) = e.health.as_ref().and_then(|h| h.release.as_ref()).filter(|_| e.new_release) {
        v.push(format!("🏷 new release {tag}"));
    }
    if let Some(c) = e.star_check.as_ref().filter(|_| e.suspicious_stars) {
        v.push(format!("🚩 suspicious stars ({}/{} recent stargazers are throwaway accounts)", c.ghosts, c.sampled));
    }
    if e.low_engagement {
        v.push("⚠ low engagement".to_string());
    }
    if let Some(h) = e.health.as_ref().filter(|h| !h.executables.is_empty()) {
        let mut exts: Vec<&str> = h.executables.iter().filter_map(|n| n.rsplit_once('.').map(|(_, e)| e)).collect();
        exts.sort_unstable_by_key(|e| e.to_ascii_lowercase());
        exts.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
        v.push(format!("📦 release ships executables (.{})", exts.join(", .")));
    }
    v
}

/// `lodash 4.17.15` (or `lodash ≥4.17.0` when only the manifest's range is known).
fn package_label(v: &Vulnerability) -> String {
    match v.uses.first() {
        Some(u) if u.exact => format!("{} {}", v.package, u.version),
        Some(u) => format!("{} ≥{}", v.package, u.version),
        None => v.package.clone(),
    }
}

/// `MALWARE` for a malicious package, else the severity (`HIGH`).
fn severity_label(severity: Severity, malware: bool) -> &'static str {
    if malware { "MALWARE" } else { severity.label() }
}

/// `🔥 exploited` for what CISA lists as exploited in the wild, else a notable EPSS score
/// (the chance of exploitation in the next 30 days).
fn exploit_label(exploited: bool, epss: Option<f64>) -> Option<String> {
    if exploited {
        return Some("🔥 exploited".into());
    }
    epss.filter(|&e| e >= MIN_EPSS).map(|e| format!("EPSS {:.0}%", e * 100.0))
}

/// EPSS scores shown: most CVEs score well under 1%.
const MIN_EPSS: f64 = 0.01;

/// `→ 4.18.0`, that no fix exists yet, or (malware) to remove it.
fn fix_label(v: &Vulnerability) -> String {
    match &v.patched {
        _ if v.malware => "✕ remove it".to_string(),
        Some(p) => format!("→ {p}"),
        None => "no fix yet".to_string(),
    }
}

/// `CWE-79, CWE-1321`, or empty.
fn cwe_label(v: &Vulnerability) -> String {
    v.cwes.iter().map(|c| c.cwe_id.as_str()).collect::<Vec<_>>().join(", ")
}

/// The projects affected, e.g. `~/code/app, ~/code/api`.
fn projects_label(v: &Vulnerability) -> String {
    v.uses.iter().map(|u| u.project.as_str()).collect::<Vec<_>>().join(", ")
}

/// `dev`, `indirect` or `indirect via express`; nothing for a runtime dependency.
fn kind_label(kind: DepKind, via: Option<&str>) -> Option<String> {
    let kind = match kind {
        DepKind::Prod => None,
        DepKind::Indirect => Some("indirect"),
        DepKind::Dev => Some("dev"),
    };
    match (kind, via) {
        (Some(k), Some(v)) => Some(format!("{k} via {v}")),
        (k, _) => k.map(String::from),
    }
}

/// `golang.org/x/crypto 0.50.0`, or `lodash ≥4.17.0` from a manifest range.
fn fix_package_label(f: &Fix) -> String {
    format!("{} {}{}", f.package, if f.exact { "" } else { "≥" }, f.version)
}

/// `→ 0.52.0`, that no fix exists yet, or (malware) to remove it.
fn fix_target_label(f: &Fix) -> String {
    match &f.target {
        _ if f.malware => "✕ remove".to_string(),
        Some(t) => format!("→ {t}"),
        None => "no fix yet".to_string(),
    }
}

/// `8 advisories`.
fn advisories_label(f: &Fix) -> String {
    let n = f.advisories.len();
    format!("{n} {}", if n == 1 { "advisory" } else { "advisories" })
}

/// Caveats: may break, dev/indirect, advisories it leaves unfixed.
fn fix_notes(f: &Fix) -> Vec<String> {
    let mut v: Vec<String> = exploit_label(f.exploited, f.epss).into_iter().collect();
    if f.breaking {
        v.push("⚠ may break".to_string());
    }
    v.extend(kind_label(f.kind, f.via.as_deref()));
    if f.target.is_some() && f.unfixed > 0 {
        v.push(format!("{} without a fix", f.unfixed));
    }
    v
}

/// `archived`, or `no commits since 2022-03-01`.
fn unmaintained_label(u: &Unmaintained) -> String {
    if u.archived { "repo archived".into() } else { format!("no commits since {}", u.pushed) }
}

/// `256 in 15 projects · 42 upgrades · 3 ignored`.
fn vulns_heading(v: &VulnScan) -> String {
    let mut s = format!("{} in {} projects", v.items.len(), v.projects);
    if !v.fixes.is_empty() {
        _ = write!(s, " · {} {}", v.fixes.len(), if v.fixes.len() == 1 { "upgrade" } else { "upgrades" });
    }
    if v.ignored > 0 {
        _ = write!(s, " · {} ignored", v.ignored);
    }
    s
}

/// Repos across all tabs, each once (a repo can be in several).
fn unique_entries(report: &Report) -> Vec<&Entry> {
    let mut seen = HashSet::new();
    report.sections.iter().flat_map(|s| &s.entries).filter(|e| seen.insert(e.repo.full_name.as_str())).collect()
}

/// One line for the notification: trending/new counts, the top repo and vulnerabilities.
pub fn summary(report: &Report) -> String {
    let unique = unique_entries(report);
    let trending = unique.iter().filter(|e| e.trending_today.is_some()).count();
    let new = unique.iter().filter(|e| e.is_new).count();
    let mut msg = format!("{} repos · {trending} on GitHub Trending · {new} new", unique.len());
    if let Some(t) = unique.iter().max_by(|a, b| a.buzz.total_cmp(&b.buzz)) {
        _ = write!(msg, " · top: {}", t.repo.full_name);
    }
    if let Some(v) = &report.vulnerabilities {
        let serious = v.items.iter().filter(|i| i.severity <= Severity::High).count();
        let fresh = v.items.iter().filter(|i| i.is_new).count();
        _ = write!(msg, " · 🛡 {} vulnerabilities ({serious} high+, {fresh} new", v.items.len());
        match v.items.iter().filter(|i| i.malware).count() {
            0 => msg.push(')'),
            n => _ = write!(msg, ", 🚨 {n} malware)"),
        }
    }
    msg
}

#[cfg(test)]
pub(crate) mod fixture {
    use crate::deps::{DepKind, Ecosystem};
    use crate::model::*;
    use crate::signals::vulns::fixes;
    use crate::sources::advisories::Cwe;
    use crate::sources::github::Repo;

    fn info(name: &str, buzz: f64, is_new: bool) -> RepoInfo {
        RepoInfo {
            repo: Repo::test(name, 120, &["react"]),
            stars_per_day: 4.0,
            stars_delta: Some(7),
            is_new,
            trending_today: Some(50),
            hn: None,
            low_engagement: false,
            star_check: None,
            suspicious_stars: false,
            health: None,
            new_release: false,
            trend: vec![],
            buzz,
        }
    }

    pub fn vuln(id: &str, severity: Severity, is_new: bool) -> Vulnerability {
        Vulnerability {
            id: id.into(),
            cve: Some("CVE-2026-1".into()),
            summary: "Code | injection".into(),
            severity,
            cvss: Some(8.1),
            cwes: vec![Cwe { cwe_id: "CWE-94".into(), name: "Improper Control of Generation of Code".into() }],
            url: format!("https://github.com/advisories/{id}"),
            published: "2026-04-01".into(),
            ecosystem: Ecosystem::Npm,
            package: "lodash".into(),
            vulnerable: "<= 4.17.23".into(),
            patched: Some("4.18.0".into()),
            uses: vec![Usage {
                project: "~/code/app".into(),
                version: "4.17.15".into(),
                exact: true,
                kind: DepKind::Prod,
                via: None,
                patched: Some("4.18.0".into()),
                name: "lodash".into(),
                manager: Default::default(),
                manifest: "/home/me/code/app/package.json".into(),
            }],
            is_new,
            malware: false,
            exploited: false,
            epss: None,
        }
    }

    pub fn report() -> Report {
        Report {
            generated: "2026-10-25 08:00 UTC".into(),
            generated_at: "2026-10-25T08:00:00+00:00".into(),
            since: Some("2026-09-25".into()),
            compared_to: Some("2026-10-24".into()),
            sections: vec![Section {
                key: "frontend".into(),
                title: "Frontend".into(),
                topics: vec!["react".into()],
                note: None,
                entries: vec![
                    Entry { info: info("a/top", 60.0, true), matched: vec!["react".into()] },
                    Entry { info: info("b/second", 30.0, false), matched: vec!["react".into()] },
                ],
            }],
            vulnerabilities: Some({
                let items = vec![vuln("GHSA-aaaa", Severity::High, true), vuln("GHSA-bbbb", Severity::Low, false)];
                VulnScan {
                    folders: vec!["~/code".into()],
                    database: "the GitHub Advisory Database".into(),
                    projects: 2,
                    packages: 40,
                    fixes: fixes(&items),
                    items,
                    ignored: 1,
                    unmaintained: Vec::new(),
                }
            }),
            warnings: vec!["Hacker News unavailable (timeout); the HN signal is missing.".into()],
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn labels_exploited_before_epss() {
        assert_eq!(super::exploit_label(true, Some(0.5)).as_deref(), Some("🔥 exploited"));
        assert_eq!(super::exploit_label(false, Some(0.213)).as_deref(), Some("EPSS 21%"));
        assert_eq!(super::exploit_label(false, Some(0.001)), None);
    }

    use super::*;

    #[test]
    fn summary_counts_repos_and_vulnerabilities() {
        assert_eq!(
            summary(&fixture::report()),
            "2 repos · 2 on GitHub Trending · 1 new · top: a/top · 🛡 2 vulnerabilities (1 high+, 1 new)"
        );
    }

    #[test]
    fn vulnerability_labels() {
        let mut v = fixture::vuln("GHSA-x", Severity::Critical, false);
        assert_eq!((package_label(&v), fix_label(&v)), ("lodash 4.17.15".into(), "→ 4.18.0".into()));
        v.uses[0].exact = false;
        v.patched = None;
        assert_eq!((package_label(&v), fix_label(&v)), ("lodash ≥4.17.15".into(), "no fix yet".into()));
    }

    #[test]
    fn fix_labels() {
        let scan = fixture::report().vulnerabilities.unwrap();
        let f = &scan.fixes[0];
        assert_eq!(
            (fix_package_label(f), fix_target_label(f), advisories_label(f)),
            ("lodash 4.17.15".into(), "→ 4.18.0".into(), "2 advisories".into())
        );
        assert_eq!(vulns_heading(&scan), "2 in 2 projects · 1 upgrade · 1 ignored");
        let mut f = f.clone();
        (f.breaking, f.kind, f.unfixed) = (true, DepKind::Dev, 1);
        assert_eq!(fix_notes(&f), ["⚠ may break", "dev", "1 without a fix"]);
        (f.kind, f.via, f.malware) = (DepKind::Indirect, Some("express".into()), true);
        assert_eq!((fix_notes(&f)[1].as_str(), fix_target_label(&f)), ("indirect via express", "✕ remove".into()));
    }
}
