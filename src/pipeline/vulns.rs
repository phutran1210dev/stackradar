//! The vulnerability step: advisories for your projects' dependencies, minus the ignored
//! ones, with what is new since the previous run marked and grouped into upgrades.

use std::collections::{BTreeSet, HashSet};

use chrono::Utc;

use super::Warnings;
use crate::deps::{Ecosystem, Project};
use crate::model::{VulnScan, Vulnerability};
use crate::signals::vulns;
use crate::sources::advisories::AdvisoryDb;
use crate::sources::exploits::Exploits;
use crate::store::ignore::Rule;
use crate::store::seen::Seen;
use crate::util::par_map;

const SEEN_FILE: &str = "vulns-seen.json";

/// Advisories affecting `projects`, marking those not reported by the previous run.
pub(super) fn scan(
    db: &dyn AdvisoryDb,
    projects: &[Project],
    rules: &[Rule],
    today: &str,
    warnings: &Warnings,
) -> VulnScan {
    let (mut scan, complete) = check(db, Some(&Exploits::new()), projects, rules, warnings);
    // A failed query must not make its vulnerabilities look fixed (and new next time).
    if complete {
        let mut seen = Seen::load(SEEN_FILE);
        let new = seen.update(scan.items.iter().map(|v| v.key()), today);
        for v in &mut scan.items {
            v.is_new = new.contains(&v.key());
        }
        if let Err(e) = seen.save() {
            eprintln!("⚠  Could not save {}: {e}", seen.path().display());
        }
        sort(&mut scan.items);
        scan.fixes = vulns::fixes(&scan.items);
    }
    scan
}

/// Advisories affecting `projects` that no rule ignores, marked from `exploits` when given,
/// most urgent first, and whether every query succeeded. Reads and writes no local state.
pub(super) fn check(
    db: &dyn AdvisoryDb,
    exploits: Option<&Exploits>,
    projects: &[Project],
    rules: &[Rule],
    warnings: &Warnings,
) -> (VulnScan, bool) {
    let index = vulns::index(projects);
    let packages: usize =
        index.values().map(|uses| uses.iter().map(|u| &u.version).collect::<HashSet<_>>().len()).sum();
    let queries: Vec<(Ecosystem, Vec<String>)> = vulns::queries(&index);
    eprintln!(
        "→ Checking {packages} dependency versions of {} projects against {} for advisories and malware…",
        projects.len(),
        db.name()
    );
    let results = par_map(&queries, 4, |(eco, batch)| db.lookup(*eco, batch));
    let mut advisories = Vec::new();
    let mut failed = 0;
    for r in results {
        match r {
            Ok(a) => advisories.extend(a),
            Err(e) => {
                failed += 1;
                eprintln!("  ✗ advisories — {e}");
            }
        }
    }
    if failed > 0 {
        warnings.add(format!("{failed}/{} advisory queries failed; the vulnerability list is partial.", queries.len()));
    }
    let found = vulns::attribute(advisories, &index);
    let (mut items, ignored, expired) = vulns::apply_ignores(found, rules, Utc::now().date_naive());
    for r in expired {
        eprintln!(
            "ℹ  The ignore rule for {} expired on {}; it is reported again.",
            r.label(),
            r.until.unwrap_or_default()
        );
    }
    if let Some(feeds) = exploits {
        mark_exploits(feeds, &mut items, warnings);
    }
    sort(&mut items);
    let fixes = vulns::fixes(&items);
    (
        VulnScan {
            folders: Vec::new(),
            database: db.name().into(),
            projects: projects.len(),
            packages,
            items,
            fixes,
            ignored,
            unmaintained: Vec::new(),
        },
        failed == 0,
    )
}

/// Mark the `items` with a CVE in CISA's KEV catalog, and their EPSS scores. A feed that
/// can't be read is a warning: nothing looks safer than it is without saying so.
fn mark_exploits(feeds: &Exploits, items: &mut [Vulnerability], warnings: &Warnings) {
    let cves: BTreeSet<String> = items.iter().filter_map(|v| v.cve.clone()).collect();
    if cves.is_empty() {
        return;
    }
    eprintln!("→ Checking {} CVEs against CISA's exploited catalog and EPSS…", cves.len());
    let cves: Vec<String> = cves.into_iter().collect();
    let (kev, epss) = std::thread::scope(|s| {
        let kev = s.spawn(|| feeds.known_exploited());
        (kev.join().expect("KEV thread panicked"), feeds.epss(&cves))
    });
    match kev {
        Ok(kev) => items.iter_mut().for_each(|v| v.exploited = v.cve.as_ref().is_some_and(|c| kev.contains(c))),
        Err(e) => warnings.add(format!("Could not read CISA's exploited catalog ({e}); nothing is marked exploited.")),
    }
    match epss {
        Ok(scores) => items.iter_mut().for_each(|v| v.epss = v.cve.as_ref().and_then(|c| scores.get(c).copied())),
        Err(e) => warnings.add(format!("Could not read EPSS scores ({e}).")),
    }
}

/// Malware first, then what is being exploited, then by severity, then runtime before dev
/// dependencies, then new first, then EPSS and CVSS score.
fn sort(items: &mut [Vulnerability]) {
    items.sort_by(|a, b| {
        b.malware
            .cmp(&a.malware)
            .then(b.exploited.cmp(&a.exploited))
            .then(a.severity.cmp(&b.severity))
            .then(a.kind().cmp(&b.kind()))
            .then(b.is_new.cmp(&a.is_new))
            .then(b.epss.unwrap_or(0.0).total_cmp(&a.epss.unwrap_or(0.0)))
            .then(b.cvss.unwrap_or(0.0).total_cmp(&a.cvss.unwrap_or(0.0)))
            .then_with(|| a.package.cmp(&b.package))
    });
}
