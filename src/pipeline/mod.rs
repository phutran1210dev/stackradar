//! One scan: gather candidates → describe each repo once → rank them into sections;
//! alongside, check your projects' dependencies for advisories.

mod describe;
mod gather;
mod health;
mod sections;
mod vulns;

use std::sync::Mutex;

use std::path::PathBuf;

use chrono::{DateTime, Duration, NaiveDate, Utc};

use crate::cli::Args;
use crate::deps::{self, Project};
use crate::model::{Report, VulnScan};
use crate::sources::advisories::AdvisoryDb;
use crate::sources::exploits::Exploits;
use crate::sources::github::GitHub;
use crate::sources::osv::Osv;
use crate::store::config::Config;
use crate::store::history::History;
use crate::store::ignore::Rule;
use crate::store::paths;

/// Unreadable files and folders listed one by one; the rest are counted.
const MAX_PROBLEMS: usize = 10;

/// Problems that make the report partial: printed as they happen and listed in the report.
#[derive(Default)]
pub struct Warnings(Mutex<Vec<String>>);

impl Warnings {
    pub fn add(&self, msg: String) {
        eprintln!("⚠  {msg}");
        self.0.lock().unwrap_or_else(|e| e.into_inner()).push(msg);
    }

    fn into_vec(self) -> Vec<String> {
        self.0.into_inner().unwrap_or_else(|e| e.into_inner())
    }
}

/// Fetch, score and rank; records today's stars in the history as a side effect.
pub fn run(gh: &GitHub, config: &Config, args: &Args) -> Result<Report, String> {
    let now = Utc::now();
    let today = now.date_naive().to_string();
    let since = (now - Duration::days(args.days)).format("%Y-%m-%d").to_string();
    let warnings = Warnings::default();
    let dirs = config.scan_dirs();
    // Without a token GitHub allows 60 advisory requests an hour; OSV.dev has no limit.
    let osv = Osv::new();
    let db: &dyn AdvisoryDb = if gh.is_authenticated() { gh } else { &osv };

    // The projects and their advisories need nothing from the repos, so they're read and
    // fetched alongside them.
    let (gathered, scanned) = std::thread::scope(|s| {
        let vulns = (!dirs.is_empty()).then(|| {
            s.spawn(|| {
                let projects = scan(&dirs, &warnings);
                let vulns = VulnScan {
                    folders: folders(&dirs),
                    unmaintained: health::unmaintained(gh, &projects, now, &warnings),
                    ..vulns::scan(db, &projects, &config.ignore, &today, &warnings)
                };
                (projects, vulns)
            })
        });
        let gathered = gather::gather(gh, config, args, &since, now, &warnings);
        (gathered, vulns.map(|h| h.join().expect("vulnerability thread panicked")))
    });
    let gather::Gathered { candidates, trending, hn } = gathered?;
    let (projects, vulnerabilities) = scanned.map_or((Vec::new(), None), |(p, v)| (p, Some(v)));

    let mut history = History::load();
    let prev = history.previous(&today).map(|(d, s)| (d.to_string(), s.clone()));
    let ctx = describe::Context {
        trending: &trending,
        hn: &hn,
        prev: prev.as_ref().and_then(|(d, s)| Some((NaiveDate::parse_from_str(d, "%Y-%m-%d").ok()?, s))),
        history: &history,
        now,
    };
    let infos = describe::describe(gh, candidates.repos, &ctx, &warnings);

    let mut sections = sections::categories(config, candidates.by_cat, &infos);
    if !dirs.is_empty() {
        sections.push(sections::for_you(config, &projects, &infos));
    }
    if !config.watch.is_empty() {
        sections.push(sections::watching(&candidates.watched, &infos));
    }

    history.record(&today, infos.values().map(|i| (i.repo.full_name.clone(), i.repo.stargazers_count)));
    if let Err(e) = history.save() {
        eprintln!("⚠  Could not save history {}: {e}", history.path().display());
    }
    if !candidates.excluded.is_empty() {
        println!("({} repos hidden by exclude list)", candidates.excluded.len());
    }
    Ok(Report {
        since: Some(since),
        compared_to: prev.map(|(d, _)| d),
        sections,
        vulnerabilities,
        ..empty_report(now, warnings)
    })
}

/// Only the vulnerability check, for the projects under `dirs` minus what `rules` ignore,
/// marked from `exploits` only if given: nothing else is fetched, nothing outside `dirs` is
/// read, and no local state is read or written.
pub fn audit(db: &dyn AdvisoryDb, exploits: Option<&Exploits>, dirs: &[PathBuf], rules: &[Rule]) -> Report {
    let warnings = Warnings::default();
    let projects = scan(dirs, &warnings);
    let (vulns, _) = vulns::check(db, exploits, &projects, rules, &warnings);
    Report { vulnerabilities: Some(VulnScan { folders: folders(dirs), ..vulns }), ..empty_report(Utc::now(), warnings) }
}

/// `dirs` as shown in the report.
fn folders(dirs: &[PathBuf]) -> Vec<String> {
    dirs.iter().map(|d| paths::tilde(d)).collect()
}

/// The projects under `dirs`, warning about what couldn't be read and when there are none.
fn scan(dirs: &[PathBuf], warnings: &Warnings) -> Vec<Project> {
    let (projects, problems) = deps::scan(dirs);
    for p in problems.iter().take(MAX_PROBLEMS) {
        warnings.add(format!("Skipped {p}; the dependencies there were not checked."));
    }
    if problems.len() > MAX_PROBLEMS {
        warnings.add(format!("Skipped {} more files or folders that couldn't be read.", problems.len() - MAX_PROBLEMS));
    }
    if projects.is_empty() {
        warnings.add(format!("No projects found under {dirs:?} (looked for {}).", deps::MANIFESTS));
    }
    projects
}

fn empty_report(now: DateTime<Utc>, warnings: Warnings) -> Report {
    Report {
        generated: now.format("%Y-%m-%d %H:%M UTC").to_string(),
        generated_at: now.to_rfc3339(),
        since: None,
        compared_to: None,
        sections: Vec::new(),
        vulnerabilities: None,
        warnings: warnings.into_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::Ecosystem;
    use crate::deps::testdir::TestDir;
    use crate::signals::vulns::tests::advisory;
    use crate::sources::advisories::Advisory;

    /// Answers every lookup the same way.
    struct Fake(Result<Vec<Advisory>, String>);

    impl AdvisoryDb for Fake {
        fn name(&self) -> &'static str {
            "Fake"
        }

        fn lookup(&self, _: Ecosystem, _: &[String]) -> Result<Vec<Advisory>, String> {
            self.0.clone()
        }
    }

    fn audit_(db: &Fake, dirs: &[PathBuf], rules: &[Rule]) -> Report {
        audit(db, None, dirs, rules)
    }

    #[test]
    fn audit_reports_findings_and_incomplete_checks() {
        let t = TestDir::new("pipeline-audit");
        t.file("app/package.json", r#"{"dependencies":{"lodash":"4.17.15"}}"#);
        let dirs = [t.root().to_path_buf()];
        let lodash = advisory("GHSA-1", "npm", &[("lodash", "< 4.17.21", Some("4.17.21"))]);

        let report = audit_(&Fake(Ok(vec![lodash.clone()])), &dirs, &[]);
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        let scan = report.vulnerabilities.unwrap();
        assert_eq!((scan.items.len(), scan.folders), (1, vec![paths::tilde(&dirs[0])]));

        let rule = Rule { id: "GHSA-1".into(), package: None, reason: None, until: None };
        let scan = audit_(&Fake(Ok(vec![lodash])), &dirs, &[rule]).vulnerabilities.unwrap();
        assert_eq!((scan.items.len(), scan.ignored), (0, 1));

        // Incomplete (exit 2): a lookup failed, or a lockfile couldn't be read.
        assert!(!audit_(&Fake(Err("HTTP 502".into())), &dirs, &[]).warnings.is_empty());
        t.file("app/package-lock.json", "{");
        let report = audit_(&Fake(Ok(Vec::new())), &dirs, &[]);
        assert!(report.warnings.iter().any(|w| w.contains("package-lock.json")), "{:?}", report.warnings);
    }
}
