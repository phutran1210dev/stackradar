mod cli;
mod deps;
mod model;
mod notify;
mod pipeline;
mod platform;
mod report;
mod schedule;
mod signals;
mod sources;
mod store;
mod uninstall;
mod update;
mod util;

use std::path::Path;

use clap::Parser;

use cli::{Args, Command};
use deps::DepKind;
use model::Report;
use sources::exploits::Exploits;
use sources::github::GitHub;
use sources::osv::Osv;
use store::ignore::{self, Rule};
use store::{config, paths, private};

/// Exit code for errors (1 means `audit` found vulnerabilities).
const ERROR_EXIT: i32 = 2;

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("✗ {msg}");
    std::process::exit(ERROR_EXIT);
}

/// Reports name your projects and their weaknesses, so only you can read them.
fn write_output(path: &Path, content: &str, label: &str) {
    match private::write(path, content.as_bytes()) {
        Ok(()) => println!("✓ {label}: {}", path.display()),
        Err(e) => fail(format!("Failed to write {}: {e}", path.display())),
    }
}

/// The optional Markdown and JSON exports.
fn write_exports(report: &Report, md: Option<&Path>, json: Option<&Path>, top: usize) {
    if let Some(p) = md {
        write_output(p, &report::markdown(report, top), "Markdown digest");
    }
    if let Some(p) = json {
        write_output(p, &serde_json::to_string_pretty(report).expect("report serializes"), "JSON data");
    }
}

/// `stackradar audit`: touches no config, history or cache, and exits with the verdict.
fn audit(a: &cli::Audit) -> ! {
    let dirs: Vec<_> = a
        .paths
        .iter()
        .map(|p| match std::fs::canonicalize(p) {
            Ok(d) if d.is_dir() => d,
            Ok(_) => fail(format!("{} is not a folder", p.display())),
            Err(e) => fail(format!("{}: {e}", p.display())),
        })
        .collect();
    let rules = a.ignore.as_deref().map(|p| ignore::load(p).unwrap_or_else(|e| fail(e))).unwrap_or_default();
    let exploits = a.exploits.then(Exploits::new);
    let report = if a.osv {
        pipeline::audit(&Osv::new(), exploits.as_ref(), &dirs, &rules)
    } else {
        let gh = GitHub::new();
        if !gh.is_authenticated() {
            eprintln!(
                "⚠  No GITHUB_TOKEN: GitHub allows 60 advisory requests an hour. Pass --osv to use OSV.dev instead."
            );
        }
        pipeline::audit(&gh, exploits.as_ref(), &dirs, &rules)
    };
    print!("{}", report::terminal(&report, a.top));
    if let Some(p) = &a.html {
        write_output(p, &report::html(&report), "HTML report");
    }
    write_exports(&report, a.md.as_deref(), a.json.as_deref(), a.top);
    if let Some(p) = &a.sarif {
        let base = std::env::current_dir().unwrap_or_default();
        write_output(p, &report::sarif(&report, &base), "SARIF");
    }
    if !report.warnings.is_empty() {
        fail("The check is incomplete (see the warnings above).");
    }
    let items = report.vulnerabilities.iter().flat_map(|v| &v.items);
    if let Some(p) = &a.write_baseline {
        let today = chrono::Utc::now().date_naive();
        let mut baseline: Vec<Rule> = rules.into_iter().filter(|r| !r.is_expired(today)).collect();
        baseline.extend(items.map(|v| Rule {
            id: v.id.clone(),
            package: Some(v.package.clone()),
            reason: Some(format!("baseline {today}")),
            until: None,
        }));
        write_output(p, &ignore::to_toml(&baseline), "Baseline");
        std::process::exit(0);
    }
    let failing = failing(&report, a);
    if failing > 0 {
        eprintln!("✗ {failing} vulnerabilities at or above the --fail-on severity");
        std::process::exit(1);
    }
    std::process::exit(0);
}

/// Findings at or above `--fail-on`, the ones that make `audit` exit 1. Malware in a dev
/// dependency still counts with `--ignore-dev`: it runs on your machine and in CI.
fn failing(report: &Report, a: &cli::Audit) -> usize {
    let items = report.vulnerabilities.iter().flat_map(|v| &v.items);
    items.filter(|v| a.fail_on.fails(v.severity) && !(a.ignore_dev && v.kind() == DepKind::Dev && !v.malware)).count()
}

/// `stackradar uninstall`: lists what goes, asks unless `--yes`, then removes it.
fn uninstall(u: &cli::Uninstall) {
    let plan = uninstall::Plan::new(u.keep_data).unwrap_or_else(|e| fail(e));
    println!("This removes:\n{}", plan.describe());
    if !u.yes {
        print!("Continue? [y/N] ");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        let mut answer = String::new();
        let _ = std::io::stdin().read_line(&mut answer);
        if !matches!(answer.trim(), "y" | "Y" | "yes") {
            println!("Nothing removed.");
            return;
        }
    }
    for msg in plan.run().unwrap_or_else(|e| fail(e)) {
        println!("✓ {msg}");
    }
}

fn main() {
    let args = Args::parse();
    match &args.command {
        Some(Command::Audit(a)) => audit(a),
        Some(Command::Uninstall(u)) => return uninstall(u),
        Some(Command::Update(u)) => {
            return match update::run(u.check) {
                Ok(msg) => println!("✓ {msg}"),
                Err(e) => fail(e),
            };
        }
        None => {}
    }
    if let Some(msg) = config::migrate_legacy_dir() {
        eprintln!("{msg}");
    }
    let out = args.out.clone().unwrap_or_else(|| paths::data_dir().join("trending.html"));
    if args.view {
        if !out.exists() {
            fail(format!("No report at {} yet — run stackradar first.", out.display()));
        }
        platform::open(&out);
        return;
    }
    if args.install_schedule || args.uninstall_schedule {
        let result = if args.install_schedule { schedule::install() } else { schedule::uninstall() };
        match result {
            Ok(msg) => println!("✓ {msg}"),
            Err(e) => fail(e),
        }
        return;
    }
    if args.init_config {
        match config::init() {
            Ok(p) => println!("✓ Wrote {} — edit categories/topics/exclude there.", p.display()),
            Err(e) => fail(e),
        }
        return;
    }
    let config = config::load().unwrap_or_else(|e| fail(format!("Invalid config — {e}")));
    let gh = GitHub::new();
    if !gh.is_authenticated() {
        eprintln!(
            "⚠  No GITHUB_TOKEN and `gh auth token` unavailable — search is limited to 10 req/min and star checks are skipped."
        );
    }

    // Created (or tightened) up front: the run writes history, caches and the report there.
    let data = paths::data_dir();
    private::create_dir(&data).unwrap_or_else(|e| fail(format!("Cannot create {}: {e}", data.display())));
    let report = pipeline::run(&gh, &config, &args).unwrap_or_else(|e| fail(e));
    print!("{}", report::terminal(&report, args.top));

    if let Some(dir) = out.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).unwrap_or_else(|e| fail(format!("Cannot create {}: {e}", dir.display())));
    }
    write_output(&out, &report::html(&report), "HTML report");
    write_exports(&report, args.md.as_deref(), args.json.as_deref(), args.top);
    if args.notify {
        notify::send(&report, config.webhook.as_deref());
    }
    if args.open {
        platform::open(&out);
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::report::fixture;

    #[test]
    fn audit_fails_on_findings_at_the_threshold() {
        let audit = |flags: &[&str]| match Args::parse_from([&["stackradar", "audit", "."], flags].concat()).command {
            Some(Command::Audit(a)) => a,
            _ => unreachable!(),
        };
        let report = fixture::report();
        let all = failing(&report, &audit(&["--fail-on", "low"]));
        assert!(all > 0);
        assert!(failing(&report, &audit(&["--fail-on", "critical"])) < all);
    }
}
