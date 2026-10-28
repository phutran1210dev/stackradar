use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::model::Severity;

/// Rising GitHub repos for your stack (default: React / React Native / Next.js,
/// Node / Express / NestJS, AI), plus security advisories affecting your own projects'
/// dependencies. Categories, project folders and watched repos live in
/// ~/.stackradar/config.toml.
///
/// Repos are ranked by "buzz": being on github.com/trending, recent Hacker News
/// discussion, stars gained since the previous run, and launch velocity — with
/// low-engagement and bought-looking stars penalized. Candidates are repos created in the
/// last N days plus any repo on GitHub Trending today that matches your topics.
#[derive(Parser)]
#[command(version)]
pub struct Args {
    #[command(subcommand)]
    pub command: Option<Command>,
    /// Only repos created within this many days
    #[arg(short, long, default_value_t = 30)]
    pub days: i64,
    /// Max repos fetched per topic (GitHub caps at 100)
    #[arg(short, long, default_value_t = 30, value_parser = clap::value_parser!(u8).range(1..=100))]
    pub limit: u8,
    /// Minimum star count
    #[arg(short = 's', long, default_value_t = 20)]
    pub min_stars: u64,
    /// Rows per category in the terminal and the Markdown digest
    #[arg(short, long, default_value_t = 10)]
    pub top: usize,
    /// HTML report output path [default: ~/.stackradar/trending.html]
    #[arg(short, long)]
    pub out: Option<PathBuf>,
    /// Also write a Markdown digest (for Slack, Notion, a README…)
    #[arg(long, value_name = "PATH")]
    pub md: Option<PathBuf>,
    /// Also write the full data as JSON
    #[arg(long, value_name = "PATH")]
    pub json: Option<PathBuf>,
    /// Open the HTML report in the browser when done
    #[arg(long)]
    pub open: bool,
    /// Show a desktop notification summarizing the update, and post a digest to the
    /// config's webhook if one is set
    #[arg(long)]
    pub notify: bool,
    /// Open the latest report without fetching anything
    #[arg(long)]
    pub view: bool,
    /// Write the default config to ~/.stackradar/config.toml and exit
    #[arg(long)]
    pub init_config: bool,
    /// Auto-update: run daily at 08:00 and 20:00 (macOS launchd, Windows Task Scheduler, Linux systemd user timer;
    /// prints a crontab line elsewhere), then exit
    #[arg(long, conflicts_with = "uninstall_schedule")]
    pub install_schedule: bool,
    /// Remove the auto-update schedule, then exit
    #[arg(long)]
    pub uninstall_schedule: bool,
}

#[derive(Subcommand)]
pub enum Command {
    /// Check the projects under PATHS for known vulnerabilities in their dependencies, and
    /// nothing else.
    ///
    /// Only manifests and lockfiles are read (never source code), nothing outside PATHS
    /// (symlinks are skipped), and only package names and versions are sent, to the GitHub
    /// Advisory Database (or with --osv to OSV.dev). Nothing is written unless
    /// --html/--md/--json/--sarif is given.
    ///
    /// Exit code: 0 = nothing at or above --fail-on, 1 = vulnerabilities found,
    /// 2 = error or incomplete check.
    ///
    /// To fail only on new vulnerabilities, record the current ones once with
    /// --write-baseline FILE, then pass --ignore FILE on every run.
    Audit(Box<Audit>),
    /// Remove stackradar from this computer: the auto-update schedule, ~/.stackradar
    /// (config, history and reports) and the stackradar binary itself.
    Uninstall(Uninstall),
    /// Replace stackradar with the latest release's build for this platform (a cargo
    /// install is left to cargo).
    Update(Update),
}

#[derive(clap::Args)]
pub struct Update {
    /// Only say whether a newer version is out
    #[arg(long)]
    pub check: bool,
}

#[derive(clap::Args)]
pub struct Uninstall {
    /// Don't ask for confirmation
    #[arg(short, long)]
    pub yes: bool,
    /// Keep ~/.stackradar (config, history and reports)
    #[arg(long)]
    pub keep_data: bool,
}

#[derive(clap::Args)]
pub struct Audit {
    /// Folders to check (each searched up to 3 levels deep for projects)
    #[arg(required = true)]
    pub paths: Vec<PathBuf>,
    /// Lowest severity that makes the exit code 1
    #[arg(long, value_enum, default_value_t = FailOn::High)]
    pub fail_on: FailOn,
    /// Don't fail on vulnerabilities only in dev, test or build dependencies
    #[arg(long)]
    pub ignore_dev: bool,
    /// Look up advisories in OSV.dev instead of GitHub's database: no token or rate limit,
    /// and the ecosystems' own databases (RustSec, PyPA, Go) too
    #[arg(long)]
    pub osv: bool,
    /// Mark vulnerabilities attackers are exploiting (CISA's KEV catalog) and their EPSS
    /// scores, and list those first. Sends their CVE ids to cisa.gov and api.first.org
    #[arg(long)]
    pub exploits: bool,
    /// Leave out the advisories listed in this file's [[ignore]] rules (same format as the
    /// config's, e.g. a --write-baseline file)
    #[arg(long, value_name = "FILE")]
    pub ignore: Option<PathBuf>,
    /// Write every vulnerability found as an ignore rule to FILE (keeping the unexpired
    /// rules from --ignore), then exit 0
    #[arg(long, value_name = "FILE")]
    pub write_baseline: Option<PathBuf>,
    /// Rows printed in the terminal
    #[arg(short, long, default_value_t = 50)]
    pub top: usize,
    /// Also write an HTML report
    #[arg(long, value_name = "PATH")]
    pub html: Option<PathBuf>,
    /// Also write a Markdown report
    #[arg(long, value_name = "PATH")]
    pub md: Option<PathBuf>,
    /// Also write the full data as JSON
    #[arg(long, value_name = "PATH")]
    pub json: Option<PathBuf>,
    /// Also write SARIF, for GitHub code scanning (paths relative to the current folder)
    #[arg(long, value_name = "PATH")]
    pub sarif: Option<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum FailOn {
    Critical,
    High,
    Medium,
    Low,
    /// Any vulnerability, including unknown severity
    Any,
    /// Never: always exit 0 when the check completes
    Never,
}

impl FailOn {
    /// Whether a vulnerability of this severity fails the audit.
    pub fn fails(self, severity: Severity) -> bool {
        let threshold = match self {
            FailOn::Critical => Severity::Critical,
            FailOn::High => Severity::High,
            FailOn::Medium => Severity::Medium,
            FailOn::Low => Severity::Low,
            FailOn::Any => Severity::Unknown,
            FailOn::Never => return false,
        };
        severity <= threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_on_threshold() {
        assert!(FailOn::High.fails(Severity::Critical));
        assert!(FailOn::High.fails(Severity::High));
        assert!(!FailOn::High.fails(Severity::Medium));
        assert!(!FailOn::Low.fails(Severity::Unknown));
        assert!(FailOn::Any.fails(Severity::Unknown));
        assert!(!FailOn::Never.fails(Severity::Critical));
    }
}
