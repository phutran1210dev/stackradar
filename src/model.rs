//! The report's data: what the pipeline produces and every output format renders.

use std::ops::Deref;
use std::path::PathBuf;

use serde::Serialize;

use crate::deps::{DepKind, Ecosystem, Manager};
use crate::signals::inspect::{Health, StarCheck};
use crate::sources::advisories::Cwe;
use crate::sources::github::Repo;
use crate::sources::hn::HnBuzz;

/// Everything known about one repo. Computed once, then shared by every tab it's in.
#[derive(Serialize, Clone)]
pub struct RepoInfo {
    #[serde(flatten)]
    pub repo: Repo,
    pub stars_per_day: f64,
    /// Stars gained since the previous run's snapshot; None if not seen then
    pub stars_delta: Option<i64>,
    /// Absent from the previous run (only set when a previous run exists)
    pub is_new: bool,
    /// Stars today, if on github.com/trending
    pub trending_today: Option<u64>,
    /// Recent Hacker News discussion
    pub hn: Option<HnBuzz>,
    /// Many stars, almost no forks/issues
    pub low_engagement: bool,
    /// Sample of recent stargazers (repos with enough stars, token required)
    pub star_check: Option<StarCheck>,
    /// Most of that sample are throwaway accounts
    pub suspicious_stars: bool,
    pub health: Option<Health>,
    /// The latest release came out since the previous run
    pub new_release: bool,
    /// Stars at earlier runs as (days ago, stars), oldest first
    pub trend: Vec<(i64, u64)>,
    pub buzz: f64,
}

#[derive(Serialize)]
pub struct Entry {
    #[serde(flatten)]
    pub info: RepoInfo,
    /// Which of the tab's topics (or, on "For you", your dependencies) matched
    pub matched: Vec<String>,
}

impl Deref for Entry {
    type Target = RepoInfo;
    fn deref(&self) -> &RepoInfo {
        &self.info
    }
}

#[derive(Serialize)]
pub struct Section {
    pub key: String,
    pub title: String,
    pub topics: Vec<String>,
    pub note: Option<String>,
    pub entries: Vec<Entry>,
}

#[derive(Serialize)]
pub struct Report {
    pub generated: String,
    /// RFC 3339, so the page can warn when it is stale
    pub generated_at: String,
    /// Start of the new-repo window; None for a vulnerability-only audit
    pub since: Option<String>,
    pub compared_to: Option<String>,
    pub sections: Vec<Section>,
    /// None when no `scan` folders are configured
    pub vulnerabilities: Option<VulnScan>,
    /// Sources that failed or were skipped, so the report is partial
    pub warnings: Vec<String>,
}

/// Advisories affecting the dependency versions your projects use.
#[derive(Serialize)]
pub struct VulnScan {
    /// The folders scanned for projects, `~/code`-style
    pub folders: Vec<String>,
    /// Where the advisories came from, e.g. "the GitHub Advisory Database"
    pub database: String,
    pub projects: usize,
    /// Distinct package versions checked
    pub packages: usize,
    /// Most severe first
    pub items: Vec<Vulnerability>,
    /// `items` grouped into one upgrade per package, most urgent first
    pub fixes: Vec<Fix>,
    /// Matched by an ignore rule, so left out of `items`
    pub ignored: usize,
    /// Direct dependencies whose GitHub repo is archived or abandoned (not checked by `audit`)
    pub unmaintained: Vec<Unmaintained>,
}

/// A direct dependency whose source repo is archived or has had no commits for a long time.
#[derive(Debug, Clone, Serialize)]
pub struct Unmaintained {
    pub ecosystem: Ecosystem,
    pub package: String,
    /// `owner/name` on GitHub
    pub repo: String,
    pub archived: bool,
    /// Date of the last push (YYYY-MM-DD)
    pub pushed: String,
    pub projects: Vec<String>,
}

/// Declared most severe first, so sorting ascending puts critical on top.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

impl Severity {
    /// GitHub's names (`moderate` is the older name of `medium`).
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" | "moderate" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Unknown,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Unknown => "UNKNOWN",
        }
    }
}

/// One advisory as it affects one of your packages.
#[derive(Debug, Clone, Serialize)]
pub struct Vulnerability {
    /// GHSA id
    pub id: String,
    pub cve: Option<String>,
    pub summary: String,
    pub severity: Severity,
    pub cvss: Option<f64>,
    /// Weakness classes
    pub cwes: Vec<Cwe>,
    pub url: String,
    pub published: String,
    pub ecosystem: Ecosystem,
    pub package: String,
    /// Affected versions, e.g. `>= 4.0.0, < 4.17.21`
    pub vulnerable: String,
    /// Lowest fixed version of the range your version is in, if one exists
    pub patched: Option<String>,
    /// Your projects using an affected version
    pub uses: Vec<Usage>,
    /// Not reported by the previous run
    pub is_new: bool,
    /// A malicious package (GitHub's malware advisories), not a vulnerable one: remove it
    pub malware: bool,
    /// In CISA's Known Exploited Vulnerabilities catalog: attackers are using it
    pub exploited: bool,
    /// FIRST's EPSS score: the chance (0–1) of exploitation in the next 30 days
    pub epss: Option<f64>,
}

impl Vulnerability {
    /// Identity across runs (one advisory can affect several of your packages).
    pub fn key(&self) -> String {
        format!("{}:{}", self.id, self.package)
    }

    /// The most important way any of your projects depends on the package.
    pub fn kind(&self) -> DepKind {
        self.uses.iter().map(|u| u.kind).min().unwrap_or_default()
    }

    /// The direct dependency that pulls the package in, unless a project depends on it directly.
    pub fn via(&self) -> Option<&str> {
        Usage::via_of(&self.uses)
    }
}

/// One package upgrade, from one version in use, and the advisories it resolves.
#[derive(Debug, Clone, Serialize)]
pub struct Fix {
    pub ecosystem: Ecosystem,
    pub package: String,
    /// The version your projects use
    pub version: String,
    /// From a lockfile or pin in every project (otherwise a manifest's lowest allowed one)
    pub exact: bool,
    /// Lowest version fixing every advisory that has a fix; None if none has one yet
    pub target: Option<String>,
    /// The upgrade crosses a semver-breaking boundary, so it may need code changes
    pub breaking: bool,
    /// The worst advisory's
    pub severity: Severity,
    /// GHSA ids, most severe first
    pub advisories: Vec<String>,
    /// Advisories without a published fix, which `target` doesn't resolve
    pub unfixed: usize,
    pub projects: Vec<String>,
    /// The most important way any project depends on the package
    pub kind: DepKind,
    /// For a package pulled in by another, the direct dependency it comes through
    pub via: Option<String>,
    /// Shell command that upgrades (or, for malware, removes) it, run in the project folder
    pub command: Option<String>,
    /// Resolves an advisory the previous run didn't report
    pub is_new: bool,
    /// The package is malware: remove it rather than upgrade
    pub malware: bool,
    /// Any of its advisories is in CISA's Known Exploited Vulnerabilities catalog
    pub exploited: bool,
    /// The highest EPSS score among its advisories
    pub epss: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Usage {
    pub project: String,
    pub version: String,
    /// From a lockfile or pin; otherwise the lowest version the manifest allows
    pub exact: bool,
    pub kind: DepKind,
    /// For a package pulled in by another, the direct dependency it comes through
    pub via: Option<String>,
    /// Lowest fixed version of the advisory range this version is in, if one exists
    pub patched: Option<String>,
    /// The package name as the project spells it (advisories match names as spelled)
    #[serde(skip)]
    pub name: String,
    #[serde(skip)]
    pub manager: Manager,
    #[serde(skip)]
    pub manifest: PathBuf,
}

impl Usage {
    /// Declared by the project, not pulled in by another dependency.
    pub fn is_direct(&self) -> bool {
        self.via.is_none() && self.kind != DepKind::Indirect
    }

    /// The direct dependency that pulls a package in, unless one of `uses` is direct.
    pub fn via_of<'a>(uses: impl IntoIterator<Item = &'a Usage> + Clone) -> Option<&'a str> {
        if uses.clone().into_iter().any(Usage::is_direct) {
            return None;
        }
        uses.into_iter().find_map(|u| u.via.as_deref())
    }
}
