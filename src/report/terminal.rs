//! The terminal tables.

use std::fmt::Write;

use super::{
    advisories_label, change_label, fix_notes, fix_package_label, fix_target_label, heading, severity_label,
    signal_labels, unmaintained_label, vulns_heading,
};
use crate::model::Report;
use crate::util::truncate;

/// The header line, top `top` repos per category and the top `top` upgrades that fix vulnerabilities.
pub fn terminal(report: &Report, top: usize) -> String {
    let mut s = String::new();
    if report.since.is_some() {
        match &report.compared_to {
            Some(d) => _ = writeln!(s, "Δ = stars gained since run on {d}"),
            None => s.push_str("First run — star deltas appear from the next day's run on.\n"),
        }
        s.push_str(
            "Ranked by buzz · 🔥 GitHub Trending today · 💬 Hacker News · 🚩 suspicious stars · ⚠ low engagement\n",
        );
    }
    for sec in &report.sections {
        _ = writeln!(s, "\n━━ {} — {} repos ━━", heading(sec), sec.entries.len());
        for (i, e) in sec.entries.iter().take(top).enumerate() {
            _ = writeln!(
                s,
                "{:>2}. {:>3.0}  {:<42} ★{:>6}  ⑂{:>5}  +{:>6.1}★/day  {:>6}  {}  {}",
                i + 1,
                e.buzz,
                truncate(&e.repo.full_name, 42),
                e.repo.stargazers_count,
                e.repo.forks_count,
                e.stars_per_day,
                change_label(e),
                e.repo.html_url,
                signal_labels(e).join(" · "),
            );
        }
    }
    if let Some(v) = &report.vulnerabilities {
        _ = writeln!(s, "\n━━ 🛡 Vulnerabilities — {} ━━", vulns_heading(v));
        if !v.folders.is_empty() {
            _ = writeln!(s, "Scanned {}", v.folders.join(", "));
        }
        if v.items.is_empty() && v.ignored > 0 {
            s.push_str("Nothing left after the ignore rules.\n");
        } else if v.items.is_empty() {
            _ = writeln!(s, "No known advisories for the {} dependency versions checked.", v.packages);
        } else {
            s.push_str("One row per package to upgrade; every advisory is listed in the HTML/Markdown report.\n");
        }
        for f in v.fixes.iter().take(top) {
            _ = writeln!(
                s,
                "{:<8} {:<3} {:>14}  {:<40} {:<14} {}  ({})",
                severity_label(f.severity, f.malware),
                if f.is_new { "NEW" } else { "" },
                advisories_label(f),
                truncate(&fix_package_label(f), 40),
                truncate(&fix_target_label(f), 14),
                fix_notes(f).join(" · "),
                f.projects.join(", "),
            );
            if let Some(c) = &f.command {
                _ = writeln!(s, "{:28}$ {c}", "");
            }
        }
        if v.fixes.len() > top {
            _ = writeln!(s, "… and {} more upgrades", v.fixes.len() - top);
        }
        if !v.unmaintained.is_empty() {
            _ = writeln!(s, "\n━━ 🪦 Unmaintained dependencies — {} ━━", v.unmaintained.len());
        }
        for u in v.unmaintained.iter().take(top) {
            _ = writeln!(
                s,
                "{:<40} {:<40} {}  ({})",
                truncate(&u.package, 40),
                truncate(&u.repo, 40),
                unmaintained_label(u),
                u.projects.join(", ")
            );
        }
    }
    s.push('\n');
    s
}
