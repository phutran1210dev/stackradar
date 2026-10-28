//! The Markdown digest (for Slack, Notion, a README…).

use std::fmt::Write;

use super::{
    advisories_label, change_label, cwe_label, exploit_label, fix_label, fix_notes, fix_package_label,
    fix_target_label, heading, kind_label, package_label, projects_label, severity_label, signal_labels,
    unmaintained_label, vulns_heading,
};
use crate::model::Report;
use crate::util::truncate;

/// Escape text for a Markdown table cell (repo descriptions are untrusted free text).
fn cell(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ").replace('\\', "\\\\").replace('|', "\\|").replace('<', "&lt;")
}

/// Top `top` repos per category, the top `top` upgrades and the top `top` vulnerabilities as Markdown tables.
pub fn markdown(report: &Report, top: usize) -> String {
    let mut md = format!("# Stack Radar — {}\n\n", report.generated);
    match &report.since {
        Some(since) => {
            _ = write!(
                md,
                "New repos since **{since}** + today's GitHub Trending, ranked by buzz (🔥 Trending · 💬 Hacker News · Δ momentum · ★/day)"
            );
            match &report.compared_to {
                Some(d) => _ = writeln!(md, "; Δ = stars gained since run on {d}."),
                None => md.push_str(".\n"),
            }
        }
        None => md.push_str("Vulnerability audit of your projects' dependencies.\n"),
    }
    for w in &report.warnings {
        _ = writeln!(md, "\n> ⚠ {}", cell(w));
    }
    for s in &report.sections {
        _ = writeln!(md, "\n## {}\n", heading(s));
        if let Some(note) = &s.note {
            _ = writeln!(md, "> ⚠ {}\n", cell(note));
        }
        if s.entries.is_empty() {
            md.push_str("_No repos._\n");
            continue;
        }
        md.push_str("| # | Buzz | Repo | ★ | ★/day | Δ | Lang | Signals | Description |\n|--:|--:|---|--:|--:|--:|---|---|---|\n");
        for (i, e) in s.entries.iter().take(top).enumerate() {
            let r = &e.repo;
            _ = writeln!(
                md,
                "| {} | {:.0} | [{}]({}) | {} | {:.1} | {} | {} | {} | {} |",
                i + 1,
                e.buzz,
                r.full_name,
                r.html_url,
                r.stargazers_count,
                e.stars_per_day,
                change_label(e),
                r.language.as_deref().unwrap_or(""),
                cell(&signal_labels(e).join(" · ")),
                cell(&truncate(r.description.as_deref().unwrap_or(""), 100)),
            );
        }
    }
    if let Some(v) = &report.vulnerabilities {
        _ = writeln!(md, "\n## 🛡 Vulnerabilities ({})\n", vulns_heading(v));
        if v.items.is_empty() && v.ignored > 0 {
            md.push_str("_Nothing left after the ignore rules._\n");
        } else if v.items.is_empty() {
            _ = writeln!(md, "_No known advisories for the {} dependency versions checked._", v.packages);
        } else {
            md.push_str("### Upgrades\n\n| Severity | Package | Fix | Resolves | Notes | Command | Projects |\n|---|---|---|---|---|---|---|\n");
        }
        for f in v.fixes.iter().take(top) {
            _ = writeln!(
                md,
                "| {}{} | {} | {} | {} | {} | {} | {} |",
                severity_label(f.severity, f.malware),
                if f.is_new { " 🆕" } else { "" },
                cell(&fix_package_label(f)),
                cell(&fix_target_label(f)),
                advisories_label(f),
                cell(&fix_notes(f).join(" · ")),
                f.command.as_deref().map(|c| format!("`{}`", c.replace('|', "\\|"))).unwrap_or_default(),
                cell(&f.projects.join(", ")),
            );
        }
        if !v.items.is_empty() {
            md.push_str(
                "\n### Advisories\n\n| Severity | Package | Fix | Advisory | CWE | Summary | Projects |\n|---|---|---|---|---|---|---|\n",
            );
        }
        for i in v.items.iter().take(top) {
            _ = writeln!(
                md,
                "| {}{}{} | {}{} | {} | [{}]({}) | {} | {} | {} |",
                severity_label(i.severity, i.malware),
                if i.is_new { " 🆕" } else { "" },
                exploit_label(i.exploited, i.epss).map(|e| format!(" {e}")).unwrap_or_default(),
                cell(&package_label(i)),
                kind_label(i.kind(), i.via()).map(|k| format!(" ({})", cell(&k))).unwrap_or_default(),
                cell(&fix_label(i)),
                i.id,
                i.url,
                cell(&cwe_label(i)),
                cell(&truncate(&i.summary, 100)),
                cell(&projects_label(i)),
            );
        }
        if !v.unmaintained.is_empty() {
            md.push_str(
                "\n### Unmaintained dependencies\n\n| Package | Repo | Status | Projects |\n|---|---|---|---|\n",
            );
        }
        for u in v.unmaintained.iter().take(top) {
            _ = writeln!(
                md,
                "| {} | [{}](https://github.com/{}) | {} | {} |",
                cell(&u.package),
                u.repo,
                u.repo,
                unmaintained_label(u),
                cell(&u.projects.join(", "))
            );
        }
    }
    md
}

#[cfg(test)]
mod tests {
    use super::super::fixture;
    use super::*;

    #[test]
    fn renders_repos_vulnerabilities_and_warnings() {
        let md = markdown(&fixture::report(), 10);
        assert!(md.contains("> ⚠ Hacker News unavailable (timeout); the HN signal is missing."));
        assert!(md.contains("| 1 | 60 | [a/top](https://github.com/a/top) | 120 | 4.0 | NEW |"));
        assert!(md.contains("## Frontend (react)\n"));
        assert!(md.contains("## 🛡 Vulnerabilities (2 in 2 projects · 1 upgrade · 1 ignored)"));
        assert!(md.contains(
            "| HIGH 🆕 | lodash 4.17.15 | → 4.18.0 | 2 advisories |  | `npm install lodash@4.18.0` | ~/code/app |"
        ));
        assert!(md.contains(
            "| HIGH 🆕 | lodash 4.17.15 | → 4.18.0 | [GHSA-aaaa](https://github.com/advisories/GHSA-aaaa) | CWE-94 | Code \\| injection | ~/code/app |"
        ));
    }
}
