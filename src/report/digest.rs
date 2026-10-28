//! The short digest posted to a webhook: what changed, not the whole report.

use std::fmt::Write;

use super::{fix_label, package_label, projects_label, severity_label, summary, unique_entries};
use crate::model::Report;
use crate::util::truncate;

/// Repos listed in the digest.
const TOP: usize = 5;
/// Discord's message limit is 2000 characters; stay under it with room to spare.
const MAX_CHARS: usize = 1900;

/// Summary line, the top repos (new ones first) and new vulnerabilities.
pub fn digest(report: &Report) -> String {
    let mut msg = format!("**Stack Radar** — {}\n{}\n", report.generated, summary(report));
    let mut repos = unique_entries(report);
    repos.sort_by(|a, b| b.is_new.cmp(&a.is_new).then(b.buzz.total_cmp(&a.buzz)));
    if !repos.is_empty() {
        msg.push_str("\nTop repos:\n");
    }
    for e in repos.iter().take(TOP) {
        let desc = inert(&truncate(e.repo.description.as_deref().unwrap_or(""), 80));
        _ = writeln!(
            msg,
            "• {}{} ⚡{:.0} — {desc} <{}>",
            if e.is_new { "🆕 " } else { "" },
            e.repo.full_name,
            e.buzz,
            e.repo.html_url
        );
    }
    let fresh: Vec<_> = report.vulnerabilities.iter().flat_map(|v| &v.items).filter(|v| v.is_new).collect();
    if !fresh.is_empty() {
        msg.push_str("\nNew vulnerabilities:\n");
    }
    for v in fresh {
        _ = writeln!(
            msg,
            "• {}{} {} ({}) in {} — {} <{}>",
            if v.exploited { "🔥 " } else { "" },
            severity_label(v.severity, v.malware),
            package_label(v),
            fix_label(v),
            projects_label(v),
            inert(&truncate(&v.summary, 80)),
            v.url
        );
    }
    for w in &report.warnings {
        _ = writeln!(msg, "⚠ {}", inert(w));
    }
    truncate(&msg, MAX_CHARS)
}

/// Text from elsewhere (repo descriptions, advisory summaries) with `<` and `>` swapped
/// for look-alikes, so it can't form Slack's `<!channel>` or `<@user>` and ping people.
/// Discord mentions are turned off in the payload instead.
fn inert(text: &str) -> String {
    text.replace('<', "‹").replace('>', "›")
}

#[cfg(test)]
mod tests {
    use super::super::fixture;
    use super::*;

    #[test]
    fn lists_new_items_and_stays_short() {
        let d = digest(&fixture::report());
        assert!(d.contains("• 🆕 a/top ⚡60"));
        assert!(d.contains("• HIGH lodash 4.17.15 (→ 4.18.0) in ~/code/app"));
        assert!(!d.contains("GHSA-bbbb"), "only new vulnerabilities");
        assert_eq!(inert("<!channel> <@U123> look"), "‹!channel› ‹@U123› look");
        let mut big = fixture::report();
        big.warnings = vec!["x".repeat(3000)];
        assert_eq!(digest(&big).chars().count(), MAX_CHARS);
    }
}
