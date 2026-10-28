//! The self-contained HTML page.

use crate::model::Report;

const TEMPLATE: &str = include_str!("template.html");

/// Self-contained HTML report. Data is embedded as JSON and rendered client-side
/// with DOM APIs (textContent), so repo descriptions can't inject markup.
pub fn html(report: &Report) -> String {
    // `<` escaped so nothing in the data can close the <script> tag.
    let data = serde_json::to_string(report).expect("report data serializes").replace('<', "\\u003c");
    // Data last, so placeholder-like text inside repo descriptions is left alone.
    let intro = match &report.since {
        Some(d) => format!("New repos since <b>{d}</b> + today's GitHub Trending, ranked by buzz"),
        None => "Vulnerability audit of your projects' dependencies".to_string(),
    };
    TEMPLATE.replace("__INTRO__", &intro).replace("__GENERATED__", &report.generated).replace("__DATA__", &data)
}

#[cfg(test)]
mod tests {
    use super::super::fixture;
    use super::*;

    /// A full run and a vulnerability-only audit (no repo window, no tabs).
    fn reports() -> [Report; 2] {
        let audit = Report { since: None, compared_to: None, sections: Vec::new(), ..fixture::report() };
        [fixture::report(), audit]
    }

    #[test]
    fn fills_every_placeholder() {
        let [full, audit] = reports().map(|r| html(&r));
        for page in [&full, &audit] {
            for slot in ["__DATA__", "__GENERATED__", "__INTRO__"] {
                assert!(!page.contains(slot), "{slot} left in the page");
            }
            assert!(page.contains("Generated 2026-10-25 08:00 UTC"));
        }
        assert!(full.contains("New repos since <b>2026-09-25</b>"));
        assert!(audit.contains("Vulnerability audit of your projects' dependencies"));
    }

    #[test]
    fn loads_nothing_from_the_network() {
        let mut report = fixture::report();
        report.sections[0].entries[0].info.repo.owner.avatar_url =
            "https://avatars.githubusercontent.com/u/1?v=4".into();
        let page = html(&report);
        // The template itself: no fonts, styles, scripts, images or frames from anywhere.
        for needle in
            ["<img", "<iframe", "<link rel=\"stylesheet\"", "@import", "url(", "src=", "fetch(", "XMLHttpRequest"]
        {
            assert!(!TEMPLATE.contains(needle), "template has {needle}");
        }
        // Initials replace avatars: the URL stays in the embedded data and is never read.
        assert!(!TEMPLATE.contains("avatar"));
        assert_eq!(page.matches("avatars.githubusercontent.com").count(), 1);
    }

    #[test]
    fn builds_markup_only_through_the_dom() {
        for needle in ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"] {
            assert!(!TEMPLATE.contains(needle), "template uses {needle}");
        }
    }

    #[test]
    fn data_cannot_close_the_script_or_fill_a_slot() {
        let mut report = fixture::report();
        let evil = "</script><script>alert(1)</script> __INTRO__ __DATA__";
        report.sections[0].entries[0].info.repo.description = Some(evil.into());
        report.vulnerabilities.as_mut().unwrap().items[0].summary = "<img src=x onerror=alert(1)>".into();
        let page = html(&report);
        assert_eq!(page.matches("</script>").count(), TEMPLATE.matches("</script>").count());
        assert!(!page.contains("<img"));
        assert!(page.contains(&evil.replace('<', concat!("\\", "u003c"))));
    }
}
