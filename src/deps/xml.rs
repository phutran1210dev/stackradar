//! Just enough XML for project files (`*.csproj`, `pom.xml`): elements by tag name, their
//! attributes and text. Not a general parser; the files are written by tools or by hand
//! in a regular shape.

use std::collections::HashMap;

/// `xml` without `<!-- comments -->`, which often hold commented-out dependencies.
pub(super) fn without_comments(xml: &str) -> String {
    let mut out = String::with_capacity(xml.len());
    let mut rest = xml;
    while let Some(i) = rest.find("<!--") {
        out.push_str(&rest[..i]);
        rest = rest[i..].find("-->").map_or("", |end| &rest[i + end + 3..]);
    }
    out.push_str(rest);
    out
}

/// `xml` without any `<tag>…</tag>` sections.
pub(super) fn without(xml: &str, tag: &str) -> String {
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    let mut out = String::with_capacity(xml.len());
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        out.push_str(&rest[..i]);
        rest = rest[i..].find(&close).map_or("", |end| &rest[i + end + close.len()..]);
    }
    out.push_str(rest);
    out
}

/// Each `<tag …>` in `xml`: its attributes (names lowercased) and its content up to
/// `</tag>` (empty when self-closing).
pub(super) fn elements<'a>(xml: &'a str, tag: &str) -> Vec<(HashMap<String, String>, &'a str)> {
    let (open, close) = (format!("<{tag}"), format!("</{tag}>"));
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        let after = &rest[i + open.len()..];
        // `<Version` must not match `<VersionOverride`.
        if !after.starts_with(|c: char| c.is_whitespace() || c == '>' || c == '/') {
            rest = after;
            continue;
        }
        let Some(end) = after.find('>') else { break };
        let (head, body) = (&after[..end], &after[end + 1..]);
        let (inner, next) = match head.strip_suffix('/') {
            Some(_) => ("", body),
            None => body.find(&close).map_or(("", body), |c| (&body[..c], &body[c + close.len()..])),
        };
        out.push((attributes(head.trim_end_matches('/')), inner));
        rest = next;
    }
    out
}

/// The trimmed text of the first non-empty `<tag>…</tag>` in `xml`.
pub(super) fn text(xml: &str, tag: &str) -> Option<String> {
    elements(xml, tag).into_iter().map(|(_, t)| t.trim().to_string()).find(|t| !t.is_empty())
}

/// The direct children of `xml` as (tag, text), e.g. a `<properties>` block.
pub(super) fn children(xml: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find('<') {
        let after = &rest[i + 1..];
        let Some(end) = after.find('>') else { break };
        let tag = &after[..end];
        let close = format!("</{tag}>");
        match after[end + 1..].find(&close) {
            Some(c) if !tag.starts_with(['/', '!', '?']) && !tag.contains(' ') => {
                out.push((tag.to_string(), after[end + 1..end + 1 + c].trim().to_string()));
                rest = &after[end + 1 + c + close.len()..];
            }
            _ => rest = &after[end + 1..],
        }
    }
    out
}

/// `Include="Serilog" Version='3.1.1'` → {include: Serilog, version: 3.1.1}.
fn attributes(head: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut rest = head;
    while let Some(eq) = rest.find('=') {
        let name = rest[..eq].split_whitespace().last().unwrap_or_default().to_ascii_lowercase();
        let after = rest[eq + 1..].trim_start();
        let Some(quote) = after.chars().next().filter(|c| matches!(c, '"' | '\'')) else { break };
        let Some(end) = after[1..].find(quote) else { break };
        out.insert(name, after[1..1 + end].to_string());
        rest = &after[end + 2..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_elements_attributes_and_text() {
        let xml = without_comments(
            r#"<Project><!-- <PackageReference Include="Old" Version="1" /> -->
  <PackageReference Include="Serilog" Version='3.1.1' />
  <PackageReference Include="Polly"><Version>8.0.0</Version></PackageReference>
  <PackageReferenceX Include="No" /></Project>"#,
        );
        let refs = elements(&xml, "PackageReference");
        let got: Vec<(&str, Option<String>)> = refs
            .iter()
            .map(|(a, inner)| (a["include"].as_str(), a.get("version").cloned().or_else(|| text(inner, "Version"))))
            .collect();
        assert_eq!(got, [("Serilog", Some("3.1.1".into())), ("Polly", Some("8.0.0".into()))]);
        assert_eq!(
            children("<a.version>1.2</a.version>\n<b>x</b>"),
            [("a.version".to_string(), "1.2".to_string()), ("b".into(), "x".into())]
        );
        assert_eq!(without("<a><b>1</b></a><b>2</b>", "a"), "<b>2</b>");
    }
}
