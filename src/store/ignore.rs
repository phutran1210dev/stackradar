//! Ignore rules: advisories you've accepted, from the config's `[[ignore]]` tables or, for
//! `audit`, a file given with `--ignore` (such as one written by `--write-baseline`).

use std::path::Path;

use chrono::NaiveDate;
use serde::{Deserialize, Deserializer, Serialize};

use crate::model::Vulnerability;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// GHSA or CVE id
    pub id: String,
    /// Only for this package (one advisory can affect several)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Last day the rule applies; after it the advisory is reported again
    #[serde(default, deserialize_with = "date", skip_serializing_if = "Option::is_none")]
    pub until: Option<NaiveDate>,
}

/// `until = 2026-12-31` (a TOML date) or `until = "2026-12-31"`.
fn date<'de, D: Deserializer<'de>>(d: D) -> Result<Option<NaiveDate>, D::Error> {
    let text = match toml::Value::deserialize(d)? {
        toml::Value::String(s) => s,
        toml::Value::Datetime(dt) => dt.to_string(),
        other => return Err(serde::de::Error::custom(format!("expected a date, got {other}"))),
    };
    NaiveDate::parse_from_str(&text, "%Y-%m-%d")
        .map(Some)
        .map_err(|_| serde::de::Error::custom(format!("{text:?} is not a YYYY-MM-DD date")))
}

impl Rule {
    pub fn validate(&self) -> Result<(), String> {
        if self.id.trim().is_empty() {
            Err("an [[ignore]] rule needs an id (GHSA-… or CVE-…)".into())
        } else {
            Ok(())
        }
    }

    pub fn is_expired(&self, today: NaiveDate) -> bool {
        self.until.is_some_and(|d| d < today)
    }

    pub fn matches(&self, v: &Vulnerability) -> bool {
        let id = self.id.trim();
        (id.eq_ignore_ascii_case(&v.id) || v.cve.as_deref().is_some_and(|c| id.eq_ignore_ascii_case(c)))
            && self.package.as_deref().is_none_or(|p| v.ecosystem.normalize(p) == v.package)
    }

    /// `GHSA-… (lodash)`, for messages.
    pub fn label(&self) -> String {
        match &self.package {
            Some(p) => format!("{} ({p})", self.id),
            None => self.id.clone(),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    ignore: Vec<Rule>,
}

/// The rules in an ignore file.
pub fn load(path: &Path) -> Result<Vec<Rule>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let file: File = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    file.ignore.iter().try_for_each(Rule::validate).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(file.ignore)
}

/// An ignore file holding `rules`.
pub fn to_toml(rules: &[Rule]) -> String {
    let body = toml::to_string(&File { ignore: rules.to_vec() }).expect("ignore rules serialize");
    format!("# Accepted advisories for `stackradar audit --ignore`. Add `until = YYYY-MM-DD` to revisit one.\n\n{body}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;
    use crate::report::fixture;

    fn rule(text: &str) -> Rule {
        toml::from_str::<File>(text).unwrap().ignore.remove(0)
    }

    #[test]
    fn matches_by_id_cve_and_package() {
        let v = fixture::vuln("GHSA-aaaa", Severity::High, false);
        assert!(rule("[[ignore]]\nid = \"ghsa-aaaa\"").matches(&v));
        assert!(rule("[[ignore]]\nid = \"CVE-2026-1\"\npackage = \"lodash\"").matches(&v));
        assert!(!rule("[[ignore]]\nid = \"GHSA-aaaa\"\npackage = \"lodash-es\"").matches(&v));
        assert!(!rule("[[ignore]]\nid = \"GHSA-bbbb\"").matches(&v));
    }

    #[test]
    fn reads_dates_and_round_trips() {
        let today = NaiveDate::from_ymd_opt(2026, 10, 26).unwrap();
        let r = rule("[[ignore]]\nid = \"GHSA-x\"\nuntil = 2026-10-25");
        assert!(r.is_expired(today));
        assert!(!rule("[[ignore]]\nid = \"GHSA-x\"\nuntil = \"2026-10-26\"").is_expired(today));
        assert!(toml::from_str::<File>("[[ignore]]\nid = \"x\"\nuntil = \"soon\"").is_err());
        let back: File = toml::from_str(&to_toml(std::slice::from_ref(&r))).unwrap();
        assert_eq!(back.ignore, [r]);
    }
}
