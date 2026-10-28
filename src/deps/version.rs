//! Dependency versions: comparison, advisory ranges (`>= 1.0.0, < 1.2.3`) and the lowest
//! version a manifest requirement allows. Dotted numbers with an optional pre-release,
//! ordered like semver; anything else (e.g. Python's `1.0rc1`) is "unknown".

use std::cmp::Ordering;

#[derive(Debug)]
struct Version {
    nums: Vec<u64>,
    pre: Option<String>,
}

impl Version {
    fn parse(s: &str) -> Option<Self> {
        let s = s.trim().trim_start_matches(['v', 'V']);
        let s = s.split('+').next()?;
        let (core, pre) = match s.split_once('-') {
            Some((c, p)) => (c, Some(p.to_string())),
            None => (s, None),
        };
        let nums = core.split('.').map(|n| n.parse().ok()).collect::<Option<Vec<u64>>>()?;
        Some(Self { nums, pre })
    }
}

impl Ord for Version {
    /// Missing components count as 0 (`1.2` = `1.2.0`); a pre-release sorts before its release.
    fn cmp(&self, other: &Self) -> Ordering {
        let len = self.nums.len().max(other.nums.len());
        let at = |v: &Version, i: usize| v.nums.get(i).copied().unwrap_or(0);
        (0..len).map(|i| at(self, i).cmp(&at(other, i))).find(|o| o.is_ne()).unwrap_or_else(|| {
            match (&self.pre, &other.pre) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(a), Some(b)) => a.cmp(b),
            }
        })
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Is `version` inside a GitHub advisory range such as `>= 4.0.0, < 4.17.21` or `= 1.0.0`?
/// None if either can't be parsed.
pub fn in_range(version: &str, range: &str) -> Option<bool> {
    let v = Version::parse(version)?;
    let mut inside = true;
    for part in range.split(',') {
        let part = part.trim();
        let (op, bound) = [">=", "<=", ">", "<", "="]
            .iter()
            .find_map(|op| part.strip_prefix(op).map(|rest| (*op, rest)))
            .unwrap_or(("=", part));
        let ord = v.cmp(&Version::parse(bound)?);
        inside &= match op {
            ">=" => ord.is_ge(),
            "<=" => ord.is_le(),
            ">" => ord.is_gt(),
            "<" => ord.is_lt(),
            _ => ord.is_eq(),
        };
    }
    Some(inside)
}

/// Compare two versions; None if either can't be parsed.
pub fn compare(a: &str, b: &str) -> Option<Ordering> {
    Some(Version::parse(a)?.cmp(&Version::parse(b)?))
}

/// Does upgrading `from` → `to` cross a semver-breaking boundary? That is the major
/// version, or for `0.x` the leftmost non-zero component (as `^` ranges treat it).
/// False if either can't be parsed.
pub fn is_breaking(from: &str, to: &str) -> bool {
    let (Some(from), Some(to)) = (Version::parse(from), Version::parse(to)) else { return false };
    let at = |v: &Version, i: usize| v.nums.get(i).copied().unwrap_or(0);
    let len = from.nums.len().max(1);
    let significant = (0..len).find(|&i| at(&from, i) != 0).unwrap_or(len - 1);
    (0..=significant).any(|i| at(&from, i) != at(&to, i))
}

/// The lowest version a requirement allows: `^1.2.3`, `~1.2`, `>=1.2,<2`, `==1.2.3`,
/// `1.2.3` → `1.2.3`/`1.2`. None for `*`, `1.x`, git/path/workspace specs and the like.
pub fn lowest(requirement: &str) -> Option<String> {
    let first = requirement.split([',', '|']).next()?.trim();
    let v = first.trim_start_matches(['^', '~', '>', '=', ' ']).split_whitespace().next()?;
    Version::parse(v).filter(|_| !first.starts_with('<')).map(|_| v.trim_start_matches(['v', 'V']).to_string())
}

/// An exact pin: `==1.2.3` (Python) or `=1.2.3` (Cargo, npm).
pub fn is_pin(requirement: &str) -> bool {
    let r = requirement.trim();
    r.starts_with('=') && Version::parse(r.trim_start_matches(['=', ' '])).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_like_semver() {
        let v = |s| Version::parse(s).unwrap();
        assert!(v("1.10.0") > v("1.9.9"));
        assert_eq!(v("1.2"), v("1.2.0"));
        assert!(v("1.0.0-rc.1") < v("1.0.0"));
        assert!(v("v1.3.1-0.2019") > v("1.3.0"));
        assert_eq!(Version::parse("1.0rc1"), None);
    }

    #[test]
    fn checks_advisory_ranges() {
        assert_eq!(in_range("4.17.15", ">= 4.0.0, <= 4.17.23"), Some(true));
        assert_eq!(in_range("4.18.0", ">= 4.0.0, <= 4.17.23"), Some(false));
        assert_eq!(in_range("1.0.0", "< 1.0.0"), Some(false));
        assert_eq!(in_range("2.0.1", "= 2.0.1"), Some(true));
        assert_eq!(in_range("v1.8.0", ">= 1.3.1-0.20190301021747-ccb9e902956d, < 1.9.1"), Some(true));
        assert_eq!(in_range("1.0rc1", "< 2"), None);
    }

    #[test]
    fn detects_breaking_upgrades() {
        assert!(!is_breaking("4.17.15", "4.18.0"));
        assert!(is_breaking("2.5.2", "4.2.1"));
        assert!(is_breaking("0.12.0", "0.16.0"), "0.x: a minor bump breaks");
        assert!(!is_breaking("0.50.0", "0.50.3"));
        assert!(is_breaking("0.0.3", "0.0.4"));
        assert!(!is_breaking("1.0rc1", "2.0"), "unparsable versions are not flagged");
        assert_eq!(compare("1.10.0", "1.9.0"), Some(Ordering::Greater));
    }

    #[test]
    fn lowest_allowed_version() {
        assert_eq!(lowest("^4.17.15").as_deref(), Some("4.17.15"));
        assert_eq!(lowest("~1.2").as_deref(), Some("1.2"));
        assert_eq!(lowest(">=2.28, <3").as_deref(), Some("2.28"));
        assert_eq!(lowest("==2.31.0").as_deref(), Some("2.31.0"));
        assert_eq!(lowest("v1.9.0").as_deref(), Some("1.9.0"));
        for none in ["*", "1.x", "latest", "workspace:*", "git+https://x/y", "<2", "!=1.0", ""] {
            assert_eq!(lowest(none), None, "{none}");
        }
        assert!(is_pin("==2.31.0") && is_pin("=1.0.0"));
        assert!(!is_pin("^1.2.3") && !is_pin(">=1") && !is_pin("1.2.3"));
    }
}
