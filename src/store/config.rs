//! User config: categories/topics to track, repos to hide or watch, projects to scan,
//! and where to send updates. Lives at `~/.stackradar/config.toml`; built-in defaults
//! apply when it doesn't exist.

use std::collections::HashSet;
use std::path::PathBuf;

use serde::Deserialize;

use super::ignore::Rule;
use super::paths::{self, data_dir};
use super::private;

/// Built-in defaults, also written verbatim by `--init-config`.
pub const DEFAULT: &str = r#"# stackradar config — edit freely, then re-run stackradar.
# Topics are GitHub topic slugs (lowercase letters, digits, hyphens), see https://github.com/topics
# Each topic costs one search request; GitHub search allows 30/min, so at most 30 in total.

# Hide repos: "owner/repo" hides one repo, "owner" hides everything from that owner.
# A category may also set `note = "..."`, shown as a banner on its tab.
exclude = []

# Folders holding your projects, e.g. scan = ["~/code"]. Manifests up to 3 levels deep
# (package.json, Cargo.toml, go.mod, pyproject.toml, requirements.txt) feed two tabs:
# "For you" (repos matching your dependencies) and "Vulnerabilities" (security
# advisories affecting the versions you use, with lockfiles read when present).
# Left unset, the usual places that exist are scanned: ~/code, ~/projects, ~/dev,
# ~/Developer, ~/src, ~/repos, ~/source/repos, ~/workspace and ~/Documents/GitHub.
# scan = []   turns both tabs off.
# scan = ["~/code"]

# "Watching" tab: repos to follow whether or not they make the top, e.g. ["vercel/next.js"].
watch = []

# Optional: with --notify (the schedule uses it), also post a digest to a webhook.
# Discord and Slack incoming webhooks work as is; for Telegram use
# "https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<CHAT_ID>".
# webhook = "https://discord.com/api/webhooks/..."

# Advisories you've accepted are left out of the "Vulnerabilities" tab. `package` and
# `until` (after which it is reported again) are optional:
# [[ignore]]
# id = "GHSA-xxxx-xxxx-xxxx"        # or a CVE id
# package = "lodash"
# reason = "only used in a build script"
# until = 2026-12-31

[[category]]
key = "frontend"
title = "Frontend"
topics = ["react", "react-native", "nextjs"]

[[category]]
key = "backend"
title = "Backend"
topics = ["nodejs", "express", "nestjs"]

[[category]]
key = "ai"
title = "AI"
topics = ["llm", "ai-agents", "generative-ai", "mcp"]
"#;

const MAX_TOPICS: usize = 30;
/// Scanned when the config doesn't set `scan`, if they exist.
const DEFAULT_SCAN: &[&str] = &[
    "~/code",
    "~/projects",
    "~/dev",
    "~/Developer",
    "~/src",
    "~/repos",
    "~/source/repos",
    "~/workspace",
    "~/Documents/GitHub",
];
/// Tab keys of the report's own sections.
pub const FOR_YOU: &str = "foryou";
pub const WATCH: &str = "watch";
/// Tab keys the report itself uses ("saved" and "vulns" exist only in the HTML page).
const RESERVED_KEYS: &[&str] = &["saved", "vulns", FOR_YOU, WATCH];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Project folders for the "For you" and "Vulnerabilities" tabs (`~` allowed);
    /// unset means the `DEFAULT_SCAN` folders that exist
    #[serde(default)]
    pub scan: Option<Vec<String>>,
    /// `owner/repo`s for the "Watching" tab
    #[serde(default)]
    pub watch: Vec<String>,
    /// Incoming-webhook URL that `--notify` posts a digest to
    #[serde(default)]
    pub webhook: Option<String>,
    /// Accepted advisories, left out of the vulnerability list
    #[serde(default)]
    pub ignore: Vec<Rule>,
    #[serde(rename = "category")]
    pub categories: Vec<Category>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Category {
    pub key: String,
    pub title: String,
    pub topics: Vec<String>,
    /// Optional banner shown on this category's tab (e.g. a safety warning)
    #[serde(default)]
    pub note: Option<String>,
}

/// One-time move of the data dir from the tool's old name (`~/.gh-trending`), so
/// history, config and reports survive the rename. Never overwrites existing data.
pub fn migrate_legacy_dir() -> Option<String> {
    let new = data_dir();
    let old = new.parent()?.join(".gh-trending");
    if !old.is_dir() || new.exists() {
        return None;
    }
    Some(match std::fs::rename(&old, &new) {
        Ok(()) => format!("Moved {} → {}", old.display(), new.display()),
        Err(e) => format!("⚠  Could not move {} → {}: {e}", old.display(), new.display()),
    })
}

pub fn path() -> PathBuf {
    data_dir().join("config.toml")
}

/// Read the user's config, or the defaults if there is none. A config that exists but
/// is invalid is an error: silently falling back would hide the user's mistake.
pub fn load() -> Result<Config, String> {
    let path = path();
    let (text, origin) = match std::fs::read_to_string(&path) {
        Ok(t) => (t, path.display().to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (DEFAULT.to_string(), "built-in defaults".into()),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let config: Config = toml::from_str(&text).map_err(|e| format!("{origin}: {e}"))?;
    config.validate().map_err(|e| format!("{origin}: {e}"))?;
    Ok(config)
}

/// Write the default config, readable by you only (it may get a webhook URL); refuses to
/// overwrite an existing one.
pub fn init() -> Result<PathBuf, String> {
    let path = path();
    private::create_dir(&data_dir()).map_err(|e| e.to_string())?;
    private::create_new(&path, DEFAULT.as_bytes()).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => format!("{} already exists — edit it directly", path.display()),
        _ => format!("{}: {e}", path.display()),
    })?;
    Ok(path)
}

/// GitHub topic slug; also guards the search query against injected qualifiers.
fn is_slug(s: &str) -> bool {
    !s.is_empty() && s.len() <= 50 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `owner/repo` as GitHub allows it; also keeps the API URL it is put into well-formed.
pub fn is_full_name(s: &str) -> bool {
    let valid = |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    matches!(s.split_once('/'), Some((owner, name)) if valid(owner) && valid(name) && name != "." && name != "..")
}

impl Config {
    fn validate(&self) -> Result<(), String> {
        if self.categories.is_empty() {
            return Err("at least one [[category]] is required".into());
        }
        let mut keys = HashSet::new();
        for c in &self.categories {
            if !is_slug(&c.key) || RESERVED_KEYS.contains(&c.key.as_str()) {
                return Err(format!("category key {:?} must be a lowercase slug other than {RESERVED_KEYS:?}", c.key));
            }
            if !keys.insert(&c.key) {
                return Err(format!("duplicate category key {:?}", c.key));
            }
            if c.title.trim().is_empty() || c.topics.is_empty() {
                return Err(format!("category {:?} needs a title and at least one topic", c.key));
            }
            if let Some(t) = c.topics.iter().find(|t| !is_slug(t)) {
                return Err(format!("topic {t:?} is not a GitHub topic slug"));
            }
        }
        let total: usize = self.categories.iter().map(|c| c.topics.len()).sum();
        if total > MAX_TOPICS {
            return Err(format!("{total} topics configured; max is {MAX_TOPICS} (GitHub search rate limit)"));
        }
        if let Some(w) = self.watch.iter().find(|w| !is_full_name(w)) {
            return Err(format!("watch entry {w:?} must be \"owner/repo\""));
        }
        if let Some(url) = self.webhook.as_deref().filter(|u| !u.starts_with("https://")) {
            return Err(format!("webhook {url:?} must be an https:// URL"));
        }
        self.ignore.iter().try_for_each(Rule::validate)
    }

    /// `scan` folders with `~` expanded, or without `scan` the default ones that exist
    /// (each once: `~/code` and `~/Code` are one folder on macOS and Windows).
    pub fn scan_dirs(&self) -> Vec<PathBuf> {
        match &self.scan {
            Some(dirs) => dirs.iter().map(|d| paths::expand(d)).collect(),
            None => {
                let mut seen = HashSet::new();
                DEFAULT_SCAN
                    .iter()
                    .map(|d| paths::expand(d))
                    .filter(|d| {
                        let key = d.canonicalize().map(|c| c.to_string_lossy().to_lowercase());
                        d.is_dir() && key.is_ok_and(|k| seen.insert(k))
                    })
                    .collect()
            }
        }
    }

    pub fn is_excluded(&self, full_name: &str) -> bool {
        let owner = full_name.split('/').next().unwrap_or_default();
        self.exclude.iter().any(|x| x.eq_ignore_ascii_case(full_name) || x.eq_ignore_ascii_case(owner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defaults with one top-level `key = value` line set (replaced or added).
    fn with(line: &str) -> Result<Config, String> {
        let key = line.split('=').next().unwrap().trim();
        let mut lines: Vec<String> =
            DEFAULT.lines().filter(|l| l.split('=').next().unwrap().trim() != key).map(String::from).collect();
        lines.insert(0, line.to_string());
        let config: Config = toml::from_str(&lines.join("\n")).map_err(|e| e.to_string())?;
        config.validate().map(|()| config)
    }

    #[test]
    fn defaults_are_valid() {
        let c = with("exclude = []").unwrap();
        assert_eq!(c.categories.len(), 3);
        assert!(c.scan.is_none() && c.watch.is_empty() && c.webhook.is_none());
        assert!(with("scan = []").unwrap().scan_dirs().is_empty());
    }

    #[test]
    fn validates_watch_webhook_and_reserved_keys() {
        assert_eq!(with(r#"watch = ["vercel/next.js"]"#).unwrap().watch, ["vercel/next.js"]);
        assert!(with(r#"webhook = "https://discord.com/api/webhooks/1/x""#).is_ok());
        for bad in [r#"watch = ["vercel"]"#, r#"watch = ["a/b/c"]"#, r#"watch = ["a/.."]"#, r#"webhook = "http://x""#] {
            assert!(with(bad).is_err(), "{bad}");
        }
        let config: Config = toml::from_str(&DEFAULT.replace(r#"key = "ai""#, r#"key = "vulns""#)).unwrap();
        assert!(config.validate().unwrap_err().contains("slug"));
    }

    #[test]
    fn reads_ignore_rules() {
        let rules = "[[ignore]]\nid = \"GHSA-x\"\nuntil = 2026-12-31\n";
        let config: Config = toml::from_str(&format!("{DEFAULT}\n{rules}")).unwrap();
        assert_eq!(config.ignore[0].until.unwrap().to_string(), "2026-12-31");
        let config: Config = toml::from_str(&format!("{DEFAULT}\n[[ignore]]\nid = \" \"\n")).unwrap();
        assert!(config.validate().unwrap_err().contains("needs an id"));
    }

    #[test]
    fn excludes_by_owner_or_repo() {
        let c = with(r#"exclude = ["Spam", "a/b"]"#).unwrap();
        assert!(c.is_excluded("spam/anything") && c.is_excluded("A/B") && !c.is_excluded("a/bc"));
    }
}
