//! Dart and Flutter: `pubspec.yaml`, with exact versions from `pubspec.lock`. The lock
//! lists every package but not which one pulls in which.

use super::lock::Lock;
use super::{DepKind, Dependency, Folder, Found, Manager, read_file};

pub(super) fn read(f: &Folder) -> Option<Found> {
    let pubspec = f.read("pubspec.yaml")?;
    let lock = f.find_up("pubspec.lock").and_then(|p| read_file(&p)).map(|t| pubspec_lock(&t)).unwrap_or_default();
    let deps = declared(&pubspec).iter().map(|(name, req, kind)| Dependency::new(name, req, *kind, &lock)).collect();
    Some(Found::new(deps, &lock, Manager::Pub, "pubspec.yaml"))
}

/// `dependencies:` and `dev_dependencies:` as (name, requirement, kind). An entry is
/// `name: ^1.2.0`, or a map (`sdk:`, `git:`, `path:`, `hosted:` + `version:`).
fn declared(pubspec: &str) -> Vec<(String, String, DepKind)> {
    let mut out: Vec<(String, String, DepKind)> = Vec::new();
    let mut section = None;
    for line in pubspec.lines().filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#')) {
        let indent = line.len() - line.trim_start().len();
        let content = line.trim();
        let unquote = |s: &str| s.trim().trim_matches(['\'', '"']).to_string();
        match indent {
            0 => {
                section = match content {
                    "dependencies:" => Some(DepKind::Prod),
                    "dev_dependencies:" => Some(DepKind::Dev),
                    _ => None,
                }
            }
            2 => {
                if let (Some(kind), Some((name, req))) = (section, content.split_once(':')) {
                    out.push((name.to_string(), unquote(req), kind));
                }
            }
            4 => {
                if let (Some(_), Some(last), Some(v)) = (section, out.last_mut(), content.strip_prefix("version:")) {
                    last.1 = unquote(v);
                }
            }
            _ => {}
        }
    }
    out
}

/// `pubspec.lock`: `packages:`, each `  name:` with `dependency: "direct main"` (or
/// `"direct dev"`, `"transitive"`) and `version: "1.2.3"`. SDK packages are left out.
fn pubspec_lock(text: &str) -> Lock {
    let mut lock = Lock::flat();
    // (name, version, direct, from the SDK)
    let mut current: Option<(String, String, bool, bool)> = None;
    let mut finish = |current: &mut Option<(String, String, bool, bool)>| {
        if let Some((name, version, direct, false)) = current.take() {
            lock.add(name.clone(), name.clone(), version, Vec::new());
            if direct {
                lock.root(name.clone(), name);
            }
        }
    };
    for line in text.lines() {
        let indent = line.len() - line.trim_start().len();
        let content = line.trim();
        let value = |key: &str| content.strip_prefix(key).map(|v| v.trim().trim_matches('"').to_string());
        if indent <= 2 {
            finish(&mut current);
        }
        if indent == 2 && content.ends_with(':') {
            current = Some((content.trim_end_matches(':').to_string(), String::new(), false, false));
        } else if let Some(c) = current.as_mut().filter(|_| indent == 4) {
            if let Some(v) = value("version:") {
                c.1 = v;
            } else if let Some(d) = value("dependency:") {
                c.2 = d.starts_with("direct");
            } else if let Some(s) = value("source:") {
                c.3 = s == "sdk";
            }
        }
    }
    finish(&mut current);
    lock
}

#[cfg(test)]
mod tests {
    use super::super::testdir::TestDir;
    use super::*;

    #[test]
    fn reads_pubspec_and_lock() {
        let t = TestDir::new("pub");
        t.file(
            "pubspec.yaml",
            "name: app\nenvironment:\n  sdk: ^3.0.0\ndependencies:\n  flutter:\n    sdk: flutter\n  http: ^1.1.0\n  dio:\n    hosted: https://x\n    version: ^5.0.0\ndev_dependencies:\n  lints: '^3.0.0'\n",
        )
        .file(
            "pubspec.lock",
            "packages:\n  http:\n    dependency: \"direct main\"\n    source: hosted\n    version: \"1.2.0\"\n  http_parser:\n    dependency: transitive\n    source: hosted\n    version: \"4.0.2\"\n  flutter:\n    dependency: \"direct main\"\n    source: sdk\n    version: \"0.0.0\"\nsdks:\n  dart: \">=3.0.0\"\n",
        );
        let found = read(&Folder::new(t.root(), t.root())).unwrap();
        let got: Vec<(&str, Option<&str>, DepKind)> =
            found.deps.iter().map(|d| (d.name.as_str(), d.version.as_deref(), d.kind)).collect();
        assert_eq!(
            got,
            [
                ("flutter", None, DepKind::Prod),
                ("http", Some("1.2.0"), DepKind::Prod),
                ("dio", Some("5.0.0"), DepKind::Prod),
                ("lints", Some("3.0.0"), DepKind::Dev),
                ("http_parser", Some("4.0.2"), DepKind::Indirect),
            ]
        );
    }
}
