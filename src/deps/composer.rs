//! PHP: `composer.json`, with exact versions and what they pull in from `composer.lock`.

use serde_json::Value;

use super::lock::Lock;
use super::{DepKind, Dependency, Folder, Found, Manager, parse_json, read_file};

/// Packages are `vendor/name` (case-insensitive); `php`, `ext-*` and `lib-*` are the
/// platform, not packages.
fn packages(requires: Option<&Value>) -> impl Iterator<Item = (String, &str)> {
    requires
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(name, _)| name.contains('/'))
        .map(|(name, req)| (name.to_ascii_lowercase(), req.as_str().unwrap_or_default()))
}

pub(super) fn read(f: &Folder) -> Option<Found> {
    let manifest = parse_json(&f.dir.join("composer.json"), &f.read("composer.json")?)?;
    let lock = f
        .find_up("composer.lock")
        .and_then(|p| parse_json(&p, &read_file(&p)?))
        .map(|v| composer_lock(&v))
        .unwrap_or_default();
    let mut deps: Vec<Dependency> = Vec::new();
    for (section, kind) in [("require", DepKind::Prod), ("require-dev", DepKind::Dev)] {
        for (name, req) in packages(manifest.get(section)) {
            if !deps.iter().any(|d| d.name == name) {
                deps.push(Dependency::new(&name, req, kind, &lock));
            }
        }
    }
    Some(Found::new(deps, &lock, Manager::Composer, "composer.json"))
}

/// `composer.lock`: `packages` and `packages-dev`, each `{ name, version, require }`.
fn composer_lock(v: &Value) -> Lock {
    let mut lock = Lock::default();
    for p in ["packages", "packages-dev"].iter().filter_map(|s| v.get(s)?.as_array()).flatten() {
        let (Some(name), Some(version)) =
            (p.get("name").and_then(Value::as_str), p.get("version").and_then(Value::as_str))
        else {
            continue;
        };
        let name = name.to_ascii_lowercase();
        let deps = packages(p.get("require")).map(|(d, _)| d).collect();
        lock.add(name.clone(), name.clone(), version.trim_start_matches('v'), deps);
        lock.root(name.clone(), name);
    }
    lock
}

#[cfg(test)]
mod tests {
    use super::super::testdir::TestDir;
    use super::*;

    #[test]
    fn reads_composer_json_and_lock() {
        let t = TestDir::new("composer");
        t.file(
            "composer.json",
            r#"{"require":{"php":">=8.1","Laravel/Framework":"^10.0"},"require-dev":{"phpunit/phpunit":"^10"}}"#,
        )
        .file(
            "composer.lock",
            r#"{"packages":[{"name":"laravel/framework","version":"v10.48.0","require":{"php":"^8.1","symfony/console":"^6.2"}},
               {"name":"symfony/console","version":"v6.4.1"}],"packages-dev":[]}"#,
        );
        let found = read(&Folder::new(t.root(), t.root())).unwrap();
        let got: Vec<(&str, Option<&str>, DepKind, Option<&str>)> =
            found.deps.iter().map(|d| (d.name.as_str(), d.version.as_deref(), d.kind, d.via.as_deref())).collect();
        assert_eq!(
            got,
            [
                ("laravel/framework", Some("10.48.0"), DepKind::Prod, None),
                ("phpunit/phpunit", Some("10"), DepKind::Dev, None),
                ("symfony/console", Some("6.4.1"), DepKind::Indirect, Some("laravel/framework")),
            ]
        );
    }
}
