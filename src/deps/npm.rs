//! npm: `package.json`, with exact versions and the packages they pull in from the
//! lockfile (npm, Yarn classic and Berry, pnpm or Bun) when present.

use std::collections::{BTreeMap, HashSet};

use serde_json::{Map, Value};

use super::lock::{Lock, split_at_version};
use super::{DepKind, Dependency, Folder, Found, Manager, is_plain_file, once, parse_json, read_file};

/// Dev last, so a package also listed as a runtime dependency counts as one.
const SECTIONS: &[(&str, DepKind)] = &[
    ("dependencies", DepKind::Prod),
    ("peerDependencies", DepKind::Prod),
    ("optionalDependencies", DepKind::Prod),
    ("devDependencies", DepKind::Dev),
];

/// What a locked package depends on (all of these are installed).
const LOCKED_SECTIONS: &[&str] = &["dependencies", "optionalDependencies", "peerDependencies"];

pub(super) fn read(f: &Folder) -> Option<Found> {
    let manifest = parse_json(&f.dir.join("package.json"), &f.read("package.json")?)?;
    let mut seen = HashSet::new();
    let declared: Vec<(&str, &str, DepKind)> = SECTIONS
        .iter()
        .filter_map(|&(s, kind)| Some((manifest.get(s)?.as_object()?, kind)))
        .flat_map(|(deps, kind)| deps.iter().map(move |(name, req)| (name, req, kind)))
        .filter(|(name, _, _)| seen.insert(name.as_str()))
        .map(|(name, req, kind)| (name.as_str(), req.as_str().unwrap_or_default(), kind))
        .collect();
    let names: Vec<(&str, &str)> = declared.iter().map(|&(name, req, _)| (name, req)).collect();
    let (lock, manager) = lockfile(f, &names);
    let deps = declared.iter().map(|&(name, req, kind)| Dependency::new(name, req, kind, &lock)).collect();
    Some(Found::new(deps, &lock, manager, "package.json"))
}

/// The nearest lockfile and the package manager it belongs to (npm without one).
fn lockfile(f: &Folder, declared: &[(&str, &str)]) -> (Lock, Manager) {
    let found = f.ancestors().find_map(|d| {
        LOCKFILES.iter().find_map(|&(file, manager)| {
            let path = d.join(file);
            is_plain_file(&path).then_some((path, manager))
        })
    });
    let Some((path, manager)) = found else { return (Lock::default(), Manager::Npm) };
    let text = once(&path, || read_file(&path));
    let Some(text) = text.as_deref() else { return (Lock::default(), manager) };
    // In a workspace the lockfile sits at the root; the project is one of its members.
    let root = path.parent().unwrap_or(f.dir);
    let member = f.dir.strip_prefix(root).map(|p| p.to_string_lossy().replace('\\', "/")).unwrap_or_default();
    match manager {
        Manager::Yarn if text.contains("\n__metadata:") => (yarn_lock(text, declared), Manager::YarnBerry),
        Manager::Yarn => (yarn_lock(text, declared), Manager::Yarn),
        Manager::Pnpm => (pnpm_lock(text, if member.is_empty() { "." } else { &member }), manager),
        Manager::Bun => {
            let json = once(&path, || parse_json(&path, &strip_trailing_commas(text)));
            (json.as_ref().as_ref().map(bun_lock).unwrap_or_default(), manager)
        }
        _ => {
            let json = once(&path, || parse_json(&path, text));
            (json.as_ref().as_ref().map(|j| npm_lock(j, &member)).unwrap_or_default(), manager)
        }
    }
}

/// Checked in this order in each folder.
const LOCKFILES: &[(&str, Manager)] = &[
    ("package-lock.json", Manager::Npm),
    ("yarn.lock", Manager::Yarn),
    ("pnpm-lock.yaml", Manager::Pnpm),
    ("bun.lock", Manager::Bun),
];

/// A locked package laid out as in `node_modules`: its path (`node_modules/a/node_modules/b`),
/// version and the names it depends on.
type Installed = (String, String, Vec<String>);

/// Packages laid out as in `node_modules`, each dependency resolved the way Node does
/// (the nearest `node_modules` up the path). A workspace `member`'s own entries
/// (`<member>/node_modules/x`) win over the hoisted ones (`node_modules/x`).
fn node_modules_lock(installed: Vec<Installed>, member: &str) -> Lock {
    let paths: HashSet<&str> = installed.iter().map(|(path, ..)| path.as_str()).collect();
    let resolve = |from: &str, name: &str| {
        let mut dir = from;
        loop {
            let candidate =
                if dir.is_empty() { format!("node_modules/{name}") } else { format!("{dir}/node_modules/{name}") };
            if paths.contains(candidate.as_str()) {
                return Some(candidate);
            }
            if dir.is_empty() {
                return None;
            }
            dir = dir.rsplit_once("/node_modules/").map_or("", |(parent, _)| parent);
        }
    };
    let member_prefix = if member.is_empty() { String::new() } else { format!("{member}/") };
    let mut lock = Lock::default();
    for (path, version, deps) in &installed {
        let Some((prefix, name)) = path.rsplit_once("node_modules/") else { continue };
        lock.add(path.clone(), name, version.clone(), deps.iter().filter_map(|d| resolve(path, d)).collect());
        if !member_prefix.is_empty() && prefix == member_prefix {
            lock.root(name, path.clone());
        } else if prefix.is_empty() {
            lock.root_default(name, path.clone());
        }
    }
    lock
}

/// The keys of `pkg`'s `sections` objects.
fn names_in(pkg: &Value, sections: &[&str]) -> Vec<String> {
    sections.iter().filter_map(|s| pkg.get(s)?.as_object()).flat_map(|o| o.keys().cloned()).collect()
}

/// `package-lock.json`: v2/v3 list every installed path under `packages`; v1 nests
/// `dependencies` objects, with `requires` for what each needs.
fn npm_lock(lock: &Value, member: &str) -> Lock {
    let version = |v: &Value| v.get("version")?.as_str().map(String::from);
    let mut installed = Vec::new();
    if let Some(packages) = lock.get("packages").and_then(Value::as_object) {
        for (path, pkg) in packages.iter().filter(|(path, _)| path.contains("node_modules/")) {
            if let Some(v) = version(pkg) {
                installed.push((path.clone(), v, names_in(pkg, LOCKED_SECTIONS)));
            }
        }
    } else if let Some(deps) = lock.get("dependencies").and_then(Value::as_object) {
        fn v1(deps: &Map<String, Value>, prefix: &str, out: &mut Vec<Installed>) {
            for (name, pkg) in deps {
                let path = format!("{prefix}node_modules/{name}");
                if let Some(v) = pkg.get("version").and_then(Value::as_str) {
                    out.push((path.clone(), v.to_string(), names_in(pkg, &["requires"])));
                }
                if let Some(nested) = pkg.get("dependencies").and_then(Value::as_object) {
                    v1(nested, &format!("{path}/"), out);
                }
            }
        }
        v1(deps, "", &mut installed);
    }
    node_modules_lock(installed, member)
}

/// `bun.lock` (Bun 1.2+, JSON with trailing commas): `packages` maps an install path
/// (`a/b` is `b` inside `a`) to `["name@version", registry, { dependencies, … }, hash]`.
fn bun_lock(lock: &Value) -> Lock {
    let Some(packages) = lock.get("packages").and_then(Value::as_object) else { return Lock::default() };
    let installed = packages
        .iter()
        .filter_map(|(path, entry)| {
            let (_, version) = split_at_version(entry.get(0)?.as_str()?)?;
            let deps = entry.get(2).map(|meta| names_in(meta, LOCKED_SECTIONS)).unwrap_or_default();
            // `@scope/a/b` → node_modules/@scope/a/node_modules/b
            let mut segments: Vec<String> = Vec::new();
            for part in path.split('/') {
                match segments.last_mut() {
                    Some(last) if last.starts_with('@') && !last.contains('/') => *last = format!("{last}/{part}"),
                    _ => segments.push(part.to_string()),
                }
            }
            let path = segments.iter().map(|s| format!("node_modules/{s}")).collect::<Vec<_>>().join("/");
            Some((path, version.to_string(), deps))
        })
        .collect();
    node_modules_lock(installed, "")
}

/// JSON with trailing commas (`[1, 2,]`) → plain JSON. Commas inside strings are kept.
fn strip_trailing_commas(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let (mut in_string, mut escaped) = (false, false);
    let chars: Vec<char> = text.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if in_string {
            (escaped, in_string) = (c == '\\' && !escaped, !(c == '"' && !escaped));
        } else if c == '"' {
            in_string = true;
        } else if c == ',' && chars[i + 1..].iter().find(|c| !c.is_whitespace()).is_some_and(|n| matches!(n, '}' | ']'))
        {
            continue;
        }
        out.push(c);
    }
    out
}

/// `yarn.lock`, classic (`version "1.2.3"`) or Berry (`version: 1.2.3`). Entries are
/// keyed by the requirements they resolve (`"lodash@^4.17.0, lodash@^4.17.21":`), and list
/// what they need as `name "range"` (classic) or `name: "npm:range"` (Berry), so each
/// dependency is found by its own requirement. A declared dependency falls back to any
/// entry of that name.
fn yarn_lock(text: &str, declared: &[(&str, &str)]) -> Lock {
    // (requirements, version, requirements of its dependencies)
    let mut entries: Vec<(Vec<String>, Option<String>, Vec<String>)> = Vec::new();
    let mut in_deps = false;
    for line in text.lines() {
        let indent = line.len() - line.trim_start().len();
        let content = line.trim();
        if indent == 0 && content.ends_with(':') && !content.starts_with('#') {
            let specs = content.trim_end_matches(':').split(", ").map(|s| s.trim_matches('"').to_string()).collect();
            entries.push((specs, None, Vec::new()));
            in_deps = false;
        } else if let Some(entry) = entries.last_mut().filter(|_| indent == 2) {
            in_deps = ["dependencies:", "optionalDependencies:"].contains(&content);
            if let Some(v) = content.strip_prefix("version") {
                entry.1 = Some(v.trim_start_matches(':').trim().trim_matches('"').to_string());
            }
        } else if let Some(entry) = entries.last_mut().filter(|_| indent == 4 && in_deps) {
            let (name, range) = match content.strip_prefix('"') {
                Some(quoted) => quoted.split_once('"').unwrap_or_default(),
                None => content.split_once([' ', ':']).unwrap_or_default(),
            };
            let range = range.trim_start_matches(':').trim().trim_matches('"');
            if !name.is_empty() {
                entry.2.push(format!("{name}@{range}"));
            }
        }
    }
    let mut by_spec: BTreeMap<&str, &str> = BTreeMap::new();
    for (specs, _, _) in &entries {
        for s in specs {
            by_spec.insert(s.as_str(), specs[0].as_str());
        }
    }
    let mut lock = Lock::default();
    for (specs, version, deps) in &entries {
        let (Some(version), Some((name, _))) = (version, split_at_version(&specs[0])) else { continue };
        let deps = deps.iter().filter_map(|d| by_spec.get(d.as_str()).map(|id| id.to_string())).collect();
        lock.add(specs[0].clone(), name, version.clone(), deps);
    }
    for &(name, req) in declared {
        let exact =
            [format!("{name}@{req}"), format!("{name}@npm:{req}")].into_iter().find_map(|k| by_spec.get(k.as_str()));
        let prefix = format!("{name}@");
        let any = || by_spec.range(prefix.as_str()..).next().filter(|(k, _)| k.starts_with(&prefix)).map(|(_, v)| v);
        if let Some(id) = exact.or_else(any) {
            lock.root(name, *id);
        }
    }
    lock
}

/// `pnpm-lock.yaml`: the `member` importer's (`.` for the root) dependencies, and the
/// package graph (`snapshots:` in v9, `packages:` before). Handles v6+ (`name:` then
/// `version: 1.2.3(peer@x)` below it, packages as `name@1.2.3`) and v5 (`name: 1.2.3_peer@x`,
/// packages as `/name/1.2.3`), with or without an `importers:` block. Parsed by
/// indentation: the file is generated.
fn pnpm_lock(text: &str, member: &str) -> Lock {
    let unquote = |s: &str| s.trim().trim_matches(['\'', '"']).to_string();
    let v5 = text
        .lines()
        .next()
        .is_some_and(|l| l.trim_start_matches("lockfileVersion:").trim().trim_matches(['\'', '"']).starts_with('5'));
    // `1.2.3(react@18)` / `1.2.3_react@18` → `1.2.3`
    let clean = |v: &str| unquote(v).split(['(', '_']).next().unwrap_or_default().to_string();
    // `/@scope/x@1.2.3(peer@1)` (v6+) or `/@scope/x/1.2.3_peer@1` (v5) → (name, version)
    let package = |key: &str| -> Option<(String, String)> {
        let key = unquote(key);
        let key = key.trim_start_matches('/').split('(').next()?;
        let (name, version) = if v5 { key.split('_').next()?.rsplit_once('/')? } else { split_at_version(key)? };
        (!name.is_empty()).then(|| (name.to_string(), version.to_string()))
    };
    let mut lock = Lock::default();
    let graph = if text.lines().any(|l| l == "snapshots:") { "snapshots:" } else { "packages:" };
    let (mut in_graph, mut in_deps, mut current) = (false, false, None::<(String, String, Vec<String>)>);
    let finish = |current: &mut Option<(String, String, Vec<String>)>, lock: &mut Lock| {
        if let Some((name, version, deps)) = current.take() {
            lock.add(format!("{name}@{version}"), name, version, deps);
        }
    };
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let indent = line.len() - line.trim_start().len();
        let content = line.trim();
        if indent == 0 {
            finish(&mut current, &mut lock);
            in_graph = content == graph;
        } else if !in_graph {
            continue;
        } else if indent == 2 {
            finish(&mut current, &mut lock);
            current = package(content.trim_end_matches(" {}").trim_end_matches(':')).map(|(n, v)| (n, v, Vec::new()));
            in_deps = false;
        } else if indent == 4 {
            in_deps = ["dependencies:", "optionalDependencies:"].contains(&content);
        } else if indent == 6
            && in_deps
            && let (Some((_, _, deps)), Some((name, v))) = (current.as_mut(), content.split_once(": "))
        {
            // An alias points at another package (`/@scope/x@1.0.0`); otherwise it's this name.
            deps.push(match package(v) {
                Some((alias, version)) if unquote(v).starts_with('/') => format!("{alias}@{version}"),
                _ => format!("{}@{}", unquote(name), clean(v)),
            });
        }
    }
    finish(&mut current, &mut lock);
    for (name, version) in pnpm_importer(text, member) {
        let id = format!("{name}@{version}");
        if !lock.contains(&id) {
            lock.add(id.clone(), name.clone(), version, Vec::new());
        }
        lock.root(name, id);
    }
    lock
}

/// The `member` importer's dependencies in `pnpm-lock.yaml`, as (name, version).
fn pnpm_importer(text: &str, member: &str) -> Vec<(String, String)> {
    let importers = text.lines().any(|l| l == "importers:");
    let (section_indent, entry_indent) = if importers { (4, 6) } else { (0, 2) };
    let unquote = |s: &str| s.trim().trim_matches(['\'', '"']).to_string();
    let clean = |v: &str| unquote(v).split(['(', '_']).next().unwrap_or_default().to_string();
    let mut out = Vec::new();
    let (mut in_importer, mut in_section, mut current) = (!importers, false, None::<String>);
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let indent = line.len() - line.trim_start().len();
        let content = line.trim();
        if importers && indent == 0 {
            in_importer = false;
            continue;
        }
        if importers && indent == 2 {
            in_importer = unquote(content.trim_end_matches(':')) == member;
            continue;
        }
        if !in_importer {
            continue;
        }
        if indent == section_indent {
            in_section = ["dependencies:", "devDependencies:", "optionalDependencies:"].contains(&content);
            current = None;
        } else if in_section && indent == entry_indent {
            let Some((name, rest)) = content.rsplit_once(':') else { continue };
            current = None;
            if rest.trim().is_empty() {
                current = Some(unquote(name));
            } else {
                out.push((unquote(name), clean(rest)));
            }
        } else if in_section
            && indent == entry_indent + 2
            && let (Some(name), Some(v)) = (&current, content.strip_prefix("version:"))
        {
            out.push((name.clone(), clean(v)));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::testdir::TestDir;
    use super::*;

    /// (name, version, kind, via) of each dependency.
    fn summary(deps: &[Dependency]) -> Vec<(&str, Option<&str>, DepKind, Option<&str>)> {
        deps.iter().map(|d| (d.name.as_str(), d.version.as_deref(), d.kind, d.via.as_deref())).collect()
    }

    #[test]
    fn reads_ranges_and_lockfile_versions() {
        let t = TestDir::new("npm");
        t.file(
            "package.json",
            r#"{"dependencies":{"lodash":"^4.17.0","@tanstack/react-query":"^5"},"devDependencies":{"lodash":"^4","x":"workspace:*"}}"#,
        )
        .file(
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/lodash":{"version":"4.17.15"},
                "node_modules/a/node_modules/lodash":{"version":"3.0.0"},"apps/web/node_modules/lodash":{"version":"4.17.21"}}}"#,
        )
        .file("apps/web/package.json", r#"{"dependencies":{"lodash":"^4"}}"#);
        let found = read(&Folder::new(t.root(), t.root())).unwrap();
        assert_eq!(found.manager, Manager::Npm);
        let deps = found.deps;
        let get = |n: &str| deps.iter().find(|d| d.name == n).unwrap().clone();
        assert_eq!(deps.len(), 3, "lodash listed twice counts once; unreachable packages are left out");
        assert_eq!((get("lodash").version.as_deref(), get("lodash").exact), (Some("4.17.15"), true));
        assert_eq!((get("lodash").kind, get("x").kind), (DepKind::Prod, DepKind::Dev), "prod wins over dev");
        assert_eq!(
            (get("@tanstack/react-query").version.as_deref(), get("@tanstack/react-query").exact),
            (Some("5"), false)
        );
        assert_eq!(get("x").version, None);
        let member = read(&Folder::new(&t.path("apps/web"), t.root())).unwrap();
        assert_eq!(member.deps[0].version.as_deref(), Some("4.17.21"));
    }

    #[test]
    fn follows_package_lock_dependencies() {
        let v3 = r#"{"lockfileVersion":3,"packages":{
            "":{"dependencies":{"express":"^4"},"devDependencies":{"jest":"^29"}},
            "node_modules/express":{"version":"4.18.0","dependencies":{"qs":"6.11.0","debug":"2.6.9"}},
            "node_modules/express/node_modules/debug":{"version":"2.6.9","dependencies":{"ms":"2.0.0"}},
            "node_modules/debug":{"version":"4.3.4","dependencies":{"ms":"2.1.2"}},
            "node_modules/ms":{"version":"2.1.2"},
            "node_modules/qs":{"version":"6.11.0"},
            "node_modules/jest":{"version":"29.0.0","dependencies":{"debug":"^4"}}}}"#;
        let lock = npm_lock(&serde_json::from_str(v3).unwrap(), "");
        let direct = vec![
            Dependency::new("express", "^4", DepKind::Prod, &lock),
            Dependency::new("jest", "^29", DepKind::Dev, &lock),
        ];
        let deps = lock.with_transitive(direct);
        let mut got = summary(&deps);
        got[2..].sort();
        assert_eq!(
            got,
            [
                ("express", Some("4.18.0"), DepKind::Prod, None),
                ("jest", Some("29.0.0"), DepKind::Dev, None),
                ("debug", Some("2.6.9"), DepKind::Indirect, Some("express")),
                ("debug", Some("4.3.4"), DepKind::Dev, Some("jest")),
                ("ms", Some("2.1.2"), DepKind::Indirect, Some("express")),
                ("qs", Some("6.11.0"), DepKind::Indirect, Some("express")),
            ],
            "the nested debug resolves first; ms is hoisted"
        );
        let v1 = r#"{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0","requires":{"b":"^2"},
            "dependencies":{"b":{"version":"2.0.0"}}},"b":{"version":"3.0.0"}}}"#;
        let lock = npm_lock(&serde_json::from_str(v1).unwrap(), "");
        let deps = lock.with_transitive(vec![Dependency::new("a", "^1", DepKind::Prod, &lock)]);
        assert_eq!(summary(&deps)[1], ("b", Some("2.0.0"), DepKind::Indirect, Some("a")));
    }

    #[test]
    fn reads_yarn_classic_and_berry() {
        let classic = "# yarn lockfile v1\n\nlodash@^4.17.0, lodash@^4.17.21:\n  version \"4.17.21\"\n  resolved \"x\"\n\nlodash@^3.0.0:\n  version \"3.10.1\"\n\n\"@babel/core@^7.0.0\":\n  version \"7.23.0\"\n  dependencies:\n    debug \"^4.1.0\"\n\ndebug@^4.1.0:\n  version \"4.3.4\"\n";
        let lock = yarn_lock(classic, &[("lodash", "^3.0.0"), ("@babel/core", "^7.1.0")]);
        assert_eq!(lock.version("lodash"), Some("3.10.1"));
        assert_eq!(lock.version("@babel/core"), Some("7.23.0"), "falls back to any locked version");
        let deps = lock.with_transitive(vec![Dependency::new("@babel/core", "^7.1.0", DepKind::Prod, &lock)]);
        assert_eq!(summary(&deps)[1], ("debug", Some("4.3.4"), DepKind::Indirect, Some("@babel/core")));
        let berry = "__metadata:\n  version: 10\n\n\"@ampproject/remapping@npm:^2.2.0\":\n  version: 2.3.0\n  resolution: \"x\"\n  dependencies:\n    \"@jridgewell/gen-mapping\": \"npm:^0.3.5\"\n\n\"@jridgewell/gen-mapping@npm:^0.3.5\":\n  version: 0.3.5\n";
        let lock = yarn_lock(berry, &[("@ampproject/remapping", "^2.2.0")]);
        assert_eq!(lock.version("@ampproject/remapping"), Some("2.3.0"));
        let deps = lock.with_transitive(vec![Dependency::new("@ampproject/remapping", "^2.2.0", DepKind::Prod, &lock)]);
        assert_eq!(deps[1].name, "@jridgewell/gen-mapping");
    }

    #[test]
    fn reads_pnpm_v9_importers_and_v5() {
        let v9 = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      '@dnd-kit/core':\n        specifier: ^6.3.1\n        version: 6.3.1(react-dom@19.2.4(react@19.2.4))(react@19.2.4)\n    devDependencies:\n      typescript:\n        specifier: ^5\n        version: 5.6.3\n\n  apps/web:\n    dependencies:\n      next:\n        specifier: ^15\n        version: 15.0.0\n\npackages:\n\n  typescript@5.6.3:\n    resolution: {integrity: x}\n\nsnapshots:\n\n  '@dnd-kit/core@6.3.1(react-dom@19.2.4(react@19.2.4))(react@19.2.4)':\n    dependencies:\n      tslib: 2.8.1\n      react: 19.2.4\n\n  tslib@2.8.1: {}\n\n  react@19.2.4: {}\n\n  typescript@5.6.3: {}\n";
        let root = pnpm_lock(v9, ".");
        assert_eq!((root.version("@dnd-kit/core"), root.version("typescript")), (Some("6.3.1"), Some("5.6.3")));
        assert_eq!(pnpm_lock(v9, "apps/web").version("next"), Some("15.0.0"));
        let deps = root.with_transitive(vec![Dependency::new("@dnd-kit/core", "^6", DepKind::Prod, &root)]);
        let mut names: Vec<&str> = deps[1..].iter().map(|d| d.name.as_str()).collect();
        names.sort();
        assert_eq!(names, ["react", "tslib"]);
        let v5 = "lockfileVersion: 5.4\n\nspecifiers:\n  react: ^18.2.0\n\ndependencies:\n  react: 18.2.0\n  react-dom: 18.2.0_react@18.2.0\n\npackages:\n\n  /react-dom/18.2.0_react@18.2.0:\n    dependencies:\n      scheduler: 0.23.0\n\n  /react/18.2.0:\n    resolution: {integrity: x}\n\n  /scheduler/0.23.0:\n    resolution: {integrity: x}\n";
        let lock = pnpm_lock(v5, ".");
        assert_eq!((lock.version("react"), lock.version("react-dom")), (Some("18.2.0"), Some("18.2.0")));
        let deps = lock.with_transitive(vec![Dependency::new("react-dom", "^18", DepKind::Prod, &lock)]);
        assert_eq!(summary(&deps)[1], ("scheduler", Some("0.23.0"), DepKind::Indirect, Some("react-dom")));
    }

    #[test]
    fn reads_bun_lock() {
        let text = r#"{
  "lockfileVersion": 1,
  "workspaces": { "": { "name": "app", "dependencies": { "@scope/a": "^1", }, }, },
  "packages": {
    "@scope/a": ["@scope/a@1.0.0", "", { "dependencies": { "b": "^2", }, }, "sha512-x"],
    "@scope/a/b": ["b@2.0.0", "", {}, "sha512-y"],
    "b": ["b@3.0.0", "", {}, "sha512-z"],
  },
}"#;
        let lock = bun_lock(&serde_json::from_str(&strip_trailing_commas(text)).unwrap());
        assert_eq!(lock.version("@scope/a"), Some("1.0.0"));
        let deps = lock.with_transitive(vec![Dependency::new("@scope/a", "^1", DepKind::Prod, &lock)]);
        assert_eq!(summary(&deps)[1], ("b", Some("2.0.0"), DepKind::Indirect, Some("@scope/a")));
        assert_eq!(strip_trailing_commas(r#"{"a": "x,}", "b": [1, ],}"#), r#"{"a": "x,}", "b": [1 ]}"#);
    }
}
