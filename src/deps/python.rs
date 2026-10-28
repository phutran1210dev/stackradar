//! Python: `requirements.txt` and `pyproject.toml` (PEP 621 or Poetry), with exact
//! versions from `poetry.lock` / `uv.lock` when present.

use std::collections::HashMap;

use toml::Value;

use super::{DepKind, Dependency, Folder, Found, Manager, read_toml, toml_lock};

/// PEP 503 name normalization, so `Foo_Bar` and `foo-bar` are one package.
pub fn normalize(name: &str) -> String {
    name.to_ascii_lowercase().replace(['_', '.'], "-")
}

pub(super) fn read(f: &Folder) -> Option<Found> {
    let requirements = f.read("requirements.txt");
    let pyproject = read_toml(&f.dir.join("pyproject.toml"));
    let manifest = match (&pyproject, &requirements) {
        (Some(_), _) => "pyproject.toml",
        (None, Some(_)) => "requirements.txt",
        (None, None) => return None,
    };
    let (lock, manager) = match (f.find_up("poetry.lock"), f.find_up("uv.lock")) {
        (Some(p), _) => (Some(p), Manager::Poetry),
        (None, Some(u)) => (Some(u), Manager::Uv),
        (None, None) => (None, Manager::Pip),
    };
    let locked = toml_lock(lock, normalize);
    let mut specs: Vec<(String, String, DepKind)> = requirements
        .iter()
        .flat_map(|r| r.lines())
        .filter_map(pep508)
        .map(|(name, req)| (name, req, DepKind::Prod))
        .collect();
    if let Some(p) = &pyproject {
        specs.extend(pyproject_specs(p));
    }
    let mut deps: Vec<Dependency> = Vec::new();
    for (name, requirement, kind) in specs {
        if name != "python" && !deps.iter().any(|d| d.name == name) {
            deps.push(Dependency::new(&name, &requirement, kind, &locked));
        }
    }
    Some(Found::new(deps, &locked, manager, manifest))
}

/// `name[extra] >=1.0 ; marker` → (normalized name, `>=1.0`). Skips comments, options
/// (`-r`, `-e`, `--index-url`) and blank lines.
fn pep508(line: &str) -> Option<(String, String)> {
    let line = line.split(" #").next()?.trim();
    if line.is_empty() || line.starts_with(['#', '-']) {
        return None;
    }
    let end = line.find(|c: char| !(c.is_ascii_alphanumeric() || "-_.".contains(c))).unwrap_or(line.len());
    let (name, rest) = line.split_at(end);
    let rest = rest.split(';').next()?.trim();
    let rest = rest.strip_prefix('[').and_then(|r| r.split_once(']')).map_or(rest, |(_, after)| after).trim();
    // `name @ https://…` is a direct reference: no version to compare.
    let requirement = if rest.starts_with('@') { "" } else { rest.trim_start_matches('(').trim_end_matches(')') };
    (!name.is_empty()).then(|| (normalize(name), requirement.to_string()))
}

/// `[project].dependencies` strings and Poetry's `[tool.poetry.*dependencies]` tables.
/// Poetry groups and the legacy `dev-dependencies` table are dev dependencies.
fn pyproject_specs(p: &toml::Table) -> Vec<(String, String, DepKind)> {
    let mut out: Vec<(String, String, DepKind)> = p
        .get("project")
        .and_then(|x| x.get("dependencies"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|v| pep508(v.as_str()?))
        .map(|(name, req)| (name, req, DepKind::Prod))
        .collect();
    let poetry = p.get("tool").and_then(|t| t.get("poetry"));
    let groups = poetry.and_then(|x| x.get("group")).and_then(Value::as_table);
    let main = poetry.and_then(|x| x.get("dependencies")).map(|t| (t, DepKind::Prod));
    let dev = poetry
        .and_then(|x| x.get("dev-dependencies"))
        .into_iter()
        .chain(groups.into_iter().flat_map(|g| g.values().filter_map(|g| g.get("dependencies"))))
        .map(|t| (t, DepKind::Dev));
    let poetry_version = |spec: &Value| match spec {
        Value::String(s) => s.clone(),
        other => other.get("version").and_then(Value::as_str).unwrap_or_default().to_string(),
    };
    // Main dependencies first, so a package also in a group counts as main.
    let mut entries: HashMap<String, (String, DepKind)> = HashMap::new();
    for (table, kind) in main.into_iter().chain(dev) {
        for (k, v) in table.as_table().into_iter().flatten() {
            entries.entry(normalize(k)).or_insert_with(|| (poetry_version(v), kind));
        }
    }
    let mut entries: Vec<(String, String, DepKind)> =
        entries.into_iter().map(|(name, (req, kind))| (name, req, kind)).collect();
    entries.sort();
    out.extend(entries);
    out
}

#[cfg(test)]
mod tests {
    use super::super::testdir::TestDir;
    use super::*;

    #[test]
    fn parses_requirement_lines() {
        let p = |l: &str| pep508(l);
        assert_eq!(p("Requests[socks]>=2.28,<3 ; python_version>'3'"), Some(("requests".into(), ">=2.28,<3".into())));
        assert_eq!(p("django==4.2.1  # pinned"), Some(("django".into(), "==4.2.1".into())));
        assert_eq!(p("pkg @ https://x/y.whl"), Some(("pkg".into(), String::new())));
        assert_eq!(p("Typing_Extensions"), Some(("typing-extensions".into(), String::new())));
        assert_eq!(p("-r base.txt"), None);
        assert_eq!(p("# comment"), None);
    }

    #[test]
    fn reads_pyproject_and_lock() {
        let t = TestDir::new("python");
        t.file(
            "pyproject.toml",
            "[project]\ndependencies = [\"fastapi>=0.100\"]\n[tool.poetry.dependencies]\npython = \"^3.11\"\nhttpx = { version = \"^0.27\" }\n[tool.poetry.group.dev.dependencies]\npytest = \"^8\"\nhttpx = \"^0.28\"\n",
        )
        .file("requirements.txt", "requests==2.19.0\n")
        .file(
            "poetry.lock",
            "[[package]]\nname = \"FastAPI\"\nversion = \"0.110.0\"\n[package.dependencies]\nStarlette = \">=0.36\"\n\n\
             [[package]]\nname = \"starlette\"\nversion = \"0.36.3\"\n",
        );
        let found = read(&Folder::new(t.root(), t.root())).unwrap();
        assert_eq!((found.manager, found.manifest.as_str()), (Manager::Poetry, "pyproject.toml"));
        let deps = found.deps;
        let got: Vec<(&str, Option<&str>, bool, DepKind)> =
            deps.iter().map(|d| (d.name.as_str(), d.version.as_deref(), d.exact, d.kind)).collect();
        assert_eq!(
            got,
            [
                ("requests", Some("2.19.0"), true, DepKind::Prod),
                ("fastapi", Some("0.110.0"), true, DepKind::Prod),
                ("httpx", Some("0.27"), false, DepKind::Prod),
                ("pytest", Some("8"), false, DepKind::Dev),
                ("starlette", Some("0.36.3"), true, DepKind::Indirect),
            ]
        );
        assert_eq!(deps[4].via.as_deref(), Some("fastapi"));
    }
}
