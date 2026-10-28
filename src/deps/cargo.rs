//! Rust: `Cargo.toml`, with exact versions from `Cargo.lock` when present.

use toml::{Table, Value};

use super::{DepKind, Dependency, Folder, Found, Manager, read_toml, toml_lock};

pub(super) fn read(f: &Folder) -> Option<Found> {
    let manifest = read_toml(&f.dir.join("Cargo.toml"))?;
    let mut locked = toml_lock(f.find_up("Cargo.lock"), str::to_string);
    if let Some(own) = manifest.get("package").and_then(|p| p.get("name")).and_then(Value::as_str) {
        locked.roots_from(own);
    }
    let table = |v: Option<&Value>| v.and_then(Value::as_table).cloned().unwrap_or_default();
    // Runtime sections first, so a crate also listed as a dev or build dependency counts as runtime.
    let sections: [(Table, DepKind); 4] = [
        (table(manifest.get("dependencies")), DepKind::Prod),
        (table(manifest.get("workspace").and_then(|w| w.get("dependencies"))), DepKind::Prod),
        (table(manifest.get("dev-dependencies")), DepKind::Dev),
        (table(manifest.get("build-dependencies")), DepKind::Dev),
    ];
    let mut deps: Vec<Dependency> = Vec::new();
    for (key, spec, kind) in sections.iter().flat_map(|(t, kind)| t.iter().map(move |(k, v)| (k, v, *kind))) {
        // `foo = "1"`, or `foo = { version = "1", package = "real-name" }`
        let (name, requirement) = match spec {
            Value::String(req) => (key.as_str(), req.as_str()),
            Value::Table(t) => (
                t.get("package").and_then(Value::as_str).unwrap_or(key),
                t.get("version").and_then(Value::as_str).unwrap_or_default(),
            ),
            _ => continue,
        };
        if !deps.iter().any(|d| d.name == name) {
            deps.push(Dependency::new(name, requirement, kind, &locked));
        }
    }
    Some(Found::new(deps, &locked, Manager::Cargo, "Cargo.toml"))
}

#[cfg(test)]
mod tests {
    use super::super::testdir::TestDir;
    use super::*;

    #[test]
    fn reads_renames_workspace_deps_and_lock() {
        let t = TestDir::new("cargo");
        t.file(
            "Cargo.toml",
            "[workspace.dependencies]\ntokio = \"1.20\"\n[dependencies]\nser = { package = \"serde\", version = \"1\" }\nlocal = { path = \"../x\" }\n[dev-dependencies]\ntokio = \"1\"\ninsta = \"1.40\"\n",
        )
        .file("Cargo.lock", "[[package]]\nname = \"tokio\"\nversion = \"1.38.0\"\n");
        let deps = read(&Folder::new(t.root(), t.root())).unwrap().deps;
        let names: Vec<(&str, Option<&str>, bool, DepKind)> =
            deps.iter().map(|d| (d.name.as_str(), d.version.as_deref(), d.exact, d.kind)).collect();
        // Tables are read in key order: `local` before `ser`.
        assert_eq!(
            names,
            [
                ("local", None, false, DepKind::Prod),
                ("serde", Some("1"), false, DepKind::Prod),
                ("tokio", Some("1.38.0"), true, DepKind::Prod),
                ("insta", Some("1.40"), false, DepKind::Dev),
            ]
        );
    }

    #[test]
    fn follows_cargo_lock_dependencies_of_the_own_package() {
        let t = TestDir::new("cargo-tree");
        t.file("Cargo.toml", "[package]\nname = \"app\"\n[dependencies]\nreqwest = \"0.12\"\n")
            .file(
                "Cargo.lock",
                "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"reqwest 0.12.0\"]\n\n\
                 [[package]]\nname = \"reqwest\"\nversion = \"0.11.0\"\n\n\
                 [[package]]\nname = \"reqwest\"\nversion = \"0.12.0\"\nsource = \"registry+x\"\ndependencies = [\"h2\"]\n\n\
                 [[package]]\nname = \"h2\"\nversion = \"0.4.0\"\n",
            );
        let deps = read(&Folder::new(t.root(), t.root())).unwrap().deps;
        let got: Vec<(&str, Option<&str>, Option<&str>)> =
            deps.iter().map(|d| (d.name.as_str(), d.version.as_deref(), d.via.as_deref())).collect();
        assert_eq!(got, [("reqwest", Some("0.12.0"), None), ("h2", Some("0.4.0"), Some("reqwest"))]);
    }
}
