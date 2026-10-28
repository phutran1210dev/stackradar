//! Your own projects and what they depend on, read from the manifests (and lockfiles,
//! for exact versions) under the config's `scan` folders. Feeds "For you" and the
//! vulnerability check.

mod cargo;
mod composer;
mod dotnet;
mod go;
mod jvm;
mod lock;
mod npm;
mod pub_dart;
mod python;
mod ruby;
pub mod version;
mod xml;

use std::any::{Any, TypeId};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use serde::Serialize;

use crate::store::paths;
use lock::Lock;

/// Manifests are looked for this many directory levels deep (monorepos).
const MAX_DEPTH: usize = 3;
/// Largest manifest or lockfile read (a big monorepo lockfile is a few MB).
const MAX_FILE_BYTES: u64 = 64 << 20;
const SKIP_DIRS: &[&str] =
    &["node_modules", "target", "dist", "build", "vendor", "Library", "venv", "__pycache__", "site-packages", "Pods"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Npm,
    Cargo,
    Go,
    Pip,
    Composer,
    RubyGems,
    Pub,
    NuGet,
    Maven,
}

impl Ecosystem {
    pub const ALL: [Ecosystem; 9] = [
        Ecosystem::Npm,
        Ecosystem::Cargo,
        Ecosystem::Go,
        Ecosystem::Pip,
        Ecosystem::Composer,
        Ecosystem::RubyGems,
        Ecosystem::Pub,
        Ecosystem::NuGet,
        Ecosystem::Maven,
    ];

    /// The name GitHub's advisory database uses.
    pub fn advisory_name(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Cargo => "rust",
            Ecosystem::Go => "go",
            Ecosystem::Pip => "pip",
            Ecosystem::Composer => "composer",
            Ecosystem::RubyGems => "rubygems",
            Ecosystem::Pub => "pub",
            Ecosystem::NuGet => "nuget",
            Ecosystem::Maven => "maven",
        }
    }

    pub fn from_advisory_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|e| e.advisory_name() == name)
    }

    /// The package name as this ecosystem compares names (PyPI ignores case and `-_.`;
    /// Composer and NuGet ignore case).
    pub fn normalize(self, name: &str) -> String {
        match self {
            Ecosystem::Pip => python::normalize(name),
            Ecosystem::Composer | Ecosystem::NuGet => name.to_ascii_lowercase(),
            _ => name.to_string(),
        }
    }
}

/// The tool that manages a project's dependencies, which decides the commands to run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Manager {
    #[default]
    Npm,
    /// Yarn 1
    Yarn,
    /// Yarn 2+ (a `__metadata` block in `yarn.lock`)
    YarnBerry,
    Pnpm,
    Bun,
    Cargo,
    Go,
    Pip,
    Poetry,
    Uv,
    Composer,
    Bundler,
    Pub,
    Dotnet,
    Maven,
    Gradle,
}

/// How a project depends on a package, most important first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DepKind {
    /// Shipped or run with the project
    #[default]
    Prod,
    /// Only pulled in by another dependency (Go's `// indirect`)
    Indirect,
    /// Only for development, tests or the build (`devDependencies`, Cargo dev/build, Poetry groups)
    Dev,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Dependency {
    pub name: String,
    /// Locked version, else the lowest version the manifest allows; None if unknown
    /// (git/path dependencies, `*`, …)
    pub version: Option<String>,
    /// `version` comes from a lockfile (or an exact pin), not a range
    pub exact: bool,
    pub kind: DepKind,
    /// For a transitive dependency, the direct one that pulls it in (if the lockfile says)
    pub via: Option<String>,
}

impl Dependency {
    /// From a manifest's name and version requirement, preferring the locked version.
    fn new(name: &str, requirement: &str, kind: DepKind, lock: &Lock) -> Self {
        let (version, exact) = match lock.version(name) {
            Some(v) => (Some(v.to_string()), true),
            None => (version::lowest(requirement), version::is_pin(requirement)),
        };
        Self { name: name.to_string(), version, exact, kind, via: None }
    }

    /// Declared in a manifest, not pulled in by another dependency.
    pub fn is_direct(&self) -> bool {
        self.via.is_none() && self.kind != DepKind::Indirect
    }
}

/// What a reader found in a folder.
pub(super) struct Found {
    /// Direct dependencies first, then the transitive ones from the lockfile
    deps: Vec<Dependency>,
    manager: Manager,
    /// The manifest file, e.g. `package.json`
    manifest: String,
}

impl Found {
    /// `declared` with their locked versions and what the lock says they pull in.
    fn new(declared: Vec<Dependency>, lock: &Lock, manager: Manager, manifest: impl Into<String>) -> Self {
        Self { deps: lock.with_transitive(declared), manager, manifest: manifest.into() }
    }
}

#[derive(Debug)]
pub struct Project {
    pub dir: PathBuf,
    pub ecosystem: Ecosystem,
    pub manager: Manager,
    /// The manifest the dependencies are declared in
    pub manifest: PathBuf,
    pub deps: Vec<Dependency>,
}

impl Project {
    /// `~/code/app`-style path for display.
    pub fn label(&self) -> String {
        paths::tilde(&self.dir)
    }
}

/// A project folder being read, inside the folder that was asked to be scanned. Nothing
/// outside that root is read: lockfiles are looked for in parents only up to it.
pub(super) struct Folder<'a> {
    pub dir: &'a Path,
    root: &'a Path,
}

impl<'a> Folder<'a> {
    fn new(dir: &'a Path, root: &'a Path) -> Self {
        Self { dir, root }
    }

    /// The folder and up to two parents inside the root (a workspace root holds the
    /// lockfile for its members).
    fn ancestors(&self) -> impl Iterator<Item = &'a Path> {
        let root = self.root;
        self.dir.ancestors().take(3).take_while(move |d| d.starts_with(root))
    }

    /// `name` in the folder or the nearest of its `ancestors`.
    fn find_up(&self, name: &str) -> Option<PathBuf> {
        self.ancestors().map(|d| d.join(name)).find(|p| is_plain_file(p))
    }

    fn read(&self, name: &str) -> Option<String> {
        read_file(&self.dir.join(name))
    }

    /// The first file in the folder (by name) with one of `extensions`, e.g. `app.csproj`.
    fn find_ext(&self, extensions: &[&str]) -> Option<(String, String)> {
        let mut names: Vec<String> = std::fs::read_dir(self.dir)
            .ok()?
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| extensions.iter().any(|ext| n.ends_with(ext)))
            .collect();
        names.sort();
        names.into_iter().find_map(|n| Some((self.read(&n)?, n)))
    }
}

thread_local! {
    /// What `scan` couldn't read or parse: the projects or lockfiles it had to skip.
    static PROBLEMS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

thread_local! {
    /// Lockfiles read or parsed during this `scan`, by path and result type: a workspace's
    /// members share the lockfile at its root, which is then read and reported on once.
    static PARSED: RefCell<HashMap<(PathBuf, TypeId), Rc<dyn Any>>> = RefCell::new(HashMap::new());
}

/// `parse()` for the file at `path`, run once per scan.
fn once<T: 'static>(path: &Path, parse: impl FnOnce() -> T) -> Rc<T> {
    let key = (path.to_path_buf(), TypeId::of::<T>());
    if let Some(done) = PARSED.with_borrow(|m| m.get(&key).cloned()) {
        return done.downcast().expect("keyed by type");
    }
    let value = Rc::new(parse());
    PARSED.with_borrow_mut(|m| m.insert(key, value.clone()));
    value
}

/// Note a file or folder `scan` had to skip, so the check is reported as incomplete.
fn problem(path: &Path, why: impl std::fmt::Display) {
    PROBLEMS.with_borrow_mut(|p| p.push(format!("{}: {why}", paths::tilde(path))));
}

/// `text` as JSON, noting `path` as a problem if it isn't.
fn parse_json(path: &Path, text: &str) -> Option<serde_json::Value> {
    serde_json::from_str(text).map_err(|e| problem(path, format!("not valid JSON ({e})"))).ok()
}

/// A regular file, not a symlink (which could point outside the scanned folder).
fn is_plain_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file())
}

/// A manifest's or lockfile's text, or None if there is no such file. Symlinks are
/// skipped; oversized and unreadable files are skipped as problems.
fn read_file(path: &Path) -> Option<String> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            problem(path, e);
            return None;
        }
    };
    if !meta.is_file() {
        return None;
    }
    if meta.len() > MAX_FILE_BYTES {
        problem(path, format!("{} MB, over the {} MB limit", meta.len() >> 20, MAX_FILE_BYTES >> 20));
        return None;
    }
    std::fs::read_to_string(path).map_err(|e| problem(path, e)).ok()
}

/// The dependencies declared in a folder, or None if it has no manifest of that kind.
type Reader = fn(&Folder) -> Option<Found>;

const READERS: &[(Ecosystem, Reader)] = &[
    (Ecosystem::Npm, npm::read),
    (Ecosystem::Cargo, cargo::read),
    (Ecosystem::Go, go::read),
    (Ecosystem::Pip, python::read),
    (Ecosystem::Composer, composer::read),
    (Ecosystem::RubyGems, ruby::read),
    (Ecosystem::Pub, pub_dart::read),
    (Ecosystem::NuGet, dotnet::read),
    (Ecosystem::Maven, jvm::read),
];

/// Manifest names, for messages.
pub const MANIFESTS: &str = "package.json, Cargo.toml, go.mod, pyproject.toml, requirements.txt, composer.json, \
    Gemfile, pubspec.yaml, *.csproj, pom.xml, build.gradle";

/// Every project (with at least one dependency) under `dirs`, and the files and folders
/// there that couldn't be read or parsed (what they hold went unchecked).
pub fn scan(dirs: &[PathBuf]) -> (Vec<Project>, Vec<String>) {
    PROBLEMS.with_borrow_mut(Vec::clear);
    let mut out = Vec::new();
    for d in dirs {
        walk(d, d, 0, &mut out);
    }
    PARSED.with_borrow_mut(HashMap::clear);
    (out, PROBLEMS.take())
}

fn walk(dir: &Path, root: &Path, depth: usize, out: &mut Vec<Project>) {
    // Checked first: in a folder that can't be listed, every manifest would fail to read too.
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => return problem(dir, e),
    };
    for &(ecosystem, read) in READERS {
        if let Some(found) = read(&Folder::new(dir, root)).filter(|f| !f.deps.is_empty()) {
            out.push(Project {
                dir: dir.to_path_buf(),
                ecosystem,
                manager: found.manager,
                manifest: dir.join(&found.manifest),
                deps: found.deps,
            });
        }
    }
    if depth == MAX_DEPTH {
        return;
    }
    let mut subdirs: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            !name.starts_with('.') && !SKIP_DIRS.contains(&name.as_ref()) && e.file_type().is_ok_and(|t| t.is_dir())
        })
        .map(|e| e.path())
        .collect();
    subdirs.sort();
    for d in subdirs {
        walk(&d, root, depth + 1, out);
    }
}

fn read_toml(path: &Path) -> Option<toml::Table> {
    let text = read_file(path)?;
    text.parse().map_err(|e: toml::de::Error| problem(path, format!("not valid TOML ({})", e.message()))).ok()
}

/// A `[[package]]` lockfile (Cargo.lock, poetry.lock, uv.lock). Packages are `name version`;
/// a dependency is `"name"` / `"name version (source)"` (Cargo), `{ name = "x" }` (uv) or a
/// table key (Poetry), and one without a version resolves to the first version locked.
/// A direct dependency resolves to the first version locked, too.
fn toml_lock(path: Option<PathBuf>, normalize: fn(&str) -> String) -> Lock {
    use toml::Value;
    let packages =
        path.map(|p| once(&p, || read_toml(&p))).and_then(|t| t.as_ref().as_ref()?.get("package")?.as_array().cloned());
    // (name, version, dependencies as (name, version if given))
    type Package = (String, String, Vec<(String, Option<String>)>);
    let packages: Vec<Package> = packages
        .unwrap_or_default()
        .iter()
        .filter_map(|p| {
            let deps = match p.get("dependencies") {
                Some(Value::Array(a)) => a
                    .iter()
                    .filter_map(|d| match d {
                        Value::String(s) => {
                            let mut parts = s.split_whitespace();
                            Some((normalize(parts.next()?), parts.next().map(String::from)))
                        }
                        Value::Table(t) => Some((
                            normalize(t.get("name")?.as_str()?),
                            t.get("version").and_then(Value::as_str).map(String::from),
                        )),
                        _ => None,
                    })
                    .collect(),
                Some(Value::Table(t)) => t.keys().map(|k| (normalize(k), None)).collect(),
                _ => Vec::new(),
            };
            Some((normalize(p.get("name")?.as_str()?), p.get("version")?.as_str()?.to_string(), deps))
        })
        .collect();
    let mut first: HashMap<&str, String> = HashMap::new();
    for (name, v, _) in &packages {
        first.entry(name).or_insert_with(|| format!("{name} {v}"));
    }
    let mut lock = Lock::default();
    for (name, v, deps) in &packages {
        let deps = deps
            .iter()
            .filter_map(|(d, v)| v.as_ref().map(|v| format!("{d} {v}")).or_else(|| first.get(d.as_str()).cloned()))
            .collect();
        lock.add(format!("{name} {v}"), name, v, deps);
    }
    for (name, id) in first {
        lock.root(name, id);
    }
    lock
}

#[cfg(test)]
pub(crate) mod testdir {
    use std::path::{Path, PathBuf};

    /// A temporary directory removed when dropped.
    pub struct TestDir(pub PathBuf);

    impl TestDir {
        pub fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("stackradar-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        /// Write `content` to `rel` (creating parent folders).
        pub fn file(&self, rel: &str, content: &str) -> &Self {
            let p = self.0.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, content).unwrap();
            self
        }

        pub fn path(&self, rel: &str) -> PathBuf {
            self.0.join(rel)
        }

        pub fn root(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testdir::TestDir;
    use super::*;

    #[test]
    fn scans_every_ecosystem_and_skips_vendored_dirs() {
        let t = TestDir::new("deps-scan");
        t.file("web/package.json", r#"{"dependencies":{"zustand":"^4.5.0"}}"#)
            .file("web/node_modules/x/package.json", r#"{"dependencies":{"ignored":"1"}}"#)
            .file("cli/Cargo.toml", "[dependencies]\nserde = \"1\"\n")
            .file("svc/go.mod", "module x\n\nrequire github.com/gin-gonic/gin v1.9.0\n")
            .file("ml/requirements.txt", "requests==2.31.0\n")
            .file("empty/package.json", r#"{"name":"no-deps"}"#);
        let (projects, problems) = scan(&[t.root().to_path_buf()]);
        assert!(problems.is_empty(), "{problems:?}");
        let found: Vec<(String, Ecosystem)> =
            projects.iter().map(|p| (p.dir.file_name().unwrap().to_string_lossy().into_owned(), p.ecosystem)).collect();
        assert_eq!(
            found,
            [
                ("cli".into(), Ecosystem::Cargo),
                ("ml".into(), Ecosystem::Pip),
                ("svc".into(), Ecosystem::Go),
                ("web".into(), Ecosystem::Npm),
            ]
        );
    }

    // Creating symlinks on Windows needs admin rights or Developer Mode.
    #[cfg(unix)]
    #[test]
    fn never_reads_outside_the_scanned_folder() {
        let t = TestDir::new("deps-root");
        t.file("Cargo.lock", "[[package]]\nname = \"serde\"\nversion = \"1.0.100\"\n")
            .file("repo/app/Cargo.toml", "[dependencies]\nserde = \"1\"\n")
            .file("outside/package.json", r#"{"dependencies":{"lodash":"4.17.15"}}"#);
        std::os::unix::fs::symlink(t.path("outside"), t.path("repo/linked")).unwrap();
        std::os::unix::fs::symlink(t.path("outside/package.json"), t.path("repo/app/package.json")).unwrap();
        let (projects, _) = scan(&[t.path("repo")]);
        assert_eq!(projects.len(), 1, "symlinked folders and manifests are skipped");
        assert_eq!(projects[0].deps[0].version.as_deref(), Some("1"), "the lockfile above the root is not read");
        // Scanning the parent, the workspace lockfile is in reach.
        let (projects, _) = scan(&[t.root().to_path_buf()]);
        let app = projects.iter().find(|p| p.dir.ends_with("app")).unwrap();
        assert_eq!(app.deps[0].version.as_deref(), Some("1.0.100"));
    }

    #[test]
    fn reports_what_it_could_not_parse() {
        let t = TestDir::new("deps-problems");
        t.file("broken/package.json", "{")
            .file("locked/package.json", r#"{"dependencies":{"zustand":"^4.5.0"}}"#)
            .file("locked/package-lock.json", "{\"packages\": [")
            .file("rust/Cargo.toml", "[dependencies\n");
        // Both workspace members share the broken lockfile at its root: reported once.
        t.file("locked/packages/a/package.json", r#"{"dependencies":{"zustand":"^4.5.0"}}"#)
            .file("locked/packages/b/package.json", r#"{"dependencies":{"zustand":"^4.5.0"}}"#);
        let (projects, problems) = scan(&[t.root().to_path_buf()]);
        assert_eq!(projects.len(), 3, "projects with a broken lockfile are still checked by their manifests");
        assert_eq!(problems.len(), 3, "{problems:?}");
        assert!(problems[0].contains("package.json: not valid JSON"), "{problems:?}");
        assert!(problems[1].contains("package-lock.json: not valid JSON"), "{problems:?}");
        assert!(problems[2].contains("Cargo.toml: not valid TOML"), "{problems:?}");
    }

    #[cfg(unix)]
    #[test]
    fn reports_unreadable_folders() {
        use std::os::unix::fs::PermissionsExt;
        let t = TestDir::new("deps-unreadable");
        t.file("app/package.json", r#"{"dependencies":{"zustand":"^4.5.0"}}"#).file("locked/x", "");
        std::fs::set_permissions(t.path("locked"), std::fs::Permissions::from_mode(0o000)).unwrap();
        let readable = std::fs::read_dir(t.path("locked")).is_ok(); // as root, it still is
        let (projects, problems) = scan(&[t.root().to_path_buf()]);
        std::fs::set_permissions(t.path("locked"), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(projects.len(), 1);
        if !readable {
            assert_eq!(problems.len(), 1, "{problems:?}");
            assert!(problems[0].contains("locked"), "{problems:?}");
        }
    }

    #[test]
    fn prefers_locked_versions() {
        let mut locked = Lock::default();
        locked.add("a 1.4.2", "a", "1.4.2", vec![]);
        locked.root("a", "a 1.4.2");
        let new = |name, req| Dependency::new(name, req, DepKind::Prod, &locked);
        assert_eq!(new("a", "^1.0.0").version.as_deref(), Some("1.4.2"));
        let d = new("b", "^2.1.0");
        assert_eq!((d.version.as_deref(), d.exact), (Some("2.1.0"), false));
        assert_eq!(new("c", "git+https://x").version, None);
    }
}
