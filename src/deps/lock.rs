//! A lockfile as a dependency graph: the exact version of each direct dependency, and
//! the packages those pull in (transitive dependencies), each tagged with the direct
//! dependency it comes through.

use std::collections::{HashMap, HashSet, VecDeque};

use super::{DepKind, Dependency, version};

/// One locked package.
#[derive(Debug)]
struct Locked {
    name: String,
    version: String,
    /// Ids of the packages it depends on
    deps: Vec<String>,
}

#[derive(Debug, Default)]
pub(super) struct Lock {
    /// Id (unique per lockfile, e.g. `node_modules/a/node_modules/b` or `serde 1.0.0`) → package
    packages: HashMap<String, Locked>,
    /// Direct dependency name → id of the version the project uses
    roots: HashMap<String, String>,
    /// The lockfile lists no dependency edges (pubspec.lock, gradle.lockfile): every
    /// package that isn't direct counts as pulled in, through an unknown one.
    flat: bool,
}

impl Lock {
    /// A lock whose edges are unknown (see `flat`).
    pub fn flat() -> Self {
        Self { flat: true, ..Self::default() }
    }

    /// Add a package, unless its version can't be compared (links, `file:`, workspaces).
    pub fn add(
        &mut self,
        id: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
        deps: Vec<String>,
    ) {
        let version = version.into();
        if version::lowest(&version).is_some() {
            self.packages.insert(id.into(), Locked { name: name.into(), version, deps });
        }
    }

    /// `name` resolves to package `id` for the project.
    pub fn root(&mut self, name: impl Into<String>, id: impl Into<String>) {
        self.roots.insert(name.into(), id.into());
    }

    /// Like `root`, keeping an earlier one.
    pub fn root_default(&mut self, name: impl Into<String>, id: impl Into<String>) {
        self.roots.entry(name.into()).or_insert_with(|| id.into());
    }

    pub fn contains(&self, id: &str) -> bool {
        self.packages.contains_key(id)
    }

    /// The ids `id` depends on.
    pub fn deps_of(&self, id: &str) -> &[String] {
        self.packages.get(id).map_or(&[], |p| &p.deps)
    }

    /// Replace the roots with what package `name` (the project's own entry, in a
    /// workspace lockfile) depends on, which picks the right one of several locked versions.
    pub fn roots_from(&mut self, name: &str) {
        let Some(own) = self.packages.values().find(|p| p.name == name) else { return };
        self.roots = own.deps.iter().filter_map(|d| Some((self.packages.get(d)?.name.clone(), d.clone()))).collect();
    }

    /// How the lock spells direct dependency `name`, compared ignoring case (NuGet).
    pub fn root_name(&self, name: &str) -> Option<&str> {
        self.roots.keys().find(|k| k.eq_ignore_ascii_case(name)).map(String::as_str)
    }

    /// The locked version of direct dependency `name`.
    pub fn version(&self, name: &str) -> Option<&str> {
        Some(&self.packages.get(self.roots.get(name)?)?.version)
    }

    /// `direct` followed by the packages they pull in that aren't direct themselves.
    /// Runtime dependencies are walked first, so a package reached from both a runtime
    /// and a dev dependency counts as runtime (`Indirect`); one reached only from dev
    /// dependencies stays `Dev`.
    pub fn with_transitive(&self, mut direct: Vec<Dependency>) -> Vec<Dependency> {
        let mut seen: HashSet<(String, String)> =
            direct.iter().filter_map(|d| Some((d.name.clone(), d.version.clone()?))).collect();
        let mut out = Vec::new();
        let mut push = |p: &Locked, kind: DepKind, via: Option<&str>| {
            if seen.insert((p.name.clone(), p.version.clone())) {
                out.push(Dependency {
                    name: p.name.clone(),
                    version: Some(p.version.clone()),
                    exact: true,
                    kind,
                    via: via.map(String::from),
                });
            }
        };
        if self.flat {
            let direct_ids: HashSet<&String> = self.roots.values().collect();
            let mut rest: Vec<&Locked> =
                self.packages.iter().filter(|(id, _)| !direct_ids.contains(id)).map(|(_, p)| p).collect();
            rest.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
            for p in rest {
                push(p, DepKind::Indirect, None);
            }
        } else {
            let mut visited: HashSet<&str> = HashSet::new();
            let order = [DepKind::Prod, DepKind::Indirect, DepKind::Dev];
            for pass in order {
                let mut queue: VecDeque<(&str, &str)> = VecDeque::new();
                for d in direct.iter().filter(|d| d.kind == pass && d.via.is_none()) {
                    if let Some(id) = self.roots.get(&d.name) {
                        visited.insert(id);
                        queue.extend(self.deps_of(id).iter().map(|c| (c.as_str(), d.name.as_str())));
                    }
                }
                let kind = if pass == DepKind::Dev { DepKind::Dev } else { DepKind::Indirect };
                while let Some((id, via)) = queue.pop_front() {
                    let Some(p) = self.packages.get(id).filter(|_| visited.insert(id)) else { continue };
                    push(p, kind, Some(via));
                    queue.extend(p.deps.iter().map(|c| (c.as_str(), via)));
                }
            }
        }
        direct.extend(out);
        direct
    }
}

/// `name@version` → (`name`, `version`), for scoped npm names too (`@scope/x@1.0.0`).
pub(super) fn split_at_version(spec: &str) -> Option<(&str, &str)> {
    let at = spec.get(1..)?.find('@')? + 1;
    Some((&spec[..at], &spec[at + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(name: &str, kind: DepKind) -> Dependency {
        Dependency { name: name.into(), version: None, exact: false, kind, via: None }
    }

    #[test]
    fn walks_runtime_dependencies_before_dev_ones() {
        let mut lock = Lock::default();
        lock.add("a", "a", "1.0.0", vec!["shared".into(), "deep".into()]);
        lock.add("deep", "deep", "2.0.0", vec!["deeper".into()]);
        lock.add("deeper", "deeper", "3.0.0", vec![]);
        lock.add("shared", "shared", "1.1.0", vec![]);
        lock.add("t", "t", "5.0.0", vec!["shared".into(), "only-dev".into(), "a".into()]);
        lock.add("only-dev", "only-dev", "0.1.0", vec![]);
        lock.add("link", "link", "file:../x", vec![]);
        lock.root("a", "a");
        lock.root("t", "t");
        let deps = lock.with_transitive(vec![dep("t", DepKind::Dev), dep("a", DepKind::Prod)]);
        let got: Vec<(&str, DepKind, Option<&str>)> =
            deps.iter().map(|d| (d.name.as_str(), d.kind, d.via.as_deref())).collect();
        assert_eq!(
            got,
            [
                ("t", DepKind::Dev, None),
                ("a", DepKind::Prod, None),
                ("shared", DepKind::Indirect, Some("a")),
                ("deep", DepKind::Indirect, Some("a")),
                ("deeper", DepKind::Indirect, Some("a")),
                ("only-dev", DepKind::Dev, Some("t")),
            ]
        );
        assert_eq!(lock.version("a"), Some("1.0.0"));
        assert!(!lock.contains("link"), "uncomparable versions are left out");
    }

    #[test]
    fn flat_locks_list_every_other_package() {
        let mut lock = Lock::flat();
        lock.add("a", "a", "1.0.0", vec![]);
        lock.add("b", "b", "2.0.0", vec![]);
        lock.root("a", "a");
        let deps = lock.with_transitive(vec![dep("a", DepKind::Prod)]);
        assert_eq!(deps[1].name, "b");
        assert_eq!((deps[1].kind, deps[1].via.as_deref()), (DepKind::Indirect, None));
    }

    #[test]
    fn splits_scoped_specs() {
        assert_eq!(split_at_version("@scope/x@1.0.0"), Some(("@scope/x", "1.0.0")));
        assert_eq!(split_at_version("lodash@npm:^4"), Some(("lodash", "npm:^4")));
        assert_eq!(split_at_version("@scope/x"), None);
    }
}
