//! "For you": what your own projects depend on, so repos touching your actual stack can
//! be surfaced. Each dependency becomes a "stack term" matched against repo topics,
//! names and owners.

use std::collections::{BTreeMap, HashSet};

use crate::deps::{Dependency, Ecosystem, Project};
use crate::sources::github::Repo;

/// Dependency names too generic to say anything about a project: build tooling,
/// linters, typings, test runners, and the frameworks the tabs already cover.
const GENERIC_NPM: &[&str] = &[
    "types",
    "babel",
    "eslint",
    "typescript",
    "prettier",
    "jest",
    "vitest",
    "testing-library",
    "commitlint",
    "husky",
    "lint-staged",
    "tslib",
    "dotenv",
    "postcss",
    "autoprefixer",
    "webpack",
    "vite",
    "rollup",
    "esbuild",
    "swc",
    "tsx",
    "ts-node",
    "nodemon",
    "rimraf",
    "cross-env",
    "concurrently",
    "sass",
    "release-it",
    "del-cli",
    "lefthook",
    "turbo",
    "react-dom",
    "react-native-community",
    "next",
    "react-test-renderer",
    "jsdom",
];
const GENERIC_NPM_PREFIXES: &[&str] = &["eslint-", "babel-", "prettier-", "jest-", "vite-plugin-", "@types"];
const GENERIC_CARGO: &[&str] = &[
    "serde",
    "serde-json",
    "anyhow",
    "thiserror",
    "log",
    "env-logger",
    "once-cell",
    "lazy-static",
    "cfg-if",
    "libc",
    "bitflags",
    "itertools",
    "rand",
    "regex",
    "chrono",
    "tempfile",
    "pretty-assertions",
];
const GENERIC_GO: &[&str] = &["testify", "errors", "pkg", "yaml", "uuid", "cmp"];
const GENERIC_GO_PREFIXES: &[&str] = &["golang.org/x/", "google.golang.org/", "gopkg.in/"];
const GENERIC_PIP: &[&str] = &[
    "pytest",
    "black",
    "ruff",
    "mypy",
    "flake8",
    "isort",
    "setuptools",
    "wheel",
    "pip",
    "typing-extensions",
    "python-dotenv",
    "six",
    "tox",
    "coverage",
    "pre-commit",
    "pylint",
    "requests",
];
const GENERIC_PIP_PREFIXES: &[&str] = &["pytest-", "types-", "flake8-", "mypy-"];
const GENERIC_NUGET: &[&str] = &["microsoft", "system", "xunit", "nunit", "coverlet"];

/// The stack term of a dependency, or None if it is too generic.
/// - npm: the scope for scoped packages (`@tanstack/react-query` → `tanstack`), else the name;
/// - Go: the repo name of `github.com/owner/repo/...`, else the last path segment;
/// - Cargo and pip: the name, with `_` as `-` (as in repo names);
/// - Composer and Maven: the package part of `vendor/name` / `group:artifact`;
/// - NuGet: the first part of the dotted id.
fn term(ecosystem: Ecosystem, dep: &Dependency) -> Option<String> {
    let name = dep.name.to_ascii_lowercase();
    let (t, generic, prefixes): (&str, &[&str], &[&str]) = match ecosystem {
        Ecosystem::Npm => {
            let t = match name.strip_prefix('@') {
                Some(scoped) => scoped.split('/').next()?,
                None => &name,
            };
            (t, GENERIC_NPM, GENERIC_NPM_PREFIXES)
        }
        Ecosystem::Go => {
            let parts: Vec<&str> = name.split('/').collect();
            let t = match parts.as_slice() {
                ["github.com", _, repo, ..] => repo,
                [.., last]
                    if last.len() >= 2 && last.starts_with('v') && last[1..].bytes().all(|b| b.is_ascii_digit()) =>
                {
                    parts.get(parts.len().checked_sub(2)?)?
                }
                [.., last] => last,
                [] => return None,
            };
            (t, GENERIC_GO, GENERIC_GO_PREFIXES)
        }
        Ecosystem::Cargo => (&name, GENERIC_CARGO, &[]),
        Ecosystem::Pip => (&name, GENERIC_PIP, GENERIC_PIP_PREFIXES),
        // `vendor/package` (Composer), `group:artifact` (Maven): the package part.
        Ecosystem::Composer | Ecosystem::Maven => (name.rsplit(['/', ':']).next()?, &[], &[]),
        // `Serilog.Sinks.Console` → `serilog`
        Ecosystem::NuGet => (name.split('.').next()?, GENERIC_NUGET, &[]),
        Ecosystem::RubyGems | Ecosystem::Pub => (&name, &[], &[]),
    };
    if prefixes.iter().any(|p| name.starts_with(p)) {
        return None;
    }
    let t = t.replace('_', "-");
    (t.len() >= 2 && !generic.contains(&t.as_str())).then_some(t)
}

pub struct Stack {
    /// Term → number of projects using it
    pub terms: BTreeMap<String, usize>,
}

impl Stack {
    /// Stack terms of the direct dependencies of `projects`, minus `topics` (already their
    /// own tabs). What those pull in is mostly plumbing (`ms`, `inherits`) and would match noise.
    pub fn of(projects: &[Project], topics: &HashSet<&str>) -> Self {
        let mut terms = BTreeMap::new();
        for p in projects {
            let mine: HashSet<String> = p
                .deps
                .iter()
                .filter(|d| d.is_direct())
                .filter_map(|d| term(p.ecosystem, d))
                .filter(|t| !topics.contains(t.as_str()))
                .collect();
            for t in mine {
                *terms.entry(t).or_insert(0) += 1;
            }
        }
        Stack { terms }
    }

    /// Terms `repo` matches: one of its topics, its name, or its owner (an npm scope is
    /// usually the org, e.g. `tanstack/router`).
    pub fn matches(&self, repo: &Repo) -> Vec<String> {
        let key = repo.key();
        let (owner, name) = key.split_once('/').unwrap_or_default();
        let mut found: Vec<String> = repo
            .topics
            .iter()
            .map(String::as_str)
            .chain([owner, name])
            .filter(|t| self.terms.contains_key(*t))
            .map(String::from)
            .collect();
        found.sort();
        found.dedup();
        found
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn dep(name: &str) -> Dependency {
        Dependency { name: name.into(), version: None, exact: false, kind: Default::default(), via: None }
    }

    #[test]
    fn dependency_terms_per_ecosystem() {
        let t = |e, n| term(e, &dep(n));
        assert_eq!(t(Ecosystem::Npm, "@tanstack/react-query").as_deref(), Some("tanstack"));
        assert_eq!(t(Ecosystem::Npm, "zustand").as_deref(), Some("zustand"));
        assert_eq!(t(Ecosystem::Npm, "@types/node"), None);
        assert_eq!(t(Ecosystem::Npm, "eslint-plugin-import"), None);
        assert_eq!(t(Ecosystem::Npm, "typescript"), None);
        assert_eq!(t(Ecosystem::Cargo, "tokio_util").as_deref(), Some("tokio-util"));
        assert_eq!(t(Ecosystem::Cargo, "serde_json"), None);
        assert_eq!(t(Ecosystem::Go, "github.com/gin-gonic/gin").as_deref(), Some("gin"));
        assert_eq!(t(Ecosystem::Go, "github.com/jackc/pgx/v5").as_deref(), Some("pgx"));
        assert_eq!(t(Ecosystem::Go, "entgo.io/ent").as_deref(), Some("ent"));
        assert_eq!(t(Ecosystem::Go, "golang.org/x/net"), None);
        assert_eq!(t(Ecosystem::Pip, "fastapi").as_deref(), Some("fastapi"));
        assert_eq!(t(Ecosystem::Pip, "pytest-cov"), None);
    }

    #[test]
    fn builds_stack_and_matches_repos() {
        let project = |e, names: &[&str]| Project {
            dir: PathBuf::new(),
            ecosystem: e,
            manager: Default::default(),
            manifest: PathBuf::new(),
            deps: names.iter().map(|n| dep(n)).collect(),
        };
        let projects = [
            project(Ecosystem::Npm, &["zustand", "react", "@tanstack/router"]),
            project(Ecosystem::Cargo, &["tokio", "serde"]),
            project(Ecosystem::Npm, &["typescript"]),
        ];
        let stack = Stack::of(&projects, &HashSet::from(["react"]));
        assert_eq!(stack.terms.keys().collect::<Vec<_>>(), ["tanstack", "tokio", "zustand"]);
        let repo = Repo::test("TanStack/start", 1, &["zustand", "react"]);
        assert_eq!(stack.matches(&repo), ["tanstack", "zustand"]);
    }
}
