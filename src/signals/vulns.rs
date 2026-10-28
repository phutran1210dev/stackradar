//! Which security advisories affect the dependency versions your projects use.
//!
//! GitHub is asked for advisories affecting each `name@version`; it can't say which of
//! the queried versions matched, so each advisory's ranges are checked here against
//! every project's version to attribute it to the right projects.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::NaiveDate;

use crate::deps::{DepKind, Ecosystem, Manager, Project, version};
use crate::model::{Fix, Severity, Usage, Vulnerability};
use crate::sources::advisories::{Advisory, Affected};
use crate::store::ignore::Rule;

/// Packages per advisory query, keeping the URL under GitHub's limit (about 8 KB; `,`
/// `@` and `/` are sent as `%2C` and so on), since a transitive tree has thousands.
const QUERY_PACKAGES: usize = 200;
const QUERY_CHARS: usize = 5000;

/// (ecosystem, normalized package name) → who uses which version of it.
pub type Index = HashMap<(Ecosystem, String), Vec<Usage>>;

/// Dependencies with a known version, by package.
pub fn index(projects: &[Project]) -> Index {
    let mut index: Index = HashMap::new();
    for p in projects {
        let project = p.label();
        for d in &p.deps {
            let Some(v) = &d.version else { continue };
            let usage = Usage {
                project: project.clone(),
                version: v.clone(),
                exact: d.exact,
                kind: d.kind,
                via: d.via.clone(),
                patched: None,
                name: d.name.clone(),
                manager: p.manager,
                manifest: p.manifest.clone(),
            };
            let uses = index.entry((p.ecosystem, p.ecosystem.normalize(&d.name))).or_default();
            if !uses.contains(&usage) {
                uses.push(usage);
            }
        }
    }
    index
}

/// Batches of `name@version` per ecosystem, for `GitHub::advisories`. GitHub matches
/// names as spelled (`Django` and `django` find different advisories), so a package is
/// asked for both as normalized and as the project spells it.
pub fn queries(index: &Index) -> Vec<(Ecosystem, Vec<String>)> {
    let mut by_eco: BTreeMap<Ecosystem, Vec<String>> = BTreeMap::new();
    for ((eco, name), uses) in index {
        let specs = uses.iter().flat_map(|u| [name, &u.name].map(|n| format!("{n}@{}", u.version)));
        by_eco.entry(*eco).or_default().extend(specs);
    }
    let mut out = Vec::new();
    for (eco, mut specs) in by_eco {
        specs.sort();
        specs.dedup();
        let mut batch: Vec<String> = Vec::new();
        let mut chars = 0;
        for spec in specs {
            if batch.len() == QUERY_PACKAGES || chars + spec.len() > QUERY_CHARS {
                out.push((eco, std::mem::take(&mut batch)));
                chars = 0;
            }
            chars += spec.len() + 1;
            batch.push(spec);
        }
        if !batch.is_empty() {
            out.push((eco, batch));
        }
    }
    out
}

/// One row per (advisory, your package) whose affected range holds a version you use.
/// A range that can't be parsed counts as affecting (the database's own match said so).
/// An advisory listed under another one's id (OSV has PyPA's `PYSEC-…` next to the
/// `GHSA-…` for the same flaw) is left out, keeping malware and GitHub's records, which
/// carry a severity. A shared CVE alone doesn't make two the same: one CVE can have an
/// advisory per affected package.
pub fn attribute(mut advisories: Vec<Advisory>, index: &Index) -> Vec<Vulnerability> {
    advisories.sort_by_key(|a| (!a.malware, !a.id.starts_with("GHSA-")));
    let mut covered = HashSet::new();
    let mut out = Vec::new();
    for adv in advisories {
        let others = || adv.aliases.iter().filter(|a| !a.starts_with("CVE-"));
        if covered.contains(&adv.id) || others().any(|a| covered.contains(a)) {
            continue;
        }
        covered.insert(adv.id.clone());
        covered.extend(others().cloned());
        let mut by_package: BTreeMap<(Ecosystem, String), Vec<&Affected>> = BTreeMap::new();
        for a in &adv.affected {
            by_package.entry((a.ecosystem, a.ecosystem.normalize(&a.name))).or_default().push(a);
        }
        for (key, ranges) in by_package {
            let Some(uses) = index.get(&key) else { continue };
            let hit = |a: &Affected, v: &str| a.range.as_deref().is_none_or(|r| version::in_range(v, r) != Some(false));
            let patched_for = |v: &str| ranges.iter().find(|a| hit(a, v)).map(|a| a.patched.clone());
            let uses: Vec<Usage> =
                uses.iter().filter_map(|u| Some(Usage { patched: patched_for(&u.version)?, ..u.clone() })).collect();
            let Some(first) = uses.first() else { continue };
            let matching: Vec<&&Affected> = ranges.iter().filter(|a| uses.iter().any(|u| hit(a, &u.version))).collect();
            out.push(Vulnerability {
                id: adv.id.clone(),
                cve: adv.cve.clone(),
                summary: adv.summary.clone(),
                severity: if adv.malware { Severity::Critical } else { Severity::parse(&adv.severity) },
                cvss: adv.cvss.filter(|s| *s > 0.0),
                cwes: adv.cwes.clone(),
                url: adv.url.clone(),
                published: adv.published.chars().take(10).collect(),
                ecosystem: key.0,
                package: key.1,
                vulnerable: matching.iter().filter_map(|a| a.range.clone()).collect::<Vec<_>>().join(" or "),
                patched: first.patched.clone(),
                uses,
                is_new: false,
                malware: adv.malware,
                exploited: false,
                epss: None,
            });
        }
    }
    out
}

/// `items` minus those an unexpired rule matches, how many were left out, and the
/// expired rules (their advisories are reported again).
pub fn apply_ignores(
    items: Vec<Vulnerability>,
    rules: &[Rule],
    today: NaiveDate,
) -> (Vec<Vulnerability>, usize, Vec<&Rule>) {
    let (active, expired): (Vec<&Rule>, Vec<&Rule>) = rules.iter().partition(|r| !r.is_expired(today));
    let before = items.len();
    let kept: Vec<Vulnerability> = items.into_iter().filter(|v| !active.iter().any(|r| r.matches(v))).collect();
    let ignored = before - kept.len();
    (kept, ignored, expired)
}

/// One upgrade per package, version in use and package manager (which decides the
/// command), resolving every advisory against that version that has a fix; for malware,
/// its removal. Malware first, then by severity, then runtime before dev dependencies,
/// then how many advisories it resolves.
pub fn fixes(items: &[Vulnerability]) -> Vec<Fix> {
    // (ecosystem, package, version in use, manager) → the advisories against it, with each project's use.
    type Hits<'a> = Vec<(&'a Vulnerability, &'a Usage)>;
    let mut groups: BTreeMap<(Ecosystem, &str, &str, Manager), Hits> = BTreeMap::new();
    for v in items {
        for u in &v.uses {
            groups.entry((v.ecosystem, v.package.as_str(), u.version.as_str(), u.manager)).or_default().push((v, u));
        }
    }
    let mut out: Vec<Fix> = groups
        .into_iter()
        .map(|((ecosystem, package, version, manager), mut hits)| {
            hits.sort_by(|(a, _), (b, _)| a.severity.cmp(&b.severity).then_with(|| a.id.cmp(&b.id)));
            let mut projects: Vec<String> = hits.iter().map(|(_, u)| u.project.clone()).collect();
            projects.sort();
            projects.dedup();
            let kind = hits.iter().map(|(_, u)| u.kind).min().unwrap_or_default();
            let exact = hits.iter().all(|(_, u)| u.exact);
            let via = Usage::via_of(hits.iter().map(|(_, u)| *u)).map(String::from);
            let malware = hits.iter().any(|(v, _)| v.malware);
            // Each advisory once (several projects can use this version).
            hits.dedup_by(|(a, _), (b, _)| a.id == b.id);
            let target = hits
                .iter()
                .filter_map(|(_, u)| u.patched.as_deref())
                .max_by(|a, b| version::compare(a, b).unwrap_or(Ordering::Equal))
                .map(String::from);
            let action = if malware { Some(Action::Remove) } else { target.as_deref().map(Action::Upgrade) };
            // The command spells the package as the project does (`Newtonsoft.Json`, not the
            // normalized `newtonsoft.json` that identifies it).
            let spelled = hits.iter().map(|(_, u)| u.name.as_str()).find(|n| !n.is_empty()).unwrap_or(package);
            Fix {
                ecosystem,
                package: package.to_string(),
                version: version.to_string(),
                exact,
                breaking: !malware && target.as_deref().is_some_and(|t| version::is_breaking(version, t)),
                command: action.and_then(|a| command(manager, spelled, a, kind, via.as_deref())),
                target: target.filter(|_| !malware),
                via,
                severity: hits[0].0.severity,
                advisories: hits.iter().map(|(v, _)| v.id.clone()).collect(),
                unfixed: hits.iter().filter(|(_, u)| u.patched.is_none()).count(),
                projects,
                kind,
                is_new: hits.iter().any(|(v, _)| v.is_new),
                malware,
                exploited: hits.iter().any(|(v, _)| v.exploited),
                epss: hits.iter().filter_map(|(v, _)| v.epss).max_by(f64::total_cmp),
            }
        })
        .collect();
    out.sort_by(|a, b| {
        b.malware
            .cmp(&a.malware)
            .then(b.exploited.cmp(&a.exploited))
            .then(a.severity.cmp(&b.severity))
            .then(a.kind.cmp(&b.kind))
            .then(b.advisories.len().cmp(&a.advisories.len()))
            .then_with(|| a.package.cmp(&b.package))
            .then_with(|| version::compare(&a.version, &b.version).unwrap_or(Ordering::Equal))
    });
    out
}

/// What to do about a package.
#[derive(Clone, Copy)]
enum Action<'a> {
    Upgrade(&'a str),
    /// It's malware: take it out (or, when it's pulled in, the dependency that brings it)
    Remove,
}

/// The usual command for `action` on `package`, run in the project folder. `via` is the
/// direct dependency that pulls a transitive `package` in (None when it's direct). None
/// when there is no one command: Maven and Gradle need the build file edited, and some
/// managers can only reach a transitive package through the dependency that pulls it in.
fn command(manager: Manager, package: &str, action: Action, kind: DepKind, via: Option<&str>) -> Option<String> {
    use Manager::*;
    let direct = via.is_none() && kind != DepKind::Indirect;
    let dev = |flag: &str| if kind == DepKind::Dev { format!("{flag} ") } else { String::new() };
    let target = match action {
        Action::Upgrade(t) => t,
        Action::Remove => {
            let verb = match manager {
                // `@none` drops a module, required directly or not.
                Go => return Some(format!("go get {package}@none")),
                Maven | Gradle => return None,
                Npm => "npm uninstall",
                Yarn | YarnBerry => "yarn remove",
                Pnpm => "pnpm remove",
                Bun => "bun remove",
                Cargo => "cargo remove",
                Pip => "pip uninstall -y",
                Poetry => "poetry remove",
                Uv => "uv remove",
                Composer => "composer remove",
                Bundler => "bundle remove",
                Pub => "dart pub remove",
                Dotnet => "dotnet remove package",
            };
            return Some(format!("{verb} {}", if direct { package } else { via? }));
        }
    };
    Some(match (manager, direct) {
        (Cargo, _) => format!("cargo update -p {package} --precise {target}"),
        (Go, _) => format!("go get {package}@v{}", target.trim_start_matches('v')),
        (Pip, _) => format!("pip install \"{package}>={target}\""),
        (Bundler, _) => format!("bundle update --conservative {package}"),
        // Pinning a transitive package as a direct one is NuGet's way to upgrade it.
        (Dotnet, _) => format!("dotnet add package {package} --version {target}"),
        (Maven | Gradle, _) => return None,
        (Npm, true) => format!("npm install {}{package}@{target}", dev("-D")),
        (Npm, false) => format!("npm update {package}"),
        (Yarn | YarnBerry, true) => format!("yarn add {}{package}@{target}", dev("-D")),
        // Yarn 1 can't update a package it doesn't list directly.
        (Yarn, false) => format!("yarn upgrade {}", via?),
        (YarnBerry, false) => format!("yarn up -R {package}"),
        (Pnpm, true) => format!("pnpm add {}{package}@{target}", dev("-D")),
        (Pnpm, false) => format!("pnpm update {package}"),
        (Bun, true) => format!("bun add {}{package}@{target}", dev("-d")),
        (Bun, false) => format!("bun update {}", via?),
        (Poetry, true) => format!("poetry add {}\"{package}>={target}\"", dev("--group dev")),
        (Poetry, false) => format!("poetry update {package}"),
        (Uv, true) => format!("uv add {}\"{package}>={target}\"", dev("--dev")),
        (Uv, false) => format!("uv lock --upgrade-package {package}"),
        (Composer, true) => format!("composer require {}\"{package}:^{target}\"", dev("--dev")),
        (Composer, false) => format!("composer update {package}"),
        (Pub, true) => format!("dart pub add {}{package}:^{target}", if kind == DepKind::Dev { "dev:" } else { "" }),
        (Pub, false) => format!("dart pub upgrade {package}"),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::deps::Dependency;

    pub(crate) fn project(dir: &str, eco: Ecosystem, deps: &[(&str, &str)]) -> Project {
        Project {
            dir: PathBuf::from(dir),
            ecosystem: eco,
            deps: deps
                .iter()
                .map(|(n, v)| Dependency {
                    name: n.to_string(),
                    version: Some(v.to_string()),
                    exact: true,
                    kind: DepKind::Prod,
                    via: None,
                })
                .collect(),
            manager: Manager::Npm,
            manifest: PathBuf::from(dir).join("package.json"),
        }
    }

    /// An advisory for packages in `eco` (GitHub's name for the ecosystem).
    pub(crate) fn advisory(id: &str, eco: &str, ranges: &[(&str, &str, Option<&str>)]) -> Advisory {
        let eco = Ecosystem::from_advisory_name(eco).unwrap();
        Advisory {
            id: id.into(),
            aliases: Vec::new(),
            cve: None,
            summary: format!("{id} summary"),
            severity: "high".into(),
            cvss: None,
            url: format!("https://github.com/advisories/{id}"),
            published: "2026-04-01T23:51:12Z".into(),
            cwes: Vec::new(),
            malware: false,
            affected: ranges
                .iter()
                .map(|(name, range, patched)| Affected {
                    ecosystem: eco,
                    name: name.to_string(),
                    range: Some(range.to_string()),
                    patched: patched.map(String::from),
                })
                .collect(),
        }
    }

    #[test]
    fn attributes_advisories_to_projects_on_affected_versions() {
        let projects = [
            project("/a", Ecosystem::Npm, &[("lodash", "4.17.15")]),
            project("/b", Ecosystem::Npm, &[("lodash", "4.18.0")]),
            project("/c", Ecosystem::Cargo, &[("tokio", "1.0.0")]),
            project("/d", Ecosystem::Pip, &[("Django", "4.2.0")]),
        ];
        let index = index(&projects);
        let advisories = vec![
            advisory(
                "GHSA-1",
                "npm",
                &[("lodash", ">= 4.0.0, <= 4.17.23", Some("4.18.0")), ("lodash-es", "<= 4.17.23", None)],
            ),
            advisory("GHSA-1", "npm", &[("lodash", "< 1", None)]),
            advisory(
                "GHSA-2",
                "rust",
                &[("tokio", ">= 1.44.0, < 1.44.2", Some("1.44.2")), ("tokio", ">= 0.2.5, < 1.38.2", Some("1.38.2"))],
            ),
            advisory("GHSA-3", "pip", &[("django", "< 4.2.2", Some("4.2.2"))]),
            advisory("GHSA-4", "npm", &[("lodash", "< 4.0.0", None)]),
        ];
        let rows = attribute(advisories, &index);
        let got: Vec<(&str, &str, Vec<&str>, Option<&str>)> = rows
            .iter()
            .map(|v| {
                (
                    v.id.as_str(),
                    v.package.as_str(),
                    v.uses.iter().map(|u| u.project.as_str()).collect(),
                    v.patched.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                ("GHSA-1", "lodash", vec!["/a"], Some("4.18.0")),
                ("GHSA-2", "tokio", vec!["/c"], Some("1.38.2")),
                ("GHSA-3", "django", vec!["/d"], Some("4.2.2")),
            ]
        );
        assert_eq!(rows[1].vulnerable, ">= 0.2.5, < 1.38.2");
    }

    #[test]
    fn batches_queries_per_ecosystem() {
        let many: Vec<(String, String)> = (0..250).map(|i| (format!("pkg{i}"), "1.0.0".to_string())).collect();
        let deps: Vec<(&str, &str)> = many.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
        let projects =
            [project("/a", Ecosystem::Npm, &deps), project("/b", Ecosystem::Go, &[("github.com/x/y", "1.2.0")])];
        let q = queries(&index(&projects));
        assert_eq!(
            q.iter().map(|(e, b)| (*e, b.len())).collect::<Vec<_>>(),
            [(Ecosystem::Npm, 200), (Ecosystem::Npm, 50), (Ecosystem::Go, 1)]
        );
        assert_eq!(q[2].1, ["github.com/x/y@1.2.0"]);
    }

    fn vuln(id: &str, eco: Ecosystem, package: &str, severity: Severity, patched: Option<&str>) -> Vulnerability {
        let mut v = crate::report::fixture::vuln(id, severity, false);
        (v.ecosystem, v.package, v.patched) = (eco, package.into(), patched.map(String::from));
        v.uses[0].patched = v.patched.clone();
        v.uses[0].name = package.into();
        v.uses[0].manager = if eco == Ecosystem::Go { Manager::Go } else { Manager::Npm };
        v
    }

    #[test]
    fn groups_advisories_into_one_upgrade_per_package() {
        let crypto = |id, sev, fix| vuln(id, Ecosystem::Go, "golang.org/x/crypto", sev, fix);
        let mut dev = vuln("GHSA-d", Ecosystem::Npm, "vite", Severity::Critical, Some("5.4.6"));
        dev.uses[0].kind = DepKind::Dev;
        let items = [
            crypto("GHSA-1", Severity::High, Some("0.52.0")),
            crypto("GHSA-2", Severity::Critical, Some("0.51.0")),
            crypto("GHSA-3", Severity::Medium, None),
            vuln("GHSA-4", Ecosystem::Npm, "lodash", Severity::High, Some("4.18.0")),
            dev,
        ];
        let fixes = fixes(&items);
        let got: Vec<(&str, Option<&str>, Severity, usize, usize)> = fixes
            .iter()
            .map(|f| (f.package.as_str(), f.target.as_deref(), f.severity, f.advisories.len(), f.unfixed))
            .collect();
        assert_eq!(
            got,
            [
                ("golang.org/x/crypto", Some("0.52.0"), Severity::Critical, 3, 1),
                ("vite", Some("5.4.6"), Severity::Critical, 1, 0),
                ("lodash", Some("4.18.0"), Severity::High, 1, 0),
            ],
            "runtime before dev at the same severity"
        );
        assert_eq!(fixes[0].advisories, ["GHSA-2", "GHSA-1", "GHSA-3"]);
        assert_eq!(fixes[0].command.as_deref(), Some("go get golang.org/x/crypto@v0.52.0"));
        assert_eq!(fixes[1].command.as_deref(), Some("npm install -D vite@5.4.6"));
        assert!(!fixes[2].breaking && fixes[2].exact);
        let mut major = vuln("GHSA-5", Ecosystem::Npm, "next", Severity::Critical, Some("15.5.7"));
        major.uses[0].version = "14.2.13".into();
        let mut patch = major.uses[0].clone();
        (patch.project, patch.version, patch.patched) = ("~/b".into(), "15.5.2".into(), Some("15.5.7".into()));
        major.uses.push(patch);
        let split = super::fixes(&[major]);
        let got: Vec<(&str, bool)> = split.iter().map(|f| (f.version.as_str(), f.breaking)).collect();
        assert_eq!(got, [("14.2.13", true), ("15.5.2", false)], "one upgrade per version in use");
    }

    #[test]
    fn commands_follow_the_package_manager() {
        use DepKind::*;
        let up = |m, kind, via| command(m, "qs", Action::Upgrade("6.11.1"), kind, via);
        assert_eq!(up(Manager::Pnpm, Dev, None).as_deref(), Some("pnpm add -D qs@6.11.1"));
        assert_eq!(up(Manager::Npm, Indirect, Some("express")).as_deref(), Some("npm update qs"));
        assert_eq!(up(Manager::YarnBerry, Indirect, Some("express")).as_deref(), Some("yarn up -R qs"));
        assert_eq!(up(Manager::Yarn, Indirect, Some("express")).as_deref(), Some("yarn upgrade express"));
        assert_eq!(up(Manager::Yarn, Indirect, None), None, "Yarn 1 needs the parent");
        assert_eq!(up(Manager::Uv, Prod, None).as_deref(), Some("uv add \"qs>=6.11.1\""));
        assert_eq!(up(Manager::Composer, Dev, None).as_deref(), Some("composer require --dev \"qs:^6.11.1\""));
        assert_eq!(up(Manager::Gradle, Prod, None), None);
        let rm = |m, kind, via| command(m, "evil", Action::Remove, kind, via);
        assert_eq!(rm(Manager::Bun, Prod, None).as_deref(), Some("bun remove evil"));
        assert_eq!(rm(Manager::Npm, Indirect, Some("parent")).as_deref(), Some("npm uninstall parent"));
        assert_eq!(rm(Manager::Go, Indirect, None).as_deref(), Some("go get evil@none"));
    }

    #[test]
    fn leaves_out_the_same_advisory_under_another_id() {
        let projects = [project("/a", Ecosystem::Npm, &[("lodash", "4.17.15"), ("lodash-es", "4.17.15")])];
        let index = index(&projects);
        let with = |id: &str, aliases: &[&str], package: &str| Advisory {
            aliases: aliases.iter().map(|a| a.to_string()).collect(),
            ..advisory(id, "npm", &[(package, "< 4.17.21", Some("4.17.21"))])
        };
        let mal = Advisory { malware: true, ..with("MAL-1", &["GHSA-m"], "lodash") };
        let rows = attribute(
            vec![
                with("PYSEC-1", &["CVE-1", "GHSA-1"], "lodash"),
                with("GHSA-1", &["CVE-1"], "lodash"),
                with("GHSA-2", &["CVE-1"], "lodash-es"),
                with("GHSA-m", &[], "lodash"),
                mal,
            ],
            &index,
        );
        let ids: Vec<&str> = rows.iter().map(|v| v.id.as_str()).collect();
        assert_eq!(ids, ["MAL-1", "GHSA-1", "GHSA-2"], "a shared CVE alone keeps both");
    }

    #[test]
    fn malware_is_critical_and_removed() {
        let mut projects = [project("/a", Ecosystem::Npm, &[("express", "4.18.0"), ("evil-dep", "1.0.3")])];
        projects[0].deps[1].via = Some("express".into());
        projects[0].deps[1].kind = DepKind::Indirect;
        let mut adv = advisory("GHSA-m", "npm", &[("evil-dep", "= 1.0.3", None)]);
        (adv.malware, adv.severity) = (true, "unknown".into());
        let items = attribute(vec![adv], &index(&projects));
        assert_eq!((items[0].severity, items[0].malware, items[0].via()), (Severity::Critical, true, Some("express")));
        let fix = &fixes(&items)[0];
        assert_eq!((fix.target.as_deref(), fix.command.as_deref()), (None, Some("npm uninstall express")));
    }

    #[test]
    fn asks_for_names_as_spelled_too() {
        let mut projects = [project("/a", Ecosystem::NuGet, &[("Newtonsoft.Json", "12.0.1")])];
        projects[0].manager = Manager::Dotnet;
        let index = index(&projects);
        assert_eq!(queries(&index)[0].1, ["Newtonsoft.Json@12.0.1", "newtonsoft.json@12.0.1"]);
        let items =
            attribute(vec![advisory("GHSA-n", "nuget", &[("Newtonsoft.Json", "< 13.0.1", Some("13.0.1"))])], &index);
        let fix = &fixes(&items)[0];
        assert_eq!(fix.package, "newtonsoft.json", "identity stays normalized");
        assert_eq!(fix.command.as_deref(), Some("dotnet add package Newtonsoft.Json --version 13.0.1"));
    }

    #[test]
    fn ignores_matching_advisories_until_the_rule_expires() {
        let rules: Vec<Rule> = toml::from_str::<toml::Table>(
            "[[ignore]]\nid = \"GHSA-1\"\n[[ignore]]\nid = \"GHSA-2\"\nuntil = 2026-01-01\n",
        )
        .unwrap()["ignore"]
            .clone()
            .try_into()
            .unwrap();
        let items = vec![
            vuln("GHSA-1", Ecosystem::Npm, "a", Severity::High, None),
            vuln("GHSA-2", Ecosystem::Npm, "b", Severity::High, None),
        ];
        let (kept, ignored, expired) = apply_ignores(items, &rules, NaiveDate::from_ymd_opt(2026, 10, 26).unwrap());
        assert_eq!((kept.len(), kept[0].id.as_str(), ignored), (1, "GHSA-2", 1));
        assert_eq!(expired, [&rules[1]]);
    }
}
