//! .NET: the `<PackageReference>`s of a `*.csproj` / `*.fsproj` / `*.vbproj` (versions
//! can come from `Directory.Packages.props`), with exact versions and what they pull in
//! from `packages.lock.json`. NuGet ids are case-insensitive, but GitHub's advisory
//! database matches them as spelled, so the lockfile's (canonical) spelling is kept.

use std::collections::HashMap;

use serde_json::Value;

use super::lock::Lock;
use super::xml::{elements, text, without_comments};
use super::{DepKind, Dependency, Folder, Found, Manager, parse_json, read_file};

pub(super) fn read(f: &Folder) -> Option<Found> {
    let (project, file) = f.find_ext(&[".csproj", ".fsproj", ".vbproj"])?;
    let project = without_comments(&project);
    // Central package management: `<PackageVersion Include="x" Version="1.0" />`
    let central: HashMap<String, String> = f
        .find_up("Directory.Packages.props")
        .and_then(|p| read_file(&p))
        .map(|props| {
            elements(&without_comments(&props), "PackageVersion")
                .into_iter()
                .filter_map(|(a, _)| Some((a.get("include")?.to_ascii_lowercase(), a.get("version")?.clone())))
                .collect()
        })
        .unwrap_or_default();
    let lock_file = f.dir.join("packages.lock.json");
    let lock = f
        .read("packages.lock.json")
        .and_then(|t| parse_json(&lock_file, &t))
        .map(|v| nuget_lock(&v))
        .unwrap_or_default();
    let deps = elements(&project, "PackageReference")
        .into_iter()
        .filter_map(|(a, inner)| {
            let include = a.get("include")?;
            let name = lock.root_name(include).unwrap_or(include).to_string();
            let version = a
                .get("version")
                .or_else(|| a.get("versionoverride"))
                .cloned()
                .or_else(|| text(inner, "Version"))
                .or_else(|| central.get(&name.to_ascii_lowercase()).cloned())
                .unwrap_or_default();
            // Analyzers and build tools are marked `PrivateAssets="all"`: not shipped.
            let private = a.get("privateassets").cloned().or_else(|| text(inner, "PrivateAssets"));
            let kind =
                if private.is_some_and(|p| p.eq_ignore_ascii_case("all")) { DepKind::Dev } else { DepKind::Prod };
            // `[1.2.3]` or `[1.0, 2.0)` ranges → their lower bound
            Some(Dependency::new(&name, version.trim_matches(['[', '(', ']', ')']), kind, &lock))
        })
        .collect();
    Some(Found::new(deps, &lock, Manager::Dotnet, file))
}

/// `packages.lock.json`: per target framework, `name → { type, resolved, dependencies }`,
/// where `type` is `Direct`, `Transitive` or `Project` (another project, not a package).
fn nuget_lock(v: &Value) -> Lock {
    let mut lock = Lock::default();
    for framework in v.get("dependencies").and_then(Value::as_object).into_iter().flat_map(|f| f.values()) {
        let Some(framework) = framework.as_object() else { continue };
        let resolved = |name: &str| -> Option<String> {
            let (n, e) = framework.iter().find(|(n, _)| n.eq_ignore_ascii_case(name))?;
            Some(format!("{n}@{}", e.get("resolved")?.as_str()?))
        };
        for (name, e) in framework {
            let (Some(kind), Some(version)) =
                (e.get("type").and_then(Value::as_str), e.get("resolved").and_then(Value::as_str))
            else {
                continue;
            };
            if kind == "Project" {
                continue;
            }
            let id = format!("{name}@{version}");
            let deps = e.get("dependencies").and_then(Value::as_object).into_iter().flatten();
            lock.add(id.clone(), name.clone(), version, deps.filter_map(|(d, _)| resolved(d)).collect());
            if kind == "Direct" {
                lock.root_default(name.clone(), id);
            }
        }
    }
    lock
}

#[cfg(test)]
mod tests {
    use super::super::testdir::TestDir;
    use super::*;

    #[test]
    fn reads_project_central_versions_and_lock() {
        let t = TestDir::new("dotnet");
        t.file(
            "App.csproj",
            r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>
  <PackageReference Include="newtonsoft.json" Version="13.0.1" />
  <PackageReference Include="Serilog" />
  <PackageReference Include="StyleCop.Analyzers" Version="[1.1.118]" PrivateAssets="all" />
</ItemGroup></Project>"#,
        )
        .file("Directory.Packages.props", r#"<Project><ItemGroup><PackageVersion Include="serilog" Version="3.1.0" /></ItemGroup></Project>"#)
        .file(
            "packages.lock.json",
            r#"{"version":1,"dependencies":{"net8.0":{
              "Newtonsoft.Json":{"type":"Direct","requested":"[13.0.1, )","resolved":"13.0.3","dependencies":{"System.Memory":"4.5.0"}},
              "System.Memory":{"type":"Transitive","resolved":"4.5.5"},
              "lib":{"type":"Project"}}}}"#,
        );
        let found = read(&Folder::new(t.root(), t.root())).unwrap();
        assert_eq!(found.manifest, "App.csproj");
        let got: Vec<(&str, Option<&str>, DepKind, Option<&str>)> =
            found.deps.iter().map(|d| (d.name.as_str(), d.version.as_deref(), d.kind, d.via.as_deref())).collect();
        assert_eq!(
            got,
            [
                ("Newtonsoft.Json", Some("13.0.3"), DepKind::Prod, None),
                ("Serilog", Some("3.1.0"), DepKind::Prod, None),
                ("StyleCop.Analyzers", Some("1.1.118"), DepKind::Dev, None),
                ("System.Memory", Some("4.5.5"), DepKind::Indirect, Some("Newtonsoft.Json")),
            ]
        );
    }
}
