//! Java and Kotlin: `gradle.lockfile` (Gradle's dependency locking: every resolved module,
//! exact) or `pom.xml` (Maven: the declared dependencies). Packages are `group:artifact`,
//! as GitHub's advisories name them.

use std::collections::HashMap;

use super::xml::{children, elements, text, without, without_comments};
use super::{DepKind, Dependency, Folder, Found, Manager, version};

const GRADLE_BUILDS: &[&str] = &["build.gradle.kts", "build.gradle"];

pub(super) fn read(f: &Folder) -> Option<Found> {
    if let Some(build) = GRADLE_BUILDS.iter().find(|b| f.dir.join(b).is_file()) {
        let deps = f.read("gradle.lockfile").map(|t| gradle_lock(&t)).unwrap_or_default();
        return Some(Found { deps, manager: Manager::Gradle, manifest: build.to_string() });
    }
    let pom = f.read("pom.xml")?;
    Some(Found { deps: pom_dependencies(&pom), manager: Manager::Maven, manifest: "pom.xml".into() })
}

/// `group:artifact:version=configuration,…` lines. The lockfile doesn't say which modules
/// are declared, so all count as direct; those only on test classpaths are dev.
fn gradle_lock(text: &str) -> Vec<Dependency> {
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let (coords, configurations) = l.split_once('=')?;
            let (module, version) = coords.rsplit_once(':')?;
            module.contains(':').then_some(())?;
            let dev = configurations.split(',').all(|c| c.starts_with("test"));
            Some(Dependency {
                name: module.to_string(),
                version: Some(version.to_string()),
                exact: true,
                kind: if dev { DepKind::Dev } else { DepKind::Prod },
                via: None,
            })
        })
        .collect()
}

/// `<dependency>`s outside `<dependencyManagement>` and `<build>`, with `${property}`
/// versions filled in from `<properties>`. `test` scope is dev.
fn pom_dependencies(pom: &str) -> Vec<Dependency> {
    let pom = without(&without(&without_comments(pom), "dependencyManagement"), "build");
    let properties: HashMap<String, String> = elements(&pom, "properties")
        .first()
        .map(|(_, inner)| children(inner).into_iter().collect())
        .unwrap_or_default();
    elements(&pom, "dependency")
        .into_iter()
        .filter_map(|(_, d)| {
            let name = format!("{}:{}", text(d, "groupId")?, text(d, "artifactId")?);
            let raw = text(d, "version").unwrap_or_default();
            let raw = match raw.strip_prefix("${").and_then(|r| r.strip_suffix('}')) {
                Some(property) => properties.get(property).cloned().unwrap_or_default(),
                None => raw,
            };
            // `[1.0,2.0)` is a range; a plain version is what Maven resolves to.
            let range = raw.starts_with(['[', '(']);
            let dev = text(d, "scope").is_some_and(|s| s == "test");
            Some(Dependency {
                name,
                version: version::lowest(raw.trim_start_matches(['[', '('])),
                exact: !range,
                kind: if dev { DepKind::Dev } else { DepKind::Prod },
                via: None,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_gradle_lockfile() {
        let deps = gradle_lock(
            "# This is a Gradle generated file\ncom.fasterxml.jackson.core:jackson-databind:2.15.0=compileClasspath,runtimeClasspath\njunit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath\nempty=annotationProcessor\n",
        );
        let got: Vec<(&str, Option<&str>, DepKind)> =
            deps.iter().map(|d| (d.name.as_str(), d.version.as_deref(), d.kind)).collect();
        assert_eq!(
            got,
            [
                ("com.fasterxml.jackson.core:jackson-databind", Some("2.15.0"), DepKind::Prod),
                ("junit:junit", Some("4.13.2"), DepKind::Dev),
            ]
        );
    }

    #[test]
    fn reads_pom_dependencies_and_properties() {
        let deps = pom_dependencies(
            r#"<project><properties><spring.version>6.1.2</spring.version></properties>
<dependencyManagement><dependencies><dependency><groupId>x</groupId><artifactId>managed</artifactId><version>1</version></dependency></dependencies></dependencyManagement>
<dependencies>
  <dependency><groupId>org.springframework</groupId><artifactId>spring-core</artifactId><version>${spring.version}</version></dependency>
  <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>[4.12,5.0)</version><scope>test</scope></dependency>
  <!-- <dependency><groupId>old</groupId><artifactId>old</artifactId></dependency> -->
</dependencies>
<build><plugins><plugin><dependencies><dependency><groupId>p</groupId><artifactId>p</artifactId></dependency></dependencies></plugin></plugins></build>
</project>"#,
        );
        let got: Vec<(&str, Option<&str>, bool, DepKind)> =
            deps.iter().map(|d| (d.name.as_str(), d.version.as_deref(), d.exact, d.kind)).collect();
        assert_eq!(
            got,
            [
                ("org.springframework:spring-core", Some("6.1.2"), true, DepKind::Prod),
                ("junit:junit", Some("4.12"), false, DepKind::Dev),
            ]
        );
    }
}
