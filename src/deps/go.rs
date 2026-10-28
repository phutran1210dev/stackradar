//! Go: `go.mod`, whose `require` versions are exact (minimal version selection).

use super::{DepKind, Dependency, Folder, Found, Manager};

/// go.mod lists every module the build needs (Go 1.17+), the indirect ones marked, so
/// there is no lockfile to follow.
pub(super) fn read(f: &Folder) -> Option<Found> {
    Some(Found { deps: parse(&f.read("go.mod")?), manager: Manager::Go, manifest: "go.mod".into() })
}

fn parse(go_mod: &str) -> Vec<Dependency> {
    let mut deps = Vec::new();
    let mut in_block = false;
    for line in go_mod.lines() {
        let (line, comment) = line.split_once("//").unwrap_or((line, ""));
        let line = line.trim();
        let spec = if in_block {
            if line == ")" {
                in_block = false;
                continue;
            }
            line
        } else if line == "require (" {
            in_block = true;
            continue;
        } else if let Some(rest) = line.strip_prefix("require ") {
            rest
        } else {
            continue;
        };
        let mut parts = spec.split_whitespace();
        if let (Some(module), Some(v)) = (parts.next(), parts.next()) {
            let version = v.trim_start_matches('v').trim_end_matches("+incompatible");
            let kind = if comment.trim() == "indirect" { DepKind::Indirect } else { DepKind::Prod };
            deps.push(Dependency {
                name: module.to_string(),
                version: Some(version.to_string()),
                exact: true,
                kind,
                via: None,
            });
        }
    }
    deps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_single_and_block_requires() {
        let deps = parse(
            "module example.com/x\n\ngo 1.22\n\nrequire github.com/gin-gonic/gin v1.9.0\n\nrequire (\n\tgolang.org/x/net v0.17.0 // indirect\n\tgithub.com/a/b v2.0.0+incompatible\n)\nreplace a => b\n",
        );
        let got: Vec<(&str, &str, DepKind)> =
            deps.iter().map(|d| (d.name.as_str(), d.version.as_deref().unwrap(), d.kind)).collect();
        assert_eq!(
            got,
            [
                ("github.com/gin-gonic/gin", "1.9.0", DepKind::Prod),
                ("golang.org/x/net", "0.17.0", DepKind::Indirect),
                ("github.com/a/b", "2.0.0", DepKind::Prod),
            ]
        );
    }
}
