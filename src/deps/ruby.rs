//! Ruby: `Gemfile`, with exact versions and what they pull in from `Gemfile.lock`.

use super::lock::Lock;
use super::{DepKind, Dependency, Folder, Found, Manager, read_file};

pub(super) fn read(f: &Folder) -> Option<Found> {
    let gemfile = f.read("Gemfile")?;
    let lock = f.find_up("Gemfile.lock").and_then(|p| read_file(&p)).map(|t| gemfile_lock(&t)).unwrap_or_default();
    let mut deps: Vec<Dependency> = Vec::new();
    for (name, req, kind) in gems(&gemfile) {
        if !deps.iter().any(|d| d.name == name) {
            deps.push(Dependency::new(&name, &req, kind, &lock));
        }
    }
    Some(Found::new(deps, &lock, Manager::Bundler, "Gemfile"))
}

/// `gem "rails", "~> 7.1"` lines as (name, requirement, kind). Gems in a
/// `group :development, :test do … end` block, or with `group: :test`, are dev.
fn gems(gemfile: &str) -> Vec<(String, String, DepKind)> {
    let is_dev = |s: &str| s.contains(":development") || s.contains(":test");
    let mut blocks: Vec<bool> = Vec::new();
    let mut out = Vec::new();
    for line in gemfile.lines().map(|l| l.split('#').next().unwrap_or_default().trim()) {
        if line == "end" {
            blocks.pop();
        } else if line.ends_with(" do") || line.contains(" do |") {
            blocks.push(line.starts_with("group ") && is_dev(line));
        } else if let Some(args) = line.strip_prefix("gem ") {
            let quoted: Vec<&str> = args.split(['"', '\'']).skip(1).step_by(2).collect();
            let Some(name) = quoted.first() else { continue };
            let req = quoted.get(1).filter(|r| r.starts_with(|c: char| c.is_ascii_digit() || "~>=<".contains(c)));
            let dev = blocks.iter().any(|&d| d) || is_dev(args.split_once("group").map_or("", |(_, g)| g));
            out.push((
                name.to_string(),
                req.map_or_else(String::new, |r| r.to_string()),
                if dev { DepKind::Dev } else { DepKind::Prod },
            ));
        }
    }
    out
}

/// `Gemfile.lock`: under each `specs:`, `    name (version)` then its dependencies as
/// `      name (constraint)`. A platform suffix (`1.15.4-arm64-darwin`) is dropped.
fn gemfile_lock(text: &str) -> Lock {
    let mut specs: Vec<(String, String, Vec<String>)> = Vec::new();
    let mut in_specs = false;
    for line in text.lines() {
        let indent = line.len() - line.trim_start().len();
        let content = line.trim();
        match indent {
            0 => in_specs = false,
            2 => in_specs = content == "specs:",
            4 if in_specs => {
                if let Some((name, version)) = content.split_once(" (") {
                    let version = version.trim_end_matches(')').split('-').next().unwrap_or_default();
                    specs.push((name.to_string(), version.to_string(), Vec::new()));
                }
            }
            6 if in_specs => {
                if let Some(spec) = specs.last_mut() {
                    spec.2.push(content.split(' ').next().unwrap_or_default().to_string());
                }
            }
            _ => {}
        }
    }
    let mut lock = Lock::default();
    for (name, version, deps) in specs {
        if !lock.contains(&name) {
            lock.add(name.clone(), name.clone(), version, deps);
            lock.root(name.clone(), name);
        }
    }
    lock
}

#[cfg(test)]
mod tests {
    use super::super::testdir::TestDir;
    use super::*;

    #[test]
    fn reads_gemfile_and_lock() {
        let t = TestDir::new("ruby");
        t.file(
            "Gemfile",
            "source \"https://rubygems.org\"\ngem \"rails\", \"~> 7.1.0\"\ngem 'nokogiri'\ngem \"rubocop\", group: :development\n\ngroup :development, :test do\n  gem \"rspec\", \"3.12.0\"\nend\n",
        )
        .file(
            "Gemfile.lock",
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.15.4-arm64-darwin)\n      racc (~> 1.4)\n    racc (1.7.3)\n    rails (7.1.3)\n      rack (>= 2.2.4)\n    rack (3.0.8)\n\nPLATFORMS\n  arm64-darwin\n\nDEPENDENCIES\n  rails (~> 7.1.0)\n",
        );
        let found = read(&Folder::new(t.root(), t.root())).unwrap();
        let got: Vec<(&str, Option<&str>, DepKind, Option<&str>)> =
            found.deps.iter().map(|d| (d.name.as_str(), d.version.as_deref(), d.kind, d.via.as_deref())).collect();
        assert_eq!(
            got,
            [
                ("rails", Some("7.1.3"), DepKind::Prod, None),
                ("nokogiri", Some("1.15.4"), DepKind::Prod, None),
                ("rubocop", None, DepKind::Dev, None),
                ("rspec", Some("3.12.0"), DepKind::Dev, None),
                ("rack", Some("3.0.8"), DepKind::Indirect, Some("rails")),
                ("racc", Some("1.7.3"), DepKind::Indirect, Some("nokogiri")),
            ]
        );
    }
}
