//! Where things live: the home directory, `~/.stackradar`, and `~` in user-given paths.

use std::path::{Path, PathBuf};

/// `$HOME`, else `%USERPROFILE%` (Windows sets only the latter, unless run from Git Bash).
pub fn home() -> PathBuf {
    ["HOME", "USERPROFILE"]
        .iter()
        .find_map(|v| std::env::var_os(v).filter(|h| !h.is_empty()))
        .map(PathBuf::from)
        .unwrap_or_default()
}

/// `~/.stackradar`: config, history, caches and reports.
pub fn data_dir() -> PathBuf {
    home().join(".stackradar")
}

/// `~/x` → `$HOME/x` (and `~` alone → `$HOME`); other paths are kept as given.
/// On Windows `~\x` works too.
pub fn expand(path: &str) -> PathBuf {
    let rest = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\").filter(|_| cfg!(windows)));
    match rest {
        Some(rest) => home().join(rest),
        None if path == "~" => home(),
        None => PathBuf::from(path),
    }
}

/// `$HOME/x` → `~/x`, for showing paths compactly.
pub fn tilde(path: &Path) -> String {
    match path.strip_prefix(home()) {
        Ok(rest) if !home().as_os_str().is_empty() => Path::new("~").join(rest).display().to_string(),
        _ => path.display().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_and_shortens_home() {
        let p = expand("~/code/app");
        assert_eq!(p, home().join("code/app"));
        assert_eq!(tilde(&p), Path::new("~").join("code/app").display().to_string());
        assert_eq!(expand("/opt/x"), PathBuf::from("/opt/x"));
        assert_eq!(tilde(Path::new("/opt/x")), "/opt/x");
    }
}
