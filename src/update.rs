//! `stackradar update`: replace this binary with the latest release's build for this
//! platform. The archive is unpacked with `tar` (built into macOS, Linux and Windows 10+,
//! where it reads zips too) once its SHA-256 matches the release's `.sha256` asset, and the
//! new binary must run before it replaces the old one.
//! A cargo install is left to cargo.

use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::deps::version;
use crate::sources::github::GitHub;
use crate::sources::http;
use crate::store::paths::data_dir;
use crate::uninstall::{cargo_bin, delete_after_exit};

const CURRENT: &str = env!("CARGO_PKG_VERSION");

/// `owner/name` of the repo releases come from.
fn repo() -> &'static str {
    env!("CARGO_PKG_REPOSITORY").trim_start_matches("https://github.com/")
}

/// The release asset built for this OS and CPU, as the release workflows name them.
fn asset_name() -> Option<&'static str> {
    Some(match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", _) => "stackradar-macos-universal.tar.gz",
        ("windows", "x86_64") => "stackradar-windows-x86_64.zip",
        ("windows", "aarch64") => "stackradar-windows-arm64.zip",
        ("linux", "x86_64") => "stackradar-linux-x86_64.tar.gz",
        ("linux", "aarch64") => "stackradar-linux-arm64.tar.gz",
        _ => return None,
    })
}

/// Check for a newer release and, unless `check_only`, install it.
pub fn run(check_only: bool) -> Result<String, String> {
    let release = GitHub::new().latest_release(repo())?;
    let latest = release.tag_name.trim_start_matches('v');
    if version::compare(latest, CURRENT) != Some(Ordering::Greater) {
        return Ok(format!("stackradar {CURRENT} is the latest version."));
    }
    if check_only {
        return Ok(format!("stackradar {latest} is available (you have {CURRENT}): run `stackradar update`."));
    }
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate stackradar binary: {e}"))?;
    if exe.parent() == Some(cargo_bin().as_path()) {
        return Ok(format!(
            "Installed with cargo: update with `cargo install --git {} --tag {} --force`.",
            env!("CARGO_PKG_REPOSITORY"),
            release.tag_name
        ));
    }
    let name = asset_name().ok_or("no prebuilt binary for this platform: build from source")?;
    let asset = release
        .assets
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| format!("release {} has no {name}: build from source", release.tag_name))?;
    let sums = sha256_asset(name, &release.tag_name);
    let sums = release
        .assets
        .iter()
        .find(|a| a.name == sums)
        .ok_or_else(|| format!("release {} has no {sums} to verify the download against", release.tag_name))?;
    let sha256 = http::checked(http::send(http::client().get(&sums.browser_download_url))?)?
        .text()
        .map_err(|e| format!("cannot read {}: {e}", sums.name))?;
    let sha256 = parse_sha256(&sha256).ok_or_else(|| format!("{} holds no SHA-256", sums.name))?;
    let dir = data_dir().join("update");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let result = install(&asset.browser_download_url, name, &sha256, &dir, &exe, latest);
    let _ = std::fs::remove_dir_all(&dir);
    result.map(|()| format!("Updated stackradar {CURRENT} → {latest}"))
}

/// The checksum asset for `name`: the release workflows hash its versioned copy, e.g.
/// `stackradar-v0.6.1-macos-universal.tar.gz.sha256` for `stackradar-macos-universal.tar.gz`.
fn sha256_asset(name: &str, tag: &str) -> String {
    format!("{}.sha256", name.replacen("stackradar-", &format!("stackradar-{tag}-"), 1))
}

/// The hash from a `sha256sum`-style line (`<hex>  <file>`), lowercase.
fn parse_sha256(text: &str) -> Option<String> {
    let hex = text.split_whitespace().next()?;
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then(|| hex.to_ascii_lowercase())
}

fn sha256_of(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &bytes);
    Ok(digest.as_ref().iter().map(|b| format!("{b:02x}")).collect())
}

/// Download the archive to `dir`, check its SHA-256, unpack it, check the binary in it,
/// then swap it in.
fn install(url: &str, name: &str, sha256: &str, dir: &Path, exe: &Path, latest: &str) -> Result<(), String> {
    let archive = dir.join(name);
    eprintln!("→ Downloading {url}");
    http::download(url, &archive)?;
    if sha256_of(&archive)? != sha256 {
        return Err(format!("{name} doesn't match the release's SHA-256; nothing was changed"));
    }
    let out = Command::new("tar")
        .arg("-xf")
        .arg(&archive)
        .arg("-C")
        .arg(dir)
        .output()
        .map_err(|e| format!("cannot run tar: {e}"))?;
    if !out.status.success() {
        return Err(format!("cannot unpack {name}: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    let new = dir.join(if cfg!(windows) { "stackradar.exe" } else { "stackradar" });
    let version =
        Command::new(&new).arg("--version").output().map_err(|e| format!("the new binary doesn't run: {e}"))?;
    if !String::from_utf8_lossy(&version.stdout).contains(latest) {
        return Err(format!("the downloaded binary isn't version {latest}; nothing was changed"));
    }
    replace(exe, &new)
}

/// Put `new` in place of the running `exe`. A rename within one folder is atomic. The
/// running exe can't be overwritten on Windows, but it can be renamed out of the way.
fn replace(exe: &Path, new: &Path) -> Result<(), String> {
    let staged = sibling(exe, "new");
    let denied = |e: std::io::Error| match e.kind() {
        std::io::ErrorKind::PermissionDenied => {
            format!("{} needs admin rights to change: run `sudo stackradar update`", exe.display())
        }
        _ => format!("cannot replace {}: {e}", exe.display()),
    };
    std::fs::copy(new, &staged).map_err(denied)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).map_err(denied)?;
    }
    if cfg!(windows) {
        let old = sibling(exe, "old");
        let _ = std::fs::remove_file(&old);
        std::fs::rename(exe, &old).map_err(denied)?;
        std::fs::rename(&staged, exe).map_err(denied)?;
        delete_after_exit(&old, None)
    } else {
        std::fs::rename(&staged, exe).map_err(denied)
    }
}

/// `stackradar.exe` → `stackradar.exe.new` in the same folder.
fn sibling(exe: &Path, suffix: &str) -> PathBuf {
    let mut name = exe.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{suffix}"));
    exe.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_assets_and_staging_files() {
        assert_eq!(repo(), "phutran1210dev/stackradar");
        assert!(asset_name().is_some_and(|n| n.starts_with("stackradar-")));
        assert_eq!(sibling(Path::new("/usr/local/bin/stackradar"), "new"), Path::new("/usr/local/bin/stackradar.new"));
    }

    #[test]
    fn verifies_against_the_release_checksum() {
        assert_eq!(
            sha256_asset("stackradar-macos-universal.tar.gz", "v0.6.1"),
            "stackradar-v0.6.1-macos-universal.tar.gz.sha256"
        );
        let line =
            "C4E5BA670EF7FA167DA0C86DB5CAD232695CAC6BCC521D25F309E9CF6BFFFA7A  stackradar-v0.6.1-windows-x86_64.zip";
        assert_eq!(parse_sha256(line).unwrap(), line[..64].to_ascii_lowercase());
        assert_eq!(parse_sha256("not a hash"), None);
        let file = std::env::temp_dir().join(format!("stackradar-sha-{}", std::process::id()));
        std::fs::write(&file, "abc").unwrap();
        let sum = sha256_of(&file);
        std::fs::remove_file(&file).unwrap();
        assert_eq!(sum.unwrap(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[cfg(unix)]
    #[test]
    fn replaces_the_binary_in_place() {
        let dir = std::env::temp_dir().join(format!("stackradar-update-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (exe, new) = (dir.join("stackradar"), dir.join("downloaded"));
        std::fs::write(&exe, "old").unwrap();
        std::fs::write(&new, "new").unwrap();
        replace(&exe, &new).unwrap();
        assert_eq!(std::fs::read_to_string(&exe).unwrap(), "new");
        assert!(!sibling(&exe, "new").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
