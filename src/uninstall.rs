//! `stackradar uninstall`: removes the schedule, `~/.stackradar` and the binary itself.
//! A running binary can be deleted on macOS and Linux, but not on Windows, where a hidden
//! PowerShell deletes it a moment after we exit.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::schedule;
use crate::store::paths::{data_dir, home};

/// Removes the exe once this process has exited, and its folder if that is now empty.
/// Paths arrive through environment variables, never spliced into the script.
const WINDOWS_DELETE_LATER: &str = r#"
Start-Sleep -Seconds 2
Remove-Item -LiteralPath $env:STACKRADAR_EXE -Force
$dir = $env:STACKRADAR_DIR
if ($dir -and -not (Get-ChildItem -LiteralPath $dir -Force)) { Remove-Item -LiteralPath $dir -Force }
"#;

/// Drops a folder from the user `PATH`, writing only if it was there.
const WINDOWS_REMOVE_FROM_PATH: &str = r#"
$parts = [Environment]::GetEnvironmentVariable('Path', 'User') -split ';' | Where-Object { $_ }
$keep = $parts | Where-Object { $_.TrimEnd('\') -ne $env:STACKRADAR_DIR.TrimEnd('\') }
if (@($keep).Count -ne @($parts).Count) { [Environment]::SetEnvironmentVariable('Path', ($keep -join ';'), 'User') }
"#;

pub struct Plan {
    exe: PathBuf,
    data: Option<PathBuf>,
}

impl Plan {
    pub fn new(keep_data: bool) -> Result<Plan, String> {
        let exe = std::env::current_exe().map_err(|e| format!("cannot locate stackradar binary: {e}"))?;
        let data = Some(data_dir()).filter(|d| !keep_data && d.exists());
        Ok(Plan { exe, data })
    }

    /// What will be removed, one item per line.
    pub fn describe(&self) -> String {
        let mut lines = vec!["  • the auto-update schedule, if installed".to_string()];
        if let Some(d) = &self.data {
            lines.push(format!("  • {} (config, history, reports)", d.display()));
        }
        lines.push(format!("  • {}", self.exe.display()));
        lines.join("\n")
    }

    /// Remove everything; each step that succeeded or needs the user is reported.
    pub fn run(&self) -> Result<Vec<String>, String> {
        let mut done = vec![schedule::uninstall()?];
        if let Some(d) = &self.data {
            std::fs::remove_dir_all(d).map_err(|e| format!("cannot remove {}: {e}", d.display()))?;
            done.push(format!("Removed {}", d.display()));
        }
        done.push(remove_binary(&self.exe)?);
        Ok(done)
    }
}

/// `$CARGO_HOME/bin`, else `~/.cargo/bin`.
pub(crate) fn cargo_bin() -> PathBuf {
    std::env::var_os("CARGO_HOME").map(PathBuf::from).unwrap_or_else(|| home().join(".cargo")).join("bin")
}

fn remove_binary(exe: &Path) -> Result<String, String> {
    // Deleting the file would leave cargo believing it's still installed.
    if exe.parent() == Some(cargo_bin().as_path()) {
        return Ok("Installed with cargo: finish with `cargo uninstall stackradar`.".into());
    }
    if cfg!(windows) {
        return remove_windows_binary(exe);
    }
    match std::fs::remove_file(exe) {
        Ok(()) => Ok(format!("Removed {}", exe.display())),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            Ok(format!("Finish with `sudo rm {}` (it needs admin rights).", exe.display()))
        }
        Err(e) => Err(format!("cannot remove {}: {e}", exe.display())),
    }
}

/// The installer in the README puts the exe alone in a `stackradar` folder on the user
/// `PATH`; only such a dedicated folder is taken off `PATH` and deleted.
fn remove_windows_binary(exe: &Path) -> Result<String, String> {
    let dir = exe.parent().filter(|d| d.file_name().is_some_and(|n| n.eq_ignore_ascii_case("stackradar")));
    if let Some(dir) = dir {
        let out = powershell(WINDOWS_REMOVE_FROM_PATH, exe, Some(dir))
            .output()
            .map_err(|e| format!("cannot run PowerShell: {e}"))?;
        if !out.status.success() {
            return Err(format!("cannot update PATH: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
    }
    delete_after_exit(exe, dir)?;
    let target = dir.unwrap_or(exe);
    Ok(format!("{} will be deleted in a few seconds.", target.display()))
}

/// On Windows, delete `exe` (a running binary can't be) a moment after this process
/// exits, and `dir` too if that leaves it empty.
pub(crate) fn delete_after_exit(exe: &Path, dir: Option<&Path>) -> Result<(), String> {
    powershell(WINDOWS_DELETE_LATER, exe, dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("cannot run PowerShell: {e}"))
}

fn powershell(script: &str, exe: &Path, dir: Option<&Path>) -> Command {
    let mut cmd = Command::new("powershell.exe");
    cmd.args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script])
        .env("STACKRADAR_EXE", exe);
    if let Some(dir) = dir {
        cmd.env("STACKRADAR_DIR", dir);
    }
    cmd
}
