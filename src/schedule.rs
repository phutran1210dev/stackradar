//! Automatic updates via a macOS LaunchAgent: runs twice a day (the evening run also
//! retries a morning run that failed offline), and launchd catches up after sleep.
//! On Windows a Task Scheduler task does the same, and on Linux a systemd user timer;
//! without systemd the equivalent crontab line is printed instead.

use std::path::PathBuf;
use std::process::Command;

use crate::store::paths::{data_dir, home};

const LABEL: &str = "com.stackradar.update";
/// Job installed under the tool's old name; removed whenever the schedule changes.
const LEGACY_LABEL: &str = "com.gh-trending.daily";
const RUN_AT: &[(u8, u8)] = &[(8, 0), (20, 0)];
const TASK_NAME: &str = "stackradar-update";
/// systemd unit name (`.service` and `.timer`).
const UNIT: &str = "stackradar-update";

fn plist_path_for(label: &str) -> PathBuf {
    home().join("Library/LaunchAgents").join(format!("{label}.plist"))
}

fn plist_path() -> PathBuf {
    plist_path_for(LABEL)
}

/// Unload a job and delete its plist; true if a plist existed.
fn remove_job(domain: &str, label: &str) -> Result<bool, String> {
    let _ = Command::new("launchctl").args(["bootout", &format!("{domain}/{label}")]).output();
    match std::fs::remove_file(plist_path_for(label)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

fn domain() -> Result<String, String> {
    let out = Command::new("id").arg("-u").output().map_err(|e| e.to_string())?;
    Ok(format!("gui/{}", String::from_utf8_lossy(&out.stdout).trim()))
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// The scheduled command line (shared by launchd and the crontab hint).
fn command(exe: &str) -> [String; 6] {
    let dir = data_dir();
    [
        exe.to_string(),
        "--md".into(),
        dir.join("digest.md").display().to_string(),
        "--json".into(),
        dir.join("data.json").display().to_string(),
        "--notify".into(),
    ]
}

fn plist(exe: &str, path_env: &str) -> String {
    let args: String = command(exe).iter().map(|a| format!("    <string>{}</string>\n", xml(a))).collect();
    let times: String = RUN_AT
        .iter()
        .map(|(h, m)| {
            format!("    <dict><key>Hour</key><integer>{h}</integer><key>Minute</key><integer>{m}</integer></dict>\n")
        })
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
{args}  </array>
  <key>EnvironmentVariables</key>
  <dict><key>PATH</key><string>{path}</string></dict>
  <key>StartCalendarInterval</key>
  <array>
{times}  </array>
  <!-- Tables go nowhere; only warnings and errors are kept. -->
  <key>StandardOutPath</key><string>/dev/null</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict>
</plist>
"#,
        path = xml(path_env),
        log = xml(&data_dir().join("run.log").display().to_string()),
    )
}

/// A Task Scheduler task, as XML: the only form `schtasks` takes with two run times.
/// It runs as the signed-in user (so notifications show) and catches up after sleep.
fn task_xml(exe: &str) -> String {
    // Windows paths can't contain `"`, so quoting each argument is enough.
    let args: Vec<String> = command(exe)[1..].iter().map(|a| format!("\"{a}\"")).collect();
    let triggers: String = RUN_AT
        .iter()
        .map(|(h, m)| {
            format!(
                "    <CalendarTrigger><StartBoundary>2020-01-01T{h:02}:{m:02}:00</StartBoundary>\
                 <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>\n"
            )
        })
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Stack Radar: refresh the report and notify</Description></RegistrationInfo>
  <Triggers>
{triggers}  </Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <StartWhenAvailable>true</StartWhenAvailable>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author">
    <Exec><Command>{cmd}</Command><Arguments>{args}</Arguments></Exec>
  </Actions>
</Task>
"#,
        cmd = xml(exe),
        args = xml(&args.join(" ")),
    )
}

fn run(program: &str, args: &[&str]) -> Result<std::process::Output, String> {
    Command::new(program).args(args).output().map_err(|e| format!("cannot run {program}: {e}"))
}

/// Run `program`, failing with its stderr unless it succeeds.
fn run_ok(program: &str, args: &[&str]) -> Result<(), String> {
    let out = run(program, args)?;
    if !out.status.success() {
        return Err(format!("{program} {} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(())
}

fn schtasks(args: &[&str]) -> Result<std::process::Output, String> {
    run("schtasks", args)
}

/// `$XDG_CONFIG_HOME/systemd/user`, else `~/.config/systemd/user`.
fn systemd_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".config"))
        .join("systemd/user")
}

/// The `.service` and `.timer` units. Arguments are double-quoted with systemd's escapes
/// (`%` starts a specifier and `$` a variable, so both are doubled).
fn systemd_units(exe: &str, path_env: &str) -> (String, String) {
    let quote =
        |a: &str| format!("\"{}\"", a.replace('\\', r"\\").replace('"', "\\\"").replace('%', "%%").replace('$', "$$"));
    let args: Vec<String> = command(exe).iter().map(|a| quote(a)).collect();
    let service = format!(
        "[Unit]\nDescription=Stack Radar: refresh the report and notify\n\n[Service]\nType=oneshot\n\
         Environment={}\nExecStart={}\n# Tables go nowhere; only warnings and errors are kept.\n\
         StandardOutput=null\nStandardError=append:{}\n",
        quote(&format!("PATH={path_env}")),
        args.join(" "),
        data_dir().join("run.log").display().to_string().replace('%', "%%"),
    );
    let calendar: String = RUN_AT.iter().map(|(h, m)| format!("OnCalendar=*-*-* {h:02}:{m:02}:00\n")).collect();
    let timer = format!(
        "[Unit]\nDescription=Run Stack Radar twice a day\n\n[Timer]\n{calendar}\
         # Catch up on a run missed while the machine was off.\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"
    );
    (service, timer)
}

/// Write the units and start the timer. Fails without a systemd user session (WSL,
/// containers), where `install` falls back to the crontab line.
fn install_systemd(exe: &str, path_env: &str) -> Result<(), String> {
    run_ok("systemctl", &["--user", "show-environment"])?;
    let dir = systemd_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let (service, timer) = systemd_units(exe, path_env);
    std::fs::write(dir.join(format!("{UNIT}.service")), service).map_err(|e| e.to_string())?;
    std::fs::write(dir.join(format!("{UNIT}.timer")), timer).map_err(|e| e.to_string())?;
    run_ok("systemctl", &["--user", "daemon-reload"])?;
    run_ok("systemctl", &["--user", "enable", "--now", &format!("{UNIT}.timer")])
}

/// Stop the timer and delete the units; true if they existed.
fn remove_systemd() -> Result<bool, String> {
    let dir = systemd_dir();
    let files = [dir.join(format!("{UNIT}.timer")), dir.join(format!("{UNIT}.service"))];
    if !files[0].exists() {
        return Ok(false);
    }
    let _ = run("systemctl", &["--user", "disable", "--now", &format!("{UNIT}.timer")]);
    for f in &files {
        std::fs::remove_file(f)
            .or_else(|e| if e.kind() == std::io::ErrorKind::NotFound { Ok(()) } else { Err(e) })
            .map_err(|e| format!("cannot remove {}: {e}", f.display()))?;
    }
    let _ = run("systemctl", &["--user", "daemon-reload"]);
    Ok(true)
}

/// Register (or replace) the task. `schtasks` reads the XML from a file, in UTF-16.
fn install_task(exe: &str) -> Result<(), String> {
    crate::store::private::create_dir(&data_dir()).map_err(|e| e.to_string())?;
    let file = data_dir().join("schedule-task.xml");
    let utf16: Vec<u8> =
        std::iter::once(0xFEFF).chain(task_xml(exe).encode_utf16()).flat_map(u16::to_le_bytes).collect();
    std::fs::write(&file, utf16).map_err(|e| e.to_string())?;
    let out = run_ok("schtasks", &["/Create", "/TN", TASK_NAME, "/XML", &file.display().to_string(), "/F"]);
    let _ = std::fs::remove_file(&file);
    out
}

fn scheduled_message(log: Option<PathBuf>) -> String {
    let times: Vec<String> = RUN_AT.iter().map(|(h, m)| format!("{h:02}:{m:02}")).collect();
    let log = log.map(|l| format!(" (log: {})", l.display())).unwrap_or_default();
    format!("Scheduled daily at {} → {}{log}", times.join(" and "), data_dir().join("trending.html").display())
}

/// Install (or replace) the LaunchAgent (or systemd timer) pointing at the running
/// binary. The current PATH is captured so the job finds `gh` for the GitHub token, as
/// in this shell. On Windows the task inherits the user's environment, so nothing is captured.
pub fn install() -> Result<String, String> {
    let exe = std::env::current_exe()
        // On Windows canonicalizing gives a `\\?\` path, and current_exe is already absolute.
        .and_then(|p| if cfg!(windows) { Ok(p) } else { p.canonicalize() })
        .map_err(|e| format!("cannot locate stackradar binary: {e}"))?;
    if cfg!(windows) {
        install_task(&exe.display().to_string())?;
        return Ok(scheduled_message(None));
    }
    let path_env = std::env::var("PATH").unwrap_or_else(|_| "/opt/homebrew/bin:/usr/bin:/bin".into());
    if !cfg!(target_os = "macos") {
        let exe = exe.display().to_string();
        return match install_systemd(&exe, &path_env) {
            Ok(()) => Ok(scheduled_message(Some(data_dir().join("run.log")))),
            Err(e) => {
                Err(format!("no systemd user session ({e}). Add this to `crontab -e` instead:\n{}", cron_line(&exe)))
            }
        };
    }
    crate::store::private::create_dir(&data_dir()).map_err(|e| e.to_string())?;
    let plist_file = plist_path();
    if let Some(dir) = plist_file.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    std::fs::write(&plist_file, plist(&exe.display().to_string(), &path_env)).map_err(|e| e.to_string())?;

    let domain = domain()?;
    // Replace any previous version; "not loaded" is expected on first install.
    remove_job(&domain, LEGACY_LABEL)?;
    let _ = Command::new("launchctl").args(["bootout", &format!("{domain}/{LABEL}")]).output();
    let out =
        Command::new("launchctl").args(["bootstrap", &domain]).arg(&plist_file).output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!("launchctl bootstrap failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(scheduled_message(Some(data_dir().join("run.log"))))
}

/// `0 8,20 * * * <command> 2>> ~/.stackradar/run.log`, arguments single-quoted for sh.
fn cron_line(exe: &str) -> String {
    let quote = |a: &str| format!("'{}'", a.replace('\'', r"'\''"));
    let hours: Vec<String> = RUN_AT.iter().map(|(h, _)| h.to_string()).collect();
    let args: Vec<String> = command(exe).iter().map(|a| quote(a)).collect();
    format!(
        "{} {} * * * {} >/dev/null 2>>{}",
        RUN_AT[0].1,
        hours.join(","),
        args.join(" "),
        quote(&data_dir().join("run.log").display().to_string())
    )
}

pub fn uninstall() -> Result<String, String> {
    if cfg!(windows) {
        if !schtasks(&["/Query", "/TN", TASK_NAME])?.status.success() {
            return Ok("No schedule was installed.".into());
        }
        let out = schtasks(&["/Delete", "/TN", TASK_NAME, "/F"])?;
        if !out.status.success() {
            return Err(format!("schtasks /Delete failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        return Ok("Scheduled updates removed.".into());
    }
    if !cfg!(target_os = "macos") {
        return Ok(if remove_systemd()? {
            "Scheduled updates removed.".into()
        } else {
            "No systemd timer was installed; if you added one, remove the stackradar line from `crontab -e`.".into()
        });
    }
    let domain = domain()?;
    let legacy = remove_job(&domain, LEGACY_LABEL)?;
    Ok(if remove_job(&domain, LABEL)? || legacy {
        "Scheduled updates removed.".into()
    } else {
        "No schedule was installed.".into()
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn plist_escapes_and_lists_both_runs() {
        let p = super::plist("/tmp/a&b/stackradar", "/opt/homebrew/bin:/usr/bin");
        assert!(p.contains("<string>/tmp/a&amp;b/stackradar</string>"));
        assert!(p.contains("<integer>8</integer>") && p.contains("<integer>20</integer>"));
        assert!(p.contains("<string>--notify</string>"));
    }

    #[test]
    fn task_xml_escapes_and_lists_both_runs() {
        let t = super::task_xml(r"C:\Tools\a&b\stackradar.exe");
        assert!(t.contains(r"<Command>C:\Tools\a&amp;b\stackradar.exe</Command>"), "{t}");
        assert!(t.contains("T08:00:00</StartBoundary>") && t.contains("T20:00:00</StartBoundary>"));
        assert!(t.contains("<Arguments>&quot;--md&quot; &quot;") && t.contains("&quot;--notify&quot;</Arguments>"));
    }

    #[test]
    fn systemd_units_escape_and_list_both_runs() {
        let (service, timer) = super::systemd_units("/opt/50%/it\"s/stackradar", "/usr/bin:$HOME/bin");
        assert!(service.contains(r#"ExecStart="/opt/50%%/it\"s/stackradar" "--md" "#), "{service}");
        assert!(service.contains(r#"Environment="PATH=/usr/bin:$$HOME/bin""#), "{service}");
        assert!(
            timer.contains("OnCalendar=*-*-* 08:00:00\nOnCalendar=*-*-* 20:00:00\n")
                && timer.contains("Persistent=true")
        );
    }

    #[test]
    fn cron_line_quotes_arguments() {
        let line = super::cron_line("/opt/it's/stackradar");
        assert!(line.starts_with("0 8,20 * * * '/opt/it'\\''s/stackradar' '--md' "), "{line}");
        assert!(line.contains("'--notify' >/dev/null 2>>'"));
    }
}
