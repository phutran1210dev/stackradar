//! The few things done through the OS: opening the report and desktop notifications.
//! macOS uses `open`/`osascript`; Windows uses `explorer`/a PowerShell toast; Linux uses
//! `xdg-open`/`notify-send`.

use std::path::Path;
use std::process::Command;

/// Windows PowerShell 5.1 (built in; `pwsh` can't load WinRT types) shows a toast under
/// PowerShell's own app id. Text arrives through environment variables and becomes XML
/// text nodes, so repo names can't inject script or markup.
const WINDOWS_TOAST: &str = r#"
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$text = $xml.GetElementsByTagName('text')
$text.Item(0).AppendChild($xml.CreateTextNode($env:STACKRADAR_TITLE)) > $null
$text.Item(1).AppendChild($xml.CreateTextNode($env:STACKRADAR_MESSAGE)) > $null
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($xml))
"#;

/// Open a file with the default app (the browser, for the report).
pub fn open(path: &Path) {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(windows) {
        "explorer"
    } else {
        "xdg-open"
    };
    // Only a failure to start counts: `explorer` exits 1 even when it opened the file.
    if Command::new(opener).arg(path).status().is_err() {
        eprintln!("⚠  Could not run {opener}; open {} yourself.", path.display());
    }
}

/// Desktop notification, best effort. The message goes in as an argument (or an
/// environment variable), never spliced into a script, so repo names can't inject anything.
pub fn notify(title: &str, message: &str) {
    let _ = if cfg!(target_os = "macos") {
        Command::new("osascript")
            .args([
                "-e",
                "on run argv",
                "-e",
                "display notification (item 2 of argv) with title (item 1 of argv)",
                "-e",
                "end run",
            ])
            .args([title, message])
            .output()
    } else if cfg!(windows) {
        Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", WINDOWS_TOAST])
            .env("STACKRADAR_TITLE", title)
            .env("STACKRADAR_MESSAGE", message)
            .output()
    } else {
        Command::new("notify-send").args([title, message]).output()
    };
}
