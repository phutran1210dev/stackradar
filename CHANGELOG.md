# Changelog

## 1.0.0 (2026-10-29)

First release.

### Audit

- `stackradar audit <paths>` checks projects' dependencies, including transitive ones from
  lockfiles, for known vulnerabilities and malware in 9 ecosystems: npm, Rust, Go, Python, PHP,
  Ruby, Dart/Flutter, .NET and Java/Kotlin.
- Findings are grouped into upgrades: the lowest fixing version, the command for your package
  manager, and a warning when the upgrade crosses a major version.
- `--fail-on`, `--ignore-dev`, `--ignore` and `--write-baseline` for CI. Exit codes are `0` clean,
  `1` findings, `2` error or incomplete check.
- `--sarif` for GitHub code scanning, plus `--html`, `--md` and `--json` reports.
- `--osv` uses OSV.dev: no token, no rate limit, and the ecosystems' own databases.
- `--exploits` marks vulnerabilities in CISA's KEV catalog and shows EPSS scores.
- A GitHub Action that installs the release, runs the audit and uploads SARIF.

### Discovery

- Ranks new and trending GitHub repos in your topics by a buzz score from GitHub Trending, Hacker
  News and star velocity, and discounts bought-looking stars.
- "For you" matches repos to your projects' dependencies, and "Watching" follows chosen repos.
- Scheduled runs, desktop notifications and webhook digests for Discord, Slack and Telegram.

### HTML report

- Opens on Vulnerabilities when anything is urgent, says what to do in its first line, and copies
  every urgent fix in one click.
- By project table with severity counts that filters the upgrades.
- Dismissing an upgrade dismisses the advisories it fixes, with Undo.
- Self-contained: nothing is loaded from the network. Untrusted text is rendered only through DOM
  APIs.

### Install and update

- Builds for macOS (universal), Linux and Windows (x86_64 and ARM64), each with a `.sha256` file.
- `stackradar update` verifies the download's SHA-256, and `stackradar uninstall` removes
  everything.
