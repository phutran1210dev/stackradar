<p align="center">
  <img src="assets/radar.svg" width="96" alt="">
</p>

<h1 align="center">Stack Radar</h1>

<p align="center">
  Known vulnerabilities and malware in your dependencies, and rising GitHub repos for your stack.
</p>

<p align="center">
  <a href="https://github.com/phutran1210dev/stackradar/releases/latest"><img src="https://img.shields.io/github/v/release/phutran1210dev/stackradar?color=5b93ff" alt="Latest release"></a>
  <a href="https://github.com/phutran1210dev/stackradar/actions/workflows/ci.yml"><img src="https://github.com/phutran1210dev/stackradar/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-2f6feb" alt="macOS | Linux | Windows">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-3fb950" alt="MIT license"></a>
</p>

Stack Radar is a single-binary CLI with two jobs:

- **Audit.** `stackradar audit` checks your projects' dependencies, including transitive ones from
  lockfiles, for known vulnerabilities and malware. It fails the build by severity and writes SARIF
  for GitHub code scanning. It reads only manifests and lockfiles, never runs anything from your
  projects, and needs no config.
- **Discovery.** `stackradar` on its own also ranks new and trending GitHub repos in the topics you
  follow, by a buzz score built from GitHub Trending, Hacker News and star velocity.

## Contents

- [Quick start](#quick-start)
- [GitHub Action](#github-action)
- [Other CI systems](#other-ci-systems)
- [Install](#install)
- [`stackradar audit`](#stackradar-audit)
- [Supported ecosystems](#supported-ecosystems)
- [Ignoring advisories](#ignoring-advisories)
- [Discovery](#discovery)
- [Privacy and safety](#privacy-and-safety)

## Quick start

```sh
stackradar audit .                       # check the projects under the current folder
stackradar audit . --fail-on critical    # exit 1 only on critical findings
stackradar audit . --html audit.html     # also write an HTML report
```

## GitHub Action

The action installs the latest release, runs the audit, uploads SARIF to code scanning and fails the
job by `fail-on`.

```yaml
name: Dependency audit
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # for the SARIF upload

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: phutran1210dev/stackradar@v1.0.0
        with:
          fail-on: high
```

| Input | Default | Description |
|:---|:---|:---|
| `path` | `.` | Folders to check, separated by spaces. Each is searched up to 3 levels deep. |
| `fail-on` | `high` | Lowest severity that fails the job: `critical`, `high`, `medium`, `low`, `any` or `never`. |
| `ignore` | | An ignore or baseline file. See [Ignoring advisories](#ignoring-advisories). |
| `args` | | Extra arguments for `stackradar audit`, such as `--ignore-dev` or `--exploits`. |
| `sarif` | `stackradar.sarif` | Where to write the SARIF report. |
| `upload-sarif` | `true` | Upload the SARIF report to code scanning. Needs `security-events: write`. |
| `version` | `latest` | Release to install, such as `v1.0.0`. |
| `token` | `${{ github.token }}` | Token for the GitHub Advisory Database. |

| Output | Description |
|:---|:---|
| `exit-code` | `0` nothing at or above `fail-on`, `1` vulnerabilities found, `2` error or incomplete check. |

It runs on Linux, macOS and Windows runners, x86_64 and ARM64.

## Other CI systems

Download the binary and run the audit. `--osv` needs no token:

```sh
curl -fsSL https://github.com/phutran1210dev/stackradar/releases/latest/download/stackradar-linux-x86_64.tar.gz | tar -xz
./stackradar audit . --osv --fail-on high
```

Fail the step on exit code `1` (findings) and `2` (error or incomplete check).

## Install

**macOS** (Apple Silicon and Intel):

```sh
mkdir -p ~/.local/bin
curl -fsSL https://github.com/phutran1210dev/stackradar/releases/latest/download/stackradar-macos-universal.tar.gz | tar -xz -C ~/.local/bin
```

**Linux** (use `linux-arm64` on ARM):

```sh
mkdir -p ~/.local/bin
curl -fsSL https://github.com/phutran1210dev/stackradar/releases/latest/download/stackradar-linux-x86_64.tar.gz | tar -xz -C ~/.local/bin
```

If `stackradar` isn't found afterwards, add `export PATH="$HOME/.local/bin:$PATH"` to your shell profile.

**Windows** (PowerShell; use `windows-arm64` on ARM), then open a new terminal:

```powershell
$dir = "$env:LOCALAPPDATA\Programs\stackradar"
Invoke-WebRequest https://github.com/phutran1210dev/stackradar/releases/latest/download/stackradar-windows-x86_64.zip -OutFile "$env:TEMP\stackradar.zip"
Expand-Archive "$env:TEMP\stackradar.zip" -DestinationPath $dir -Force
[Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "User") + ";$dir", "User")
```

**From source** ([Rust](https://rustup.rs) 1.85+):

```sh
cargo install --git https://github.com/phutran1210dev/stackradar
```

Every release asset has a `.sha256` file next to it. `stackradar update` installs the latest release
and checks it against that file.

### GitHub token

A token raises GitHub's rate limits and enables the repo health and fake-star checks. No scopes are
needed. Without one, the full run looks up advisories in OSV.dev; for `audit`, pass `--osv`.

```sh
gh auth login                  # the GitHub CLI's token is picked up automatically
export GITHUB_TOKEN=ghp_xxx    # or set any token (Windows: setx GITHUB_TOKEN ghp_xxx)
```

## `stackradar audit`

```
stackradar audit [OPTIONS] <PATHS>...
```

`audit` checks only the folders you name. It reads no config, history or cache, and writes nothing
unless you ask for an output file.

| Option | Description |
|:---|:---|
| `--fail-on <LEVEL>` | Lowest severity that makes the exit code `1`: `critical`, `high` (default), `medium`, `low`, `any` or `never`. |
| `--ignore-dev` | Don't fail on vulnerabilities only in dev, test or build dependencies. Malware still fails. |
| `--osv` | Use [OSV.dev](https://osv.dev) instead of the GitHub Advisory Database: no token, no rate limit. |
| `--exploits` | Mark vulnerabilities in CISA's KEV catalog as exploited, show EPSS scores and list those first. |
| `--ignore <FILE>` | Leave out the advisories in this file's `[[ignore]]` rules. |
| `--write-baseline <FILE>` | Write every current finding as an ignore rule, then exit `0`. |
| `--html`, `--md`, `--json`, `--sarif <PATH>` | Also write an HTML, Markdown, JSON or SARIF report. |
| `-t, --top <N>` | Rows printed in the terminal (default 50). |

**Exit codes**

| Code | Meaning |
|:---|:---|
| `0` | Nothing at or above `--fail-on`. |
| `1` | Vulnerabilities at or above `--fail-on`. |
| `2` | Error or incomplete check, such as a lockfile that couldn't be read. Any warning means `2`. |

**What a finding contains.** Findings are grouped into upgrades, not listed advisory by advisory:

- the lowest version that fixes every advisory against the package;
- the command for your package manager (`npm`, `yarn`, `pnpm`, `bun`, `cargo`, `go`, `pip`,
  `poetry`, `uv`, `composer`, `bundle`, `dart pub` or `dotnet`);
- a "may break" warning when the upgrade crosses a major version;
- for a transitive package, the direct dependency it comes through (`qs` via `express`).

Upgrades are ordered malware first (its command removes the package), then exploited
vulnerabilities, then by severity, with runtime dependencies before dev and indirect ones.

## Supported ecosystems

Projects are found up to 3 levels deep.

| Ecosystem | Manifest | Exact and transitive versions from |
|:---|:---|:---|
| npm | `package.json` | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock` |
| Rust | `Cargo.toml` | `Cargo.lock` |
| Go | `go.mod` | `go.mod` |
| Python | `requirements.txt`, `pyproject.toml` | `==` pins, `poetry.lock`, `uv.lock` |
| PHP | `composer.json` | `composer.lock` |
| Ruby | `Gemfile` | `Gemfile.lock` |
| Dart / Flutter | `pubspec.yaml` | `pubspec.lock` |
| .NET | `*.csproj`, `*.fsproj`, `*.vbproj`, `Directory.Packages.props` | `packages.lock.json` |
| Java / Kotlin | `pom.xml`, `build.gradle(.kts)` | `gradle.lockfile` |

**Advisory sources.** The [GitHub Advisory Database](https://github.com/advisories), or
[OSV.dev](https://osv.dev) with `--osv` (the full run uses it when there is no token). OSV.dev adds
RustSec, PyPA, the Go vulnerability database and OpenSSF's malicious packages. CISA's
[Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
catalog and [EPSS](https://www.first.org/epss/) scores are always on in the full run, and opt-in for
`audit` with `--exploits`.

## Ignoring advisories

To accept an advisory, add an ignore rule. It is reported again after `until`:

```toml
[[ignore]]
id = "GHSA-xxxx-xxxx-xxxx"    # or a CVE id
package = "lodash"            # optional
reason = "only used in a build script"
until = 2026-12-31            # optional
```

Put rules in a file and pass it with `--ignore` (or the action's `ignore` input). To fail only on
**new** vulnerabilities, record a baseline once and commit it:

```sh
stackradar audit . --write-baseline .stackradar-ignore.toml
stackradar audit . --ignore .stackradar-ignore.toml
```

For the full run, the same rules go in `~/.stackradar/config.toml`.

## Discovery

```sh
stackradar --open
```

The full run ranks rising repos in your topics, checks the projects in your scan folders and opens
an HTML report. A first run takes about a minute; later runs reuse cached checks.

| Command | Description |
|:---|:---|
| `stackradar --view` | Reopen the last report without fetching. |
| `stackradar -d 7 -s 50` | Only repos from the last 7 days with at least 50 stars (defaults: 30 days, 20 stars). |
| `stackradar --md digest.md --json data.json` | Also write Markdown and JSON. |
| `stackradar --notify` | Desktop notification, plus a digest to your webhook if one is set. |
| `stackradar --install-schedule` | Run at 08:00 and 20:00 with `--notify` (launchd, Task Scheduler or a systemd user timer). |
| `stackradar update` | Install the latest release (`--check` only reports whether there is one). |
| `stackradar uninstall` | Remove the schedule, `~/.stackradar` and the binary (`--keep-data` keeps your config). |

### Configuration

`stackradar --init-config` writes `~/.stackradar/config.toml` with the defaults:

```toml
scan = ["~/code"]                       # your projects, for the "For you" and "Vulnerabilities" tabs
watch = ["vercel/next.js"]              # "Watching" tab: follow repos even outside the top
exclude = ["some-owner", "owner/repo"]  # hide noisy repos
webhook = "https://discord.com/api/webhooks/…"  # for --notify; Slack and Telegram work too

[[category]]
key = "trading"
title = "Trading & Crypto"
topics = ["trading", "cryptocurrency", "defi"]   # GitHub topic slugs, at most 30 in total
```

The default tabs are **Frontend** (react, react-native, nextjs), **Backend** (nodejs, express,
nestjs) and **AI** (llm, ai-agents, generative-ai, mcp).

If `scan` isn't set, these folders are scanned when they exist: `~/code`, `~/projects`, `~/dev`,
`~/Developer`, `~/src`, `~/repos`, `~/source/repos`, `~/workspace` and `~/Documents/GitHub`.
`scan = []` turns the scan off. The full run also flags unmaintained direct dependencies: ones whose
repo is archived or hasn't had a push in two years.

### Buzz score

| Signal | Effect |
|:---|:---|
| On GitHub Trending today | Strong boost |
| Discussed on Hacker News in the last 30 days | Boost |
| Stars gained since your last run | Boost |
| Stars per day since creation | Small boost |
| Low engagement: many stars, almost no forks or issues | × 0.5 |
| Suspicious stars: most recent stargazers are throwaway accounts | × 0.3 |

<details>
<summary><b>More about the report</b></summary>

- **For you** shows repos whose owner, name or topics match your projects' dependencies.
- **Watching** shows the repos in `watch`, with a badge when a new release has shipped since the
  last run.
- **Suspicious stars**: for repos with 100 stars or more, up to 30 recent stargazers are sampled. If
  at least half are under a year old with at most one follower, the repo is flagged.
- **Repo health** covers the license, latest release, commits and the closed-issue ratio, and flags
  releases that ship `.exe`, `.dmg` or `.apk` files.
- **History**: star counts are kept for 60 days. They drive the stars-gained column, the NEW badges
  and the sparklines.
- **The HTML page** opens on **Vulnerabilities** when anything is urgent (malware, exploited,
  critical or high), and otherwise on the first tab. Its first line says what to do, and **Copy N
  urgent fixes** copies every urgent command, each under a comment naming the package and its
  projects.
- **By project** lists your projects with their open advisories by severity. Choose one to see only
  its upgrades.
- **Dismissing** an upgrade also dismisses the advisories it fixes, with **Undo**. Saved, dismissed
  and seen repos are kept in this browser. Search (`/`), filters and sorting are kept in the URL, and
  the theme follows the system unless you pick light or dark.
- **Nothing is loaded from the network.** Owners are shown as initials rather than avatars, and the
  page uses Geist where it's installed, otherwise the system font.

</details>

## Privacy and safety

- Only package names and versions leave your machine, to the advisory database. For the exploited
  checks (full run, or `audit --exploits`), CVE ids are also sent to cisa.gov and api.first.org.
- Project files are read as data. Nothing from a scanned project is run, symlinks are skipped, and
  nothing above a scanned folder is read.
- Reports, config and history live in `~/.stackradar/` (`%USERPROFILE%\.stackradar\` on Windows)
  and only you can read them.
- Discovery results are public repos, **not vetted ones**. Exploit PoCs, "hack tools", trading bots
  and wallet tools are common malware lures. Read the code before you run it, and never paste a seed
  phrase or private key into code you haven't reviewed.

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE) © Alex (phutran1210dev)
