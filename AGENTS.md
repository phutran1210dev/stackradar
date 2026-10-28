# AGENTS.md

Guidance for coding agents working in this repository. Read [README.md](README.md) for user-facing behavior.

Stack Radar is a single-binary Rust CLI (edition 2024, Rust 1.85+). It ranks rising GitHub repos
for the user's stack by a buzz score, and checks the user's own projects' dependencies for known
vulnerabilities and malware.

## Commands

CI (`.github/workflows/ci.yml`, manually triggered, Ubuntu and Windows) runs exactly these. Keep
all three passing:

```sh
cargo fmt --check                                   # max_width 120, use_small_heuristics = "Max"
cargo clippy --all-targets --locked -- -D warnings  # warnings are errors
cargo test --locked
```

- Run a single test with `cargo test <name>` or a module path such as `cargo test deps::npm::`.
- `cargo run -- audit <dir>` is the quickest way to exercise the code; it needs no config. The full
  run is `cargo run -- --open`.
- The GitHub token comes from `GITHUB_TOKEN`, then `gh auth token`.

## Tests

- All tests are inline `#[cfg(test)]` modules in `src/`. There is no `tests/*.rs` suite.
- HTTP code is tested against `sources::mock::Mock`, a local stand-in server. Point a client at it
  with `GitHub::at`, `Osv::at` or `Exploits::at`.
- The vulnerability pipeline is tested with a fake `AdvisoryDb`.
- Tests that need Unix (symlinks, permissions) are `#[cfg(unix)]`.

## Architecture

Data flows one way:

`sources` → `pipeline` → `signals` → `model::Report` → `report`

- **`sources`**: everything over HTTP.
  - The GitHub API, the trending page, Hacker News and the package registries.
  - Advisories behind the `advisories::AdvisoryDb` trait. GitHub and `osv::Osv` implement it, and
    each keeps its own wire format.
  - `exploits`: CISA KEV and EPSS.
- **`pipeline`** has two entry points:
  - `run`, the full scan. Gathering repos runs in parallel with the project scan and the
    vulnerability check, which uses OSV.dev when there is no token. As a side effect, it records
    today's star counts.
  - `audit`, the `stackradar audit` path. See the rules below.
- **`signals`** computes the buzz score, repo health, fake-star checks, "For you" matching, and
  advisory attribution and fixes.
- **`deps`** parses manifests and lockfiles for 9 ecosystems, up to `MAX_DEPTH` levels deep.
  - Lockfiles become a `lock::Lock` graph; transitive packages carry `via`, the direct dependency
    they come through.
  - The `Manager` (npm/Yarn/pnpm/Bun, Poetry/uv, …) decides the fix commands.
  - Files it can't read or parse are returned as problems and become warnings.
- **`store`** holds the local state under `~/.stackradar/`: config, 60-day star history, caches and
  "seen" sets. JSON goes through `json_file`, and private files through `store::private`.
- **`report`** has five renderers: terminal, Markdown, HTML, the webhook digest and SARIF (audit
  only). Shared labels live in `report/mod.rs`, so every format agrees.
- **`Warnings`** (`pipeline/mod.rs`) carries partial failures. Each one is printed and embedded in
  the report. Prefer a warning to failing the run.

## Rules to keep

- **`audit` stays isolated.**
  - It reads no config, history or cache, and nothing outside the given folders except an explicit
    `--ignore` file.
  - It writes only the outputs it is asked for.
  - It talks only to the advisory database: GitHub's, or OSV.dev with `--osv`. Any other source
    must be opt-in behind a flag, like `--exploits`.
  - Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` error or incomplete check.
    Any warning means `2`.
- **Project files are data.** Never execute anything from a scanned project. Skip symlinks, and
  never read above the folder being scanned.
- **Repo descriptions and advisory text are untrusted.**
  - The HTML report embeds its data as JSON with `<` escaped, and renders it with `textContent` and
    `setAttribute`, never `innerHTML`. It loads nothing from the network: no fonts, avatars or
    scripts. `report/html.rs` tests both.
  - The webhook digest neutralises `<` and `>`, and Discord payloads disable mentions.
- **Local files are private.** `~/.stackradar` is `0700`, and reports and state are `0600`, because
  they name the user's projects, their weaknesses and the webhook URL.
- **Every OS compiles every branch.** Use `cfg!(...)` over `#[cfg]` where possible. Windows can't
  be checked from a Mac (`aws-lc-sys` needs the Windows SDK), so rely on CI for Windows.
  - The OS-specific code is in `schedule.rs`, `update.rs`, `platform.rs`, `uninstall.rs` and
    `paths::home()`.

## Releases

- Publishing a release triggers `release-macos.yml`, `release-windows.yml` and `release-linux.yml`,
  which build and upload every asset. The macOS one is a universal tarball merged with `lipo` from
  the `aarch64` and `x86_64` targets. Each workflow can also be run by hand for an existing tag.
- `stackradar update` and `action.yml` download assets by name.
- `stackradar update` refuses an archive that doesn't match its versioned
  `stackradar-<tag>-<platform>.sha256` asset. Every asset, the macOS one included, needs that file.

## Style

- Match the surrounding code: short doc comments that say why, early returns, and `Result<_, String>`
  errors with context.
- Add a test with each behavior change, next to the code it covers.
- Keep CLI help, README.md and this file in step with behavior changes.
