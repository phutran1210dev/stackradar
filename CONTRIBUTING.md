# Contributing to Stack Radar

Contributions are welcome: bug reports, ideas, docs and code. You don't need to ask first.

## Reporting a bug or idea

Open an [issue](https://github.com/phutran1210dev/stackradar/issues). For a bug, include
`stackradar --version`, your OS, the command you ran and what you expected. For a wrong
vulnerability result, the ecosystem, package and version help most.

Please report a security problem in Stack Radar itself privately, via
[a security advisory](https://github.com/phutran1210dev/stackradar/security/advisories/new),
not a public issue.

## Sending a change

1. Fork the repo and create a branch from `main`.
2. Make your change. Keep the style of the code around it, and add a test for new behavior
   (tests live next to the code, in `#[cfg(test)]` modules).
3. Run what CI runs, and make sure all three pass:

   ```sh
   cargo fmt --check
   cargo clippy --all-targets --locked -- -D warnings
   cargo test --locked
   ```

4. Open a pull request saying what it changes and why.

[AGENTS.md](AGENTS.md) describes the architecture and the rules the code keeps, for example
that `stackradar audit` only talks to the advisory database and never runs anything from
the projects it reads. It's a good map of the codebase for people too.

By contributing, you agree that your contribution is licensed under the [MIT License](LICENSE).
