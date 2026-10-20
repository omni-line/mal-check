# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Offline check of lockfiles and manifests against an embedded snapshot of
  OpenSSF malicious-packages (`MAL-`) advisories: 239,358 records from
  `ossf/malicious-packages@349d5c41c1b7`, withdrawn advisories excluded
- Parsers: npm (`package-lock.json` v1–3, `npm-shrinkwrap.json`, `yarn.lock`
  classic and Berry, `pnpm-lock.yaml` v5–v9, `package.json`), PyPI (`poetry.lock`,
  `uv.lock`, `Pipfile.lock`, requirements / constraints files), RubyGems
  (`Gemfile.lock`), NuGet (`packages.lock.json`, MSBuild project files,
  `packages.config`), crates.io (`Cargo.lock`), Go (`go.mod`), Composer
  (`composer.lock`, `composer.json`), VS Code / Open VSX (`.vscode/extensions.json`)
- Version-aware verdicts: `critical` (installed version malicious, or every version),
  `high` (version-specific advisory, unpinned declaration), `low` /
  `previously_compromised` (clean version of a once-hijacked package; summarized,
  not failed, by default)
- Registry-accurate name matching (PEP 503 for PyPI, case and `-`/`_` folding for
  crates.io, case folding for NuGet, Composer, and extensions)
- Text, JSON (`schema_version: 1`), and SARIF 2.1.0 output; `--min-severity`,
  `--fail-on`, `--strict`, `--ignore`, `--exclude`, `--db-info`
- Weekly workflow that rebuilds the snapshot and opens a PR
- Agent skill at `skills/mal-check/SKILL.md`
