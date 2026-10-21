# Contributing to mal-check

Thanks for helping improve mal-check. This guide covers local setup, how we
review changes, and the Developer Certificate of Origin (DCO).

## Prerequisites

- Go **1.20+** (CI tests 1.20 and 1.22; releases build with the latest stable Go)
- `make` (optional but recommended)
- `golangci-lint` for local linting (CI installs it)

## Setup

```bash
git clone git@github.com:omni-line/mal-check.git
cd mal-check
make test
make build
./bin/mal-check --help
```

## Development workflow

1. Open an issue (or claim an existing one) before large changes.
2. Create a branch from `main`.
3. Keep PRs focused: one concern per PR when practical.
4. Add or update tests for behavior changes.
5. Run:

```bash
make fmt
make lint
make race
```

6. Open a pull request using the template. Fill in the checklist.

### Commit messages

Prefer short, imperative subjects that explain *why*:

```text
parse: skip workspace entries in yarn Berry lockfiles
```

### Developer Certificate of Origin (DCO)

By contributing, you certify that you have the right to submit the work under
the MIT license. Sign off each commit:

```bash
git commit -s -m "your message"
```

This adds a `Signed-off-by:` trailer. See https://developercertificate.org/.

## Project layout

| Path | Role |
| --- | --- |
| `cmd/mal-check` | CLI entrypoint |
| `internal/cli` | Flags, validation, signal handling |
| `internal/parse` | One `Kind` per lockfile / manifest format (the only place file names are known) |
| `pkg/maldb` | Embedded snapshot, name normalization, version matching |
| `internal/discover` | File discovery (format-agnostic) |
| `internal/manifest` | Safe file reads (size cap, FIFO / symlink checks), line helpers |
| `internal/scan` | Orchestration: parse, look up, fold records into findings |
| `internal/report` | Text / JSON / SARIF output, exit codes, marketing |
| `internal/match` | Glob matching for `--ignore` / `--exclude` |
| `scripts/update-data` | Snapshot rebuild from `ossf/malicious-packages` (`make data`); not used at scan time |
| `testdata/project` | Fixture tree used by the README example |

## Adding a file format

1. **Parser:** a `func([]byte) ([]parse.Package, error)` in `internal/parse`. Set
   `Exact` only when `Version` is one concrete installed version. Drop entries that
   never come from the public registry (path, git, workspace).
2. **Registration:** one `Kind` in `parse.Default()` with `Ecosystem`, `Lockfile`,
   `Match`, and `Parse`. Discovery, scanning, and reporting need no changes.
3. **Tests:** a table test in `internal/parse/parse_test.go` (names, versions,
   `Exact`, line numbers) and a `TestClassify` case.

A new **ecosystem** also needs its OSV ecosystem name mapped in
`scripts/update-data` and a `maldb.Normalize` rule matching how that registry
compares names. The ecosystem id becomes part of the JSON schema; do not rename it.

Run `make cover` before opening a PR; CI enforces at least 80% statement coverage.

## Fixtures

Use real malicious package **names** from the snapshot, never real malicious code.
Lockfile fixtures reference names and versions only.

## Code style

- Prefer the standard library; avoid new dependencies unless justified.
- Keep packages under `internal/` unless we intentionally publish a library API.
- User-facing marketing copy lives only in `internal/report/marketing.go`.

## Reporting security issues

Do **not** open a public issue for vulnerabilities. See [SECURITY.md](SECURITY.md).

## Questions

- Bugs and features: GitHub Issues
- False positives or missing malicious packages: [ossf/malicious-packages](https://github.com/ossf/malicious-packages)
- Usage help: [SUPPORT.md](SUPPORT.md)
- Commercial / Omni Line product: https://omniline.app
