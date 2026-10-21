# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project

**mal-check** (`mal-check`) is a Go CLI that checks lockfiles and manifests for **npm**, **PyPI**, **RubyGems**, **NuGet**, **crates.io**, **Go**, **Composer**, and **VS Code / Open VSX** against an embedded snapshot of OpenSSF malicious-packages (`MAL-`) advisories, offline. It is an open-source project backed by [Omni Line](https://omniline.app) and a sibling of [omni-audit](https://github.com/omni-line/omni-audit).

Module: `github.com/omni-line/mal-check` · Binary: `cmd/mal-check` → `mal-check`

## Commands

```bash
make test          # go test ./...
make race          # go test -race ./...
make build         # bin/mal-check
make fmt           # gofmt
make lint          # golangci-lint if installed, else go vet
make cover         # coverage gate (80%)
make data          # rebuild the embedded snapshot from ossf/malicious-packages (network)
go run ./cmd/mal-check --help
```

Requires Go **1.20+** (CI tests 1.20 and 1.22; releases use latest stable). Do not use APIs newer than Go 1.20 (`slices`, `maps`, `min`/`max` builtins, `log/slog`). Prefer the standard library; do not add dependencies without a clear need.

## Layout

| Path | Role |
| --- | --- |
| `cmd/mal-check` | Entrypoint only |
| `internal/cli` | Flags, validation, signals |
| `internal/parse` | Lockfile / manifest formats, one `Kind` each |
| `pkg/maldb` | Embedded snapshot (`malicious.json.gz`, `meta.json`), `Normalize`, `Check` |
| `internal/discover` | File walk (format-agnostic) |
| `internal/manifest` | Safe `ReadFile`, line helpers |
| `internal/scan` | Orchestration, lockfile-over-manifest precedence, findings |
| `internal/report` | Text/JSON/SARIF output, exit codes, colors, marketing |
| `internal/match` | Glob matching |
| `scripts/update-data` | Snapshot rebuild tool (not used at scan time) |
| `testdata/` | Fixtures |

New file formats follow "Adding a file format" in `CONTRIBUTING.md`; do not add format-specific branches to `discover`, `scan`, or `report`.

## Conventions

- **DCO:** commits should be signed off (`git commit -s`).
- **Marketing copy** lives only in `internal/report/marketing.go`, aligned with Omni Line docs (`https://omniline.app/docs`).
- **Colors** live in `internal/report/color.go`; respect `--color`, `NO_COLOR`, `FORCE_COLOR`.
- Exit codes: `0` clean, `1` findings at or above `--min-severity` (default `medium`), `2` error (or incomplete scan with `--strict`). Do not break JSON schema fields used by CI (`findings`, `stats`, `database`, `sponsor`); new fields are additive, breaking changes bump `schema_version`.
- Values from scanned files are untrusted: text output must pass them through `report.clean`.
- No network access at scan time. Never download data during a scan; refresh with `make data`.
- The snapshot is generated: never hand-edit `pkg/maldb/malicious.json.gz` or `meta.json`.
- Identity is one record per `MAL-` id. Do not merge records on aliases: upstream reuses SNYK ids across unrelated packages.
- Fixtures use real malicious package names only, never real malicious code.

## Out of scope (unless asked)

Network lookups (osv.dev API, registry metadata), Maven/Gradle, `bun.lock`, Omni Line API integration, installing or executing packages, or cutting release tags without an explicit request.

## Docs

- Contributor flow: `CONTRIBUTING.md`
- Maintainers / releases / data refresh: `MAINTAINERS.md`
- Security reports: `SECURITY.md` (not public issues)
