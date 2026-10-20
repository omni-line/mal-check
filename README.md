# mal-check

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/omni-line/mal-check/actions/workflows/ci.yml/badge.svg)](https://github.com/omni-line/mal-check/actions/workflows/ci.yml)
[![Powered by Omni Line](https://img.shields.io/badge/Powered%20by-Omni%20Line-FF4B4B?style=flat)](https://omniline.app/)

**mal-check** is a fast, zero-config, offline CLI that tells you whether any package in your project was **published to a public registry as malware**. It reads your lockfiles and manifests for npm, PyPI, RubyGems, NuGet, crates.io, Go, Composer, and VS Code / Open VSX extensions, and checks every package and version against an embedded snapshot of the **239,358** [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) (`MAL-`) advisories.

It's a single static Go binary with no Node, Python, or Ruby runtime and no network calls. Nothing leaves the machine.

Sibling to [omni-audit](https://github.com/omni-line/omni-audit), which covers dependency confusion, typosquats, and shadow registries.

## The problem

Vulnerability scanners (`npm audit`, Dependabot, `pip-audit`) answer "is this version of a legitimate package vulnerable?". They don't answer "is this package malware?". That covers two cases:

- **Throwaway malware names.** Info-stealers, crypto drainers, and probe packages are published by the thousand and installed through typos, AI-suggested names, and copy-pasted commands. Every version is malicious.
- **Hijacked legitimate packages.** `nx`, `chalk`, `debug`, `axios`, and `@oku-ui/presence` all had specific releases pushed from a compromised maintainer account. Only those versions are malicious.

In both cases the payload runs in an install hook, before any test or review. If one of these is in your lockfile, the question isn't "should we upgrade?". It's "which secrets did that machine have?".

Detection is the first step. [Omni Line](https://omniline.app) is the durable fix: a self-hosted registry that proxies npm, PyPI, RubyGems, NuGet, and more, and blocks `MAL-` packages at install time.

## Install

### Prebuilt binaries

Download the latest release from
[GitHub Releases](https://github.com/omni-line/mal-check/releases).
See [SECURITY.md](SECURITY.md#verifying-releases) for cosign, attestation, and
checksum verification commands.

### From source

Requires Go 1.20+:

```bash
go install github.com/omni-line/mal-check/cmd/mal-check@latest
```

Or clone and build:

```bash
git clone https://github.com/omni-line/mal-check.git
cd mal-check
make build
./bin/mal-check --help
```

### With an AI agent

Paste this into Claude Code, Codex, or Cursor at the repository root:

```text
Read https://raw.githubusercontent.com/omni-line/mal-check/main/skills/mal-check/SKILL.md and follow it to set up mal-check for this repository.
```

## Quick start

```bash
# Check the current directory
mal-check

# Check a path, or a single lockfile
mal-check ./apps/web
mal-check ./services/api/poetry.lock

# JSON for CI
mal-check --format json --no-marketing

# SARIF for GitHub code scanning
mal-check --format sarif > mal-check.sarif

# Also list clean versions of once-hijacked packages
mal-check --min-severity low -v
```

Example output, from `testdata/project` in this repository:

```text
mal-check v0.1.0 — Malicious package check
Backed by Omni Line — one registry for every package your team ships

✗ 5 known malicious packages found (6 occurrences)

  SEVERITY  ECOSYSTEM  PACKAGE                 VERSION   LOCATION                   ADVISORY         NOTE
  critical  cargo      proc-macro1             1.0.95    rs/Cargo.lock:4            MAL-2026-14338   installed version is malicious
  critical  npm        @oku-ui/presence        0.6.2     web/package-lock.json:7    MAL-2025-191265  installed version is malicious
  critical  pypi       Torchflow_Experimental  0.3.0     py/requirements.txt:4      MAL-2025-191907  installed version is malicious
  critical  rubygems   turboscan-client        99.99.99  rb/Gemfile.lock:5          MAL-2025-46946   installed version is malicious
  high      pypi       torchflow-experimental  >=0.1     py/requirements.txt:3      MAL-2025-191907  version not pinned; some versions malicious
  high      vscode     checkmarx.ast-results   -         .vscode/extensions.json:5  MAL-2026-2231    version not pinned; some versions malicious

These packages were published to a public registry as malware (OpenSSF MAL-
advisories). Install hooks run on `npm install` / `pip install`, so a machine
that installed one may already have leaked its environment variables and tokens.

How to fix
  malicious    Remove the package, delete node_modules / virtualenvs / caches, and reinstall from a clean lockfile. If it ran on a machine or in CI, treat that environment as compromised: rotate every secret and token it could read.

1 finding below --min-severity not listed (packages that shipped malicious releases before; your versions are not among them). Use --min-severity low to list them.

Scanned 7 files (3 lockfiles) · 12 packages (11 unique) · 7 findings · 3 skipped · 0 errors in 2ms
Database: 239,358 known malicious packages (OpenSSF, 2026-10-20)
```

## Severities

| Severity | Meaning | Fails the build by default |
| --- | --- | --- |
| `critical` | The installed version is malicious, or every version of the package is | yes |
| `high` | Some versions are malicious and yours isn't pinned (a range in `package.json`, an unpinned requirement), so an install may resolve to one | yes |
| `low` | The package shipped malicious releases before (for example after an account takeover) and your locked version is not one of them | no; summarized in one line, not listed |

`low` findings aren't noise, but they are numerous. On a typical monorepo, hundreds of lockfile entries are clean versions of `chalk`, `debug`, or `ansi-styles` from the September 2025 hijack. Use `--min-severity low` to list them and fail on them.

## How it works

1. Walks the tree for supported files. It skips `node_modules`, `vendor`, `target`, `.venv`, `.git`, `dist`, `build`, and other dependency and cache dirs, plus anything matched by `--exclude`.
2. Parses every supported file:

   | Ecosystem | Lockfiles (installed versions) | Manifests (declared ranges) |
   | --- | --- | --- |
   | npm | `package-lock.json`, `npm-shrinkwrap.json` (v1–3), `yarn.lock` (classic and Berry), `pnpm-lock.yaml` (v5–v9) | `package.json` |
   | PyPI | `poetry.lock`, `uv.lock`, `Pipfile.lock` | `requirements*.txt`, `constraints*.txt`, `requirements/*.txt` |
   | RubyGems | `Gemfile.lock` | |
   | NuGet | `packages.lock.json` | `*.csproj`, `*.fsproj`, `*.vbproj`, `Directory.Packages.props`, `packages.config` |
   | crates.io | `Cargo.lock` (registry sources only) | |
   | Go | | `go.mod` |
   | Composer | `composer.lock` | `composer.json` |
   | VS Code / Open VSX | | `.vscode/extensions.json` |

3. Normalizes each name the way its registry compares names: PEP 503 for PyPI, case and `-`/`_` folding for crates.io, case folding for NuGet, Composer, and extensions. `Torchflow_Experimental` and `torchflow-experimental` are the same package.
4. Checks each package against the embedded snapshot and compares the installed version with the advisory's affected versions and ranges.
5. Lockfiles win. A `package.json` declaration of a package that a lockfile already pins is skipped, because the lockfile says what is actually installed.

### The database

The snapshot is built from `osv/malicious/**` of
[ossf/malicious-packages](https://github.com/ossf/malicious-packages) (Apache-2.0)
by `scripts/update-data`. It is one record per `MAL-` id, packed into ~2.8 MB of gzip inside the binary.
A [weekly workflow](.github/workflows/update-data.yml) rebuilds it and opens a PR.
`mal-check --db-info` prints the upstream commit a binary was built from.

- **Withdrawn advisories are excluded.** `osv/withdrawn/` holds false positives; a snapshot where every record means "malware" must not carry them.
- **Mass campaigns are labeled.** About 59% of records are tea.xyz token-farming spam on npm. They are still blocked packages, and findings carry `campaign: "tea-xyz-token-farming"`.
- **No completeness claim.** A package that is absent from the snapshot is not proven safe. It may be unreported, reported after the snapshot was built, or not yet analyzed.

### Security properties

- No network access at scan time. The database is embedded.
- Files are read with a 64 MiB cap. FIFOs and devices are rejected before open, and symlinks that resolve outside the scan root are skipped.
- Values from scanned files are escaped before being printed, so a crafted lockfile can't inject terminal escape sequences.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No findings at or above `--min-severity` (or `--fail-on none`) |
| `1` | One or more findings at or above `--min-severity` (default `medium`) |
| `2` | Usage or runtime error, or an incomplete scan with `--strict` |

### Flags

| Flag | Description |
| --- | --- |
| `--format text\|json\|sarif` | Output format (default `text`) |
| `--min-severity low\|medium\|high\|critical` | Lowest severity listed in text and SARIF and that fails the build (default `medium`). JSON always carries every finding |
| `--fail-on any\|none` | Whether findings fail the process |
| `--strict` | Exit `2` if any lockfile or manifest could not be read or parsed |
| `--ignore` | Skip package name globs (repeatable / comma-separated) |
| `--exclude` | Skip paths: directory/file names or globs relative to the scan root |
| `--db-info` | Print the embedded database's upstream commit and size |
| `-q` / `--quiet` | Findings table only; no banner, warnings, summary, or marketing |
| `--no-marketing` | Hide Omni Line CTA / JSON `sponsor` |
| `--marketing` | Force marketing even when non-TTY |
| `--color auto\|always\|never` | ANSI colors (default `auto` on TTY) |
| `-v` / `--verbose` | Show advisory URLs, finders, and malicious versions |
| `--version` | Print version |

### JSON output

```json
{
  "schema_version": 1,
  "version": "v0.1.0",
  "complete": true,
  "findings": [
    {
      "ecosystem": "cargo",
      "package": "proc-macro1",
      "version": "1.0.95",
      "exact": true,
      "manifest": "rs/Cargo.lock",
      "line": 4,
      "reason": "malicious",
      "severity": "critical",
      "ids": ["MAL-2026-14338"],
      "url": "https://osv.dev/vulnerability/MAL-2026-14338",
      "finders": ["SafeDep", "jhobern"],
      "published": "2026-08-20",
      "remediation": "Remove the package, delete node_modules / virtualenvs / caches, and reinstall from a clean lockfile. ..."
    }
  ],
  "stats": { "files": 7, "lockfiles": 3, "packages": 12, "unique_packages": 11, "findings": 7, "skipped": 3, "errors": 0, "duration_ms": 2 },
  "database": {
    "generated_at": "2026-10-20T20:33:01Z",
    "source": "https://github.com/ossf/malicious-packages",
    "commit": "349d5c41c1b78dcece775455353694a7b37ae07a",
    "license": "Apache-2.0",
    "records": 239358
  }
}
```

`reason` is `malicious` or `previously_compromised`. `complete` is `false` when any file could not be read or parsed (see `warnings[]`). New fields may be added; breaking changes bump `schema_version`. JSON includes an optional top-level `sponsor` object unless you pass `--no-marketing` or `-q`.

Environment:

- `MAL_CHECK_NO_MARKETING=1`: same as `--no-marketing` (handy in CI)
- `NO_COLOR=1`: disable colors ([no-color.org](https://no-color.org))
- `FORCE_COLOR=1`: enable colors when not a TTY

## CI example

```yaml
- name: Malicious package check
  run: |
    curl -sL https://github.com/omni-line/mal-check/releases/latest/download/mal-check_Linux_x86_64.tar.gz | tar xz
    ./mal-check --format json --no-marketing --strict
```

GitHub code scanning (findings appear as alerts with file and line annotations):

```yaml
- name: Malicious package check
  run: ./mal-check --format sarif --fail-on none > mal-check.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mal-check.sarif
```

Run from the repository root so SARIF paths are repository-relative. Run it **before** `npm ci` / `pip install` in the job, so a malicious package is caught before its install hook gets the runner's secrets.

## Roadmap

- `pom.xml` / Gradle, `bun.lock`, `Package.resolved`, `pubspec.lock`
- `--db <file>` to check against a fresher snapshot without a new release
- `pkg/` library API so omni-audit can report `reason=malicious` from the same data

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [MAINTAINERS.md](MAINTAINERS.md), and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Security reports: [SECURITY.md](SECURITY.md).

## License

Code: [MIT](LICENSE) · Copyright Omni Line and contributors.
Embedded database: derived from [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages), [Apache-2.0](LICENSES/Apache-2.0.txt). See [NOTICE](NOTICE).

---

<div align="center">
  <a href="https://omniline.app/">
    <img src="https://omniline.app/omni-line-icon.png" alt="Omni Line" width="120">
  </a>
  <p><b>mal-check</b> is built and maintained by <a href="https://omniline.app/"><b>Omni Line</b></a> — one self-hosted registry for every package your team ships.</p>
</div>
