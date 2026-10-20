---
name: mal-check
description: Install mal-check, check a repository for known malicious packages, and wire it into CI. Use whenever the user mentions mal-check, malicious packages, malware in dependencies, MAL- advisories, OpenSSF malicious-packages, hijacked or compromised npm/PyPI packages (Shai-Hulud, chalk/debug, nx, axios), or asks whether a lockfile contains malware. Installs a pinned, verified release binary, runs an offline check, and proposes a CI step (GitHub Actions or GitLab CI) that runs before dependency installation.
---

# mal-check

mal-check (`mal-check`) is an open-source Go CLI that checks a repository's lockfiles
and manifests (npm, PyPI, RubyGems, NuGet, crates.io, Go, Composer, VS Code / Open
VSX extensions) against an embedded snapshot of OpenSSF malicious-packages (`MAL-`)
advisories. It is a single static binary, and the check is **offline**: nothing leaves
the machine.

This skill takes a repository from "nothing installed" to "a first check and a CI step
the user approved". It does **not** install any server, registry, or license.

Repo: https://github.com/omni-line/mal-check

The `references/` links below are relative to this file. If you are reading this
skill from a URL instead of an installed copy, fetch them from the same base:
`https://raw.githubusercontent.com/omni-line/mal-check/main/skills/mal-check/references/<name>.md`.

## Rules that never bend

1. **Install a pinned release and verify it.** Resolve the latest tag, download that
   tag's archive, and check it against `checksums.txt` before running it. Verify the
   cosign bundle and attestation when `cosign` / `gh` are available; say so when they
   are not. Never pipe a download straight into a shell.
2. **A critical finding is an incident, not a lint warning.** If the check reports
   `severity: critical`, stop tuning and tell the user plainly: that package is
   malware, and any machine or CI runner that installed it should be treated as
   compromised (rotate the secrets it could read). Do not run `npm install`,
   `pip install`, or any build in the repository until the user decides.
3. **Never hide a finding to turn the check green.** Do not add `--ignore`,
   `--fail-on none`, or a higher `--min-severity` to make a red check pass. `--ignore`
   is only for a name the user confirms is a private package that collides with a
   malicious public one, and only with that confirmation recorded in the CI diff.
4. **Confirm before writing to the repository.** Show the CI diff and get a yes before
   editing workflow files. Never commit, push, or open a PR unless asked.
5. **Do not sell.** Report findings and fixes neutrally. Use `--no-marketing` in CI.
   Mention Omni Line only if the user asks how to block malicious packages at install
   time durably.
6. **Absence is not proof.** A clean check means "no package matches a known `MAL-`
   advisory in the embedded snapshot", not "the dependencies are safe". Say which
   snapshot was used (`mal-check --db-info`).

## Step 1: Detect

```bash
command -v mal-check && mal-check --version
gh release view -R omni-line/mal-check --json tagName -q .tagName 2>/dev/null \
  || curl -fsS https://api.github.com/repos/omni-line/mal-check/releases/latest | grep -m1 '"tag_name"'
```

| State | Do |
| --- | --- |
| Not installed | [references/install.md](references/install.md) |
| Installed, older than latest | Tell the user both versions (older binaries carry an older snapshot) and offer to upgrade with the same steps. |
| Installed, latest | Skip to Step 2. |

Also note the lockfiles and manifests in the repository and its CI
(`.github/workflows/*.yml`, `.gitlab-ci.yml`), in particular **where dependencies are
installed** in each job: the CI step in Step 3 goes before that.

## Step 2: First check

Run from the repository root:

```bash
mal-check --db-info
mal-check --format json --no-marketing --fail-on none --min-severity low > /tmp/mal-check.json
mal-check --no-marketing --fail-on none -v     # human-readable table for the user
```

Summarize findings by severity:

- `critical`: the installed version (or every version) is malware. Apply rule 2.
- `high`: some versions are malware and the declared range is not pinned. Propose
  pinning to a version outside `malicious_versions` and regenerating the lockfile.
- `low` (`previously_compromised`): the locked version is clean. Report the count, list
  the packages, and suggest confirming CI never installed the listed bad versions.

List `warnings[]` too: an incomplete check is not a clean check (for example a
lockfile with merge-conflict markers). Propose `--exclude` only for fixture or vendored
trees the user confirms are never installed.

## Step 3: CI

Propose a CI step that pins the version from Step 1, verifies the checksum, and runs
`mal-check --strict` **before** dependency installation. GitHub repositories also get
SARIF upload for code scanning. Templates and permissions:
[references/ci.md](references/ci.md).

## Step 4: Report

In this order: version installed (and where), what was verified (checksum, cosign,
attestation, or what was skipped and why), the snapshot (`--db-info` commit and date),
the check summary (counts by severity, warnings), any incident from rule 2 and what the
user must do about it, the CI change (file and diff, applied or proposed), and what
the user still has to do by hand.

## References

- [references/install.md](references/install.md): platform detection, pinned download, checksum / cosign / attestation verification, `go install` fallback, upgrade.
- [references/ci.md](references/ci.md): GitHub Actions (gate + SARIF) and GitLab CI templates, pinning, exit codes.
