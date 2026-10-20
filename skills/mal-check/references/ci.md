# mal-check in CI

Pin the tag from Step 1 (never `latest` in CI), verify the checksum in the job, and
run from the repository root so SARIF paths are repository-relative. Replace `FLAGS`
with the flags agreed in Step 2.

Exit codes: `0` clean, `1` findings at or above `--min-severity`, `2` usage/runtime
error or an incomplete scan with `--strict`.

## GitHub Actions

Detect existing workflows in `.github/workflows/`. Prefer adding a job to the workflow
that already runs on `pull_request`; otherwise create `.github/workflows/mal-check.yml`.

```yaml
name: mal-check

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  mal-check:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # SARIF upload
    env:
      MAL_CHECK_VERSION: v0.1.0
      MAL_CHECK_NO_MARKETING: "1"
    steps:
      - uses: actions/checkout@v4

      - name: Install mal-check
        run: |
          base="https://github.com/omni-line/mal-check/releases/download/${MAL_CHECK_VERSION}"
          curl -fsSLO "$base/mal-check_Linux_x86_64.tar.gz"
          curl -fsSLO "$base/checksums.txt"
          sha256sum --ignore-missing -c checksums.txt
          tar xzf mal-check_Linux_x86_64.tar.gz mal-check

      - name: Malicious package check (SARIF)
        run: ./mal-check --format sarif --fail-on none FLAGS > mal-check.sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: mal-check.sarif
          category: mal-check

      - name: Malicious package check (gate)
        run: ./mal-check --strict FLAGS
```

The SARIF step never fails (alerts show up in code scanning with file/line
annotations; rules `MC001` known malicious package, `MC002` previously compromised
package). The gate step fails the job. Keep both steps **before** any `npm ci` /
`pip install` / `bundle install` in the job: the point is to stop a malicious package
before its install hook runs with the job's secrets. SARIF upload needs GitHub code scanning (public repos, or
GitHub Advanced Security on private ones); if it is unavailable, drop the SARIF and
upload steps and keep the gate.

## GitLab CI

Add a job to `.gitlab-ci.yml`:

```yaml
mal-check:
  stage: test
  image: alpine:3.20
  variables:
    MAL_CHECK_VERSION: v0.1.0
    MAL_CHECK_NO_MARKETING: "1"
  before_script:
    - apk add --no-cache curl
    - base="https://github.com/omni-line/mal-check/releases/download/${MAL_CHECK_VERSION}"
    - curl -fsSLO "$base/mal-check_Linux_x86_64.tar.gz"
    - curl -fsSLO "$base/checksums.txt"
    - grep " mal-check_Linux_x86_64.tar.gz$" checksums.txt | sha256sum -c -
    - tar xzf mal-check_Linux_x86_64.tar.gz mal-check
  script:
    - ./mal-check --strict FLAGS
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

For a machine-readable artifact add `--format json > mal-check.json` and an
`artifacts:` entry with `when: always`.

## Other CI systems

Print the same three steps (download pinned archive + `checksums.txt`, verify,
`./mal-check --strict FLAGS`) as a shell snippet and tell the user where it goes.

## Before you apply

Show the full diff, state which flags it uses and why, and say whether the gate will
pass on the current branch (based on the tuned scan from Step 2). If it will fail, say
which findings the user must fix first, rather than loosening the gate.
