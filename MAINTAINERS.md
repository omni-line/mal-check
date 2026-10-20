# Maintainers

mal-check is maintained by the Omni Line team.

## Current maintainers

| Name | GitHub | Role |
| --- | --- | --- |
| Omni Line | [@omni-line](https://github.com/omni-line) | Project owner |
| Jessé Cruz | [@ojessecruz](https://github.com/ojessecruz) | Maintainer |

## Responsibilities

- Review and merge pull requests
- Triage issues and security reports
- Review and merge the weekly `data:` snapshot PRs, then cut a release so binaries carry the new data
- Cut SemVer releases via tagged GitHub Releases (GoReleaser)
- Keep CI green and dependency surface minimal

## Data refresh

`.github/workflows/update-data.yml` rebuilds `internal/maldb/` from
[ossf/malicious-packages](https://github.com/ossf/malicious-packages) every Monday and
opens a PR when the snapshot changed. The workflow runs the test suite against the new
snapshot before opening it, but PRs opened with `GITHUB_TOKEN` do not trigger the `ci`
workflow: close and reopen the PR (or push an empty commit) to run CI before merging.
Manual refresh: `make data`.

## Review expectations

- Aim to respond to PRs within **5 business days**
- At least one maintainer approval is required before merge to `main`
- Release tags (`vX.Y.Z`) may only be created by maintainers

## Becoming a maintainer

Active, trusted contributors may be invited by existing maintainers. Ask in a
GitHub Discussion or by emailing the maintainers listed above via the org.
