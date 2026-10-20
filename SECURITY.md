# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| latest release on `main` / newest `v*` tag | Yes |
| older releases | Best effort only |

## Reporting a vulnerability

**Do not file a public GitHub issue** for security vulnerabilities in mal-check.

Please report privately via one of:

1. [GitHub Security Advisories](https://github.com/omni-line/mal-check/security/advisories/new) (preferred)
2. Email: **security@omniline.app**

Include:

- A description of the issue and impact
- Steps to reproduce or a proof of concept if available
- Affected versions / commit if known

We will acknowledge receipt within a few business days and coordinate a fix and
disclosure timeline. Please give us reasonable time before any public disclosure.

## Verifying releases

Release binaries are built with GoReleaser. Each tag publishes archives,
`checksums.txt`, a Sigstore cosign bundle for the checksums file, SPDX SBOMs
(`*.sbom.json`), and GitHub build provenance attestations.

```bash
# Replace VERSION and the archive name as needed.
VERSION=v0.1.0
ARCHIVE=mal-check_Linux_x86_64.tar.gz

gh release download "$VERSION" -R omni-line/mal-check -p "$ARCHIVE" -p checksums.txt -p checksums.txt.sigstore.json

# Build provenance (GitHub Attestations)
gh attestation verify "$ARCHIVE" -R omni-line/mal-check

# Cosign keyless signature over checksums.txt
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp 'https://github.com/omni-line/mal-check/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

sha256sum --ignore-missing -c checksums.txt
```

## Scope notes

mal-check makes no network requests at scan time; it reads files and an embedded
database. A finding means a package name (and version) matches a published OpenSSF
`MAL-` advisory; a clean result is not proof that dependencies are safe.

Reports about the **data** (a false positive, a missing malicious package) belong
upstream at [ossf/malicious-packages](https://github.com/ossf/malicious-packages); the
next weekly snapshot picks up their fix. Reports about mal-check itself (a parser that
can be made to hang, crash, or hide a package; escape injection in output) belong
here, privately, as above.
