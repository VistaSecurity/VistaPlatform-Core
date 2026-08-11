---
render_macros: false
---

# Releases & Versioning

How VistaPlatform Core releases are versioned, what they contain, and how to
verify them.

## Versioning

Releases follow [Semantic Versioning](https://semver.org/) (`vMAJOR.MINOR.PATCH`).
For any given release the version is identical across:

- the git tag (e.g. `v0.2.0`),
- the Helm chart `version` and `appVersion`, and
- every service container image tag.

So a chart at `0.2.0` always runs the `v0.2.0` images — there is no skew to
reason about.

## What a release contains

Each release is published as signed, attested artifacts on GHCR:

- **The Helm chart** — `oci://ghcr.io/vistasecurity/vistaplatform:<version>`.
  Built from this source, unobfuscated.
- **Service images** — `ghcr.io/vistasecurity/<service>:<version>`, each
  cosign-signed (keyless OIDC) with a CycloneDX SBOM attached as an attestation.
- **Sensor and device-agent binaries** — prebuilt for multiple OSes and
  architectures, attached to the GitHub Release along with a signed
  `SHA256SUMS`.

Install and upgrade from the **published OCI chart**, never from the
repository.

## Release notes

- **Changelog:** [`CHANGELOG.md`](../../../CHANGELOG.md) at the repo root carries a
  section per version (Keep a Changelog format).
- **GitHub Releases:** every release is published on the repository it was built
  from, with the changelog section as its notes. This is generated automatically
  by the release pipeline, so it never drifts from the changelog.

## Verify a release

Signing is keyless: there is no key to trust, because the signing identity *is*
the release workflow. That means the registry and the identity both depend on
which edition you installed — so rather than guessing, **use the command
`helm install` printed at the end of its output.** The chart fills in the
registry, the version and the signing identity for the artifact you actually
have.

For Core, that command is:

```bash
cosign verify ghcr.io/vistasecurity/vistaplatform:<chart-version> \
  --certificate-identity-regexp 'https://github.com/VistaSecurity/VistaPlatform-Core/.github/workflows/release-core.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Substitute a service image ref (e.g. `ghcr.io/vistasecurity/auth-service:<version>`)
to verify an image with the same identity.


## Upgrading

See the RKE2 deployment guide's **Upgrade** section for cross-version upgrade
mechanics (`--reset-then-reuse-values`, schema-migration/seed Jobs, single-node
surge caveats). The chart's `NOTES.txt` echoes the key upgrade flags on every
`helm upgrade`.

## Where documentation lives

- **Tenant-facing capabilities:** `docsv4/core/`
- **Deployment and operations:** `docsv4/core/operate/`
