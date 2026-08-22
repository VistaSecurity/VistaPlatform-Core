# How Vista Platform is Built and Shipped

Vista Platform inventories other people's cryptography. That makes this
repository's own security posture part of the product claim rather than a
footnote to it — a crypto-inventory tool that leaks its own inventory has
inverted its purpose.

This page describes the practices behind the code, in enough detail to check.
Where a claim is enforced by something automated, the enforcing mechanism is
named so you can go read it. Where something is a deliberate weakness we accept,
it is in [SECURITY.md](../../SECURITY.md#known-design-tradeoffs) rather than
here, because a posture page that only lists strengths is marketing.

## Tenant isolation

The platform is multi-tenant, and tenant separation is enforced in the database
rather than in application code.

Every tenant-scoped table carries a PostgreSQL **row-level security** policy
keyed on `current_setting('app.tenant_id')`. Services connect as a role that
RLS applies to, and set the tenant on the transaction. A query that forgets its
tenant filter returns nothing rather than returning another tenant's rows — the
failure mode is an empty result, not a leak.

That choice has a cost worth stating: it means a service which acquires a
connection without setting the tenant sees an empty database, and that has
broken features during development. We consider a self-inflicted empty screen
much the better failure than a cross-tenant read, and cross-tenant access is the
highest-severity bug class in our [security policy](../../SECURITY.md#scope).

## Service-to-service authentication

Internal calls between services are signed with **HMAC-SHA256** over the request
method, path, query, body hash, timestamp and tenant. An unsigned or
badly-signed internal call is rejected.

Signing alone leaves a replay window, which is documented as a known tradeoff
in [SECURITY.md](../../SECURITY.md#known-design-tradeoffs) rather than glossed:
the nonce is signed entropy, not a recorded dedup key, so a captured internal
request can be replayed until its timestamp ages out of the clock-skew window.

The mitigation we recommend and run ourselves is the chart's **service-mesh
mTLS**, an opt-in mode that puts every in-cluster hop behind mutual TLS using a
private, cert-manager-provisioned platform CA with 90-day auto-rotating
per-service certificates. It is independent of your browser-facing certificate,
and it composes with two further toggles that require TLS on the PostgreSQL and
NATS connections. See
[Service-mesh mTLS](./operate/security/service-mesh-mtls.md).

## Collect posture, never key material

This is the design rule we are most deliberate about, because it is the one
where a crypto-inventory product can do real damage.

**We inventory which algorithms a device uses, not the keys it uses them with.**
Storing key material would make the inventory database a more attractive target
than the devices it describes — you would be concentrating every secret in the
estate into one place in order to report on them.

It is enforced in three layers, in order of preference:

1. **Don't retrieve it.** Device interrogation asks narrow questions. Cisco
   configuration is read with `show running-config | include ssl cipher` rather
   than a section query, because the section form returns pre-shared keys on
   lines we never parse.
2. **Don't collect it.** Vendor API responses are projected onto an explicit
   allowlist of fields something actually reads, rather than being stored
   wholesale. This is not theoretical — see the note below.
3. **Backstop.** Every interrogator is wrapped in a redaction pass that strips
   by field name, with crypto-posture names such as key size and public key
   explicitly marked safe so the redactor does not eat the actual product data.

We also do not store whole command transcripts or unbounded pattern-matched
configuration, because a pattern cannot tell you what it will match on a vendor
firmware version nobody has seen yet.

Projection tests accompany each collector, and they are mutation-tested — the
test is verified to fail when the protection is removed.

### The over-collection this rule came from — affects v0.5.0–v0.5.6

We would rather you hear this from us, with versions attached, than infer it from
the shape of the rule above.

The UniFi collector assigned the controller's API response object directly into a
metadata field instead of projecting it. Everything the controller returned was
therefore stored on every collection run — including the site's **mesh PSK**,
per-device auth keys, the syslog key, the configured **SMTP relay password**, and
the operator's email address. Roughly 350 KB per run that nothing ever read.

| | |
|---|---|
| **Affected releases** | **v0.5.0 – v0.5.6** (published 2026-08-11 to 2026-08-12) |
| **Fixed in** | **v0.5.7**, 2026-08-13 |
| **Scope** | The UniFi collector only. Other vendors' collectors were already projected or returned typed structs. |

**What it was, precisely:** over-collection into *your own* database, not
transmission anywhere. The values were written to `device_jobs.results` and
`discovery_findings.details` in the Postgres instance you run. Nothing was sent
off-box, and no Vista Security-operated system ever held them — this platform is
self-hosted and we do not receive your data.

**If you ran v0.5.0–v0.5.6 against a UniFi controller,** those rows may still be
in your database and in any backup taken during that window. Upgrading does not
remove data already written. Consider purging the affected `device_jobs.results`
and `discovery_findings.details` rows from that period, and rotating any UniFi
mesh PSK, syslog key or SMTP relay credential that was configured on the
controller at the time.

The fix ([`d3bce648`](https://github.com/VistaSecurity/VistaPlatform-Core)) added
the field projection, and the mutation-tested projection tests above exist so
this specific failure cannot recur silently.

## Credentials at rest

Integration credentials, device credentials and the sensor CA are encrypted at
rest with a key derived through HKDF from a master key supplied at deploy time
and never stored in the repository.

## Authentication and authorization

- Browser sessions use **httpOnly cookies**, not browser-readable storage.
- Tenant permissions are RBAC, and the permission catalogue is **generated from
  a single source of truth** (`standards/permissions.yaml`) into the database
  seed, the Go constants, the TypeScript constants and the audit's expectations.
  A build-time audit fails on any drift between them, so a permission cannot
  exist in one layer and be silently missing from another.
- Feature entitlements are a separate axis from permissions, and a check that a
  feature is licensed is not a substitute for a check that the user may use it.

Note the boundary we deliberately do **not** defend: edition gating is a
commercial boundary backed by a licence agreement, not a security control, and
it is not designed to resist an operator with source access. That is stated in
the [security policy's out-of-scope list](../../SECURITY.md#scope) so nobody
spends a weekend on it expecting a bounty.

## Supply chain

Everything published is signed, and everything signed is verifiable without
trusting us to hold a key.

| | |
|---|---|
| **Image signing** | Keyless [cosign](https://github.com/sigstore/cosign) via Fulcio, logged to the Rekor transparency log. The signing identity is the release workflow's OIDC token, so what you verify is "built by that workflow in that repository" — there is no long-lived private key to steal. |
| **SBOM** | Every image carries a CycloneDX SBOM attestation, generated at build time. |
| **Build provenance** | Images are built with SLSA provenance in `max` mode. |
| **Chart signing** | The Helm chart is signed and attested the same way. |
| **Binary signing** | Sensor and agent binaries are checksummed into a `SHA256SUMS` file which is itself cosign-signed. |
| **Base images** | Backend services in the official builds start from [Docker Hardened Images](https://www.docker.com/products/hardened-images). Rebuilt from source without a Docker Hub subscription they fall back to the public `alpine` bases the Dockerfiles default to, so anyone can reproduce a tag without paying for one. The two web UIs are the exception: they run on the upstream `caddy:2-alpine` image, which is not a hardened base — and that is where the scan report's findings are concentrated. |
| **Action pinning** | Every third-party GitHub Action is pinned to a commit SHA, and a check verifies each pinned SHA actually **exists** — see below. |

### Why the pin check verifies existence

A SHA is opaque by design: it looks equally correct whether or not it resolves.
Our release pipeline once carried a pin whose first 24 characters matched a real
commit and whose tail was invented. Nothing in the repository could tell the
difference, and GitHub only discovers it when a runner tries to resolve the
action — so it failed most of a release build and not one moment earlier.

It fails closed, which is the one mercy, since an unresolvable action cannot
execute. But the lesson generalizes past that bug: a check that can only compare
a string to itself is not a check. `scripts/verify-action-pins.sh` asks the
GitHub API whether each commit exists, and refuses to pass quietly when it
cannot reach the API at all.

## Continuous scanning

Every pull request and every night, several independent scanners run against the
source and the published artifacts.

| Scanner | What it looks at | When | Gating |
|---|---|---|---|
| **govulncheck** | Go CVEs the code actually *calls*, not merely depends on | every PR | **blocks the merge** |
| **Gitleaks** | committed secrets | every PR + nightly | **blocks the merge** |
| **npm audit** | frontend production dependencies | nightly | **blocks** at HIGH and above |
| **gosec** | Go static analysis | nightly | advisory |
| **Trivy (filesystem)** | dependency manifests in the source tree | nightly | advisory |
| **Trivy (config)** | Dockerfiles and compose files | nightly | advisory |
| **Trivy (image)** | the **published container images** | nightly | advisory, published |
| **Secret scanning + push protection** | GitHub-native, on the public repository | on push | **blocks the push** |

The distinction between the dependency scanners is deliberate. `govulncheck`
gates because it reports *reachable* vulnerabilities — a CVE in a function the
binary never calls is not a reason to stop a release, and a gate that fires on
unreachable findings gets switched off within a month. The advisory scanners
cast a wider net and are read rather than obeyed.

### The published image scan

The nightly image scan is the one whose results we publish:
**[security-scans/](https://github.com/VistaSecurity/VistaPlatform-Core/tree/main/security-scans)**
in the public repository, refreshed every night against the current release
images.

Two things about how it reports, both learned the hard way:

- **An image that was not scanned is reported as "not scanned", never as
  clean.** The predecessor of this workflow pointed at a registry reference that
  did not resolve, and so scanned nothing at all for roughly ten weeks. It said
  so in its logs every single week. A report that rendered a missing scan as a
  zero would have converted that outage into a published claim of safety, which
  is far worse than publishing nothing.
- **The counts are fixable CRITICAL and HIGH only.** Findings with no upstream
  fix are excluded because they are not actionable by upgrading. A zero there
  does not mean zero known CVEs, and the report says so on its face.

You do not have to take the number on trust. The images are public and the scan
is one command:

```bash
trivy image --ignore-unfixed --severity CRITICAL,HIGH \
  ghcr.io/vistasecurity/auth-service:latest
```

## Guards are mutation-tested

A recurring theme across the items above is that **a check which cannot fail is
worse than no check**, because it reports the work it did not do. We have hit
this enough times to make it a practice: when a guard is added, it is verified
by breaking the thing it guards, confirming the guard fails, then restoring and
confirming it passes — in both directions, because an over-strict guard that
rejects a correct setup is the same bug pointed the other way.

Some specific instances that produced this rule:

- A string rewrite that matches nothing returns its input and says nothing, so
  every rewrite in the public-tree export now **asserts** that it matched.
- `git ls-remote` succeeds against a public repository with a garbage
  credential, because git falls back to anonymous — so credential preflight uses
  the REST API, which returns 401.
- `curl -k` validates nothing, and reported HTTP 200 for hours while the ingress
  was serving a certificate for the wrong hostname.
- jq's `//` operator treats `false` as empty, silently converting an explicit
  "no" into "unknown".

## Reporting a vulnerability

Privately, through GitHub Security Advisories or email — see
**[SECURITY.md](../../SECURITY.md)** for the process, the response times we
commit to, what is in and out of scope, and the design tradeoffs we have
knowingly accepted.

Please do not open a public issue for a vulnerability.
