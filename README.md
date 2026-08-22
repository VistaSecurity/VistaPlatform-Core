# Vista Platform

**Find every piece of cryptography in your estate, and prove what it is.**

Vista Platform discovers cryptographic assets across your network, builds an
inventory of the certificates, keys, algorithms and configurations actually in
use, tells you which of them a quantum computer will break, and generates a
CycloneDX **Cryptographic Bill of Materials** you can hand to an auditor.

It is a self-hosted platform, not a SaaS. Your inventory never leaves your
infrastructure.

> **Beta — use at your own risk.** Vista Platform is pre-1.0. It discovers,
> assesses and generates a CBOM today, but interfaces, schema and chart values
> change between 0.x releases without notice, there is no guaranteed upgrade
> path, and there is no SLA. **The software is provided "AS IS", without
> warranty of any kind, and is used entirely at your own risk.** Evaluate it
> before you depend on it, and read [DISCLAIMER.md](DISCLAIMER.md) before you
> point it at anything.

---

## Why

Most organizations cannot answer basic questions about their own cryptography:

- Which of our TLS endpoints still negotiate RSA key exchange?
- Where are the certificates that expire during the holiday freeze?
- What breaks the day a cryptographically relevant quantum computer exists?
- Can we produce evidence of any of that for an auditor?

Spreadsheets go stale the day they are written. Scanners tell you about hosts,
not about crypto. Vista Platform is built around the inventory being *current* —
discovery runs continuously, and compliance is evaluated against what is
actually deployed rather than what was documented.

## What it does

**Discovery.** A libpcap-based sensor observes TLS, SSH, SMB and OT/ICS
(Modbus, DNP3, BACnet-SC) handshakes passively, and probes TLS and SSH actively
when you ask it to. *Active* probing of OT/ICS protocols, and the OT-specific
inventory lens, are Enterprise capabilities — Core's passive OT observation and
its full TLS/SSH/SMB pipeline are not gated.
A separate interrogation agent queries network devices (F5, Palo Alto, Cisco,
Fortinet) and cloud providers for their crypto configuration. Both are Go
binaries you deploy inside your own network. Active probing and device
interrogation touch live infrastructure — run them **only against systems you
own or are authorized to assess**, and read the OT/ICS caution in
[DISCLAIMER.md](DISCLAIMER.md#authorized-use-only) first.

**Inventory.** Everything discovered lands in a CMDB-aligned model: assets,
certificates, keys, crypto configurations, and the relationships between them.
Nine lenses reshape the same data — infrastructure, certificates, keys,
configuration, network, third-party connections, stale assets, and TLS/SSH.

**Assessment.** Every algorithm is scored against a maintained catalog:
strength, deprecation status, post-quantum resistance, and NIST security level.
Post-quantum exposure is computed per asset, so "what does Shor's algorithm
break" is a query rather than a research project.

**Compliance.** A rules engine evaluates your inventory continuously against
policy frameworks and materializes findings as things change. Core ships six
frameworks: security best practices, post-quantum readiness, certificate
hygiene, and three certificate-expiry policies.

**CBOM.** Define a *scope* — a named, versioned predicate over your inventory —
and generate an immutable, content-hashed CycloneDX 1.7 cryptographic bill of
materials for exactly that boundary.

## Editions

Vista Platform ships in three editions — **Vista Platform Core** (free and
source-available, this repository), **Vista Platform Enterprise** and **Vista
Platform MSP**. Core is a complete product for a single organization. Nothing
that matters for security is held back: tenant isolation, service-mesh mTLS,
datastore TLS, RBAC, and audit logging are all here, because paywalling
security in a security product is indefensible.

| | Core | Enterprise | MSP |
|---|---|---|---|
| Discovery — sensor, agent, cloud; passive OT/ICS | ✅ | ✅ | ✅ |
| Inventory, CMDB model, all nine lenses | ✅ | ✅ | ✅ |
| Crypto assessment + PQC exposure | ✅ | ✅ | ✅ |
| Compliance engine + 6 frameworks | ✅ | ✅ | ✅ |
| CBOM generation + CycloneDX export | ✅ | ✅ | ✅ |
| Tenant isolation, mTLS, RBAC, audit log | ✅ | ✅ | ✅ |
| Ticketing, notifications, dashboards | ✅ | ✅ | ✅ |
| Regulated frameworks — SOC 2, PCI-DSS, ISO 27001, NIST CSF, IEC 62351-3 | | ✅ | ✅ |
| CBOM evidence — signing, attestation, drift comparison, SPDX/PDF | | ✅ | ✅ |
| SSO — tenant OIDC/SAML, social sign-up, staff SSO | | ✅ | ✅ |
| Custom policies + threshold overrides | | ✅ | ✅ |
| CMDB/ITSM sync — ServiceNow, Device42, SolarWinds | | ✅ | ✅ |
| SIEM forwarding, scheduled audit reports | | ✅ | ✅ |
| White-label branding | | ✅ | ✅ |
| OT/ICS active probing + OT inventory lens | | ✅ | ✅ |
| Multi-tenant management plane, tiering, billing | | | ✅ |

The line is **generation vs. evidence**: Core produces a real CycloneDX CBOM
that your pipeline can consume. Enterprise makes it *audit-grade* — signed,
attested, and diffable against a previous snapshot.

Enterprise and MSP are commercially licensed and sold direct.

## Getting started

On a machine with Kubernetes — including a one-line k3s on a bare VM:

```bash
helm install vista oci://ghcr.io/vistasecurity/vistaplatform \
  --namespace vista --create-namespace --wait
```

No values file. The chart generates its own secrets and a self-signed
certificate on first install, so it comes up without being told anything.

**On a bare k3s VM this needs two prerequisites first** (cert-manager and
Stakater Reloader — internal traffic is mTLS-encrypted by default) or the
install stops with a clear error naming what's missing. See
[**Evaluate it**](INSTALL.md#evaluate-it) in INSTALL.md for the two extra
commands.

Or on a laptop, to look around:

```bash
git clone https://github.com/VistaSecurity/VistaPlatform-Core.git
cd VistaPlatform-Core
./scripts/bootstrap-env.sh     # writes .env with freshly generated secrets
docker compose up -d
```

Web UI on `:3000`, admin console on `:3006`, API gateway on `:8080`. Sign up —
the first account creates the organization.

**[INSTALL.md](INSTALL.md)** covers all three paths — laptop, single VM, and a
real cluster with your own certificates — plus how to verify the images.

## Downloads

Prebuilt sensor and device-agent binaries for Linux, Windows, and macOS,
container images, and the Helm chart are all published on every release — see
**[Downloads in INSTALL.md](INSTALL.md#downloads)** for the OS/arch table and
verification commands. In short:

- **Sensor / device agent**: [latest GitHub release](https://github.com/VistaSecurity/VistaPlatform-Core/releases/latest)
  (the sensor asset is named `crypto-sensor-*`, a historical name — same binary)
- **Container images**: `ghcr.io/vistasecurity/<service>:<version>` — GHCR, not Docker Hub
- **Helm chart**: `oci://ghcr.io/vistasecurity/vistaplatform`

## Architecture

Sixteen Go services behind an API gateway, two React frontends, PostgreSQL 17
with row-level security for tenant isolation, NATS JetStream for events, and
Redis for caching. Service-to-service calls are HMAC-authenticated and can run
over mutual TLS.

- **Go 1.26** — services, sensor, and device agent
- **React 19 + Vite + TypeScript 6** — tenant and admin UIs
- **PostgreSQL 17** — single database, RLS-enforced multi-tenancy
- **Helm** — the supported deployment path

Sensors and agents are standalone cross-platform binaries. They are in this
repository and always will be: you should be able to read the code you are
about to run inside your own network.

## Security

This is a security product, so its own posture is part of the claim.

[![critical CVEs](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FVistaSecurity%2FVistaPlatform-Core%2Fmain%2Fsecurity-scans%2Flatest.json&query=%24.totals.critical&label=critical%20CVEs&color=informational)](security-scans/)
[![high CVEs](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FVistaSecurity%2FVistaPlatform-Core%2Fmain%2Fsecurity-scans%2Flatest.json&query=%24.totals.high&label=high%20CVEs&color=informational)](security-scans/)
[![unscanned images](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FVistaSecurity%2FVistaPlatform-Core%2Fmain%2Fsecurity-scans%2Flatest.json&query=%24.totals.images_not_scanned&label=unscanned%20images&color=informational)](security-scans/)
[![last scanned](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FVistaSecurity%2FVistaPlatform-Core%2Fmain%2Fsecurity-scans%2Flatest.json&query=%24.generated_date&label=last%20scanned&color=informational)](security-scans/)

**[Container scan report](security-scans/)** — every published image is scanned
nightly with Trivy and the result is committed here, findings and all. The
counts cover *fixable* CRITICAL and HIGH findings, and an image that could not
be scanned is reported as unscanned rather than as clean — which is why
"unscanned images" is a badge and not a footnote. A zero CVE count is only
meaningful next to it: zero findings across sixteen of eighteen images is not
the same claim as zero across all eighteen. The "last scanned"
badge is there on purpose: a vulnerability count with no date on it is not
evidence of anything.

**[How the platform is built and shipped](docsv4/core/security-posture.md)** —
tenant isolation through PostgreSQL row-level security, HMAC-signed
service-to-service calls and optional mesh mTLS, the rule that we collect
cryptographic *posture* and never key material, keyless cosign signatures with
SBOM and provenance attestations, and which CI scanners block a merge versus
which are advisory.

**[Reporting a vulnerability](SECURITY.md)** — please do not open a public
issue. That page also lists the design tradeoffs we have knowingly accepted,
including where token revocation fails open and where internal requests have a
replay window, so you can decide whether they matter to you rather than
discovering them yourself.

Verify what you pull — images and the chart are cosign-signed, keylessly, and
logged to Rekor:

```bash
cosign verify ghcr.io/vistasecurity/auth-service:latest \
  --certificate-identity-regexp 'https://github.com/VistaSecurity/VistaPlatform-Core/.github/workflows/release-core.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Contributing

**Not taking code contributions yet** — see [CONTRIBUTING.md](CONTRIBUTING.md)
for why, and for what is genuinely useful in the meantime (bug reports,
documentation corrections). Security issues should **not** go through public
issues — see [SECURITY.md](SECURITY.md).

## License

**Functional Source License 1.1, with an Apache 2.0 future licence**
([FSL-1.1-ALv2](LICENSE.md)). In practice:

- ✅ **Run it for anything you like, including commercially.** Self-host it for
  your own organization, modify it, build it yourself — no fee, no registration,
  no licence key, no phone-home.
- ✅ **Read, fork and patch the source**, including the sensor and agent code
  you deploy inside your own network. You should be able to inspect what you run.
- 🚫 **Don't sell it back to the market** — you can't offer Vista Platform, or
  something substantially similar built from it, to others as a commercial
  product or service. That's what the paid MSP edition is for.
- ⏳ **Every release becomes Apache-2.0 two years after it ships**, automatically
  and irrevocably. You are not betting on our goodwill.

This is *source-available*, not OSI open source, and we would rather say so
plainly than blur the term. The restriction is narrow and deliberate: it stops
someone reselling the work, and nothing else. If you are wondering whether your
use is permitted, it almost certainly is — email
[product@vistasecurity.io](mailto:product@vistasecurity.io) if you want that
in writing.

The licensor is **LakeShore Labs LLC**, which does business as **Vista
Security**.

Vista Platform Enterprise and Vista Platform MSP features are not in this
repository and are licensed commercially. See [NOTICE](NOTICE) for third-party
components.

## Disclaimer — use at your own risk

**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING WITHOUT LIMITATION THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. YOU USE IT
ENTIRELY AT YOUR OWN RISK, AND THE LICENSOR HAS NO LIABILITY TO YOU ARISING OUT
OF OR RELATED TO IT** — see [LICENSE.md](LICENSE.md) for the controlling terms.

In practice, the three things to understand before you run it:

- **You are responsible for where you point it.** The sensor probes actively,
  including OT/ICS, and the interrogation agent authenticates to network devices
  and cloud accounts. Run it only against infrastructure you own or are
  authorized to assess.
- **Compliance output is informational.** It is not an audit, an attestation, a
  certification, or legal advice. No affiliation with or endorsement by the PCI
  SSC, AICPA, ISO, NIST, IEC or any named vendor is claimed or implied.
- **Discovery is best-effort.** An empty result means nothing was found, never
  that nothing is there.

[**DISCLAIMER.md**](DISCLAIMER.md) covers all of this in full.
