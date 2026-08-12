# VistaPlatform

**Find every piece of cryptography in your estate, and prove what it is.**

VistaPlatform discovers cryptographic assets across your network, builds an
inventory of the certificates, keys, algorithms and configurations actually in
use, tells you which of them a quantum computer will break, and generates a
CycloneDX **Cryptographic Bill of Materials** you can hand to an auditor.

It is a self-hosted platform, not a SaaS. Your inventory never leaves your
infrastructure.

---

## Why

Most organizations cannot answer basic questions about their own cryptography:

- Which of our TLS endpoints still negotiate RSA key exchange?
- Where are the certificates that expire during the holiday freeze?
- What breaks the day a cryptographically relevant quantum computer exists?
- Can we produce evidence of any of that for an auditor?

Spreadsheets go stale the day they are written. Scanners tell you about hosts,
not about crypto. VistaPlatform is built around the inventory being *current* —
discovery runs continuously, and compliance is evaluated against what is
actually deployed rather than what was documented.

## What it does

**Discovery.** A libpcap-based sensor observes TLS, SSH, and SMB handshakes
passively, and probes actively when you ask it to — including OT/ICS protocols.
A separate interrogation agent queries network devices (F5, Palo Alto, Cisco,
Fortinet) and cloud providers for their crypto configuration. Both are Go
binaries you deploy inside your own network.

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

Core is a complete product for a single organization. Nothing that matters for
security is held back: tenant isolation, service-mesh mTLS, datastore TLS,
RBAC, and audit logging are all here, because paywalling security in a security
product is indefensible.

| | Core | Enterprise | MSP |
|---|---|---|---|
| Discovery — sensor, agent, cloud, OT | ✅ | ✅ | ✅ |
| Inventory, CMDB model, all lenses | ✅ | ✅ | ✅ |
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
- 🚫 **Don't sell it back to the market** — you can't offer VistaPlatform, or
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

Enterprise and MSP features are not in this repository and are licensed
commercially. See [NOTICE](NOTICE) for third-party components.
