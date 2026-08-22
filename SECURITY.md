# Security Policy

Vista Platform is a security product. A vulnerability here can expose the
cryptographic inventory of the organizations running it, so we treat reports
accordingly.

## Reporting a vulnerability

**Do not open a public issue.**

Report privately through either channel:

- **GitHub Security Advisories** — [open a draft advisory](https://github.com/VistaSecurity/VistaPlatform-Core/security/advisories/new).
  Preferred: it keeps the report, the fix, and the CVE in one place.
- **Email** — product@vistasecurity.io

If you want to encrypt the report, ask for a key in a first message with no
details in it.

## What to include

The more of this you can provide, the faster we can confirm and fix:

- The version or commit you tested
- How it was deployed — Helm chart, Docker Compose, or from source
- Which edition (this repository is Core; Enterprise and MSP are separate)
- Reproduction steps, ideally the smallest case that shows the problem
- What an attacker gets, and what access they need to start

## What to expect

| | |
|---|---|
| Acknowledgement | within 3 business days |
| Initial assessment | within 10 business days |
| Fix or mitigation plan | communicated with the assessment |

We will tell you plainly if we think a report is not a vulnerability, and why.
If we disagree with your severity assessment we will say so rather than quietly
downgrading it.

## Disclosure

We ask for **90 days** before public disclosure, or until a fix ships if that
is sooner. If a fix is going to take longer we will tell you why rather than
letting the clock run out in silence.

Reporters are credited in the advisory and release notes unless you ask us not
to be. We do not currently run a paid bounty.

## Scope

**In scope** — anything in this repository: the services, the sensor and device
agent, the Helm chart, the frontends, and the database schema, including
authentication, tenant isolation, and the entitlement gates.

Findings we particularly want:

- Cross-tenant data access. Tenant isolation is enforced by PostgreSQL
  row-level security; a bypass is our highest-severity class of bug.
- Authentication or session flaws, including the token-issuing OAuth server.
- Anything that lets an unauthenticated caller reach tenant data.
- Sensor or agent enrollment weaknesses — those binaries run inside customer
  networks and hold client certificates.

**Out of scope**

- Findings that require an operator to already have database or cluster admin
  access. Self-hosted software cannot defend against its own administrator, and
  we would rather spend the effort elsewhere.
- The absence of a runtime licence check. Edition gating is a commercial
  boundary backed by a licence agreement, not a security control, and it is not
  designed to resist an operator with source access.
- Missing security headers or TLS configuration on a deployment you control —
  those are yours to set. Report them if the *chart defaults* are unsafe.
- Automated scanner output with no demonstrated impact.

## Our own posture

Two things you can check rather than take on trust:

- **[Container scan report](security-scans/)** — every published image, scanned
  nightly with Trivy, results committed to this repository. Images that could
  not be scanned are reported as unscanned, not as clean.
- **[How the platform is built and shipped](docsv4/core/security-posture.md)** —
  tenant isolation, service-to-service authentication, the collect-posture-never-key-material
  rule, supply-chain signing, and which CI scanners gate a merge.

## Known design tradeoffs

These are deliberate, and visible in the source. We would rather state them here
than have you spend an afternoon rediscovering them and filing a report we close
as known. If you can show impact beyond what is described, we very much want it.

- **Token revocation fails open.** The revocation denylist is backed by Redis. If
  it is unreachable, the check is skipped and the request proceeds, with a
  warning logged. A revoked token therefore stays usable for the duration of a
  Redis outage. The alternative — failing closed — turns a cache outage into a
  total authentication outage, which we judged worse for self-hosted operators.
- **Service-to-service requests have a replay window.** Internal calls are signed
  with HMAC-SHA256 over the method, path, query, body hash, timestamp and tenant.
  The nonce is signed entropy, not a dedup key: it is never recorded, so an exact
  replay of a captured internal request succeeds until its timestamp ages out of
  the ±5 minute clock-skew window. Enabling `serviceMtls` puts the whole mesh
  behind mutual TLS, which is the mitigation we recommend and run ourselves.

## Supported versions

Security fixes land on the latest minor release. If you are running something
older, expect the fix to require an upgrade.
