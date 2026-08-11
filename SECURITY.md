# Security Policy

VistaPlatform is a security product. A vulnerability here can expose the
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

## Supported versions

Security fixes land on the latest minor release. If you are running something
older, expect the fix to require an upgrade.
