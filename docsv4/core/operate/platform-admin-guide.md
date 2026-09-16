---
render_macros: false
---

# Platform Administrator Guide

**Version:** 4.0 (1.0.0 navigation refresh)
**Last Updated:** 2026-09-16

This guide is for **platform administrators** — the staff who operate Vista Platform for an organization and its customers. If you run Vista Platform as a white-label provider, *your* admins own everything described here: the tenants, the fleet, the catalog, the packaging, the activity trail.

It documents the administration console (admin-ui v2). The console has a single, persistent **left-rail navigation**: top-level sections, with sub-pages indented underneath the active section (there are no in-page tabs). The sections are grouped into three blocks — an ungrouped operations block at the top, then **Platform**, then **Governance**.

**Core vs. paid editions.** A handful of sections belong to a specific edition and simply don't exist in a Core build — their rail entries are hidden and their routes render an edition notice rather than a page whose calls 404. **Tenants** and **Comms** are part of the MSP tenant-lifecycle surface; **Billing & Revenue** is part of the Enterprise+ billing surface. Everything else on this page — Mission Control, Support, Fleet, Jobs & Queues, Plans & Pricing, System Health, Catalog, Settings, Staff & Access, and Security & Trust — ships in every edition, including Core.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Mission Control](#mission-control)
3. [Tenants](#tenants)
4. [Support](#support)
5. [Fleet](#fleet)
6. [Jobs & Queues](#jobs--queues)
7. [Billing & Revenue](#billing--revenue)
8. [Plans & Pricing](#plans--pricing)
9. [System Health](#system-health)
10. [Comms](#comms)
11. [Catalog](#catalog)
12. [Settings](#settings)
13. [Staff & Access](#staff--access)
14. [Security & Trust](#security--trust)
15. [Appendix: Tenant Roles (support reference)](#appendix-tenant-roles-support-reference)

---

## Getting Started

### Accessing the console

1. Navigate to the administration console at your platform's admin URL.
2. Log in with your platform administrator credentials. Authentication uses an httpOnly session cookie — if a save ever fails with a session error, log out and back in to refresh it.
3. You land on **Mission Control**, the operations overview.

### First sign-in: mandatory password rotation

A fresh deployment seeds two default administrator accounts, both flagged **must change password**:

| Email | Role | Password |
|---|---|---|
| `su_admin@vistaplatform.invalid` | Super Administrator | `PlatformAdm!n2026` |
| `admin@vistaplatform.invalid` | Platform Administrator | `PlatformAdm!n2026` |

These are published defaults — every deployment starts with them. The `.invalid` domain is deliberate ([RFC 6761](https://www.rfc-editor.org/rfc/rfc6761#section-6.4) reserves it as permanently unresolvable), so the seeded addresses can never reach a real mailbox — which also means **password-reset email to a seeded account goes nowhere**. Rotate on first sign-in, then add your own administrator under a real address in **Staff & Access → Staff** and use that account day to day. Do not rename a seeded account: the seed re-applies on every upgrade and renames it back.

Signing in with a seeded (or admin-issued temporary) password gives you a limited session that can do exactly one thing: set a new password. The console presents the change-password screen immediately, and the services reject every other request until the rotation completes — this is enforced server-side, not just by the UI. After you set a new password you continue straight into the console. Rotate the seeded credentials on day one and never share them; the same forced rotation applies whenever an administrator resets a colleague's password with "require password change on next login."

### Platform administrator roles

Access is role-based. Roles and the permissions they carry are managed in **Staff & Access → Roles**; the typical shape is:

- **Super Administrator** — full access, including billing, packaging, and security policy.
- **Platform Administrator** — day-to-day platform and tenant management, excluding the most sensitive billing/settings actions.
- **Support Administrator** — read-oriented access for assisting tenants.

Permissions are enforced by the services, not just hidden in the UI — a missing permission yields a `403` even on a direct request. The console only shows you the sections and actions your role permits, and an edition your build doesn't ship is hidden regardless of role.

### Navigation structure

The left rail is the spine of the console. Top-level sections in order:

| Block | Sections |
|---|---|
| (top) | Mission Control · Tenants · Support · Fleet · Jobs & Queues · Billing & Revenue · Plans & Pricing |
| **Platform** | System Health · Comms · Catalog · Settings |
| **Governance** | Staff & Access · Security & Trust |

When a section has sub-pages, selecting it expands them indented in the rail; the first sub-page is the section's default view. The topbar shows the active section's title and a one-line subtitle so you always know where you are.

A command palette (**Cmd/Ctrl + K**) lets you jump to any page by name; it respects your permissions and only lists pages you can reach.

---

## Mission Control

**What it's for:** the morning screen — *what's healthy, what's earning, what's running, and what needs you.* It rolls up service health, fleet status, and a "needs attention" overview into one page so you can triage before diving into any one area. On a build that ships tenant management or billing, the page also surfaces a tenant roster and a revenue hero — those two tiles are edition-gated the same way the sections that own them are; a Core build's Mission Control shows the service-health picture without them.

**Key tasks:**

- Scan overall service health at a glance.
- Work the "needs you" items — failing services, expiring trials, open security events — each links straight to the section that owns it.
- Use it as the jumping-off point; it's an index, not a place you do detailed work.

---

---

## Support

**What it's for:** the customer-success operator cockpit — **tenant health, impersonation, and job repair**. Three sub-pages:

- **Tenant Health** — per-tenant health scores and the alerts that drive them, so you can spot a customer trending toward churn or trouble before they open a ticket.
- **Impersonation** — the audit trail of support-impersonation sessions: who impersonated which tenant's user, when, and for how long.
- **Job Repair** — retry or cancel stuck discovery jobs on a tenant's behalf, without needing database access.

**Key tasks:** triage tenant health, review impersonation history, and unstick a discovery job a tenant has reported as hung.

---

## Fleet

**What it's for:** every discovery **sensor and agent across all tenants**, in one cross-tenant view. Where an individual tenant sees only their own agents, you see the whole fleet.

**Key tasks:**

- Monitor sensor/agent health and connectivity platform-wide.
- Spot agents that are offline, stale, or misbehaving across any tenant.
- Use it as the operator's-eye view of deployed discovery capacity.

---

## Jobs & Queues

**What it's for:** discovery **runs and platform pipelines** — the work the platform is executing right now and recently.

**Key tasks:**

- Watch discovery jobs progress and complete.
- Investigate stuck, slow, or failed runs and pipeline depth.
- Correlate a tenant's "my discovery didn't finish" report against actual queue state.

---


---

## Plans & Pricing

**What it's for:** **packaging** — *what you sell and how it's composed.* This section ships in every edition: browse the **Entitlements** catalogue (the levers), the **Tiers** built from them, and any **Add-ons**, and assign a tenant to a tier. Tier assignment and enforcement work on every edition, so entitlements still resolve correctly on a Core deployment.

Sub-pages: **Entitlements** · **Tiers** · **Add-ons**.


---

## System Health

**What it's for:** the live operational health of the platform itself. Sub-pages:

- **Services** — backend service status and latency. The first place to look when something feels slow or broken.
- **Gateway** — API gateway routers, services, and routing health.
- **Alerts** — system alert history and the thresholds that fire them.

**Key tasks:** confirm all services are healthy, diagnose latency or routing problems, and review what's been alerting.

---

---

## Catalog

**What it's for:** the platform's authored content — the things you maintain centrally that every tenant consumes. Sub-pages:

### Algorithms

The crypto-assessment **source of truth**: the platform-wide table of cryptographic algorithms with strength ratings, deprecation status, PQC posture, risk scores, and remediation guidance. What you set here drives risk classification and the remediation advice tenants see on their crypto-risk views. Keep it current as standards evolve so assessments stay accurate across the whole fleet.

### Frameworks (compliance framework authoring)

**Catalog → Frameworks** is where platform admins **author the compliance frameworks** that tenants evaluate against. This is a core platform-owner responsibility, so it gets real weight:

- A **framework** is a named compliance policy (e.g., a security standard or an internal baseline) made of **controls**, and each control of **measurement rules** (typed predicates) that the evaluation engine checks against tenant assets and certificates.
- From the framework catalog you **create, edit, and publish** frameworks. Publishing makes a framework available for tenants to activate; until then it's a draft you're shaping.
- Build a framework top-down: define the framework, add its **controls**, then attach **measurements** to each control. Each measurement expresses a concrete, machine-checkable rule.
- **Evaluation is the product.** Once published and activated by a tenant, a framework is evaluated continuously against that tenant's live inventory; tenants see a score and per-control findings. You are authoring the policy that the engine materializes — accuracy and clarity of controls/measurements directly shape what tenants are told.
- Maintain the catalog over time: refine controls as guidance changes, deprecate frameworks you no longer offer, and add new ones as you expand coverage.

> A framework's *availability* to tenants is governed by your packaging (a capacity cap on the number of frameworks a tier can activate, set in [Plans & Pricing](#plans--pricing)). Authoring the framework and gating who can activate it are two separate jobs.

### End-of-life, Vulnerability feed, and Classification rules

The remaining three catalog pages are covered in full in [Platform catalogues and their feeds](../operate/catalogs.md) — this section only orients you to what each one is, not how to run it.

- **End-of-life** mirrors upstream release-cycle data from [endoflife.date](https://endoflife.date) into three views: the **Catalogue** itself, **Proposals** (AI-proposed rows awaiting your review, Enterprise), and **Gaps** (products the catalogue couldn't answer for, so you know what to add by hand). See [Air-gapped installs: the offline bundle](../operate/catalogs.md#air-gapped-installs-the-offline-bundle) if your deployment has no internet access, and [Filling gaps in the end-of-life catalogue](../operate/catalogs.md#filling-gaps-in-the-end-of-life-catalogue) for working the gap list.
- **Vulnerability feed** mirrors CVE data from [NVD](https://nvd.nist.gov) and [OSV](https://osv.dev), and reports the health of both feeds — see [The feeds](../operate/catalogs.md#the-feeds) for the mirror mechanics, rate limits, and attribution requirements.
- **Classification rules** are the fingerprint rules (OUI, sysObjectID, cloud type, banner, model, platform) behind every class proposal a discovery produces — see [Classification rules](../operate/catalogs.md#classification-rules) for what a rule looks like and how precedence is resolved when two rules disagree.

All three are gated on the platform permission `catalogs.manage`, separate from the `algorithms.manage` permission the two sections above use, since curating crypto ratings and re-pointing the platform at a vulnerability source are different trust decisions.

---

## Settings

**What it's for:** platform-wide configuration — email delivery, self-service sign-up, white-labeling, legal documents, identity providers, and outbound notification delivery. Six sub-pages:

- **Email** — SMTP configuration for invitations, password resets, and onboarding mail.
- **Access & Sign-up** — self-service sign-up and email-verification gates for new organizations.
- **Branding** — white-label the platform: product name, logos, and favicon.
- **Legal** — author and version your Terms of Service and Privacy Policy.
- **Identity Providers** — the platform's own Google / Microsoft OAuth apps, used for social sign-up.
- **Notification Delivery** — the platform-level notification channels (chat webhook, email, generic webhook, paging), the routing rules that send alerts of a given source/severity to them, and delivery history. These are platform-level notifications — from monitoring and security — distinct from any tenant's own channels.

**Key tasks:** wire up email delivery, configure self-service sign-up policy, white-label the console, keep your legal documents current, connect an identity provider for social sign-up, and configure where platform alerts go.

If no platform notification channels are configured yet, the Notification Delivery page shows a prominent warning — platform-level alerts (from monitoring and security) are still recorded but reach nobody until at least one channel and a matching routing rule exist. The **bell icon** in the admin console header gives platform staff a live in-app feed of these alerts independent of that external-channel setup.

---

## Staff & Access

**What it's for:** the platform's **own** administrators and what they can do — not tenant users. (Tenant users are managed by each tenant's own administrators; see the [appendix](#appendix-tenant-roles-support-reference) for that model.) Sub-pages:

### Staff

The list of platform (internal) admin users. From here you **invite/create** a platform admin, assign them a **role**, **update** their details and role, and **deactivate/remove** access when someone leaves. Invited staff receive an email to set up their account. Treat this list as a privileged-access inventory — review it periodically and remove stale accounts.

### Roles

The platform **roles and their permissions**. Create, edit, and delete roles, and tune exactly which permissions each role grants. Because every section and action in this console is permission-gated, Roles is where you implement least-privilege for your team — e.g., a support role that can scope-to-tenant and read the activity trail but can't touch packaging or billing.

**Key tasks:** onboard/offboard platform staff, assign least-privilege roles, and adjust role definitions as your team's responsibilities change.

---

## Security & Trust

**What it's for:** the consolidated "are we trustworthy" home — posture, the platform-wide activity trail, and the outbound integrations and retention controls around it. Five sub-pages:

- **Dashboard** — security events, anomalies, and overall posture across the platform.
- **Activity Log** — the full platform-wide activity trail: user and system actions across platform and tenants. Filter by tenant, user, event type, status, and date range to investigate an incident or answer a "who changed this?" question. Scope-to-tenant sessions and other sensitive operator actions land here. Export the filtered set to CSV or JSON.
- **Retention** — log **retention and archival** policies: how long activity is kept hot vs. archived. Set these to match the compliance regimes you operate under; longer retention typically means tiered/archived storage rather than indefinite hot storage.
- **SIEM Export** — outbound **SIEM forwarding**: stream the activity trail to your external security tooling (Splunk, Datadog, Elasticsearch, etc.) for correlation and long-term analysis. Configure and verify the forwarding integration here.
- **Policy** — platform security and authentication settings (the policy that governs how the platform itself is secured): registration toggles, email-verification requirement, password policy, and session/lockout controls.

**Key tasks:** monitor security events and investigate anomalies, search and export the activity trail, set retention to satisfy your compliance obligations, forward the trail to your SIEM, and set platform-level security/authentication policy.

---

## Appendix: Tenant Roles (support reference)

You don't manage *tenant* user roles — each tenant's administrators do — but you'll need this model when supporting a tenant whose user "can't do something." Each tenant has five built-in roles:

| Role | Scope |
|------|-------|
| **Billing Admin** | Billing/payment + read-only view of users and settings. **No operational access** (no assets, sensors, discovery, compliance). |
| **Tenant Administrator** | Full operations + user management. Can *read* billing but not change it. |
| **Security Administrator** | Security operations, compliance, discovery, sensors; reads users/settings for incident response. No billing. |
| **Viewer** | Read-only operational data, no billing. |
| **API User** | Read-only integration scope; no users/settings/billing. |

Permissions are enforced by the services, not just the UI — a tenant user without the required permission gets a `403` even on a direct API request.

**Common support scenarios:**

- *"My user can't add a device / edit assets / run compliance, and the button is missing."* → Their role lacks the write permission. The tenant admin should move them to **Tenant Administrator** or **Security Administrator**. Viewer and API User are read-only by design.
- *"After upgrading, my account owner lost access to everything except billing."* → Expected. **Billing Admin** is billing-only. Whoever runs the tenant day-to-day should be **Tenant Administrator**. Have the tenant reassign them.
- *"Right after an upgrade, writes briefly returned 403, then started working."* → Expected and self-healing. Role-grant reconciliation runs as a post-upgrade job; there's a brief window before it completes. Reads are unaffected.

---

## See also

- **Money operations:** Billing & Revenue (in this console) for invoices, coupons, dunning, trials, and FinOps; deeper runbooks in [operations/](operations/) and [troubleshooting/](troubleshooting/).
- **Platform catalogues:** [Platform catalogues and their feeds](catalogs.md) for the End-of-life, Vulnerability feed, and Classification rules pages.
- **Tenant-side documentation:** the [Tenant Administrator Guide](../guides/tenant-admin-guide.md).
