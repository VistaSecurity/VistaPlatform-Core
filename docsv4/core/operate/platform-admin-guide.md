---
render_macros: false
---

# Platform Administrator Guide

**Version:** 3.0 (admin-ui v2 rewrite)
**Last Updated:** 2026-06-24

This guide is for **platform administrators** — the staff who operate Vista Platform for an organization and its customers. If you run Vista Platform as a white-label provider, *your* admins own everything described here: the tenants, the fleet, the catalog, the packaging, the audit trail.

It documents the rebuilt administration console (admin-ui v2). The console has a single, persistent **left-rail navigation**: top-level sections, with sub-pages indented underneath the active section (there are no in-page tabs). The sections are grouped into three blocks — an ungrouped operations block at the top, then **Platform**, then **Governance**.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Mission Control](#mission-control)
3. [Tenants](#tenants)
4. [Fleet](#fleet)
5. [Jobs & Queues](#jobs--queues)
6. [Billing & Revenue](#billing--revenue)
7. [Plans & Pricing](#plans--pricing)
8. [System Health](#system-health)
9. [Notifications](#notifications)
10. [Catalog](#catalog)
11. [Settings](#settings)
12. [Staff & Access](#staff--access)
13. [Security](#security)
14. [Compliance Packages](#compliance-packages)
15. [Audit](#audit)
16. [Appendix: Tenant Roles (support reference)](#appendix-tenant-roles-support-reference)

---

## Getting Started

### Accessing the console

1. Navigate to the administration console at your platform's admin URL.
2. Log in with your platform administrator credentials. Authentication uses an httpOnly session cookie — if a save ever fails with a session error, log out and back in to refresh it.
3. You land on **Mission Control**, the operations overview.

### First sign-in: mandatory password rotation

A fresh deployment seeds default administrator accounts flagged **must change password**. Signing in with a seeded (or admin-issued temporary) password gives you a limited session that can do exactly one thing: set a new password. The console presents the change-password screen immediately, and the services reject every other request until the rotation completes — this is enforced server-side, not just by the UI. After you set a new password you continue straight into the console. Rotate the seeded credentials on day one and never share them; the same forced rotation applies whenever an administrator resets a colleague's password with "require password change on next login."

### Platform administrator roles

Access is role-based. Roles and the permissions they carry are managed in **Staff & Access → Roles**; the typical shape is:

- **Super Administrator** — full access, including billing, packaging, and security policy.
- **Platform Administrator** — day-to-day platform and tenant management, excluding the most sensitive billing/settings actions.
- **Support Administrator** — read-oriented access for assisting tenants.

Permissions are enforced by the services, not just hidden in the UI — a missing permission yields a `403` even on a direct request. The console only shows you the sections and actions your role permits.

### Navigation structure

The left rail is the spine of the console. Top-level sections in order:

| Block | Sections |
|---|---|
| (top) | Mission Control · Tenants · Fleet · Jobs & Queues · Billing & Revenue · Plans & Pricing |
| **Platform** | System Health · Notifications · Catalog · Settings |
| **Governance** | Staff & Access · Security · Compliance Packages · Audit |

When a section has sub-pages, selecting it expands them indented in the rail; the first sub-page is the section's default view. The topbar shows the active section's title and a one-line subtitle so you always know where you are.

A command palette (**Cmd/Ctrl + K**) lets you jump to any page by name; it respects your permissions and only lists pages you can reach.

---

## Mission Control

**What it's for:** the morning screen — *what's healthy, what's earning, what's running, and what needs you.* It rolls up platform health, revenue, fleet status, and a "needs attention" overview into one page so you can triage before diving into any one area.

**Key tasks:**

- Scan overall service health and recent revenue at a glance.
- Work the "needs you" items — failing services, expiring trials, open security events — each links straight to the section that owns it.
- Use it as the jumping-off point; it's an index, not a place you do detailed work.

---

## Tenants

**What it's for:** every customer organization, and the place where the entire **tenant lifecycle** lives. The section opens on a searchable, filterable tenant table; selecting a tenant opens a **detail drawer** with everything about that customer.

This is the highest-traffic operational section, so it gets real weight below.

### Create a tenant

1. From the tenant table, click **Create tenant** (or **New tenant**).
2. Provide the tenant's identity and starting plan:
   - **Name** — the organization name.
   - **Slug / identifier** — URL-friendly handle.
   - **Tier** — the plan they start on (from your published Tiers — see [Plans & Pricing](#plans--pricing)).
   - **Admin email** — the person who'll receive the invitation and become the tenant's first administrator.
3. Save. The tenant administrator receives an invitation to set up their account.

### Edit a tenant

Open the tenant's drawer to review and update its core record — name, identifier, contact, plan/tier, and status. Changes save from the drawer. Switching a tenant's tier here changes the plan they're on; pricing and packaging behavior follows from the tier definition in Plans & Pricing.

### Suspend a tenant

From the drawer's actions, **Suspend** the tenant. Suspended tenants' users lose access to the product until you restore them. Reverse it with the matching **Restore** action. Suspension is the right lever for non-payment holds or security holds where you intend to bring the customer back.

### Delete a tenant

From the drawer's actions, **Delete** removes the tenant. This is destructive and final (as opposed to suspend, which is reversible) — use it for genuine off-boarding, and confirm you have the right tenant first. Prefer **suspend** whenever there's any chance the customer returns.

### Scope to a tenant (support context)

From the tenant drawer you can **scope to the tenant** — enter that tenant's context to assist with a support request and see what they see. The action is logged in the [Audit](#audit) trail with your identity and the reason, the session is time-bounded, and it does not grant the tenant any platform-admin capability. Use it to reproduce a tenant's problem or verify a fix, then exit the scoped context when you're done. Because every scope-to-tenant session is audited (start and end), it's the supportable, accountable way to act on a customer's behalf rather than asking them for credentials.

### Per-tenant tabs in the drawer

The drawer is organized into tabs for the customer's full record:

- **Overview / details** — the editable core record (above), usage at a glance, status.
- **SSO** — the tenant's single-sign-on configuration.

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

## Billing & Revenue

**What it's for:** **money operations** — the RevOps surface. This is revenue and collections, kept deliberately separate from *packaging* (which lives in [Plans & Pricing](#plans--pricing)). Sub-pages in the left rail:

- **Overview** — MRR, ARR, revenue by plan, and invoices. Your top-line revenue picture and invoice list.
- **Coupons** — create, edit, deactivate, and apply discount codes; review redemptions. You can apply or remove a coupon for a specific tenant from here.
- **Trials** — trial-conversion analytics: who's in trial, who's converting, who's expiring soon.
- **Dunning (Payment Recovery)** — past-due invoices and the recovery workflow: review failed payments, trigger retries, and manage suspension/restoration for non-payment.
- **FinOps** — platform infrastructure cost broken down by service and by tenant, so you can see cost against revenue.

**Key tasks:** track MRR/ARR and revenue mix, run discount campaigns, monitor and recover failed payments, and watch unit economics.

**Deeper billing operations** — Stripe setup, the dunning retry schedule, trial lifecycle, coupon strategy, usage monitoring, and invoice PDFs — have dedicated runbooks (billing is flat per-tier; there is no overage/metered billing):


---

## Plans & Pricing

**What it's for:** **packaging** — *what you sell and how it's composed.* You define **Entitlements** (the levers), compose them into **Tiers** (the plans you publish), and offer **Add-ons** à la carte. Per-tenant **Plan Exceptions** are the rare, non-billing escape hatch and are granted from the [tenant drawer](#tenants), not here.

Sub-pages: **Entitlements** · **Tiers** · **Add-ons**.

This area has its own authoritative operator guide — it is not duplicated here:


(That guide covers the lever catalog, the tier matrix and plan builder, custom/bespoke tiers, add-ons, and exactly when to use a Custom tier vs. a Plan Exception vs. a Catalog → Artifacts → Tenant Override.)

---

## System Health

**What it's for:** the live operational health of the platform itself. Sub-pages:

- **Services** — backend service status and latency. The first place to look when something feels slow or broken.
- **Gateway** — API gateway routers, services, and routing health.
- **Alerts** — system alert history and the thresholds that fire them.

**Key tasks:** confirm all services are healthy, diagnose latency or routing problems, and review what's been alerting.

---

## Notifications

**What it's for:** how the platform reaches operators and tenants — **channels, rules, announcements, and maintenance windows** for infrastructure, security, and system events. These are platform-level notifications, distinct from any tenant's own channels.

**Key tasks:**

- Configure platform notification **channels** (e.g., chat webhook, email, generic webhook, paging) and test connectivity.
- Define **rules** that route alerts of a given source/severity to specific channels.
- Post **announcements** to tenants and schedule **maintenance windows**.

If no platform channels are configured yet, the Notifications page shows a
prominent warning — platform-level alerts (from monitoring and audit) are
still recorded but reach nobody until at least one channel and a matching
routing rule exist. The **bell icon** in the admin console header gives
platform staff a live in-app feed of these alerts independent of that
external-channel setup.

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

### Artifacts

Downloadable binaries (sensor/agent installers and similar) the platform distributes. Indented one level deeper under Artifacts:

- **Tenant Overrides** — pin a specific tenant to a specific **artifact/binary version**. ⚠️ This is *version pinning of downloadable artifacts* and is **not** the same thing as a Plan Exception (an entitlement grant). The names are similar; the features are unrelated. Use Tenant Overrides only to control which binary build a tenant gets.

---

## Settings

**What it's for:** platform-wide configuration: **email, limits, and security**. This is the operator's control panel for cross-cutting defaults — outbound email setup, platform/tenant limits and rate caps, file-upload limits, registration toggles, session and password policy, storage backends, and related security knobs.

**Key tasks:** wire up email delivery, configure object storage for artifacts/branding, set platform-wide limits and rate controls, and configure authentication/session policy. Changes apply platform-wide, so review before saving. (Object-storage backends for artifacts and branding are configured here; see the deployment docs for the underlying S3/bucket setup.)

---

## Staff & Access

**What it's for:** the platform's **own** administrators and what they can do — not tenant users. (Tenant users are managed by each tenant's own administrators; see the [appendix](#appendix-tenant-roles-support-reference) for that model.) Sub-pages:

### Staff

The list of platform (internal) admin users. From here you **invite/create** a platform admin, assign them a **role**, **update** their details and role, and **deactivate/remove** access when someone leaves. Invited staff receive an email to set up their account. Treat this list as a privileged-access inventory — review it periodically and remove stale accounts.

### Roles

The platform **roles and their permissions**. Create, edit, and delete roles, and tune exactly which permissions each role grants. Because every section and action in this console is permission-gated, Roles is where you implement least-privilege for your team — e.g., a support role that can scope-to-tenant and read audit logs but can't touch packaging or billing.

**Key tasks:** onboard/offboard platform staff, assign least-privilege roles, and adjust role definitions as your team's responsibilities change.

---

## Security

**What it's for:** the platform's security posture and policy. Sub-pages:

- **Dashboard** — security events, anomalies, and overall posture across the platform.
- **Policy** — platform security and authentication settings (the policy that governs how the platform itself is secured): registration toggles, email-verification requirement, password policy, and session/lockout controls.

**Key tasks:** monitor security events, investigate anomalies, and set platform-level security/authentication policy.

---

## Compliance Packages

**What it's for:** assembling **auditor evidence bundles** — packaged compliance artifacts you can hand to an auditor or customer to demonstrate the platform's compliance posture.

**Key tasks:** generate and manage evidence packages for audits and customer due-diligence requests.

---

## Audit

**What it's for:** the **platform-wide activity trail** and everything built on top of it — the system of record for who did what, and the outbound integrations and retention controls around it. This is a Governance cornerstone, so it gets real weight. Sub-pages:

- **Activity** — the full platform-wide activity log: user and system actions across platform and tenants. Filter by tenant, user, event type, status, and date range to investigate an incident or answer a "who changed this?" question. Scope-to-tenant sessions and other sensitive operator actions land here. Export the filtered set to CSV or JSON.
- **Alerts** — audit alerts that have triggered (e.g., a watched event occurred).
- **Alert Rules** — configure which audit events raise an alert. This is how you turn the raw trail into proactive signals (e.g., alert on privileged-role changes or repeated failures).
- **SIEM** — outbound **SIEM forwarding**: stream the audit trail to your external security tooling (Splunk, Datadog, Elasticsearch, etc.) for correlation and long-term analysis. Configure and verify the forwarding integration here.
- **Retention** — log **retention and archival** policies: how long activity is kept hot vs. archived. Set these to match the compliance regimes you operate under; longer retention typically means tiered/archived storage rather than indefinite hot storage.
- **Compliance** — audit compliance reporting built from the trail.

**Key tasks:** investigate activity, codify watch-for events into alert rules, forward the trail to your SIEM, and set retention to satisfy your compliance obligations.

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
- **Tenant-side documentation:** the [Tenant Administrator Guide](../guides/tenant-admin-guide.md).
