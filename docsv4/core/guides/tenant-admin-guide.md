# Tenant Administrator Guide

**Version:** 2.0
**Last Updated:** 2026-06-24

> **What changed in 2.0:** This guide was refreshed for the rebuilt
> Vista Platform web console and its new five-section lifecycle
> navigation. Every page reference below now points at the current UI. If
> you previously bookmarked the old "Reports & Analytics," "Crypto Workbench,"
> or "Operations → Activity Logs" surfaces, see the
> [What moved where](#what-moved-where) map — those surfaces have been
> replaced, not just renamed.

This guide provides instructions for **Tenant Administrators** — the elevated
web-console users who run Vista Platform for their organization: managing
members and access, configuring SSO and org settings, owning billing, and
setting the policies that govern discovery, compliance, and the asset
lifecycle.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [How the Console Is Organized](#how-the-console-is-organized)
3. [What Moved Where](#what-moved-where)
4. [Members & Access (Roles)](#members--access-roles)
5. [Security & SSO](#security--sso)
6. [Billing, Usage & Plan](#billing-usage--plan)
7. [Organization Settings](#organization-settings)
8. [Notifications & Alerts](#notifications--alerts)
9. [Policies](#policies)
10. [Integrations & CMDB](#integrations--cmdb)
11. [Infrastructure (Sensors, Locations, Segments)](#infrastructure-sensors-locations-segments)
12. [Audit](#audit)
13. [Working with Inventory & Certificates](#working-with-inventory--certificates)
14. [Compliance & Frameworks](#compliance--frameworks)
15. [Evidence: CBOM Artifacts & Exports](#evidence-cbom-artifacts--exports)
16. [Best Practices](#best-practices)
17. [Troubleshooting](#troubleshooting)
18. [Support](#support)

---

## Getting Started

### First Login

1. Receive your invitation email.
2. Click the invitation link and set your password (or sign in with your
   organization's SSO provider, if your admin enabled it).
3. You land on the **Dashboard** — a priority-based health overview of your
   organization's crypto posture.

### Getting Started Checklist

New organizations get a guided checklist. Open it any time from the
**profile menu** (your avatar, bottom of the left rail) → **Getting Started**.
It walks you through the first high-value setup steps: inviting members,
configuring discovery, and activating a compliance framework.

### The Profile Menu

Your avatar at the bottom of the left navigation rail opens the profile menu.
This is the home for everything that isn't a lifecycle workspace:

- **Getting Started** — the onboarding checklist (shown while onboarding is live)
- **My Profile** — your personal identity, security/MFA, sessions, connected
  SSO accounts, and personal API tokens
- **Organization Settings** — all tenant-admin configuration (this guide's
  main subject)
- **About** — version and platform information
- **Light / Dark theme toggle** — appearance is a personal preference, set here
- **Sign out**

> There is **no** standalone "Reports" area and **no** separate "Tickets" page.
> See [What Moved Where](#what-moved-where).

---

## How the Console Is Organized

The console has **five lifecycle sections** along the top of the left rail.
Everything a tenant does day-to-day lives in one of these:

| Section | What it's for |
|---------|---------------|
| **Dashboard** | Priority-based health overview — risk summary, compliance status, recent activity. |
| **Discovery** | Run and review discovery — sensors & agents, jobs, devices, scheduled scans, cloud sources, PCAP upload, and approvals. |
| **Inventory** | Your unified asset inventory, viewed through switchable **lenses** (infrastructure, certificate, configuration, network, keys, connections, stale, and more). |
| **Risk & Compliance** | **Posture** (scores, framework transparency, algorithm reference), **Findings**, and **CBOM**. |
| **Remediation** | **Triage**, **Queue** (the unified ticket work surface), and **Plans** (migration planning). |

**Organization Settings** (the admin's main workspace) opens from the profile
menu and replaces the primary rail with its own settings navigation, grouped
into: Organization · Account · People & Access · Integrations ·
Notifications & Alerts · Policies · Audit · Infrastructure.

Throughout this guide, "Organization Settings → *Section* → *Page*" means: open
the profile menu, click **Organization Settings**, then pick the section and
page from the settings rail.

---

## What Moved Where

If you used the previous version of the console, here's where the old surfaces
went:

| Old location (v1) | Where it is now |
|-------------------|-----------------|
| **Reports → Create Report** / **Reports & Analytics** | **Removed.** For evidence-grade output, generate a **CBOM artifact** (Risk & Compliance → **CBOM**). For a quick spreadsheet of what's on screen, use the **Export** button on any **Inventory** lens. See [Evidence](#evidence-cbom-artifacts--exports). |
| **Crypto Inventory → Certificates view** | **Inventory** → switch to the **certificate** lens. |
| **Crypto Workbench** (perspectives, framework selector) | Split: browse assets via **Inventory** lenses; review compliance posture and framework transparency under **Risk & Compliance → Posture**; work findings under **Risk & Compliance → Findings**. |
| **Operations → Activity Logs** | **Organization Settings → Audit**. |
| **Operations → Notification History** | **Organization Settings → Notifications & Alerts** (routing and alert rules); delivery history surfaces there and in **My Profile → Notifications**. |
| **Settings → General / UI Configuration** | No such pages. Org identity is **Organization Settings → Organization → Overview**; appearance (light/dark) is the **theme toggle** in the profile menu; personal preferences live in **My Profile → Preferences**. |
| **Settings → SSO / Members / Roles** | **Organization Settings → People & Access** (Members, Roles & Permissions, Security & SSO). |
| **Standalone Tickets page** | **Remediation → Queue.** |

---

## Members & Access (Roles)

Member and role management lives under **Organization Settings → People &
Access**.

### Inviting Members

1. Go to **Organization Settings → People & Access → Members**.
2. Click **Invite Member**.
3. Enter the user's **email** and assign a **role** (see [User Roles](#roles--permissions)).
4. Click **Send Invitation**. The user receives an invite email.

> If SSO auto-provisioning is enabled, members can also be created
> automatically on first SSO login. See [Security & SSO](#security--sso).

### Managing Members

On **Members** you can:

- View every member with their **role(s)**, **auth method** (Password, Google,
  Microsoft, SAML, Okta), **last active** time, and **status** (active /
  pending / suspended).
- Add or remove roles inline.
- **Edit** a member's details and status.
- **Deactivate** a member — they can no longer sign in, but their data and
  audit trail are preserved (members are soft-deleted, never hard-deleted).

### Roles & Permissions

Define roles and the access each grants under **Organization Settings → People
& Access → Roles & Permissions**.

Vista Platform ships the built-in roles below, and you can **define custom
roles** of your own when your team doesn't fit them — see
[Roles and Permissions](../features/roles-and-permissions.md) for creating,
editing and deleting them. Assign each member the narrowest role that still lets
them do their job. *Full* = view + create + edit + delete; *Read* = view only;
*None* = no access (navigation and buttons are hidden).

| Role | Assets | Sensors | Discovery | Compliance | Members | Settings | Audit | Billing |
|------|--------|---------|-----------|------------|---------|----------|-------|---------|
| **Billing Admin** | None | None | None | None | Read | Read | None | **Full** |
| **Tenant Administrator** | Full | Full | Full | Full | Full | Full | Full | Read |
| **Security Administrator** | Full | Full | Full | Full | Read | Read | Read | None |
| **Viewer** | Read | Read | Read | Read | Read | Read | Read | None |
| **API User** | Read | Read | Read | Read | None | None | None | None |

The **built-in roles cannot be edited or deleted.** Their definitions are
re-applied on every upgrade, so an edit would be reverted the next time you
upgraded — the screen shows them read-only rather than letting you make a change
that would not survive. Custom roles are never touched by that process.

**Choosing a role:**

- **Tenant Administrator** is the day-to-day admin — full operational control
  and member management. They can *view* billing (invoices, usage) but cannot
  change payment details. This is the role for whoever runs the platform for
  your organization.
- **Billing Admin** is a finance/account-owner role. It manages billing and
  payment and can see who has access (Members) and basic org settings, but has
  **no operational access** — it cannot touch assets, sensors, discovery, or
  compliance. Assign this to a finance contact, not your platform operator.
- **Security Administrator** runs security operations — assets, sensors,
  discovery, and compliance — and can read the member list and settings for
  incident response, but cannot manage members, change settings, or see billing.
- **Viewer** is read-only across operational data (no billing).
- **API User** is a read-only role for integrations and service accounts,
  scoped to operational data only (no members, settings, or billing).
- **A custom role** is the answer when none of the above fits — for example a
  compliance analyst who should read everything and manage findings but never
  touch sensors. Pick exactly the permissions the job needs.

> **Audit access.** Every role that can read operational data can also read the
> audit trail; only Tenant Administrator can change retention policies and audit
> alert rules. Custom roles can be given either level.

> **CBOM & evidence:** CBOM artifacts and Inventory exports follow operational
> read access — any role that can read inventory can view and generate them.

> **Enforcement is server-side.** Permissions are enforced everywhere, not just
> in the UI: a member without the required permission cannot perform the action
> at all. Navigation links and action buttons are simply hidden for members who
> lack the permission, so assigning the correct role is all you need to do.

---

## Security & SSO

Configure identity-provider connections, the org authentication policy, and
SSO-group → role mapping under **Organization Settings → People & Access →
Security & SSO**.

### Authentication Policy

Vista Platform supports four authentication policies. Set yours at the top
of the **Security & SSO** page; it takes effect immediately.

| Policy | Behavior | Best for |
|--------|----------|----------|
| **Password Only** | Email/password only; SSO disabled. | Small teams without an enterprise IdP. |
| **Prefer SSO** *(recommended)* | SSO shown first; password still available as fallback. | Organizations transitioning to SSO. |
| **Enforce SSO** | Regular users must use SSO; admins keep password access for emergencies. | SSO-required security policies that still need a break-glass path. |
| **SSO Only** | Everyone, including admins, must use SSO; passwords disabled entirely. | Strict policies with redundant SSO infrastructure. |

> Before enabling **Enforce SSO** or **SSO Only**, make sure you have at least
> one enabled, **tested** SSO provider and a backup plan for an IdP outage. The
> console blocks these policies until an enabled provider exists.

### Adding an OAuth2 / OIDC Provider (Google, Microsoft / Entra ID, Azure AD, Okta)

1. On **Security & SSO**, click **Add OAuth/OIDC**.
2. Pick a preset provider type — most fields (endpoints, scopes) are pre-filled.
3. Enter your **Client ID** and **Client Secret** (encrypted before storage).
   Adjust the authorization/token/user-info URLs and scopes only if your preset
   doesn't supply them.
4. Set basic options: **Enabled**, **Set as Default Provider**, and
   **Auto-provision Users** (auto-create accounts on first SSO login).
5. *(Optional)* Restrict **Allowed Email Domains** to limit which addresses may
   sign in via this provider.
6. Set the **Default Role** for auto-provisioned users (defaults to Viewer).
7. *(Optional)* Configure **Group-to-Role Mappings** (see below).
8. Click **Test**, then **Create Provider**.

The form shows the **callback URL** to register in your IdP.

### Adding a SAML Provider

1. Click **Add SAML**.
2. Enter the **Display Name**, **Entity ID (Issuer)**, **SSO URL**, and your
   IdP's **X.509 certificate** (used to verify assertions). Add a **Private
   Key** only if you sign requests.
3. Configure the same options as OAuth (enabled, default, auto-provision,
   allowed domains, default role, group mappings).
4. Provide the **Entity ID** and **ACS URL** shown in the form to your IdP.
5. Click **Test**, then **Create Provider**.

### Group-to-Role Mapping

Automatically assign roles from a member's IdP group membership:

1. On SSO login, Vista Platform reads the **groups claim** from the IdP
   response.
2. Each group is matched against your configured mappings.
3. Every match assigns the corresponding Vista Platform role.
4. If nothing matches, the provider's **default role** is assigned.

| Provider | Groups claim | Setup required |
|----------|--------------|----------------|
| **Google Workspace** | `groups` | Admin SDK Directory API + domain-wide delegation. |
| **Microsoft / Entra ID** | `groups` | Enable the "groups" claim in App Registration → Token Configuration. |
| **Okta** | `groups` | Add a "groups" claim under Security → API → Claims. |
| **SAML** | `groups` (or a custom attribute) | Configure the group attribute in your SAML assertion. |

### Managing & Testing Providers

The provider list shows each provider's status (**Enabled/Disabled**,
**Default**), key details, auto-provision state, mapping count, and domain
restriction. Each provider offers **Test**, **Edit**, and **Delete**.

Always **Test** before enabling for users: a window opens the full SSO flow;
confirm you're redirected back and that email/name map correctly. If it fails,
recheck the Client ID/Secret or SAML certificate, the callback URL registered
in your IdP, and that scopes include `email` and `profile`.

### Members Linking Their Own SSO Accounts

Individual members link providers under **My Profile → Connected Accounts**.
A member must always keep at least one authentication method; under **Enforce
SSO** / **SSO Only** they cannot unlink their SSO account.

---

## Billing, Usage & Plan

Billing lives under **Organization Settings → Account → Billing** (requires a
role with billing access — Tenant Administrator can view; Billing Admin can
manage). Usage lives alongside it under **Account → Usage & Limits**.

### Billing

The Billing page covers:

- **Current plan** — tier, price, billing interval, status, and your
  **12-month agreement** dates (start and auto-renewal).
- **Next payment** — amount, date, and the card on file (or a cancellation
  notice with a **Reactivate** option).
- **Active discount** — any applied coupon and its remaining time.
- **Plan changes** — switch between **Monthly** and **Annual** (annual prepay
  is 10× the monthly price — two months free), or **upgrade** to a higher
  tier (effective immediately; Stripe prorates; the agreement dates don't
  change). Moving to a lower tier mid-agreement is handled by support, not
  self-service.
- **Cancel / reactivate** — cancel any time with an optional reason. On
  monthly billing, billing and service continue **through the end of the
  agreement year** (the confirmation shows the exact date); on annual prepay
  the plan simply ends at the close of the paid year. Reactivate any time
  before the end date.
- **Invoices** — number, status, amount, period, date, and **Download PDF**
  when available.
- **Payment methods** — cards on file with brand, last4, expiry, and a
  **Default** badge; update via the secure (Stripe) form.

### Usage & Limits

**Account → Usage & Limits** shows consumption (sensors, assets, storage, API
calls) against your plan limits with progress bars, and an **Upgrade Plan**
link into Billing.

### Trial Banner

Organizations on a **free trial** see a banner: blue/Billing-only with more than
7 days left, amber/global within 7 days, and red once the trial ends. **Upgrade
now** opens the Billing page.

---

## Organization Settings

Edit core org metadata and branding under **Organization Settings →
Organization**.

### Overview

**Organization → Overview** shows your read-only **Tenant ID** and **Slug**, and
lets you edit:

- **Company Name** — appears in the header as "for [Company Name]"
- **Domain** — your primary domain
- **Billing Email** — address for billing communications

It also surfaces a glance at the compliance frameworks you're licensed for.
Click **Save changes** to apply.

### Branding

**Organization → Branding** white-labels the console:

- **Logo** — upload PNG, JPEG, SVG, or ICO (max 5 MB; ~40×40 recommended). It
  appears in the header to the right of the user menu. Use **Remove** to clear
  it.
- **Favicon** — the icon shown in browser tabs.
- **Company Name** — shown as a subtitle ("for Acme Corp").

> If you see a "storage not configured" error on logo upload, ask your platform
> administrator to enable storage before tenant branding uploads will work.

Branding applies to everyone in your organization. The platform's own name and
logo are set by the platform administrator and can't be changed by tenants.

> **Appearance is personal, not org-wide.** Light/dark mode is the **theme
> toggle** in the profile menu, and each member sets their own under **My
> Profile → Preferences**. There is no org-level "UI Configuration" page.

---

## Notifications & Alerts

Configure how events reach your team under **Organization Settings →
Notifications & Alerts**. (Delivery channels — Slack, email, webhook,
PagerDuty, in-app — are connected in [Integrations](#integrations--cmdb).)

Every new organization starts pre-wired: an **in-app channel**, an
**email channel** addressed to your admins, and two default routing rules
(critical/high severity → in-app + email; medium/low → in-app only) are
seeded automatically the moment the organization is created. Nothing below
is required to get first alerts — it's how you customize beyond that
starting point.

### Routing Rules

**Notifications & Alerts → Routing Rules** matches events to delivery channels.

1. Create rules that match your routing needs.
2. Set **priorities** (higher-priority rules evaluate first).
3. Filter by **Alert Source** (monitoring, discovery, compliance, audit,
   inventory), **Alert Type**, and **Severity**.
4. Choose **frequency** — immediate, or a digest (hourly / daily / weekly).

### Alert Rules — the alert catalog and audit rules

**Notifications & Alerts → Alert Rules** has two parts.

The top section is the **alert catalog** — the platform's built-in library of
stateful conditions it can raise a persistent alert for (see
[Remediation → Alerts](../features/remediation.md#alerts) for what these
look like once raised). For each catalog entry you can:

- **Enable or disable** it. Entries marked "coming soon" are registered but
  not yet wired to a detector.
- For **escalating (ladder) types** like certificate expiry, see and adjust
  the **warning ladder** — the schedule of thresholds at which the alert
  opens or escalates. Each rung shows where it came from: the platform
  default, your own preference, or a compliance framework your organization
  has activated. **Framework rungs cannot be removed here** — only by
  deactivating that framework — because a policy commitment shouldn't be
  silenceable from a settings toggle. Your own preference *replaces* the
  platform default, so activating more frameworks can only tighten the
  schedule, never loosen it.

Below the catalog is the pre-existing **audit alert rules** list —
threshold- and pattern-based detection over the activity log (failed-login
bursts, bulk exports, privileged actions). These are a separate, narrower
mechanism from the stateful alert catalog above; both feed the same routing
rules and channels.

### Delivery History

**Notifications & Alerts → Delivery History** shows every notification the
platform has sent (or attempted to send) — timestamp, source, severity,
channels used, and status. Rows where nothing was actually delivered (no
routing rule matched) are called out, so a misconfigured or missing rule is
visible instead of silent.

> **Delivery history** previously lived under "Operations → Notification
> History." Review it here and in **My Profile → Notifications**, where each
> member chooses which notifications they receive and how (today this
> records member preference; the organization's routing rules above still
> govern what's actually sent).

The **bell icon** in the header gives every member a live view of their
in-app notifications and a shortcut into the alert inbox
([Remediation → Alerts](../features/remediation.md#alerts)) without needing
to visit these settings pages at all.

---

## Policies

The **Policies** section of Organization Settings is where a Tenant Admin sets
the rules that govern compliance, severity scoring, the asset lifecycle, data
retention, and CBOM scoping.

| Page | What you set |
|------|--------------|
| **Compliance Frameworks** | Activate frameworks and set the default. See [Compliance & Frameworks](#compliance--frameworks). |
| **Severity Ratings** | The source-of-truth registry that rates cryptographic values consistently over time. |
| **Asset Lifecycle** | Staleness thresholds and auto-archive behavior. |
| **Retention Policies** | Data-retention schedules for audit and event logs. |
| **Scopes** | Named, versioned asset boundaries used by CBOM. See the [Scopes guide](../features/scopes.md). |

### Asset Lifecycle

**Policies → Asset Lifecycle** controls how stale assets are detected and
handled:

- **Stale Warning Days** — days before an asset is flagged (default 30).
- **Stale Archived Days** — days before auto-archiving (default 60; must be
  greater than the warning threshold).
- **Auto Archive Enabled** — automatically archive stale assets.
- **Notifications Enabled** — notify when assets become stale.

Set the warning threshold to your scan cadence, and keep the archive threshold
high enough to allow review before anything is archived.

### Scopes

**Policies → Scopes** defines the named, versioned predicate (which assets count)
that a CBOM artifact attests to. System defaults (**All**, **Production**,
**Non-Dev/Test**) seed automatically; you can author your own. Full detail in
the [Scopes guide](../features/scopes.md).

---

## Integrations & CMDB

Connect Vista Platform to third-party systems under **Organization Settings
→ Integrations** — one hub for SIEM, CMDB/ITSM, messaging channels, and storage.

### Setting Up an Integration

1. Go to **Organization Settings → Integrations**.
2. Choose an integration type (Slack, PagerDuty, Datadog, Splunk, custom
   webhook, a CMDB platform, etc.).
3. Enter credentials (webhook URL, routing key, API key — as appropriate).
4. **Test** the connection, then **Save**.

Messaging integrations you connect here become the delivery channels referenced
by [Notifications & Alerts](#notifications--alerts).

### CMDB Integrations

Push your cryptographic inventory to an external CMDB for unified IT asset
management. Supported platforms: **ServiceNow**, **Device42**, **SolarWinds**,
and **Oomnitza**.

1. From **Integrations**, add a CMDB integration.
2. Select the target platform and enter connection details.
3. Configure **field mappings** to match your CMDB schema.
4. Set a **sync schedule** (manual / hourly / daily / weekly).
5. **Test** before enabling.

Each configured CMDB integration offers **View History** (last 20 sync jobs),
**Test Connection**, **Trigger Sync**, **Edit**, and **Delete**. Sync history
shows per-job status, trigger, start time, duration, and item-level
pushed/reconciled/failed/skipped counts.

The model is **push with reconciliation**: data is pushed from Vista Platform
to your CMDB, and external IDs/sync status are pulled back for linking — your
CMDB remains the system of record. Full detail in the
[CMDB Integrations feature documentation](../features/cmdb-integrations.md).

---

## Infrastructure (Sensors, Locations, Segments)

The **Infrastructure** section of Organization Settings defines where your
infrastructure lives and how discovered assets are classified. **Discovery
requires at least one location and one network segment.**

### Locations

**Infrastructure → Locations** maintains the hierarchical physical/cloud
location registry used by Inventory and Discovery:

- Create hierarchical locations (region → datacenter → rack) or cloud regions.
- Each can carry a physical address, cloud provider/region, and geo/timezone.
- Locations must exist before you create network segments.

### Network Segments

**Infrastructure → Network Segments** defines the boundaries Discovery scopes
scans against:

- Define CIDR blocks, IP ranges, domain patterns, or VPCs, each with an
  environment and location.
- Optionally set description, business unit, owner email, and tags (applied to
  matching assets on reclassify).
- Enable **Auto-approve discoveries** so sensor findings in the segment skip
  manual approval.
- Use **Reclassify all assets** to re-match existing assets and update their
  location, environment, and tags.

### Sensor Configuration

**Infrastructure → Sensor Configuration** sets global discovery-engine behavior:

- **Active Scanning Policy** — tenant-wide enable/disable for active probing,
  with optional per-segment allow lists (segments without it stay passive-only).
- **Observation Rest Period** — the minimum time before deployable sensors
  re-report the same endpoint/protocol pair (e.g. 15 minutes to 24 hours).
- **Sensor binaries** — platform/architecture selection and tenant artifact
  overrides for downloadable sensor builds.

Viewing requires settings read access; creating/editing requires settings
management permission.

---

## Audit

Search, view, and export your organization's full audit trail under
**Organization Settings → Audit** — the home for what used to be "Activity
Logs."

- **Filter** by date range, event type, member, and status (success / failure).
- **Inspect** any entry for timestamp, actor, action, affected resource, IP and
  browser, and changed fields.
- **Export** the filtered set to CSV or JSON for compliance audits.

Event coverage spans authentication, asset changes, discovery jobs, compliance
evaluations, and more. Retention follows the schedule you set in **Policies →
Retention Policies**. For detail, see the
[Audit Logging User Guide](./audit-logging.md).

---

## Working with Inventory & Certificates

Asset and certificate management is no longer a separate "Crypto Inventory" area
or "Workbench" — it's the **Inventory** section, viewed through **lenses** that
reshape the same data without changing pages. Switch lenses from the Inventory
view.

Lenses include **infrastructure**, **certificate**, **configuration**,
**network**, **keys**, **connections** (third-party external connections),
and **stale** (archived/aging assets), among others. For the full lens model
and how to drill through them, see
[Inventory & Lenses](../features/inventory-and-lenses.md).

### Certificates

To work with certificates, open **Inventory** and switch to the **certificate**
lens. It lists **all** certificates — sensor-discovered and manually uploaded
(shown "Unassigned" until linked to an asset). From here you can:

- See common name, issuer, expiration, key size/algorithm, associated assets,
  and risk indicators.
- Click any certificate for details, including the **Chain** tab showing the
  root → intermediate → leaf hierarchy and a chain-status indicator
  (Complete / Incomplete / Broken / Self-Signed).
- Rebuild a chain from the certificate detail view after bulk imports or
  newly discovered intermediates.

To act on expiring certificates, filter the certificate lens by expiration and
either work them as findings under **Risk & Compliance → Findings** or capture
the list with the lens **Export** button. See
[Certificate Chain Management](../features/certificate-chain-management.md).

> The old "Reports → Certificate Expiration Report" template is gone. For an
> evidence-grade certificate snapshot, generate a **CBOM artifact**; for a quick
> working list, use the certificate lens **Export**.

---

## Compliance & Frameworks

In Vista Platform, **evaluation is the product** — your inventory is
continuously evaluated against the frameworks you've activated; there's no
per-framework charge. As a Tenant Admin you decide which frameworks are active
and which is the default.

### Activating Frameworks

1. Go to **Organization Settings → Policies → Compliance Frameworks**.
2. Browse the available published frameworks. Each shows a **preview score** so
   you can see your standing before committing.
3. **Activate** the frameworks relevant to your organization (PCI DSS, NIST CSF,
   SOC 2, etc.). Your tier sets a limit on how many you can activate at once.
4. Choose one framework as the **default** — it drives dashboard compliance
   scores and the default posture view. Individual members can override the
   default with a personal preference under **My Profile → Preferences**.

> **Security Best Practices** is auto-activated for every organization, doesn't
> count toward your activation limit, and can't be deactivated. If you set no
> other default, it's the default.

### Reviewing Posture & Findings

- **Risk & Compliance → Posture** — your compliance scores, plus **Framework
  Transparency** and an **Algorithm Reference** for understanding how scores are
  computed and which controls apply.
- **Risk & Compliance → Findings** — the individual control results you act on.
  Use the **By Control** view to see each control's result. Create remediation
  work from a finding; that work lands in **Remediation → Queue**.

Each control reads **PASS** (checked, nothing violated it), **FAIL** (checked,
something violated it — at any severity), or **Not assessed** (it could not be
checked: no measurement rule, nothing in scope, or the check failed). Scores
cover assessed controls only and come with a coverage line such as *"8 of 11
controls assessed"*; a framework with nothing assessed shows **—**, never 100%.
See [Viewing Frameworks, Controls & Measurements](../features/framework-transparency.md#control-results-pass-fail-and-not-assessed).

### Custom Policies (Enterprise)

Enterprise organizations author their own frameworks — framework → controls →
measurement rules — under **Organization Settings → Policies → Custom
Policies**. Full CRUD on your own controls and measurements. See the

> The old "Copy Framework" workflow has been removed. You **activate** platform
> frameworks (you don't copy them), and Enterprise tenants build bespoke
> frameworks via **Custom Policies**.

### Remediating

Work that comes out of findings is tracked under **Remediation**:

- **Triage** — review and prioritize incoming remediation items.
- **Queue** — the unified ticket work surface (this replaces the old standalone
  Tickets page). Tickets can link to assets, certificates, configurations, and
  findings, support comments and due dates, and can reference an external system
  (Jira, ServiceNow, GitHub, PagerDuty) for manual linking.
- **Plans** — migration planning, including PQC/quantum-readiness progress.

See the [Remediation guide](../features/remediation.md).

---

## Evidence: CBOM Artifacts & Exports

The old "Reports & Analytics" area is gone, replaced by two purpose-built paths.

### CBOM Artifacts (audit-grade)

A **CBOM artifact** is an immutable, dated, content-hashed snapshot of every
cryptographic component matching a **Scope** at the moment of generation — the
right tool when you need evidence with provenance.

1. Go to **Risk & Compliance → CBOM**.
2. Generate an artifact against a **Scope** (defined under
   [Policies → Scopes](#policies)).
3. Download it as **CycloneDX 1.7** (also SPDX and PDF as those formatters
   become available).

CBOM artifacts are useful for supply-chain risk management (feed CycloneDX into
SBOM-aware tooling), federal SBOM requirements, crypto-agility audits
(deprecated algorithms, weak keys, expired certs in one signed artifact), and
audit evidence packages. You can also **compare** two artifacts to see what
improved, regressed, or drifted between them.

### Page-Local Exports (convenience)

For a quick, working spreadsheet of what's on screen, use the **Export** button
on any **Inventory** lens. It produces a CSV of the rows already loaded —
no template engine, no wait.

> **Exports are convenience, not evidence.** They have no provenance or content
> hash. When you need audit-grade output, generate a **CBOM artifact**.

---

## Best Practices

### Members & Access

- Review member access regularly and deactivate inactive members.
- Assign the narrowest role that fits each member's job.
- Encourage members to enable MFA (**My Profile → Security**).

### Security

- Configure SSO for enterprise authentication and **test** every provider
  before enabling it.
- Keep a break-glass admin password path unless you run redundant SSO
  infrastructure.

### Asset Lifecycle

- Set staleness thresholds to your scan cadence and keep the archive threshold
  above the warning threshold.
- Enable stale-asset notifications and review aging assets periodically.

### Billing

- Watch **Usage & Limits** against your plan and upgrade before you hit a cap.
- Review usage trends monthly.

### Compliance

- Activate only the frameworks relevant to your industry; set a sensible
  default for dashboard scoring.
- Work findings under **Risk & Compliance → Findings** and track remediation in
  **Remediation → Queue**.

---

## Troubleshooting

### Members Can't Sign In

1. Check the member's status (active / suspended) under **People & Access →
   Members**.
2. Verify the authentication policy under **Security & SSO** isn't blocking
   their method.
3. If using SSO, **Test** the provider and check the member's connected
   account.
4. Review **Organization Settings → Audit** for the login attempts.

### SSO Not Working

1. Recheck provider configuration on **Security & SSO** and click **Test**.
2. Confirm the callback URL is registered in your IdP and the Client
   ID/Secret or SAML certificate are valid.
3. For auto-provisioning, confirm it's enabled and that the IdP returns
   `email` and `profile`.

### Billing Issues

1. Confirm subscription status and the payment method on **Account → Billing**.
2. Check **Account → Usage & Limits** against your plan.
3. Contact platform support if the discrepancy persists.

### Compliance Looks Wrong

1. Confirm the framework is **activated** under **Policies → Compliance
   Frameworks**.
2. Confirm the **default** framework is the one you expect (and that no personal
   override is in play under **My Profile → Preferences**).
3. Check that inventory data exists and that any **Scope** you're using isn't
   excluding everything.

---

## Support

For tenant administration support:

- **Tenant user guide:** [User Guide](./tenant-user-guide.md)
- **Feature docs:** [Inventory & Lenses](../features/inventory-and-lenses.md) ·
  [Remediation](../features/remediation.md) ·
  [Scopes](../features/scopes.md)
- **Platform support:** contact your platform administrator.

---

**Last Updated:** 2026-06-24
