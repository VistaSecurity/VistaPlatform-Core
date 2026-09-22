# Tenant Administrator Guide

**Version:** 3.0
**Last Updated:** 2026-09-16

> **What changed in 3.0:** This guide was rewritten against the 1.0.0 console.
> Settings now has two new pages — **Policies → Classes** and **Policies →
> Identification rules** — that explain how your inventory is decided, and an
> **Integrations → AI assistant** page that says which AI capabilities this
> deployment has and gives you two switches over them. Three surfaces the 2.0
> guide described were never actually built, and have been removed from this
> guide rather than described — see [What moved where](#what-moved-where) for
> where each of those jobs is really done.

This guide is for **Tenant Administrators** — the elevated web-console users who
run Vista Platform for their organization: managing members and access,
configuring org settings, owning billing, connecting third-party systems, and
setting the policies that govern discovery, identification, compliance, and the
asset lifecycle.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [How the Console Is Organized](#how-the-console-is-organized)
3. [What Moved Where](#what-moved-where)
4. [Organization](#organization)
5. [Account: Billing & Usage](#account-billing--usage)
6. [People & Access](#people--access)
7. [Integrations](#integrations)
8. [Notifications & Alerts](#notifications--alerts)
9. [Policies](#policies)
10. [Audit](#audit)
11. [Infrastructure (Locations & Segments)](#infrastructure-locations--segments)
12. [Working with Inventory & Certificates](#working-with-inventory--certificates)
13. [Compliance & Frameworks](#compliance--frameworks)
14. [Evidence: Bills of Materials & Exports](#evidence-bills-of-materials--exports)
15. [Best Practices](#best-practices)
16. [Troubleshooting](#troubleshooting)
17. [Support](#support)

---

## Getting Started

### First Login

1. Receive your invitation email and click **Accept invitation**.
2. Choose how to sign in — set a password, or continue with a configured
   identity provider. See [Inviting Members](../features/member-invitations.md).
3. You land on the **Dashboard**.

### Getting Started Checklist

New organizations get a guided checklist. Open it any time from the **profile
chip** (your avatar, bottom of the left rail) → **Getting Started**. It walks
you through defining network segments, adding locations, and registering your
first sensor or agent. Detail: [Getting Started](../features/getting-started.md).

### The Profile Chip Menu

Your avatar at the **bottom of the left navigation rail** opens the profile
menu. This is the home for everything that isn't a lifecycle workspace:

- **Getting Started** — the onboarding checklist (shown while onboarding is live)
- **My Profile** — your personal identity, security/MFA, notification choices,
  sessions, connected SSO accounts, and personal API tokens
- **Organization Settings** — all tenant-admin configuration (this guide's
  main subject)
- **About** — version and platform information
- **Switch to Light / Dark Mode** — appearance is a personal choice, set here
- **Sign out**

> There is **no** standalone "Reports" area and **no** separate "Tickets" page.
> See [What Moved Where](#what-moved-where).

---

## How the Console Is Organized

The console has **five lifecycle sections** along the left rail. Everything a
tenant does day-to-day lives in one of these:

| Section | What it's for |
|---------|---------------|
| **Dashboard** | Priority-based health overview — cryptographic posture and inventory health, and what needs attention. |
| **Discovery** | Command Center, sensors & agents, discovery jobs, devices, active and scheduled scans, **Approvals**, job logs, and the three intake sources — Cloud, PCAP Upload and SBOM Upload. |
| **Inventory** | Your unified asset inventory, viewed through switchable **lenses**. |
| **Risk & Compliance** | **Posture** (scores, framework transparency, algorithm reference), **Findings**, and **Bills of Materials**. |
| **Remediation** | **Alerts**, **Queue** (the unified ticket work surface), and **Plans** (migration planning). |

**Organization Settings** opens from the profile chip and replaces the primary
rail with its own navigation, in this order:

| Settings section | Pages |
|---|---|
| **Organization** | Overview · Branding |
| **Account** | Billing *(Enterprise)* · Usage & Limits |
| **People & Access** | Members · Roles & Permissions · Security & SSO *(Enterprise)* |
| **Integrations** | Integrations · AI assistant |
| **Notifications & Alerts** | Routing Rules · Alert Rules · Delivery History |
| **Policies** | Compliance Frameworks · Custom Policies *(Enterprise)* · Asset Lifecycle · Scopes · Classes · Identification rules |
| **Audit** | Audit |
| **Infrastructure** | Locations · Network Segments |

Throughout this guide, "**Settings → *Section* → *Page***" means: open the
profile chip, click **Organization Settings**, then pick the page from the
settings rail.

> **The rail only lists pages you can actually use.** A page your edition does
> not include is hidden rather than shown locked, and a page your role cannot
> open shows an access notice rather than a failing screen. If a page named here
> is not in your rail, that is why.

---

## What Moved Where

### Since 1.0.0

| If you are looking for… | It is now |
|---|---|
| Three pages an earlier version of this guide described | **Never built, and now removed from this guide** rather than described. Global sensor configuration: active-scanning policy is set per network segment (**Settings → Infrastructure → Network Segments**) and per scan, and sensor binaries are downloaded from **Discovery → Sensors & Agents**. Algorithm severity ratings: published read-only under **Risk & Compliance → Posture → Algorithm Reference**. Personal app preferences: light/dark mode is the theme toggle in the profile chip menu, and there is no personal framework-default override — the organization default under **Policies → Compliance Frameworks** applies to everyone. |
| "Why is this asset classified as a Server?" | **Settings → Policies → Classes** — the taxonomy, its attributes, and what a class decides. |
| "Why did these two records become one asset?" | **Settings → Policies → Identification rules** — identifier precedence per class, and the auto-accept threshold. |
| Which AI capabilities are on, and what answers without them | **Settings → Integrations → AI assistant**. |
| Slack / PagerDuty / webhook channels, SIEM forwarding, CMDB, NetBox | All one hub: **Settings → Integrations**. |

### From the pre-rebuild console

| Old location | Where it is now |
|-------------------|-----------------|
| **Reports → Create Report** / **Reports & Analytics** | **Removed.** For evidence-grade output, generate a **Bill of Materials** (Risk & Compliance → **Bills of Materials**). For a quick spreadsheet of what's on screen, use the **Export** button on an **Inventory** lens. See [Evidence](#evidence-bills-of-materials--exports). |
| **Crypto Inventory → Certificates view** | **Inventory** → the **Certificates** lens. |
| **Crypto Workbench** (perspectives, framework selector) | Split: browse assets via **Inventory** lenses; review posture and framework transparency under **Risk & Compliance → Posture**; work findings under **Risk & Compliance → Findings**. |
| **Operations → Activity Logs** | **Settings → Audit**. |
| **Operations → Notification History** | **Settings → Notifications & Alerts → Delivery History**. |
| **Settings → General / UI Configuration** | No such pages. Org identity is **Settings → Organization → Overview**; appearance is the theme toggle in the profile chip menu. |
| **Settings → SSO / Members / Roles** | **Settings → People & Access**. |
| **Standalone Tickets page** | **Remediation → Queue.** |

---

## Organization

### Overview

**Settings → Organization → Overview** shows and edits your organization's core
details:

- **Organization name** — shown across the console
- **Primary domain** — used to match SSO and invited users
- **Billing email**
- **Organization ID** — read-only; quote it in support requests

Click **Save changes** to apply. Saved changes appear across the console after
the next sign-in or refresh. Editing needs the settings-update permission;
without it the page is read-only and the Save button is absent.

Below the details, **Licensed frameworks** lists the frameworks your
organization has activated, with a **Manage** link into
[Policies → Compliance Frameworks](#compliance--frameworks).

### Branding

**Settings → Organization → Branding** styles the console. Every edition can set
the **primary**, **secondary** and **accent** colors — a single organization
styling itself.

> **Replacing the product marks is an Enterprise capability.** Uploading your own
> logo and favicon and setting a display name are white-label features. In Core
> those three rows say so and the color pickers still work.


Branding applies to everyone in your organization. Light/dark mode is **not**
org-wide — each member sets their own from the theme toggle in the profile chip
menu.

---

## Account: Billing & Usage

**Usage & Limits** is included in every edition. The Billing page is not.

> **Self-service billing is an Enterprise capability.** A Core deployment has no
> subscription, no invoices and no payment provider, so there is nothing for a
> Billing page to show and Core does not mount one. Tier assignment and
> usage-against-limits still work.


### Usage & Limits

**Settings → Account → Usage & Limits** meters five things against your plan:
**assets monitored**, **users**, **discovery sensors**, **API calls this
period**, and **storage**. A limit of "unlimited" means no cap; a limit of zero
means a real zero. The footer says when the period resets.

---

## People & Access

### Members

**Settings → People & Access → Members** is the organization roster. Each row
shows the member, their **role**, **status** (active / inactive), **last
active** time, and which **auth methods** their account has.

**Invite member** (top right) needs the create-users permission. Enter an email,
pick a role, and send. The dialog also offers a copyable invite link for when
mail delivery is still being set up. Full flow, including what the invitee sees:
[Inviting Members](../features/member-invitations.md).

**Pending invitations** appears below the roster whenever someone has been
invited but has not joined. Each can be **resent** (which issues a fresh link and
invalidates the old one) or **revoked**.

Three per-member actions sit at the end of each row, all needing the manage-users
permission:

- **Change role** — assign a different role. It takes effect on the member's next
  request. You cannot change your own role from here.
- **Export this member's data** — downloads a JSON document of everything held
  about them: profile, the legal-document versions they accepted, their
  invitation, their API token *names*, and their activity from the last 12
  months. It never contains passwords or token values, and it states inside what
  it leaves out. Use this to answer a subject access request. Available for
  yourself too.
- **Erase personal data** — replaces the member's profile with an anonymous
  placeholder, deletes their API tokens and invitation, and removes their name
  from the activity trail. You must type `erase` to confirm, and **it cannot be
  undone**.

> **What erasure keeps, and why.** The dialog says this before it runs, and so
> does this guide, because "we erased your data" and "we kept your acceptance
> records" have to be the same conversation:
> - **Their acceptance of your legal documents** — which version, when, from
>   where. This is your evidence that they agreed to your terms.
> - **The activity trail itself**, with their identity removed. The events stay
>   so the record stays complete; a log that can be selectively rewritten proves
>   nothing.
> - **Tickets and comments they wrote**, shown as an anonymous author.
>
> It does not reach backups, personal data that happens to appear inside
> discovered certificates or key comments, or value snapshots stored in older
> activity entries.

Members are never hard-deleted.

### Roles & Permissions

**Settings → People & Access → Roles & Permissions** defines roles and what each
grants. The page needs the **manage-users** permission — the same permission
that governs every action on it — so if you can open it, you can use it.

Vista Platform ships five **built-in roles** and lets you define **custom
roles** of your own:

| Role | In one line |
|------|-------------|
| **Tenant Administrator** | Everything except changing payment details. The day-to-day admin for your organization. |
| **Security Administrator** | Full operational and security scope — assets, sensors, discovery, PCAP, compliance, alerts — plus read access to members, settings and the audit trail. No member management, no settings changes, no billing. |
| **Billing Admin** | Billing and payment, plus read-only visibility of the member list and basic settings. **No operational access at all.** Assign this to a finance contact, not your platform operator. |
| **Viewer** | Read-only across everything operational, including the audit trail. No billing. |
| **API User** | Read-only integration scope — assets, sensors, discovery, PCAP, compliance and Bills of Materials. No members, settings, audit or billing. |
| **A custom role** | The answer when none of the above fits — say a compliance analyst who reads everything and manages findings but never touches sensors. |

The full permission matrix, how to create and delete custom roles, and why some
checkboxes are locked are in
[Roles and Permissions](../features/roles-and-permissions.md).

**Built-in roles cannot be edited or deleted.** Their definitions are re-applied
on every upgrade, so an edit would be silently reverted; the screen shows them
read-only rather than accepting a change that would not survive. Custom roles are
never touched by that process.

> **Audit access is its own permission.** Tenant Administrator, Security
> Administrator and Viewer can read the audit trail; Billing Admin and API User
> cannot. Only Tenant Administrator (and any custom role you grant it to) can
> change retention policies and audit alert rules.

> **Delegating billing.** A Tenant Administrator does not hold the
> billing-update permission and cannot put it on a custom role — but *can*
> assign the built-in **Billing Admin** role to a finance contact. Being able to
> delegate a power and holding it yourself are different things, and the
> separation is deliberate.

> **Enforcement is server-side.** A member without the required permission cannot
> perform the action at all. Navigation links and buttons are hidden for members
> who lack the permission, so assigning the correct role is all you need to do.

### Security & SSO

> **Federated sign-in is an Enterprise capability.** In Core the **Security &
> SSO** entry is not in the rail, and a direct link shows an upgrade card. Local
> user accounts, invitations and roles are included in every edition.


---

## Integrations

**Settings → Integrations** is one hub for every third-party system, in four
sections. **Add connection** (top right) needs the settings-update permission.

### Configured connections

Every connection you have authenticated, as a card. **Add connection** offers
four channel types — **Email** (a recipient list), **Slack** (an incoming-webhook
URL), **Generic webhook** (a POST endpoint that receives the alert JSON) and
**PagerDuty** (an Events API v2 routing key) — and each card then offers
**test**, **configure** and **remove**.

A connection is authenticated once here and then referenced wherever it is used,
which is why the channels you add become the delivery targets in
[Notifications & Alerts](#notifications--alerts). The seeded **In-app** and
**Tenant admin email** channels are listed here alongside anything you add.


> **Outbound SIEM forwarding is an Enterprise capability, configured
> platform-wide.** Audit events are recorded and searchable here in every
> edition; only forwarding them to an external SIEM is gated.

### CMDB / ITSM sync

> **Enterprise capability.** Core does not mount the CMDB endpoints in either
> direction, so the section shows an upgrade card and no Add button. Core keeps
> the complete *internal* inventory — see
> [Working with Inventory & Certificates](#working-with-inventory--certificates).


### NetBox

> **Enterprise capability.** Core does not mount the NetBox endpoints. Discovery,
> the inventory and the network-segment editor are included in every edition.


### Available connectors

The catalogue at the bottom of the page lists **everything the platform can
integrate with**, grouped by kind, with each entry's real state:

- an **Add** button — you can connect it now, here or on the page named under it;
- an **Enterprise** tag — a real capability your plan does not include;
- a **Soon** tag — declared but not built yet. The card is dimmed and has no
  button. It is deliberately *not* offered as an upgrade: we do not sell
  something that does not exist.

The list is generated from the platform's connector registry, so it cannot drift
from what the platform can actually do.

### AI assistant

**Settings → Integrations → AI assistant** is a Core page in every edition,
because its job is to tell you the truth about this deployment rather than to
sell you something. Opening it needs the settings-update permission — its two
controls are what it exists for.

**Nothing in the platform depends on AI; every capability has a rule-based
default.** The page is built around that sentence and then proves it.

**This deployment** says which model provider is configured (if any), which model
it asks for, and how many capabilities can answer here right now.

**Capabilities** is a table of every AI seam — Asset matching, Asset
classification, Drift detection, Catalogue enrichment, Written summaries, Ask a
question, Drafting from a standard, Remediation plans — with, for each:

| Column | What it tells you |
|---|---|
| **Where** | The surface it appears on. |
| **Without AI** | What answers instead when no model does. This is the row that matters on a Core install. |
| **Status** | **On**, **Enterprise** (your edition does not include it), **No provider** (nobody has configured one — ten minutes of an administrator's time, not a purchase), or **Not yet built**. |

Those four states are kept distinct on purpose: "your edition does not include
this" and "nobody has configured a provider" send you to completely different
places.

**Your organization's controls** are two switches you own in every edition:

- **Use the AI assistant** — turn it off and no generative capability runs for
  your organization, even where the deployment has a provider. Every one of them
  falls back to the rule-based behaviour listed in the table.
- **Record the questions we send** — off by default. Off, the audit trail records
  that a call happened (which capability, which model, who asked, and a
  fingerprint of the request) but not the text anyone typed. On, it also stores
  the text. Secrets are removed before anything is sent or recorded either way.

Click **Save changes** to apply. More: [AI assistant](../features/ai-assistant.md).

---

## Notifications & Alerts

Configure how events reach your team under **Settings → Notifications & Alerts**.
Delivery channels themselves are connected in [Integrations](#integrations).

Every new organization starts **pre-wired**, so detection never fires into zero
channels. Seeded the moment the organization is created:

- an **In-app** channel (the bell feed, no configuration needed);
- a **Tenant admin email** channel, whose recipients resolve to whoever holds the
  Tenant Administrator role at the moment each message is sent — so it works
  before anyone has typed an address, and keeps working as your admins change;
- **Default critical alerts** — all sources, critical and high → in-app + email;
- **Default activity feed** — all sources, medium, low and info → in-app only.

All four are yours to edit or delete. Nothing below is required to get first
alerts; it is how you go beyond that starting point.

### Routing Rules

**Routing Rules** matches events to delivery channels. Create rules, set
**priorities** (higher-priority rules evaluate first), filter by **alert
source**, **alert type** and **severity**, and choose a **frequency** —
immediate, or a digest (hourly / daily / weekly).

### Alert Rules

This page has two parts.

The top is the **alert catalog** — the platform's built-in library of stateful
conditions it can raise a persistent alert for (see
[Remediation → Alerts](../features/remediation.md#alerts) for what these look
like once raised). For each entry you can:

- **Enable or disable** it. Entries tagged **Detector coming soon** are
  registered but not yet wired to a detector.
- **Certificate expiring** is the one type with an editable **warning ladder**.
  **Edit warning rung** sets the day count at which it first opens; **Reset to
  default** removes your rung and falls back to the 60-day product default. Each
  rung on the ladder shows where it came from — the product default, your own
  preference, or a compliance framework you have activated. **Framework rungs
  cannot be removed here**, only by deactivating that framework, because a policy
  commitment should not be silenceable from a settings toggle. Your preference
  *replaces* the product default and policy rungs are always added on top, so
  activating more frameworks can only tighten the schedule, never loosen it.
- **Known vulnerability**, **End of life** and **Drift detected** show their
  rungs but offer **no editor**. Their boundaries are not ours to move: the
  vulnerability rungs are the published CVSS severity bands, the end-of-life rungs
  are the deadline itself, and the drift rungs are the grade the drift producer
  gave the change. You can still enable, disable and route all three.

Changing anything in the catalog needs the manage-alerts permission.

Below it is the **audit alert rules** list — threshold- and pattern-based
detection over the activity log (failed-login bursts, bulk exports, privileged
actions). A separate, narrower mechanism from the catalog above; both feed the
same routing rules and channels.

### Delivery History

**Delivery History** shows every notification the platform tried to send — time,
source, type, severity, message, the channels used, and status.

Rows where **no routing rule matched** are tinted and say so in the channels
column: the event was recorded but delivered nowhere. That is the page's main
job — a misconfigured or missing rule is visible instead of silent. If those
events should reach someone, add or widen a rule under **Routing Rules**.

The **bell icon** in the header gives every member a live view of their in-app
notifications and a shortcut into the alert inbox
([Remediation → Alerts](../features/remediation.md#alerts)) without visiting
these pages at all. Each member chooses which notifications they personally
receive under **My Profile → Notifications**.

---

## Policies

**Settings → Policies** is where a Tenant Admin sets the rules that govern
compliance, identification, the asset lifecycle, data retention and BOM scoping.

| Page | What you set |
|------|--------------|
| **Compliance Frameworks** | Which frameworks are active, and which is the default. |
| **Asset Lifecycle** | Staleness thresholds, auto-archive behavior, and the drift baseline window. |
| **Scopes** | Named, versioned asset boundaries used by Bills of Materials. |
| **Classes** | Browse the asset class taxonomy and the attributes each class carries. |
| **Identification rules** | How a sighting is matched to an existing asset, and whether a high enough match may be accepted without you. |


### Classes

Every asset has exactly one **class**, and the class decides which attributes it
can carry, which CycloneDX component type it exports as, and which CMDB
configuration-item type it maps to. **Policies → Classes** is the browser for
that taxonomy — 49 classes under 7 fixed top-level branches, each with its own
attributes and its inherited ones.

It is **read-only in this release**; adding your own subclasses is planned.

Full detail: [Asset Classes and Identification Rules](../features/asset-classes.md).

### Identification rules

When something is discovered, the platform decides whether it is a thing you
already have by matching **identifiers, strongest first** — and the order is per
class, because a server can be known by the agent installed on it and a printer
cannot. This page shows that order for any class you pick, marks each identifier
**Global** or **Scoped**, and says why each sits where it does.

This is why one host seen by a sensor, pulled from your CMDB and typed in by hand
becomes **one** asset rather than three.

#### The auto-accept threshold

When the identifiers disagree, the platform does not guess — it raises a **merge
proposal** in **Discovery → Approvals** and a person decides. The card at the
bottom of this page is where you decide whether a high enough match may settle
one without you.

The steps are **Never · 70% · 80% · 90% · 95% · 99%**. **"Never" is not 0% — it
is off**, and it is the default. The setting covers **every** intake path:
discovery, spreadsheet imports, SBOM uploads, passively observed hosts, device
interrogation and cloud collectors.

> ⚠️ **An auto-accepted merge cannot be undone from this page**, and two things
> are never auto-accepted whatever the score: a sighting whose serial number,
> cloud resource ID, agent ID or CMDB sys_id *disagrees* with the candidate's,
> and anything involving an asset still waiting for approval. Everything the
> threshold does is listed under "Auto-merged by the matcher" in **Discovery →
> Approvals**, with the score and the reasons.

Changing it needs **both** settings-update and asset-update permission, because
it authorizes the platform to merge two of your assets without asking.

Full detail: [Asset Classes and Identification Rules](../features/asset-classes.md#when-the-evidence-is-ambiguous).

### Asset Lifecycle

**Policies → Asset Lifecycle** carries two time windows.

**Staleness thresholds:**

- **Stale warning** — days since last seen before an asset is flagged stale.
- **Auto-archive after** — days since last seen before a stale asset is archived.
  Must be greater than the warning threshold.
- **Auto-archive stale assets** and **Stale notifications** — two switches.

Set the warning threshold to your scan cadence, and keep the archive threshold
high enough to allow review before anything is archived. See
[Asset Lifecycle Management](../features/asset-lifecycle-management.md).

**Drift baseline** is the second window, and it answers a different question:
*how far back do we compare when deciding something is new?* A device class,
protocol, listening port or certificate issuer first seen inside the baseline
window is reported as **drift**; once it has been there for a full window it
becomes part of the baseline and the finding closes. The page states the
permitted range.

> Nothing is reported as drift until your organization has been observed for a
> full window — a new organization is not told that every asset it has is new.

Both sections need the settings-update permission to change.

### Retention Policies

**Audit-log retention is set by your platform operator, not per organization.**
A retention policy governs the audit store as a whole — every organization on
the deployment shares it — so it is configured in the platform administration
console rather than in your settings. There is no Retention Policies page in
your settings rail.

If you need a different retention period, or need to know the one in force, ask
your platform operator.

### Scopes

**Policies → Scopes** defines the named, versioned query (which assets count)
that a Bill of Materials attests to. System defaults (**All**, **Production**,
**Non-Dev/Test**) seed automatically; you can author your own. Creating and
editing scopes needs the compliance-update permission, not the settings one —
so a Security Administrator can manage them. Full detail:
[Scopes](../features/scopes.md).

---

## Audit

**Settings → Audit** is your organization's activity trail — the home for what
used to be "Activity Logs". Reading it needs the **audit-read** permission (not
the settings permission): Tenant Administrator, Security Administrator and Viewer
have it by default; Billing Admin and API User do not.

The page lists the most recent events with **actor**, **action** (failures
marked as such), **target**, and **when**. Three controls narrow the list:

- a **search** box across actor, action, event type, category and target
- an **actor** selector
- a **window** — last 24 hours, 7 days, or 30 days

> **The filters narrow what is on screen, not what is fetched.** The page loads
> the most recent events and tells you how many of the total it is showing — so a
> 30-day window can still show fewer events than 30 days' worth if the trail is
> busy.

There is **no export control on this page**. To take events away — for an
auditor, or to reach further back than the page holds — call the audit service's
export endpoint with a personal API token
(**My Profile → API Tokens**):

```
GET /api/v1/audit-service/activity-logs/export?format=csv
GET /api/v1/audit-service/activity-logs/export?format=json
```

It accepts date, event-type, category, actor, resource, compliance-tag and
success filters, returns at most 10,000 events per request, and a tenant user's
request is always scoped to their own organization. JSON carries the full record
(including which fields changed, and their old and new values); CSV is a flat
fourteen-column table. The
[Audit Logging guide](./audit-logging.md#getting-events-out) documents the
filters.

Event coverage spans authentication, asset changes, discovery jobs, compliance
evaluations, and more. Retention follows the schedule your platform operator
sets — see [Retention Policies](#retention-policies). For the full event
taxonomy and the investigation workflows, see the
[Audit Logging guide](./audit-logging.md).


---

## Infrastructure (Locations & Segments)

**Settings → Infrastructure** defines where your infrastructure lives and how
discovered assets are placed. **Discovery works best with at least one location
and one network segment**, and the Getting Started checklist asks for both.

### Locations

**Infrastructure → Locations** maintains the hierarchical physical/cloud location
registry used by Inventory and Discovery. Create hierarchical locations (region →
datacenter → rack) or cloud regions, each with an optional physical address,
cloud provider and region, and timezone. Each row shows how many assets sit
there. A segment can point at a location, so it is usually easiest to create
locations first.

### Network Segments

**Infrastructure → Network Segments** defines the boundaries Discovery scopes
scans against — and the scope inside which a hostname or IP address is treated as
unique (see [Identification rules](#identification-rules)).

**New segment** asks for a **name**, a **type** — CIDR block, IP range, domain
pattern or cloud VPC — a **value** in that type's format (validated as you type),
a **network type** and an **environment**. Location, business unit, owner email
and description are optional.

Two switches sit at the bottom:

- **Active** — whether Discovery scopes against it at all.
- **Auto-approve discoveries** — assets found here skip **Discovery → Approvals**
  and go straight to monitoring. Turning it on asks *which* sources it covers:
  **sensor discoveries**, **cloud discoveries**, or both. A cloud VPC segment
  defaults to cloud only, because no IP address ever falls inside one. See
  [Asset Approval](../features/asset-approval.md).

**Import** (top right) bulk-creates segments from a spreadsheet — see
[Spreadsheet Import](../features/spreadsheet-import.md).

Creating, editing and deleting need the settings-update permission; the list is
readable without it.

---

## Working with Inventory & Certificates

There is **one inventory** — a single dataset — and **lenses** re-angle it
without changing pages. Lenses are grouped in the Inventory rail:

| Group | Lenses |
|---|---|
| **Assets** | All assets · Map · Software |
| **Cryptography** | Certificates · Keys · Configuration · TLS · SSH · Data Protection · 3rd Party |
| **Lifecycle** | Stale · Pending (a link across to Discovery → Approvals) |

The active lens is in the page address, so a view is bookmarkable and shareable.
Full model: [Inventory & Lenses](../features/inventory-and-lenses.md).

Three things are worth an admin's attention:

- **An asset is a configuration item, not an address.** A host running five
  services is one row, with its five **endpoints** on its own page. Each endpoint
  carries its own protocol details and its own risk; the asset rolls them up.
- **Every asset has exactly one class**, and the class facet in the left rail is
  the taxonomy as a tree with counts. Picking a parent selects everything beneath
  it, and the table's columns follow the class you pick. See
  [Asset Classes](../features/asset-classes.md).
- **The query box is the filter.** Every filter you click writes into it, in the
  platform's own query language, so a view can be shared, saved, or reused as a
  Scope. See [Query](../features/query.md).

### Certificates

Open **Inventory** and switch to the **Certificates** lens. It lists **all**
certificates — sensor-discovered and manually uploaded (shown "Unassigned" until
linked to an asset). Click one to open its drawer, which shows:

- **Identity** — common name, subject, issuer, serial, subject alternative names
- **Validity** — not before, not after, days remaining
- **Key & signature** — public key algorithm and size, signature algorithm, key
  usage
- **Issuer chain** — the leaf → intermediate → root hierarchy, with an explicit
  warning when the chain is incomplete because the issuer is not in your
  inventory
- **Trust & revocation** — state, OCSP status, whether it is logged in
  Certificate Transparency, known-bad CA, deployment count
- **Fingerprints** — SHA-256 and SHA-1

To act on expiring certificates, filter the lens and either work them as findings
under **Risk & Compliance → Findings** or capture the list with the lens
**Export** button. See
[Certificate Chain Management](../features/certificate-chain-management.md).

---

## Compliance & Frameworks

**Evaluation is the product** — your inventory is continuously evaluated against
the frameworks you have activated, and there is no per-framework charge. As a
Tenant Admin you decide which are active and which is the default.

### Activating Frameworks

1. Go to **Settings → Policies → Compliance Frameworks**.
2. Browse the published catalog. Each card shows a **preview score** against your
   current inventory, so you can see your standing before committing, plus a
   coverage line such as *"8 of 11 controls assessed"*.
3. **Activate** the frameworks relevant to your organization. Your tier sets a
   limit on how many can be active at once.
4. Use **Set default** on an activated framework to make it your organization's
   default — it drives the dashboard compliance score and the default posture
   view.

> **The Default tag does not move when you set a default.** **Set default**
> records your organization's default framework, but the **Default** tag on the
> cards marks the platform's shipped default, not your choice. To confirm which
> framework is driving your scores, check **Risk & Compliance → Posture** rather
> than this page.

Activating, deactivating and setting the default need the compliance-update
permission.

> **Security Best Practices** is free and permanent for every organization. It is
> the framework the cards mark **Default**, and it is the one framework with no
> **Deactivate** control — you cannot switch it off. Every other activated
> framework can be deactivated, and any of them can be made your default.

> A framework nothing could be assessed against shows **—**, never 100%. A
> preview can never flatter itself with a score nothing earned.

### Reviewing Posture & Findings

- **Risk & Compliance → Posture** — scores, plus **Framework Transparency** and
  the **Algorithm Reference** for understanding how scores are computed and which
  controls apply.
- **Risk & Compliance → Findings** — the individual results you act on. Create
  remediation work from a finding; it lands in **Remediation → Queue**.

Each control reads **PASS** (checked, nothing violated it), **FAIL** (checked,
something violated it), or **Not assessed** (it could not be checked: no
measurement rule, nothing in scope, or the check failed). Scores cover assessed
controls only. See
[Framework Transparency](../features/framework-transparency.md#control-results-pass-fail-and-not-assessed).

### Remediating

- **Alerts** — the alert inbox: acknowledge, snooze, resolve, or turn an alert
  into a ticket. Those actions need the manage-alerts permission.
- **Queue** — the unified ticket work surface. Tickets link to assets,
  certificates, configurations and findings, support comments and due dates, and
  can reference an external system (Jira, ServiceNow, GitHub, PagerDuty).
- **Plans** — migration planning, including post-quantum readiness progress.

See [Remediation](../features/remediation.md).

> The old "Copy Framework" workflow has been removed. You **activate** platform
> frameworks rather than copying them.

---

## Evidence: Bills of Materials & Exports

The old "Reports & Analytics" area is gone, replaced by two purpose-built paths.

### Bills of Materials (audit-grade)

**Risk & Compliance → Bills of Materials** generates an immutable, dated,
content-hashed snapshot of everything matching a **Scope** at the moment of
generation. There are **four kinds**:

| Kind | Contains |
|---|---|
| **Cryptographic (CBOM)** | Every cryptographic component — certificates, keys, algorithms, protocol configurations. |
| **Software (SBOM)** | One component per distinct software *product*, with the hosts running it listed underneath — not one row per installation. |
| **Hardware (HBOM)** | One component per hardware-class asset, with its vendor, model, serial and firmware. Membership is decided by the asset's **class**, so "hardware" here means what it means everywhere else in the product. |
| **Full inventory** | Every asset in scope, typed by its class. |

Generating one needs the manage-reports permission. What each kind contains
precisely, which download formats exist in which edition, and the **OCSF event
export** for feeding a SIEM are all in
[Bills of Materials](../cbom/xbom.md); the artifact lifecycle (verify, delete,
re-download) is in [CBOM Artifacts](../cbom/cbom-artifacts.md).

### Page-local exports (convenience)

For a quick working spreadsheet of what is on screen, use the **Export** button
on an **Inventory** lens. It produces a CSV of the rows already loaded — no
template engine, no wait.

> **Exports are convenience, not evidence.** They have no provenance and no
> content hash. When you need audit-grade output, generate a Bill of Materials.

---

## Best Practices

### Members & Access

- Assign the narrowest role that still lets each member do their job.
- Review the roster periodically. For someone who has left, move them to a role
  with nothing in it, or erase their personal data if they have asked you to —
  their events stay in the audit trail either way.
- Clear out stale **pending invitations**: a live invite link is a credential.
- Encourage members to enable MFA (**My Profile → Security**).
- Keep **Billing Admin** for finance contacts only — it has no operational access
  by design, and giving it to your platform operator will not work.

### Identification & classes

- Read **Policies → Identification rules** before turning the auto-accept
  threshold on, and watch the merge proposals the matcher raises for a while
  first. **Never** is a safe default, not a timid one.
- Define network segments before running wide discovery: a hostname or IP is only
  unique inside a segment, and an unsegmented organization matches them against
  one tenant-wide scope.

### Asset lifecycle

- Set the stale-warning threshold to your scan cadence, and keep the archive
  threshold above it.
- Enable stale notifications and review aging assets periodically.

### Compliance

- Activate only the frameworks relevant to your industry, and set a sensible
  default for dashboard scoring.
- Work findings under **Risk & Compliance → Findings** and track remediation in
  **Remediation → Queue**.

### Usage

- Watch **Usage & Limits** against your plan and act before you hit a cap.

---

## Troubleshooting

### A settings page I expected is not in the rail

Two causes, and they are different: your **edition** does not include it (the
entry is hidden entirely), or your **role** cannot open it (the entry is hidden
and a direct link shows an access notice). Check
[How the Console Is Organized](#how-the-console-is-organized) for which pages are
Enterprise, and your role under
[People & Access](#people--access) for the rest.

### Members can't sign in

1. Check the member's status under **People & Access → Members**.
2. Confirm they accepted the invitation — an unaccepted one is still listed under
   **Pending invitations**, and can be resent from there.
3. Review **Settings → Audit** for the login attempts.

### Two records for the same machine

That is a **merge proposal** waiting in **Discovery → Approvals**, not a bug —
the platform refuses to guess when identifiers disagree. Decide it there, and see
[Identification rules](#identification-rules) for why it could not be settled
automatically.

### An alert reached nobody

Open **Notifications & Alerts → Delivery History** and look for tinted rows with
an empty channels column: those matched no routing rule. Add or widen a rule
under **Routing Rules**.

### Compliance looks wrong

1. Confirm the framework is **activated** under **Policies → Compliance
   Frameworks**, and that the one driving the dashboard is the default you set.
2. Check that inventory data exists, and that any **Scope** you are using isn't
   excluding everything.
3. Remember that **Not assessed** is not a failure — a control with no
   measurement rule or nothing in scope is excluded from the score rather than
   counted against you.

### The Retention Policies page is gone

Audit retention applies to the whole deployment, so it is set by your platform
operator rather than per organization. See
[Retention Policies](#retention-policies).

---

## Support

- **Tenant user guide:** [User Guide](./tenant-user-guide.md)
- **Feature docs:**
  [Asset Classes & Identification](../features/asset-classes.md) ·
  [Inventory & Lenses](../features/inventory-and-lenses.md) ·
  [Roles and Permissions](../features/roles-and-permissions.md) ·
  [Asset Approval](../features/asset-approval.md) ·
  [Remediation](../features/remediation.md) ·
  [Scopes](../features/scopes.md)
- **Platform support:** contact your platform administrator.

---

**Last Updated:** 2026-09-16
