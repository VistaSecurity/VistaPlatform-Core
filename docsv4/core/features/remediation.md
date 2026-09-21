# Remediation

**Remediation** is where the work of fixing things lives. Vista Platform surfaces cryptographic weaknesses, compliance gaps, certificate problems, and operational alerts all over the platform — but the place you actually triage them, assign them, comment on them, and track them to "done" is here. It is built on one unified ticketing model, so a certificate ticket, a compliance ticket, and a remediation ticket all behave the same way and live in the same queue.

> **Looking for the old Tickets page?** It's now **Remediation → Queue.** There is no separate "Tickets" item in the profile dropdown anymore — every ticket you've ever created (from a crypto risk, a finding, an alert, or by hand) shows up in the Queue.

## Where to find it

**Remediation** is a top-level section in the main navigation. Opening it lands you on **Alerts**, with four sub-sections in the left nav:

| Sub-section | What it's for |
|---|---|
| **Alerts** | Everything the platform is asking you to look at — each with a full lifecycle and an audit-grade evidence trail |
| **Queue** | The unified ticket list — everything that's been turned into trackable work |
| **Plans** | Group related work into an initiative (e.g. a PQC migration) and watch progress as one number |
| **Progress** | Are you keeping up? Opened against resolved over time, how long a fix takes, and where the backlog actually is |

> **Where did Triage go?** Triage was a second alert inbox, fed by audit-rule
> pattern detection. It never had anything to show: nothing persisted those
> alerts, so the page reported "Inbox zero" permanently and acknowledging one
> stored nothing. It has been removed, and `/remediation/triage` now takes you
> to **Alerts** — the inbox that does hold state. Audit-rule alerts that the
> platform tracks (failed-login bursts today) arrive there like any other
> alert, and the rest still reach you as notifications.

---

## Alerts

An **alert** is different from a one-off notification: it's a condition the
platform is actively tracking, with a status (Active, Acknowledged, Snoozed,
or Resolved) and a permanent, append-only record of everything that's
happened to it. The clearest examples today are a certificate approaching
expiry and a burst of failed logins against one account. Take the expiring
certificate — the platform doesn't send you a new warning every time it
re-checks it; it raises one alert and escalates its severity as the
deadline gets closer, driven by a warning schedule your organization
controls (see **Settings → Notifications & Alerts → Alert Rules**, described
in the [Tenant Administrator Guide](../guides/tenant-admin-guide.md#notifications--alerts)).
Compliance frameworks your organization has activated can tighten that
schedule automatically — for example, a framework requiring 30-day
certificate warnings adds that checkpoint regardless of your own
preferences, so activating a compliance commitment can only add warning,
never take it away.

### Working an alert

Each row shows the alert's severity, what it's about, its status, and how
long ago it last changed. Where the thing the alert is about has a page of
its own, the **Subject** is a link straight to it — an asset opens its
asset page, a package or a configuration opens the findings about that
exact subject, a control opens the control, a certificate opens the
certificate lens. Subjects with nowhere to go yet (a sensor, a discovery
job) stay as plain text rather than sending you to a page that cannot show
you the thing. Filter by status (Active / Acknowledged / Snoozed
/ Resolved / All) or by severity. Click a row to open the detail drawer,
which shows the full **evidence timeline** — every state change, timestamped
and attributed, from when the alert first opened through every escalation,
acknowledgement, snooze, and resolution. This is the record you'd hand an
auditor to answer "when did you know, and what did you do about it?"

From the drawer (or the row), you can:

- **Acknowledge** — mark that someone is aware and on it.
- **Snooze** — pause it for a chosen period (a day up to two weeks) with an
  optional reason, useful when you know about the issue and have a plan but
  don't need it demanding attention right now. A snoozed alert automatically
  reactivates when the snooze period ends.
- **Resolve** — close it out manually, with an optional note.
- **Create ticket** — convert the alert into a remediation ticket without
  losing anything: the ticket inherits the alert's full history up to that
  point, and every subsequent alert event (an escalation, a snooze, the
  eventual resolution) is added to the ticket automatically as a system
  comment from then on. The ticket carries a **View alert** link back to the
  live evidence drawer at all times.

An alert's severity follows the condition in **both directions**. If things get
worse — a tighter certificate deadline, a worse advisory — the alert escalates
and tells you. If things get better without the condition going away — a
partial fix drops the worst CVSS on a package, or the worst of several
end-of-life deadlines on an asset is dealt with and a milder one remains — the
alert is **lowered** to match what is actually still open, and the change is
recorded in its evidence timeline like any other. A lowered severity does not
notify anybody: the alert stays where it is, re-graded, so the list you triage
top-down by severity is telling you the truth about today rather than the worst
thing that was ever true.

Some alerts resolve themselves: when the underlying condition is observed to
have cleared — for example, a certificate gets renewed — the alert closes
automatically and records what was observed (the new expiry date, when it
was detected) as the final entry in its evidence timeline. Note that
**resolving a linked ticket does not resolve its alert** — the alert only
closes when the condition itself is actually fixed, so a ticket getting
closed can't accidentally mask a certificate that's still expiring.

> Acting on an alert (acknowledge, snooze, resolve, create ticket) requires
> permission to manage alerts. If you only see the Alerts list with no
> action buttons, your role is read-only here.

### Alerts raised from your inventory

Four alert types come straight from what Vista Platform finds in your
estate. All four are on by default and can be switched off (or routed
separately) under **Settings → Notifications & Alerts → Alert Rules**.

**Vulnerable software.** When an installed package matches a published
security advisory, you get **one alert for that installation**, not one per
CVE — because the fix is the same either way: upgrade the package. Its
severity follows the worst advisory that matched, on the standard CVSS
severity bands: Medium from CVSS 4.0, High from 7.0, Critical from 9.0. If a
worse advisory turns up later, the same alert escalates rather than a second
one appearing. It closes itself on the next inventory pass that no longer
sees the vulnerable version.

> Advisories below CVSS 4.0, and advisories the feed has not scored at all,
> are still recorded and still shown on the asset under **Findings** — they
> just don't open an alert. An advisory nobody has graded is never reported
> as harmless; it is reported as ungraded.

**End of life.** When something on an asset passes — or approaches — the date
its vendor stops shipping fixes, you get **one alert for that asset**, even if
both its operating system and its hardware are affected; the alert is graded
by whichever is worse and names both. The ladder is the deadline:

| How long you have | Severity |
|---|---|
| 180 days or less | Low |
| 90 days or less | Medium |
| Past the date | High |
| Past the date by more than a year | Critical |

How early the first alert appears depends on what it is about:
Vista Platform starts reporting hardware 180 days ahead (a refresh needs a
purchase order and a rack visit) and an operating system or a package 90 days
ahead. The alert closes itself when the next inventory pass sees an upgraded
version — or when the subject leaves your inventory.

> The severity on the alert answers "how urgent is this?", which is not the
> same question as the risk score on the finding behind it. An end-of-life
> package and an end-of-life operating system share a deadline but not a blast
> radius, so the finding grades them differently while the alert grades the
> clock. The finding is the one that moves the asset's risk score.

**Changed since baseline.** When something about an asset stops matching its
own recent history, you get **one alert for that asset** naming what changed: a
class of device never before seen on its network segment, a protocol it has not
spoken before, a different set of listening ports, or a certificate from an
issuer it has not presented. Its severity is the severity of the change itself
— a changed port profile is Low, a new issuer or an unexpected protocol is
Medium — and an asset with several changes open is graded by the worst.

> Drift is not automatically bad. Most of these are planned changes, and the
> right response to a planned one is to resolve the finding behind it: that
> tells the baseline the new behaviour is expected, and the alert closes with
> it. The alert also closes on its own once the asset is back in line with its
> baseline.

**Inventory hygiene score drop.** If your Inventory Hygiene score falls by more
than 10 points in 24 hours, you get a Medium alert naming the before and after
figures. It resolves itself when the score recovers. This is the same detector
that watches your compliance frameworks, split out as its own type because
hygiene is data quality rather than security posture — so you can route it to a
different channel, or silence it, without touching compliance alerting.

---

## Queue — the work list

The Queue is the heart of Remediation: every ticket, from every source, in one SLA-driven list.

### The summary cards

Across the top, five cards summarize **all** your tickets — not just the ones on
screen. Click any card to narrow the list to that slice:

- **Open work** — everything currently open or in progress
- **Overdue** — open tickets past their due date
- **Due soon** — open tickets due within the next three days, and not already overdue
- **Resolved** — tickets that are resolved or closed
- **Keeping pace** — the share of open work that's still on track, with a progress bar

The counts are organization-wide and do not change when you filter the list
below them: they are the total that the filtered list is a slice of. So a card
reading 120 above a list of 8 is not a contradiction — it is telling you that
your filter matched 8 of 120.

### Filtering and finding a ticket

Below the cards: filter by **category**, **status** or **assignee**, and search
titles. The list is paginated, with the total count shown on the right. Clearing
the filters returns you to all open work.

Every ticket also has its own link. Opening one puts `?ticket=<id>` in the
address bar, so you can send a colleague straight to it.

### Reading a ticket row

Each row shows, at a glance:

- A **severity dot** (Critical / High / Medium / Low)
- The **title**, with the current status and priority underneath
- The **category** with its icon — see [Categories](#categories) below
- An **External** link, if the ticket is linked to an outside system (e.g. Jira or ServiceNow), showing the system name and external ID
- The **SLA** state — **Overdue**, **Due soon**, or **On track** (resolved/closed tickets show no SLA)
- The **Due** column — days remaining, or "Nd late" if it's overdue

### The ticket drawer

Click any row to open the ticket drawer on the right. It shows everything about that ticket and is where you move it forward:

- **Header** — category, title, status and priority pills, and the SLA state with days remaining or days late.
- **Advance the status** — a single button walks the ticket through its lifecycle: **Start work** (open → in progress) → **Mark resolved** (in progress → resolved) → **Close ticket** (resolved → closed).
- **Description** — the full write-up of the issue.
- **Details** — due date, who it's assigned to (by name), where it came from, created/updated dates, any tags, and the resolution notes once it is resolved.
- **Edit** — change anything about the ticket: reassign it, change its priority, severity or category, set or clear the due date, edit the description and tags, record resolution notes, or attach a link to a ticket in Jira, ServiceNow, GitHub or PagerDuty. Clearing the due date is allowed, but a ticket without one does not appear in any of the SLA views above.
- **Linked** — what the ticket is attached to: an asset, a certificate, a finding, a crypto configuration, and/or an external ticket (with a clickable link out to the external system when a valid web URL is present). If the ticket was created from an alert, a **View alert** link takes you straight back to that alert's evidence timeline (see [Alerts](#alerts) above).
- **Comments** — a running thread. Add a comment in the box at the bottom (⌘/Ctrl + Enter posts it) to collaborate with your team without leaving the ticket. Tickets created from an alert also receive automatic **System**-tagged comments whenever that alert changes state — an escalation, a snooze, an auto-resolution — so the ticket stays current with the underlying condition without anyone copying updates over by hand.

Editing, advancing and commenting require remediation-management permission;
read-only users can open the drawer and read everything, but not change it.
**Creating** a ticket is different — see below.

### Deleting a ticket

**Edit → Delete ticket**, at the bottom of the edit panel, behind a
confirmation.

Most tickets should end their life **closed**, not deleted: a closed ticket
still counts in your history, still shows in Progress, and still tells the
story of what was found and fixed. Delete is for the ones that should never
have existed — a duplicate, a test, something filed against the wrong thing.

What happens:

- The ticket and **its entire comment thread** are removed for everyone. This
  cannot be undone.
- If it came from an alert, **the alert stays open** and keeps its full
  evidence timeline. It simply stops showing a link to a ticket that no longer
  exists.
- If it was part of a **Plan**, the plan item survives and becomes unlinked —
  the finding behind it is still real.
- The deletion is **recorded in the audit trail** under the name of whoever did
  it, together with the ticket's details: title, category, status, priority,
  assignee, due date, tags and everything it was linked to. Because the ticket
  itself is gone, that audit entry is the only remaining record of it — which
  is exactly why it holds the whole ticket rather than just an ID.

Deleting requires remediation-management permission, even though **creating**
does not. Reporting a problem and destroying the record of one are not the same
authority.

### Due dates and SLA

Every ticket gets a **due date**. Vista Platform watches those dates
continuously: anything past due is flagged **Overdue**, and anything due within
three days is flagged **Due soon** — on the row, on the summary cards, and in
the email and in-app reminders.

A ticket the platform files for you is dated from its priority:

| Priority | Due in |
|---|---|
| Critical | 7 days |
| High | 14 days |
| Medium | 30 days |
| Low | 60 days |

These are starting points, not commitments your organization has made — change
any of them when you file or edit the ticket. The shortest is deliberately a
week rather than a day or two, so a new ticket is never born already flagged
"due soon"; a warning that is on from the moment a ticket exists is a warning
people learn to ignore.

You can clear a due date entirely. A ticket without one never appears as
overdue or due soon, is not counted in **Keeping pace**, and generates no
reminders — which is occasionally what you want for a genuinely open-ended
piece of work, and almost never what you want otherwise.

### Creating a ticket

**New ticket**, top right of the Queue, opens a blank ticket for anything you
want tracked — whether or not Vista Platform found it itself. Give it a
title, pick a category, and optionally set a priority, severity, due date,
assignee, tags and a link to an external ticket. The due date is filled in for
you from the priority; change it freely.

**Anyone in your organization can file a ticket**, including read-only users.
Reporting a problem and triaging it are different jobs: the person who notices
something is often not the person who can fix it, and requiring permission to
report would mean only the people who could already fix a problem could raise
it. Changing a ticket afterwards still requires remediation-management
permission.

Tickets also flow *into* the Queue from elsewhere:

- **From Alerts** — *Create ticket* on an alert (see above). The ticket inherits the alert's evidence and keeps a live link back to it.
- **From Risk & Compliance → Findings** — each finding and crypto risk has a **Create ticket** action. Creating one opens a pre-filled ticket tied to that exact subject, categorized to match what the finding is about, and it lands in this same Queue. This is the same unified ticket — there's no separate tracking surface.

Because it's one model, a ticket you typed by hand and a ticket raised from a
compliance finding sort, filter, and advance identically.

### Categories

A ticket's **category** says what it is about. There is one for each kind of
problem Vista Platform detects, plus three for work that comes from
somewhere else:

| Category | What it covers |
|---|---|
| **Compliance** | A framework control your inventory is failing |
| **Cryptography** | A weak cipher, protocol version or key size |
| **PQC migration** | Quantum-vulnerable cryptography that needs migrating |
| **Certificate** | Certificate lifecycle — expiry, revocation, a broken chain |
| **Vulnerability** | A known CVE in software installed on an asset |
| **End of life** | An operating system, package or device past end-of-life or end-of-support |
| **Inventory hygiene** | A gap in the inventory record itself — no owner, no class, no location, stale, or a suspected duplicate |
| **Configuration** | Insecure exposure — plaintext management, default credentials, a service that should not be reachable |
| **Drift** | Something changed against its baseline — a new issuer, an unexpected protocol, a changed port profile |
| **Operational** | The platform itself — a sensor or agent offline, a service not responding |
| **General** | Anything else worth tracking |

A ticket raised from a finding is categorized automatically to match the finding.

> **Tickets filed before this split** carry a **Remediation** category, which
> was the single catch-all the platform used for most automatic tickets. Those
> tickets still work exactly as they did and you can still filter for them —
> they simply cannot be created any more. Re-categorize one by editing it.

---

## Plans — track an initiative end to end

A single ticket is one fix. A **Plan** is a *campaign* — a group of related findings you want to drive to completion as one initiative, with a single progress number. The classic example is a **PQC (post-quantum cryptography) migration**: dozens of findings across many systems that you want to manage as one program rather than one ticket at a time.

The Plans page shows a card per plan, each with:

- An icon for the **plan type** — Remediation, **PQC migration**, Framework, or Custom
- The **item count** and **target date** (with an overdue/due-in label)
- A big **percent-complete** number, a **resolved / total** count, and a progress bar
- **Status** (draft, active, completed, cancelled) and **priority** pills

### Creating a plan

Click **New plan**, give it a title and optional description, pick a **type** (Remediation, PQC migration, Framework, or Custom) and a **priority**, and create it. New plans start as a **draft**.

### Working a plan

Click a plan card to open its drawer:

- **Advance the plan** — move it **draft → active → completed** with one button.
- **Items** — the findings rolled into this plan. Use **Add finding** to pull an open finding into the plan, or remove one with the **✕**. Each item shows its severity and whether it's already been ticketed, plus its current status.
- **Progress** — the percentage and resolved/total counts update as the underlying work moves.

One important rule: **an item's status mirrors its linked finding or ticket.** You don't advance individual items inside the plan — you advance the *ticket* over in the Queue, and the plan's progress reflects it automatically. The plan is the rollup; the Queue is where the per-item work happens.

> Creating plans, adding/removing items, and advancing a plan require remediation-management permission. Read-only users can view plans and progress.

---

## Progress — are you keeping up?

The Queue tells you what is open right now. **Progress** tells you whether that
number is getting better or worse.

Pick a window (7, 30 or 90 days) and the page shows:

- **Opened** and **Resolved** in that window, and a **Keeping up** ratio of one
  against the other. Above 1.0× means you closed more than arrived and the
  backlog is shrinking; below 1.0× means it is growing. With nothing opened in
  the window there is no ratio to report, and the page says so rather than
  printing a number it cannot compute.
- **Avg resolution** — how long a ticket takes from opened to resolved.
- **Opened vs resolved** — a day-by-day bar for the window, so a bad week is
  visible as a bad week rather than averaged away.
- **Where the work is** — open tickets per category, ordered by how much is
  still open rather than by how many there have ever been. Click a category to
  open the Queue filtered to it.
- **Quantum readiness** — the share of your cryptographic configurations that
  need no post-quantum migration, split into PQC-ready, symmetric (nothing to
  migrate), needs migration, and unclassified. **Unclassified counts against
  readiness** rather than being assumed safe: a configuration whose algorithms
  could not be resolved is an unknown, not a pass.

---

## A typical flow

1. An alert fires and shows up in **Alerts**. You decide it's real and **Create ticket**.
2. The new ticket appears in the **Queue**. You open it, **Start work**, assign it, and leave a comment.
3. If it's part of a larger effort (say, retiring TLS 1.0 everywhere), you add its finding to a **Plan** so leadership can watch the whole campaign in one number.
4. As you fix and verify, you **Mark resolved** then **Close** the ticket — and the plan's progress ticks up on its own.
5. At the end of the month, **Progress** tells you whether you closed more than arrived.

---

## See also

- [Crypto Risks Dashboard](./crypto-risks.md) — where most remediation tickets are born; *Create ticket* / *View ticket* on each risk flows into the Queue
- [Compliance Frameworks](./compliance-frameworks.md) — framework findings that can be ticketed and grouped into Plans
- [Inventory & Lenses](./inventory-and-lenses.md) — the assets, certificates, and crypto configurations a ticket can link back to
