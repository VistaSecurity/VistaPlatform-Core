# Remediation

**Remediation** is where the work of fixing things lives. Vista Platform surfaces cryptographic weaknesses, compliance gaps, certificate problems, and operational alerts all over the platform — but the place you actually triage them, assign them, comment on them, and track them to "done" is here. It is built on one unified ticketing model, so a certificate ticket, a compliance ticket, and a remediation ticket all behave the same way and live in the same queue.

> **Looking for the old Tickets page?** It's now **Remediation → Queue.** There is no separate "Tickets" item in the profile dropdown anymore — every ticket you've ever created (from a crypto risk, a finding, an alert, or by hand) shows up in the Queue.

## Where to find it

**Remediation** is a top-level section in the main navigation. Opening it lands you on **Alerts**, with three sub-sections in the left nav:

| Sub-section | What it's for |
|---|---|
| **Alerts** | Everything the platform is asking you to look at — each with a full lifecycle and an audit-grade evidence trail |
| **Queue** | The unified ticket list — everything that's been turned into trackable work |
| **Plans** | Group related work into an initiative (e.g. a PQC migration) and watch progress as one number |

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
long ago it last changed. Filter by status (Active / Acknowledged / Snoozed
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

---

## Queue — the work list

The Queue is the heart of Remediation: every ticket, from every source, in one SLA-driven list.

### The summary cards

Across the top, five cards both summarize and filter the list. Click any card to narrow the Queue to just that slice; click it again (or **clear the filter**) to go back to all open work:

- **Open work** — everything currently open or in progress
- **Overdue** — open tickets past their due date
- **Due soon** — open tickets due within the next three days
- **Resolved** — tickets that are resolved or closed
- **Keeping pace** — the share of open work that's still on track, with a progress bar

### Reading a ticket row

Each row shows, at a glance:

- A **severity dot** (Critical / High / Medium / Low)
- The **title**, with the current status and priority underneath
- The **category** with its icon — one of **compliance, certificate, remediation, vulnerability, operational,** or **general**
- An **External** link, if the ticket is linked to an outside system (e.g. Jira or ServiceNow), showing the system name and external ID
- The **SLA** state — **Overdue**, **Due soon**, or **On track** (resolved/closed tickets show no SLA)
- The **Due** column — days remaining, or "Nd late" if it's overdue

### The ticket drawer

Click any row to open the ticket drawer on the right. It shows everything about that ticket and is where you move it forward:

- **Header** — category, title, status and priority pills, and the SLA state with days remaining or days late.
- **Advance the status** — a single button walks the ticket through its lifecycle: **Start work** (open → in progress) → **Mark resolved** (in progress → resolved) → **Close ticket** (resolved → closed).
- **Description** — the full write-up of the issue.
- **Details** — due date, who it's assigned to, where it came from, created/updated dates, and any tags.
- **Linked** — what the ticket is attached to: an asset, a certificate, a finding, a crypto configuration, and/or an external ticket (with a clickable link out to the external system when a valid web URL is present). If the ticket was created from an alert, a **View alert** link takes you straight back to that alert's evidence timeline (see [Alerts](#alerts) above).
- **Comments** — a running thread. Add a comment in the box at the bottom (⌘/Ctrl + Enter posts it) to collaborate with your team without leaving the ticket. Tickets created from an alert also receive automatic **System**-tagged comments whenever that alert changes state — an escalation, a snooze, an auto-resolution — so the ticket stays current with the underlying condition without anyone copying updates over by hand.

Status changes and comments require remediation-management permission; read-only users can view the drawer but not advance or comment.

### Due dates and SLA

Tickets can carry a **due date**. Vista Platform watches those dates continuously: anything past due is flagged **Overdue**, and anything due within three days is flagged **Due soon** — both on the row and on the summary cards, and the same windows drive the email/notification reminders. That's what keeps the Queue honest about what needs attention now versus later.

### Creating a ticket

You rarely start in the Queue — tickets flow *into* it:

- **From Alerts** — *Create ticket* on an alert (see above). The ticket inherits the alert's evidence and keeps a live link back to it.
- **From Risk & Compliance → Crypto Risks** — each risk row has **Create ticket** / **View ticket** actions. Creating one opens a pre-filled ticket tied to that specific crypto configuration; it then lands in this same Queue (category **remediation**) and **View ticket** jumps you back to it. This is the same unified ticket — there's no separate tracking surface.
- **From a finding or other surface** — wherever a *Create ticket* control appears, the resulting ticket lives here too.

Because it's one model, a ticket created from a crypto risk, a certificate problem, or a compliance finding all sort, filter, and advance identically in the Queue.

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

## A typical flow

1. An alert fires and shows up in **Alerts**. You decide it's real and **Create ticket**.
2. The new ticket appears in the **Queue**. You open it, **Start work**, assign it, and leave a comment.
3. If it's part of a larger effort (say, retiring TLS 1.0 everywhere), you add its finding to a **Plan** so leadership can watch the whole campaign in one number.
4. As you fix and verify, you **Mark resolved** then **Close** the ticket — and the plan's progress ticks up on its own.

---

## See also

- [Crypto Risks Dashboard](./crypto-risks.md) — where most remediation tickets are born; *Create ticket* / *View ticket* on each risk flows into the Queue
- [Compliance Frameworks](./compliance-frameworks.md) — framework findings that can be ticketed and grouped into Plans
- [Unified Crypto Inventory](./unified-crypto-inventory.md) — the assets, certificates, and crypto configurations a ticket can link back to
