# Dashboards

There are four dashboards, in the **Dashboard** section of the left rail:

| | |
|---|---|
| **[Overview](#overview)** | The page you land on. Everything, across every section. |
| **[Assets](#assets)** | Your configuration items — composition, lifecycle, and how complete the records are. |
| **[Compliance](#compliance)** | Where you stand against each framework, and how the remediation is moving. |
| **[PQC](#pqc)** | Post-quantum readiness, and exactly what has to be replaced. |

Overview is unchanged and remains the default. The other three are not summaries of it — each goes deeper into one question than a shared page has room for.

The rule they all follow: **every number links to the list it counted.** If a bar says 40, the page it opens shows those 40 and nothing else. Where a number has no such list — a few breakdowns have no equivalent filter — the row is deliberately not clickable rather than dropping you on an unfiltered page.

## Overview

The page you land on, and it is written for **two different readers at once**.

Someone running the estate wants to know what is out there, what is waiting for a decision, and what has gone quiet. Someone answering to an auditor wants to know how much of it is on strong cryptography and how good the records are. Both questions are on one page, side by side, because the answers move together — an inventory nobody has curated produces a compliance score nobody should trust.

### The two heroes

#### Cryptographic posture

The top panel. The headline is the **percentage of monitored assets that are high-risk**, with the numerator and denominator shown beside it. It is a population share, so it does not receive an individual-risk band. An empty monitored population shows a dash rather than 0%. The panel also shows the thirty-day individual-risk trend, observed third-party exposure, open critical findings, and post-quantum adoption.

#### Inventory health

Directly beneath it, and the subject of the rest of this page.

| | |
|---|---|
| **Configuration items** | Everything in the inventory, whatever it is made of — not only the things that speak TLS. |
| **Pending approval** | Discovered assets nobody has accepted or denied yet. |
| **Stale** | Assets nothing has seen recently. Still in the inventory, and still counted. |
| **By class** | The estate broken down by top-level [asset class](./inventory-and-lenses.md). |
| **Data quality** | Your score on the free **Inventory Hygiene** framework. |

Every one of these is a link. The big number opens the whole inventory; **Pending approval** opens [Discovery → Approvals](./asset-approval.md), which is the one place assets are accepted or denied; **Stale** opens the inventory filtered to them; each class bar opens the inventory filtered to that class and everything beneath it in the taxonomy.

### Reading "By class"

The bars show **top-level** classes — Hardware, Virtual, Cloud resource, Application, Service, External party, Unknown host — not the specific class of each asset. Those top-level classes divide the estate exactly: every asset is in one and only one, so the bars add up to the total beside them.

Past the fifth, the rest are rolled into a single **Other** row. Other is a remainder rather than a class, so it is not clickable; expand the inventory's class facet to see what is in it.

The **Topology** link beside the heading opens the [map's topology view](./map.md#the-topology-view) — the same estate arranged by site and segment instead of by class.

### Reading "Data quality"

This is the **percentage score** of **Inventory Hygiene**, one of the free [compliance frameworks](./compliance-frameworks.md) every edition ships. It asks the questions an auditor asks about the records themselves rather than about the cryptography: does every asset have an owner, a business unit, an environment; has anything gone unseen for too long; is anything still sitting unapproved. The gauge shows `%` and uses Inventory Hygiene's existing green/amber/red feedback; those colours are not individual-risk bands.

Three numbers sit beside the gauge, and the third is the important one:

- **passing** — checks that had something to look at and were satisfied.
- **failing** — checks with at least one open finding.
- **not assessed** — checks that could not be evaluated at all, because nothing was in scope for them or no rule is configured.

A control nobody could evaluate is **not** a control that passed. Those are counted separately and are never folded into the score, which is why a small "not assessed" number beside a high score is worth a second look: the score describes the checks that ran.

#### "Not assessed"

If the whole panel reads **Not assessed** rather than showing a score, one of two things is true and the panel says which:

- **Inventory Hygiene is not activated.** Activate it from Risk & Compliance → Posture. It is free, in every edition, and does not count against any framework limit.
- **It is activated but has produced no score yet.** Evaluation reconciles when assets change; it has not had anything to reconcile yet.

Neither is 100%, and neither is 0. "We have not looked" is a third answer, and this platform reports it as one everywhere rather than rounding it towards reassurance.

### The rest of the page

Below the two heroes:

- **Needs attention now** — a strip of prioritised counts across every section: critical findings, high-risk assets, certificates expiring within thirty days, unscored assets, configurations not yet post-quantum, configurations with no algorithm data at all, and overdue tickets. Each opens the page that answers it. The critical-findings count is across **every** finding producer (config, drift, EOL, vulnerability, hygiene, crypto and compliance), not just crypto — see [Findings → Where to find them](./findings.md#where-to-find-them) for exactly what the tile counts and what its drill-through shows.
- **The lifecycle, end to end** — Discovery → Inventory → Risk & Compliance → Remediation, with a live number at each stage.
- **Certificate expiry outlook** and **Quantum readiness** — the two supporting charts.

"Not PQC-ready" and "Not yet assessed" are two separate tiles on the attention strip, deliberately: a configuration on classical cryptography is a migration target, and a configuration with no algorithm data is a data-quality gap. They are different jobs.

## Assets

**Dashboard → Assets.** The estate as configuration items: what you have, who owns it, where it runs, and what you do not know about it.

- **Configuration items** — the total, with its **thirty-day movement**. A tenant still onboarding sees a large increase and no percentage: a percentage needs a previous count to be a percentage *of*.
- **Needs a decision** — pending approval, stale, unscored, and assets with no endpoints to probe.
- **Composition** — the estate by class, environment, business unit and ownership.
- **Lifecycle and provenance** — by status, freshness, how each asset was discovered, and risk band.
- **Record quality** — your [Inventory Hygiene](./compliance-frameworks.md) score, the same one Overview shows.
- **Attribute coverage** — the share of assets carrying each attribute *at all*. This is the number the breakdowns above cannot tell you: a business-unit chart showing a clean three-way split is far less useful if only a fifth of the estate has a business unit recorded. A low figure here is a data-quality gap, not a risk.

## Compliance

**Dashboard → Compliance.** Where you stand, as opposed to what to do about it — that is [Posture](./compliance-frameworks.md), which is still where you work a framework control by control.

- **Overall compliance** — the severity-weighted score across your activated frameworks, and how many of the catalogue you have activated.
- **Posture trend** — the same thirty-day risk index Overview shows.
- **Open findings** — active findings and the four severity rungs, across **every** producer. Each opens the Findings page filtered to that severity.
- **Frameworks** — a card per framework with its score, ranked activated-first and then worst-score-first. A framework you have not activated shows a **Preview** badge: that score is what you *would* score, not an obligation you hold. Each card carries the coverage line — "12 of 20 controls assessed" — because 92% over three assessed controls is not a 92% framework.
- **Top exposures** — active findings grouped by the control that failed.
- **Finding workflow** — new, notified, resolved, suppressed and resurfaced. These are shown as separate rows rather than one stacked bar, because they do not divide the findings between them: a resurfaced finding is also counted in its current state.
- **Remediation** — tickets raised, how many are overdue, and the share on track.

## PQC

**Dashboard → PQC.** Post-quantum readiness, and the migration worklist.

Classification follows **NIST IR 8547**, which deprecates classical asymmetric cryptography (RSA, ECDSA, EdDSA, DH, ECDH) after **2030** and disallows it after **2035**. Every crypto configuration is classified **exactly once** into one of four categories, so they add up to your total:

| | |
|---|---|
| **PQC-ready** | Uses post-quantum algorithms and no classical asymmetric ones. |
| **Symmetric-safe** | Uses no asymmetric cryptography at all, so there is nothing to migrate. |
| **Needs migration** | Has at least one classical asymmetric component. |
| **Not yet assessed** | Its algorithms did not resolve against the catalogue. An unknown, not a pass. |

"Needs migration" and "Not yet assessed" are kept apart throughout. Folding the second into the first would overstate your migration workload by exactly the number of things nobody has looked at yet.

### The migration worklist

The part of this page you act on: each algorithm family in use that a quantum computer breaks, biggest first, with the catalogue's recommended post-quantum replacement beside it. Where the [algorithm catalogue](./algorithm-reference.md) has no recommendation for a family, the row says so rather than suggesting one.

**These counts do not add up to your configuration total, and are not meant to.** A configuration is counted under every algorithm family it uses, so one TLS configuration appears under its key exchange, its signature algorithm and its cipher at once. The four categories above are the partition; this is a worklist.

Beside it, **Already quantum-safe** lists the families needing no action. AES appears here, not on the worklist: AES is not a post-quantum algorithm and never will be, but at its key sizes it is quantum-safe, and putting every symmetric cipher you own on a list of things to replace would be wrong.

### What if I have no cryptography yet?

The gauge reads **—**, not 0%. Readiness is measured over discovered crypto configurations; nothing discovered means nothing to assess, which is a different statement from "none of your cryptography is safe."

## When a number cannot be loaded

On every dashboard, a tile that could not fetch its number shows a dash and says "Couldn't load", not a zero.

This matters more than it looks. Zero is the *most* reassuring thing several of these tiles can say — no assets waiting, nothing stale — and a failed request that rendered as zero would be a statement about your estate made on the strength of a request that never answered.

## What you need to see it

Anyone who can view assets can see all four dashboards. The individual tiles link to pages with their own permissions — approving an asset needs **assets.update**, for instance — so a tile may open a page you can read but not act on. See [Roles & Permissions](./roles-and-permissions.md).

## See also

- [Inventory & Lenses](./inventory-and-lenses.md) — the list every class bar opens
- [The Map](./map.md) — including the topology view the "By class" heading links to
- [Asset Approval](./asset-approval.md) — the queue behind "Pending approval"
- [Compliance Frameworks](./compliance-frameworks.md) — Inventory Hygiene and the rest
- [Findings](./findings.md) — what "open" means, and who produces them
