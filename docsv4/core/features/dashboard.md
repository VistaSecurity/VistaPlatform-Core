# The Dashboard

The Dashboard is the page you land on, and it is written for **two different readers at once**.

Someone running the estate wants to know what is out there, what is waiting for a decision, and what has gone quiet. Someone answering to an auditor wants to know how much of it is on strong cryptography and how good the records are. Both questions are on one page, side by side, because the answers move together — an inventory nobody has curated produces a compliance score nobody should trust.

## The two heroes

### Cryptographic posture

The top panel. A risk index, a thirty-day trend and your observed third-party exposure. What proportion of your assets are at high risk, how many critical findings are open, and how many of your cryptographic configurations are already post-quantum.

### Inventory health

Directly beneath it, and the subject of the rest of this page.

| | |
|---|---|
| **Configuration items** | Everything in the inventory, whatever it is made of — not only the things that speak TLS. |
| **Pending approval** | Discovered assets nobody has accepted or denied yet. |
| **Stale** | Assets nothing has seen recently. Still in the inventory, and still counted. |
| **By class** | The estate broken down by top-level [asset class](./inventory-and-lenses.md). |
| **Data quality** | Your score on the free **Inventory Hygiene** framework. |

Every one of these is a link. The big number opens the whole inventory; **Pending approval** opens [Discovery → Approvals](./asset-approval.md), which is the one place assets are accepted or denied; **Stale** opens the inventory filtered to them; each class bar opens the inventory filtered to that class and everything beneath it in the taxonomy.

## Reading "By class"

The bars show **top-level** classes — Hardware, Virtual, Cloud resource, Application, Service, External party, Unknown host — not the specific class of each asset. Those top-level classes divide the estate exactly: every asset is in one and only one, so the bars add up to the total beside them.

Past the fifth, the rest are rolled into a single **Other** row. Other is a remainder rather than a class, so it is not clickable; expand the inventory's class facet to see what is in it.

The **Topology** link beside the heading opens the [map's topology view](./map.md#the-topology-view) — the same estate arranged by site and segment instead of by class.

## Reading "Data quality"

This is the score of **Inventory Hygiene**, one of the free [compliance frameworks](./compliance-frameworks.md) every edition ships. It asks the questions an auditor asks about the records themselves rather than about the cryptography: does every asset have an owner, a business unit, an environment; has anything gone unseen for too long; is anything still sitting unapproved.

Three numbers sit beside the gauge, and the third is the important one:

- **passing** — checks that had something to look at and were satisfied.
- **failing** — checks with at least one open finding.
- **not assessed** — checks that could not be evaluated at all, because nothing was in scope for them or no rule is configured.

A control nobody could evaluate is **not** a control that passed. Those are counted separately and are never folded into the score, which is why a small "not assessed" number beside a high score is worth a second look: the score describes the checks that ran.

### "Not assessed"

If the whole panel reads **Not assessed** rather than showing a score, one of two things is true and the panel says which:

- **Inventory Hygiene is not activated.** Activate it from Risk & Compliance → Posture. It is free, in every edition, and does not count against any framework limit.
- **It is activated but has produced no score yet.** Evaluation reconciles when assets change; it has not had anything to reconcile yet.

Neither is 100%, and neither is 0. "We have not looked" is a third answer, and this platform reports it as one everywhere rather than rounding it towards reassurance.

## When a number cannot be loaded

A tile that could not fetch its number shows a dash and says "Couldn't load", not a zero.

This matters more than it looks. Zero is the *most* reassuring thing several of these tiles can say — no assets waiting, nothing stale — and a failed request that rendered as zero would be a statement about your estate made on the strength of a request that never answered.

## The rest of the page

Below the two heroes:

- **Needs attention now** — a strip of prioritised counts across every section: critical findings, high-risk assets, certificates expiring within thirty days, unscored assets, configurations not yet post-quantum, configurations with no algorithm data at all, and overdue tickets. Each opens the page that answers it.
- **The lifecycle, end to end** — Discovery → Inventory → Risk & Compliance → Remediation, with a live number at each stage.
- **Certificate expiry outlook** and **Quantum readiness** — the two supporting charts.

"Not PQC-ready" and "Not yet assessed" are two separate tiles on the attention strip, deliberately: a configuration on classical cryptography is a migration target, and a configuration with no algorithm data is a data-quality gap. They are different jobs.

## What you need to see it

Anyone who can view assets can see the Dashboard. The individual tiles link to pages with their own permissions — approving an asset needs **assets.update**, for instance — so a tile may open a page you can read but not act on. See [Roles & Permissions](./roles-and-permissions.md).

## See also

- [Inventory & Lenses](./inventory-and-lenses.md) — the list every class bar opens
- [The Map](./map.md) — including the topology view the "By class" heading links to
- [Asset Approval](./asset-approval.md) — the queue behind "Pending approval"
- [Compliance Frameworks](./compliance-frameworks.md) — Inventory Hygiene and the rest
- [Findings](./findings.md) — what "open" means, and who produces them
