# Asset Approval Workflow

The Asset Approval Workflow allows tenants to review and approve/deny assets discovered through network scanning before they are added to active monitoring.

## Overview

Every discovered asset takes the same path, whatever found it:
1. **Automatically processed** — discovery jobs, sensors and cloud discovery all
   feed one pipeline. There is no import step.
2. **Auto-approved** if, and only if, the asset is on a network segment with
   auto-approve enabled
3. **Reviewed** by security teams (everything else)
4. **Approved** to move to `monitoring` status
5. **Denied** to suppress from rediscovery

## The one auto-approval rule

An asset is auto-approved **only** when it falls inside a network segment you
defined with **auto-approve enabled** (Settings → Infrastructure → Network
Segments). That toggle is off by default, and it is the only control that skips
the approval queue.

Nothing else promotes an asset. Creating one by hand, importing a spreadsheet,
pulling from a CMDB, or running a discovery scan all land in **Discovery →
Approvals** unless the address is on an auto-approving segment — in which case
all of them go straight to `monitoring`. The rule does not depend on how the
asset was found.

### Which discoveries a segment auto-approves

Turning auto-approve on opens a second choice: **which discovery sources** it
covers.

| Source | Covers |
|---|---|
| **Sensor discoveries** | Anything observed on the network — passive sensor capture, active scans, device interrogation, manual creation, spreadsheet and CMDB import |
| **Cloud discoveries** | Resources read from your cloud accounts through the provider APIs you connected (AWS, Azure, GCP) |

Both are unchecked-by-default in the sense that matters: **an existing segment
covers sensor discoveries only**, exactly as it did before this setting existed.
Cloud coverage is something you tick on purpose, per segment. A new cloud VPC
segment is the one exception — it can only ever be matched by cloud
discoveries, so its sources start as cloud (with auto-approve itself still off).

Understand what you are opting into. A cloud discovery comes from your own
account, read with credentials you supplied, which is a higher-trust source than
a sensor watching whatever traffic crosses a wire — that is why it can be
auto-approved at all. But it is still inventory admitted without a human
looking: enable it for a segment when you want everything the platform finds in
that cloud account monitored automatically, not as a way to shorten a backlog.

Cloud resources are matched to a segment by the **account and region** they live
in, not by an IP address — most of them (KMS keys, buckets, managed databases)
have no address of their own. Each provider/region (or VPC, where the resource
reports one) gets its own segment, created the first time a resource is found
there, and its auto-approve toggle is per-segment like any other.

The one deliberate exception is **elevating an external connection** (Inventory
→ Connections → Elevate): that is an explicit, confirmed click on a specific
endpoint, so the click is the approval and the asset is created as `monitoring`.

## Certificates and crypto configurations are deferred until approval

While an asset is `pending_approval`, its discovered certificates and crypto
configurations are **not** written to the inventory tables. The raw findings are
held with the pending asset and **materialized when the asset is approved** —
only then do rows appear in the Certificate, Keys, and Configuration lenses and
become visible to compliance evaluation and risk scoring. Denying the asset
discards them.

This is deliberate: unapproved discoveries must not leak data into the
tenant's inventory. The practical consequence is that on a fresh deployment
with auto-approval off (the default), sensors can be discovering plenty while
Inventory shows nothing — the work is waiting in **Discovery → Approvals**.
The Inventory page shows a pending-approval banner with the count and a link
to the queue whenever assets are waiting.

## Workflow

### 1. Asset Discovery

Assets are discovered through:
- **Discovery jobs** (`POST /api/v1/inventory-service/discovery/jobs`) - **Automatically processed** by `discovery-processor-service`
- **Network sensors** (automatic discovery) - **Automatically processed** by `discovery-processor-service`
- **Cloud discovery** (`POST /api/v1/device-interrogation-service/cloud/discover`) - **Automatically processed** by `discovery-processor-service`
- Manual creation, spreadsheet import and CMDB pull - approval evaluated the same way

**Sensor Discoveries:**
- Automatically processed within seconds of submission
- Network space classification applied automatically
- Auto-approval rules evaluated automatically
- Assets created with `monitoring` (if auto-approved) or `pending_approval` status
- No manual import required

**Cloud Discoveries:**
- Automatically processed within seconds of discovery
- Written to `sensor_discoveries` table (unified pipeline)
- Network segment classification applied automatically
- Auto-approval rules evaluated automatically
- Assets created with `monitoring` (if auto-approved) or `pending_approval` status
- **Appear in Discovery Approvals modal alongside sensor discoveries**
- No manual import required

**Discovery Jobs:**
- Findings flow into the same pipeline as sensor discoveries, server-side
- Network segment classification applied automatically
- Auto-approval rules evaluated automatically
- Assets created with `monitoring` (if on an auto-approving segment) or `pending_approval` status
- No manual import required — the Discover wizard's results step reports where
  the findings went and links to Discovery → Approvals

### 2. Where the findings went

The Discover wizard's final step reports the split — how many were
auto-approved, how many are awaiting approval, and how many the pipeline is
still processing — and links to the Approvals queue. It is a report, not a
decision: no client chooses an asset's approval status.

Two counts appear because they answer different questions. **Found** is what the
scan saw; the split is what reached your inventory. They can differ: external
endpoints are recorded under Inventory → Connections rather than as assets, and
a finding with no resolvable address cannot be anchored to one. The wizard says
so rather than presenting one number as if it answered both.

### 3. Review Pending Assets

Review assets awaiting approval:

**UI:** Discovery → Approvals (also reachable from the Inventory page's
pending-approval banner, and from **Inventory → Lifecycle → Pending**, which is
a link to this page rather than a second queue)

**API:** `GET /api/v1/inventory-service/assets?status=pending_approval`

Approvals is the **single proposal queue**. Everything that wants your decision
lands here, whatever produced it, and there is no second inbox anywhere in the
product.

**Each row shows:**
- The asset's name, and its primary endpoint's address and port. An asset with
  no network endpoint — an object store, a declared service — shows a blank
  address, which is the truth rather than a missing value.
- Its **class** (Server, Switch, Object storage …), from the class taxonomy
- Its network segment or business unit
- Its **source** — see below
- The platform's confidence, when it recorded one
- When it was found

Each row also has an **open-page** button, so you can look at the whole asset
before deciding.

#### The source filter

The chips above the queue filter by where a row came from:

| Source | What it means |
|---|---|
| **Discovered** | A sensor or scan observed this on the network. |
| **Imported** | It came in through the spreadsheet import. |
| **Pulled from CMDB** | It came from a connected CMDB. |
| **Proposed by matcher** | The identification engine thinks two records are one thing — a merge proposal (below). |
| **Proposed by classifier** | A class was proposed and nothing measured it — either by the classification rules or, where those could not decide, by the learned classifier. The row itself says which. See *Class proposals* below. |
| **Proposed by assistant** | The AI assistant proposed this. Nothing is applied without a person accepting it. |

Every source is always listed, with its count — including the ones at zero, so
you can see what the queue is capable of holding and the row does not jump
around as proposals arrive. Selecting none means *all*.

### 3a. Merge proposals

When a discovery carries identifiers that match an asset you already have, but
the evidence is not conclusive, the platform does **not** guess. It raises a
**merge proposal**: a row that asks whether two records are the same physical
thing.

A proposal shows both candidates side by side, with **the identifiers that
matched highlighted on each card** — that highlighting is the evidence, and it
is what lets you answer the question rather than trust a number. Alongside it:
the platform's confidence, and which producer raised the proposal.

#### How proposals are scored

Each candidate carries a **score** — a percentage bar on its card — and,
underneath it, **the three signals that moved that score most**, with an arrow
saying whether each counted for the merge or against it.

The score is a probability, and **50% means "as likely as not"**. It is produced
by a small model that ships inside the platform: it runs locally, sends nothing
anywhere, and looks at nothing but comparisons between the two records. The
signals it weighs are things like:

| Signal | Reads as |
|---|---|
| A one-per-asset identifier matches | serial number, cloud resource id, agent id or CMDB sys_id agreeing — the strongest evidence there is |
| A tenant-unique identifier matches | SSH host key, MAC address or FQDN agreeing |
| A scope-local identifier matches | hostname or address agreeing — real evidence, but only alongside agreement about *where* |
| How many kinds agree | one serial is strong and narrow; a MAC, an FQDN and a hostname agreeing is corroboration from several angles |
| The names are alike | and, separately, whether they differ **only in a trailing number** — `web01` and `web02` are the commonest thing that looks identical and is not |
| Same or different network segment | every segment has a `db01` |
| Same or different vendor and model | a disagreement is real evidence of two things |
| How close in time the sightings are | |
| Whether two *different kinds* of source agree | a sensor and your CMDB both saying so is not the same as one collector saying it twice |

Three things the score deliberately does **not** do:

- It never decides. The order of the cards and the reasons are what it produces;
  the decision is yours, unless you set a threshold (below).
- It never sees key material, raw captures or configuration text — only the
  comparisons above.
- A score of **0%** means *nothing scored this pairing*, not "certainly wrong".
  An unscored candidate simply shows no bar.

#### Letting a high score settle it

Under **Settings → Policies → Identification rules** you can set an
**auto-accept threshold**: a score at or above it is accepted without asking you.
That page also explains which identifier decides a match in the first place —
see [Asset Classes & Identification Rules](./asset-classes.md).

The default is **Never**, and that is not a low bar — it is off. No score
bypasses it.

**The threshold applies to every sighting**, whichever way it reached us —
discovery, imports, SBOM uploads, passively observed hosts, device
interrogation, cloud collectors, and the neighbours an interrogated device
reports. One host seen two ways is one question, so which collector happened to
see it does not change the answer.

> ⚠️ **An auto-accepted merge cannot be undone from the UI today.** The sighting
> is written into the asset the matcher chose, and putting it back is manual
> work. Turn this on only once you have watched the proposals the matcher raises
> and agree with how it ranks them.

Two things are **never** auto-accepted, whatever the score:

- a sighting whose **serial number, cloud resource id, agent id or CMDB sys_id
  disagrees** with the candidate's. Two different serials are two different
  machines, and no amount of other agreement changes that;
- anything involving an asset **still waiting for approval**. Admitting an asset
  to your inventory and merging two assets are two decisions, and the threshold
  licenses only the second.

Everything the threshold does is listed on **Discovery → Approvals** under
**"Auto-merged by the matcher (last 30 days)"**, with the score, the reasons and
a link to the asset — so you can check its work. That section is absent while
the threshold is Never, because nothing can have happened.

Two actions:

- **Merge** — the records become one asset. The surviving asset's **History**
  tab records what was merged into it, so the decision is auditable and the old
  identity is not lost.
- **Keep separate** — they stay two assets, and the matcher will not propose
  this pair again.

Merging needs the same permission as approving an asset.

**Why this exists:** the same machine seen by a sensor, exported from your CMDB
and typed in by hand should be one row, not three. The platform matches them on
their identifiers automatically where it can (see
**Settings → Policies → Identification rules**), and asks you only where it
genuinely cannot tell.

**Auto-accepted proposals.** If you have set an auto-accept threshold, a
proposal the matcher settled still appears — marked **Auto-accepted into one**,
and listed separately under "Auto-merged by the matcher". Its *remaining*
candidates are still yours to decide: the threshold settled where the sighting
went, not whether every other candidate is the same thing.

### 3b. Class proposals

Vista Platform works out what a thing **is** from evidence it already collected:
the manufacturer registered to a device's MAC prefix, the model it stated over
SNMP or CDP, the services it advertises on the LAN (`_ipp._tcp` means it accepts
print jobs), the capabilities it advertises over CDP or LLDP, and the management
API it answered. Those mappings are a curated table your platform administrator
maintains — not code — so the catalogue grows without waiting for a release.

**For a newly discovered asset, there is nothing extra to do.** The class is
already on the row when it reaches this queue, and approving the asset approves
the class with it. The Class column shows what the rules decided.

**A class proposal appears when the rules disagree with an asset you already
have.** That is a separate question — "this thing you admitted as an unknown
host looks like a printer" — and the platform will not answer it for you. The
row shows:

- what the asset is classed as **now**, and what the rules say it is;
- **which rules matched**, with the pattern each one keyed on and a link to the
  source the mapping comes from. That link is the point: a rule you cannot check
  is one you can only rubber-stamp.

Two actions, both needing the same permission as approving an asset:

- **Accept** — the class changes, and the asset's **History** records which rule
  decided it, so six months later the decision can be traced back to a specific
  row rather than to "the system".
- **Reject** — nothing changes, and the same class is **not proposed again** for
  that asset. Without that, a printer advertising its print service every few
  minutes would put the same question back in your queue all day.

Three things the platform will not do here:

- **It never changes a class you set yourself.** A class a person chose is never
  proposed against, at any confidence.
- **When two rules disagree, it proposes nothing** and shows you both candidates
  instead. You pick one, or reject both — in which case the *rules* want fixing,
  and your platform administrator is who does that.
- **It never guesses.** A device nothing recognises stays `unknown host`, which
  reads as "we have not worked this out" and invites a look. A confident wrong
  answer is the one that gets bulk-approved.

#### "Proposed by model"

Some rows are marked **Model** rather than **Rule**, with a probability beside
them — *proposed by model (P=0.87)*.

That is the **learned classifier**. It only ever speaks where the curated rules
could not: either no rule recognised the device at all, or two rules disagreed
and the rules themselves refused to choose. Where a rule has an answer, the rule
wins and the model is not consulted.

It runs entirely inside your own installation. There is no external service, no
network call and nothing sent anywhere: the model is a small set of numbers
shipped inside the software, and it reads only the evidence already on the row —
the manufacturer a MAC prefix is registered to, which ports are open, what a
service banner said about itself, which services the device advertises. It never
sees a hostname, an address or a credential, because none of those is an input
to the question "what is this".

Because it cannot link you to a source the way a rule can, the row carries its
**three strongest reasons** instead — "port 9100 is open", "the MAC prefix is
registered to Hewlett Packard", "it advertises `_scanner._tcp`". Those are not a
summary of the model's reasoning; they are the arithmetic it actually did.

Four things to know about these rows:

- **They are always proposals.** A model-proposed class is *never* put on an
  asset, not even a brand-new one. A rule's class arrives already on a newly
  discovered asset and approving the asset approves it; a model's class waits
  here for a person, every time.
- **A low score never reaches you.** The model proposes only at **0.80 or
  above**. Below that it says nothing and the asset stays `unknown host` — a
  thin guess in your queue is worse than an honest blank.
- **It cannot invent a class.** It can only propose a class your classification
  rules already know about, and on a rules disagreement it can only pick one of
  the two the rules named.
- **Accepting records that a model proposed it.** The asset's **History** shows
  the class came from the model and names the exact version, so a class that
  later turns out wrong can be traced — the same way a rule-derived one names
  its rule.

Rejecting works exactly as it does for a rule proposal: nothing changes, and the
same class is not proposed for that asset again.

Your platform administrator can turn the model off without affecting the
classification rules at all — the `CLASSIFIER_MODEL_ENABLED` setting. The rules
go on proposing exactly as before, and nothing is proposed where they cannot
decide.

### 4. Approve Assets

Approve assets to add to monitoring:

**UI:** Select assets → Click "Approve"

**API:** `POST /api/v1/inventory-service/assets/approve`

**Request Body:**
```json
{
  "asset_ids": ["asset-uuid-1", "asset-uuid-2"]
}
```

**Result:**
- Assets move from `pending_approval` to `monitoring` status
- Deferred certificates and crypto configurations are materialized into the
  inventory (Certificate / Keys / Configuration lenses populate)
- Assets are included in compliance checks
- Assets are monitored for changes

### 5. Deny Assets

Deny assets to suppress from rediscovery:

**UI:** Select assets → Click "Deny"

**API:** `POST /api/v1/inventory-service/assets/deny`

**Request Body:**
```json
{
  "asset_ids": ["asset-uuid-1", "asset-uuid-2"]
}
```

**Result:**
- Assets move to `denied` status
- Assets are suppressed from future discovery
- Assets are not included in compliance checks
- Assets can be restored if needed

## Asset Status Flow

```
Sensor Discoveries:
  discovered → [auto-approval check] → monitoring (if auto-approved)
                              ↓
                    pending_approval (if not auto-approved)
                              ↓
                         [manual review]
                              ↓
                    monitoring or denied

Cloud Discoveries:
  discovered → [auto-approval check] → monitoring (if auto-approved)
                              ↓
                    pending_approval (if not auto-approved)
                              ↓
                         [manual review]
                              ↓
                    monitoring or denied

Discovery Jobs:
  discovered → pending_approval (or monitoring if on an auto-approve segment)
                              ↓
                         [manual review]
                              ↓
                    monitoring or denied
```

**Auto-Approval:**
- Sensor and cloud discoveries can both be auto-approved, per network segment
- Configured per network segment: **Settings → Infrastructure** → edit a
  segment → "Auto-approve discoveries", then pick which sources it covers —
  sensor discoveries, cloud discoveries, or both. The toggle is **off by
  default**, so a fresh tenant reviews everything, and a segment that was
  already auto-approving covers **sensor discoveries only** until you tick
  cloud.
- Auto-approved assets skip the pending approval step (their certificates and
  crypto configurations materialize immediately)
- Auto-approved assets show "Auto" badge in the approvals page

**Status Values:**
- `pending_approval` - Awaiting review and approval
- `monitoring` - Active and being monitored
- `denied` - Denied and suppressed from rediscovery
- `archived` - Archived (soft deleted via `deleted_at`, or merged into another asset)

**Note:** Assets can also have a `stale_status` of `warning` or `archived` when they haven't been seen recently. See [Asset Lifecycle Management](./asset-lifecycle-management.md) for details.

## Merge proposals

Sometimes the same physical thing is discovered twice — a server seen by a
sensor on one address and pulled from your cloud account under another, say —
and the two observations resolve to different assets. When the platform is
confident they might be one thing but not confident enough to act, it opens a
**merge proposal** instead of guessing.

Merge proposals appear in **Discovery → Approvals** alongside pending assets.
Each one shows both candidates side by side with the evidence — the identifiers
that matched — so you can see *why* it was proposed rather than being asked to
rubber-stamp it. You have two answers:

- **Merge** — you pick which asset survives; the platform never chooses for you,
  because merging is not easily undone. Everything the other asset carried moves
  across: its endpoints, identifiers, crypto configurations, facts, software
  installs, relationships and its history, so the surviving asset's timeline
  includes what happened before the merge rather than starting at it. Where both
  assets had the same endpoint or identifier, they become one, and the earliest
  first-seen and latest last-seen are kept.
- **Keep separate** — these are genuinely two things. The proposal is resolved
  and the newly-discovered asset stays in the pending queue for the ordinary
  approve/deny decision, because "this is not that" is not the same answer as
  "this belongs in inventory".

### What happens to the merged-away asset

It is **archived, not deleted**, and its ID keeps working. If a ticket, a
bookmark, a dashboard or an integration still holds the old ID, looking it up
returns the asset with `asset_status: archived` and a `merged_into` field naming
the survivor — a signpost rather than a dead end. Integrations that store asset
IDs should follow `merged_into` and replace the ID they held; the
`inventory.lifecycle.asset.merged` event carries the same pair for systems that
would rather be told than find out on their next read.

Archived assets are outside the default inventory view. To see one, filter for
it explicitly — `status:archived` in the Inventory search box.

## Bulk Operations

### Bulk Approve

Approve multiple assets at once:

**UI:** Select multiple assets → Bulk Approve

**API:** `POST /api/v1/inventory-service/assets/approve`

**Request Body:**
```json
{
  "asset_ids": ["asset-uuid-1", "asset-uuid-2", "asset-uuid-3"]
}
```

### Bulk Deny

Deny multiple assets at once:

**UI:** Select multiple assets → Bulk Deny

**API:** `POST /api/v1/inventory-service/assets/deny`

## Pending-Approval Banner

The Inventory page shows a banner whenever the tenant has anything awaiting
review — discovered assets, merge proposals, relationship proposals and class
proposals all count towards it, because Approvals is one queue and a banner that
counted only part of it would send you to a page with more work on it than the
number admitted:

**UI:** Inventory (any lens) → "N discovered assets awaiting approval" banner
with a **Review** button that opens Discovery → Approvals. The infrastructure
lens empty state also points at the queue when Inventory is empty but assets
are pending.

## Suppression from Rediscovery

When assets are denied:
- They are marked with `status: denied`
- Future discovery jobs skip these assets
- Sensors do not report these assets again
- Suppression is based on hostname/IP/port combination

## Restore Denied Assets

Denied assets can be restored:

**UI:** Assets → Denied → Select asset → Restore

**API:** `POST /api/v1/inventory-service/assets/:id/restore`

**Result:**
- Asset moves back to `pending_approval` status
- Asset can be reviewed and approved again

## Filtering by Status

Filter assets by approval status:

**UI:** Assets → Filter → Status → Select status

**API:** `GET /api/v1/inventory-service/assets?status=pending_approval`

**Available Filters:**
- `monitoring` - Approved and active
- `stale_status` - Filter by stale status: `warning`, `archived` (see [Asset Lifecycle Management](./asset-lifecycle-management.md))
- `pending_approval` - Awaiting approval
- `denied` - Denied assets
- `archived` - Archived assets

## Best Practices

1. **Review Before Approving**: Always review asset details before approval
2. **Use Network Spaces**: Classify assets into network spaces during approval
3. **Bulk Operations**: Use bulk approve/deny for efficiency
4. **Document Denials**: Document reasons for denying assets
5. **Regular Review**: Periodically review denied assets for changes

## Security Considerations

- Only users with appropriate permissions can approve/deny assets
- Approval actions are logged for audit purposes
- Denied assets are suppressed to prevent rediscovery noise
- Approval workflow can be bypassed with `auto_approve: true` (use with caution)

## Related Documentation

- [Discovery Feature](./discovery.md) - Discovery job workflow
- [Operational Context](./operational-context.md) - Network segments, which decide ownership and auto-approval
