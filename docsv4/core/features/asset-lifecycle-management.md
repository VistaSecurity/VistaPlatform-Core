# Asset Lifecycle Management

An inventory that only ever grows is not an inventory. Things get
decommissioned, moved, replaced and forgotten, and unless something notices they
have gone quiet, your asset list slowly becomes a list of what you *used* to
have — with compliance scores and risk counts computed over ghosts.

Asset lifecycle management is how the platform notices. It watches when each
asset was last observed, tells you which ones have gone quiet, and gives you the
four things you can do about one: **rescan it**, **archive it**, **delete it**,
or **restore it**.

## Where it lives

| What | Where |
|---|---|
| The list of quiet assets, and the actions on them | **Inventory → Stale** |
| The thresholds and the automatic behaviour | **Settings → Policies → Asset Lifecycle** |
| Delete and restore for one asset | The asset's drawer, reached from a certificate, key or configuration row |

Stale is a **lens** on the one inventory, not a separate screen — the same data,
cut to the assets nothing has seen recently. Its address is
`/inventory?lens=stale`, so you can bookmark it or send it to someone.

## What "stale" means

**Nothing has observed this asset for more than 30 days.**

That is a claim about your *coverage*, not about the asset. A host behind a
firewall your sensors cannot reach is stale on its first day of life; a
decommissioned host is stale because it is genuinely gone. The platform cannot
tell those apart from silence alone, which is exactly why the lens exists — the
list is a question to answer, not a verdict to act on blindly.

Individual **endpoints** go stale on the same 30-day boundary, shown on the
asset's Services & Endpoints tab. An endpoint is only ever marked **closed** by
something that actually connected and found nothing listening; time alone never
closes one, because a measurement should not be overruled by a calendar.

The same 30 days is the first rung of the inventory-hygiene finding ladder and
the threshold in the seeded Inventory Hygiene framework, so the lens, the
finding and the compliance control all mean the same thing by the word. Findings
escalate at **30**, **90** and **180** days.

## The Stale lens

Each row shows the asset, its class, its network segment, its status and how many
days it has been quiet. Click a row to open the asset's page.

**On each row**, at the right:

- **Rescan** — queue a revalidation job for that one asset.
- **Archive** — move it to archived.

**Above the table**, a bar that acts on every stale asset on the page you are
looking at:

- **Revalidate all** — queue revalidation for all of them.
- **Archive all** — archive all of them, after a confirmation that spells out how
  many and what archiving does.

There is no row-selection checkbox. The bar acts on the current page — up to 50
assets — which is why it tells you how many that is before you click. To work
through a long list, act on a page and move to the next one.

Both bars require the **update assets** permission; without it they are not
shown.

### Rescan and revalidate

Both queue the same work: the platform re-probes the asset's endpoints using the
ordinary discovery machinery. If something answers, `last seen` moves forward and
the asset drops out of the lens on the next pass. If nothing answers, the asset
stays where it is — which is itself an answer, and the second one you get for
free.

A rescan becomes an ordinary discovery job, so it turns up under **Discovery →
Discovery Jobs** with everything else and you can watch it run there. A large
selection may be dispatched as several jobs.

### Archive

Archiving takes an asset out of active inventory and out of reporting, without
deleting anything. Discovery can bring it back on its own if the thing turns out
to still be there.

Use it when you are fairly sure something is gone but not ready to say so
permanently.

## Delete and restore

These live on the **asset drawer** — the quick-look panel that slides in when you
click through to an asset from one of the cryptography lenses. They act on one
asset that is already in front of you, which is the point: a one-click bulk
delete of a page of rows is not something anyone should be offered.

The drawer header shows whichever of these apply to the asset you are looking at:

- **Delete** asks you to confirm, then soft-deletes: the asset leaves active
  inventory but the record is kept, and it can be restored. Requires the **delete
  assets** permission. Not offered on an asset that is already deleted.
- **Restore** brings a soft-deleted or archived asset back to active inventory.
  Requires the **update assets** permission. Offered only on a deleted or
  archived asset.
- **Active Scan** probes the asset now and catalogues what it finds — faster than
  waiting for the next scheduled sweep when you just want to know whether
  something is still alive. Offered only on a live asset.
- **Edit** opens the asset form. Also on the asset page.
- **Open full page** hops from the peek to the whole record.

> Clicking a row on **All assets** or **Stale** takes you straight to the asset
> *page*, which carries **Edit** but not delete, restore or active scan. To reach
> those, open the asset through a certificate, key or configuration row — or use
> the Stale lens's own Rescan and Archive actions, which cover the same ground
> for a quiet asset.

### Permanent deletion

There is a **permanent delete** operation — it removes the asset row and its
crypto configurations for good, with no restore — but it is reachable only
through the API (`DELETE /api/v1/inventory-service/assets/:id/hard`), not from
any button. It requires the **manage assets** permission.

Everything the console offers you is reversible. If you need the irreversible
version, you have to ask for it deliberately.

## The lifecycle policy

**Settings → Policies → Asset Lifecycle**

| Setting | Default | What it does |
|---|---|---|
| **Stale warning** | 30 days | Days since last seen before an asset is flagged stale. |
| **Auto-archive after** | 60 days | Days since last seen before a stale asset is archived automatically. Must be greater than the warning threshold. |
| **Auto-archive stale assets** | On | The master switch for the automatic pass. Turn it off and nothing ages by itself — no warning flag, no archiving. The Stale lens still lists quiet assets and its actions still work; the decisions just become yours. |
| **Stale notifications** | On | Records your preference. Stale assets surface in the Stale lens and as inventory-hygiene findings; no message is sent for them today. |

**The defaults apply whether or not you have ever opened this page.** A tenant
that has never saved a policy still gets 30/60 with auto-archive on. Saving a
policy overrides the defaults; turning auto-archive off opts you out, and that
opt-out is honoured.

A background pass runs daily. It walks every tenant that has assets, reads that
tenant's effective policy, and moves assets to warning or archived accordingly.

### The drift baseline window

The same page carries one more setting, which is about change rather than
silence.

**Drift baseline** is how far back the platform looks when deciding that
something is *new*. A device class, a protocol, a listening port or a certificate
issuer first seen inside the window is reported as drift; once it has been there
for a full window it becomes part of the baseline and the finding closes.

Nothing is reported as drift until your organization has been observed for a full
window — a new tenant is never told that everything it owns is new.

Changing it needs the **update settings** permission; everyone with settings
access can see it.

## How an asset moves through the states

```
monitoring
   │  nothing observes it for the warning threshold (default 30 days)
   ▼
stale (warning)                      ← shown in Inventory → Stale
   │  ├─ Rescan / Revalidate → something answers → back to monitoring
   │  └─ nothing answers
   │     and auto-archive is on, at the archive threshold (default 60 days)
   ▼
archived                             ← out of active inventory and reporting
   │  ├─ Restore (asset drawer) → back to active inventory
   │  └─ Delete (asset drawer)
   ▼
soft-deleted                         ← record kept, restorable
   │
   ▼
permanently deleted                  ← API only, not reversible
```

You can skip steps in either direction. Archive something on day one if you know
it is gone; restore something from archived years later if it comes back.

## Reading the lens honestly

- **A long stale list on a new deployment is usually a coverage problem, not a
  decommissioning backlog.** Check that the segments those assets live in are
  actually being scanned before you archive a few hundred rows.
- **Rescan before you archive.** It costs one click per page and it turns a guess
  into a measurement.
- **Prefer archive over delete, and delete over permanent delete.** Each step
  keeps less. Nothing you archive is lost; almost nothing you soft-delete is.
- **An asset that has never been seen at all is not stale.** Staleness is computed
  from the last observation, so a record with no observation to date is absent
  from this lens rather than at the top of it — look for it under Risk → Not
  assessed instead.

## When something looks wrong

**Assets are not being flagged stale.** Check **Settings → Policies → Asset
Lifecycle**: if the warning threshold has been raised, or auto-archive turned
off, the pass may be doing exactly what you told it. Then check that `last seen`
on a sample asset is actually old — an asset a sensor keeps re-observing is not
stale however dead the service on it is.

**Rescan finds nothing.** Confirm the asset is reachable from a sensor in its
segment at all, and find the job under **Discovery → Discovery Jobs**. A rescan
that cannot get a packet to the host reports the same silence as a host that is
gone.

**The archive count seems too small.** The daily pass takes assets in order of
how long they have been quiet and works through a bounded batch, so a very large
backlog clears over several nights rather than in one.

## Related

- [Inventory and lenses](./inventory-and-lenses.md) — the Stale lens in its place among the rest
- [Discovery](./discovery.md) — what does the observing
- [Asset approval](./asset-approval.md) — how assets get into inventory in the first place
- [Findings](./findings.md) — the inventory-hygiene findings staleness raises
- [Operational context](./operational-context.md) — locations and network segments
