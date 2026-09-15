---
render_macros: false
---

# Asset Approval Workflow Issues

Discovery ran, and Inventory does not show what you expected. This page is
organised by **symptom**, and the first one is by far the most common — and is
not a fault at all.

> **The model this page assumes.** An asset is one **thing** — a server, a
> switch, a bucket, a service — with a **class**, the **identifiers** it is
> known by, and the **endpoints** it listens on. A host exposing five services
> is one asset with five endpoints, not five assets. Queries below read
> `assets`, `asset_identifiers`, `asset_endpoints` and `asset_history`. If you
> arrived here with older notes, see [What replaced what](#what-replaced-what)
> at the bottom.

Substitute your tenant's UUID for `<tenant>` throughout. Every query is written
against a single tenant on purpose: every table here is row-level-security
scoped, and a query without a tenant predicate is a query that will surprise
you.

---

## Symptom: discovery ran, but Inventory is empty

Sensors are reporting, batches are processed, external connections appear — and
Inventory shows nothing, with `certificates` and `crypto_implementations` at
zero rows.

**This is the designed approval workflow, not a broken pipeline.** New assets
land with `asset_status = 'pending_approval'`, and their certificates and
crypto configurations are deliberately **deferred** — held with the pending
asset — until it is approved in **Discovery → Approvals**. Only approval
materializes them into the inventory tables. Auto-approval is per network
segment and is **off by default**.

Confirm it in one query:

```sql
SELECT asset_status, count(*)
FROM assets
WHERE tenant_id = '<tenant>' AND deleted_at IS NULL
GROUP BY asset_status
ORDER BY asset_status;
```

A large `pending_approval` count and a small (or zero) `monitoring` count is the
answer: the work is waiting for a person, in **Discovery → Approvals**.

To see what is being held with each pending asset — the certificates and crypto
configurations that will appear the moment it is approved:

```sql
SELECT id,
       display_name,
       class_key,
       jsonb_array_length(COALESCE(metadata -> 'deferred_findings', '[]'::jsonb)) AS deferred
FROM assets
WHERE tenant_id = '<tenant>'
  AND asset_status = 'pending_approval'
  AND deleted_at IS NULL
ORDER BY deferred DESC
LIMIT 20;
```

`deferred_findings` is a holding pen, not an attribute of the thing: it is
drained on approval and the key disappears. A pending asset with `0` deferred
findings is normal — it means nothing cryptographic was observed on it yet.

Two things exist to make this self-evident before anyone reaches for SQL: the
discovery-processor batch log reports internal findings split by
monitoring/pending and notes the deferral rather than printing `0 asset
findings`, and the Inventory page shows a pending-approval banner with a count
and a link to the queue.

---

## Symptom: assets keep queuing when you expected auto-approval

Two independent gates decide this, and both are off until someone turns them on.

**1. The segment's own toggle, and which sources it covers.** Auto-approval is a
property of a network segment (**Settings → Infrastructure**), and a segment
that auto-approves sensor discoveries does not thereby auto-approve cloud ones:

```sql
SELECT name,
       value,
       network_type,
       auto_approve_discoveries,
       metadata -> 'auto_approve_sources' AS sources
FROM network_segments
WHERE tenant_id = '<tenant>' AND is_active
ORDER BY name;
```

`auto_approve_discoveries = false` is the default for every segment.
A `NULL` in `sources` means **sensor-only** — the default that every segment
created before the setting existed still carries. That is the usual answer when
cloud resources queue on a segment whose toggle is on.

**2. The tenant's auto-approval rules, which are queries now.** A rule is a
query-language string over the `observation` target, not a JSON object
interpreted by a hand-written evaluator:

```sql
SELECT name, is_active, query
FROM discovery_auto_approval_rules
WHERE tenant_id = '<tenant>'
ORDER BY name;
```

Read the `query` column as the rule: `class:server and environment:production`
approves exactly what it says. Two things worth knowing when one does not fire:
an **empty** query matches every observation (a rule that auto-approves
everything — deliberately expressible, and deliberately something a person has
to type), and a query is validated when it is saved, so a rule that stored at
all is a rule that parses. A rule that parses and never matches is a rule about
the wrong thing, not a typo.

---

## Symptom: the queue is full of merge proposals, and nothing new appears

**Discovery → Approvals** holds two kinds of work. Pending assets are one; the
other is a **merge proposal** — the identification engine's report that a new
sighting matched more than one existing asset, or matched one it is not
confident enough to fold into. Nothing is ever merged for you: a proposal waits
for a person to say "these are the same thing" or "keep them separate".

Merge proposals are rows in `asset_history`, not a table of their own:

```sql
SELECT seq,
       asset_id,
       created_at,
       changes_json ->> 'fingerprint' AS fingerprint,
       changes_json
FROM asset_history
WHERE tenant_id = '<tenant>'
  AND action = 'merge_proposed'
  AND COALESCE(changes_json ->> 'status', 'pending') = 'pending'
ORDER BY created_at DESC;
```

`changes_json` carries the candidate assets and the identifiers that matched
them — which is what the Approvals row renders. Deciding a proposal writes
`status` into it, so it drops out of the query above.

**One proposal per question.** A unique index on
`(tenant_id, changes_json->>'fingerprint')` for pending proposals means a
collector that re-observes the same conflict every fifteen minutes does not
deposit 96 identical work items a day. If you see many proposals with DIFFERENT
fingerprints for what looks like one machine, that is a real signal: something
is producing observations that identify differently each time.

To see why the engine thinks a particular asset is ambiguous, read its
identifiers — the scope is usually the answer, because a hostname or an IP
identifies only within its network segment:

```sql
SELECT kind, value, scope, source_kind, source_ref, last_seen_at
FROM asset_identifiers
WHERE tenant_id = '<tenant>' AND asset_id = '<asset>'
ORDER BY kind;
```

And the asset's own story, in order:

```sql
SELECT seq, action, source, actor_user_id, created_at, changes_json
FROM asset_history
WHERE tenant_id = '<tenant>' AND asset_id = '<asset>'
ORDER BY seq;
```

Order by `seq`, never by `created_at`: several history rows are written inside
one transaction and therefore carry the same timestamp, so ordering by time
returns them in whatever order the planner chose.

---

## Symptom: cloud discoveries are not reaching Inventory

Cloud discoveries go through the **same** pipeline as sensor discoveries:

1. `device-interrogation-service` discovers the cloud resources (AWS, Azure, GCP).
2. They are written to `sensor_discoveries` with
   `metadata->>'discovery_method' = 'cloud_api'`.
3. `discovery-processor-service` polls that table and processes batches.
4. A cloud discovery is classified by its `cloud_provider`/`cloud_region` — the
   per-region cloud segment — not by its address. Most cloud resources have no
   address at all, and an asset with no endpoint is a real answer rather than a
   gap: a bucket or a key store has nothing listening on a port.
5. Assets land `pending_approval` and appear in Discovery → Approvals, unless
   that cloud segment auto-approves **with cloud among its sources**.

Check that the discoveries arrived at all:

```sql
SELECT batch_id, count(*) AS rows, min(created_at) AS first_seen
FROM sensor_discoveries
WHERE metadata ->> 'discovery_method' = 'cloud_api'
GROUP BY batch_id
ORDER BY first_seen DESC;
```

Unprocessed rows:

```sql
SELECT id, batch_id, created_at
FROM sensor_discoveries
WHERE metadata ->> 'discovery_method' = 'cloud_api'
  AND processed_at IS NULL
ORDER BY created_at;
```

If rows are arriving and never processed, check the processor:

```bash
docker compose logs discovery-processor-service
```

Cloud discovery runs through the Platform Device Interrogation Agent system
sensor — verify that sensor exists and is active for the tenant.

---

## What replaced what

Older runbooks (and older habits) reach for tables and a screen that no longer
exist. A query naming any of these fails at runtime with `relation … does not
exist`, per query — which is exactly the error this codebase has historically
swallowed behind a 200, so it is worth recognising.

| If your notes say | Read instead |
|---|---|
| `network_assets` (any form) | `assets` — one row per thing, with `class_key` / `class_path` |
| an asset's `ip_address` / `port` | `asset_endpoints` — one row per network face |
| an asset's `asset_type` | `assets.class_key`, or `class_path` for a whole subtree |
| `devices` | `assets` joined to `asset_management` (a device is an asset with management configured) |
| `discovery_approval_queue` | `sensor_discoveries` + the approval state on `assets` — this table is dropped, not merely deprecated |
| "import the discovery results" | Nothing to do: a job's findings reach inventory server-side. No API accepts a caller-supplied approval status. |

## Related

- [Asset Approval](../../features/asset-approval.md) — the feature, from the
  user's side.
- [Infrastructure Assets and Crypto Configurations](../../features/network-assets-vs-crypto-implementations.md)
  — assets, endpoints, classes and what hangs off which.
- [Database Migrations](../deployment/database-migrations.md) — there is no
  separate migration file; schema changes live in `scripts/database/schema.sql`.
- [Device auto-discovery troubleshooting](../../guides/device-auto-discovery-troubleshooting.md).
