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
pending-approval banner)

**API:** `GET /api/v1/inventory-service/assets?status=pending_approval`

**Information Displayed:**
- Hostname and IP address
- Port and protocol
- **Discovery source** (Sensor, Cloud, or Job) - with filter option
- **Network ownership** (Internal, 3rd Party, Unknown)
- **Approval source** (Auto or Manual) - indicates if auto-approved
- Discovery timestamp
- Cryptographic details (TLS version, cipher suites, etc.)
- Risk level

**Filtering Options:**
- Filter by discovery source: "All Sources", "Discovery Jobs", "Sensor Discoveries", or "Cloud Discoveries"
- Filter by status: `pending_approval`, `monitoring`, `denied`
- Filter by network ownership: `internal`, `third_party`, `unknown`

**Note:** Cloud-discovered assets (from AWS, Azure, GCP) now appear in the Discovery Approvals modal alongside sensor-discovered assets, providing a unified approval workflow for all automatically processed discoveries.

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
- `archived` - Archived (soft deleted via `deleted_at`)

**Note:** Assets can also have a `stale_status` of `warning` or `archived` when they haven't been seen recently. See [Asset Lifecycle Management](./asset-lifecycle-management.md) for details.

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

The Inventory page shows a banner whenever the tenant has assets awaiting
approval:

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
- [Network Spaces Feature](./network-spaces.md) - Asset classification
