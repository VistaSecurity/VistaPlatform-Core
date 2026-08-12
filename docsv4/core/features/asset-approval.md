# Asset Approval Workflow

The Asset Approval Workflow allows tenants to review and approve/deny assets discovered through network scanning before they are added to active monitoring.

## Overview

When assets are discovered (via discovery jobs or sensors), they can be:
1. **Automatically processed** (sensor discoveries) or **imported** (discovery jobs) with `pending_approval` or `monitoring` status
2. **Auto-approved** based on network segment rules (sensor discoveries only)
3. **Reviewed** by security teams (if pending approval)
4. **Approved** to move to `monitoring` status
5. **Denied** to suppress from rediscovery

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
- **Discovery jobs** (`POST /api/v1/inventory-service/discovery/jobs`) - Manual review and import required
- **Network sensors** (automatic discovery) - **Automatically processed** by `discovery-processor-service`
- **Cloud discovery** (`POST /api/v1/device-interrogation-service/cloud/discover`) - **Automatically processed** by `discovery-processor-service`
- Manual import

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
- Results require manual review and import
- User selects findings to import
- Can use auto-approve option during import

### 2. Import with Approval

When importing discovery results:

**UI:** Discovery Results → Import Selected

**API:** `POST /api/v1/inventory-service/discovery/jobs/:id/import`

**Options:**
- **Auto-approve**: Assets are immediately set to `monitoring` status
- **Require Approval**: Assets are set to `pending_approval` status (default)

**Request Body:**
```json
{
  "findings": ["finding-uuid-1", "finding-uuid-2"],
  "auto_approve": false
}
```

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
  discovered → [manual import] → pending_approval (or monitoring if auto-approved)
                              ↓
                         [manual review]
                              ↓
                    monitoring or denied
```

**Auto-Approval:**
- Sensor and cloud discoveries can be auto-approved based on network space rules
- Configured per network segment: **Settings → Infrastructure** → edit a
  segment → "Auto-approve discoveries" (applies to both sensor and cloud
  discoveries; **off by default**, so a fresh tenant reviews everything)
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
