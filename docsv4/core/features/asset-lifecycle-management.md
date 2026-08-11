# Asset Lifecycle Management

The Asset Lifecycle Management feature enables automatic detection and management of stale assets, ensuring inventory stays current and providing users with control over asset lifecycle decisions.

## Overview

Asset Lifecycle Management allows tenants to:
- Automatically detect assets that haven't been seen recently
- Configure thresholds for stale asset warnings and archiving
- Review stale assets in a dedicated management modal
- Rescan assets to verify if they're still alive
- Soft delete assets (remove from active inventory, preserve for reporting)
- Hard delete assets (permanent removal, admin-only)
- Configure lifecycle policies per tenant

## Workflow

### 1. Automatic Stale Detection

A background job runs daily (configurable) to detect stale assets:
- Queries all assets where `last_seen_at` exceeds configured thresholds
- Updates `stale_status` to `warning` or `archived` based on policy
- Sends notifications if enabled

**Default Thresholds:**
- **Warning**: 30 days since `last_seen_at`
- **Archived**: 60 days since `last_seen_at`

These defaults apply to **every** tenant, including one that has never opened
Settings and saved a lifecycle policy — you do not have to configure anything to
get stale detection. Saving a policy overrides the defaults; clearing
**Auto Archive Enabled** opts a tenant out of archiving entirely, and that
opt-out is honoured.

### 2. Review Stale Assets

**UI:** Navigate to Assets → Stale Assets

**API:** `GET /api/v1/inventory-service/assets/stale`

The stale assets modal displays:
- Hostname, IP address, port
- Stale status (warning/archived)
- Days since last seen
- Last seen timestamp

**Filtering:**
- Filter by status: All, Warning, Archived
- Pagination support

### 3. Manage Stale Assets

Users can take the following actions on selected assets:

#### Rescan Assets
**UI:** Select assets → Click "Rescan Selected"

**API:** `POST /api/v1/inventory-service/assets/stale/rescan`

Creates a discovery job targeting the selected assets to verify if they're still alive:
- If found: Updates `last_seen_at` and clears `stale_status`
- If not found: Keeps `stale_status`, notifies user

#### Archive Assets
**UI:** Select assets → Click "Archive Selected"

**API:** `POST /api/v1/inventory-service/assets/stale/archive`

Archives selected assets without removing them from inventory:
- Moves assets from `warning` to `archived` status
- Assets remain visible with an "Archived" badge
- Use this as an intermediate step before removal when you want to flag assets as inactive but retain them for reference
- Requires `assets.manage` permission

#### Remove from Inventory (Soft Delete)
**UI:** Select assets → Click "Remove from Inventory"

**API:** `DELETE /api/v1/inventory-service/assets/:id`

Soft deletes assets by setting `deleted_at`:
- Assets are removed from active inventory
- Assets are preserved for reporting and historical data
- Can be restored if needed

#### Permanently Delete (Hard Delete)
**UI:** Select assets → Click "Permanently Delete" (admin-only)

**API:** `DELETE /api/v1/inventory-service/assets/:id/hard`

Permanently deletes assets from the database:
- Requires `assets.hard_delete` permission (admin-only)
- Cannot be undone
- Removes asset and associated crypto configurations

### 4. Configure Lifecycle Policy

**UI:** Navigate to Organization Settings → Asset Lifecycle

**API:**
- `GET /api/v1/inventory-service/lifecycle/policy` - Get current policy
- `PUT /api/v1/inventory-service/lifecycle/policy` - Update policy

**Policy Settings:**
- **Stale Warning Days**: Days before marking as warning (default: 30)
- **Stale Archived Days**: Days before auto-archiving (default: 60)
- **Auto Archive Enabled**: Automatically archive stale assets (default: true)
- **Notifications Enabled**: Send notifications for stale assets (default: true)
- **Revalidation Schedule**: Configure automatic re-validation (future enhancement)

## Stale Status Visibility in the Asset Table

Assets with a stale status display inline badges in the **Status** column of the asset management table:

- **`Stale Xd`** (yellow badge, ⚠ icon) — Asset has `stale_status: warning`. The `Xd` shows days since last seen (e.g., "Stale 32d").
- **`Archived`** (orange badge) — Asset has `stale_status: archived`.

These badges appear alongside the normal asset status (monitoring, pending approval, etc.) so you can identify stale assets without opening the Stale Assets modal.

## Asset Status Flow

```
monitoring → (30 days) → warning → (60 days) → archived (automatic)
                              ↓
                     Archive Selected (manual)
                              ↓
                           archived
                              ↓
                    Remove from Inventory (soft delete)
                              ↓
                          deleted_at set
                              ↓
               Permanently Delete (hard delete, admin-only)
```

**Status Values:**
- `monitoring` - Active asset being monitored
- `warning` - Asset hasn't been seen in X days (configurable)
- `archived` - Asset hasn't been seen in Y days (configurable, Y > X)
- `deleted_at` set - Soft deleted, preserved for reporting
- Hard deleted - Permanently removed from database

## Re-validation

Re-validation uses the existing discovery infrastructure:
- Creates discovery jobs targeting existing assets
- Extracts IP addresses/hostnames from asset inventory
- Uses same discovery job system as new asset discovery
- Results update `last_seen_at` and clear `stale_status` if found

**API:** `POST /api/v1/inventory-service/assets/revalidate`

## Permissions

- **View Stale Assets**: `assets.read` or `assets.manage`
- **Rescan Assets**: `assets.manage`
- **Archive Assets**: `assets.manage`
- **Soft Delete**: `assets.delete` or `assets.manage`
- **Hard Delete**: `assets.hard_delete` (admin-only: `billing_admin`, `tenant_admin`)

## Notifications

When enabled, notifications are sent for:
- Assets becoming stale (warning status)
- Assets being auto-archived
- Re-validation completion (if assets still not found)

**Configuration:** Organization Settings → Asset Lifecycle → Notifications Enabled

## Best Practices

1. **Set Appropriate Thresholds**: Adjust warning/archived days based on your network characteristics
2. **Regular Re-validation**: Periodically rescan stale assets before removing them
3. **Review Before Deleting**: Always review stale assets before permanent deletion
4. **Use Soft Delete First**: Prefer soft delete to preserve historical data
5. **Monitor Notifications**: Enable notifications to stay informed about stale assets

## Limitations

- Maximum 1000 assets per revalidation job
- Background job runs daily (configurable via `STALE_ASSET_DETECTION_INTERVAL`)
- Hard delete requires admin permissions
- Re-validation uses existing discovery infrastructure (subject to discovery job limits)

## Troubleshooting

### Assets Not Being Detected as Stale

- Verify lifecycle policy exists for tenant
- Check `auto_archive_enabled` is true
- Verify `last_seen_at` timestamps are accurate
- Check background job is running (inventory-service logs)

### Re-validation Not Finding Assets

- Verify assets are still on the network
- Check discovery job status
- Verify IP addresses/hostnames are correct
- Check network connectivity

### Hard Delete Fails

- Verify user has `assets.hard_delete` permission
- Check user role is `billing_admin` or `tenant_admin`
- Verify asset exists and belongs to tenant

## Related Documentation

- [Discovery Feature](./discovery.md) - Asset discovery and re-validation
- [Asset Approval Workflow](./asset-approval.md) - Asset approval process
