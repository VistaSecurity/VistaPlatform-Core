---
render_macros: false
---

# Asset Approval Workflow Issues - Resolution Documentation

**Date:** December 9, 2025  
**Status:** ✅ Fully Resolved - All Issues Fixed and Tested

> **Reading note (2026-08).** The rule this page states — *auto-approval is per
> network segment (Settings → Infrastructure) and is off by default* — is
> current, and now applies to **every** path into inventory: discovery jobs,
> sensors, cloud, manual creation, spreadsheet import and CMDB pull.
>
> What is historical is the **import step**. The transcripts below show findings
> being imported from the Discovery Results screen; that step no longer exists.
> A job's findings reach inventory server-side, and no API accepts a
> caller-supplied approval status. See
> [Asset Approval](../../features/asset-approval.md).

## Issues Reported

### 1. Assets Visible Before Approval
**Problem:** Assets imported from discovery results were visible in the main assets list even though they had not been approved yet.

**Expected Behavior:** Assets should only be visible in the main assets window after they have been approved. Pending approval assets should only appear in the "Discovery Approvals" modal.

### 2. 404 Error When Clicking Asset Row
**Problem:** When clicking on an asset row in the assets list, the system returned a 404 error when trying to fetch asset details.

**Error:** `GET http://localhost:8080/api/v1/inventory-service/assets/{id} 404 (Not Found)`

### 3. 404 Error When Approving Assets
**Problem:** Attempting to approve assets from the "Discovery Approvals" modal resulted in a 404 error.

**Error:** `POST http://localhost:8080/api/v1/inventory-service/assets/approve 404 (Not Found)`

### 4. Missing Pending Count Badge
**Problem:** The "Discovery Approvals" button did not show a counter indicating how many assets are pending approval.

**Expected Behavior:** The button should display a badge with the count of pending approval assets.

## Root Causes Identified

### Issue 1: Missing `asset_status` Column
**Root Cause:** The `network_assets` table was missing the `asset_status` column, even though it was defined in `schema.sql`. This meant:
- Assets could not be properly filtered by status
- The approval workflow could not function
- Default filtering to exclude pending assets was not working

**Investigation:**
- Database schema check revealed the column did not exist
- Code references to `asset_status` were failing silently or causing errors
- Migration script was needed to add the column to existing databases

### Issue 2: Route Registration Order
**Root Cause:** The `/approve` and `/deny` routes were registered **after** the `/:id` route in Gin's router. Gin matches routes in registration order, so requests to `/api/v1/inventory-service/assets/approve` were being matched by the `/:id` route first, treating "approve" as an asset ID.

**Investigation:**
- Routes were not appearing in Gin's debug logs
- Testing showed GET requests to `/assets/approve` returned "Invalid asset ID" (from `/:id` handler)
- Route registration order was incorrect in `services/inventory-service/cmd/main.go`

### Issue 3: Service Binary Not Updated
**Root Cause:** After fixing the route ordering, the Docker container was still running an old binary that didn't include the route changes. Multiple rebuilds were required to ensure the latest code was included.

**Investigation:**
- Log statements added to verify route registration were not appearing
- Binary timestamp showed it was from an earlier build
- Required full rebuild without cache to ensure latest code

## Solutions Implemented

### Solution 1: Database Migration
**File:** now folded into `scripts/database/schema.sql` (there is no separate migration file — see [Database Migrations](../deployment/database-migrations.md)).

Added migration script to:
- Add `asset_status` column to `network_assets` table if it doesn't exist
- Set default value to `'monitoring'`
- Add CHECK constraint to allow only `'pending_approval'`, `'monitoring'`, or `'denied'`
- Update existing assets to have `'monitoring'` status
- Create index for efficient status filtering

```sql
ALTER TABLE IF EXISTS network_assets
    ADD COLUMN IF NOT EXISTS asset_status VARCHAR(50) DEFAULT 'monitoring' 
    CHECK (asset_status IN ('pending_approval', 'monitoring', 'denied'));

UPDATE network_assets 
SET asset_status = 'monitoring' 
WHERE asset_status IS NULL AND deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_network_assets_status 
    ON network_assets (tenant_id, asset_status) 
    WHERE deleted_at IS NULL;
```

### Solution 2: Route Ordering Fix
**File:** `services/inventory-service/cmd/main.go`

Moved `/approve` and `/deny` routes to be registered **before** the `/:id` route:

```go
// Before (incorrect order)
api.GET("/inventory-service/assets/:id", assetHandler.GetAssetByID)
api.POST("/inventory-service/assets/approve", assetApprovalHandler.ApproveAssets)

// After (correct order)
api.POST("/inventory-service/assets/approve", assetApprovalHandler.ApproveAssets)
api.POST("/inventory-service/assets/deny", assetApprovalHandler.DenyAssets)
api.GET("/inventory-service/assets/:id", assetHandler.GetAssetByID)
```

Applied to both:
- Service-prefixed routes (`/inventory-service/assets/...`)
- Direct routes (`/assets/...`)

### Solution 3: Default Asset Filtering
**File:** `services/inventory-service/internal/services/asset_service.go`

Verified that `GetAssets` defaults to filtering by `'monitoring'` status when no status filter is provided:

```go
// Default status filter: only monitoring unless explicitly requested
if len(filters.AssetStatus) > 0 {
    whereConditions = append(whereConditions, fmt.Sprintf(`a.asset_status = ANY($%d)`, argCount))
    args = append(args, filters.AssetStatus)
} else {
    whereConditions = append(whereConditions, `a.asset_status = 'monitoring'`)
}
```

This ensures that:
- Main assets list only shows approved (`monitoring`) assets
- Pending approval assets are excluded by default
- Approval modal can explicitly request `pending_approval` status

### Solution 4: Pending Count Badge
**File (at the time):** `web-ui/src/pages/assets-page.tsx`. The `web-ui` app was later rebuilt from scratch as `frontend-v2`; the equivalent pending-approval flow now lives at Discovery → Approvals (`frontend-v2/src/sections/discovery/approvals-page.tsx`), with the main Inventory list still excluding pending assets by default.

Added:
- React Query hook to fetch pending approval count
- Badge component on "Discovery Approvals" button
- Badge displays count when `pendingApprovalCount > 0`
- Badge shows "99+" for counts over 99

```typescript
const { data: pendingApprovalResponse } = useQuery({
  queryKey: ['pending-approval-count'],
  queryFn: () => inventoryApi.getAssets({
    asset_status: ['pending_approval'],
    page: 1,
    page_size: 1, // We only need the count
  }),
  enabled: isAuthenticated && !authLoading,
  retry: 1,
});
const pendingApprovalCount = pendingApprovalResponse?.pagination?.total || 0;
```

## Verification

### Testing Performed

1. **Route Registration:**
   - Verified routes appear in Gin debug logs
   - Confirmed `/approve` endpoint returns 200 OK (not 404)
   - Tested with real asset IDs

2. **Asset Filtering:**
   - Verified main assets list only shows `"monitoring"` status
   - Confirmed pending assets are excluded by default
   - Tested explicit filtering by `pending_approval` status

3. **Approve Endpoint:**
   - Successfully approved assets via API
   - Verified status changes from `pending_approval` to `monitoring`
   - Confirmed response: `{"count": 1, "message": "assets approved"}`

4. **Database:**
   - Confirmed `asset_status` column exists
   - Verified existing assets have status values
   - Checked index creation

## Verification (Updated - Dec 9, 2025)

### Additional Fixes Applied
1. **IngestFindings null-safe query fix:**
   - **Problem:** PostgreSQL error "could not determine data type of parameter $2" when importing findings with nullable hostname/IP/port
   - **Solution:** Switched to `sql.NullString`/`sql.NullInt64` with `IS NOT DISTINCT FROM` operator for NULL-safe comparisons
   - **Location:** `services/inventory-service/internal/services/asset_service.go:902-928`
   - **Impact:** Enables reliable asset import from discovery results regardless of which fields are present

2. **Asset status filter array handling:**
   - **Problem:** PostgreSQL error "unsupported type []string" when filtering by `asset_status` array
   - **Solution:** Wrapped `AssetStatus` filter with `pq.Array()` to properly handle PostgreSQL array parameters
   - **Location:** `services/inventory-service/internal/services/asset_service.go:304`
   - **Impact:** Enables querying pending approval assets via API

### End-to-End Testing Results
**Test Script:** an internal end-to-end test script (not included in this repository); the results below are recorded for reference.

**All Tests Passed:**
- ✅ Authentication successful
- ✅ Discovery job creation works
- ✅ Results import creates 3 assets with `pending_approval` status
- ✅ Pending assets correctly excluded from main assets list
- ✅ Asset approval workflow transitions 3 assets to `monitoring` status
- ✅ Approved assets appear in main assets list
- ✅ Pending approval count decreases correctly after approval

**Test Output Summary:**
```
✓ Import completed. Assets imported: 3
✓ Found 3 pending approval assets
✓ Pending assets correctly excluded from main assets list
✓ Approved 3 assets
✓ Approved assets now appear in main assets list
✓ Pending approval count decreased correctly (from 3 to 0)
```

## Files Modified

### Core Fixes
- `services/inventory-service/internal/services/asset_service.go` - IngestFindings and GetAssets fixes
- `services/inventory-service/cmd/main.go` - Route ordering fix
- `web-ui/src/pages/assets-page.tsx` - Pending count badge
- Database migration, now part of `scripts/database/schema.sql`

### Testing & Verification
- Internal end-to-end test scripts (not included in this repository)


## Resolution Status

✅ **All Issues Resolved and Verified**

1. ✅ Full workflow tested: Import discovery results → Verify pending status → Approve assets → Verify they appear in main list
2. ✅ Assets created with `pending_approval` status verified
3. ✅ Frontend correctly filters assets by default (pending excluded)
4. ✅ Counter badge updates correctly after approvals
5. ✅ End-to-end automated tests passing

**No further action required.**

## Cloud Discovery Pipeline (Updated)

**Important Change:** Cloud discoveries now flow through the same unified pipeline as sensor discoveries. The `discovery_approval_queue` table is deprecated for cloud discoveries.

### Unified Discovery Pipeline

Cloud discoveries are processed through the same workflow as sensor discoveries:

1. **Cloud Discovery** → `device-interrogation-service` discovers cloud resources (AWS, Azure, GCP)
2. **Storage** → Discoveries written to `sensor_discoveries` table with `metadata->>'discovery_method' = 'cloud_api'`
3. **Processing** → `discovery-processor-service` polls `sensor_discoveries` and processes batches
4. **Classification** → A cloud discovery is classified by its `cloud_provider`/`cloud_region` (the per-region cloud segment), not by its address — most cloud resources have no address and are written with an unspecified-address placeholder
5. **Approval** → Assets are created `pending_approval` and appear in Discovery → Approvals, unless that cloud segment has auto-approve enabled **with cloud among its sources** (Settings → Infrastructure → edit the segment). That is off for every segment created before the setting existed
6. **Approval Workflow** → Same approval process as sensor discoveries

If cloud assets are queuing when you expect them to auto-approve, check the
segment's sources first:

```sql
SELECT name, value, auto_approve_discoveries, metadata->'auto_approve_sources'
FROM network_segments WHERE tenant_id = '<tenant>' AND network_type = 'cloud';
```

A `NULL` in the last column means sensor-only — the pre-setting default.

### Troubleshooting Cloud Discoveries

When troubleshooting cloud discovery issues:

- **Check `sensor_discoveries` table** instead of `discovery_approval_queue`:
  ```sql
  SELECT * FROM sensor_discoveries 
  WHERE metadata->>'discovery_method' = 'cloud_api' 
  AND processed_at IS NULL;
  ```

- **Verify discovery-processor-service** is running and processing batches:
  ```bash
  docker compose logs discovery-processor-service
  ```

- **Check for cloud discovery entries** in `sensor_discoveries`:
  ```sql
  SELECT batch_id, COUNT(*) as count, MIN(created_at) as first_seen
  FROM sensor_discoveries 
  WHERE metadata->>'discovery_method' = 'cloud_api'
  GROUP BY batch_id
  ORDER BY first_seen DESC;
  ```

- **Cloud discoveries use the Platform Device Interrogation Agent system sensor** - verify this sensor exists and is active

### Deprecated: discovery_approval_queue

The `discovery_approval_queue` table is no longer used for cloud discoveries. If you see references to this table in troubleshooting steps for cloud discoveries, those steps are outdated. Cloud discoveries now follow the same path as sensor discoveries through `sensor_discoveries` and `discovery-processor-service`.

## Misdiagnosis Trap: "Empty Inventory + zero certificates" (August 2026)

**Symptom:** Sensors are discovering (external connections appear, batches are
processed), but Inventory is empty and `certificates` /
`crypto_implementations` are at zero rows.

**This is the designed approval workflow, not a broken pipeline.** New assets
land with `asset_status='pending_approval'`, and their certificates and crypto
configurations are deliberately **deferred** (held with the pending asset)
until the asset is approved in **Discovery → Approvals** — only approval
materializes them into the inventory tables. Auto-approval is per network
segment (Settings → Infrastructure) and is off by default.

Two changes shipped in v0.5.2 to make this self-evident (#1274):

- The discovery-processor batch log no longer prints `0 asset findings` for
  external-only batches; batch summaries now report internal findings split by
  monitoring/pending and note the deferral.
- The Inventory page shows a pending-approval banner (count + link to the
  Approvals queue) whenever assets are waiting.

The same verification pass found and fixed a real defect: the
`valid_certificate_role` CHECK on `crypto_implementation_certificates`
rejected the `leaf` role the code writes, so the primary certificate was never
linked into the junction (chain certs were) and expiring-certificate risk
queries missed sensor-discovered leaf certificates. Fixed in the same release.

## Related Code References

- Route registration: `services/inventory-service/cmd/main.go:85-88`
- Asset filtering: `services/inventory-service/internal/services/asset_service.go:300-307`
- Asset creation: `services/inventory-service/internal/services/asset_service.go:1136-1139`
- Asset import: `services/inventory-service/internal/services/asset_service.go:936`
- Approval handler: `services/inventory-service/internal/handlers/asset_approval_handler.go:24-58`
- Frontend badge (at the time): `web-ui/src/pages/assets-page.tsx:100-107, 434-443`. `web-ui` was later rebuilt as `frontend-v2`; the current pending-approval UI is `frontend-v2/src/sections/discovery/approvals-page.tsx`.
- Cloud discovery to sensor_discoveries: `services/device-interrogation-service/internal/services/cloud_discovery_service.go:545-596`
- Discovery processor: `services/discovery-processor-service/internal/processor/discovery_processor.go`