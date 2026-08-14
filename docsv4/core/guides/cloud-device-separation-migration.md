# Cloud and Device Management Separation - Migration Guide

**Last Updated:** February 2, 2026

## What Changed

We've simplified the platform by separating cloud integrations from network device management and introducing **automatic device discovery**:

### Before
- Single "Cloud & Device Integrations" page managed both cloud providers and network devices
- Network devices linked to "integrations" for credentials
- Required 10+ fields to add a device manually
- Confusing terminology mixing cloud APIs with physical devices

### After
- **Cloud Integrations** page - AWS, Azure, GCP only
- **Network Devices** page - UniFi, Cisco, Fortinet, Palo Alto, F5
- Each network device stores its own credentials (embedded)
- **Auto-discovery** requires only 4 fields (device type, URL, username, password)
- 80% reduction in data entry for device onboarding
- Clearer separation of concepts

## New Feature: Auto-Discovery

### What is Auto-Discovery?

When adding a network device, you now only need to provide:
1. **Device Type** (manufacturer: UniFi, Cisco, etc.)
2. **Management URL** (e.g., `https://192.168.1.1`)
3. **Username**
4. **Password**

The platform will:
- Connect to the device
- Authenticate
- Automatically retrieve: model, serial number, firmware version, hostname, IP address, MAC address
- Create the device with all information populated
- Encrypt and store credentials securely

### Current Support

- ✅ **UniFi devices (fully functional)**: UDM, UDR, USG, UniFi Network Controllers
- 🔧 **Other vendors**: Framework ready, basic info returned (full discovery coming soon)

### Benefits

- **Faster onboarding** - 4 fields instead of 10+
- **No data entry errors** - Information pulled directly from device
- **Automatic updates** - Can re-discover to update device info
- **Secure** - Credentials encrypted at rest

## Impact on Existing Users

### Automatic Migration

If you had existing network devices linked to integrations, credentials were automatically migrated:
- Username and password copied from integration to device record
- Old `credential_id` link remains for backward compatibility but is deprecated
- No action required - your devices continue to work

### Going Forward

When adding new network devices, you have two options:

#### Option 1: Auto-Discovery (Recommended)
1. Navigate to **Discovery > Devices**
2. Click **Add Device**
3. Enter only 4 fields:
   - Device Type (manufacturer)
   - Management URL
   - Username
   - Password
4. Click **Add Device**
5. System auto-discovers and populates all device details

#### Option 2: Manual Entry
1. Navigate to **Discovery > Devices**
2. Click **Add Device**
3. Enter all device details manually (use when auto-discovery is not available)

### If You Had Multiple Devices Sharing Credentials

Previously, you might have created one UniFi integration and linked 10 devices to it. After migration:
- Each device now has its own copy of the credentials
- Updating credentials requires updating each device individually
- Consider this when planning password rotation

## Benefits

1. **Simpler workflow**: Add device + credentials in one step
2. **Clearer terminology**: "Integrations" now clearly means cloud APIs
3. **Better UX**: No confusion about "Account ID" fields for network devices
4. **Per-device security**: Each device can have unique credentials if needed

## Questions?

Contact support or refer to the updated [Device Interrogation User Guide](./device-interrogation-user-guide.md).

---

## Database Migrations Applied

The following changes were made to support this feature. There is no migration
runner in this project — each is folded directly into
[`scripts/database/schema.sql`](../../../scripts/database/schema.sql), which is
applied as a whole (see [Database Migrations](../operate/deployment/database-migrations.md)).
They're listed here for historical reference only; there are no separate
migration files to run.

### Add Device Credentials

Adds `username` and `password` columns to `devices` table for embedded credentials.

### Update Integration Constraints

Updates `platform_integrations` table to enforce cloud-only integration types, removing network device types.

### Migrate Device Credentials

One-time data migration copying credentials from `platform_integrations.config` to `devices` table for existing network devices.

### Add Device Jobs Updated At

Adds `updated_at` timestamp column to `device_jobs` table with automatic update trigger.

---

## Technical Implementation Details

### Architecture Changes

1. **Embedded Credentials**
   - Network device credentials stored directly in `devices` table
   - Encrypted at rest using `ENCRYPTION_MASTER_KEY`
   - `credential_id` field deprecated but maintained for backward compatibility

2. **Auto-Discovery Service**
   - New `DeviceDiscoveryService` in Go
   - Connects to devices, authenticates, retrieves information
   - Vendor-specific implementation for each device type
   - 30-second timeout protection

3. **API Endpoints**
   - New: `POST /devices/discover-and-create` for auto-discovery
   - Existing: `POST /devices` for manual creation (still supported)

4. **Frontend Components**
   - New: `DeviceFormModalSimple` for auto-discovery
   - Existing: `DeviceFormModal` for manual/edit operations
   - Simplified device type selection (manufacturer-based)

### Security Features

- All passwords encrypted using AES-256-GCM with platform master key
- Credentials never logged or exposed in API responses
- Password masking in frontend forms
- Secure transmission over HTTPS/TLS

### Database Schema

```sql
-- Devices table additions
ALTER TABLE devices ADD COLUMN username VARCHAR(255);
ALTER TABLE devices ADD COLUMN password TEXT; -- Encrypted

-- Device jobs table additions  
ALTER TABLE device_jobs ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();

-- System user for automated jobs
INSERT INTO users (id, email, first_name, last_name, ...) 
VALUES ('00000000-0000-0000-0000-000000000000', 'system@platform.local', ...);
```
