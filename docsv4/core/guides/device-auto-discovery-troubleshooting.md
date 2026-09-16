# Device Auto-Discovery Troubleshooting Guide

## Known Issues

### Job reports "completed" but nothing appears in Inventory

**Symptom:**
- The interrogation job shows **Completed** with a non-zero asset count ✅
- Nothing appears in Discovery → Approvals or in Inventory ❌

**First: check the job detail, not the job row.** Click the job on Discovery →
Discovery Jobs or Job Logs. The **Outcome** panel shows *Discovered* and *Into
inventory* separately. If they disagree, the run found assets but failed to
materialize them, and **Processing errors** names the reason.

The asset count on the job row is the number of assets the device returned. It
is not a claim that any of them were kept — which is why the two figures are
reported apart.

**If "Into inventory" matches "Discovered":** the assets did materialize, and
this is the approval workflow behaving as designed. Discovered assets land as
`pending_approval` unless an auto-approval rule matches their network segment.
Look in **Discovery → Approvals**, not Inventory. See
[Asset approval workflow](../operate/troubleshooting/asset-approval-workflow-issues.md).

**If the asset is in neither place, check whether it was *merged*.** An
interrogation that matched an asset you already had does not create a second
one. Where the match scored at or above your **auto-accept threshold**
(**Settings → Policies → Identification rules**) it was accepted silently, and
the sighting went onto the existing asset — look at that asset's **History**
rather than expecting a new row. Where it scored below, the proposal is waiting
in **Discovery → Approvals** as a *merge* proposal, which is easy to scroll past
if you are looking for a pending asset.

This is the most common "nothing appeared" that is not a failure at all: the
platform did exactly what you asked and put the information where it belonged.

---

### A neighbour the device reported did not become an asset

Devices tell us about their neighbours — an access point adopted by a
controller, an LLDP or CDP neighbour, the members of a load balancer's pool.
Those become **proposals**, not assets: the device stated that something is
there, which is not the same as having looked at it.

Find them on **Discovery → Approvals**, where the relationship proposal appears
alongside the pending asset. Approving the asset approves what was observed
about it.

---

## Auto-Discovery Issues

### Authentication Failures

**Symptom:** Device creation fails with authentication error

**Error Messages:**
- `"AUTHENTICATION_FAILED_INVALID_CREDENTIALS"`
- `"Unauthorized"`
- `401` or `403` HTTP status codes

**Solutions:**

1. **Verify credentials by logging in manually**
   - Go to your device's web UI (e.g., `https://10.0.0.1`)
   - Try logging in with the same username/password
   - If it works in web UI but not auto-discovery, check case sensitivity

2. **Check username format**
   - UniFi: Use just the username (e.g., `admin`, not `local\admin`)
   - Some systems: May require domain prefix or email format

3. **Verify user permissions**
   - The account needs at least read-only network access
   - For UniFi: Ensure user has "Read-Only" or higher permission to "Network"

4. **Check for account lockout**
   - Too many failed attempts can lock accounts
   - Wait or reset the account

### Discovery Endpoint Not Found

**Symptom:** Login succeeds but discovery fails with 404

**Error Message:**
- `"sysinfo request failed with status 404: Not Found"`

**What the platform already does:** it tries several endpoint patterns before
giving up:
- `/proxy/network/api/s/default/stat/sysinfo` (UDM/UDR)
- `/api/s/default/stat/sysinfo` (standard controller)
- `/api/system` (alternative)

**If it still fails:** this usually means an unsupported model or firmware
version. Report the exact model, the firmware version, the management URL form
you used, and the error the job recorded.

### Connection Timeout

**Symptom:** Device creation takes 30+ seconds then fails

**Possible Causes:**
1. **Network connectivity issue**
   - Device not reachable from platform
   - Firewall blocking connection
   - Wrong IP address or URL

2. **Device is slow to respond**
   - Overloaded device
   - Slow network
   - Device startup/reboot in progress

**Solutions:**
- Verify network connectivity: `ping <device-ip>`
- Check firewall rules
- Try again later if device is busy
- Verify management URL is correct

### TLS/Certificate Errors

**Symptom:** Connection fails with TLS or certificate error

**What the platform already does:** management interfaces on network devices
are routinely self-signed, so the **Skip TLS verification** option on the device
form exists for exactly this and is honoured when set.

**If it still fails:**
- Verify HTTPS is enabled on the device management interface
- Check if device requires specific TLS version
- Ensure management port is correct (usually 443 or 8443)

---

## General Troubleshooting

### "Failed to add device"

Usually one of:

- a required field left empty — a device needs a type and at least one way to
  reach it (host name, IP address or management URL);
- a management URL without its scheme: `10.0.0.1` rather than `https://10.0.0.1`;
- the platform cannot reach the address at all — see *Connection timeout* above.

### Device Shows "Unknown" Status

This is normal for newly added devices. The status will update:
- After first successful test connection
- After first interrogation job completes
- Based on health check results

### Missing Device Information

If some fields are empty after auto-discovery:
- **Normal**: Not all devices expose all information (e.g., serial number, MAC address)
- **Device-specific**: Some information only available via interrogation jobs
- **Can be edited**: You can manually add missing information by editing the device

---

## Getting Help

If you hit something this page does not cover:

1. **Read the run's own detail.** Open the job on **Discovery → Job Logs**. The
   **Outcome** panel separates what was discovered from what reached inventory,
   and **Processing errors** names the reason when those two disagree.
2. **Check both queues.** **Discovery → Approvals** holds pending assets *and*
   merge proposals; something you cannot find in Inventory is usually in one of
   them.
3. **Contact your platform administrator** with the device type and model, the
   job id, and the error the job recorded.
