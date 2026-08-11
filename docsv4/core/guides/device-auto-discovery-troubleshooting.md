# Device Auto-Discovery Troubleshooting Guide

**Last Updated:** February 2, 2026

## Known Issues

### Device Interrogation Job Failures (Investigation Required)

**Symptom:**
- Device successfully added with auto-discovery ✅
- Device information correctly populated ✅
- Device test connection works ✅
- But clicking "Interrogate" creates a job that fails immediately ❌

**Error Message:**
```
failed to create discovery job: pq: insert or update on table "discovery_jobs" 
violates foreign key constraint "discovery_jobs_created_by_fkey"
```

**Status:** Under investigation

**Likely Cause:**
This appears to be an architectural issue where network device interrogation jobs are trying to create `discovery_jobs` records (which were designed for cloud discovery workflows) with system user references that may not properly cascade through the foreign key relationships.

**Workaround:**
Currently none. This does not impact device creation or auto-discovery - only the subsequent interrogation of discovered devices.

**Timeline:**
This issue will be investigated and resolved in the next development cycle.

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
   - Go to your device's web UI (e.g., `https://192.168.1.1`)
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

**What We've Done:**
The platform now tries multiple endpoint patterns automatically:
- `/proxy/network/api/s/default/stat/sysinfo` (UDM/UDR)
- `/api/s/default/stat/sysinfo` (standard controller)
- `/api/system` (alternative)

**If Still Failing:**
This may indicate an unsupported device model or firmware version. Please report:
- Device model (exact model number)
- Firmware version
- Management URL format
- Error logs

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

**What We've Done:**
The platform automatically handles self-signed certificates (common for network devices) by setting `InsecureSkipVerify: true` for device connections.

**If Still Failing:**
- Verify HTTPS is enabled on the device management interface
- Check if device requires specific TLS version
- Ensure management port is correct (usually 443 or 8443)

---

## General Troubleshooting

### "Failed to add device"

Check the browser console for detailed error messages:
1. Open browser Developer Tools (F12)
2. Go to Console tab
3. Look for red error messages
4. Check the request payload and response

Common issues:
- Empty required fields
- Invalid URL format (missing `https://`)
- Network connectivity problems
- Backend service not running

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

If you encounter issues not covered here:

1. **Check service logs**
   ```bash
   docker compose logs device-interrogation-service --tail=50
   ```

2. **Verify database schema**
   - Ensure all migrations have been applied
   - Check for missing columns or constraints

3. **Check browser console**
   - Look for JavaScript errors
   - Check network requests and responses

4. **Contact support** with:
   - Device type and model
   - Error messages from logs
   - Steps to reproduce
   - Browser console output
