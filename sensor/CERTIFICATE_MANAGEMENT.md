# Sensor Certificate Management

## Overview

The crypto-inventory sensor uses mTLS (mutual TLS) certificates for secure authentication with the control plane. This document explains how certificates are managed throughout the sensor lifecycle.

## Certificate Lifecycle

### 1. Initial Registration

When a sensor first registers with the control plane:

1. **Sensor generates a keypair** locally (private key never leaves the sensor)
2. **Sensor creates a CSR** (Certificate Signing Request) with its proposed UUID as CN
3. **Sensor sends registration** request with:
   - Registration key (from UI)
   - CSR
   - Sensor metadata (name, IP, platform, etc.)
4. **Control plane validates** the registration key
5. **Control plane signs** the CSR and returns:
   - Signed client certificate
   - Server CA certificate
   - Sensor ID (UUID)

### 2. Certificate Persistence

After successful registration, certificates are automatically saved to disk:

```
<DataPath>/
├── certs/                    # Certificate directory (0700 permissions)
│   ├── client.crt           # Signed client certificate (0644)
│   ├── client.key           # Private key (0600 - owner only!)
│   └── ca.crt               # Server CA certificate (0644)
└── config.yaml              # Updated with certificate paths
```

**Platform-Specific Data Paths:**
- **Windows:** `%LOCALAPPDATA%\CryptoSensor\` (typically `C:\Users\<username>\AppData\Local\CryptoSensor\`)
- **macOS:** `~/Library/Application Support/CryptoSensor/`
- **Linux:** `/var/lib/crypto-sensor/`

### 3. Subsequent Startups

On restart, the sensor:

1. **Loads config file** (contains sensorId and certificate paths)
2. **Reads certificates** from disk files
3. **Enables mTLS** automatically (no re-registration needed)
4. **Connects to control plane** using mTLS
5. **Checks certificate expiration** daily

**No registration key needed after initial registration!**

### 4. Certificate Rotation

Certificates are automatically rotated when:
- Certificate expires within 30 days
- Manual rotation requested via UI
- Certificate revoked by admin

The sensor checks certificate expiration:
- On startup
- Every 24 hours during operation

## Authentication Flow

### Registration Endpoint (No mTLS)
```
POST /api/v1/sensor-manager/sensors/register
Authentication: Registration Key
mTLS: Not required (sensor doesn't have cert yet)
```

### All Other Endpoints (mTLS Required)
```
POST /api/v1/sensor-manager/sensors/{sensor_id}/heartbeat
POST /api/v1/sensor-manager/sensors/{sensor_id}/discoveries
GET  /api/v1/sensor-manager/sensors/{sensor_id}/commands
Authentication: mTLS Certificate
- Certificate CN must match sensor_id
- Certificate must not be expired
- Certificate must not be revoked
- Certificate chain must validate against tenant CA
```

## Configuration File Format

### Before Registration
```yaml
controlPlaneUrl: "http://192.168.1.100:8080"
registrationKey: "REG-abc-123-xyz"
# ... other config ...
```

### After Registration
```yaml
controlPlaneUrl: "http://192.168.1.100:8080"
sensorId: "550e8400-e29b-41d4-a716-446655440000"

# mTLS Certificate Configuration (auto-generated after registration)
security:
  clientCertPath: "/path/to/certs/client.crt"     # Unix/Linux/macOS
  # OR on Windows:
  # clientCertPath: "C:\\Users\\username\\AppData\\Local\\CryptoSensor\\certs\\client.crt"
  clientKeyPath: "/path/to/certs/client.key"      # Unix/Linux/macOS
  # OR on Windows:
  # clientKeyPath: "C:\\Users\\username\\AppData\\Local\\CryptoSensor\\certs\\client.key"
  serverCACertPath: "/path/to/certs/ca.crt"       # Unix/Linux/macOS
  # OR on Windows:
  # serverCACertPath: "C:\\Users\\username\\AppData\\Local\\CryptoSensor\\certs\\ca.crt"
  useTLS: true

# ... other config ...
```

**Note for Windows**: All paths are automatically quoted and escaped with double backslashes (`\\`) by the sensor when writing the configuration file. This ensures proper YAML parsing on Windows systems.

## Security Considerations

### File Permissions

| File | Permissions | Reason |
|------|-------------|--------|
| `certs/` directory | `0700` (rwx------) | Only owner can access certificate directory |
| `client.key` | `0600` (rw-------) | Private key readable/writable by owner only |
| `client.crt` | `0644` (rw-r--r--) | Certificate can be read by others (contains no secrets) |
| `ca.crt` | `0644` (rw-r--r--) | CA cert is public |
| `config.yaml` | `0644` (rw-r--r--) | Config contains paths only, not actual keys |

### Best Practices

1. **Never manually edit certificate files** - use the control plane UI for certificate operations
2. **Back up certificates** if running in production - losing them requires re-registration
3. **Protect the private key** - it authenticates the sensor
4. **Don't share certificates** between sensors - each sensor must have unique credentials
5. **Monitor certificate expiration** - the sensor does this automatically, but admin UI shows status

## Troubleshooting

### Problem: "Certificate has expired" Error

**Symptoms:**
```
⚠️ Failed to send heartbeat: certificate has expired
```

**Solution:**
```bash
# The sensor should auto-rotate, but if it doesn't:
1. Stop the sensor
2. Delete certificate files (they'll be regenerated)
3. Restart sensor (will use registration key if still valid)

# Or regenerate via UI:
Sensor Management -> Select Sensor -> Certificates -> Regenerate
```

### Problem: Sensor Can't Connect After Restart

**Symptoms:**
```
❌ Connection refused
⚠️ mTLS handshake failed
```

**Check:**
1. Certificate files exist in `<DataPath>/certs/`
2. `config.yaml` has `security.clientCertPath` set
3. Private key file has correct permissions (0600 on Unix/Linux/macOS)
4. Certificate hasn't been revoked in admin UI
5. **Windows**: Config file paths are properly quoted (automatic in v1.2.1+)

**Solution:**
```bash
# Check certificate files
ls -la <DataPath>/certs/
# Windows: dir %LOCALAPPDATA%\CryptoSensor\certs

# If files are missing or corrupted, delete and re-register:
rm -rf <DataPath>/certs/
# Windows: rmdir /s %LOCALAPPDATA%\CryptoSensor\certs

# Edit config.yaml, remove security section
# Ensure registrationKey is set
# Restart sensor
```

### Problem: "yaml: line X: did not find expected hexdecimal number" (Windows)

**Cause:** Configuration file contains unquoted Windows paths with backslashes (fixed in v1.2.1+).

**Symptoms:**
```
⚠️ Failed to load config file: failed to parse config file: yaml: line 36: did not find expected hexdecimal number
```

**Solution:**
1. **Update to sensor v1.2.1 or later** (recommended - automatically quotes all paths)
2. **OR delete config and re-run interactive setup**:
   ```cmd
   del "%LOCALAPPDATA%\CryptoSensor\sensor-config.yaml"
   crypto-sensor.exe -interactive
   ```
3. **OR manually fix config file** by quoting all Windows paths:
   ```yaml
   dataPath: "C:\\Users\\username\\AppData\\Local\\CryptoSensor"
   interfaces:
     - "\\Device\\NPF_{GUID}"
   clientCertPath: "C:\\Users\\username\\AppData\\Local\\CryptoSensor\\certs\\client.crt"
   ```

### Problem: "Registration key invalid" After Previously Working

**Cause:** You're trying to re-register with an expired or already-used registration key.

**Solution:**
1. Generate new registration key in UI
2. Update `registrationKey` in `config.yaml`
3. Delete old certificates: `rm -rf <DataPath>/certs/`
4. Restart sensor

## Command-Line Options

### First-Time Registration
```bash
crypto-sensor -config config.yaml

# Or interactive mode:
crypto-sensor -interactive
```

### Subsequent Starts (Uses Persisted Certificates)
```bash
# Normal startup - certificates loaded automatically
crypto-sensor -config config.yaml

# Verbose mode
crypto-sensor -config config.yaml -verbose

# The sensor will automatically:
# 1. Load sensorId from config
# 2. Load certificates from disk files
# 3. Connect using mTLS
# 4. No registration needed!
```

### Force Re-Registration
```bash
# Delete certificates to force re-registration
rm -rf <DataPath>/certs/
crypto-sensor -config config.yaml -register
```

## API Integration

### For Developers: Certificate Paths in Config

The config object now includes both PEM data and file paths:

```go
type SecurityConfig struct {
    ClientCert       string // PEM-encoded certificate (loaded from file)
    ClientKey        string // PEM-encoded key (loaded from file)
    ServerCACert     string // PEM-encoded CA cert (loaded from file)
    ClientCertPath   string // Path to certificate file on disk
    ClientKeyPath    string // Path to private key file on disk
    ServerCACertPath string // Path to CA cert file on disk
    UseTLS           bool   // Automatically set to true when certs exist
}
```

**Loading certificates:**
```go
// Certificates are loaded automatically from paths when config is loaded
cfg, err := config.LoadFromFile("config.yaml")
// cfg.Security.ClientCert contains PEM data loaded from ClientCertPath
// cfg.Security.UseTLS is true if certificates were loaded successfully
```

**Saving certificates after registration:**
```go
// After registration, save certificates to disk
err := config.SaveCertificatesToFiles(cfg, clientCert, clientKey, caCert)
// This creates the certs directory, saves files with proper permissions,
// and updates cfg with file paths
```

## Migration from Previous Versions

If upgrading from a sensor version that didn't persist certificates:

1. **Sensor will continue to work** on first startup (certificates in memory)
2. **On next registration**, certificates will be automatically saved to disk
3. **No manual migration needed**

For clean migration:
1. Stop old sensor
2. Deploy new sensor binary
3. Keep existing `config.yaml`
4. Start sensor - it will register and persist certificates automatically

## Certificate Validity Period

- **Default:** 365 days (1 year)
- **Rotation Window:** Automatic rotation starts 30 days before expiration
- **Grace Period:** Certificate works until actual expiration date

The sensor runs daily checks and logs warnings:
```
✅ Certificate valid until 2027-01-29T10:30:00Z
⚠️ Certificate expires soon (in 25 days), will auto-rotate
🔄 Certificate expires on 2027-01-29T10:30:00Z, rotating...
✅ Certificate rotated successfully
```

## Summary

**Key Points:**
- ✅ Certificates automatically saved to disk after registration
- ✅ No re-registration needed on restart
- ✅ Secure file permissions (private key is 0600)
- ✅ Automatic rotation before expiration
- ✅ Registration key only needed once (initial registration)
- ✅ Simple backup/restore (just copy `<DataPath>` directory)
