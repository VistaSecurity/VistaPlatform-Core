# Device Agent Certificate Management

## Overview

The crypto-inventory device agent uses mTLS (mutual TLS) certificates for secure authentication with the control plane. This document explains how certificates are managed throughout the agent lifecycle.

## Certificate Lifecycle

### 1. Initial Registration

When an agent first registers with the control plane:

1. **Agent generates a keypair** locally (private key never leaves the agent)
2. **Agent creates a CSR** (Certificate Signing Request) with its proposed UUID as CN
3. **Agent sends registration** request with:
   - Registration key (from UI)
   - CSR
   - Agent metadata (platform, version, etc.)
4. **Control plane validates** the registration key
5. **Control plane signs** the CSR and returns:
   - Signed client certificate
   - Server CA certificate
   - Agent ID (UUID)

### 2. Certificate Persistence

After successful registration, certificates are automatically saved to disk:

```
<DataPath>/
├── certs/                    # Certificate directory (0700 permissions)
│   ├── client.crt           # Signed client certificate (0644)
│   ├── client.key           # Private key (0600 - owner only!)
│   └── ca.crt               # Server CA certificate (0644)
└── agent-config.yaml        # Updated with certificate paths
```

**Platform-Specific Data Paths:**
- **Windows:** `%LOCALAPPDATA%\CryptoDeviceAgent\` (typically `C:\Users\<username>\AppData\Local\CryptoDeviceAgent\`)
- **macOS:** `~/Library/Application Support/CryptoDeviceAgent/`
- **Linux:** `/var/lib/crypto-device-agent/`

### 3. Subsequent Startups

On restart, the agent:

1. **Loads config file** (contains agentId and certificate paths)
2. **Reads certificates** from disk files
3. **Enables mTLS** automatically (no re-registration needed)
4. **Connects to platform** using mTLS
5. **Checks certificate expiration** on startup

**No registration key needed after initial registration!**

### 4. Certificate Rotation

Certificates can be rotated when:
- Certificate expires within 30 days
- Manual rotation requested via platform
- Certificate revoked by admin

The agent checks certificate expiration on startup.

## Authentication Flow

### Registration Endpoint (No mTLS)
```
POST /api/v1/device-interrogation-service/agents/register
Authentication: Registration Key
mTLS: Not required (agent doesn't have cert yet)
```

### All Other Endpoints (mTLS Required)
```
GET  /api/v1/device-interrogation-service/agents/{agent_id}/jobs
POST /api/v1/device-interrogation-service/agents/{agent_id}/results
POST /api/v1/device-interrogation-service/agents/{agent_id}/heartbeat
POST /api/v1/device-interrogation-service/agents/{agent_id}/certificates/rotate

Authentication: mTLS Certificate
- Certificate CN must match agent_id
- Certificate must not be expired
- Certificate must not be revoked
- Certificate chain must validate against tenant CA
```

## Configuration File Format

### Before Registration
```yaml
platform_url: "http://192.168.1.100:8080"
registration_key: "REG-abc-123-xyz"
poll_interval: 30s
data_path: "/var/lib/crypto-device-agent"
```

### After Registration
```yaml
platform_url: "http://192.168.1.100:8080"
agent_id: "550e8400-e29b-41d4-a716-446655440000"
registration_key: "REG-abc-123-xyz"
poll_interval: 30s
data_path: "/var/lib/crypto-device-agent"

# mTLS Certificate Configuration (auto-generated after registration)
security:
  client_cert_path: "/var/lib/crypto-device-agent/certs/client.crt"  # Unix/Linux/macOS
  # OR on Windows:
  # client_cert_path: "C:\\Users\\username\\AppData\\Local\\CryptoDeviceAgent\\certs\\client.crt"
  client_key_path: "/var/lib/crypto-device-agent/certs/client.key"
  # OR on Windows:
  # client_key_path: "C:\\Users\\username\\AppData\\Local\\CryptoDeviceAgent\\certs\\client.key"
  server_ca_cert_path: "/var/lib/crypto-device-agent/certs/ca.crt"
  # OR on Windows:
  # server_ca_cert_path: "C:\\Users\\username\\AppData\\Local\\CryptoDeviceAgent\\certs\\ca.crt"
  use_tls: true
```

**Note for Windows**: All paths are automatically quoted and escaped with double backslashes (`\\`) by the agent when writing the configuration file. This ensures proper YAML parsing on Windows systems.

## Security Considerations

### File Permissions

| File | Permissions | Reason |
|------|-------------|--------|
| `certs/` directory | `0700` (rwx------) | Only owner can access certificate directory |
| `client.key` | `0600` (rw-------) | Private key readable/writable by owner only |
| `client.crt` | `0644` (rw-r--r--) | Certificate can be read by others (contains no secrets) |
| `ca.crt` | `0644` (rw-r--r--) | CA cert is public |
| `agent-config.yaml` | `0644` (rw-r--r--) | Config contains paths only, not actual keys |

### Best Practices

1. **Never manually edit certificate files** - use the platform UI for certificate operations
2. **Back up certificates** if running in production - losing them requires re-registration
3. **Protect the private key** - it authenticates the agent
4. **Don't share certificates** between agents - each agent must have unique credentials
5. **Monitor certificate expiration** - check logs for rotation notifications

## Troubleshooting

### Problem: "Certificate has expired" Error

**Symptoms:**
```
⚠️ Failed to poll for jobs: certificate has expired
```

**Solution:**
1. Certificate rotation should happen automatically within 30 days of expiration
2. If auto-rotation fails, manually trigger via platform UI
3. Or re-register the agent with a new registration key

### Problem: Agent Can't Connect After Restart

**Symptoms:**
```
❌ Connection refused
⚠️ mTLS handshake failed
```

**Check:**
1. Certificate files exist in `<DataPath>/certs/`
2. `agent-config.yaml` has `security.client_cert_path` set
3. Private key file has correct permissions (0600 on Unix/Linux/macOS)
4. Certificate hasn't been revoked in platform UI
5. **Windows**: Config file paths are properly quoted (automatic in v1.2.0+)

**Solution:**
```bash
# Check certificate files
ls -la <DataPath>/certs/
# Windows: dir %LOCALAPPDATA%\CryptoDeviceAgent\certs

# If files are missing or corrupted, delete and re-register:
rm -rf <DataPath>/certs/
# Windows: rmdir /s %LOCALAPPDATA%\CryptoDeviceAgent\certs

# Run interactive setup
device-agent -interactive
```

### Problem: "yaml: line X: did not find expected hexdecimal number" (Windows)

**Cause:** Configuration file contains unquoted Windows paths with backslashes (fixed in v1.2.0+).

**Symptoms:**
```
⚠️ Failed to load config file: failed to parse config file: yaml: line X: did not find expected hexdecimal number
```

**Solution:**
1. **Update to agent v1.2.0 or later** (recommended - automatically quotes all paths)
2. **OR delete config and re-run interactive setup**:
   ```cmd
   del "%LOCALAPPDATA%\CryptoDeviceAgent\agent-config.yaml"
   device-agent.exe -interactive
   ```
3. **OR manually fix config file** by quoting all Windows paths:
   ```yaml
   data_path: "C:\\Users\\username\\AppData\\Local\\CryptoDeviceAgent"
   client_cert_path: "C:\\Users\\username\\AppData\\Local\\CryptoDeviceAgent\\certs\\client.crt"
   ```

## Command-Line Usage

### Interactive Setup (Recommended for First-Time)
```bash
device-agent -interactive
```

This will:
- Prompt for platform URL and registration key
- Register with the platform
- Save certificates to disk
- Create configuration file
- Provide command to start the agent

### Manual Registration
```bash
# Set environment variables
export PLATFORM_URL="http://192.168.1.100:8080"
export REGISTRATION_KEY="REG-abc-123-xyz"

# Register
device-agent -register -config agent-config.yaml
```

### Start Agent (After Registration)
```bash
device-agent -config /path/to/agent-config.yaml
```

The agent will:
- Load configuration from file
- Load certificates from paths specified in config
- Connect to platform using mTLS
- Begin polling for jobs

### Verbose Mode
```bash
device-agent -config agent-config.yaml -verbose
```

Shows detailed logging including certificate loading and TLS handshake information.

## Configuration Options

### Environment Variables

All configuration can be set via environment variables:

```bash
# Required for first registration
export PLATFORM_URL="http://192.168.1.100:8080"
export REGISTRATION_KEY="REG-abc-123-xyz"

# Optional
export DATA_PATH="/custom/path"
export POLL_INTERVAL="60s"
export VERBOSE="true"

# Certificate paths (if not using config file)
export CLIENT_CERT_PATH="/path/to/client.crt"
export CLIENT_KEY_PATH="/path/to/client.key"
export SERVER_CA_CERT_PATH="/path/to/ca.crt"
```

### Config File

Preferred method - all settings in one YAML file:

```yaml
agent_id: "550e8400-e29b-41d4-a716-446655440000"
platform_url: "http://192.168.1.100:8080"
poll_interval: 30s
data_path: "/var/lib/crypto-device-agent"
verbose: false

security:
  client_cert_path: "/var/lib/crypto-device-agent/certs/client.crt"
  client_key_path: "/var/lib/crypto-device-agent/certs/client.key"
  server_ca_cert_path: "/var/lib/crypto-device-agent/certs/ca.crt"
  use_tls: true
```

## Platform Integration

### Registration in Platform UI

1. Navigate to **Device Agent Management**
2. Click **Register New Agent**
3. Enter agent name and description
4. Click **Generate Registration Key**
5. Copy the registration key
6. Use key with `device-agent -interactive` or `device-agent -register`

### Monitoring Agent Status

The platform UI shows:
- Agent online/offline status
- Certificate expiration date
- Last heartbeat time
- Job execution history

### Certificate Rotation

Automatic rotation occurs when certificate expires within 30 days. Manual rotation can be triggered from the platform UI:

1. Navigate to agent details
2. Click **Certificates** tab
3. Click **Rotate Certificate**
4. Agent will receive new certificate on next heartbeat

## Security Architecture

### Why mTLS?

- **Mutual authentication**: Both agent and platform verify each other's identity
- **No shared secrets**: Each agent has unique certificate
- **Certificate-based**: More secure than API keys
- **Automatic rotation**: Certificates can be rotated without downtime

### Private Key Security

- Generated on agent (never transmitted)
- Stored with `0600` permissions
- Used only for TLS handshake
- Never leaves the agent filesystem

### Certificate Chain

```
Root CA (Platform)
  └─ Tenant CA
      └─ Agent Certificate (signed by Tenant CA)
```

Each tenant has its own CA, ensuring tenant isolation.

## Troubleshooting Checklist

- [ ] Certificate files exist in `<DataPath>/certs/`
- [ ] Private key has `0600` permissions (Unix/Linux/macOS)
- [ ] Config file has certificate paths set
- [ ] Certificate not expired (check expiration date)
- [ ] Certificate not revoked in platform UI
- [ ] Platform URL is correct and reachable
- [ ] Agent ID matches certificate CN
- [ ] Windows paths properly quoted in config (v1.2.0+)

## Version History

- **v1.2.0** (2026-01-29): Added certificate persistence, Windows path handling, interactive mode
- **v1.0.0** (2026-01-20): Initial release with CSR-based registration

---

For additional support, consult the platform documentation or contact support.
