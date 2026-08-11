---
render_macros: false
---

# Device Agent Deployment Guide

## Overview

The device agent is a downloadable binary that customers deploy in their on-premises or air-gapped environments to perform device interrogations. The agent communicates outbound-only with the platform service, receiving jobs and submitting results.

## Architecture

The device agent operates in a hybrid deployment model:

- **Platform Internal Agent**: Runs as a background worker in the device-interrogation-service, handling cloud provider APIs and internet-accessible devices
- **Downloadable Binary**: Customer-deployed agent for on-premises/air-gapped environments

## Prerequisites

- Network access to the platform API gateway (outbound HTTPS)
- Registration key from the platform
- Appropriate credentials for target devices (configured in platform)

## Installation

### Linux (AMD64)

```bash
# Download the binary
curl -O https://platform.example.com/api/v1/device-interrogation-service/downloads/agent/linux/amd64

# Make executable
chmod +x device-agent

# Create configuration file
cat > device-agent.yaml <<EOF
platform_url: https://platform.example.com
registration_key: YOUR_REGISTRATION_KEY
poll_interval: 30s
verbose: true
EOF

# Run the agent
./device-agent --config device-agent.yaml
```

### Linux (ARM64)

```bash
# Download the binary
curl -O https://platform.example.com/api/v1/device-interrogation-service/downloads/agent/linux/arm64

# Make executable
chmod +x device-agent

# Follow same configuration steps as AMD64
```

### Windows

```powershell
# Download the binary
Invoke-WebRequest -Uri "https://platform.example.com/api/v1/device-interrogation-service/downloads/agent/windows/amd64" -OutFile "device-agent.exe"

# Create configuration file
@"
platform_url: https://platform.example.com
registration_key: YOUR_REGISTRATION_KEY
poll_interval: 30s
verbose: true
"@ | Out-File -FilePath device-agent.yaml -Encoding utf8

# Run the agent
.\device-agent.exe --config device-agent.yaml
```

### macOS

```bash
# Download the binary
curl -O https://platform.example.com/api/v1/device-interrogation-service/downloads/agent/darwin/amd64

# Make executable
chmod +x device-agent

# Follow same configuration steps as Linux
```

## Configuration

### Environment Variables

The agent can be configured via environment variables or a YAML file:

- `PLATFORM_URL`: Platform API gateway URL (default: http://localhost:8080)
- `PLATFORM_URL_OVERRIDE`: set to `1` to force `PLATFORM_URL` on an **already-enrolled**
  agent (see below)
- `REGISTRATION_KEY`: Agent registration key (required)
- `AGENT_ID`: Agent ID (set after first registration)
- `POLL_INTERVAL`: Job polling interval (default: 30s)
- `VERBOSE`: Enable verbose logging (default: false)

### Configuration File

Create a `device-agent.yaml` file:

```yaml
platform_url: https://platform.example.com
registration_key: your-registration-key-here
poll_interval: 30s
verbose: true
```

## Registration

### Registration key type (required)

Create a **pending registration** from the tenant web UI (**Operations** / **Sensors**, or the enhanced registration flow) and select **Device interrogation agent** so the profile is `device_interrogation`. Keys issued for **network sensors** are rejected by `POST /api/v1/device-interrogation-service/agents/register`.

### Gateway-first

> **Enrolled agents pin their own endpoint.** When agent mTLS is enabled, registration
> saves the advertised TLS-passthrough URL into the agent's config, and that saved value
> **wins over `PLATFORM_URL`** on subsequent starts. This is deliberate: the agent's
> client certificate is bound to that endpoint, and letting a stale bootstrap
> `PLATFORM_URL` win would send post-registration traffic back through the edge proxy,
> where TLS terminates, the client cert is lost, and the agent gets 401s.
>
> The agent logs a line when it ignores `PLATFORM_URL` for this reason. To repoint an
> enrolled agent deliberately, set `PLATFORM_URL_OVERRIDE=1` alongside the new
> `PLATFORM_URL` — expect to re-enroll, since the existing certificate will not be valid
> for the new endpoint. The sensor has the equivalent pair
> (`CONTROL_PLANE_URL` / `CONTROL_PLANE_URL_OVERRIDE`).

Set `platform_url` (or `PLATFORM_URL`) to the **API gateway** base URL (for example `https://platform.example.com` or `http://localhost:8080`). Do not point the agent at individual backend service ports.

### First-time enrollment

1. Add `registration_key` to your YAML file or environment.
2. **Option A — explicit register flag:**  
   `device-agent -register -config device-agent.yaml`  
   Then run the agent normally: `device-agent -config device-agent.yaml`.
3. **Option B — auto-enroll on start (sensor-style):**  
   If `registration_key` is set and `agent_id` is empty, the agent registers once on startup, saves certificates under `<data_path>/certs`, and updates the config file with `agent_id`. If you did not pass `-config`, it writes `<data_path>/agent-config.yaml` by default.
4. After a successful enrollment, the server marks the key as used. Keep `agent_id` and the saved certificate paths for subsequent runs.

Job polling, results, and heartbeat use **agent mTLS** (client certificate) when certificates are present; they do not use tenant user JWT cookies.

### Platforms with a privately-signed certificate

If the platform's edge certificate comes from an internal CA this host does not
trust, enrollment fails certificate verification before it can start —
registration is itself an HTTPS call. The agent resolves this with an explicit
one-time trust decision rather than by skipping verification.

- **Interactive:** `device-agent --interactive` shows the CA the platform
  presents, with its SHA-256 fingerprint, and asks whether to trust it.
  Accepting pins it to the agent's config; every later connection is verified
  against it.
- **Unattended:** pass `--ca-fingerprint <sha256>`. The agent pins the CA only
  if it hashes to that value and aborts on a mismatch. With neither a
  fingerprint nor an operator to ask, it refuses rather than pinning an
  unapproved CA.
- **Alternative:** install the CA into the host's system trust store, after
  which no flag is needed.

The expected fingerprint is shown in the web UI when you mint the registration
code (**Discovery → Sensors & Agents → Register**, on the confirmation screen),
so you can compare it against what the agent displays. Read it there rather than
trusting the connection you are trying to validate. If the platform cannot
inspect its own certificate, get it from the host directly:

```bash
openssl s_client -showcerts -connect <platform-host>:443 </dev/null 2>/dev/null | openssl x509 -outform PEM | openssl x509 -noout -fingerprint -sha256
```

Full explanation, including the trust-on-first-use caveat:
[Sensor Registration → Trust Bootstrap](../../features/SENSOR_REGISTRATION.md).

## Operation

### Job Polling

The agent polls the platform every 30 seconds (configurable) for pending jobs. When a job is available:

1. Agent receives job with encrypted credentials
2. Credentials are decrypted in-memory
3. Device interrogation is executed
4. Results are submitted back to platform
5. Credentials are cleared from memory

### Supported Device Types

Currently supported:
- **Fortinet FortiGate** - SSL VPN, IPSec tunnels, certificates
- **F5 BigIP** - Virtual servers, SSL profiles with cipher lists, cert chains (iControl REST API)
- **Palo Alto Networks** - SSL/TLS policies, certificates (PanOS XML API)
- **Cisco** - Crypto maps, IPSec/IKEv2 SAs, SSL/TLS configs, SSH metadata (SSH/CLI)
- **Ubiquiti UniFi** - Controller TLS configs, device enumeration, site settings (REST API)
- **Generic HTTP** - REST API certificate extraction with TLS deep scan
- **Generic SNMP** - SNMPv2c system information collection

### Heartbeat

The agent sends a heartbeat to the platform every 60 seconds to indicate it's alive and ready for jobs.

## Security Considerations

### Credential Handling

- Credentials are encrypted at rest in the platform database
- Credentials are wrapped in AES-256-GCM envelope per-job (key derived from job ID)
- Agent decrypts credentials in-memory only during job execution
- Backward compatible: accepts pre-decrypted credentials if `encrypted_data` field absent
- Credentials are never written to disk or logged
- Credentials are cleared from memory after job completion

### Network Security

- Agent uses outbound-only HTTPS communication
- No inbound ports required
- All communication is initiated by the agent
- TLS 1.2+ required for all connections

### Access Control

- Registration key required for initial bootstrap only
- Client certificate (issued at registration) and agent ID are used for job polling and results
- Jobs are scoped to specific agents
- Agent can only access jobs assigned to it

## Troubleshooting

### HTTP 401 on job polling or heartbeat

Usually means the agent request hit a route that still required a **tenant JWT** (browser session) instead of **agent mTLS**. Ensure the platform runs a build where outbound routes (`/agents/:id/jobs`, `/results`, `/heartbeat`) are protected by agent auth, not only JWT. Also confirm `agent_id` in the config file matches the enrolled agent (after registration, the agent should persist `agent_id` automatically).

### Invalid or rejected registration key

- Wrong key type: use a **device interrogation** pending key, not a network sensor key.
- Key expired, already used, or database was reset: create a new pending key and enroll again.

### Agent Not Receiving Jobs

1. Verify registration key is correct
2. Check agent status in platform UI
3. Verify network connectivity to platform
4. Check agent logs for errors

### Job Execution Failures

1. Verify device credentials are correct in platform
2. Check device connectivity from agent location
3. Review job error messages in platform UI
4. Enable verbose logging: `VERBOSE=true`

### Connection Issues

1. Verify `PLATFORM_URL` is correct
2. Check firewall rules allow outbound HTTPS
3. Verify TLS certificate is valid
4. Check DNS resolution for platform URL

## Service Management

### systemd (Linux)

Create `/etc/systemd/system/device-agent.service`:

```ini
[Unit]
Description=Device Interrogation Agent
After=network.target

[Service]
Type=simple
User=device-agent
WorkingDirectory=/opt/device-agent
ExecStart=/opt/device-agent/device-agent --config /etc/device-agent/config.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable device-agent
sudo systemctl start device-agent
```

### Windows Service

Use NSSM (Non-Sucking Service Manager) or similar to run as a Windows service.

## Monitoring

### Health Checks

The agent sends periodic heartbeats to the platform. Monitor agent status in the platform UI.

### Logs

Logs are written to stdout/stderr. For production, redirect to log files:

```bash
./device-agent --config device-agent.yaml >> /var/log/device-agent.log 2>&1
```

## Updates

To update the agent:

1. Download new binary version
2. Stop current agent
3. Replace binary
4. Restart agent

The agent will automatically re-register with the platform if needed.

## Building and Uploading Binaries (Platform Administrators)

For platform administrators who need to build and upload device-agent binaries:

### Prerequisites

- Go 1.26+ installed
- AWS credentials configured (for S3 upload)
- S3 bucket: `crypto-inventory-artifacts` (or set `S3_ARTIFACTS_BUCKET` env var)

### Build Process

```bash
# Build binaries for all supported platforms
make device-agent-all-platforms

# This creates binaries in artifacts/device-agent/{os}/{arch}/device-agent
# Supported platforms:
# - linux/amd64
# - linux/arm64
# - windows/amd64
# - darwin/amd64 (macOS Intel)
# - darwin/arm64 (macOS Apple Silicon)
```

### Upload to S3

```bash
# Upload latest version
make device-agent-upload

# Upload with specific version tag
make device-agent-upload-version VERSION=v1.0.0

# Dry run (preview what would be uploaded)
make device-agent-upload-dry-run
```

### S3 Structure

Binaries are uploaded to:
```
s3://crypto-inventory-artifacts/device-agents/{version}/{os}/{arch}/device-agent
```

For example:
- `s3://crypto-inventory-artifacts/device-agents/latest/linux/amd64/device-agent`
- `s3://crypto-inventory-artifacts/device-agents/v1.0.0/windows/amd64/device-agent.exe`

### Distribution

The platform does not serve device-agent binaries over HTTP — there is no
download endpoint. Operators distribute the uploaded S3 objects (or the signed
GitHub Release assets) to their target hosts themselves.

### Version Management

- `latest` - Always points to the most recent version
- Version tags (e.g., `v1.0.0`) - Specific versioned releases
- SHA256 hashes stored in S3 metadata for integrity verification

## Support

For issues or questions:
- Check platform documentation
- Review agent logs
- Contact platform support
