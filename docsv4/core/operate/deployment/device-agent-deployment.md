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

### Getting the binary

Download the `device-agent-<os>-<arch>-<version>` asset matching your
platform from the
[latest GitHub release](https://github.com/VistaSecurity/VistaPlatform-Core/releases/latest)
and verify it against that release's signed `SHA256SUMS` — see
[Downloads in INSTALL.md](https://github.com/VistaSecurity/VistaPlatform-Core/blob/main/INSTALL.md#downloads)
for the full OS/arch table and the `cosign verify-blob` command. **There is
no in-product download endpoint** — the platform does not serve agent
binaries over HTTP, so a `curl`/`Invoke-WebRequest` against the platform
itself will not work (see "There is no binary-download API" in the
[sensor registration guide](../../features/SENSOR_REGISTRATION.md), which
applies to the device agent too).

Prefer to build it yourself? `make build-device-agent` (current platform) or
`make device-agent-all-platforms` (all six targets) builds the same binary
from this repository.

The sections below assume you've downloaded the asset for your platform and
renamed it to `device-agent` (`device-agent.exe` on Windows) for brevity —
substitute the versioned filename if you'd rather keep it as-is.

### Linux (AMD64)

```bash
# after downloading device-agent-linux-amd64-<version> from the release page
mv device-agent-linux-amd64-<version> device-agent
chmod +x device-agent

# Run it — with no arguments the agent walks you through setup and then starts
./device-agent
```

Running the binary with no arguments opens the interactive installer: it asks
for the platform URL (and tests reachability), the registration key, the data
path and the poll interval, enrolls the agent, writes
`<data_path>/agent-config.yaml`, and then **starts polling for jobs**
immediately. Verbose logging is on by default. On every later start the agent
finds that config file and runs straight away — no flags, no second command.

To configure a host without answering prompts, write the config file yourself
and the installer stays out of the way:

```bash
cat > device-agent.yaml <<EOF
platform_url: https://platform.example.com
registration_key: YOUR_REGISTRATION_KEY
poll_interval: 30s
verbose: true
EOF

./device-agent --config device-agent.yaml
```

### Linux (ARM64)

```bash
# after downloading device-agent-linux-arm64-<version> from the release page
mv device-agent-linux-arm64-<version> device-agent
chmod +x device-agent

# Follow same configuration steps as AMD64
```

### Windows

```powershell
# after downloading device-agent-windows-amd64-<version>.exe from the release page
Rename-Item device-agent-windows-amd64-<version>.exe device-agent.exe

# Run it — with no arguments the agent walks you through setup and then starts
.\device-agent.exe
```

As on Linux, a config file suppresses the installer:

```powershell
@"
platform_url: https://platform.example.com
registration_key: YOUR_REGISTRATION_KEY
poll_interval: 30s
verbose: true
"@ | Out-File -FilePath device-agent.yaml -Encoding utf8

.\device-agent.exe --config device-agent.yaml
```

### macOS

```bash
# after downloading device-agent-darwin-amd64-<version> (Intel) or
# device-agent-darwin-arm64-<version> (Apple Silicon) from the release page
mv device-agent-darwin-*-<version> device-agent
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
- `VERBOSE`: Enable verbose logging. Verbose is **on by default**; set
  `VERBOSE=false` (or `verbose: false` in the config file, or `-verbose=false`
  on the command line) to quiet a long-running install.

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

1. **Option A — just run the binary (default):**  
   `device-agent` with no arguments prompts for the registration key, enrolls,
   saves the config, and starts the agent in one step. Nothing to prepare
   beforehand.
2. Or, to prepare the config yourself, add `registration_key` to your YAML file
   or environment and pick one of the following.
3. **Option B — explicit register flag:**  
   `device-agent -register -config device-agent.yaml`  
   Then run the agent normally: `device-agent -config device-agent.yaml`.
4. **Option C — auto-enroll on start (sensor-style):**  
   If `registration_key` is set and `agent_id` is empty, the agent registers once on startup, saves certificates under `<data_path>/certs`, and updates the config file with `agent_id`. If you did not pass `-config`, it writes `<data_path>/agent-config.yaml` by default.
5. After a successful enrollment, the server marks the key as used. Keep `agent_id` and the saved certificate paths for subsequent runs.

Job polling, results, and heartbeat use **agent mTLS** (client certificate) when certificates are present; they do not use tenant user JWT cookies.

### Platforms with a privately-signed certificate

If the platform's edge certificate comes from an internal CA this host does not
trust, enrollment fails certificate verification before it can start —
registration is itself an HTTPS call. The agent resolves this with an explicit
one-time trust decision rather than by skipping verification.

- **Interactive:** the default install path — plain `device-agent`, or
  `device-agent --interactive` to force the dialogue on a host that already has
  a config file — shows the CA the platform presents, with its SHA-256
  fingerprint, and asks whether to trust it. Accepting pins it to the agent's
  config; every later connection is verified against it.
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

Before offering you a CA to approve, the agent checks that the certificate the
platform presents is valid for the hostname you gave it. If it is not, the agent
refuses and names what the server is actually serving — commonly an ingress
controller's placeholder such as `a1b2c3d4.traefik.default`, which means the
platform's TLS certificate was never installed. Trusting a CA cannot fix this:
verification checks the hostname before it checks the signature, so the
connection would fail either way, and approving one would look like a completed
security step while changing nothing. Fix the platform's certificate and run
setup again. The same refusal applies on the `--ca-fingerprint` path.

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

The agent sends a heartbeat to the platform every 60 seconds to indicate it's alive and ready for jobs. The heartbeat also reports the agent's binary version and the addresses bound on its host, which is how the fleet list shows a multi-homed agent's full address inventory — the platform cannot observe those itself, because NAT and ingress rewrite the connection source.

### Viewing the fleet

Enrolled agents appear under **Discovery → Sensors & Agents**, in their own **Discovery agents** table below the network sensors. Sensors and agents are different things and are listed separately: the table shows, per agent, the host and its addresses, what the agent is permitted to interrogate, when it last ran a job and how many it has run in total, its version, and whether it is currently checking in.

An agent whose last heartbeat is stale shows as offline even if its status column still reads `active` — nothing rewrites that column after enrollment, so the heartbeat is the authority.

### Removing an agent

**Discovery → Sensors & Agents → Discovery agents → ✕** on the row, then confirm. Requires the `discovery.manage` permission.

Removing an agent:

- takes it out of the fleet list and stops it being assigned any further work;
- **revokes its client certificate**;
- returns its queued jobs to the pool, so another agent — or the platform's own in-cluster worker — picks them up. A queued job that names no device cannot be reassigned and is marked failed, because nothing else can resolve its target;
- marks any job it was **currently running** as failed. That job is not retried automatically, since the agent may have already carried out the work before it was removed; re-run it from the device if you need the result.

**This does not uninstall the agent.** The binary keeps running on its host and will keep polling. Stop and remove it separately on its host (stop the service, then delete its install directory and config). Until you do, its polls are rejected with a 404 — harmless, but noisy in its logs, and covered under Troubleshooting below.

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

### The platform is presenting a certificate for another hostname

Setup stops before offering you a trust decision, and names the certificate's
real identity. A name like `<hash>.traefik.default` means the platform's TLS
secret is missing and its ingress controller is serving a self-issued
placeholder. This is a platform-side fix; no CA you pin on the agent changes the
outcome, because hostname verification runs before signature verification. See
[Platforms with a privately-signed certificate](#platforms-with-a-privately-signed-certificate).

### HTTP 404 "Agent not registered" on every poll

The agent was **deleted from the platform** (Discovery → Sensors & Agents), but the binary is still installed and running. This is the expected, deliberate response: a removed agent is rejected at the door and receives no jobs and no credentials, even though its certificate file is still on disk.

It is not a network fault and there is nothing to fix on the platform side. Either stop and uninstall the agent on this host, or — if it was deleted by mistake — mint a fresh registration key and enroll it again. The old key cannot be reused.

### Agent Not Receiving Jobs

1. Verify registration key is correct
2. Check agent status in platform UI — if the agent is missing from the **Discovery agents** table entirely, it has been deleted (see the 404 entry above)
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

# Stamp a release version into the binaries (reported at registration and
# shown in the UI). Without AGENT_VERSION the binary reports "dev".
make device-agent-all-platforms AGENT_VERSION=v0.5.1

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

# Upload with a specific version tag
make device-agent-upload DEVICE_AGENT_VERSION=v1.0.0

# Dry run (preview what would be uploaded, without the Makefile's build step)
go run scripts/upload-device-agent-artifacts.go -artifacts-dir artifacts/device-agent -dry-run
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
