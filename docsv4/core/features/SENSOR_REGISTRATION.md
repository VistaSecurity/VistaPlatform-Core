# Enhanced Sensor Registration & Management Guide

## Overview

The Vista Platform provides a comprehensive sensor registration and management system that enables administrators to easily deploy and manage network sensors at scale. The enhanced system features simplified registration workflows, mTLS security, binary downloads, and full sensor lifecycle management.

## Key Features

- **Simplified Registration**: Minimal fields required (name, IP address, optional description)
- **Recent Registration History**: View and manage recent registrations with details
- **mTLS Security**: Automatic certificate generation and validation
- **Cross-Platform Downloads**: Pre-built binaries for Linux, Windows, and macOS
- **Full Sensor Management**: Interface management, configuration updates, certificate regeneration
- **Real-time Status**: Live sensor status and health monitoring
- **System Sensors**: Platform-provided sensors that automatically appear in every tenant's sensor list

## Architecture

The enhanced sensor registration system consists of:

- **Enhanced UI Components**: Simplified modals with registration history
- **mTLS Certificate Management**: Automatic CA and sensor certificate generation
- **Cross-platform Binaries**: Signed GitHub Release assets per OS/architecture
- **Sensor Management APIs**: Full lifecycle management endpoints
- **Real-time Updates**: Live status and configuration management
- **System Sensors**: Platform-provided sensors with automated health synchronization
- **Bootstrap mTLS Certificates**: Secure mTLS certificate-based authentication for platform sensor registration

## System Sensors

Every tenant automatically has access to two **System Sensors** that are provided by the platform:

### Platform Discovery Sensor
- **ID**: `550e8400-e29b-41d4-a716-446655440001`
- **Purpose**: Network discovery operations across the platform
- **Service**: Backed by `cluster-sensor-service`

### Platform Device Interrogation Agent
- **ID**: `550e8400-e29b-41d4-a716-446655440002`
- **Purpose**: Device interrogation and data collection
- **Service**: Backed by `device-interrogation-service`

### How System Sensors Work

1. **Automatic Provisioning**: System sensor records are automatically created in the `sensors` table for each tenant via database triggers and seed data
2. **Health Synchronization**: The `sensor-manager` runs a background service that periodically checks the health of platform services and updates the system sensor status/heartbeat
3. **Tenant-Specific Data**: Discovery counts and activities are filtered by tenant, so each tenant sees only their own data
4. **Shared Resources**: The underlying platform services are shared, but each tenant has their own sensor record for viewing and tracking

### UI Differentiation

System sensors are visually distinguished in the Sensor Management UI:
- **Blue/Indigo Background**: System sensor rows have a distinct background color
- **"System" Type Badge**: Instead of "network" or "endpoint", system sensors show a "System" badge
- **No Delete Button**: System sensors cannot be deleted by tenants
- **Platform Banner**: The sensor details view shows a banner indicating it's a platform-managed sensor
- **Hidden Certificate Info**: Certificate details are hidden as system sensors use platform-level authentication

## Enhanced Registration Workflow

### 1. Simplified Registration Process

The new registration process requires only essential information:

1. **Navigate to Sensor Management** page
2. **Click "Register New Sensor"** (opens modal)
3. **Fill minimal required fields**:
   - **Name**: Human-readable sensor name (required)
   - **IP Address**: Expected IP address for validation (required)
   - **Description**: Optional description
4. **Click "Generate Registration Key"**

The system automatically:
- Sets default profile (`datacenter_host`)
- Generates unique registration key
- Creates pending registration with 60-minute expiration
- Shows registration in recent history

### 2. Registration Details & Downloads

After key generation, the **Registration Details Modal** provides:

#### Registration Information
- **Registration Key**: Copy-to-clipboard functionality
- **Status**: Pending/Used/Expired with visual indicators
- **Created/Expires**: Timestamps with timezone
- **Profile**: Deployment profile information

#### Installation Commands
- **Registration Key**: Copy-to-clipboard command showing the key, expected IP,
  and sensor name to pass to the installer
- **Copy Commands**: One-click copy to clipboard

#### Getting the Sensor Binary
The registration modal does not serve the binary itself — get it one of two ways
(see "Getting the Sensor Binary" below for the full instructions):

- **GitHub Release** (recommended): every Vista Platform release publishes
  pre-built binaries for Linux (x86_64, ARM64), Windows (x86_64, 386), and
  macOS (x86_64, Apple Silicon) — named `crypto-sensor-<os>-<arch>` — as assets
  on the matching GitHub Release, alongside a signed `SHA256SUMS`.
- **Build from source**: `make build-sensor` (current platform) or
  `make sensor-all-platforms` (all supported targets).

#### mTLS Certificates (CSR-Based Flow)
- **Secure Generation**: Sensor generates private key locally and creates Certificate Signing Request (CSR)
- **Platform Signing**: Platform signs CSR and returns only the certificate (private key never leaves sensor)
- **Automatic Rotation**: Sensors automatically rotate certificates when expiring within 30 days
- **Certificate Management**: View certificate status, expiration, and revocation in the Certificates tab

### 3. Pending Registrations Section

The **Sensor Management** page now prominently displays a **Pending Registrations** section at the top of the main content area:

- **Immediate Visibility**: All pending registrations are displayed as cards above the sensor filters
- **Visual Distinction**: Yellow/amber background highlights pending items requiring attention
- **Quick Actions**: Each card provides:
  - **View Guide**: Opens the installation guide with registration-specific details
  - **Delete**: Remove pending registration if no longer needed
- **Expiration Countdown**: Real-time display of time remaining before expiration
- **Auto-Hide**: Section automatically hides when no pending registrations exist

### 4. Recent Registrations Management

The enhanced registration modal includes a **Recent Registrations** panel:

- **Status Indicators**: Visual status (pending/used/expired)
- **Quick Details**: Name, IP, description, timestamps
- **Details Button**: Opens full registration details modal
- **Real-time Updates**: Status updates as registrations are used

### 5. Accessing Installation Instructions

Installation instructions are accessible from multiple entry points:

1. **Installation Guide Button**: Located in the sensor management page header, next to the "Register new" button
   - Opens a generic installation guide modal
   - Platform selection (Linux, Windows, macOS)
   - Generic installation commands for interactive setup
   - Platform-specific prerequisites

2. **Pending Registration Cards**: Click "View Guide" on any pending registration card
   - Opens installation guide with registration-specific details
   - Pre-filled registration key and IP address
   - Installation commands ready to copy

3. **Registration Details Modal**: After generating a registration key
   - Full installation instructions
   - Registration-specific commands, pre-filled with the key, IP, and name
   - mTLS certificate information

Neither the modal nor the guide serves the binary — see "Getting the Sensor
Binary" below.

### 6. Sensor Installation

Installing a sensor needs two things together: the platform-specific
**binary**, and the `install-sensor.sh` (Linux/macOS) or `install-sensor.ps1`
(Windows) installer script tracked in this repository at `scripts/`.

#### Getting the Sensor Binary
- **From a GitHub Release** (recommended): download the
  `crypto-sensor-<os>-<arch>` asset matching your platform — e.g.
  `crypto-sensor-linux-amd64` — from the release matching your installed
  version, and verify it against that release's signed `SHA256SUMS` (see
  "Verifying the binary" below).
- **Build it yourself**: `make build-sensor` from a checkout of this
  repository (or `make sensor-all-platforms` to build every supported
  target).

Then get the matching installer script — clone this repository, or download
`scripts/install-sensor.sh` / `scripts/install-sensor.ps1` directly for the
tag you installed — and place it alongside the binary.

#### Running the Installer
The **Registration Details Modal** and the **Pending Registration** card build
the exact command for you, pre-filled with the registration key, expected IP,
and sensor name:

```bash
sudo ./install-sensor.sh --url https://<your-vista-host> --key REG-tenant-20260420-A7B3C9 --ip 192.168.1.100 --name sensor-dc01
```
```powershell
.\install-sensor.ps1 -Url https://<your-vista-host> -Key REG-tenant-20260420-A7B3C9 -IP 192.168.1.100 -Name sensor-dc01
```

The installer places the binary, drives the CSR-based mTLS enrollment
described below, and registers it as a service.

#### Verifying the Binary
Every release publishes a `SHA256SUMS` file alongside the binaries, signed
with cosign (keyless OIDC — no key to trust):

```bash
cosign verify-blob SHA256SUMS \
  --signature SHA256SUMS.sig --certificate SHA256SUMS.pem \
  --certificate-identity-regexp 'https://github.com/VistaSecurity/VistaPlatform-Core/.github/workflows/release-core.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS
```

## Enhanced Sensor Management

### Interfaces & Config Tab

The new **Interfaces & Config** tab provides comprehensive sensor management:

#### Network Interfaces Management
- **Current Interfaces**: List all configured interfaces with remove buttons
- **Add Interface**: Input field to add new network interfaces
- **Real-time Updates**: Immediate interface list updates
- **Validation**: Interface name validation and error handling

#### Sensor Configuration
- **Profile Selection**: Choose deployment profile (datacenter_host, cloud_instance, etc.)
- **Description Editor**: Update sensor description
- **Tags Management**: Checkbox grid for common tags
- **Update Configuration**: Save all changes with validation

#### Certificate Management (Certificates Tab)
The new **Certificates** tab provides comprehensive certificate management:
- **Certificate Status**: View certificate expiration, revocation status, and details
- **Automatic Rotation**: Sensors automatically rotate certificates when expiring within 30 days
- **Manual Rotation**: Request manual rotation (sensor-initiated)
- **Certificate Revocation**: Revoke certificates with reason tracking
- **CSR-Based Security**: Information about secure certificate generation flow

## API Endpoints

### Enhanced Registration Endpoints

#### Create Pending Sensor (Simplified)
```http
POST /api/v1/sensor-manager/sensors/pending
Content-Type: application/json

{
  "name": "sensor-dc01",
  "ip_address": "192.168.1.100",
  "description": "Main datacenter sensor"
}
```

#### Register Sensor (CSR-Based mTLS)
```http
POST /api/v1/sensor-manager/sensors/register
Content-Type: application/json

{
  "registration_key": "REG-...",
  "name": "sensor-dc01",
  "platform": "linux",
  "version": "1.0.0",
  "profile": "datacenter_host",
  "network_interfaces": ["eth0"],
  "ip_address": "192.168.1.100",
  "description": "Main datacenter sensor",
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...",
  "sensor_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response (CSR-Based Flow):**
```json
{
  "sensor_id": "550e8400-e29b-41d4-a716-446655440000",
  "client_cert": "-----BEGIN CERTIFICATE-----\n...",
  "server_ca_cert": "-----BEGIN CERTIFICATE-----\n...",
  "certificate_expires_at": "2026-04-27T10:30:00Z",
  "config": {
    "control_plane_url": "https://crypto-inventory.company.com",
    "reporting_interval": 30,
    "features": {
      "tls_analysis": true,
      "ssh_analysis": true,
      "certificate_analysis": true,
      "active_probing": true,
      "network_discovery": true
    }
  }
}
```

**Note**: The `client_key` is NOT included in the response - it remains on the sensor host and is never transmitted to the platform.

### There is no binary-download API

The platform does not serve sensor binaries over HTTP at all — no service has a
download endpoint, for tenants or for platform admins. The two supported ways to
get the binary are the signed GitHub Release asset and `make build-sensor`,
both described in "Getting the Sensor Binary" above.

### Sensor Management Endpoints

#### Update Network Interfaces
```http
PUT /api/v1/sensor-manager/sensors/{sensor_id}/interfaces
Content-Type: application/json

{
  "add": ["eth1", "wlan0"],
  "remove": ["eth0"]
}
```

#### Update Sensor Configuration
```http
PUT /api/v1/sensor-manager/sensors/{sensor_id}/config
Content-Type: application/json

{
  "profile": "cloud_instance",
  "description": "Updated description",
  "tags": ["production", "cloud"]
}
```

#### Rotate Certificate (CSR-Based)
```http
POST /api/v1/sensor-manager/sensors/{sensor_id}/certificates/rotate
Content-Type: application/json

{
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\n..."
}
```

**Response:**
```json
{
  "sensor_id": "550e8400-e29b-41d4-a716-446655440000",
  "client_cert": "-----BEGIN CERTIFICATE-----\n...",
  "server_ca_cert": "-----BEGIN CERTIFICATE-----\n...",
  "certificate_expires_at": "2026-04-27T10:30:00Z",
  "message": "Certificate rotated successfully"
}
```

#### Revoke Certificate
```http
POST /api/v1/sensor-manager/sensors/{sensor_id}/certificates/revoke
Content-Type: application/json

{
  "reason": "compromised"
}
```

**Response:**
```json
{
  "message": "Certificate revoked successfully",
  "sensor_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

#### Get Certificate Status
```http
GET /api/v1/sensor-manager/sensors/{sensor_id}/certificates
```

**Response:**
```json
{
  "sensor_id": "550e8400-e29b-41d4-a716-446655440000",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
  "serial_number": "1234567890",
  "issued_at": "2026-04-28T10:30:00Z",
  "expires_at": "2026-04-27T10:30:00Z",
  "revoked_at": null
}
```

## Security Features

### Trusting a Privately-Signed Platform (Trust Bootstrap)

A self-hosted platform commonly serves its edge certificate from an internal CA
that the agent's host does not trust. Registration is itself an HTTPS call, so
without a trust anchor it fails certificate verification before a sensor can
enroll. Agents resolve this the way SSH resolves an unknown host key — an
explicit, one-time decision — and **never** by skipping verification.

**Interactive install.** `crypto-sensor --interactive` (and
`device-agent --interactive`) detect the untrusted certificate during the
connectivity check, then show the CA the platform presents and ask:

```
⚠️  The platform's certificate is not signed by any CA this host trusts.

    Subject:     CN=Acme Internal Root CA,O=Acme Corp
    Issuer:      CN=Acme Internal Root CA,O=Acme Corp
    Type:        self-signed root CA
    Valid:       2026-08-11 → 2027-08-11
    SHA-256:     43:7c:fc:92:2e:3a:2f:24:1c:53:c4:e2:a8:de:49:64:
                 e3:7e:d7:12:46:ff:6e:98:69:47:bf:ac:72:b8:f0:f6

Trust this CA for this agent? (y/N):
```

Accepting writes the CA to `<dataPath>/certs/platform-ca.crt` and records
`security.serverCACertPath` in the agent's config. Declining cancels setup; the
agent will not connect to a platform it cannot verify.

The anchor you approve verifies **enrollment** — the connection that matters
most, because it happens before the agent has any other way to know who it is
talking to. It then keeps verifying every connection afterwards.

Registration additionally returns the platform's own CA, and the agent **adds**
it to its trust pool rather than replacing what you approved. Both are kept, and
that is deliberate: the CA you approved is what signs the ordinary endpoint,
while the one returned at registration signs the mTLS passthrough listener that
exists only when `agentMtls` is enabled. Which of the two an agent ends up
talking to is a deployment choice, so it carries both and verifies against
whichever applies. The second CA is safe to trust because it arrives over the
connection the first one just authenticated.

So the file on disk after enrollment may contain more certificates than you
approved, but never fewer. Verification is never disabled in either phase.

**Unattended install.** A scripted install cannot answer a prompt, so pass the
expected fingerprint instead:

```bash
crypto-sensor --ca-fingerprint 437cfc922e3a2f241c53c4e2a8de4964e37ed71246ff6e986947bfac72b8f0f6
```

The agent pins the CA only if it hashes to that value, and aborts loudly on a
mismatch. Colons, uppercase, and a `sha256:` prefix are all accepted. With no
fingerprint and no operator to ask, the agent refuses rather than pinning
something nobody approved.

**Where to get the expected fingerprint.** The platform shows it to you when you
mint the registration code: **Discovery → Sensors & Agents → Register sensor or
agent**, on the confirmation screen directly beneath the registration code and
install commands. Copy it, then compare against what the agent prints.

The panel appears only when it is needed. A platform whose certificate is
publicly trusted shows nothing — agents verify it automatically and never
prompt. If the platform cannot inspect its own certificate (no public URL
configured, plain HTTP), the panel says so and points at the manual route:

```bash
openssl s_client -showcerts -connect <platform-host>:443 </dev/null 2>/dev/null | openssl x509 -outform PEM | openssl x509 -noout -fingerprint -sha256
```

**Why the comparison is the whole point.** This is trust-on-first-use: an
attacker positioned at the moment of enrollment could present their own CA and
the prompt would happily offer it for approval. Reading the expected value from
the web UI — a separate, authenticated session — is what closes that gap. An
approval given without comparing provides no protection at all.

If the agent shows a fingerprint that does not match, stop. Either the CA was
rotated since you last looked, or something is sitting between the agent and the
platform.

**When none of this applies.** A platform with a publicly-trusted certificate
verifies against the host's system trust store and the prompt never appears.
Installing the internal CA into the host trust store
(`/usr/local/share/ca-certificates/` + `update-ca-certificates` on Linux) has
the same effect.

### Enhanced mTLS Security (CSR-Based Flow)
- **Secure Certificate Generation**: Sensors generate private keys locally and never transmit them to the platform
- **CSR-Based Issuance**: Certificates issued via Certificate Signing Requests (CSR)
- **Persistent Tenant CA**: Each tenant has a persistent Certificate Authority (10-year validity)
- **Comprehensive Validation**: Certificate chain validation, expiration checks, and revocation status
- **Automatic Rotation**: Sensors automatically rotate certificates when expiring within 30 days
- **Secure Communication**: All sensor-to-control-plane communication encrypted with mTLS

### IP Address Validation
- **Registration Key Binding**: Keys bound to specific IP addresses
- **Network Validation**: Sensors must register from expected IP
- **Subnet Support**: Flexible IP validation for dynamic environments

### Key Management
- **Time-Limited Keys**: Configurable expiration (default: 60 minutes)
- **Single-Use Keys**: Keys marked as "used" after successful registration
- **Tenant Isolation**: 
  - Keys are tenant-specific and isolated
  - Registration key lookup retrieves tenant_id from database (source of truth)
  - Sensor inherits tenant_id from registration key, not from request
  - Database-level Row Level Security (RLS) enforces tenant isolation

## Build System & Artifacts

### Cross-Platform Build Targets

`.github/workflows/release-core.yml` builds the sensor for every supported
platform on every release (Linux x86_64/ARM64, Windows x86_64/386, macOS
x86_64/Apple Silicon) and attaches the binaries to the GitHub Release. The
same targets are available locally:

```bash
# Build for all platforms
make sensor-all-platforms

# Build for specific platforms
make sensor-linux-amd64
make sensor-linux-arm64
make sensor-windows-amd64
make sensor-windows-386
make sensor-darwin-amd64
make sensor-darwin-arm64

# Current platform only
make build-sensor
```

The sensor is CGO-linked against libpcap, so Linux and macOS builds run
natively per-platform rather than cross-compiling; Windows is CGO-free and
cross-compiles from Linux.

### Build Output

`make sensor-<platform>` places the binary at `bin/crypto-sensor-<os>-<arch>`
(or `bin/crypto-sensor-<os>-<arch>.exe` on Windows) and additionally copies it,
already bundled with the matching `install-sensor.sh` / `.ps1`, into
`artifacts/sensor/<os>/<arch>/`:

```
artifacts/sensor/
├── linux/
│   ├── amd64/{crypto-sensor,install-sensor.sh}     # Linux x86_64
│   └── arm64/{crypto-sensor,install-sensor.sh}     # Linux ARM64
├── windows/
│   ├── amd64/{crypto-sensor.exe,install-sensor.ps1}
│   └── 386/{crypto-sensor.exe,install-sensor.ps1}
└── darwin/
    ├── amd64/{crypto-sensor,install-sensor.sh}     # macOS x86_64
    └── arm64/{crypto-sensor,install-sensor.sh}     # macOS ARM64
```

This directory is a local build convenience only — nothing serves it over
HTTP. See [`artifacts/README.md`](../../../artifacts/README.md).

## Troubleshooting

### Enhanced Debugging

#### Registration Issues
1. **Check Recent Registrations**: View status in the enhanced modal
2. **Validate Registration Key**: Use the details modal to verify key status
3. **Confirm the Binary and Installer Match**: The `install-sensor.sh`/`.ps1`
   version should match the binary's — mixing versions from different releases
   is the most common install failure
4. **Check Certificate Generation**: Ensure mTLS certificates are created

#### Sensor Management Issues
1. **Interface Management**: Verify interface names and permissions
2. **Configuration Updates**: Check for validation errors
3. **Certificate Regeneration**: Monitor certificate expiration and rotation
4. **Real-time Status**: Use the enhanced UI for live status monitoring

### Common Solutions

#### "Registration key not found"
- **Cause**: Key expired or doesn't exist
- **Solution**: Generate new key using enhanced modal

#### "Certificate validation failed"
- **Cause**: Certificate CN mismatch, expired, revoked, or chain validation failure
- **Solution**: Check certificate status in Certificates tab, rotate if needed

#### "Certificate has expired"
- **Cause**: Certificate past expiration date
- **Solution**: Sensor should automatically rotate, or manually trigger rotation

#### "Certificate has been revoked"
- **Cause**: Certificate was revoked by administrator
- **Solution**: Sensor must re-register to obtain new certificate

#### "Can't find a binary for my platform"
- **Cause**: The GitHub Release for the installed version doesn't cover your
  OS/architecture, or you're looking for a download endpoint that no longer
  exists on the platform
- **Solution**: Check the Release's assets for `crypto-sensor-<os>-<arch>`, or
  build it yourself with `make sensor-<platform>` / `make sensor-all-platforms`

## Configuration

### Enhanced Admin Settings

| Setting | Description | Range | Default |
|---------|-------------|-------|---------|
| `key_expiration_minutes` | Registration key expiration time | 5-1440 | 60 |
| `max_pending_sensors` | Maximum pending registrations | 1-1000 | 50 |
| `require_ip_validation` | Enable IP address validation | true/false | true |
| `mtls_enabled` | Enable mTLS certificate generation | true/false | true |
| `certificate_expiry_days` | Certificate validity period | 30-365 | 365 |

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CERTIFICATE_CA_PATH` | CA certificate storage path | `/app/certs/ca` |
| `CERTIFICATE_EXPIRY_DAYS` | Certificate validity period | `365` |

## Best Practices

### Enhanced Security
- **Regular Certificate Rotation**: Rotate certificates annually or when compromised
- **Monitor Registration Attempts**: Track failed registration attempts
- **Use Strong Keys**: Generate cryptographically secure registration keys
- **Network Segmentation**: Isolate sensor networks from management networks

### Operational Excellence
- **Use Descriptive Names**: Clear, consistent sensor naming conventions
- **Tag Management**: Organize sensors with meaningful tags
- **Monitor Interface Changes**: Track network interface modifications
- **Document Configurations**: Maintain configuration documentation

### Performance Optimization
- **Batch Operations**: Use bulk interface updates when possible
- **Efficient Downloads**: Cache binary artifacts for faster deployments
- **Connection Pooling**: Optimize sensor-to-control-plane connections
- **Resource Monitoring**: Monitor sensor resource usage and health

## Support & Resources

### Documentation
- **API Reference**: Complete endpoint documentation
- **Certificate Management**: mTLS setup and troubleshooting
- **Build System**: Cross-platform compilation guide
- **Deployment Guide**: Production deployment best practices

### Community & Support
- **Internal Wiki**: [Company Wiki](https://wiki.company.com/crypto-inventory)
- **GitHub Issues**: [Issue Tracker](https://github.com/company/crypto-inventory/issues)
- **Slack Channel**: #crypto-inventory-support
- **Email Support**: crypto-inventory-support@company.com

### Training & Onboarding
- **Video Tutorials**: Enhanced UI walkthrough videos
- **Hands-on Labs**: Interactive sensor deployment exercises
- **Certification Program**: Platform administration certification
- **Best Practices Guide**: Production deployment guidelines

## Changing a Sensor's Reporting Interval

The **reporting interval** is how often a sensor sends discovered data to the
platform. It's configured on the sensor at install time, reported up to the
control plane, and shown on each sensor's **Overview** tab ("Reporting interval").

To change it from the console (requires the **Manage sensors** permission):

1. Go to **Operations → Sensors & Agents** and click the sensor.
2. Open the **Control** tab → **Reporting interval**.
3. Pick a value from the menu — **30 seconds, 1 / 5 / 15 / 30 minutes, or 1 / 2 /
   4 / 8 / 12 / 24 hours** — and click **Apply**.

The change is **queued as a command** and takes effect the next time the sensor
checks in (so an offline sensor picks it up when it reconnects). Once applied,
the sensor reports the new interval back and the Overview tab updates. The new
value is saved on the sensor, so it persists across restarts.

**Choosing a value:** shorter intervals surface discoveries faster but generate
more traffic and platform load; longer intervals are better for low-change or
bandwidth-constrained environments. For large fleets, standardizing on a few
intervals keeps load predictable.
