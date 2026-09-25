# Fortinet Device Interrogation

Direct interrogation of Fortinet FortiGate devices to collect cryptographic configurations.

## Overview

Fortinet Device Interrogation enables direct collection of cryptographic configurations from FortiGate firewalls via the FortiGate REST API, providing comprehensive visibility into SSL VPN, IPSec, and certificate configurations.

## Supported FortiGate Features

### ✅ Fully Implemented

#### SSL VPN Interrogation
- **Endpoint**: `/api/v2/cmdb/vpn/ssl/settings`
- **Data Collected**:
  - SSL VPN server configurations
  - Cipher suites and TLS versions
  - Key sizes (extracted from cipher names)
  - Hash algorithms (extracted from cipher suites)
  - Server hostnames and IP addresses
  - Port configurations

#### IPSec Tunnel Interrogation
- **Endpoint**: `/api/v2/cmdb/vpn/ipsec/phase1-interface`
- **Data Collected**:
  - Phase 1 interface configurations
  - Encryption algorithms and key sizes
  - Authentication algorithms and hash algorithms
  - DH (Diffie-Hellman) groups for key exchange
  - Remote gateway information
  - Proposal details

#### Certificate Store
- **Endpoint**: `/api/v2/cmdb/certificate/local`
- **Data Collected**:
  - Certificate name, source and state
  - The certificate body, from which subject, issuer, serial, validity,
    key algorithm and size, signature algorithm, SANs and fingerprints are parsed

#### System Information
- **Endpoint**: `/api/v2/cmdb/system/status`
- **Data Collected**:
  - Device firmware version, build and branch point
  - Model and serial number
  - Hostname

### What is deliberately not collected

FortiOS `cmdb` endpoints return configuration, which means they return the
material that makes the configuration work. Each response is projected onto the
fields listed above; everything else is discarded before the result leaves the
collector. In particular:

| Endpoint | Field dropped | Why it matters |
|---|---|---|
| `vpn.ipsec/phase1-interface` | `psksecret`, `ppk-secret`, `authpasswd` | The tunnel's pre-shared key |
| `certificate/local` | `private-key`, `password`, `csr` | The certificate's own private key |
| `system/status` | admin/session detail | Not cryptographic posture |

The platform inventories what algorithms a device uses, not the keys it uses
them with.

## Workflow

### 1. Add the FortiGate

**Where:** **Discovery → Devices → Add device**. Give the management URL,
username and password; the platform asks the FortiGate for its own model,
serial, firmware and host name (`system/status` only).

**Credentials belong to the device.** A FortiGate carries its own username and
password, entered on the device form and encrypted at rest — there is no
separate integration record to create and link. **Skip TLS verification** is
there for a management interface with a self-signed certificate.

**API:** `POST /api/v1/device-interrogation-service/devices`

```json
{
  "device_type": "fortinet",
  "vendor": "Fortinet",
  "model": "FortiGate-100F",
  "hostname": "fw01.example.com",
  "ip_address": "10.0.1.1",
  "management_url": "https://fw01.example.com",
  "username": "vista-readonly",
  "password": "…"
}
```

### 2. Interrogate

**Where:** the device's row on **Discovery → Devices** → **Interrogate**. **Test
connection** first if you want to check the credentials before queueing work.

**API:** `POST /api/v1/device-interrogation-service/devices/:id/interrogate`

The run creates a job, decrypts the credentials for that job only, connects over
the FortiGate REST API, reads the SSL VPN, IPSec and certificate configuration,
parses the cryptographic detail out of it, and produces a finding per discovered
asset.

### 3. Review the run

**Where:** **Discovery → Discovery Jobs**, or **Discovery → Job Logs** for the
per-stage detail. The run reports what it discovered and what reached inventory
as two separate counts, so a job that answered but materialized nothing says so.

Findings include the SSL VPN configuration with its crypto parameters, each
IPSec tunnel with its encryption and authentication algorithms, the certificates
found, and the device's own identity.

### 4. Where it lands

There is no import step and nothing to select. Findings flow into the inventory
through the normal pipeline: the asset is auto-approved if its network segment
says so, and otherwise waits on **Discovery → Approvals**. Assets carry a
discovery method of `device_interrogation`.

## Crypto Parameter Extraction

### SSL VPN Crypto Details

The service extracts detailed crypto parameters from SSL VPN configurations:

**Cipher Suite Parsing:**
- Extracts cipher names (e.g., `AES256-SHA256`)
- Determines key sizes (128, 256) from cipher names
- Extracts hash algorithms (SHA1, SHA256, SHA384, SHA512) from cipher names

**TLS Version Extraction:**
- Reads `tls_version` or `min_tls_version` from configuration
- Defaults to TLS 1.2 if not specified

**Example Extracted Data:**
```json
{
  "protocol": "SSL VPN",
  "protocol_version": "TLS 1.2",
  "cipher_suite": "AES256-SHA256",
  "key_size": 256,
  "hash_algorithm": "SHA256",
  "port": 443,
  "hostname": "vpn.example.com",
  "ip_address": "10.0.1.1"
}
```

### IPSec Crypto Details

The service extracts detailed crypto parameters from IPSec configurations:

**Encryption Algorithm Parsing:**
- Extracts encryption algorithms (AES, 3DES, etc.)
- Determines key sizes from algorithm names
- Extracts authentication algorithms

**Hash Algorithm Extraction:**
- Parses hash algorithms from proposal names
- Extracts from authentication algorithm fields

**DH Group Information:**
- Reads the tunnel's Diffie-Hellman groups (`dhgrp`, e.g. `14 5`, in preference order)
- Reports the first group as the tunnel's key exchange, and links **every**
  configured group to the algorithm catalogue, so the tunnel is scored on the
  weakest group it offers and appears as needing post-quantum migration
- `key_size` is the key exchange's size (the group's modulus or curve), not the
  cipher's

**Example Extracted Data:**
```json
{
  "protocol": "IPSec",
  "cipher_suite": "aes256-sha256",
  "key_exchange_algorithm": "DH-MODP-2048",
  "key_size": 2048,
  "hash_algorithm": "SHA256",
  "port": 500,
  "hostname": "tunnel-to-remote-site",
  "ip_address": "10.0.0.1",
  "metadata": {
    "encryption_algorithm": "aes256",
    "authentication_algorithm": "sha256",
    "dh_group": "14"
  }
}
```

## Example Discovery Result

```json
{
  "job_id": "uuid",
  "assets": [
    {
      "hostname": "vpn.example.com",
      "ip_address": "10.0.1.1",
      "port": 443,
      "protocol": "SSL VPN",
      "protocol_version": "TLS 1.2",
      "cipher_suite": "AES256-SHA256",
      "key_size": 256,
      "hash_algorithm": "SHA256",
      "metadata": {
        "server_hostname": "vpn.example.com",
        "server_ip": "10.0.1.1",
        "port": 443,
        "cipher": "AES256-SHA256"
      }
    },
    {
      "hostname": "tunnel-to-datacenter",
      "ip_address": "10.0.0.1",
      "port": 500,
      "protocol": "IPSec",
      "cipher_suite": "aes256-sha256",
      "key_size": 256,
      "hash_algorithm": "SHA256",
      "metadata": {
        "name": "tunnel-to-datacenter",
        "remote-gw": "10.0.0.1",
        "proposal": "aes256-sha256",
        "encryption": "aes256",
        "authentication": "sha256",
        "dhgrp": "14"
      }
    }
  ],
  "device_info": {
    "version": "v7.4.0",
    "serial": "FG100FTK12345678",
    "hostname": "fw01"
  }
}
```

## Error Handling

### Connection Errors
- **Authentication Failures**: Stored in `device.interrogation_error`
- **Connection Timeouts**: Device `connection_status` set to `error`
- **API Errors**: Logged and reported in job status

### Status Updates
- **Success**: `connection_status = 'connected'`, `last_interrogated_at` updated
- **Failure**: `connection_status = 'error'`, `interrogation_error` populated
- **Errors Cleared**: On successful subsequent interrogation

## Security Considerations

### Credential Management
- Credentials are encrypted at rest on the device record
- Decrypted only when needed for API calls
- Never logged or exposed in responses
- Credentials cleared from memory after use

### API Authentication
- FortiGate REST API uses HTTP Basic Authentication
- Supports self-signed certificates (configurable via `insecure_skip_verify`)
- All communication over HTTPS

### Network Security
- Device must be reachable from platform service
- For on-premises devices, consider deploying device-agent binary
- Agent uses outbound-only communication (no inbound ports required)

## FortiGate API Requirements

### Required Permissions
- Read access to SSL VPN settings
- Read access to IPSec phase1-interface configurations
- Read access to certificate store
- Read access to system status

### API Version
- FortiGate REST API v2 (`/api/v2/`)
- Compatible with FortiOS 6.0 and later

## Limitations

### Current Implementation
- ✅ SSL VPN interrogation fully implemented
- ✅ IPSec tunnel interrogation fully implemented
- ✅ Certificate store retrieval fully implemented
- ✅ Crypto parameter extraction fully implemented
- 🚧 Additional FortiGate features (SSL inspection policies, etc.) - framework ready

### API Limitations
- Requires FortiGate REST API access
- Some configurations may require specific FortiOS versions
- Rate limiting may apply for large configurations

## Related Documentation

- [Device Interrogation](./device-interrogation.md) — every vendor, and what is collected
- [Device Interrogation User Guide](../guides/device-interrogation-user-guide.md) — the walkthrough
- [Discovery](./discovery.md) — where the findings go
- [Asset Approval](./asset-approval.md) — the queue a discovered asset waits in
