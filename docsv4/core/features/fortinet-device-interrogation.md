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
  - Local certificate store
  - Certificate metadata
  - Certificate usage information

#### System Information
- **Endpoint**: `/api/v2/cmdb/system/status`
- **Data Collected**:
  - Device firmware version
  - System status
  - Device metadata

## Workflow

### 1. Register Fortinet Device

Register a Fortinet device with the platform:

**UI:** Navigate to Devices → Add Device

**API:** `POST /api/v1/device-interrogation-service/devices`

**Request Body:**
```json
{
  "device_type": "fortinet",
  "vendor": "Fortinet",
  "model": "FortiGate-100F",
  "hostname": "fw01.example.com",
  "ip_address": "10.0.1.1",
  "management_url": "https://fw01.example.com",
  "firmware_version": "7.4.0",
  "discovery_method": "device_interrogation",
  "credential_id": "uuid-of-platform-integration"
}
```

### 2. Configure Credentials

Store Fortinet credentials in platform integrations:

**UI:** Navigate to Settings → Integrations → Add Integration

**Required Fields:**
- Integration Type: `fortinet` (or generic device type)
- Username: FortiGate admin username
- Password: FortiGate admin password
- URL: Management URL (optional, uses device management_url if not provided)
- Insecure Skip Verify: Boolean (for self-signed certificates)

Credentials are encrypted at rest and decrypted only when needed.

### 3. Interrogate Device

Initiate device interrogation:

**UI:** Navigate to Devices → Select Device → Interrogate

**API:** `POST /api/v1/device-interrogation-service/devices/:id/interrogate`

The service automatically:
1. Creates a discovery job
2. Retrieves and decrypts device credentials
3. Connects to FortiGate via REST API
4. Interrogates SSL VPN, IPSec, and certificate configurations
5. Parses crypto details from configurations
6. Creates discovery findings for each discovered asset

### 4. Review Results

Review discovery findings:

**UI:** Navigate to Assets → Discovery Jobs → View Results

**Findings Include:**
- SSL VPN configurations with detailed crypto parameters
- IPSec tunnel configurations with encryption/authentication details
- Certificate information
- Device metadata

### 5. Import to Inventory

Import findings as infrastructure assets:

**UI:** Select findings → Import Selected

Imported assets are:
- Linked to parent device via `device_id`
- Created with `discovery_method = 'device_interrogation'`
- Set to `pending_approval` status

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
- Extracts Diffie-Hellman group information
- Stores in metadata for key exchange analysis

**Example Extracted Data:**
```json
{
  "protocol": "IPSec",
  "cipher_suite": "aes256-sha256",
  "key_size": 256,
  "hash_algorithm": "SHA256",
  "port": 500,
  "hostname": "tunnel-to-remote-site",
  "ip_address": "192.168.1.1",
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
      "ip_address": "192.168.1.1",
      "port": 500,
      "protocol": "IPSec",
      "cipher_suite": "aes256-sha256",
      "key_size": 256,
      "hash_algorithm": "SHA256",
      "metadata": {
        "name": "tunnel-to-datacenter",
        "remote-gw": "192.168.1.1",
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
- Credentials encrypted at rest in `platform_integrations` table
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

- [Device Interrogation Feature](./device-interrogation.md)
- [Platform Integrations](../operate/configuration/platform-integrations.md)
- [Discovery Feature](./discovery.md)
