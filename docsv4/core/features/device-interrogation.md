# Device Interrogation Feature

Direct interrogation of network devices and cloud resources to collect cryptographic configurations.

## Overview

Device Interrogation complements the existing network traffic analysis sensor by enabling direct collection of cryptographic configurations from:
- **Network Devices**: F5 load balancers, Cisco routers/switches/ASA, Fortinet firewalls, Palo Alto firewalls, Ubiquiti UniFi
- **Servers & generic endpoints**: PostgreSQL/MySQL databases, generic SNMP devices, and generic HTTPS/TLS endpoints
- **Cloud Resources**: AWS, Azure, and GCP — TLS front ends (load balancers, API gateways, CDN), key-management inventory (KMS / Key Vault / Cloud KMS), and at-rest encryption (object storage, managed SQL)

This provides a more comprehensive view of cryptographic assets, especially for devices that may not generate network traffic or are in isolated networks.

## Use Cases

### 1. Load Balancer Configuration Discovery
Discover TLS configurations for all Virtual IPs (VIPs) on an F5 BigIP load balancer:
- SSL profiles and cipher suites
- Certificate bindings
- TLS version settings
- Multiple VIPs from a single device

### 2. Cloud Resource Discovery
Automatically discover cryptographic configurations and certificates from cloud providers:
- AWS: ALB, ELB, NLB, API Gateway, CloudFront distributions
  - Full certificate chain extraction via TLS handshake against public endpoints
  - ACM metadata enrichment (ARN, renewal eligibility, validation status)
  - Complete crypto implementation records with linked certificates
- Azure: Application Gateway, Load Balancer, App Service TLS bindings
  - TLS handshake verification for Application Gateways
- GCP: Cloud Load Balancing, Cloud SQL encryption settings

### 3. Firewall Configuration Extraction
Extract cryptographic settings from network security devices:
- Fortinet: SSL VPN configurations, IPSec tunnel settings
- Cisco: Crypto maps, IPSec configurations, SSL proxy settings
- Palo Alto: SSL/TLS inspection policies

## Workflow

### 1. Add Device with Auto-Discovery (Recommended)

**NEW:** The platform now supports automatic device discovery for simplified onboarding.

**UI:** Navigate to Discovery → Devices → Add Device

**API:** `POST /api/v1/device-interrogation-service/devices/discover-and-create`

**Required Information (Only 4 fields!):**
- Device type (manufacturer: UniFi, Cisco, F5, Fortinet, Palo Alto)
- Management URL (e.g., `https://192.168.1.1`)
- Username (device admin)
- Password (device admin)

**What Gets Auto-Discovered:**
- ✅ Vendor name
- ✅ Model number
- ✅ Serial number
- ✅ Hostname
- ✅ IP address(es)
- ✅ Firmware version
- ✅ MAC address

**Current Support:**
- ✅ **UniFi (Fully Functional)**: UDM, UDR, USG, UniFi Network Controllers
- 🔧 **Other Vendors**: Framework in place, returns basic vendor info

**Process:**
1. User enters 4 fields
2. Platform connects and authenticates to device
3. Platform queries device API for information
4. Device created with all discovered information
5. Credentials encrypted and stored securely

### 2. Register Device Manually (Alternative)

For devices without auto-discovery support, register manually with all details.

Register a network device or cloud integration with the platform.

**UI:** Navigate to Devices → Add Device

**API:** `POST /api/v1/device-interrogation-service/devices`

**Required Information:**
- Device type (f5, cisco_router, aws_alb, etc.)
- Management URL or IP address
- Credential reference (links to `platform_integrations`)

### 2. Configure Credentials

Store encrypted credentials in platform integrations.

**UI:** Navigate to Settings → Integrations → Add Integration

**Supported Types:**
- AWS: Access Key ID, Secret Access Key
- Azure: Service Principal (Client ID, Client Secret, Tenant ID)
- GCP: Service Account JSON key
- Network Devices: Username/Password, API keys

### 3. Create Interrogation Job

Create a job to interrogate a device or discover cloud resources.

**UI:** Navigate to Devices → Select Device → Interrogate

**API:** `POST /api/v1/device-interrogation-service/devices/:id/interrogate`

**For Cloud Discovery:**
- `POST /api/v1/device-interrogation-service/cloud/discover`

### 4. Review Results

Review discovered cryptographic configurations and assets.

**Results Include (Enriched v2):**
- Infrastructure assets (hostname, IP, port, asset type classification)
- Cryptographic configurations (protocol, cipher suite, key exchange, hash algorithm)
- Supported cipher list and TLS version enumeration
- Full certificate chain with PEM, fingerprints, SANs, key usage
- Certificate validation status (valid, self_signed, expired, hostname_mismatch)
- SSH protocol details (banner, host key type, fingerprint)
- Device identity (vendor, model, firmware version, serial number)
- Service identification hints

### 5. Import to Inventory

Imported assets appear in the inventory with `discovery_method` set to `device_interrogation` or `cloud_api`.

## Device Types

### Network Devices

#### F5 BigIP ✅ **IMPLEMENTED**
- **Method**: iControl REST API
- **Data Collected**: VIP configurations, SSL profiles (client/server), certificate bindings
- **Multiple Assets**: One F5 device → multiple VIPs
- **Endpoints**: 
  - `/mgmt/tm/ltm/virtual` - Virtual servers
  - `/mgmt/tm/ltm/profile/client-ssl` - Client SSL profiles
  - `/mgmt/tm/ltm/profile/server-ssl` - Server SSL profiles

#### Cisco Routers/Switches/ASAs ✅ **IMPLEMENTED**
- **Method**: SSH + CLI commands
- **Data Collected**: Crypto maps, IPSec configurations, ISAKMP/IKE SAs, SSL proxy settings
- **Commands**: `show crypto map`, `show ipsec sa`, `show crypto isakmp sa`, `show ssl`, `show webvpn`
- **Supported Types**: `cisco_router`, `cisco_switch`, `cisco_asa`, `cisco`

#### Fortinet FortiGate ✅ **IMPLEMENTED**
- **Method**: FortiGate REST API
- **Data Collected**: 
  - SSL VPN configurations with detailed crypto parameters
  - IPSec tunnel settings with encryption/authentication algorithms
  - Certificate store information
  - Cipher suites, key sizes, hash algorithms extracted from configs
  - TLS versions and protocol details
- **Endpoints**: 
  - `/api/v2/cmdb/vpn/ssl/settings` - SSL VPN configurations
  - `/api/v2/cmdb/vpn/ipsec/phase1-interface` - IPSec tunnel configurations
  - `/api/v2/cmdb/certificate/local` - Certificate store
  - `/api/v2/cmdb/system/status` - System information

#### Palo Alto Networks ✅ **IMPLEMENTED**
- **Method**: PanOS XML API
- **Data Collected**: SSL decrypt profiles, security rules with SSL settings, certificate configurations
- **Endpoints**: 
  - `/api/?type=keygen` - API key authentication
  - `/api/?type=config&action=get&xpath=/config/devices/entry/network/profiles/ssl-decrypt` - SSL decrypt profiles
  - `/api/?type=config&action=get&xpath=/config/devices/entry/vsys/entry/rulebase/security/rules` - Security rules

#### Ubiquiti UniFi ✅ **IMPLEMENTED WITH AUTO-DISCOVERY**
- **Method**: UniFi Network API (REST over HTTPS)
- **Authentication**: Session-based with username/password
- **Auto-Discovery**: ✅ Fully functional
  - Automatically detects: model, serial, firmware, hostname, IP addresses, MAC address
  - Supports: UDM, UDR, USG, UniFi Network Controllers
  - Dual-endpoint authentication (modern `/api/auth/login` and legacy `/api/login`)
  - Multi-endpoint discovery with fallback logic
- **Data Collected**: 
  - System information (model, serial, firmware)
  - Network configuration (hostname, IP addresses, MAC address)
  - Controller management interface TLS configuration
  - Site-specific device configurations
  - Gateway/UDM VPN configurations (if available)
  - Certificate information (if accessible)
- **Supported Types**: `unifi`, `ubiquiti`, `unifi_controller`, `udm_pro`
- **Endpoints**: 
  - `/api/auth/login` - Modern authentication (UDM/UDR)
  - `/api/login` - Legacy authentication (older controllers)
  - `/proxy/network/api/s/default/stat/sysinfo` - UDM/UDR system info
  - `/api/s/default/stat/sysinfo` - Controller system info
  - `/api/s/{site}/stat/device` - Device configurations
  - `/api/s/{site}/list/setting` - Settings and configurations
- **Multi-site Support**: Optional site ID for multi-site controllers
- **TLS Support**: Handles self-signed certificates automatically

### Servers & Generic Endpoints

#### Databases (PostgreSQL / MySQL) ✅ **IMPLEMENTED**
- **Method**: SQL connection (read-only)
- **Supported Types**: `postgresql`, `mysql`
- **Extracts**: in-transit TLS (mode, cipher, version, enforcement), at-rest encryption posture, password-hashing method, and a computed risk score

#### Generic SNMP ✅ **IMPLEMENTED**
- **Method**: SNMP v2c (UDP/161), hand-rolled (no CGO)
- **Supported Types**: `generic_snmp`
- **Extracts**: standard system OIDs (sysDescr, sysName, sysObjectID, …) for device identity — a fallback for appliances without a dedicated vendor integration

#### Generic HTTP / TLS ✅ **IMPLEMENTED**
- **Method**: REST certificate endpoint + direct TLS handshake
- **Supported Types**: `generic_http`
- **Extracts**: certificates from a configurable REST endpoint, plus a direct TLS handshake with supported-version enumeration

### Cloud Resources

> Full per-cloud detail (resource types, request parameters, IAM/RBAC) lives in the dedicated guides: [AWS](./aws-cloud-discovery.md) · [Azure](./azure-cloud-discovery.md) · [GCP](./gcp-cloud-discovery.md).

#### AWS ✅ **IMPLEMENTED**
- **TLS front ends**: ALB, NLB, Classic ELB, API Gateway, CloudFront — SSL policies, cipher suites, certificate chains (via TLS handshake) + ACM metadata
- **KMS**: customer-managed key inventory (spec, state, rotation, aliases)
- **At-rest**: S3 bucket and RDS instance encryption (algorithm, CMK)

#### Azure ✅ **IMPLEMENTED**
- **TLS front ends**: Application Gateway (full SSL policy + handshake), Load Balancer
- **Key Vault**: key inventory (spec, state, rotation, HSM)
- **At-rest**: Storage account and SQL Database (TDE) encryption (Microsoft-managed vs CMK)

#### GCP ✅ **IMPLEMENTED**
- **TLS front ends**: HTTPS Load Balancer (Target HTTPS Proxy), SSL Proxy — SSL policy, certificates, handshake
- **Cloud KMS**: key inventory (algorithm, state, rotation, protection level)
- **At-rest**: Cloud Storage and Cloud SQL encryption (Google-managed vs CMEK)

## Agent Deployment

### On-Premises Network Devices

For devices that cannot be reached from the cloud platform, deploy the device-agent binary:

1. **Download Agent**: Download the device-agent binary for your platform
2. **Register Agent**: `./device-agent -register`
3. **Configure**: Set `PLATFORM_URL` and `REGISTRATION_KEY`
4. **Start Agent**: `./device-agent`

The agent will:
- Poll the platform for jobs
- Receive AES-256-GCM encrypted credentials per-job
- Execute device interrogation with enriched data collection
- Perform TLS deep scan (version enumeration, full cert chain extraction, validation)
- Collect SSH metadata from management interfaces
- Extract device identity (vendor, model, firmware, serial) and auto-update platform
- Submit enriched results back to platform
- Never store credentials locally

### Cloud Resources

Cloud resources are interrogated directly by the platform service using cloud provider APIs. No agent deployment required.

## Security Considerations

### Credential Storage
- All credentials encrypted at rest in `platform_integrations` table
- Credentials decrypted only when needed for interrogation
- Agent receives credentials encrypted, decrypts in-memory only

### Network Security
- Agent uses outbound-only communication (no inbound ports required)
- All communication over HTTPS
- Credentials never logged or exposed in error messages

### Access Control
- Device management requires appropriate RBAC permissions
- Credential access audited
- Per-tenant device isolation

## Integration with Discovery

Device interrogation results integrate with the existing discovery system:
- Discovered assets appear in discovery job results
- Can be reviewed and approved like sensor discoveries
- Imported assets linked to parent device via `device_id` FK

## Implementation Status

### ✅ Completed (AWS, Fortinet, F5, Palo Alto, Cisco, UniFi)
- **Device CRUD operations** - Full device lifecycle management
- **Agent registration and job management** - Agent framework complete
- **AWS cloud resource discovery** - ALB, ELB, NLB, API Gateway, CloudFront with TLS handshake
- **AWS crypto configuration extraction** - SSL policies, full certificate chains, TLS versions, cipher suites
- **TLS handshake service** - Live certificate chain extraction from cloud endpoints with ACM metadata enrichment
- **Fortinet device interrogation** - SSL VPN, IPSec, certificates with detailed crypto extraction
- **F5 BigIP device interrogation** - Virtual servers, SSL profiles (client/server), certificate key chains
- **Palo Alto device interrogation** - SSL decrypt profiles, security rules with SSL settings
- **Cisco device interrogation** - Crypto maps, IPSec tunnels, ISAKMP/IKE/IKEv2 SAs, WebVPN/SSL, SSH host-key fingerprint
- **UniFi device interrogation** - Controller TLS configs, site device configurations, VPN settings
- **Database interrogation (PostgreSQL/MySQL)** - in-transit TLS, at-rest encryption, password hashing, risk score
- **Generic SNMP and HTTP/TLS probers** - SNMP v2c device identity; REST cert endpoint + direct TLS handshake
- **Discovery job integration** - Seamless integration with existing discovery workflow
- **Device-to-asset linking** - Assets linked to parent devices via `device_id`
- **Error handling** - Connection status tracking and error management
- **Device agent support** - All device types supported in downloadable agent binary

### ✅ Implemented Cloud Providers

All three clouds cover three resource families — TLS front ends, key-management inventory, and at-rest encryption (object storage + managed SQL):

- **AWS**: ALB, ELB, NLB, API Gateway, CloudFront; KMS keys; S3 and RDS encryption
- **Azure**: Application Gateway, Load Balancer; Key Vault keys; Storage accounts and SQL Database (TDE) encryption
- **GCP**: HTTPS Load Balancer, SSL Proxy; Cloud KMS keys; Cloud Storage and Cloud SQL encryption

Per-cloud resource types, request parameters, and IAM/RBAC are documented in the dedicated guides ([AWS](./aws-cloud-discovery.md) · [Azure](./azure-cloud-discovery.md) · [GCP](./gcp-cloud-discovery.md)).

## Related Documentation

- [Platform Integrations](../operate/configuration/platform-integrations.md)
- [Discovery Feature](./discovery.md)
- [Infrastructure Assets vs Crypto Configurations](./network-assets-vs-crypto-implementations.md)
