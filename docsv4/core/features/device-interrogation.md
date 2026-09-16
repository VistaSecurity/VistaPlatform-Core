# Device Interrogation Feature

Direct interrogation of network devices and cloud resources to collect cryptographic configurations.

## Overview

Device Interrogation complements the existing network traffic analysis sensor by enabling direct collection of cryptographic configurations from:
- **Network Devices**: F5 load balancers, Cisco routers/switches/ASA, Fortinet firewalls, Palo Alto firewalls, Ubiquiti UniFi
- **Servers & generic endpoints**: PostgreSQL/MySQL databases, generic SNMP devices, and generic HTTPS/TLS endpoints
- **Cloud Resources**: AWS, Azure, and GCP — TLS front ends (load balancers, API gateways, CDN), key-management inventory (KMS / Key Vault / Cloud KMS), and at-rest encryption (object storage, managed SQL)

This provides a more comprehensive view of cryptographic assets, especially for devices that may not generate network traffic or are in isolated networks.

### A device is an asset with management configured

Discovery → **Devices** is a view of your **inventory**, filtered to the assets
the platform knows how to log in to. There is no separate "device" record any
more: a firewall you add here is the same asset as the firewall your sensor sees
on the wire, and everything the platform learns about it — its endpoints, its
certificates, its findings, its history — accumulates on that one asset.

What that changes, in practice:

- **A device you add may already be in your inventory.** If the hostname,
  address or serial number you supply matches something already known, the
  management configuration attaches to that existing asset rather than creating a
  duplicate. The page will show you an asset that already has discovery history.
- **Each device has an asset class** — what it *is* (`firewall`,
  `load_balancer`, `switch`, `object storage`…) — alongside its **device type**,
  which names the vendor connector used to interrogate it. An F5 BIG-IP is a load
  balancer interrogated with the F5 connector. The class is what Inventory
  facets, the CMDB sync and the map all read.
- **A newly discovered asset waits in Approvals**, exactly like a sensor
  discovery. It appears on the Devices page immediately and you can interrogate
  it straight away; its cryptographic findings reach Inventory once the asset is
  approved (or automatically, if an auto-approval rule covers its segment).
- **"Stop managing" is not "delete".** The row action is **Stop managing this
  asset**, and that is exactly what it does: it removes the management
  configuration and the stored credentials, and takes the row off this page. The
  asset stays in Inventory with its endpoints, certificates, findings and
  history intact — the host did not stop existing because you stopped managing
  it, and you can manage it again at any time. Deleting an *asset* is an
  inventory action and lives on the asset's own page.

### What sits between interrogation and your inventory

An interrogation does not write to your inventory directly. Everything it
returns goes through the **identification engine** first, which asks one
question: is this thing already in the inventory?

It answers from the identifiers the run produced — a serial number, a management
address, a hardware address, a name — in a fixed order of trust, and scores how
confident the match is. What happens next depends on your **auto-accept
threshold** (**Settings → Policies → Identification rules**):

- **Above the threshold**, the match is accepted without you, and the audit
  trail records the score that let it through.
- **Below it**, the proposal waits in **Discovery → Approvals** as a merge
  proposal, next to the pending assets.
- **Two things are never auto-accepted at any score** — see
  [Asset Approval](./asset-approval.md).

This is why a device you add may quietly attach to an asset you already had, and
why a neighbour a device told us about can turn up as a *proposal* rather than as
a new asset.

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

### 1. Discover and add a device (recommended)

The quickest way to onboard a device: give the platform four things and it asks
the device for the rest.

**UI:** **Discovery → Devices → Discover & add**

**API:** `POST /api/v1/device-interrogation-service/devices/discover-and-create`

**What you supply:**
- Device type (manufacturer: UniFi, Cisco, F5, Fortinet, Palo Alto)
- Management URL (e.g., `https://10.0.0.1`)
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

The platform connects, authenticates, asks the device's own API what it is, and
creates the record with everything it learned. The credentials are encrypted at
rest.

### 2. Add a device manually (alternative)

For devices without auto-discovery support, add them with the details you
already have.

**UI:** **Discovery → Devices → Add device**

**API:** `POST /api/v1/device-interrogation-service/devices`

**What it takes:** a device type, a way to reach it (hostname, IP address or
management URL), the credentials, and optionally vendor, model, serial and
firmware. Anything you leave blank an interrogation can fill in later.

### 3. Credentials

**A network device carries its own credentials.** You enter the username and
password on the device itself, in the Add device / Discover & add form, and they
are encrypted at rest. There is no separate integration record to create and
link.

**Cloud providers are the exception.** A cloud integration holds the credential
for a whole account or subscription, and is created under **Discovery → Cloud →
Connect integration**:

- AWS: Access Key ID, Secret Access Key
- Azure: Service Principal (Client ID, Client Secret, Tenant ID)
- GCP: Service Account JSON key

### 4. Create an interrogation job

Create a job to interrogate a device or discover cloud resources.

**UI:** **Discovery → Devices →** the row's **Interrogate** button

**API:** `POST /api/v1/device-interrogation-service/devices/:id/interrogate`

**For Cloud Discovery:**
- `POST /api/v1/device-interrogation-service/cloud/discover`

### 5. Review results

Review discovered cryptographic configurations and assets.

**Results Include (Enriched v2):**
- Infrastructure assets (hostname, the endpoints found on them — address, port and service — and the class each asset was given)
- Cryptographic configurations (protocol, cipher suite, key exchange, hash algorithm)
- Supported cipher list and TLS version enumeration
- Full certificate chain with PEM, fingerprints, SANs, key usage
- Certificate validation status (valid, self_signed, expired, hostname_mismatch)
- SSH protocol details (banner, host key type, fingerprint)
- Device identity (vendor, model, firmware version, serial number)
- Service identification hints

### 6. Where it lands

There is no import step. Results reach the inventory through the pipeline
described above — the asset is either auto-approved by its segment's rule or
waiting in **Discovery → Approvals** — and carry a discovery method of
`device_interrogation` or `cloud_api` so you can tell where they came from.

## What is collected

Interrogation collects **operational facts and cryptographic posture**. It never
collects key material, and the rule is enforced in two independent places: each
collector copies only an explicit list of fields from the device's response, and
everything a collector emits is then scrubbed of anything whose name looks like
a secret.

**Never collected, from any device:** pre-shared keys, private keys, passwords,
API keys, community strings, RADIUS or mesh secrets, SNMP v3 user tables,
command transcripts, or whole configuration files. A device's DHCP option set,
its routing table and its bridge forwarding table are not collected either —
they are a map of your network, and nothing in the inventory reads them. A
firewall's policy objects (addresses, groups, rules), its user and
administrator accounts, and a load balancer's iRules and health-monitor
credentials are not collected for the same reason.

The one exception on routing is a **count**: on a FortiGate, where the device
can answer it as structured data, we record how many distinct next hops the
routing table forwards through. No prefix and no next-hop address is stored —
only the number, which is what tells a reader whether a box is an edge with one
default route or a core router with forty paths.

Per vendor, beyond the cryptographic posture described under Device Types:

| Vendor | Operational facts | Relationships |
|---|---|---|
| **Ubiquiti UniFi** | Per managed device: vendor, model, serial, firmware, uptime, interfaces (name, MAC, link and admin state, speed, VLAN). Per site: each LAN and VLAN with its name, prefix, gateway, and whether DHCP is served — never the DHCP range or its options. | Each adopted device to its controller, each device to the switch it uplinks through (with port names on both ends), and each LLDP neighbour. |
| **Palo Alto Networks** | Hostname, model, serial, PAN-OS version, uptime, management address and MAC, every interface (address, VLAN tag, MAC, link state, speed), and the ARP table. | Each LLDP neighbour, with the local and remote port names. |
| **Cisco** | Chassis model and serial from `show inventory` (the chassis only — a power supply or transceiver is a part, not an asset), IOS / IOS-XE / NX-OS / ASA version, uptime, every interface (address, MAC, administrative and operational state, bandwidth), the active VLANs, and the ARP table. On **NX-OS** the interface list is the device's layer-3 interfaces only: a Nexus formats the detailed interface command differently from IOS, so the summary form is what is read there, and it reports the interfaces that carry an address. | Each CDP and each LLDP neighbour, with the local and remote port names, and a proposed class for the neighbour taken from the platform it advertises. |
| **Fortinet FortiGate** | Model, serial, FortiOS version, every interface (address, MAC, administrative status, 802.1Q tag) joined to its live link state and negotiated speed, each tagged VLAN with its prefix and the firewall's own address on it, and the routing next-hop count described above. | None — a FortiGate reports no neighbour table this integration reads. |
| **F5 BIG-IP** | Chassis serial and platform from `sys/hardware`, TMOS version, every interface (MAC, administrative state, link state, negotiated speed), and each VLAN with its tag, prefix and self IP. | **Each virtual server to the members of the pool it forwards to**, with the pool name, the member port and the monitor's verdict. This is the dependency map a load balancer already holds and nothing else on the network states outright. A pool member is not classified from the pool: a pool states an address, a port and a monitor verdict, not whether the thing behind it is a server, another load balancer or a container ingress. |
| **Generic SNMP** | Vendor, model, serial and firmware from the chassis entry, uptime, every interface (name, MAC, admin and operational state, speed), the ARP cache, and that the device is managed over SNMP v2c — which carries its credentials in the clear, and is reported as a finding. | Each LLDP neighbour, with the local and remote port names. |

Interfaces, neighbours and VLANs are ordinary inventory data, not secrets. They
are what makes a device page answer "what is this, where is it plugged in, and
what is it talking to" without a second tool.

## Device Types

### Network Devices

#### F5 BigIP ✅ **IMPLEMENTED**
- **Method**: iControl REST API
- **Data Collected**: VIP configurations, SSL profiles (client/server), certificate bindings, plus device identity, the operational facts listed under [What is collected](#what-is-collected), and the virtual-server → pool-member dependency map
- **Multiple Assets**: One F5 device → multiple VIPs
- **Endpoints**: 
  - `/mgmt/tm/ltm/virtual` - Virtual servers
  - `/mgmt/tm/ltm/profile/client-ssl` - Client SSL profiles
  - `/mgmt/tm/ltm/profile/server-ssl` - Server SSL profiles
  - `/mgmt/tm/sys/hardware` - chassis serial and platform
  - `/mgmt/tm/net/interface`, `/mgmt/tm/net/vlan`, `/mgmt/tm/net/self` - interfaces, VLANs and self IPs
  - `/mgmt/tm/ltm/pool` (members expanded) - pool membership, for the dependency edges
- **Never read**: `/mgmt/tm/sys/crypto/key` and `/mgmt/tm/sys/file/ssl-key` (the private half of every certificate on the box — only the public half, `sys/crypto/cert`, is read), `/mgmt/tm/auth/user` and `/mgmt/tm/sys/db` (administrator accounts and the authentication configuration, including LDAP and RADIUS bind secrets), `/mgmt/tm/ltm/rule` (iRules — customer-written code, and a place people do put credentials), `/mgmt/tm/ltm/monitor/*` (health monitors carry the password a monitor authenticates to the backend with), and `/mgmt/tm/net/route`.

#### Cisco Routers/Switches/ASAs ✅ **IMPLEMENTED**
- **Method**: SSH + CLI commands
- **Data Collected**: Crypto maps, IPSec configurations, ISAKMP/IKE SAs, SSL proxy settings, plus device identity and the operational facts listed under [What is collected](#what-is-collected)
- **Commands**: `show version`, `show crypto map`, `show crypto ipsec sa`, `show crypto isakmp sa`, `show crypto ikev2 sa`, `show ssl`, `show webvpn`, `show running-config | include ssl cipher`, `show inventory`, `show ip interface brief`, `show interfaces`, `show vlan brief`, `show cdp neighbors detail`, `show lldp neighbors detail`, `show ip arp`. That is the whole list — it is a closed set, and adding to it is a deliberate edit the test suite makes visible.
- **Never run**: `show running-config` in any form broader than `| include ssl cipher` (the section form returns pre-shared keys, enable secrets, SNMP communities and tunnel-group passwords), `show startup-config`, `show ip route`, `show mac address-table`, `show snmp`, `show crypto key`. Every command output is read up to a size bound, and a reply cut short at that bound is reported as partial rather than presented as a complete table.
- **Platform differences**: on IOS, IOS-XE and ASA the interface list comes from the detailed interface command. **NX-OS formats that command differently**, so on a Nexus the interface summary is the source instead and the list is the device's layer-3 interfaces — those carrying an address — rather than every physical port.
- **Supported Types**: `cisco_router`, `cisco_switch`, `cisco_asa`, `cisco`

#### Fortinet FortiGate ✅ **IMPLEMENTED**
- **Method**: FortiGate REST API
- **Data Collected**: 
  - SSL VPN configurations with detailed crypto parameters
  - IPSec tunnel settings with encryption/authentication algorithms
  - Certificate store information
  - Cipher suites, key sizes, hash algorithms extracted from configs
  - TLS versions and protocol details
  - Device identity and the operational facts listed under [What is collected](#what-is-collected)
- **Endpoints**: 
  - `/api/v2/cmdb/vpn/ssl/settings` - SSL VPN configurations
  - `/api/v2/cmdb/vpn/ipsec/phase1-interface` - IPSec tunnel configurations
  - `/api/v2/cmdb/certificate/local` - Certificate store
  - `/api/v2/cmdb/system/status` - System information
  - `/api/v2/cmdb/system/interface` - configured interfaces, addresses and VLAN tags
  - `/api/v2/monitor/system/interface` - live link state and negotiated speed
  - `/api/v2/monitor/router/ipv4` - read to count distinct next hops; nothing from it is stored
- **Never read**: `firewall/address`, `firewall/addrgrp`, `firewall/policy`, anything under `user/`, `system/admin`, `system/api-user`, or the CA and remote certificate stores

#### Palo Alto Networks ✅ **IMPLEMENTED**
- **Method**: PanOS XML API
- **Data Collected**: SSL decrypt profiles, security rules with SSL settings, certificate configurations, plus device identity and the operational facts listed under [What is collected](#what-is-collected)
- **Endpoints**: 
  - `/api/?type=keygen` - API key authentication
  - `/api/?type=config&action=get&xpath=/config/devices/entry/network/profiles/ssl-decrypt` - SSL decrypt profiles
  - `/api/?type=config&action=get&xpath=/config/devices/entry/vsys/entry/rulebase/security/rules` - Security rules
  - `show system info` - hostname, model, serial, PAN-OS version, uptime, management address
  - `show interface all` - interfaces, addresses, VLAN tags, link state
  - `show arp all` - layer-3 neighbours
  - `show lldp neighbors all` - layer-2 neighbours

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
  - Per managed device: uptime, interfaces, LLDP neighbours and uplink (see [What is collected](#what-is-collected))
  - Per site: LAN and VLAN definitions with prefix, gateway and whether DHCP is served
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
- **Extracts**: the standard system OIDs (sysDescr, sysName, sysObjectID, sysUpTime) plus the standard MIBs every network device answers — ENTITY-MIB for the chassis model, serial and firmware; IF-MIB for interfaces; LLDP-MIB for neighbours; IP-MIB for the ARP cache. This is the fallback that inventories an appliance from any vendor without a dedicated integration.
- **Bounded**: each table walk stops at 500 rows and the whole collection at 30 seconds, so a device with a very large table cannot hold a job open.
- **Note**: SNMP v2c authenticates with a community string sent in the clear. A device managed this way is recorded as having a plaintext management plane, which raises a finding.

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

## When the platform cannot reach the device

Devices on a network the platform cannot reach are interrogated by a **discovery
agent** you deploy on a host that can. Register it from **Discovery → Sensors &
Agents → Register sensor or agent** (see
[Sensor & Agent Registration](./SENSOR_REGISTRATION.md)), and installation is
covered in the
[device agent deployment guide](../operate/deployment/device-agent-deployment.md).

Once running, the agent:

- polls the platform for work — it opens no inbound ports;
- receives the credentials for one job, encrypted for that agent and that job,
  and decrypts them in memory only;
- performs the interrogation, including a TLS deep scan (version enumeration,
  full certificate chain, validation) and SSH metadata from management
  interfaces;
- reports the device's identity back, so vendor, model, firmware and serial stay
  current;
- keeps no credentials on disk.

The same agent can also [inventory a host](./host-inventory.md) rather than
interrogate a device.

**Cloud resources need no agent.** They are reached directly over the provider's
API from the platform.

## Security Considerations

### Credential Storage
- Device credentials are encrypted at rest, and the stored value is tagged so a
  reader can never mistake ciphertext for plaintext
- Cloud integration credentials are encrypted at rest in the integrations store
- Credentials decrypted only when needed for interrogation
- Agent receives credentials sealed for that one agent and that one job, and
  decrypts in memory only

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
- Everything a run learns lands on the interrogated **asset**: its measured
  hardware identity (vendor, model, firmware, serial), the operational facts the
  connector read (interfaces, neighbours, VLANs, uptime), and the
  **relationships** it observed — an access point adopted by a controller, an
  uplink, an LLDP neighbour
- A neighbour the device tells us about becomes a pending asset of its own, and
  the relationship to it appears in Approvals alongside it. Approving the asset
  approves what was observed about it.
- Values a person typed in are not overwritten by a later scan: a measurement
  and a declared value are both kept, with the human's answer winning for the
  fields a person is the authority on

## Cloud coverage

All three clouds cover three resource families — TLS front ends, key-management inventory, and at-rest encryption (object storage + managed SQL):

- **AWS**: ALB, ELB, NLB, API Gateway, CloudFront; KMS keys; S3 and RDS encryption
- **Azure**: Application Gateway, Load Balancer; Key Vault keys; Storage accounts and SQL Database (TDE) encryption
- **GCP**: HTTPS Load Balancer, SSL Proxy; Cloud KMS keys; Cloud Storage and Cloud SQL encryption

Per-cloud resource types, request parameters, and IAM/RBAC are documented in the dedicated guides ([AWS](./aws-cloud-discovery.md) · [Azure](./azure-cloud-discovery.md) · [GCP](./gcp-cloud-discovery.md)).

## Related Documentation

- [Discovery Feature](./discovery.md)
- [Assets and Crypto Configurations](./assets-and-crypto-configurations.md)
- [Host Inventory](./host-inventory.md) — the same agent, describing a host instead of a device
- [Asset Approval](./asset-approval.md) — the queue, and the auto-accept threshold
