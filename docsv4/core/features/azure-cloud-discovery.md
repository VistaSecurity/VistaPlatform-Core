# Azure Cloud Resource Discovery

**Version:** 1.2  
**Last Updated:** 2026-06-24

Automated discovery and interrogation of Azure cloud resources for cryptographic configuration collection.

---

## Overview

Azure Cloud Resource Discovery enables automatic discovery and detailed interrogation of Azure resources that use TLS/HTTPS, providing comprehensive cryptographic configuration information directly from Azure APIs.

---

## Supported Resources

### ✅ Fully Implemented

#### Application Gateway

Azure Application Gateway with WAF and SSL/TLS termination.

- **Discovery**: Automatic enumeration of all Application Gateways across subscriptions
- **Interrogation**: Detailed crypto configuration extraction including:
  - SSL policy (protocols, cipher suites, minimum TLS version)
  - Policy type and name
  - Certificate configurations
  - HTTPS listener configurations
  - Frontend IP configurations
- **TLS Configuration**: Extracts complete SSL policy including:
  - Minimum protocol version (TLS 1.0, 1.1, 1.2)
  - Supported cipher suites
  - Policy type (Predefined, Custom, CustomV2)

#### Load Balancer

Azure Load Balancer (Standard and Basic SKUs).

- **Discovery**: Automatic enumeration of Load Balancers with public IPs
- **Interrogation**: Configuration extraction including:
  - Frontend IP configurations
  - Public IP associations
  - Provisioning state
  - Resource group and location metadata
- **Note**: Standard Azure Load Balancers operate at Layer 4 (TCP/UDP), so detailed TLS configuration is typically on backend services. The platform discovers LBs with public IPs and infers TLS capability on port 443.

#### Key Vault Keys (key management inventory)

- **Discovery**: Enumerates keys across every Key Vault in the subscription (`armkeyvault` management plane)
- **Interrogation**: Per key — key type/size/curve normalized to a canonical key spec (RSA-2048/3072/4096, ECC P-256/384/521, etc.), key state (enabled/disabled), protection level (software vs **HSM**), rotation-policy presence, and creation time
- Keys are written to the `kms_keys` inventory (provider `azure`) and surface as cryptographic-key assets
- **Note:** key *metadata* only — Key Vault does not expose key material, and the platform does not retrieve it

#### Storage Account Encryption (at-rest)

- **Discovery**: Enumerates Storage accounts (`armstorage`)
- **Interrogation**: at-rest encryption is always AES-256; surfaces Microsoft-managed vs **customer-managed (CMK, KeySource = Microsoft.Keyvault)** plus the key reference and infrastructure-encryption flag

#### SQL Database (TDE) Encryption (at-rest)

- **Discovery**: Enumerates SQL servers → user databases (`armsql`); the system `master` database is skipped
- **Interrogation**: Transparent Data Encryption (on by default, AES-256); reads each server's encryption protector to distinguish **service-managed TDE** from an **Azure Key Vault CMK** (BYOK), including the key URI

---

## What is enumerated

Alongside the cryptographic resources above, a run **inventories the
subscription's compute and network estate**: virtual machines, virtual networks,
their subnets, and NSG membership. This is inventory rather than cryptography —
a VM negotiates no protocol and states no at-rest encryption — and it is what
makes the rest of a run legible.

It is controlled by one switch per integration, **Inventory compute, networks and
subnets** in Discovery → Cloud → Edit integration. It is **on by default**,
including for integrations created before this feature existed.

### Exact API calls

| Call | Scope | Produces |
|---|---|---|
| `VirtualMachines.ListAll` | Subscription, paginated | One asset per VM |
| `VirtualNetworks.ListAll` | Subscription, paginated | One asset per VNet — **and its subnets, which ARM returns inline** |
| `NetworkSecurityGroups.ListAll` | Subscription, paginated | NSG **membership** — never the rules |
| `NetworkInterfaces.ListAll` | Subscription, paginated | MAC, private addresses, and the VM ↔ subnet link |

The NIC listing is not optional on Azure: a VM's own payload carries **no
addressing at all** — it names its NICs by resource id and nothing else — so
without it a VM is recorded with no address and no subnet.

Subnets cost no call of their own.

**Cost.** Four extra subscription-wide calls per run, each paginated. Azure
enumeration is not per-region, so the number does not grow with the number of
regions you use.

### Azure RBAC actions to add

```json
"Microsoft.Compute/virtualMachines/read",
"Microsoft.Network/virtualNetworks/read",
"Microsoft.Network/networkSecurityGroups/read",
"Microsoft.Network/networkInterfaces/read"
```

All four are covered by the built-in **Reader** role. `virtualNetworks/read` and
`networkSecurityGroups/read` may already be in your custom role.

### What lands in the inventory

| Azure resource | Asset class | Identified by |
|---|---|---|
| Virtual machine | Compute instance | its `/subscriptions/…/virtualMachines/<name>` resource id |
| Virtual network | Virtual network | its `/subscriptions/…/virtualNetworks/<name>` resource id |
| Subnet | Subnet | its `…/virtualNetworks/<vnet>/subnets/<name>` resource id |
| Network security group | *not an asset* | recorded as membership on the VM and the subnet |

Each VM carries its private addresses, its NICs (name, MAC, addresses), its VM
size, its image reference, its tags, its **`vmId`** (Azure's per-VM UUID, which
is what the guest reads back through IMDS — the join between a VM seen from
outside and the same machine reporting from inside), and the `cloud.*` placement
facts. The relationships **VNet contains subnet** and **subnet contains VM** are
drawn from the provider's own placement, and a subnet's address prefix becomes a
network segment.

A VM inherits membership of **both** its NIC's NSG and its subnet's NSG, because
both govern it.

New assets arrive in **Pending approval**. A re-run matches on the resource id
and updates.

### Two machines that share a private address

A private address is not unique in a subscription, and the inventory is built so that
it never has to be.

- **Two virtual networks using the same CIDR** are two separate network segments, tagged
  with the virtual network they belong to. Two VMs at the same private address in two
  different virtual networks are **two assets**, and neither is affected by the other.
- **An address reused inside one subnet** — the provider gives a freed address to
  the next VM created — is genuinely the same segment, and the platform cannot
  tell from outside whether an address that changed hands means a new machine or
  a rebuilt one. So it does not guess: the new VM is recorded as its own asset
  in Pending approval, and a **review item appears in Approvals** asking whether
  it is the machine that used to answer to that address. You decide; nothing is
  merged on your behalf.

  The previous asset is left exactly as it was, so its history, tags and
  findings stay with the machine they were recorded against.

### What is deliberately NOT collected

- **`osProfile`.** `adminPassword` and `customData` (Azure's user-data, base64
  of whatever bootstrap script you wrote) are never projected, and neither is
  the SSH public-key block.
- **NSG rules.** `properties.securityRules` is not read. Only the group's
  identity is recorded — membership, not policy.
- **A NIC's public IP.** Public exposure is a posture question answered by
  probing, and the reference points at a separate resource whose payload is not
  read.
- **Guest operating system.** Azure states an OS **family** on the OS disk
  ("Linux", "Windows"), which is not a product name, and an image reference says
  what the VM booted from rather than what it runs now. The OS fields stay empty
  rather than carrying a guess.
- **Power state.** `ListAll` returns the *provisioning* state; the running state
  needs a per-VM `InstanceView` call, which would be one call per VM.

## Workflow

### 1. Configure Azure Integration

Store Azure credentials in platform integrations:

**UI:** Navigate to Settings → Integrations → Add Integration

**Required Fields:**
- **Integration Type**: `azure`
- **Client ID**: Azure AD application (client) ID
- **Client Secret**: Azure AD application secret
- **Tenant ID**: Azure AD directory (tenant) ID
- **Subscription ID**: Azure subscription ID

Credentials are encrypted at rest using the platform's master encryption key.

### 2. Discover Azure Resources

Initiate cloud resource discovery:

**UI:** Navigate to Devices → Discover Cloud Resources

**API:** `POST /api/v1/device-interrogation-service/cloud/discover`

**Request Body:**
```json
{
  "integration_id": "uuid-of-azure-integration",
  "cloud_provider": "azure",
  "resource_types": ["application_gateway", "load_balancer", "key_vault", "storage_account", "sql_database"],
  "resource_groups": ["rg-production", "rg-networking"]
}
```

**Parameters:**
- `integration_id` (required): UUID of the Azure integration
- `cloud_provider` (required): Must be `"azure"`
- `resource_types` (required): Array of resource types to discover
  - `application_gateway` or `appgw`: Application Gateways
  - `load_balancer` or `lb`: Load Balancers
  - `key_vault` or `keyvault`: Key Vault keys (key-management inventory)
  - `storage_account` or `storage`: Storage account at-rest encryption
  - `sql_database` or `sql`: SQL Database TDE encryption
- `resource_groups` (optional): Filter by resource groups (discovers all if empty). **Note:** Key Vault / Storage / SQL discovery enumerates across the whole subscription; resource-group filtering applies to the network resources.

### 3. Automatic Processing

The service automatically:
1. Creates Azure SDK clients using decrypted credentials
2. Enumerates resources by type across the subscription
3. Filters by resource groups if specified
4. Extracts TLS/crypto configurations
5. Creates discovery findings with:
   - Device information (device_id, device_type, vendor)
   - Crypto configurations (SSL policies, certificates, TLS versions)
   - Metadata (Azure resource IDs, regions, SKU info)

### 4. Review and Import

Review discovery findings in the discovery job results:

**UI:** Navigate to Assets → Discovery Jobs → View Results

**Findings Include:**
- Hostname (DNS name or endpoint)
- Port (443 for HTTPS)
- Protocol (TLS/HTTPS)
- Protocol version (from SSL policy)
- Cipher suites (from SSL policy)
- Device ID (links asset to parent device)
- Azure metadata (resource ID, resource group, location)

### 5. Import to Inventory

Import findings as infrastructure assets:

**UI:** Select findings → Import Selected

**API:** `POST /api/v1/inventory-service/discovery/jobs/:id/import`

Imported assets are:
- Linked to parent device via `device_id`
- Created with `discovery_method = 'cloud_api'`
- Set to `pending_approval` status — unless their cloud segment (per
  subscription/region) has auto-approve enabled **with cloud discoveries among
  its sources**, which is off on every pre-existing segment. See
  [Asset Approval](asset-approval.md#which-discoveries-a-segment-auto-approves).

---

## Crypto Configuration Details

### Application Gateway SSL Policies

For each Application Gateway with HTTPS listeners, the service extracts:

| Field | Description |
|-------|-------------|
| **Policy Type** | Predefined, Custom, or CustomV2 |
| **Policy Name** | e.g., AppGwSslPolicy20220101 |
| **Min Protocol Version** | TLSv1_0, TLSv1_1, TLSv1_2 |
| **Cipher Suites** | List of supported cipher suites |

**Example SSL Policy Extraction:**
```json
{
  "protocol": "TLS",
  "protocol_version": "TLS 1.2",
  "policy_type": "Predefined",
  "policy_name": "AppGwSslPolicy20220101",
  "cipher_suites": [
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
  ],
  "port": 443,
  "handshake_verified": true,
  "certificates": [
    {
      "subject_dn": "CN=myapp.contoso.com",
      "issuer_dn": "CN=DigiCert SHA2 Extended Validation Server CA",
      "fingerprint_sha256": "abcdef...",
      "key_algorithm": "RSA",
      "key_size": 2048,
      "chain_order": 0
    }
  ]
}
```

### Certificate Discovery via TLS Handshake

For Application Gateways with public-facing endpoints, the service performs a **TLS handshake** to extract the full certificate chain. This provides the same level of certificate detail as sensor-based discoveries.

#### How It Works

1. After extracting SSL policy details from the Azure API, the service performs a TLS handshake against the Application Gateway's hostname
2. The handshake extracts the full certificate chain (leaf + intermediates) including:
   - Certificate PEM data and fingerprints (SHA-256, SHA-1)
   - Subject DN, Issuer DN, Serial Number
   - Subject Alternative Names (SANs)
   - Key algorithm, key size, and signature algorithm
   - Validity period and CA flag
3. The certificates flow through the standard `sensor_discoveries` → `discovery-processor-service` → `inventory-service` pipeline, creating proper `certificates` records linked to `crypto_implementations`

#### Fallback Behavior

- **Private endpoints**: If the Application Gateway is not publicly accessible, the TLS handshake will fail gracefully. The device and crypto configuration are still created with SSL policy metadata, but without a full certificate record.
- **Handshake timeout**: Default 10-second timeout prevents blocking on unreachable endpoints.
- The `handshake_verified` flag in discovery metadata indicates whether the certificate was obtained via TLS handshake (`true`) or API metadata only (`false`).

### Load Balancer Configuration

For Load Balancers with public IPs:

| Field | Description |
|-------|-------------|
| **Frontend IP** | Public IP configuration |
| **Provisioning State** | Succeeded, Failed, etc. |
| **Port** | Typically 443 for HTTPS |

**Note:** Azure Standard Load Balancers are Layer 4 devices. Detailed TLS configurations are typically on the backend pool members (VMs, VMSS, etc.) or associated Application Gateways.

---

## Example Discovery Result

```json
{
  "job_id": "uuid",
  "devices": [
    {
      "id": "device-uuid",
      "device_type": "azure_application_gateway",
      "vendor": "Microsoft",
      "hostname": "my-appgw.azure.com",
      "metadata": {
        "azure_resource_id": "/subscriptions/.../resourceGroups/rg-prod/providers/Microsoft.Network/applicationGateways/my-appgw",
        "resource_group": "rg-prod",
        "subscription_id": "subscription-uuid",
        "location": "eastus",
        "sku": {
          "name": "WAF_v2",
          "tier": "WAF_v2",
          "capacity": 2
        },
        "provisioning_state": "Succeeded",
        "crypto_configs": [
          {
            "protocol": "TLS",
            "protocol_version": "TLS 1.2",
            "policy_type": "Predefined",
            "policy_name": "AppGwSslPolicy20220101",
            "cipher_suites": [
              "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
            ],
            "port": 443,
            "handshake_verified": true,
            "certificates": [
              {
                "subject_dn": "CN=myapp.contoso.com",
                "issuer_dn": "CN=DigiCert SHA2 Extended Validation Server CA",
                "not_after": "2026-06-15T00:00:00Z",
                "fingerprint_sha256": "abcdef...",
                "key_algorithm": "RSA",
                "key_size": 2048,
                "chain_order": 0
              }
            ]
          }
        ]
      }
    }
  ],
  "count": 1
}
```

---

## Resource Group Filtering

Filter discovery to specific resource groups:

```json
{
  "integration_id": "uuid",
  "cloud_provider": "azure",
  "resource_types": ["application_gateway"],
  "resource_groups": ["rg-production", "rg-dmz"]
}
```

Resources are filtered case-insensitively to the specified resource groups.

---

## Error Handling

- **Authentication Errors**: Logged with status `connection_error` - verify credentials
- **Permission Errors**: Logged with details - verify RBAC permissions
- **API Errors**: Non-fatal, discovery continues for other resources
- **Retries and throttling**: the platform configures no retry or backoff policy of its own; it relies on the Azure SDK's default retry behaviour for throttled and transient responses. There is no platform-level pacing across a run.

---

## Security Considerations

### Credential Management

- Credentials encrypted at rest in `platform_integrations` table
- Decrypted only when needed for API calls
- Never logged, and masked in API responses

### Azure RBAC Permissions Required

Minimum Azure RBAC permissions for discovery:

```json
{
  "Name": "Crypto Platform Reader",
  "Actions": [
    "Microsoft.Network/applicationGateways/read",
    "Microsoft.Network/loadBalancers/read",
    "Microsoft.Network/publicIPAddresses/read",
    "Microsoft.Resources/subscriptions/resourceGroups/read",
    "Microsoft.KeyVault/vaults/read",
    "Microsoft.KeyVault/vaults/keys/read",
    "Microsoft.Storage/storageAccounts/read",
    "Microsoft.Sql/servers/read",
    "Microsoft.Sql/servers/databases/read",
    "Microsoft.Sql/servers/encryptionProtector/read"
  ],
  "NotActions": [],
  "DataActions": [],
  "NotDataActions": [],
  "AssignableScopes": [
    "/subscriptions/{subscription-id}"
  ]
}
```

**Built-in Role Alternative:** `Reader` role provides sufficient permissions but with broader access.

### Service Principal Setup

1. Create an Azure AD App Registration
2. Create a client secret
3. Assign the `Reader` role (or custom role above) at subscription level
4. Store credentials in platform integration

---

## Limitations

### Current Implementation

| Resource | Status | Notes |
|----------|--------|-------|
| Application Gateway | ✅ Implemented | Full SSL policy extraction + TLS handshake certificate chain |
| Load Balancer | ✅ Implemented | Public IP detection, L4 TLS inferred |
| Key Vault keys | ✅ Implemented | Key-management inventory (spec, state, rotation, HSM) → `kms_keys` |
| Storage accounts | ✅ Implemented | At-rest encryption posture (Microsoft-managed vs CMK) |
| SQL Database (TDE) | ✅ Implemented | Per-database TDE; service-managed vs Key Vault CMK |
| Front Door | 🚧 Planned | Structure ready |
| API Management | 🚧 Planned | Structure ready |

### Rate Limits

- Azure API rate limits apply
- Large-scale discoveries may take time
- Consider resource group batching for very large environments

### TLS Details

- Application Gateway provides complete SSL policy details and full certificate chains via TLS handshake
- Standard Load Balancers operate at L4 - TLS config is on backends
- For detailed backend TLS, use active probing or agent-based discovery
- Private Application Gateways that are not publicly reachable will have SSL policy metadata but no handshake-verified certificates

---

## Comparison: AWS vs Azure Discovery

| Feature | AWS | Azure |
|---------|-----|-------|
| Load Balancers | ALB, NLB, ELB | App Gateway, LB |
| SSL Policy Extraction | ✅ Full | ✅ Full (App Gateway) |
| TLS Handshake Certs | ✅ Full chain extraction | ✅ Full chain extraction (App Gateway) |
| Key management inventory | ✅ KMS | ✅ Key Vault keys |
| Object storage at-rest | ✅ S3 | ✅ Storage accounts |
| Managed SQL at-rest | ✅ RDS | ✅ SQL Database (TDE) |
| Multi-Region | Regions parameter | Single subscription |
| Filtering | Regions | Resource Groups |

---

## Related Documentation

- [AWS Cloud Discovery](./aws-cloud-discovery.md) - AWS resource discovery
- [Device Interrogation Feature](./device-interrogation.md) - Device and cloud interrogation overview
- [Platform Integrations](../operate/configuration/platform-integrations.md) - Integration configuration
- [Discovery Feature](./discovery.md) - General discovery workflows

---

**Last Updated:** 2026-06-24
