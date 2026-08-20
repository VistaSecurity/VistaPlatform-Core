# GCP Cloud Resource Discovery

**Version:** 1.1
**Last Updated:** 2026-06-24

Automated discovery and interrogation of Google Cloud Platform resources for cryptographic configuration collection.

---

## Overview

GCP Cloud Resource Discovery enables automatic discovery and detailed interrogation of GCP resources that terminate TLS/HTTPS, providing comprehensive cryptographic configuration information directly from the GCP Compute Engine API.

GCP uses a proxy-based load balancing architecture. TLS termination happens at **Target HTTPS Proxies** and **Target SSL Proxies**, which reference **SSL Policies** (cipher suite profiles) and **SSL Certificates**. **Forwarding Rules** map public IPs to these proxies.

---

## Supported Resources

### Target HTTPS Proxy (HTTPS Load Balancer)

External and internal HTTPS load balancers using Target HTTPS Proxies.

- **Discovery**: Automatic enumeration of all Target HTTPS Proxies in the project
- **Interrogation**: Detailed crypto configuration extraction including:
  - SSL policy (profile, minimum TLS version, cipher suites)
  - SSL certificate metadata (managed/self-managed, SANs, expiry)
  - Forwarding rule details (public IP, port range, load balancing scheme)
- **TLS Handshake**: Performs actual TLS handshake against public endpoints to verify negotiated parameters and extract certificate chains

### Target SSL Proxy (SSL Proxy Load Balancer)

SSL Proxy load balancers for non-HTTP TLS termination.

- **Discovery**: Automatic enumeration of all Target SSL Proxies in the project
- **Interrogation**: Same crypto configuration extraction as HTTPS proxies
- **TLS Handshake**: Same handshake verification as HTTPS proxies

### Cloud KMS (key management inventory)

- **Discovery**: Enumerates KMS locations → key rings → crypto keys across the project
- **Interrogation**: Per key — algorithm normalized to a canonical key spec (e.g. `GOOGLE_SYMMETRIC_ENCRYPTION`→AES-256, `RSA_DECRYPT_OAEP_4096_*`→RSA-4096, `EC_SIGN_P256_*`→ECC P-256), key state, purpose, protection level (SOFTWARE / HSM / EXTERNAL), and **rotation period**
- Keys are written to the `kms_keys` inventory (provider `gcp`) and surface as cryptographic-key assets
- **Note:** key *metadata* only — Cloud KMS does not expose key material, and the platform does not retrieve it

### Cloud Storage (at-rest encryption)

- **Discovery**: Enumerates buckets in the project
- **Interrogation**: at-rest encryption is always AES-256; surfaces Google-managed (default) vs **customer-managed (CMEK, `defaultKmsKeyName` set)** plus the key reference

### Cloud SQL (at-rest encryption)

- **Discovery**: Enumerates Cloud SQL instances in the project
- **Interrogation**: at-rest encryption (AES-256); surfaces Google-managed vs **customer-managed (CMEK, `diskEncryptionConfiguration.kmsKeyName`)**, with the database engine derived from `databaseVersion`

---

## Workflow

### 1. Configure GCP Integration

Store GCP credentials in platform integrations:

**UI (Tenant):** Navigate to Operations > Cloud > Add Integration > GCP tab

**UI (Admin):** Navigate to Integrations > GCP tab

**Required Fields:**
- **Integration Type**: `gcp`
- **Project ID**: GCP project ID (not project number)
- **Service Account JSON**: Complete JSON key file for a service account

Credentials are encrypted at rest using the platform's master encryption key.

### 2. Discover GCP Resources

Initiate cloud resource discovery:

**UI:** Click "Discover" on the GCP integration card, then select resource types

**API:** `POST /api/v1/device-interrogation-service/cloud/discover`

**Request Body:**
```json
{
  "integration_id": "uuid-of-gcp-integration",
  "resource_types": ["load_balancer", "ssl_proxy", "kms", "storage", "cloudsql"]
}
```

**Resource types:** `load_balancer` (Target HTTPS Proxies), `ssl_proxy` (Target SSL Proxies), `kms` / `cloudkms` (Cloud KMS keys), `storage` / `gcs` (Cloud Storage at-rest encryption), `cloudsql` / `sql` (Cloud SQL at-rest encryption).

**Note:** GCP load balancer resources are global (not regional), so no region parameter is needed for discovery. The integration's region field is informational metadata only. KMS is enumerated across all KMS locations in the project.

### 3. Automatic Processing

The service automatically:
1. Creates a discovery job
2. Authenticates using the service account credentials (JWT-based OAuth2)
3. Enumerates Target HTTPS Proxies and/or Target SSL Proxies
4. For each proxy, fetches the associated SSL Policy and SSL Certificates
5. Resolves the Forwarding Rule to determine the public IP
6. Performs a TLS handshake against reachable endpoints
7. Creates or updates device records with crypto configuration metadata
8. Writes discoveries to the `sensor_discoveries` table (unified pipeline)

### 4. Automatic Asset Creation

Cloud discoveries are automatically processed by the `discovery-processor-service`:

1. **Unified Pipeline**: GCP discoveries flow through the same `sensor_discoveries` pipeline as AWS, Azure, and sensor discoveries
2. **Auto-Processing**: The `discovery-processor-service` automatically processes discoveries within seconds
3. **Network Classification**: Discoveries are classified by the cloud segment for their project/region — a cloud resource's ownership comes from the account it lives in, not from an IP address it may not have
4. **Auto-Approval**: The segment's auto-approval rule is evaluated. It applies only if that segment has auto-approve enabled **and** lists cloud discoveries among its sources — off on every pre-existing segment; see [Asset Approval](asset-approval.md#which-discoveries-a-segment-auto-approves)
5. **Asset Creation**: Assets are created with `monitoring` (if auto-approved) or `pending_approval` status

### 5. Review and Approve Assets

Review cloud-discovered assets in the Discovery Approvals modal:

**UI:** Navigate to Assets > Discovery Approvals

**GCP-discovered assets appear alongside other discoveries** with:
- Hostname or public IP address
- Port (typically 443)
- Protocol (TLS/HTTPS)
- Protocol version (from SSL policy or TLS handshake)
- Cipher suite (from SSL policy or TLS handshake)
- Certificate information (SANs, expiry, managed status)
- Device ID (links asset to parent GCP device)
- Discovery source indicator (shows as cloud discovery)

---

## Crypto Configuration Details

### SSL Policies

For each proxy, the service extracts SSL policy configuration:

- **Policy Name**: e.g., `my-ssl-policy`
- **Profile**: `COMPATIBLE`, `MODERN`, `RESTRICTED`, or `CUSTOM`
- **Minimum TLS Version**: `TLS 1.0`, `TLS 1.1`, or `TLS 1.2`
- **Enabled Cipher Suites**: Complete list of effective cipher suites
- **Custom Features**: For CUSTOM profiles, the explicitly configured cipher suites

#### GCP SSL Policy Profiles

| Profile | Min TLS | Description |
|---------|---------|-------------|
| COMPATIBLE | TLS 1.0 | Broadest compatibility, includes legacy ciphers |
| MODERN | TLS 1.0 | Modern ciphers only, wider client support |
| RESTRICTED | TLS 1.2 | Strict security, limited cipher set |
| CUSTOM | Configurable | User-selected cipher suites |

**Default behavior**: Proxies without an explicit SSL policy use GCP's default settings (equivalent to COMPATIBLE profile with TLS 1.0 minimum).

### SSL Certificates

The service discovers certificate metadata:

- **Certificate Name**: GCP resource name
- **Type**: `SELF_MANAGED` or `MANAGED` (Google-managed)
- **Subject Alternative Names**: Domain names covered
- **Expiry Time**: Certificate expiration date
- **Managed Status**: For managed certificates — provisioning status and per-domain status

### TLS Handshake Verification

For proxies with a reachable public IP (via Forwarding Rules), the service performs a live TLS handshake to extract:

- Negotiated TLS version and cipher suite
- Full certificate chain (leaf + intermediates)
- Certificate fingerprints (SHA-256, SHA-1)
- Key algorithm and size
- Subject Alternative Names

#### Fallback Behavior

- **Internal load balancers**: If the forwarding rule uses `INTERNAL` scheme, the TLS handshake may fail. The device and crypto configuration are still created from API metadata.
- **No forwarding rule**: Proxies without associated forwarding rules are still discovered with SSL policy details.
- **Handshake timeout**: Default 10-second timeout prevents blocking on unreachable endpoints.
- The `handshake_verified` flag indicates whether crypto config was obtained via TLS handshake (`true`) or API metadata only (`false`).

---

## Example Discovery Result

```json
{
  "job_id": "uuid",
  "devices": [
    {
      "id": "device-uuid",
      "device_type": "gcp_https_load_balancer",
      "vendor": "Google Cloud",
      "hostname": "34.120.10.50",
      "ip_address": "34.120.10.50",
      "metadata": {
        "gcp_resource_id": "https://compute.googleapis.com/compute/v1/projects/my-project/global/targetHttpsProxies/my-lb",
        "proxy_type": "target_https_proxy",
        "project_id": "my-project",
        "ssl_policy_name": "modern-ssl-policy",
        "ssl_policy_profile": "MODERN",
        "forwarding_rule": "my-forwarding-rule",
        "load_balancing_scheme": "EXTERNAL",
        "port_range": "443-443",
        "crypto_configs": [
          {
            "protocol": "HTTPS",
            "protocol_version": "TLS 1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "cipher_suites": ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"],
            "port": 443,
            "handshake_verified": true,
            "certificates": [
              {
                "subject_dn": "CN=example.com",
                "issuer_dn": "CN=GTS CA 1P5,O=Google Trust Services LLC,C=US",
                "not_before": "2026-01-15T00:00:00Z",
                "not_after": "2026-04-15T00:00:00Z",
                "fingerprint_sha256": "abcdef1234...",
                "key_algorithm": "ECDSA",
                "key_size": 256,
                "chain_order": 0
              }
            ],
            "metadata": {
              "ssl_policy": "modern-ssl-policy",
              "ssl_policy_profile": "MODERN"
            }
          }
        ],
        "certificates": [
          {
            "name": "my-managed-cert",
            "type": "MANAGED",
            "managed": true,
            "managed_status": "ACTIVE",
            "managed_domains": ["example.com", "www.example.com"],
            "subject_alternative_names": ["example.com", "www.example.com"],
            "expire_time": "2026-04-15T00:00:00Z"
          }
        ]
      }
    }
  ],
  "count": 1
}
```

---

## Error Handling

- **API Errors**: Logged but non-fatal — discovery continues for other resources
- **Permission Errors**: Reported in job status with guidance on required roles
- **Token Errors**: Service account key validation errors are surfaced in connection test results
- **Compute API Disabled**: Detected during validation with a clear error message

---

## Security Considerations

### Credential Management
- Service account key encrypted at rest in `platform_integrations` table
- Decrypted only when needed for API calls
- JWT-based OAuth2 token exchange — tokens are short-lived (1 hour) and cached
- Credentials never logged or exposed in responses

### IAM Permissions Required

Minimum IAM roles for GCP discovery, by resource family:

| Resource family | Role |
|---|---|
| Load balancers / SSL proxies | `roles/compute.viewer` |
| Cloud KMS keys | `roles/cloudkms.viewer` |
| Cloud Storage buckets | `roles/storage.admin` (read is sufficient: `storage.buckets.list/get`) |
| Cloud SQL instances | `roles/cloudsql.viewer` |

The compute portion maps to these granular permissions:

```
compute.targetHttpsProxies.list
compute.targetSslProxies.list
compute.sslPolicies.get
compute.sslPolicies.list
compute.sslCertificates.list
compute.sslCertificates.get
compute.globalForwardingRules.list
cloudkms.keyRings.list
cloudkms.cryptoKeys.list
storage.buckets.list
storage.buckets.get
cloudsql.instances.list
```

The integration requests the read-only superset scope `https://www.googleapis.com/auth/cloud-platform.read-only`, so the service account's granted roles (above) are what actually bound access — not the OAuth scope.

### Service Account Setup

1. Create a service account in the GCP Console (IAM & Admin > Service Accounts)
2. Grant `roles/compute.viewer` (plus `roles/cloudkms.viewer`, `roles/cloudsql.viewer`, and storage read for the at-rest families you want) on the project
3. Create and download a JSON key
4. Paste the key contents into the integration form

---

## Limitations

### Current Implementation
- Discovery is project-scoped (one project per integration)
- Load balancing: global resources only (Target HTTPS/SSL Proxies, Global Forwarding Rules); regional forwarding rules and regional SSL resources are not yet discovered
- ✅ Cloud KMS key inventory, Cloud Storage at-rest encryption, and Cloud SQL at-rest encryption are implemented
- 🚧 Not yet covered: GCP Certificate Manager, Secret Manager, persistent-disk encryption
- Google-managed certificates show metadata but not PEM content (by design — GCP does not expose private keys or PEM data for managed certs)

### API Quotas
- GCP Compute Engine API quotas apply
- Default quota: 1,500 requests per 100 seconds
- Large projects with many proxies may require quota increases

---

## Related Documentation

- [AWS Cloud Discovery](./aws-cloud-discovery.md)
- [Azure Cloud Discovery](./azure-cloud-discovery.md)
- [Platform Integrations](../operate/configuration/platform-integrations.md)
- [Discovery Feature](./discovery.md)
