# AWS Cloud Resource Discovery

Automated discovery and interrogation of AWS cloud resources for cryptographic configuration collection.

## Overview

AWS Cloud Resource Discovery reads your AWS account through the AWS management APIs with read-only credentials and lands the results in the same inventory as sensor-discovered assets. It covers two families of resource:

- **TLS-terminating front ends** — load balancers, API Gateway custom domains, CloudFront distributions. For these the platform reads the configured TLS policy *and* performs a live TLS handshake against publicly reachable endpoints to capture the served certificate chain.
- **At-rest cryptographic posture** — KMS keys, S3 bucket default encryption, RDS storage encryption. These are configuration records, not reachable TLS endpoints.

Nothing is deployed inside your VPC. No traffic is mirrored. The platform only reads what the AWS control plane already exposes.

## Supported Resources

Each type is either **regional** (scanned once per region you select) or **global** (listed account-wide, region selection does not apply). The Discovery → Cloud run dialog marks the global ones with a `GLOBAL` badge and disables the region picker when your selection contains only global types.

| Resource type | Scope | What is collected |
|---|---|---|
| Application Load Balancer (ALB) | Regional | SSL policy (permitted protocol versions and cipher suites), certificate bindings, listener configuration. One record per TLS listener. |
| Network Load Balancer (NLB) | Regional | TLS listener configuration and certificates. |
| Classic Load Balancer (ELB) | Regional | Basic SSL/TLS configuration only — see Limitations. |
| API Gateway (v2) | Regional | Per mapped custom domain: the domain's minimum TLS security policy, endpoint type, domain status and bound ACM certificate. |
| CloudFront | **Global** | Viewer-side minimum protocol version, SSL support method, certificate source and bound ACM certificate; **plus one record per custom origin**, including the origin protocol policy and the TLS versions permitted toward that origin. |
| KMS keys | Regional | Customer-managed keys only (AWS-managed keys are skipped): key spec / algorithm, state, usage, origin, rotation enabled and period, multi-Region flag, aliases. Metadata only — KMS never exposes key material. |
| S3 bucket encryption | **Global** | Default server-side encryption per bucket (SSE-S3, SSE-KMS, DSSE-KMS), the KMS key when customer-managed, whether S3 Bucket Keys are enabled, and the bucket's home region. |
| RDS instance encryption | Regional | Storage-encrypted flag, algorithm, KMS key, engine and version, Multi-AZ, Performance Insights KMS key. |

### Partitions

Only the **AWS commercial partition** (`aws`) is supported. **GovCloud (`aws-us-gov`) and China (`aws-cn`) are not** — they are separate partitions with separate credentials, separate account namespaces and separate service endpoints, and they are not selectable in the region picker.

The region list in the run dialog is a fixed list of commercial-partition regions. The platform does not enumerate the regions enabled on your account (that would require an additional IAM grant before the dialog could render).

## Workflow

### 1. Add the AWS integration

**UI:** Discovery → Cloud → **Add integration**, choose provider **AWS**.

AWS authenticates one of two ways, selected by the **Authentication** dropdown. The fields change with the choice; only the fields on screen are submitted.

#### Access key (default)

| Field | Required | Notes |
|---|---|---|
| Access key ID | Yes | |
| Secret access key | Yes | |
| Session token | No | Only for temporary STS credentials. Leave blank for a long-lived IAM user key. |

#### Assume role (STS)

| Field | Required | Notes |
|---|---|---|
| Role ARN | Yes | The role in *your* account that the platform will assume. |
| External ID | No | The shared secret named in your role's trust policy. Recommended — see below. |
| Role session name | No | Appears in your CloudTrail records. Defaults to `vistaplatform-discovery`. |
| Access key ID / Secret access key | No | Optional. If supplied, the `sts:AssumeRole` call is signed with these. If both are blank, it is signed with the platform's own ambient AWS identity (environment credentials, IRSA, or the instance profile of the host running the platform). |

Also set **Region** (the default region used when a run selects none) and optionally **Account ID**.

Sensitive values — access key ID, secret access key, session token and external ID — are encrypted at rest and masked in API responses. On edit, leaving a masked field blank keeps the stored value. The role ARN and role session name are not secrets and are displayed.

#### Test the connection

Discovery → Cloud → the plug icon on the integration runs **`sts:GetCallerIdentity`** through exactly the same credential-assembly path discovery uses, so a green test proves discovery will authenticate the same way — including through the assume-role chain. **Your policy must therefore allow `sts:GetCallerIdentity`**; it is included in the policy below.

### 2. Cross-account setup for assume-role

Assume-role is the right choice when you do not want to hand out a long-lived IAM user key, or when you want the read to appear in CloudTrail as an identifiable session.

You create the role **in your own AWS account**. The platform is self-hosted, so there is no vendor-owned AWS account to trust: the principal you trust is whatever identity the platform itself calls AWS as — the IAM user whose access key you configured on the integration, or the role/instance profile of the host or pod running the platform.

**Trust policy on the role you create** (substitute the principal for your deployment):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<platform-account-id>:user/<platform-iam-user>"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "<the-external-id-you-set-on-the-integration>"
        }
      }
    }
  ]
}
```

Attach the permissions policy from **IAM permissions required** below to the same role.

If you do not set an external ID, omit the whole `Condition` block. Do **not** leave the condition in place with an empty value — the platform omits the external ID from the AssumeRole call entirely when the field is blank, and AWS rejects a call that omits an external ID the trust policy requires.

#### Why the external ID exists

The external ID solves the *confused deputy* problem. Your role's trust policy names a principal; anyone who can persuade that principal to call `sts:AssumeRole` on your role can read your account. If the same platform is used by several organizations, and one of them learns your role ARN, nothing but the external ID stops them from entering your ARN into their own integration and having the shared principal assume it on their behalf.

The external ID is a value only you and the platform operator know. AWS requires it to be presented on the AssumeRole call and matched against the trust policy, so knowing the role ARN alone is not enough. AWS recommends one whenever a third party assumes a role in your account. It is not a password for a human — it just has to be unpredictable and not reused across customers.

### 3. Run discovery

**UI:** Discovery → Cloud → the ▶ (play) icon on the integration.

Choose the resource types, and — if any regional type is selected — the regions. If your selection is only global types (S3, CloudFront), the region picker is disabled and no `regions` value is sent, because none would be applied.

**API:** `POST /api/v1/device-interrogation-service/cloud/discover`

```json
{
  "integration_id": "uuid-of-aws-integration",
  "resource_types": ["alb", "elb", "nlb", "api_gateway", "cloudfront", "kms", "s3", "rds"],
  "regions": ["us-east-1", "us-west-2"]
}
```

`regions` is optional and applies only to the regional types. When omitted, the integration's default region is used.

### 4. Automatic processing

The service creates a discovery job, enumerates and interrogates the resources, and writes discoveries to the `sensor_discoveries` table — the same pipeline sensor discoveries use. Each discovery carries its `cloud_provider` and `cloud_region`, so cloud resources are grouped into per-region cloud network segments.

### 5. Review and approve

**UI:** Discovery → Approvals.

Cloud-discovered assets appear alongside sensor-discovered ones with hostname, port, protocol, protocol version, cipher suite and certificate detail. They carry `discovery_method = 'cloud_api'` and arrive as `pending_approval` — unless the cloud segment they belong to (the per-region segment created from their `cloud_provider`/`cloud_region`) has auto-approve enabled **with cloud discoveries among its sources**, in which case they go straight to `monitoring`. Cloud coverage is off on every pre-existing segment and is enabled per segment in Settings → Infrastructure; see [Asset Approval](asset-approval.md#which-discoveries-a-segment-auto-approves).

Approved resources appear as Infrastructure Assets with their Crypto Configurations. Cloud device types render with readable names ("AWS S3 bucket", "AWS KMS key") on Discovery → Devices and in the job drawer, and map to CMDB asset types: load balancers to **appliance**, managed services (API Gateway, CloudFront, KMS, S3) to **service**, and RDS instances to **server**.

## Crypto Configuration Details

### Reported TLS version is the *minimum permitted*, not the negotiated one

For every AWS-configured TLS surface, the `protocol_version` the platform records is the **weakest version the endpoint still accepts**, and the full permitted set is recorded alongside it.

This is deliberate. A listener on `ELBSecurityPolicy-TLS-1-0-2015-04` negotiates TLS 1.2 with a modern client and still accepts TLS 1.0 from anyone who asks for it. Recording the negotiated version would hide exactly the finding this feature exists to produce.

- **Load balancers** — the permitted protocol set comes from the SSL policy's own protocol list.
- **API Gateway** — the domain's `SecurityPolicy` (`TLS_1_0` / `TLS_1_2`) is a floor; the permitted set is everything at or above it.
- **CloudFront viewer** — `MinimumProtocolVersion` is likewise a floor.
- **CloudFront origins** — the explicitly configured origin SSL protocols. An origin with an HTTP-only protocol policy is reported as **HTTP on its HTTP port**, with no TLS version, because that is what CloudFront actually uses to reach it.

Where a live TLS handshake also succeeds, the version our client negotiated is preserved separately as `negotiated_protocol_version`; it does not overwrite the permitted minimum. The negotiated **cipher suite** does come from the handshake, since that is a real measurement of the endpoint.

Anything AWS reports that the platform cannot map to a known protocol version is surfaced verbatim rather than guessed at or dropped.

### Certificate Discovery

Cloud discovery performs **TLS handshake verification** against publicly accessible endpoints to extract full certificate chains, giving the same level of certificate detail as sensor-based discovery.

1. After interrogating a resource via the AWS API, the service performs a TLS handshake against the resource's DNS name.
2. The handshake extracts the full chain (leaf + intermediates): PEM, SHA-256/SHA-1 fingerprints, subject/issuer DN, serial, SANs, key algorithm, key size, signature algorithm, validity period, key usage and extended key usage, CA flag, chain order.
3. Handshake certificates are enriched with ACM metadata by matching domain names against the ACM certificates bound to the resource.
4. Certificates flow through `sensor_discoveries` → discovery-processor-service → inventory-service, creating `certificates` records and Crypto Configurations with certificate linkages.

#### Fallback behaviour

- **Private endpoints** — an internal ALB whose DNS name is not publicly resolvable will fail the handshake gracefully. The device and its Crypto Configuration are still created from the API data (including the permitted TLS versions and ACM metadata), but without a full certificate record.
- **Handshake timeout** — 10 seconds, so unreachable endpoints do not block a run.
- `handshake_verified` in the discovery metadata records whether the certificate came from a real handshake (`true`) or from API metadata only (`false`).

#### ACM metadata enrichment

Where a certificate matches an ACM certificate bound to the resource, the platform records the ACM ARN, status, certificate type (`AMAZON_ISSUED`, `IMPORTED`, …), renewal eligibility, in-use-by resources and domain validation options.

#### Certificate data sources

- `cloud_api` — discovered via cloud TLS handshake + API enrichment
- `discovery` — sensor-based discovery
- `manual` — manually uploaded

### S3 encryption: "could not determine" is a distinct answer

When the bucket encryption configuration cannot be read — `AccessDenied`, throttling, any API failure — the bucket is recorded as **undetermined**, not as encrypted. An unreadable bucket is not a compliant bucket.

The one case that does license a conclusion is S3's specific "this bucket has no bucket-level encryption configuration" response: since January 2023 such a bucket receives SSE-S3 by default, and it is recorded as `sse-s3-default`, flagged as an AWS default rather than as an explicit configuration you chose.

Each bucket's home region is resolved individually rather than assumed to be the integration's default region.

## Example Discovery Result

```json
{
  "job_id": "uuid",
  "devices": [
    {
      "id": "device-uuid",
      "device_type": "aws_alb",
      "vendor": "AWS",
      "hostname": "my-alb-123456789.us-east-1.elb.amazonaws.com",
      "metadata": {
        "arn": "arn:aws:elasticloadbalancing:us-east-1:123456789:loadbalancer/app/my-alb/123456789",
        "region": "us-east-1",
        "crypto_configs": [
          {
            "protocol": "HTTPS",
            "protocol_version": "TLS 1.0",
            "negotiated_protocol_version": "TLS 1.3",
            "tls_versions": ["TLS 1.0", "TLS 1.1", "TLS 1.2"],
            "cipher_suite": "TLS_AES_128_GCM_SHA256",
            "port": 443,
            "handshake_verified": true,
            "certificates": [
              {
                "subject_dn": "CN=example.com",
                "issuer_dn": "CN=Amazon RSA 2048 M01,O=Amazon,C=US",
                "serial_number": "0123456789abcdef",
                "not_before": "2026-04-15T00:00:00Z",
                "not_after": "2027-04-15T00:00:00Z",
                "fingerprint_sha256": "abcdef1234...",
                "key_algorithm": "RSA",
                "key_size": 2048,
                "chain_order": 0,
                "acm_metadata": {
                  "arn": "arn:aws:acm:us-east-1:123456789:certificate/abc123",
                  "renewal_eligibility": "ELIGIBLE",
                  "status": "ISSUED"
                }
              }
            ],
            "metadata": {
              "ssl_policy": "ELBSecurityPolicy-TLS-1-0-2015-04",
              "certificates": [
                { "arn": "arn:aws:acm:us-east-1:123456789:certificate/abc123" }
              ]
            }
          }
        ]
      }
    }
  ],
  "count": 1
}
```

The example shows the point of the minimum-version rule: the listener negotiated TLS 1.3 with the platform's client, and is nonetheless reported as TLS 1.0 because that is what it still accepts.

## Multi-Region Discovery

```json
{
  "integration_id": "uuid",
  "resource_types": ["alb"],
  "regions": ["us-east-1", "us-west-2", "eu-west-1"]
}
```

**Regions are scanned sequentially, one after another, as are resource types.** A run over many regions takes proportionally longer; every region you add costs another full pass. There is no parallel fan-out across regions today. For very large estates, prefer several smaller runs over one run covering every region.

S3 and CloudFront are listed account-wide and are enumerated once regardless of how many regions are selected.

## Error Handling

- **API errors** — logged and non-fatal; discovery continues with the other resources.
- **Permission errors** — reported in the job status and the device connection status for the TLS front-end types. For **KMS, S3 and RDS** they are not: see Limitations.
- **Retries and throttling** — the platform does not configure its own retry or backoff policy. It uses the AWS SDK for Go v2 **standard retryer defaults**: up to 3 attempts per request, exponential backoff with jitter capped at 20 seconds, applied to throttling responses (`Throttling`, `TooManyRequestsException`, `SlowDown`, …), request timeouts and HTTP 500/502/503/504, governed by a retry-token quota that stops a storm of retries. Requests that exhaust their attempts surface as ordinary API errors. There is no platform-level pacing across a run.

## Security Considerations

### Credential management

- Credentials are encrypted at rest in the `platform_integrations` table using the platform's master encryption key.
- They are decrypted only when an API call needs them.
- They are never logged, and are masked in API responses.
- Only the credential fields are treated as secret; the role ARN and role session name are stored and displayed in the clear.

### IAM permissions required

Attach this policy to the IAM user whose access key you configure, or to the role you let the platform assume. It is sufficient for **every** resource type; drop the statements for types you do not intend to discover.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",

        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeSSLPolicies",

        "apigateway:GET",

        "cloudfront:ListDistributions",
        "cloudfront:GetDistributionConfig",

        "acm:DescribeCertificate",

        "kms:ListKeys",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "kms:ListAliases",

        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetEncryptionConfiguration",

        "rds:DescribeDBInstances"
      ],
      "Resource": "*"
    }
  ]
}
```

Notes on the individual grants:

- **`sts:GetCallerIdentity`** — called by the **Test connection** button. Without it the connection test fails on first use even though discovery itself would work.
- **`apigateway:GET`** — API Gateway v2 has no `apigatewayv2:` IAM namespace; its read operations authorize under the `apigateway` service prefix with HTTP-verb actions. Scope it down with a resource ARN (`arn:aws:apigateway:<region>::/domainnames*`, `.../apis*`) if you prefer.
- **`cloudfront:GetDistributionConfig`** — required for real CloudFront interrogation. `GetDistributionConfig` is used deliberately in preference to `GetDistribution`: it is the narrower response and does not return trusted-signer material.
- **`acm:DescribeCertificate`** — required for ACM enrichment of discovered certificates.
- **`s3:GetBucketLocation`** — required to place each bucket in its true region. This is **one extra API call per bucket per run**; on an account with thousands of buckets that is thousands of additional calls. If the call is denied, the bucket falls back to the integration's default region.
- **`s3:GetEncryptionConfiguration`** — the IAM action name for the `GetBucketEncryption` operation.

All of these are read-only. Nothing in the policy can modify a load balancer, create or export a certificate, read object or database contents, or retrieve key material.

## Limitations

Read this section before drawing conclusions from a run.

### KMS results are not yet browsable as a key inventory

**You can run KMS discovery, but you cannot yet browse the results as a key inventory in the tenant UI.** Discovered KMS keys are written to a separate `kms_keys` table that no page in the tenant UI reads. The keys do appear as devices on Discovery → Devices and as `service`-type Infrastructure Assets, but Inventory → Keys is a different inventory and does not show them; there is no view today that lists key spec, rotation status or rotation age for your KMS estate. Do not plan a KMS rotation review around this feature yet.

### "No results" can mean "no permission"

KMS, S3 and RDS discovery failures — including a missing IAM grant — are logged as warnings and the job **still reports success with zero results for that type**. If a type comes back empty, verify your IAM policy before concluding you have no resources of that type. The load-balancer, API Gateway and CloudFront paths do fail the job on a permission error, so this asymmetry applies only to the three at-rest types.

### S3 and RDS records are not reachable endpoints

S3 buckets and RDS instances are inventoried with a **placeholder network endpoint** (port 443, an unresolved address). They are at-rest posture records, not TLS endpoints, and nothing handshakes with them. Treat the endpoint fields on those records as meaningless.

### Scheduled runs collect less than interactive runs

A **scheduled** cloud discovery produces materially less than a run started from Discovery → Cloud. The scheduled path does not carry certificates, certificate quality flags, OCSP status, or the region/segment enrichment, because it takes a different route into the inventory. Use an interactive run when you need full certificate detail.

### Other gaps

- **Classic ELB detailed interrogation is basic only** — enumeration and basic SSL/TLS configuration, without the listener-level SSL policy detail available for ALB and NLB.
- **Not covered:** AWS Secrets Manager, EBS volume encryption, DynamoDB.
- **Not covered:** the GovCloud and China partitions (see Partitions above).
- **Regions are not enumerated from your account** — the region list is a fixed commercial-partition list, not the set of regions you have enabled.
- **Discovery is sequential** — see Multi-Region Discovery. Large multi-region runs take proportionally longer.
- **Nothing in this feature has been verified against a live AWS account.** The behaviour described here is what the implementation does; it has not been exercised end-to-end against real AWS resources.

## Related Documentation

- [Device Interrogation Feature](./device-interrogation.md)
- [Platform Integrations](../operate/configuration/platform-integrations.md)
- [Discovery Feature](./discovery.md)
