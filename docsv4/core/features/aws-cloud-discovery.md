# AWS Cloud Resource Discovery

Automated discovery and interrogation of AWS cloud resources for cryptographic configuration collection.

## Overview

AWS Cloud Resource Discovery enables automatic discovery and detailed interrogation of AWS resources that use TLS/HTTPS, providing comprehensive cryptographic configuration information directly from AWS APIs.

## Supported Resources

### ✅ Fully Implemented

#### Application Load Balancer (ALB)
- **Discovery**: Automatic enumeration of all ALBs in specified regions
- **Interrogation**: Detailed crypto configuration extraction
  - SSL policy details (protocols, cipher suites, minimum TLS versions)
  - Certificate ARNs and metadata
  - Listener configurations
  - Default actions and redirect rules
- **Multiple Findings**: One discovery finding per listener (one device → many assets)

#### Network Load Balancer (NLB)
- **Discovery**: Automatic enumeration of NLBs with TLS listeners
- **Interrogation**: TLS listener configurations and certificates

#### Classic Load Balancer (ELB)
- **Discovery**: Automatic enumeration of classic ELBs
- **Interrogation**: SSL/TLS configurations

#### API Gateway v2
- **Discovery**: Automatic enumeration of APIs with custom domain configurations
- **Interrogation**: Domain certificate bindings and TLS settings

#### CloudFront Distributions
- **Discovery**: Automatic enumeration of distributions with HTTPS
- **Interrogation**: Viewer protocol policies and certificate requirements

#### KMS Keys (key management inventory)
- **Discovery**: Enumerates customer-managed KMS keys across the specified regions (AWS-managed keys are skipped)
- **Interrogation**: Per key — key spec / algorithm (e.g. `SYMMETRIC_DEFAULT`→AES-256, `RSA_2048`, `ECC_NIST_P256`), key state, usage, origin, **rotation enabled + rotation period**, multi-region flag, and aliases
- Keys are written to the `kms_keys` inventory (provider `aws`) and surface as cryptographic-key assets; key specs normalize to the shared algorithm taxonomy
- **Note:** key *metadata* only — KMS never exposes the secret key material, and the platform does not attempt to retrieve it

#### S3 Bucket Encryption (at-rest)
- **Discovery**: Enumerates buckets and their default server-side encryption
- **Interrogation**: encryption type (SSE-S3, SSE-KMS, SSE-KMS-DSSE, or default), algorithm, and the KMS key id when customer-managed; bucket-key flag

#### RDS Instance Encryption (at-rest)
- **Discovery**: Enumerates DB instances across regions
- **Interrogation**: storage-encrypted flag, algorithm, KMS key id, engine/version, Multi-AZ, and Performance Insights KMS key

## Workflow

### 1. Configure AWS Integration

Store AWS credentials in platform integrations:

**UI:** Navigate to Settings → Integrations → Add Integration

**Required Fields:**
- Integration Type: `aws`
- Access Key ID: AWS access key
- Secret Access Key: AWS secret key
- Region: Default AWS region
- Account ID: AWS account ID (optional)

Credentials are encrypted at rest using the platform's master encryption key.

### 2. Discover AWS Resources

Initiate cloud resource discovery:

**UI:** Navigate to Devices → Discover Cloud Resources

**API:** `POST /api/v1/device-interrogation-service/cloud/discover`

**Request Body:**
```json
{
  "integration_id": "uuid-of-aws-integration",
  "resource_types": ["alb", "elb", "nlb", "api_gateway", "cloudfront", "kms", "s3", "rds"],
  "regions": ["us-east-1", "us-west-2"] // Optional, uses integration default if empty
}
```

### 3. Automatic Processing

The service automatically:
1. Creates a discovery job
2. Enumerates AWS resources by type and region
3. Interrogates each resource for detailed crypto configurations
4. Writes discoveries to the `sensor_discoveries` table (unified pipeline)

### 4. Automatic Asset Creation

Cloud discoveries are automatically processed by the `discovery-processor-service`:

1. **Unified Pipeline**: Cloud discoveries flow through the same `sensor_discoveries` pipeline as sensor discoveries
2. **Auto-Processing**: The `discovery-processor-service` automatically processes cloud discoveries within seconds
3. **Network Classification**: Discoveries are classified by network space
4. **Auto-Approval**: Auto-approval rules are evaluated based on network space
5. **Asset Creation**: Assets are created with `monitoring` (if auto-approved) or `pending_approval` status

### 5. Review and Approve Assets

Review cloud-discovered assets in the Discovery Approvals modal:

**UI:** Navigate to Assets → Discovery Approvals

**Cloud-discovered assets appear alongside sensor-discovered assets** with:
- Hostname (DNS name or endpoint)
- IP address (if available)
- Port (443 for HTTPS)
- Protocol (TLS/HTTPS)
- Protocol version (from SSL policy)
- Cipher suite (from SSL policy)
- Certificate information (ARNs, metadata)
- Device ID (links asset to parent device)
- Discovery source indicator (shows as cloud discovery)

**Asset Status:**
- Assets are created with `discovery_method = 'cloud_api'`
- Assets appear with `pending_approval` status (unless auto-approved by network space rules)
- Auto-approved assets appear with `monitoring` status

## Crypto Configuration Details

### SSL Policies

For each load balancer listener, the service extracts:
- **SSL Policy Name**: e.g., `ELBSecurityPolicy-TLS-1-2-2017-01`
- **Supported Protocols**: TLS 1.2, TLS 1.3
- **Supported Cipher Suites**: Complete list from policy
- **Minimum Protocol Version**: Minimum TLS version required

### Certificate Discovery

Cloud discovery now performs **TLS handshake verification** against publicly accessible endpoints to extract full certificate chains. This provides the same level of certificate detail as sensor-based discoveries.

#### How It Works

1. After interrogating a resource via the AWS API (e.g., SSL policy details from an ALB), the service performs a TLS handshake against the resource's DNS name
2. The handshake extracts the full certificate chain (leaf + intermediates) including:
   - Certificate PEM data
   - SHA-256 and SHA-1 fingerprints
   - Subject DN, Issuer DN, Serial Number
   - Subject Alternative Names (SANs)
   - Key algorithm, key size, and signature algorithm
   - Validity period (not_before, not_after)
   - Key usage and extended key usage
   - CA flag and chain order
3. Handshake certificates are enriched with ACM metadata (ARN, renewal eligibility, validation method) by matching domain names
4. The certificates flow through the standard `sensor_discoveries` → `discovery-processor-service` → `inventory-service` pipeline, creating proper `certificates` records and `crypto_implementations` (crypto configurations) with certificate linkages

#### Fallback Behavior

- **Private endpoints**: If a resource's DNS name is not publicly accessible (e.g., internal ALBs in a VPC), the TLS handshake will fail gracefully. The device and crypto configuration are still created with ACM metadata, but without a full certificate record.
- **Handshake timeout**: Default 10-second timeout prevents blocking on unreachable endpoints.
- The `handshake_verified` flag in the discovery metadata indicates whether the certificate was obtained via actual TLS handshake (`true`) or API metadata only (`false`).

#### ACM Metadata Enrichment

Certificates discovered via TLS handshake are enriched with AWS Certificate Manager metadata when available:
- **ACM ARN**: Links the certificate to its ACM resource
- **Renewal Eligibility**: Whether the certificate can be auto-renewed
- **Validation Method**: DNS or email validation status
- **Certificate Type**: AMAZON_ISSUED, IMPORTED, etc.
- **In-Use Resources**: List of AWS resources using this certificate

#### Certificate Data Sources

Certificates in the inventory show their data source:
- `cloud_api`: Certificate discovered via cloud TLS handshake + API enrichment
- `discovery`: Certificate discovered via sensor-based discovery
- `manual`: Certificate manually uploaded

### Listener Configurations

- **Protocol**: HTTPS or TLS
- **Port**: Listener port (typically 443)
- **Default Actions**: Forward, redirect, or fixed response
- **Redirect Rules**: HTTP to HTTPS redirect configurations

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
            "protocol_version": "TLS 1.3",
            "cipher_suite": "TLS_AES_128_GCM_SHA256",
            "port": 443,
            "handshake_verified": true,
            "certificates": [
              {
                "subject_dn": "CN=example.com",
                "issuer_dn": "CN=Amazon RSA 2048 M01,O=Amazon,C=US",
                "serial_number": "0123456789abcdef",
                "not_before": "2026-04-15T00:00:00Z",
                "not_after": "2026-01-01T00:00:00Z",
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
              "ssl_policy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
              "certificates": [
                {
                  "arn": "arn:aws:acm:us-east-1:123456789:certificate/abc123"
                }
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

## Multi-Region Discovery

The service supports discovery across multiple AWS regions:

```json
{
  "integration_id": "uuid",
  "resource_types": ["alb"],
  "regions": ["us-east-1", "us-west-2", "eu-west-1"]
}
```

Resources are discovered and interrogated in parallel across regions for efficiency.

## Error Handling

- **API Errors**: Logged but non-fatal - discovery continues for other resources
- **Permission Errors**: Reported in job status and device connection_status
- **Rate Limiting**: AWS API rate limits are respected with exponential backoff

## Security Considerations

### Credential Management
- Credentials encrypted at rest in `platform_integrations` table
- Decrypted only when needed for API calls
- Never logged or exposed in responses
- Credentials cleared from memory after use

### IAM Permissions Required

Minimum IAM permissions for AWS discovery:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeSSLPolicies",
        "apigatewayv2:GetApis",
        "apigatewayv2:GetDomainNames",
        "apigatewayv2:GetApiMappings",
        "cloudfront:ListDistributions",
        "cloudfront:GetDistribution",
        "kms:ListKeys",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "kms:ListAliases",
        "s3:ListAllMyBuckets",
        "s3:GetEncryptionConfiguration",
        "rds:DescribeDBInstances"
      ],
      "Resource": "*"
    }
  ]
}
```

## Limitations

### Current Implementation
- ✅ ALB, ELB, NLB fully implemented with TLS handshake certificate extraction
- ✅ API Gateway v2 fully implemented with TLS handshake certificate extraction
- ✅ CloudFront fully implemented with TLS handshake certificate extraction
- ✅ ACM metadata enrichment (ARN, renewal status, validation method)
- ✅ Full certificate chain extraction via TLS handshake
- ✅ KMS key inventory (spec, state, rotation, aliases) → `kms_keys` + key assets
- ✅ S3 bucket and RDS instance at-rest encryption posture (algorithm, CMK)
- 🚧 Classic ELB detailed interrogation (basic support only)
- 🚧 Not yet covered: Secrets Manager, EBS volume encryption, DynamoDB

### Rate Limits
- AWS API rate limits apply
- Large-scale discoveries may take time
- Consider regional batching for very large environments

## Related Documentation

- [Device Interrogation Feature](./device-interrogation.md)
- [Platform Integrations](../operate/configuration/platform-integrations.md)
- [Discovery Feature](./discovery.md)
