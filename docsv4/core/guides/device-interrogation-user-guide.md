# Device Interrogation User Guide

This guide covers how to use the Device Interrogation features in the Vista Platform to discover and monitor cryptographic assets across your network devices and cloud infrastructure.

## Overview

The Device Interrogation service enables you to:

- **Discover cryptographic configurations** from network devices (F5, Fortinet, Cisco, Palo Alto, UniFi)
- **Integrate with cloud providers** (AWS, Azure, GCP) to discover cloud-based cryptographic resources
- **Schedule automated interrogations** to maintain an up-to-date inventory
- **Track discovered assets** through the approval workflow

## Getting Started

### Prerequisites

- Active tenant account with appropriate permissions
- Network connectivity to target devices (for on-premises)
- Cloud credentials with read access (for cloud discovery)

## Cloud Integrations

### Adding a Cloud Integration

1. Navigate to **Discovery > Cloud Integrations**
2. Click **Add Integration**
3. Select the cloud provider (AWS, Azure, or GCP)
4. Enter the required credentials:

#### AWS
- **Name**: A descriptive name for this integration
- **Access Key ID**: Your AWS access key
- **Secret Access Key**: Your AWS secret key
- **Region**: Default region for discovery

#### Azure
- **Name**: A descriptive name for this integration
- **Tenant ID**: Your Azure AD tenant ID
- **Client ID**: Application (client) ID
- **Client Secret**: The client secret value
- **Subscription ID**: Azure subscription to scan

#### GCP
- **Name**: A descriptive name for this integration
- **Project ID**: GCP project ID
- **Service Account JSON**: The service account key JSON file

5. Click **Save** to create the integration
6. Use **Test Connection** to verify the credentials work

### Discovering Cloud Resources

1. From the Cloud Integrations page, click **Discover** on an integration
2. Select the resource types to discover:
   - **AWS**: ALB / NLB / Classic ELB, API Gateway, CloudFront, KMS keys, S3 encryption, RDS encryption
   - **Azure**: Application Gateway, Load Balancer, Key Vault keys, Storage account encryption, SQL Database (TDE)
   - **GCP**: HTTPS Load Balancer, SSL Proxy, Cloud KMS keys, Cloud Storage encryption, Cloud SQL encryption
3. Select regions or resource groups to scan
4. Click **Start Discovery**
5. Monitor progress in the **Interrogation Jobs** page

### Cloud Discovery Results

After a cloud discovery job completes, discovered cloud resources are **automatically processed** through the unified discovery pipeline:

1. **Automatic Processing**: Cloud discoveries are written to the `sensor_discoveries` table and processed by the `discovery-processor-service`, using the same pipeline as sensor discoveries.

2. **Certificate Extraction**: For publicly accessible cloud resources (e.g., internet-facing load balancers, CloudFront distributions, API Gateways), the platform performs a **TLS handshake** to extract the full certificate chain. This means cloud-discovered assets include the same certificate detail as sensor-discovered assets:
   - Full certificate chain (leaf + intermediates)
   - Certificate PEM data and fingerprints
   - Subject DN, Issuer DN, SANs, validity period
   - Key algorithm, key size, and signature algorithm
   - For AWS resources, certificates are enriched with ACM metadata (ARN, renewal eligibility)

   **Note:** Private/internal endpoints that are not publicly reachable will still have their devices and crypto configurations created with API-only metadata, but without a full certificate record.

3. **Discovery Approvals**: Discovered cloud resources automatically appear in the **Discovery Approvals modal** (accessible from the Assets page). You don't need to manually import cloud discovery results. The **Certs** column shows how many certificates were discovered for each asset.

4. **Approval Workflow**: Review and approve cloud-discovered assets just like sensor-discovered assets:
   - Navigate to **Assets** → Click **Discovery Approvals** button
   - Filter by source to see **Cloud Discovery** entries
   - Review asset details and approve or deny

5. **Processing Time**: Cloud discoveries typically appear in the Discovery Approvals modal within a few minutes after the discovery job completes, depending on the number of resources discovered.

**Note**: Cloud discoveries use the same approval workflow as sensor discoveries. All discovered assets (whether from sensors or cloud APIs) flow through the unified pipeline and appear together in the Discovery Approvals modal.

### Viewing Cloud-Discovered Certificates

After cloud-discovered assets are approved into inventory:

- **Certificate List**: Navigate to **Inventory > Certificates**. Cloud-discovered certificates display a **Cloud API** badge indicating they were discovered via cloud integration.
- **Certificate Details**: Click a cloud certificate to see standard details plus a **Cloud Provider Details** section showing ACM ARN, renewal eligibility, and validation status (AWS) when available.
- **Asset Details**: Click an asset to see its linked certificates with expiry status indicators.
- **Crypto Configuration Details**: The Certificates tab shows full certificate details with chain visualization and a badge indicating whether the certificate was verified via TLS handshake or obtained from API metadata only.

## Network Devices

### Adding a Network Device with Auto-Discovery

The platform now features **automatic device discovery** that simplifies device onboarding by automatically retrieving device information.

1. Navigate to **Discovery > Devices**
2. Click **Add Device**
3. Fill in the **simplified form** with just 4 fields:
   - **Device Type**: Select manufacturer (UniFi, Cisco, F5, Fortinet, Palo Alto)
   - **Management URL**: Web management interface URL (e.g., `https://192.168.1.1`)
   - **Username**: Device admin username
   - **Password**: Device admin password
4. Click **Add Device**
5. The system will:
   - Connect to the device and authenticate
   - Automatically discover: model, serial number, firmware version, hostname, IP address, MAC address
   - Create the device with all discovered information populated
   - Encrypt and securely store your credentials

**Benefits:**
- **80% less data entry** - Only 4 fields instead of 10+
- **No typos** - Device information pulled directly from the device
- **Faster onboarding** - Complete in seconds
- **Secure** - Credentials encrypted at rest

**Supported for Auto-Discovery:**
- ✅ **UniFi**: UDM, UDR, USG, UniFi Network Controllers (fully functional)
- 🔧 **Other vendors**: Basic information (auto-discovery coming soon)

**Note:** For devices without auto-discovery support, you can still add them manually with all fields.

### Interrogating Devices

#### Single Device
1. From the device list, click the **Interrogate** button
2. A job will be created and you can track its progress

#### Bulk Interrogation
1. Select multiple devices using the checkboxes
2. Click **Bulk Interrogate**
3. Review the selected devices
4. Click **Start Interrogation**

### Device Health Monitoring

Each device shows its connection status:
- **Connected**: Device is reachable and responding
- **Error**: Last interrogation failed
- **Unknown**: Device hasn't been tested yet

Click on a device to view:
- **Overview**: Basic device information and status
- **Interrogation History**: Past interrogation jobs and results
- **Discovered Assets**: Cryptographic assets found on this device
- **Health Metrics**: Success rates and response times over time

## Scheduled Interrogations

### Creating a Schedule

1. Navigate to **Discovery > Scheduled Scans**
2. Click **Create Schedule**
3. Configure the schedule:
   - **Name**: Descriptive name for the schedule
   - **Target**: Select a device or cloud integration
   - **Schedule**: Choose a preset or enter a custom cron expression
4. Click **Save**

### Schedule Options

| Preset | Cron Expression | Description |
|--------|----------------|-------------|
| Hourly | `0 * * * *` | Every hour at minute 0 |
| Daily | `0 0 * * *` | Every day at midnight |
| Weekly | `0 0 * * 0` | Every Sunday at midnight |
| Monthly | `0 0 1 * *` | First day of each month at midnight |

### Managing Schedules

- **Enable/Disable**: Toggle schedules on or off
- **Trigger Now**: Run a schedule immediately
- **View History**: See past executions and results

## Interrogation Jobs

### Monitoring Jobs

The **Interrogation Jobs** page shows all running and completed jobs:

| Status | Description |
|--------|-------------|
| Pending | Job is queued and waiting to run |
| Running | Job is currently executing |
| Completed | Job finished successfully |
| Failed | Job encountered an error |
| Cancelled | Job was manually cancelled |

### Job Details

Click any row on **Discovery → Discovery Jobs** or **Discovery → Job Logs** to
open that run's detail.

**Execution** — target device or integration, status, created / started /
completed times, duration, and the error message if it failed.

**Outcome** — three counts that are deliberately separate:

| Count | Meaning |
|-------|---------|
| Discovered | Assets the interrogation returned |
| Crypto measured | Assets whose TLS posture was actually observed |
| Into inventory | Assets that became a discovery finding |

"Discovered" and "Into inventory" are different questions. A job can finish
successfully and still fail to materialize what it found — the device answered,
but something downstream rejected the results. When those two numbers disagree
the panel says so, and the reason appears under **Processing errors**.

**Pipeline** — per-stage counts for the run: assets received, findings created,
records queued for classification, and anything skipped.

**Discovered assets** — each asset with its negotiated TLS version, cipher
suite, key exchange and key size, plus every certificate found (subject, issuer,
key algorithm and size, signature algorithm, expiry, SHA-256 fingerprint, and a
`self-signed` marker). Certificate validation failures are shown against the
asset that produced them.

An asset marked **not probed** was listed by the device's management API but
never had its own handshake measured — so its cryptographic posture is
*unknown*, not clean. Interrogating a controller commonly returns both kinds:
the controller itself is measured, the devices it manages are inventoried.

### Cancelling Jobs

For running jobs, click **Cancel** to stop execution. Note that some operations may not be interruptible.

## Discovery Approval Workflow

Discovered assets go through an approval workflow before being added to your inventory:

1. **Discovered**: Assets appear in the Discovery Approvals queue
2. **Review**: Examine the discovered cryptographic configuration
3. **Approve/Reject**: Accept assets into inventory or reject them

### Filtering by Source

The Discovery Approvals page can filter by source:
- **Sensor**: Assets discovered by network sensors
- **Device Interrogation**: Assets from network device interrogation
- **Cloud Discovery**: Assets from cloud provider integrations

## Best Practices

### Security

- **Least Privilege**: Use credentials with minimum required permissions
- **Credential Rotation**: Regularly rotate cloud credentials
- **Network Segmentation**: Run agents behind firewalls when possible

#### What the platform records from your devices

Interrogation collects cryptographic **posture** — algorithms, key sizes,
protocol versions, cipher suites, certificate identity and validity. It does
not collect key material.

Vendor management APIs frequently return secrets next to the configuration we
want: a FortiGate's IPsec phase-1 object carries the tunnel pre-shared key, its
certificate store carries private keys, a UniFi controller's settings carry the
mesh PSK and SMTP relay password. Each collector projects the vendor's response
onto an explicit list of fields the platform actually uses, so those values are
discarded at the point of collection rather than stored and filtered later.
A second, name-based check runs over everything a collector emits as a backstop.

Two consequences worth knowing:

- Where a device's configuration can be read without retrieving secrets, the
  platform asks narrowly. Cisco interrogation requests only the `ssl cipher`
  configuration lines rather than the whole crypto section, so pre-shared keys
  are never transmitted off the device at all.
- Cloud key discovery reads key *metadata* only — state, algorithm, protection
  level, rotation policy. AWS KMS keys are non-exportable by design; Azure Key
  Vault is read through the management plane, which exposes key properties and
  never secret values.

The credentials **you** give the platform to reach a device are a separate
matter: those are encrypted at rest and are never returned by any API.

### Performance

- **Stagger Schedules**: Avoid running all interrogations at the same time
- **Use Regions/Resource Groups**: Limit discovery scope for faster results
- **Bulk Operations**: Use bulk interrogation for multiple devices instead of individual jobs

### Maintenance

- **Review Failed Jobs**: Check job errors and fix connectivity issues
- **Update Credentials**: Replace expired credentials promptly
- **Clean Up**: Remove devices and integrations that are no longer needed

## Troubleshooting

### Common Issues

#### "Connection refused"
- Verify the device IP address and port
- Check firewall rules allow access
- Ensure the management interface is enabled

#### "Authentication failed"
- Verify credentials are correct
- Check if credentials have expired
- Ensure the user has required permissions

#### "Timeout"
- Increase timeout settings if devices are slow
- Check network connectivity
- Verify the device is not overloaded

### Getting Help

If you encounter issues not covered here:
1. Check the device's health metrics for patterns
2. Review job error messages for specific issues
3. Contact your platform administrator
