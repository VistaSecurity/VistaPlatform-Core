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

## Cloud

### Connecting a cloud account

1. Go to **Discovery → Cloud**.
2. Click **Connect integration**.
3. Pick the provider (AWS, Azure or GCP) and give the connection a **name**, and
   optionally an account id, a default **region**, an environment and a
   description.
4. Enter the credentials:

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

5. Click **Connect**.
6. Use the row's **Test connection** action to check the credentials work.

Editing a connection later leaves the stored secrets alone unless you type new
ones.

### Running a cloud discovery

1. On **Discovery → Cloud**, use the connection's **Run discovery now** action.
2. Choose the resource types. They start all selected; clear the ones you do not
   want:
   - **AWS**: ALB / NLB / Classic ELB, API Gateway, CloudFront, KMS keys, S3
     encryption, RDS encryption
   - **Azure**: Application Gateway, Load Balancer, Key Vault keys, Storage
     account encryption, SQL Database (TDE)
   - **GCP**: HTTPS Load Balancer, SSL Proxy, Cloud KMS keys, Cloud Storage
     encryption, Cloud SQL encryption
3. Choose the **regions**, where the selected types are regional at all. Some —
   S3 buckets and CloudFront distributions, for instance — are listed
   account-wide, and the modal marks those rather than offering a region filter
   that would do nothing.
4. Start the run, and watch it on **Discovery → Discovery Jobs**.

### Cloud Discovery Results

After a cloud discovery job completes, discovered cloud resources are **automatically processed** through the unified discovery pipeline:

1. **Automatic processing**: cloud discoveries go through exactly the same
   pipeline as sensor discoveries. There is nothing to import.

2. **Certificate Extraction**: For publicly accessible cloud resources (e.g., internet-facing load balancers, CloudFront distributions, API Gateways), the platform performs a **TLS handshake** to extract the full certificate chain. This means cloud-discovered assets include the same certificate detail as sensor-discovered assets:
   - Full certificate chain (leaf + intermediates)
   - Certificate PEM data and fingerprints
   - Subject DN, Issuer DN, SANs, validity period
   - Key algorithm, key size, and signature algorithm
   - For AWS resources, certificates are enriched with ACM metadata (ARN, renewal eligibility)

   **Note:** Private/internal endpoints that are not publicly reachable will still have their devices and crypto configurations created with API-only metadata, but without a full certificate record.

3. **Approvals**: what was discovered waits on **Discovery → Approvals**, unless
   its segment auto-approves it. Approvals is a page of its own — the queue is
   shared by every source, and the **source** facet is how you narrow it to what
   came from the cloud.

4. **Processing time**: expect the assets to appear within a few minutes of the
   run finishing, depending on how much was discovered.

### Viewing Cloud-Discovered Certificates

After cloud-discovered assets are approved into inventory:

- **Certificate list**: **Inventory → Certificates**. Cloud-discovered
  certificates carry a **Cloud API** badge.
- **Certificate Details**: Click a cloud certificate to see standard details plus a **Cloud Provider Details** section showing ACM ARN, renewal eligibility, and validation status (AWS) when available.
- **Asset detail**: open the asset to see its certificates with expiry status.
- **Crypto configuration details**: the asset's **Cryptography** tab shows the
  full certificate detail and whether it was verified by a real TLS handshake or
  taken from API metadata alone.

## Network Devices

Devices live on **Discovery → Devices**. The page lists the assets you have
given the platform credentials for, with the management address, the asset's
class, which interrogator handles it, its firmware, when it was last
interrogated, and its connection status.

### Adding a device

Give the platform four things and it asks the device for the rest.

1. Go to **Discovery → Devices** and click **Add device**.
2. Fill in the **device type** (F5, Palo Alto, Cisco, Fortinet or UniFi), the
   **management address**, and a **username** and **password**. For a web-API
   device the address is its management URL (`https://10.0.0.1`). A Cisco
   device is reached over SSH, so give its host, `host:port` or
   `ssh://host:port`.
3. Tick **Skip TLS verification** if the management interface uses a
   self-signed certificate. It is not offered for Cisco devices, which are
   reached over SSH: their host key is checked instead, and the key seen when
   the device is added is pinned to it.
4. Click **Add device**.

The platform connects, logs in, and asks the device what it is, using the same
calls an interrogation makes:

| Device | What it reads |
|---|---|
| FortiGate | System status |
| Palo Alto | `show system info` |
| F5 BIG-IP | Software version and hardware |
| Cisco | `show version` and `show inventory`, over SSH |
| UniFi | The controller's device list |

It then creates the device with the vendor, model, serial number, firmware
version, host name and addresses it learned. Only that identity is read — not
the device's VPN keys, certificates or other configuration. Your credentials are
encrypted at rest.

**If it can't connect,** nothing is created. The form says why and shows the
remaining fields so you can still add the device by hand:

| Reason shown | What to check |
|---|---|
| Couldn't reach the device | The address and port, and that the device is reachable from the platform. If only a deployed agent can reach it, add it by hand. |
| The device's certificate isn't trusted | Tick **Skip TLS verification** and click **Try connecting again**. |
| The device rejected the credentials | The username and password, and that the account may read system information. |
| That address isn't allowed | Loopback and link-local addresses (including cloud metadata) are never probed. |
| That management address isn't valid | Use `https://host[:port]` with no user name, query or fragment. |
| Something else answered at that address | The device type, and that the address is the device's management interface. |

If your organization enforces identity admission, a device added this way is
created because the platform read its serial number itself. A device whose
serial could not be read is kept for review in **Discovery → Observations**,
like a device added by hand.

Adding and testing devices is recorded in the audit log, and an organization
can run 20 of these connections a minute.

Click **Add without connecting** to save what you entered, or **Enter the details
by hand instead** to skip the connection altogether. For **Other** device types,
which can't be identified automatically, the form shows every field from the
start. Anything you leave blank an interrogation can fill in later.

### Interrogating

Each row carries its own actions:

| Action | What it does |
|---|---|
| **Interrogate** | Queues a run against that device |
| **Test connection** | Opens a dialog; click **Test** to log in with the stored credentials and read the device's identity. Reports how long that took, or why it failed, using the same reasons as **Add device**. A device can be tested once every 10 seconds, because repeated logins with a wrong stored password can lock the device's account. Needs the same permission as **Interrogate**. |
| **Edit management settings** | Changes the address, credentials or TLS option |
| **Open this asset's page** | Goes to the asset in Inventory |
| **Stop managing this asset** | Removes the management configuration and its credentials. The asset stays. |

There is **no bulk interrogate** — interrogation is queued one device at a time.
For repeating work, use a schedule (below).

An asset discovered through a cloud API has no management credentials and is not
interrogable; its row says so rather than offering a button that would fail.

### Connection status

| Status | Meaning |
|---|---|
| **Connected** | Reachable and responding |
| **Error** | The last attempt failed — hover the status for the reason |
| **Testing** | A connection test is in flight |
| **Unknown** | Nothing has tried yet |

There is no per-device detail panel: a device *is* an asset, so its history,
endpoints, certificates and findings are on **the asset's own page**, which the
row links to. Run history is on **Discovery → Discovery Jobs** and **Job Logs**.

## Scheduled Interrogations

### Creating a schedule

1. Go to **Discovery → Scheduled Scans** and click **New schedule**.
2. Give it a **name** and an optional description.
3. Pick the **target** — a device, or a cloud integration. The target is fixed
   once the schedule exists; to point at something else, make a new schedule.
4. Enter a **cron expression** — a standard five-field cron, for example
   `0 2 * * *` for 02:00 daily. There is no preset picker; the field is the
   expression itself.
5. Save.

Common cadences, if you want them to hand:

| Cadence | Expression |
|---|---|
| Every hour, on the hour | `0 * * * *` |
| Daily at midnight | `0 0 * * *` |
| Weekly, Sunday midnight | `0 0 * * 0` |
| Monthly, 1st at midnight | `0 0 1 * *` |

### Managing schedules

A schedule can be **enabled or disabled** (it runs on its cadence only while
enabled), edited, triggered immediately, and deleted. Its runs appear with
everything else on **Discovery → Discovery Jobs**.

## Jobs

### Monitoring jobs

**Discovery → Discovery Jobs** lists every run with its status, and offers
**Retry** and **Cancel** on the rows where those apply:

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

#### Where an interrogated configuration lands

Everything an interrogation reports is read from the device's own
configuration, so it belongs to that device unless it clearly describes
something else on your network:

| The configuration names… | It lands on |
|---|---|
| The device's own address as the platform has measured it (its management SSH or HTTPS service) — the address you typed in the device form does not count | The interrogated device, with an endpoint at that address and port |
| Any other address in one of your private or registered networks (an F5 private VIP) | That address's own asset, found or proposed the usual way |
| A public address (a public VIP, a gateway's WAN VPN) | The interrogated device, with an endpoint at that address and port |
| No address (a PAN-OS decryption rule, a profile) | The interrogated device, with no endpoint |
| Only a tunnel's far end (a FortiGate or Cisco IPsec peer) | The interrogated device, with no endpoint; the peer is kept as the tunnel's peer, not made into an asset or an external connection |

A name the device reports without an address — a rule, a virtual server, a
tunnel — is kept as the configuration's label. It is never looked up in DNS,
and an interrogated address is never given a name by reverse DNS either.

If a finding cannot be attributed to any device, the job's **Pipeline** counts
it as skipped, with the reason, rather than dropping it silently.

### Cancelling a job

Use the row's **Cancel** action on a running job. Some operations are not
interruptible and will finish anyway.

## The approval queue

Discovered assets wait on **Discovery → Approvals** — a page, not a button on
some other page — unless the network segment they landed in auto-approves them,
or they are the host a device agent of yours is installed on (its first
[host inventory](../features/host-inventory.md) admits it).

The queue is shared by everything that proposes something: discovered assets,
imported rows, assets declared by an uploaded SBOM, records pulled from a CMDB,
merge proposals from the identification engine, class proposals from a
classifier, and anything the AI assistant suggested. The **source** facet is how
you narrow it, and every source states plainly what kind of claim it is making —
a serial read off a device is not the same claim as a classifier's guess.

Approving accepts the asset into your inventory. Rejecting suppresses it from
being proposed again. Full detail: [Asset Approval](../features/asset-approval.md).

## Practices worth adopting

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

Three consequences worth knowing:

- Past the collector, only a fixed set of posture fields travels on to
  inventory: a VPN's peer address and IKE version, an SSH server's banner,
  host-key type and fingerprint, a managed device's MAC address, and the names
  of profiles, certificates and configuration objects. Each is checked again
  when it arrives. The device's own identity (vendor, model, serial) is
  recorded against the device only, never copied onto what it reports.
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

- **Stagger schedules** so every interrogation does not fire at the same minute
- **Narrow a cloud run** to the resource types and regions you care about — a
  full sweep of everything costs API calls on the provider's side too

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

#### "Timed out" or "below the auto-accept threshold"

See
[Device auto-discovery troubleshooting](./device-auto-discovery-troubleshooting.md),
which covers the failures that look like nothing happened.

### Getting help

If you hit something this page does not cover:

1. Open the run on **Discovery → Job Logs** and read its **Outcome** and
   **Processing errors** — a job that "completed" can still have materialized
   nothing, and that is where it says so.
2. Check **Discovery → Approvals** before concluding an asset is missing.
3. Contact your platform administrator with the job's id and the error it
   recorded.
