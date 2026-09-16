# PCAP File Ingestion

## Overview

Upload a packet capture (`.pcap` or `.pcapng`) and the platform extracts what
the traffic in it reveals about cryptography. Extracted discoveries feed into the
same pipeline as live sensors, so they land in your inventory alongside
everything else.

PCAP analysis is **narrower than a live sensor**. A sensor sees a connection as it happens and can probe the endpoint; a capture file is whatever bytes someone recorded. The table below is the honest list of what a capture yields today — see [Limits](#limits) for what it does not.

## Uploading a capture

1. Go to **Discovery → Sources → PCAP Upload**.
2. Drop a `.pcap` or `.pcapng` file onto the dropzone, or click **Choose file**.
3. The upload appears under **Recent uploads** on the same page, with its
   processing status.
4. What it found reaches your inventory the same way a sensor's findings do —
   see [Where the discoveries go](#where-the-discoveries-go).

Uploading needs the **Upload PCAP files** permission (`pcap.upload`); without it
the dropzone says so instead of accepting a file.

Uploaded captures are decoded for **host announcements** as well as handshakes,
which often makes a capture the only practical way to inventory a segment that
cannot host a sensor. See
[Passive host observation](./discovery.md#passive-host-observation).

## What Data Is Extracted

The PCAP processor reassembles TLS handshakes per connection and analyzes them for cryptographic detail:

| Protocol | Data Extracted |
|----------|---------------|
| **TLS 1.0–1.3** | Negotiated protocol version, selected cipher suite, client-offered cipher suites, SNI hostname, and the server's certificate chain (see the TLS 1.3 note below) |
| **SSH** | Banner protocol version |
| **QUIC** | QUIC version and Initial-packet detection |

Cipher suites are reported by their **IANA name** (for example `TLS_AES_128_GCM_SHA256`), so they resolve against the platform's algorithm catalogue and carry a real risk score.

The negotiated TLS version is read from the **server's** response — from the `supported_versions` extension when the server sends it, and from the legacy version field otherwise. A capture that contains only the client's side of a handshake records the client's best *offer* as metadata and leaves the negotiated version blank, because what a client asked for is not what the connection used.

One discovery is produced per unique server endpoint (IP + port) in the capture, no matter how many clients connected to it.

### Limits

These are properties of packet captures, not gaps we plan to close:

- **TLS 1.3 hides certificates.** In TLS 1.3 the server's certificate message is encrypted, so a passive capture cannot see it. Certificate chains are extracted from TLS 1.2 and earlier handshakes only. For certificate coverage on TLS 1.3 endpoints, use a sensor or a device/cloud integration.
- **A capture must contain the handshake.** A capture that starts mid-connection carries only encrypted application data and yields nothing.
- **Lossy or heavily reordered captures are skipped, not guessed at.** A connection whose record framing does not line up is dropped rather than parsed into inaccurate inventory.

Not extracted from PCAP today: ALPN, JA3/JA4 fingerprints, SSH key exchange / encryption / MAC algorithm lists, STARTTLS upgrades, and IKE/IPsec. Live sensors cover several of these.

## Where the discoveries go

Discoveries from a capture are treated as **sensor** discoveries by the approval
rules, so a network segment you have set to auto-approve admits them
automatically; everything else waits in **Discovery → Approvals** like any other
discovery. (This was not always true — captures used to pile up in Approvals on
segments that should have admitted them.)

**Confidence is graded, not flat.** A host announcement from a replayed capture
scores exactly what the same announcement scores from a live sensor: how
*directly* the device stated its own identity. A switch advertising itself over
LLDP is worth more than an address seen in a DNS answer, and an auto-approval
rule that filters on confidence therefore behaves the same way on a replay as it
does live.

## What Is NOT Stored

- Raw packet payloads are never persisted
- Application-layer data (HTTP bodies, email content, etc.) is not inspected
- Temporary PCAP files are deleted immediately after processing
- Only cryptographic metadata (protocol versions, cipher suites, certificates) is retained

## File Format Support

- `.pcap` (libpcap format) — magic bytes: `0xA1B2C3D4` or `0xD4C3B2A1`
- `.pcapng` (pcap-ng format) — magic bytes: `0x0A0D0D0A`

## Size Limits

- **Default**: 500 MB
- **Hard cap**: 5,000 MB (5 GB)

The limit is a **platform-wide setting** (`pcap_max_upload_size_mb`) that the
operator of your deployment changes through the platform settings API. There is
no console page for it today — ask your platform administrator if you need a
larger capture accepted.

## Permissions

| Permission | What it allows | Built-in roles that have it |
|------------|----------------|-----------------------------|
| `pcap.upload` | Upload captures | Tenant Administrator, Security Administrator |
| `pcap.read` | See upload jobs and their results | Tenant Administrator, Security Administrator, Viewer, API User |
| `pcap.delete` | Delete upload job records | Tenant Administrator, Security Administrator |

Custom roles can carry any of these; see
[Roles & Permissions](./roles-and-permissions.md).

## API Endpoints

| Method | Path | Permission | Description |
|--------|------|-----------|-------------|
| `POST` | `/api/v1/sensor-manager/pcap/upload` | `pcap.upload` | Upload pcap file (multipart) |
| `GET` | `/api/v1/sensor-manager/pcap/jobs` | `pcap.read` | List upload jobs (paginated) |
| `GET` | `/api/v1/sensor-manager/pcap/jobs/:id` | `pcap.read` | Get job status and results |
| `DELETE` | `/api/v1/sensor-manager/pcap/jobs/:id` | `pcap.delete` | Delete job record |

## Security Considerations

- File magic bytes are validated server-side (not just file extension)
- Uploads are stored under generated names, in per-organization directories
- Concurrent processing is limited (default: 4 jobs) to prevent resource exhaustion
- Processing timeout (default: 5 minutes) prevents runaway jobs
- Row-level security ensures tenants only see their own jobs
- Internal service communication uses HMAC-SHA256 authentication

## Job Status Lifecycle

```
pending → processing → completed
                    → failed (with error_message)
         → cancelled
```

## Processing Details

- Each uploaded file is stored under a generated name and deleted as soon as it
  has been processed
- TLS handshake bytes are reassembled per connection and per direction, so
  certificate messages that span several packets are parsed correctly
- Discoveries are recorded with a discovery method of `pcap_upload`, so you can
  always tell a replay from a live capture or an active probe
- Everything then flows through the normal discovery pipeline

### Memory bounds

So that an unusual capture (a port scan, a DDoS trace) cannot exhaust the processor, reassembly is capped:

| Cap | Value | Behaviour when exceeded |
|-----|-------|------------------------|
| Buffered handshake bytes per connection direction | 256 KB | That connection is abandoned; a full handshake is a few KB, so a legitimate one never reaches this |
| Concurrently tracked TLS connections | 8,192 | Additional connections are skipped |

Anything skipped for these reasons is counted and written to the job's processing log, so a partial result is never presented as a complete one.

## Related

- [Discovery](./discovery.md) — the pipeline a capture's findings join
- [Sensor & Agent Registration](./SENSOR_REGISTRATION.md) — the live alternative
- [Asset Approval](./asset-approval.md) — where the discoveries wait, and what admits them
