# PCAP File Ingestion

## Overview

PCAP ingestion allows tenants to upload packet capture files (.pcap and .pcapng) through the web UI for offline cryptographic analysis. Extracted discoveries feed into the same discovery pipeline as live sensors, so they land in your inventory alongside everything else.

PCAP analysis is **narrower than a live sensor**. A sensor sees a connection as it happens and can probe the endpoint; a capture file is whatever bytes someone recorded. The table below is the honest list of what a capture yields today — see [Limits](#limits) for what it does not.

## User Workflow

1. Navigate to **Operations > PCAP Upload** in the web UI
2. Drag and drop a `.pcap` or `.pcapng` file (or click to browse)
3. Monitor upload progress and processing status
4. View extracted discoveries in the Inventory

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

## What Is NOT Stored

- Raw packet payloads are never persisted
- Application-layer data (HTTP bodies, email content, etc.) is not inspected
- Temporary PCAP files are deleted immediately after processing
- Only cryptographic metadata (protocol versions, cipher suites, certificates) is retained

## Architecture

```
Web UI → sensor-manager (upload, validate, store) → NATS → pcap-processor (parse) → discoveries
```

- **sensor-manager**: Accepts uploads, validates file format and size, creates job records, publishes NATS events
- **pcap-processor**: Subscribes to NATS, opens pcap files with libpcap, reassembles TLS handshakes per connection, and submits discoveries back through the standard pipeline

## File Format Support

- `.pcap` (libpcap format) — magic bytes: `0xA1B2C3D4` or `0xD4C3B2A1`
- `.pcapng` (pcap-ng format) — magic bytes: `0x0A0D0D0A`

## Size Limits

The maximum upload size is configurable by platform administrators:

- **Default**: 500 MB
- **Setting**: `pcap_max_upload_size_mb` in Admin UI > Settings > API & Limits
- **Hard cap**: 5,000 MB (5 GB)

## Permissions

| Permission | Description | Default Roles |
|------------|-------------|---------------|
| `pcap.upload` | Upload PCAP files | billing_admin, tenant_admin, security_admin |
| `pcap.read` | View upload jobs and results | All roles except api_user |
| `pcap.delete` | Delete upload job records | billing_admin, tenant_admin, security_admin |

## API Endpoints

| Method | Path | Permission | Description |
|--------|------|-----------|-------------|
| `POST` | `/api/v1/sensor-manager/pcap/upload` | `pcap.upload` | Upload pcap file (multipart) |
| `GET` | `/api/v1/sensor-manager/pcap/jobs` | `pcap.read` | List upload jobs (paginated) |
| `GET` | `/api/v1/sensor-manager/pcap/jobs/:id` | `pcap.read` | Get job status and results |
| `DELETE` | `/api/v1/sensor-manager/pcap/jobs/:id` | `pcap.delete` | Delete job record |

## Security Considerations

- File magic bytes are validated server-side (not just file extension)
- UUID filenames prevent path traversal attacks
- Tenant-scoped temporary directories provide isolation
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

- Each uploaded file is assigned a UUID and stored temporarily
- The pcap-processor service uses `pcap.OpenOffline()` from gopacket/libpcap
- TLS handshake bytes are reassembled per connection and per direction, so certificate messages that span several packets are parsed correctly
- Discoveries are created with `discovery_method = "pcap_upload"` to distinguish from live capture and active probing
- Results flow through the normal discovery pipeline (discovery-processor → inventory-service)

### Memory bounds

So that an unusual capture (a port scan, a DDoS trace) cannot exhaust the processor, reassembly is capped:

| Cap | Value | Behaviour when exceeded |
|-----|-------|------------------------|
| Buffered handshake bytes per connection direction | 256 KB | That connection is abandoned; a full handshake is a few KB, so a legitimate one never reaches this |
| Concurrently tracked TLS connections | 8,192 | Additional connections are skipped |

Anything skipped for these reasons is counted and written to the job's processing log, so a partial result is never presented as a complete one.
