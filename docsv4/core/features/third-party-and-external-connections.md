# Third-Party Systems and External Connections

This feature helps you focus on cryptography on your own network while identifying and assessing **3rd party systems** your infrastructure talks to—and finding **which internal hosts** connect to those systems (for example, when you discover weak crypto on a 3rd party).

## How 3rd party is determined

- **Network Spaces** define “your” network (CIDR blocks, IP ranges, domains). See [Network Spaces](./network-spaces.md).
- Every discovered asset is classified as:
  - **Internal** – matches one of your network spaces
  - **3rd party** – does not match (e.g. internet or partner destinations)
  - **Unknown** – private IP but no matching space (review recommended)

**Important:** Define your internal network in **Network Spaces** so 3rd party vs internal is accurate.

## Finding 3rd party systems and weak crypto

1. **Assets list**
   - Open **Manage Assets** and use **Filters** → **Ownership** → check **3rd party**.
   - You get a list of all assets classified as 3rd party.

2. **Weak crypto**
   - Weak encryption detection runs on **all** assets (internal and 3rd party).
   - Use the Ownership filter to focus on 3rd party assets, then review risk and crypto configurations as usual.

3. **External connections**
   - Go to **Inventory** → **External Connections**.
   - This shows **source → destination** connections from discovery data (which internal host talked to which destination).
   - Filter by **Destination ownership** = “3rd party” to see only external destinations.
   - To see **which internal hosts talk to a specific 3rd party**: open that asset’s detail and use “Internal hosts that connect here,” or go to External Connections and filter by that destination asset.

## Typical workflow: weak crypto on a 3rd party

1. Find a 3rd party asset with weak crypto (e.g. from reports or the assets list filtered by Ownership = 3rd party and risk).
2. Open **External Connections** and filter by **destination asset** = that 3rd party (or use the “Hosts connecting here” link from the connections table).
3. Review the list of internal hosts (source IP/hostname) that connect to that 3rd party.
4. Use that list to prioritize remediation or policy (e.g. restrict or upgrade those internal systems’ connections).

## TLS version enumeration

When sensors actively probe a TLS endpoint, they test **all four TLS versions** (1.3, 1.2, 1.1, 1.0) individually and record which ones the server accepts. This answers a critical compliance question: *does this vendor still accept TLS 1.0/1.1?*

- **Supported TLS Versions** are shown as color-coded pills in the connection detail modal (green for good, red for legacy).
- If a server accepts TLS 1.0 or 1.1 — even if it negotiated TLS 1.2 — the connection is flagged as **Weak crypto**.
- Use the **Legacy TLS only** filter to quickly find all connections accepting deprecated TLS versions.
- The **Legacy TLS** summary card shows the total count of connections accepting TLS 1.0/1.1.

## HTTP/3 and QUIC connections

Some external connections show a protocol version of **QUIC v1** with **no cipher
suite and no certificate**. This is expected, and it is worth understanding why.

HTTP/3 runs over QUIC, which — unlike TLS over TCP — **encrypts its own handshake**.
Everything that identifies the negotiated cryptography (the server's chosen cipher
suite and its certificate) is protected by keys derived during the handshake itself.
A passive sensor watching the traffic cannot read them, no matter how the sensor is
configured. This is a property of the protocol, not a gap in your deployment.

**In practice, a passively observed QUIC connection yields little more than its QUIC
version and its destination.** Some additional detail — the server name requested
(SNI), the offered ALPN protocols, a client fingerprint — is readable from the very
first packet of a connection, and the platform reads it when it can. But a sensor
only sees that packet if it happens to be watching at the moment the connection
opens. HTTP/3 connections are long-lived, so most of what a sensor observes is
mid-connection traffic with no handshake left to read. Expect this extra detail to be
present on a small minority of QUIC connections, and absent on the rest.

By contrast, the same sensor watching ordinary TLS over TCP recovers this detail on
most connections, because a TLS handshake is readable whenever it occurs and is not
encrypted end to end.

This matters more over time — HTTP/3 is enabled by default in current browsers, so a
typical desktop generates a substantial share of its traffic over QUIC.

**Why we don't simply probe those destinations.** Recovering the cipher suite and
certificate requires opening a connection to the server. The platform does **not**
send traffic to third-party hosts merely because one of your systems happened to
connect to them. Probing is reserved for infrastructure you own or have explicitly
chosen to monitor.

**How to get full crypto detail for a vendor that matters.** Use **Elevate** (below).
An elevated connection becomes a monitored asset and is actively probed like any
internal one, which captures its certificate and negotiated cryptography. Deciding to
elevate is what authorizes the platform to talk to that host.

> Elevated HTTP/3 endpoints are probed over TLS today, which is sufficient for the
> large majority of them (servers offering HTTP/3 on port 443 almost always serve
> TLS over TCP on the same port). Native HTTP/3 interrogation — probing the QUIC
> endpoint directly and recording its QUIC-specific cryptography — is planned.

## Elevating a vendor connection to monitored

Your sensors observe **thousands** of outbound 3rd-party connections — most are
noise (CDNs, analytics, OS telemetry). But a few vendors matter enough to watch
their cryptography continuously. **Elevation** lets you promote a hand-picked
connection to a fully monitored asset, on par with your own internal inventory.

1. Open **Inventory → Connections** (the 3rd-party lens).
2. Find the vendor connection you want to watch and click **Elevate**.
3. Confirm. The connection becomes a **monitored asset** (still tagged 3rd-party)
   and its certificate is captured and assessed exactly like an internal one.
   The row now shows an **Elevated** badge instead of the button.

Once elevated, the vendor:

- appears in the **Infrastructure** lens as a monitored asset, and
- its certificate appears in the **Certificate** lens — where it is evaluated for
  expiry, weak algorithms, and PQC-readiness like any internal cert.

Auto-discovered connections you don't elevate stay in the Connections list and
never clutter your managed inventory. Re-discovery of an elevated vendor keeps
its monitored asset current (it is refreshed in place, not re-listed as noise).

### "Are my vendors using good crypto?"

Open the **Certificate** lens and set the **Ownership** filter to **3rd-party**.
You'll see only the vendor certificates you've elevated — algorithm, key size,
expiry, and strength — side by side with the same assessment your internal certs
get. That's your vendor-cryptography posture in one view.

> Elevation requires the **assets.update** permission. It is reversible by design
> (a future release adds a "return to 3rd-party" action); today, elevate only the
> vendors you intend to track.

## Data source

- **Sensor discoveries** record both source and destination when your sensors see traffic. The platform stores **source IP** with each discovery so it can show “which internal hosts talk to which destination.”
- Connections are only shown for discoveries that have been **processed** and have a **source IP** (sensor-reported traffic). Cloud-only discoveries may not have source IP.

## Related

- [Network Spaces](./network-spaces.md) – define internal network for classification
- [Asset Approval](./asset-approval.md) – review and approve discovered assets (ownership is shown there)
- [Discovery](./discovery.md) – how assets are discovered
