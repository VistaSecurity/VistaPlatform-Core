# Third-Party Systems and External Connections

This feature helps you focus on cryptography on your own network while identifying and assessing **3rd party systems** your infrastructure talks to—and finding **which internal hosts** connect to those systems (for example, when you discover weak crypto on a 3rd party).

## How 3rd party is determined

- **Network Segments** define "your" network — CIDR blocks, IP ranges, domains and
  cloud VPCs. You maintain them under **Settings → Infrastructure → Network
  Segments**; see [Operational context](./operational-context.md).
- Every discovered asset is classified as:
  - **Internal** – matches one of your network segments
  - **3rd party** – does not match (e.g. internet or partner destinations)
  - **Unknown** – private IP but no matching segment (review recommended)

**Important:** define your internal network in **Network Segments** first, or the
internal / 3rd-party split is a guess.

## Finding 3rd party systems and weak crypto

1. **Certificates**
   - Open **Inventory → Certificates** and set **Ownership** to **3rd-party**.
   - You get the certificates of the vendors you have elevated — algorithm, key
     size, expiry and strength, assessed the same way your own are. **Unknown** is
     an option there too, for certificates that matched neither.

2. **Weak crypto**
   - Crypto assessment runs on **everything** — internal and third-party alike.
     Nothing is skipped because it belongs to somebody else.

3. **Third-party connections**
   - Open **Inventory → 3rd Party**.
   - Each row is a **destination your environment talks to**, with the source it
     was seen from underneath it: protocol and version, cipher suite, a strength
     badge, certificate expiry and when it was last seen.
   - The strength badge carries the reason. A connection marked *weak* that looks
     fine at a glance — TLS 1.3, a strong cipher — has something else behind it,
     such as an undersized certificate key or a weak signature hash. Certificate Transparency and trust observations appear separately as certificate hygiene.
     Hover the badge to read what.

Strength uses **Weak, Acceptable, Strong, Recommended**. The weakest assessed component wins, even when the cipher suite itself is recommended. **Not assessed** means evidence is insufficient; it does not mean the connection is safe. **Reassessment required** means an earlier weakness was recorded but its supporting facts are incomplete. Hover for the retained reason. Some older observations stored cipher size where exchange-key size was expected; these retain the original number for review and require a fresh exchange-key measurement. Rows with a proven weak component retain their **Weak** badge and show any unresolved evidence in its hover details; unresolved rows without a proven grade appear under the **Not assessed** filter. The **Reassessment required** dashboard count includes both groups and can overlap **Weak crypto**. A partial observation cannot clear prior key-size, signature or offered-protocol weakness.

Existing observations are reassessed at service startup and during the regular nightly assessment. Historical ratings retain their original vocabulary: an old “good” label does not tell us whether the connection meets today's Strong or Recommended rating.

## Typical workflow: weak crypto on a 3rd party

1. Open **Inventory → 3rd Party** and look down the **Strength** column, or search
   for the vendor by name.
2. Hover the strength badge to see exactly why a connection is rated as it is.
3. The row names the internal source the connection was seen from — that is who
   you talk to about it.
4. If the vendor matters enough to watch continuously, **Elevate** it (below). If
   it does not, leave it; the row stays in this list and never clutters your
   managed inventory.

## TLS version enumeration

When a sensor actively probes a TLS endpoint it tests **all four TLS versions**
(1.3, 1.2, 1.1, 1.0) one at a time and records which ones the server accepts.
That answers the question a vendor questionnaire actually asks: *does this
service still accept TLS 1.0 or 1.1?* — which is not the same question as *what
did it negotiate with us?*

A server that still accepts TLS 1.0 or 1.1 is rated **weak** even when the
connection you observed negotiated TLS 1.2 or better. The accepted-version list
is the claim about the server; the negotiated version is only a claim about one
conversation.

The versions a probe found are shown on the discovery record the probe produced,
under **Discovery**. The **Dashboard** summarises the whole picture in its
external-exposure panel: how many connections were rated weak, how many involve
**legacy TLS**, how many carry expired certificates, and how many are already
quantum-resistant.

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

1. Open **Inventory → 3rd Party**.
2. Find the vendor connection you want to watch and click **Elevate**.
3. Confirm. The connection becomes a **monitored asset** (still tagged 3rd-party)
   and its certificate is captured and assessed exactly like an internal one.
   The row now shows an **Elevated** badge instead of the button.

Once elevated, the vendor:

- appears under **Inventory → All assets** as a monitored asset, filterable there
  like any other, and
- its certificate appears under **Inventory → Certificates** — where it is
  evaluated for expiry, weak algorithms, and PQC-readiness like any internal
  cert.

Connections you don't elevate stay in the 3rd Party list and never clutter your
managed inventory. Re-discovery of an elevated vendor keeps its monitored asset
current — it is refreshed in place, not re-listed as noise.

### "Are my vendors using good crypto?"

Open **Inventory → Certificates** and set the **Ownership** filter to
**3rd-party**. You'll see the vendor certificates you've elevated — algorithm,
key size, expiry, and strength — side by side with the same assessment your
internal certs get. That's your vendor-cryptography posture in one view.

> Elevation requires the **update assets** permission. There is no one-click way
> back today, so elevate the vendors you intend to track rather than
> experimenting through the list.

## Data source

- **Sensor discoveries** record both source and destination when your sensors see traffic. The platform stores **source IP** with each discovery so it can show “which internal hosts talk to which destination.”
- Connections are only shown for discoveries that have been **processed** and have a **source IP** (sensor-reported traffic). Cloud-only discoveries may not have source IP.

## Related

- [Operational context](./operational-context.md) – network segments, which define what counts as internal
- [Inventory and lenses](./inventory-and-lenses.md) – the 3rd Party lens among the rest
- [Asset Approval](./asset-approval.md) – review and approve discovered assets (ownership is shown there)
- [Discovery](./discovery.md) – how assets are discovered
