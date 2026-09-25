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
certificate requires opening a connection to the server. By default the platform
does **not** send traffic to third-party hosts merely because one of your systems
happened to connect to them. Probing is reserved for infrastructure you own or have
explicitly chosen to monitor — unless you opt in, as described under
[Certificates of third-party TLS connections](#certificates-of-third-party-tls-connections).

**How to get full crypto detail for a vendor that matters.** Use **Elevate** (below).
An elevated connection becomes a monitored asset and is actively probed like any
internal one, which captures its certificate and negotiated cryptography. Deciding to
elevate is what authorizes the platform to talk to that host.

> Elevated HTTP/3 endpoints are probed over TLS today, which is sufficient for the
> large majority of them (servers offering HTTP/3 on port 443 almost always serve
> TLS over TCP on the same port). Native HTTP/3 interrogation — probing the QUIC
> endpoint directly and recording its QUIC-specific cryptography — is planned.

## Certificates of third-party TLS connections

A sensor watching TLS traffic reads the server's certificate straight off the wire
for **TLS 1.2 and older**. **TLS 1.3 encrypts the certificate** as part of the
handshake, so a passively observed TLS 1.3 connection — which is now most of them —
arrives with its version and cipher suite but **no certificate**. To fill that in,
a sensor can open its own connection to the same server and read the certificate
it presents. We call that *enrichment*.

**What a sensor enriches by default.** Only endpoints that are yours:

- **private addresses** — RFC 1918 (10/8, 172.16/12, 192.168/16), IPv6 unique-local
  (fc00::/7), loopback and link-local;
- addresses inside a **network segment you registered** under **Settings →
  Infrastructure → Network Segments**, whatever its type, public included.
  Segments the platform *learned* from a firewall's or switch's VLAN table do not
  count: a device reporting its internet-facing network is telling us where it is
  connected, not what you own;
- connections you **elevated** to monitored (below) — that one endpoint, not every
  port on the vendor's host.

Carrier-grade NAT space (100.64.0.0/10) is **not** treated as yours by default: it
is your provider's space, with other customers on the far side.

> **Tailscale and other CGNAT overlays: register your range.** Tailscale gives
> every device an address in 100.64.0.0/10. Until you register that space under
> **Settings → Infrastructure → Network Segments** — either all of
> `100.64.0.0/10` or just your tailnet's range — your sensors treat your own
> tailnet peers as third parties and **do not read their certificates**. The same
> applies to any other overlay or provider network that hands out 100.64.0.0/10
> addresses.

A registered segment must be a range you could plausibly own: an IPv4 segment must
be **/8 or narrower** and an IPv6 segment **/16 or narrower**. Saving anything wider
— `0.0.0.0/0` above all — is refused with a message saying so, because registering
"the whole internet" as yours would amount to switching on the opt-in below without
saying so. (Ranges wholly inside private space, such as `fd00::/8`, are exempt:
they are yours already.) A segment that wide saved before this rule existed is
kept, but it does not count as yours for enrichment; narrow it to the ranges you
own.

Everything else — vendors, SaaS, CDNs, anything your hosts merely talked to — is
recorded exactly as the sensor saw it and **not** contacted. For a TLS 1.3
connection that means the row under **Inventory → 3rd Party** shows the version
and cipher suite with **no certificate**. That is not a fault; it is the sensor
declining to connect to someone else's server without being asked. When the opt-in
below is off, the row's **Cert expires** cell says so: hover the dash to read
*Certificate not collected: active enrichment of third parties is off*.

**How long a sensor trusts what it was told.** The platform re-sends your
registered ranges and elevated connections to every sensor on every check-in. A
sensor that has not heard from the platform for **24 hours** stops treating them as
yours and enriches private addresses only, until the platform answers again.
Exclusions are never forgotten that way. If the platform cannot work out your
ranges on a check-in — for example because a scan-exclusion setting is malformed —
it tells the sensor so explicitly: no ranges count as yours until it can, and the
exclusions it could read are added to the ones the sensor already had.

A network segment marked **sensitive** or with **active probes disabled**, and any
range on your automatic-scan exclusion list, is never enriched — not even with the
opt-in below.

**Opting in.** If you want the certificates of every external TLS service your
network talks to, turn on **Actively enrich third-party TLS connections**:

1. Open **Discovery → Sensors & Agents** and click **Sensor defaults**.
2. Turn on **Actively enrich third-party TLS connections**, click **Save**, and
   confirm. The confirmation is recorded with your account.

It is off by default. When on, sensors actively connect to external TLS services
your network talks to, to read their certificates — **third parties may see these
connections** in their own logs. Each destination is contacted at most once per
observation rest period (the sensor's *Dedup TTL* setting), with a single
handshake; the extra handshakes a sensor uses to test which key exchanges a
server supports are only ever sent to your own endpoints. The setting can also be
overridden per sensor from that sensor's **Settings** tab, like any other sensor
setting (see [Agent and sensor settings](./agent-and-sensor-settings.md)).
Changing fleet defaults needs the **Update sensors** permission.

A sensor running a build older than this setting reports it as unsupported on its
**Settings** tab — and such a sensor still enriches third parties, because it
predates the rule. Upgrade it.

**Air-gapped sensors.** A sensor that never talks to the platform can be given the
same two decisions in its own configuration file (`sensor-config.yaml`) or
environment:

```yaml
capture:
  # Local third-party opt-in. Default false.
  thirdPartyTLSEnrichment: true          # env: THIRD_PARTY_TLS_ENRICHMENT=true
  # Public ranges this sensor may treat as yours, like registered segments.
  ownedNetworks:                         # env: OWNED_NETWORKS=203.0.113.0/24,2001:db8::/32
    - 203.0.113.0/24
```

These apply **only while the platform has never delivered a value**. The first time
the platform delivers the setting or its list of your networks, the platform's
value replaces the local one. The sensor records what it was given, so the
platform's value still wins after a restart — a sensor does not fall back to its
file just because it was restarted. The local opt-in is never reported to the
platform either, so a value written on one host cannot become the platform's
setting without the console's confirmation. To hand a sensor back to its local
file for good, stop it and delete `platform-probe-consent.json` from its data
directory. The record names the sensor it was written for: a data directory reused
for a sensor enrolled again — into another organization, say — ignores the old
record rather than inheriting its answers. Local `ownedNetworks` follow the same
/8 and /16 rule as segments.

Consent is never adopted from a sensor. When a sensor first reports the settings
it is running, the platform normally records them as that sensor's own starting
point; settings that need a confirmation in the console — third-party enrichment
and DNS decoding — are left out of that, so a sensor cannot grant itself either.

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
current — it is refreshed in place, not re-listed as noise. Elevating also tells
your sensors that endpoint is yours to enrich, so a TLS 1.3 vendor connection gets
its certificate read on the next observation without any opt-in.

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
