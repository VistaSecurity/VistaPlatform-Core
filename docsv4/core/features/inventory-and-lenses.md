# Inventory and Lenses

The **Inventory** page is the heart of Vista Platform. It's where every asset, certificate, cryptographic key, crypto configuration, and third-party connection your environment has discovered comes together in one place.

There is **one inventory** — a single dataset — and **lenses** reshape it. A lens doesn't take you to a different page or a different copy of the data; it re-angles the same underlying inventory so you see it the way the task in front of you needs. Auditing certificate expiry? Switch to the Certificates lens. Checking weak ciphers? Switch to Configuration. Tracking down assets that have gone quiet? Switch to Stale Assets. Same data, different angle.

## Where to find it

**Inventory** in the top navigation. The lens switcher lives in the **left sidebar** — each lens is a row you click. The active lens is reflected in the page address (`/inventory?lens=…`), so a lens view is bookmarkable and shareable: send a colleague a link and they land on the exact lens you were looking at.

## Switching lenses

Pick a lens from the left sidebar. The page reshapes immediately. A few things to know:

- **Your filters carry over.** Environment, Risk, and Strength filters describe *your slice of interest*, not the lens, so they persist as you switch lenses. The page resets to the first page of results when you change lenses, but your filters stay put.
- **Search is lens-aware.** The search box at the top filters the current lens against the fields that matter for that lens (hostnames and IPs for assets, common names and issuers for certificates, key types and fingerprints for keys, and so on). Clear it to see everything again.
- **The count is always honest.** The header shows how many items the current lens holds (e.g. `412 assets`, `28 stale`). When a filter is narrowing the view, it reads `shown of total`.

## The lenses

The first group of lenses are the **primary** lenses, always visible in the sidebar. Below them is a **By Protocol** group that narrows the Configuration view to a single protocol.

### Infrastructure

The default landing view. Each row is one **Infrastructure Asset** — a server, load balancer, network device, or other host Vista Platform knows about. Expand an asset to see the **Crypto Configurations** discovered on it (the protocols, cipher suites, and keys it's actually using).

Each row summarises the asset across seven columns:

| Column | What it shows |
|---|---|
| **Identity** | Hostname when known, otherwise the address. Below it: the address, asset type and operating system, as far as they're known. |
| **Location** | Environment badge (production, staging, …) and the network segment or business unit the asset sits in. |
| **Service** | The identified service and version (for example `nginx` / `v1.25.3`). |
| **Risk** | The asset's risk score and severity band. A dash with **not assessed** means nothing on the asset has resolved against the algorithm catalogue yet — it is *not* a clean bill of health. |
| **Crypto** | A badge per protocol found on the asset, coloured by the worst risk seen for that protocol, plus the total number of crypto configurations. A greyed badge is a protocol whose configurations aren't assessed yet. |
| **Certs** | How many certificates are deployed on the asset. |
| **Status** | Any abnormal state (pending approval, stale, archived) and when the asset was last seen. |

Anything Vista Platform genuinely doesn't know shows as a dash rather than a guess. On narrower windows the Location, Service, Crypto and Certs columns drop away in that order, so Identity, Risk and Status always stay visible.

**Use it when** you want the asset-centric picture: what do we have, where does it live, and what crypto is running on each thing.

### Certificates

Every certificate in your inventory, one per row — common name, issuer, key algorithm and size, expiry, and how many places it's deployed. This lens lists **all** certificates, including ones you've uploaded manually (shown as unassigned until they're linked to an asset), not just certificates discovered by a sensor. It's sorted by expiry so the certificates closest to expiring float to the top, and an **Ownership** filter lets you narrow to internal vs. third-party certificates.

**Use it when** you're managing certificate lifecycle — renewals, expiry sweeps, finding weak key sizes, or confirming an uploaded certificate landed.

### Cryptographic Keys

A dedicated inventory of every cryptographic key discovered across your environment — key type and size (or curve), lifecycle state, expiry, and how many assets use each key. A key marked **Unlinked** is in inventory but isn't (yet) referenced by any discovered configuration — expected for imported or newly-catalogued key material, and tracked here so nothing is invisible.

**Use it when** you're running a key-length policy audit, reviewing lifecycle state, or tracing the blast radius of a weak or compromised key. (See the dedicated [Cryptographic Keys](./cryptographic-keys.md) guide for the full column reference.)

### Configuration

Every discovered **Crypto Configuration**, grouped by strength — Weak, Acceptable, Strong — with the weak group expanded first so the riskiest crypto is in front of you. Each row shows the host, protocol and version, cipher suite, key details, and hash. An additional **Strength** filter (on top of Environment and Risk) lets you isolate exactly the band you care about.

**Use it when** you're hunting for weak or deprecated crypto — outdated TLS versions, weak ciphers, small key sizes — across everything at once.

### Network

The same assets as the Infrastructure lens, but grouped by **network segment** instead of listed flat. Each segment is a collapsible group; assets fall under the segment they belong to (or "Unsegmented"). Empty segments still appear, so you can see coverage gaps, not just populated segments.

**Use it when** you want a topology-shaped view — which segment is an asset in, and how is crypto distributed across your network zones.

### 3rd Party

Outbound connections your assets make to **external** endpoints — SaaS providers, partners, APIs. This is its own dataset (not your internal assets): each row is a destination your environment talks to over TLS, with the protocol, cipher suite, crypto strength, certificate expiry, and when it was last seen. Where you have the right permission, you can **Elevate** a connection to bring it into managed inventory, after which it's tracked like an internal asset and the row shows an "Elevated" badge.

**Use it when** you're assessing third-party crypto exposure — are the vendors and services we depend on using strong TLS? (See [Third-Party and External Connections](./third-party-and-external-connections.md) for detail.)

### Stale Assets

Assets that haven't been seen recently (more than two weeks) or are no longer active. Each row shows how long it's been since the asset was last observed, its status, and quick actions for housekeeping. The staleness cut is applied across the whole inventory, so the count and pagination reflect every stale asset, not just the current page.

**Use it when** you're cleaning up — retiring decommissioned hosts, investigating assets that dropped off the radar, or keeping your inventory honest.

### By Protocol: TLS and SSH

Two protocol sub-lenses under the **By Protocol** heading. They show the same flat Configuration view as the Configuration lens, pre-narrowed to a single protocol — **TLS** or **SSH** — so you can focus on one without setting a filter.

**Use it when** you want a clean, protocol-specific list — e.g. reviewing every SSH configuration in one shot.

## Drilling into a row: the detail drawer

Click any row to slide open a **detail drawer** with the full record. Drawers **stack** — you can drill from one record into a related one without losing your place, and each drawer paints on top of the last. The top drawer closes first (press Esc or click the dimmed background), peeling back one layer at a time:

- From a **key**, jump to the asset that uses it.
- From a **certificate**, jump to the asset it's deployed on.
- From a **crypto configuration**, jump to its asset or its certificate.
- From an **asset**, expand into its configurations.

This is how you answer "what depends on this?" questions: start anywhere and follow the relationships, with every step you took stacked behind you.

### Why a configuration scored what it did

A crypto configuration's drawer carries a **Why this score** section under its
Assessment rows. It names the component that set the score, shows each
component's catalogue assessment, marks whether the component was **observed in
use** or only **offered, not observed**, and surfaces the catalogue's migration
guidance for the offending one. When nothing resolved against the catalogue it
says **not assessed** — which is not the same as safe. See
[Crypto Risks → Seeing why a configuration scored what it did](./crypto-risks.md#seeing-why-a-configuration-scored-what-it-did).

## Exporting the current view

The **Export** button (top right) downloads exactly what you're looking at — the current lens, with your active filters and search applied — as a CSV. Each lens exports the columns that make sense for it (assets export hostnames and segments; certificates export issuers and expiry; keys export sizes and fingerprints; and so on). The file is built right in your browser from the rows already on screen, so there's no waiting.

**Exports are convenience, not evidence.** A page-local CSV is perfect for a quick spreadsheet pivot, a key-length sweep, or sharing a snapshot with a teammate. It is **not** an audit-grade artifact: it has no provenance, no content hash, and no fixed scope boundary. When you need something an auditor can rely on — reproducible, hashed, and tied to a defined boundary — generate a **CBOM artifact** instead. (See [Page-Local Exports](./page-local-exports.md) for the distinction, and [CBOM Artifacts](../cbom/cbom-artifacts.md) for audit-grade output.)

## See also

- [Cryptographic Keys](./cryptographic-keys.md) — the Keys lens in depth
- [Third-Party and External Connections](./third-party-and-external-connections.md) — the 3rd Party lens in depth
- [Page-Local Exports](./page-local-exports.md) — what the Export button is (and isn't) for
- [CBOM Artifacts](../cbom/cbom-artifacts.md) — audit-grade, hashed, scoped evidence
