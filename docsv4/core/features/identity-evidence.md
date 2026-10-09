# Asset identity and discovery evidence

Inventory records approval, identity quality, classification, and assessment
separately. A monitored asset can have an unknown type or be unassessed.

Existing records remain visible as **Identity not evaluated**. This
label does not change their IDs, approval decisions, placement, or associations.
The identity coverage row reports not-evaluated, established, and operator-confirmed
assets separately, and links to unresolved observations and identity conflicts.

Open **Discovery → Observations** to inspect retained evidence, its source,
observation times, identifiers, network, and enrichment state. Each row says
what it needs — **Ready to confirm**, **Matches an asset**, **Several match**,
**Needs a network**, **Needs a sensor** or **Likely noise** — and opening it
explains why. Repeated delivery of one observation does not count as independent corroboration. Linked records open
the corresponding asset; conflict records link to Approvals.

**Why DHCP hosts wait here.** On a network that hands out addresses
dynamically, today's address is tomorrow's other device, so an address alone
never creates or matches an asset (a **pinned** address is the exception,
below). A host found by address on such a network — a scan sees no MAC address
or host key — is kept as an observation instead. Confirming says you recognise
it. If the network's addresses do not in fact move, set the segment's DHCP to
off in **Settings → Network Segments**; future scans then create assets there
directly.

**A scan you run on an asset is that asset's.** Pressing **Scan** on an asset
(**Scan** in Inventory, or the asset's own **Active Scan**) names the asset,
and the platform scans the address it has for it, so the result updates that
asset rather than waiting here — unless the scan meets a different MAC address,
host key or serial number than the asset has, or an identifier another asset
holds. Automatic scans keep waiting as described above.

**What the observation needs depends on who owns it.** The row reads **Ready to
confirm** only when nothing you already have owns the observation's address or
any other of its identifiers. If exactly one asset does, Confirm would be
refused — it would create a second record of the same device — so the row reads
**Matches an asset** and its suggested action is **Link to** that asset's name.
This happens only when nothing has confirmed that device at the address
recently: a probe of an address a sensor has seen the asset's MAC at within the
last day attaches to the asset itself and never reaches the table, and the
asset's timeline records the match as decided by a lease-fresh address.
If more than one asset owns identifiers of it — or the one that does is deleted,
archived or denied and cannot take a link — it reads **Several match** and has
no one-click action: compare the assets (merge them if they are one
device), link the observation to the right one yourself, or dismiss it.

**Why a static address on a DHCP network still matches.** A network flagged
DHCP is flagged as a whole, but not every address on it is a lease: a router's
own LAN address, a server or a printer configured by hand keeps its address
for good. An address its asset holds **pinned** still identifies that asset
inside a DHCP network, so a scan of it — even a plain port scan with no MAC
address or host key — updates the asset instead of waiting as an observation.
The network keeps its DHCP setting; only the pinned address is exempt, and it
only ever matches the asset that holds it. An address is pinned when:

- you add it to the asset yourself (the asset form, or **Add device** /
  **Edit device** on the Devices page), or tick **Pin** next to an address a
  sensor recorded, in the asset form's **Identifiers** list;
- the host's own agent reports the interface as statically configured (Linux,
  Windows and macOS, where the operating system says so — an address the
  operating system says nothing about is not pinned).

A pinned address shows **static** in the asset page's **Identifiers** list. To
unpin an address you added, remove it from the asset form; the next sighting
records it again, unpinned. An address the agent reports as a DHCP lease is
recorded as such and behaves like any other address on the network.

With asset-edit permission, an unresolved observation offers three decisions,
each with a reason the platform proposes from what was seen and you can edit:

- **Confirm identity** records your reason and creates an operator-confirmed
  asset, subject to your asset allowance. Monitoring approval remains separate.
- **Link to an asset** requires selecting the existing asset and explaining the
  evidence; on a **Matches an asset** row the owning asset is already chosen.
  Conflicting identifier ownership must be resolved in Approvals.
- **Dismiss** removes the observation from active work without asserting that
  it represents a different device. Repeated identical evidence does not undo
  the dismissal.

Confirm and Dismiss also work on many rows at once: tick them and use the bar
above the table. Bulk Confirm is offered only when every selected observation
is Ready to confirm, and bulk **Link to existing** only when every selected
observation Matches an asset (each is linked to the asset that owns it); linking
to an asset you choose stays one observation at a time. One reason covers
the batch, and each observation reports its own outcome.

Each decision is retained in audit storage. A changed or conflicting observation
returns a refresh request so you can review its current evidence before deciding.
Retained certificate findings become eligible for attachment after the observation
is linked and the asset is approved for monitoring.

**Confirm and Link attach the endpoints.** The ports listed under an
observation's **Endpoints** become endpoints of the asset you confirm it as or
link it to, as soon as you decide; their services, certificates and crypto
configurations follow once the asset is approved for monitoring. Confirming
several observations of one address — a scan that found 443, 8443 and 9443 on
a host nothing owns leaves three — gives **one** asset with three endpoints: the
first confirmation creates the asset, and each later one from the same
collector and network joins it.

**Supporting evidence keeps its endpoints until you attach them.** Some
sightings are linked to an asset you already have without being able to
identify it on their own — for example a scan of an address that is in none of
your network segments, or one on a DHCP network that carried a host key but
no MAC address. This **supporting evidence** is listed as **Linked**, moves the
asset's last-seen time, and adds nothing else: no endpoint, no identified
service, no crypto configuration. Its row offers **Attach endpoints…**, which
links it to that asset and adds its endpoints there. Endpoints the asset
already had are never removed; supporting sightings just stop refreshing them,
so an endpoint's last-seen time shows when something last identified the asset
on that port.

**When a matched device's identifiers differ.** A sighting that matches an
asset but carries a different SSH host key or address is not silently accepted:
the platform decides whether the key was rotated, the device moved, it was
reimaged or a different device now answers, and records it on the asset's
History tab. See
[When a device's identifiers change](inventory-and-lenses.md#when-a-devices-identifiers-change).

Unresolved observations leave the active view after 30 days without a sighting.
Unlinked summaries are eligible for removal after 90 days; linked evidence and
open conflicts are retained. These observation records still do not count as
assets. A provisional inventory item is different: it is an asset, with its
own id and history, but — like an observation — it does not count toward your
asset allowance until it is established. See **Provisional inventory items**
below.

New signups start with admission and enrichment enabled. Existing tenants can
activate them in Settings; the coverage row explains when admission is not
activated, observing only, or paused. Activation does not reset or bulk rewrite
existing inventory. Later qualifying evidence can establish an existing asset
in place; weaker evidence does not demote
it. A verified unnamed device may remain an unknown type, and **Not assessed**
continues to mean that assessment coverage is missing. An empty observation view
does not establish complete discovery coverage.

Approval records a decision, not another sighting: it never refreshes Last seen.

A resource listed through a connected cloud account — including object storage,
managed databases and key stores — establishes its asset from the provider's
resource id (ARN, Azure resource id or GCP resource name), and a re-run matches the
same asset on that id. A resource name alone, from any source, does not.

Cloud job logs report identity outcomes separately from the resources enumerated.
A retained cloud observation keeps encrypted provider context, including captured
crypto evidence and enumeration facts. After linking and monitoring approval,
replay uses the original observation time and fills missing context without
replacing populated class attributes. A cloud resource with an unresolved parent
keeps its context pending until the parent can be identified. Replay schedules no
new DNS or certificate-status lookup.

Automatic enrichment first checks existing configured sources. A device is not
re-interrogated for something it reported itself: a peer a controller or switch
named, which could not be identified, waits on what is actually missing (its
network, for example) rather than prompting another interrogation that would
repeat the same answer. Automatic re-checks of any one configured device run at
most once every 6 hours; interrogating it yourself, and its interrogation
schedule, are not limited. When that work
finishes, eligible observations may request one scoped DNS lookup and bounded
TLS/SSH probes through the observing collector. DNS answers are context, not
proof that a device has been identified. Results follow the same identity and
approval checks as other observations.

Observation details show enrichment states and recent attempts. **Blocked**
includes a reason, such as an outdated collector, unresolved network scope,
excluded address, sensitive device, or an unavailable configured source. A
`.local` name is resolved only on its observing local network. Ambiguous or
overlapping network scopes wait for source evidence rather than initiating a
probe whose result could be attributed to the wrong network.

Enrichment reuses configured credentials and profiles; it does not try default
credentials or expand a weak hostname into a subnet scan. Repeated delivery and
worker restarts reuse persisted work. New useful evidence and the configured
rescan interval permit another bounded enrichment cycle. Pausing admission also
pauses automatic enrichment while retaining incoming evidence.

## Provisional inventory items

Some evidence is worth showing before anyone has confirmed it. When a sensor
hears an advertisement for a device that lives on a different, configured
network — a reflected mDNS announcement is the common case — the device does
not disappear into an observation nothing can see. It appears in Inventory as
a **provisional** item: label **Provisional identity — unverified**. A
provisional item is pending approval, like any newly discovered device, so the
default Inventory → All assets view — which shows monitored assets — does not
list it. Reach it instead through the **Identity** facet on the Inventory
rail (choose **Provisional**), the "N provisional items" link in the identity
coverage row (which opens Inventory already filtered to them), Discovery →
Approvals, or **Open provisional item** on the observation that produced it.

A provisional item is not established and not assessed. It does not count
toward your asset allowance while it stays provisional — creating one performs
no allowance check, because it is still a guess about another network's
chatter, not yet an asset you are paying inventory space for. Approving a
provisional item starts monitoring it; identity stays provisional until
something corroborates it or an operator confirms it.

The asset page's Identity section leads with "This item was created from an
advertisement that no collector has verified directly." and then says what is
known: `Advertised by <sensor> (reflected mDNS, <time>)`; when the advertising
sensor cannot itself reach the device's network, `<sensor> — <reason>`;
`Enrichment can run through <sensor>.` when a collector is able to do the
work, or — when none can — "No collector currently reaches this network.
Deploy a sensor on the observed network to continue."; and `Next attempt:
<time>`. "Inspect discovery evidence" opens the same observation. The panel
closes with "Approving this item monitors it; its identity stays provisional
until a collector on its network corroborates it or you confirm it." The
identity coverage row also reports how many provisional items exist, linking
to Inventory filtered to them.

### What establishes a provisional item

A provisional item becomes **Identity established** — in place, same asset,
same id — when a collector on the device's own network observes it directly
and agrees with the advertisement about its name (hostname, FQDN, or declared
name). Agreement on an address alone is not enough to combine two devices: an
IP address can move between devices, so when direct evidence matches only the
address, the address moves to the device that was actually observed, and the
provisional item keeps whatever name it was created from. If that leaves the
provisional item with nothing, it is archived — nothing was merged; the guess
was simply about a device that turned out not to be separate from the one just
observed.

Either way, the item's history keeps the whole story: creation from the
advertisement, then establishment (or the address reassignment), and Discovery
→ Observations lists every sensor's observation still linked to the resulting
item. No second asset is ever created for the same device.

An advertisement that names a device but carries no address on a configured
network, or one whose network is unresolved or overlaps another configured
segment, does not become a provisional item. It stays in Discovery →
Observations until a sensor on its own network resolves the ambiguity.

### Deciding a provisional-linked observation

The observation that produced a provisional item still offers the usual three
decisions, with provisional items handled explicitly:

- **Confirm identity** promotes the same item to operator-confirmed. It never
  creates a second asset.
- **Link to an asset** is refused: "This observation already backs a
  provisional inventory item. To combine it with another asset, use merge
  review from Inventory." Combining a provisional item with an existing asset
  is a merge decision, not a link — select both assets in Inventory and merge
  them there.
- **Dismiss** archives the provisional item, if no other observation is still
  linked to it.

### Upgrading from an earlier release

If trustworthy discovery was already active before this release, existing
retained observations do not need to be re-registered. Most become provisional
items within minutes of the upgrade, on the next enrichment sweep. An
observation that was refused for an unresolved or overlapping network is
re-checked on a six-hour cadence instead, so fixing the segment is reflected
within six hours, with no action required from you either way.

## Review and merge

Use **Discovery → Approvals** for existing-asset identity questions. A proposal
containing only candidates can still be reviewed: explicitly select the source
assets and survivor, then request the preview. Inventory also offers merge review
for explicitly selected assets. The preview shows current evidence, field choices
and affected records. Populated survivor values are preserved by default;
conflicting declared values require an explicit choice. Give a reason before
confirming the merge. If evidence or candidates change, refresh the preview and
review it again.

A merge archives its sources with links to the survivor. Audit history records
the actor, reason, source snapshots, field decisions and moved or coalesced
records. Endpoint, certificate, key, software, finding and other associations
remain accessible, including distinct certificates on different endpoints.
A sensitive source asset transfers its protection to the survivor; this policy
change is audited and invalidates an older settings draft or merge preview.
**Keep Separate** records a durable identity decision; dismissal only hides an
observation from active work. Existing assets are never combined merely because
a similarity score is high. Merge undo and asset split tooling are not available.

## Configure and pause discovery

New tenants start with identity admission enforced and automatic enrichment
enabled. Qualifying evidence can establish assets; weaker evidence remains in
Discovery for corroboration. Network access and active probes still follow the
configured scanning policy. The initial policy is recorded in the settings audit
as a product default. Existing tenants retain their current policy, including
those that have not activated identity admission.

Open **Settings → Discovery → Active Scanning → Trustworthy discovery**. Viewing
the policy requires settings-read permission; changes require settings-update
permission and a reason. Choose identity admission and automatic enrichment
separately. Network exclusions and sensitive asset IDs further restrict permitted
enrichment and automatic asset scans, including queued work before dispatch.
The scanning policy below controls active protocols, ports and cadence.
A changed policy requires reloading the saved version before another save.

Before first activation, **Observe** records evidence while preserving the
previous admission behavior. **Enforce** applies the admission rules to future
observations. After activation, **Pause** stops new admission and enrichment while
incoming evidence remains durable; **Enforce** resumes processing. Returning to
Disabled or Observe after activation is refused, so pausing cannot silently
restore permissive asset creation. A pause does not undo measurements already
performed or existing operator decisions. Keep the admission-aware release running
while paused; rolling back to a release that predates admission would restore its
older asset-creation behavior.

Enrichment needs a current collector that reports the required capability and a
reachable interface in the observed network. Installing only the platform does
not give an older collector DNS capability. `.local` lookups stay on that local
network; there is no public-resolver fallback. A hostname or DNS answer alone
still does not establish a device. Configured credentialed sources must already
have an authorized profile and executor. Blocked observations retain their
source evidence and explain what is missing.

For API clients, use tenant-authenticated `GET` and `PUT`
`/api/v2/inventory-service/settings/identity-discovery`. Read the current version
and release capabilities before updating. A write includes the version, reason,
admission mode and enrichment policy; a stale version returns a refreshable 409.
See the [inventory API specification](../../../api/openapi/inventory-service.openapi.yaml).

## Rollout evidence

The combined release must pass all three isolated estates and every reference
stage, including restart/resume and certificate replacement, before prospective
activation. The canary tenant then needs a separate baseline reconciled against current
controllers, agents and cloud sources, followed by at least 24 hours and two
completed enrichment cycles. Existing inventory stays intact. Stop expansion
for false merges, missing evidence or attachments, cross-tenant access, unexplained
count growth or ingestion failures. Historical failed runs remain part of the
acceptance record. These steps are release gates; this guide does not claim they
have completed. Live Windows deployment acceptance remains separate operational
work.

Sensor installations and device-agent installations have separate identifiers
(`sensor_id` and `agent_id`). When both report the same host, matching hardware
evidence can associate them with one asset. Their different installation IDs do
not themselves constitute a conflict. Upgrades correct the identifier type for
existing sensor self-reports while preserving asset ownership and sighting
timestamps. Existing duplicate assets still require explicit reconciliation;
a shared hostname alone is not permission to combine them.

An online sensor is not necessarily eligible to enrich every device it observes.
Reflected mDNS advertisements can describe a device on another subnet. Automatic
network checks require a recently reported, enabled interface with an address and
prefix in the target network. Discovery explains this separately from a collector
whose heartbeat is stale or whose profile disables active network checks.
