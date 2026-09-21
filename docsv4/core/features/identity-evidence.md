# Asset identity and discovery evidence

Inventory records approval, identity quality, classification, and assessment
separately. A monitored asset can have an unknown type or be unassessed.

Existing records remain visible as **Identity not evaluated**. This
label does not change their IDs, approval decisions, placement, or associations.
The identity coverage row reports not-evaluated, established, and operator-confirmed
assets separately, and links to unresolved observations and identity conflicts.

Open **Discovery → Observations** to inspect retained evidence, its source,
observation times, identifiers, network scope, and enrichment state. Repeated
delivery of one observation does not count as independent corroboration.
Linked records open the corresponding asset; conflict records link to Approvals.

With asset-edit permission, an unresolved observation offers three decisions:

- **Confirm identity** records your reason and creates an operator-confirmed
  asset, subject to your asset allowance. Monitoring approval remains separate.
- **Link to an asset** requires selecting the existing asset and explaining the
  evidence. Conflicting identifier ownership must be resolved in Approvals.
- **Dismiss** removes the observation from active work without asserting that
  it represents a different device. Repeated identical evidence does not undo
  the dismissal.

Each decision is retained in audit storage. A changed or conflicting observation
returns a refresh request so you can review its current evidence before deciding.
Retained certificate findings become eligible for attachment after the observation
is linked and the asset is approved for monitoring.

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

Cloud job logs report identity outcomes separately from the resources enumerated.
A retained cloud observation keeps encrypted provider context, including captured
crypto evidence and enumeration facts. After linking and monitoring approval,
replay uses the original observation time and fills missing context without
replacing populated class attributes. A cloud resource with an unresolved parent
keeps its context pending until the parent can be identified. Replay schedules no
new DNS or certificate-status lookup.

Automatic enrichment first checks existing configured sources. When that work
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
