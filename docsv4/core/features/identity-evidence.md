# Asset identity and discovery evidence

Inventory records approval, identity quality, classification, and assessment
separately. A monitored asset can have an unknown type or be unassessed.

Existing records remain visible as **Legacy — identity not reevaluated**. This
label does not change their IDs, approval decisions, placement, or associations.
The identity coverage row reports legacy, established, and operator-confirmed
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
open conflicts are retained. These observation records do not count as assets.

Admission is enabled prospectively for each tenant after the complete release
passes acceptance. Until then, Settings reports that activation is unavailable.
Enabling it does not reset or bulk rewrite existing inventory. Later qualifying
evidence can establish a legacy asset in place; weaker evidence does not demote
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
