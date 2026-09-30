# `shared/identity` — the identification engine

The one place that answers **"is this observation a thing we already know
about?"** It implements ADR-0002 D3 (identification), D4 (reconciliation) and
the dependent-identity rules, with the ADR-0008 matcher seam behind the
conflict path.

It replaces the four ad hoc dedupe keys the survey found: six intake paths,
four keys, no `ON CONFLICT` anywhere, and manual create not deduping at all.

**Nothing is wired to it yet.** Workstream 0.4 builds the engine; workstream
1.2 wires it into every intake path with per-path observation builders, and
1.1 supplies the Postgres `Repository`. It is pure Go, CGO-free, with no
database and no service dependency, so the sensor and the in-cluster services
can both import it.

## How an intake path calls it

```go
engine, err := identity.New(identity.Config{
    Repo:          repo,                       // the only required field
    DynamicScopes: dhcpSegments,               // segment ids that hand out addresses
})

res, err := engine.Resolve(ctx, identity.Observation{
    TenantID:  tenantID,
    ClassHint: assetclass.KeyServer,           // "" when the path has no opinion
    Identifiers: []identity.Identifier{
        {Kind: identity.KindSerialNumber, Value: "J7K2L9", Confidence: 1},
        {Kind: identity.KindHostname, Value: "db-1", Scope: segmentID, Confidence: 1},
    },
    Endpoints: []identity.EndpointObservation{
        {Address: "10.4.1.20", Port: 5432, Transport: "tcp", Protocol: "postgres"},
    },
    Source:     identity.Source{Kind: identity.SourceMeasured, Ref: "sensor", Mode: identity.ModePassive},
    Network:    identity.Network{Ownership: "internal", Type: "private", SegmentID: segmentID},
    ObservedAt: seenAt,
    Confidence: 0.9,
})

switch res.Outcome {
case identity.OutcomeMatched:  // res.Asset was updated; res.DecidedBy says on what
case identity.OutcomeCreated:  // res.Asset is new, pending approval, class res.ClassKey
case identity.OutcomeConflict: // res.Asset is a new pending asset; res.Proposal needs a human
}
```

`Resolve` does the writes itself: it attaches identifiers, upserts endpoints,
advances last-seen, opens the merge proposal, and writes `asset_history` — of
which this package is the **first writer**. The caller acts on the outcome; it
does not repeat the work.

## The outcomes

| Outcome | When | What the engine did |
|---|---|---|
| `matched` | Exactly one existing asset resolved from the identifiers | Attached the new identifiers, upserted the endpoints, advanced last-seen, history `updated`. `DecidedBy` names the highest-precedence kind that matched. A DHCP address still owned by the previous lease holder may MOVE to the matched asset — see **The address follows the MAC** below. |
| `created` | Nothing matched | Created a `pending_approval` asset with the class hint, or `unknown_host` / `external` per the network ownership. History `created`. |
| `provisional` | Evidence that cannot establish anything, placed on a configured and unambiguous tenant segment, owned by nobody — and `Config.ProvisionalInventory` is on | Created a `pending_approval` asset with `identity_status = provisional`, WITHOUT an allowance check. See **Provisional identity** below. |
| `supporting` | Evidence that cannot establish anything, every owned identifier belonging to ONE asset — and `Config.ProvisionalInventory` is on. **Or** the floor: every identifier owned, all by ONE asset, none allowed to vote — whatever the flag (#2081 A1) | Linked the observation to that asset. Advanced its last-seen — and, if the asset is itself provisional, attached the new identifiers — but ONLY when the observation is a sighting. Not a match: nothing was allowed to decide. A link that is a **lease alone** is the exception — see the address-only link rule below. |
| `conflict` | One kind matched several assets, **or** two kinds matched different assets, **or** every identifier is owned by TWO OR MORE other assets and none may vote | Opened a merge proposal listing every candidate with the identifiers that matched it. The observation becomes its own pending asset ONLY if it carries an identifier nobody owns (history `created` then `merge_proposed`); when everything is contested nothing is created and `Resolution.Asset` is ZERO — see the floor. **Never merged inside `Resolve`.** When the same-device rule holds the proposal is stamped `rule_verdict: same_device` and `Resolution.MergeRecommended` is set; inventory-service's rule-merge executor merges it later (see **The same-device rule**). A proposal always names at least two candidates. |

## The rules, and why each exists

**Precedence.** The class's `IdentifierPrecedence` from `shared/assetclass`
decides which kinds may vote, and in what order; with no class hint the ADR's
default order is used. A tenant override or a tenant leaf subclass comes in
through `Config.Precedence`. A kind that is **not** in the list is still
recorded — it is true — but it never decides. That is why a MAC-only
observation can never match a cloud resource: cloud classes drop
`mac_address`, because a cloud resource does not have one in any stable sense.

**Scope.** `hostname` and `ip_address` identify only *within a segment* — else
within the **tenant-wide default scope**, the literal `tenant`
(`identity.ScopeTenantDefault`). There is always an answer: "this tenant has no
segments" is a fact about their topology, not the absence of one.
`Identifier.Normalized` fills the default in, so no builder can produce a scoped
identifier that cannot decide anything.

That was the fix for the worst defect A1 shipped with: with *no* scope, an
unscoped identifier could not vote, so in a tenant with no segments configured —
every fresh tenant — one host observed three times became **three assets**, each
after the first carrying no identifier at all. `ip_address` still never votes
inside a scope flagged dynamic — today's DHCP lease is tomorrow's other host.

`Repository.ScopeForAddress` is the one place that decides which scope an
address is in, so inventory-service and device-interrogation-service cannot
disagree about it. When a tenant later creates segments, an asset identified
under the default scope keeps its identifiers and a re-observation inside a new
segment adds the segment-scoped one alongside; the engine matches through the
stronger kinds first, and a tenant reorganising its segments may see merge
proposals — which is correct.

**Where a segment's `dynamic` flag comes from.** `ScopeForAddress` reads exactly
one key, `network_segments.metadata.dynamic`, and that key has three authors with
a precedence between them: **operator** (Network Segments → edit, `PUT …
dhcp: true|false|null`) **>** **measured** (device-interrogation read a
controller's network list — `ensureVLANSegments`, on *whatever* segment matches
the CIDR, not only the ones it created) **>** **inferred** (inventory-service saw a
DHCP ACK assign an address inside the segment, at most once a day, never `false`).
A lower source never overwrites a higher one; the same source overwrites itself.
The rule lives in one place — `postgres.RecordSegmentPosture` /
`ClearSegmentPosture` (`segment_posture.go`), a single UPDATE so two services
writing at once cannot interleave — and both services call it. Nothing else may
write `dynamic`: it is the effective value, with `dynamic_source` and
`dynamic_evidence` beside it, and each source's own latest statement is kept in
`dynamic_by_source` so that handing the segment back to automatic (`null`) falls
back to the best remaining source instead of blanking a flag whose absence reads
as *static*. A row written before this existed carries `dynamic` alone and is
read by its writer (`postgres.PostureFromMetadata`): a bare flag on a row
interrogation created is a measurement, anywhere else it is the operator's.

**Name scope.** Every address keeps its OWN scope. A sighting's names
(`hostname`) take the scope of the **first address in the sighting that resolves
to a real segment** — not simply the first address. A sighting that lists an
IPv6 ULA or link-local address first (no configured segment covers it) used to
scope its names to `tenant` while an IPv4 address beside it sat in a real
segment, so one name lived under two scopes and never collided with itself.
When no address resolves, the old rule stands: the first address, then a
`domain` segment matched by name, then `tenant`. The Devices form follows the
same rule over the IP field, an address typed into the name field, and the
management URL's host (device-interrogation `deviceSegmentScope`). Existing
rows are not rewritten.

**Synthetic names are attributes, not identifiers.**
`hostnamequality.IsIdentityName` is the one test: a name whose first label is
UUID-form (a rotating service-instance name), IP-encoded (`192-0-2-5.local`, the
lease written as a name) or `none` / `none-N` is not identity. Both intakes —
inventory-service's host-observation ingest and device-interrogation's
`peerObservation` — record such names in the asset's `synthetic_names`
attribute (deduplicated, most recent first, at most
`hostnamequality.MaxSyntheticNames` = 20) instead of minting a `hostname`
identifier per announcement. A 12-hex `.local` name is **kept** as an
identifier: it is derived from the device's own hardware address and is the only
stable name some devices announce. Admission never read names, so a sighting
whose only name is synthetic admits exactly as before, just without a name
identifier; one that carried nothing else is refused (the floor below).
The fold is `shared/identity/attrlist` (`Merge`, `Record`), which the IPv6
address lists below use too.

**IPv6 addresses are identifiers only where they identify (#2081 D2).**
`attrlist.AddressAttribute` (over `derive.IPv6Role`) is the one rule both
intakes apply, per address:

| Address | Becomes |
|---|---|
| IPv4; IPv6 with an EUI-64 IID; IPv6 with a low-entropy (hand-assigned) IID such as `2001:db8::10` | an `ip_address` identifier, as before |
| link-local (`fe80::/10`), the sighting resolved to a real segment | an `ip_address` identifier scoped to THAT segment (unique only on its link) |
| link-local, no real segment | the `link_local_addresses` attribute |
| ULA/GUA whose IID is neither EUI-64 nor low-entropy | the `ipv6_temporary_addresses` attribute |

Both attributes hold at most `attrlist.MaxAddressEvidence` (10), most recent
first, deduplicated. "Low-entropy" is at least 8 of the IID's 16 hex digits
zero: a generated IID (RFC 8981 temporary, RFC 7217 stable-privacy) hits that
about 3·10⁻⁶ of the time, a hand-assigned or DHCPv6-pool address by
construction. The known cost: a stable-privacy address cannot be told from a
temporary one by its IID and is demoted with it — it stays on the asset as an
attribute, and the device is identified by its other evidence. Addresses a
person typed (the Devices form) are not put through this rule. A collector's
peer left with nothing but such addresses is skipped like a synthetic-names-only
peer.

**Declared names.** A tenth kind, `name`, scoped by class key, is how the
`service` branch is identified: `(tenant, class, name)`, normalised by trimming,
collapsing whitespace and lowercasing. It is NOT in the default precedence, so a
class that does not list it can never match on one.

The scope is also part of the uniqueness key, so it cuts the other way: a
scope on a kind that has none (`Kind.AcceptsScope` — only `hostname`,
`ip_address` and `cmdb_sys_id` take one) is **rejected**, not trimmed away.
One serial number arriving once bare and once carrying whatever segment the
collector happened to know would otherwise be two keys, two owners and two
assets, with no conflict and no proposal — the "four dedupe keys" failure
reappearing one field to the right.

**Empty and false.** `Reconcile` implements ADR-0002 D4's three precedence
tables plus "empty never wins" and "inferred never overwrites measured or
declared". A bool `false` is **not** empty: an explicit false is an answer, and
demoting it is the jq `//` mistake that silently inverts a security flag.

**Never auto-merge.** `Config.AutoAcceptThreshold` defaults to **0**, which
means never. A matcher scoring 1.0 still produces a proposal at 0 — the test
that proves it is `TestMatcherNeverAutoMergesAtTheDefaultThreshold`. Above a
threshold a tenant deliberately set, the observation goes into the top
candidate, the proposal is still opened marked `AutoAccepted` (it is both the
evidence and the executor's work item), and history records `merged_from` then
`merge_proposed` — the second entry carrying the `proposal_id`, the score and
the `model_id`, so the one outcome a model decided is not the one outcome
whose history dead-ends.

**Nothing in this package deletes or rewrites another asset.** Even an
auto-accepted merge only writes the observation into the winner; absorbing the
losing candidates is the approvals path's job (workstream 1.3). The same-device
rule (#2081 Phase 4) keeps to this too: the engine only stamps a verdict, and
the merge runs later, outside `Resolve`, through the audited merge path.

**Four conditions gate an auto-accept**, all of them in `Engine.autoAcceptable`
so a guard cannot exist on one conflict path and not the other:

1. the tenant set a threshold above zero (zero is the default and means never);
2. something scored, at or above it;
3. **no singleton identifier disagrees** with the top candidate's — checked
   against that candidate's own identifiers, consulting no score, because
   ADR-0002 D3's singleton erratum is categorical: two ARNs are two resources
   whatever a matcher thinks of the pair;
4. **every candidate is already `monitoring`.** Merging into an asset still
   waiting in Approvals would settle, on a model's say-so, a question a human
   has not been asked — whether that asset belongs in the inventory at all.
   Admitting an asset and merging two assets are two decisions, and a threshold
   licenses only the second.

Both new guards are mutation-proven in both polarities
(`TestAutoAcceptRefusesASingletonDisagreementAtAnyScore`,
`TestAutoAcceptRefusesAPendingCandidate` — each has a control case that MUST
auto-accept, or the refusal proves nothing).

**The threshold is per tenant, and per observation.** `Config.AutoAcceptThreshold`
is the engine's floor; `Engine.WithAutoAcceptThreshold` returns a copy carrying
one tenant's setting, which is how a single shared engine serves tenants who have
decided differently. A value outside 0..1 is refused into zero rather than
clamped — the safe reading of a threshold nobody can account for is the one that
merges nothing.

**The matcher seam's default is the learned model** of
`shared/identity/matcher` (ADR-0008 D2): a logistic regression with its weights
embedded in the binary, in-process, no provider and no network. It RANKS and
EXPLAINS; with the threshold at zero it decides nothing. `matcher: none` is
still selectable and still leaves every candidate unscored. See
[matcher/MATCHER.md](matcher/MATCHER.md).

**What `rank` hands the seam, and keeps (matcher v2, #2081 Phase 5).** The
seam sees every value of every kind (normalised like stored values), which
values were derived, and which names the intake marked generic — so the v2
features (`vendor_oui_*`, `name_generic`, `name_synthetic`, `id_match_derived`,
`binding_conflict`) can read what the engine already knows. `rank` also scores
the two top-ranked candidates against EACH OTHER and stamps `PairScore` /
`PairAssetIDs` / `PairReason` on the proposal ("the two records themselves
score N%" on the Approvals card) — advisory, read by no threshold or rule. And
every proposal carries the matcher's view of both sides as it was
(`ObservationIdentifiers`, `ObservationContext`, each candidate's `Snapshot`;
in Postgres `observation_identifiers`, `observation_context`,
`candidate_snapshots`), which `FoldMergeProposal` unions across re-asked
sightings and `scripts/export-merge-decisions.sql` turns into lossless training
samples. All three go through `Engine.openMergeProposal`, so no conflict path
can open a proposal without them.

**Floating addresses.** A MAC that resolves to one asset while the address
beside it resolves to another is a cross-kind conflict in every case but one:
when that is *all* the observation says. MetalLB L2, kube-vip, keepalived,
Windows NLB, VRRP, HSRP and CARP announce a floating address by gratuitous ARP
from whichever node holds it, using that node's own NIC, so "MAC of node X at
address Y" is a correct L2 fact and not evidence that X and Y are one thing.
`Engine.Resolve` recognises the shape (`floating.go`) — the observation is
**L2-only** (source `measured`, identifiers nothing but `mac_address` and
`ip_address`, at least one of each), every MAC resolves to X and every address
to Y, and the store is healthy — and resolves it to **Y**, the address's asset:
Y is touched and updated, the MAC is reported in `Unattached` (a deliberate
skip, not a swallowed error), the fact is recorded through
`Repository.RecordAnnouncement` (Postgres: an `asset_relationships` row of type
`hosted_on`, Y → X, evidence in `attributes.floating_address`), X is touched
and gets an `announces` history entry, and **no proposal is opened**.
`Resolution.FloatingAddress` says so. The qualifier is pinned by
`TestFloatingAddressL2OnlyIsExactlyMACAndIP`: the node's MAC arriving with a
name, host key, serial, agent or cloud id of Y is a re-imaged, cloned or
spoofed host, and still gets the proposal.

**The announcer's own address (#2081 B3).** A frame from node X may carry X's
own address beside the VIP it holds. "Every address resolves to Y" used to
exclude that, so the frame was a cross-kind conflict and a proposal to merge
the node with the service. An address the announcer itself owns is now
accepted (`floatingPair.ownAddresses`); at least one address must still be
Y's, and the frame must still be L2-only and measured. X's own addresses are
re-attached to X as an ordinary match would (refreshing their last-seen, not
reported unattached) and are never part of the announcement, so the holder's
`floating_address` history names only the floated addresses. That history is
what `Repository.AddressAnnounced` honours for the lease rule: on a DYNAMIC
segment neither address votes, the walk decides X by its MAC and
`floatingAddress` is never consulted, and the VIP stays on Y because Y is a
named service record (no device binding) or because the frame was recognised
as floating while the segment was static.

Virtual router MACs (VRRP, HSRP,
GLBP, CARP — `shared/hostobs.VirtualMACProtocol`) never reach the engine as
identifiers at all; the rule here is for the nodes that announce from a real
NIC.

**Decision memory.** `kept_separate` used to be write-only. Before any proposal
is opened, `Engine.priorDecision` asks `Repository.LastKeptSeparate` for the
most recent proposal a reviewer resolved `kept_separate` that named every one
of today's candidates (unordered; the earlier proposal's observation asset
counts as one of them). Two gates, both in the engine: it must be a **pair**
(two or more candidates — one candidate is not a decision about the next thing
to share an identifier with it), and today's evidence must be the **same kinds
or a subset** of what the reviewer saw (identifiers that matched the earlier
proposal's own observation asset excepted — they were its identity, not
evidence about the pair). A conflict that now carries an SSH host key where the
reviewer weighed a MAC against an address is a new question and is proposed
again. When the decision holds, the observation is resolved to the earlier
proposal's **observation asset** if it had one (it was created to be exactly
this observation), otherwise to the candidate the **weakest evidence** names —
the reviewer set aside the strong kind's claim, so the address or name that
remains says where it belongs. History records `suppressed_proposal`,
`Resolution.Suppressed` carries the proposal, date and reviewer, and the
auto-accept threshold never applies: no score overturns a human's no.
Separately, `ProposalRef.Reused` lets the engine write its `merge_proposed`
pointer entry once per question rather than once per observation.

**One pair, one pending proposal; the evidence folds in (#2081 A3).**
`MergeProposalFingerprint` — the key a pending proposal is idempotent over — is
the SORTED candidate ids plus the observation asset id, and nothing else. It
used to include the matched identifier keys, so one pair of records collected a
pending row per combination of identifiers its sightings happened to carry, and
a reviewer had to answer the same question several times. When
`OpenMergeProposal` finds a pending proposal with the same fingerprint it
**folds** the new evidence in through `identity.FoldMergeProposal`, the one rule
both stores call: each candidate's `matched_identifiers` become the union of
both; a candidate's score, reason and explanation are replaced only by a
strictly higher score (and the proposal's `model_id` / `source_ref` follow the
highest top score); an auto-accept, once recorded, stays recorded; `proposed_at`
(the row's `created_at`) keeps the first time the question was asked and
`latest_evidence_at` becomes the newest observation time seen. Every rule is
commutative, so the order sightings arrive in does not matter. The Postgres
fold is a `SELECT … FOR UPDATE` read-modify-write, merged with `||` so keys
another path stamped on the row survive. Pending rows written under the old
fingerprint are left alone on upgrade.

**The address follows the MAC (#2081 1b).** Inside a dynamic scope an address
decides nothing, but until 1b it could not MOVE either: a device matched by its
own MAC at an address the previous lease holder still owned left the address on
the previous holder for ever, reported as unattached on every sighting. Now, on
the **matched** branch, each unattached `ip_address` owned by ONE other asset
moves to the matched asset (`lease.go`) when ALL of these hold:

1. the match was decided by an OBSERVED (not derived — see **Derived
   identifiers**) **device-binding kind** (`mac_address`,
   `ssh_host_key_fingerprint`, `serial_number`, `agent_id`, `sensor_id`,
   `cloud_resource_id` — `deviceBindingKinds`) that ranks above `ip_address` in
   the effective precedence. A hostname or fqdn match never moves an address,
   although both rank above it by default: a DHCP client's name is a choice
   like its lease. A precedence that puts `ip_address` above the deciding kind
   (or leaves it out) is honoured as written;
2. the observation is a `measured` sighting that met the device **directly and
   not relayed**, or is **authoritative** (a controller's client table). An
   import is not evidence of who holds a lease now;
3. the address's scope is **dynamic** (`Config.DynamicScopes` or the
   observation's own `DynamicScopes`, which is how `ScopeForAddress`'s
   `metadata.dynamic` reaches the engine in production);
4. the observation's own `ObservedAt` is **strictly later** than
   `Repository.IdentifierLastSeen` — `asset_identifiers.last_seen_at`, the last
   time an observation resolved to the previous holder carried the address
   (attach advances it with `GREATEST`). A replayed or late-arriving sighting
   therefore never moves an address back, and a tie moves nothing;
5. the store implements `IdentifierReassigner`.

And the previous holder is not a record a person made about the address: its
copy of the identifier is `declared`, or it carries a `declaration_id`, or its
identity is `operator_confirmed` (guard rail: declared values are never
overwritten by measured ones).

And the previous holder is **a device that lost a lease, not a VIP**. An ARP
frame cannot tell the two apart: "VIP is-at node A's MAC" is exactly what a
MetalLB / keepalived node sends, and in a dynamic scope the address never
votes, so the floating-address rule's two-candidate shape never forms and the
frame arrives as a match on the node. The HOLDER is the discriminator
(`holderLostALease`, `Repository.AddressAnnounced`): the address moves only
when the holder carries a device-binding identifier of its own (necessarily a
different one from the announcer's — the match went elsewhere) or nothing but
addresses (the IP-only record, which the move empties). A holder with a name,
fqdn, CMDB id or other non-address identifier and **no** device binding is a
service or VIP record and keeps its address, at every failover. And any holder
the floating-address rule has **ever** recorded that address as announced for —
its `hosted_on` edge's `floating_address.addresses`, or a `floating_address`
entry in its history — keeps it too, whatever else it carries: that is the VIP
that was seen on a static segment before the segment was marked DHCP.

The move goes through `ReassignIdentifier` only;
both assets get `identifier_reassigned` with `reason: lease_moved`, `from`,
`to`, `decided_by` and `previous_last_seen_at`; the address is then attached to
the matched asset like any other identifier, which stamps its last-seen with
this observation. A **provisional** previous holder left with no identifier is
archived (`archiveIfEmptied`); an established or legacy one is left for a
person. Endpoints are NOT moved: `asset_endpoints` is unique per asset (so the
new holder's own endpoints at the address never collide with them), the
previous holder's rows describe services IT ran there, and they keep their own
`last_seen_at`, which nothing refreshes any more. Whether they should be
marked stale when the lease moves is a Phase 1 follow-up in the #2081 spec. The
rule fires only
on a match — a device's
FIRST sighting creates its asset and leaves the address where it is; its next
sighting moves it.

**Generic names (#2081 B2) — marking.** Every phone that was never renamed
announces `iphone`, and an equal hostname used to be enough for a weak match, so
three different phones shared one pending record. A hostname is **generic** when
either

- it is in the default-name dictionary or matches the phone pattern
  (`hostnamequality.IsGeneric` — one entry per line, one comment per entry, in
  `hostnamequality/generic.go`; the pattern admits digits only, so `iphone-13` is
  generic and `sams-iphone` is not, because a person's name is what makes a name
  identify one device); or
- **three or more distinct live assets** in the tenant carry it, in any scope
  (`Repository.HostnameCardinality`, the tenant-frequency signal).

A name is judged only as a `hostname` identifier: a single label, or a single
label plus the mDNS `.local` suffix. A multi-label name that is not `.local`
(`printer.corp.example`) is an FQDN — issued by whoever owns the domain — and is
never generic; ingest files those as `fqdn` and never asks. Only the
**measured** intake paths mark: the sensor's host observation, discovery
findings (inventory-service `discoveryObservation` — sensor, scan, PCAP and
cloud), the scoped DNS enrichment lookup, and device-interrogation's peers. A
name a person or a system of record supplied — manual create, elevation, SBOM
subjects, spreadsheet/CMDB/NetBox imports (`manualObservation`), operator edits
of an asset or a managed device — is a statement about which device this is and
is never marked.

Marking is done in one place, `identity.GenericNames`, which both services call:
it sets `Identifier.Generic` and lowers `Confidence` to 0.3 (`GenericConfidence`,
never raising it). The name is **still recorded** — it is true — and `Generic`
is per-observation context, not identity: it is not part of `Identifier.Key()`
and is not stored (`asset_identifiers` has no column for it; only the lowered
confidence lands, and the store keeps the *greater* of old and new, so an older
row can stay at 1.0). The tenant count is cached per `(tenant, value)` for ten
minutes in a bounded LRU (10 000 entries), and it is fail-open: an error asking
the store is logged and the name is treated as not generic by that signal,
because losing an observation over a naming heuristic is worse than trusting a
common name once.

**What the engine does with the mark (#2081 B2, part B).** A generic name is
recorded and proves nothing. Three rules, all reading `Identifier.Generic` and
sharing one definition of "linked by generic names alone"
(`genericOnly` / `withoutGeneric` in `generic_names.go`):

1. **It never decides.** `kindVotes` returns false for it, whatever the
   admission decision. Two phones announcing `iphone` are two assets; a
   controller reporting a phone by its MAC and a default name another record
   holds is a match on the MAC, not a cross-kind conflict.
2. **It is not a candidate.** `resolveContested` (the floor) and
   `resolveConflict` (the cross-kind path) drop an asset whose ONLY link to the
   observation is generic names. None left: `unresolved`, no proposal, nothing
   written. One left: supporting evidence (the A1 single-owner rule), which
   applies the C1 address-only link refusal as usual. An asset linked by a
   generic name AND something real is still a candidate, and the name stays in
   its evidence for the reviewer. (Through `Resolve`, `resolveConflict` cannot
   see a generic-only candidate — its evidence is only the identifiers that
   voted — so its pruning is belt and braces, pinned directly.)
3. **It is never corroboration.** `resolveSupporting` writes nothing for a
   link of generic names alone — no identifier, no touch, no history, because
   every unrenamed phone's sighting would otherwise leave an entry on whichever
   record first held the name — and returns `unresolved` with no asset. A
   generic name beside an address does not count as the "name in common" that
   lifts the address-only link rule, so `iphone` + a lease is still a lease
   link. `provisionalMatchMode` ignores it, so an address plus `iphone` is an
   address-only match (hearsay yields) and `iphone` alone corroborates nothing.
   This is the C1 wrong merge with a default name standing in for the lease: a
   shared `iphone` must not be the link that fills one phone's MAC into another
   phone's provisional record.

`dedupeIdentifiers` keeps the mark if ANY copy of a name carries it (it is a
judgement about the value), and caps that copy's confidence at 0.3.

## Derived identifiers (#2081 Phase 2)

Some identity evidence spells another identifier. An EUI-64 IPv6 address is
built from the MAC of the interface that holds it; some vendors use the
interface MAC as the serial. `shared/identity/derive` recovers that MAC
(`MACFromEUI64`, `MACFromSerialRegistered` — the latter only for an OUI the
curated table in `standards/oui-vendors.csv` lists), and the INTAKES emit it —
the engine never invents an identifier:

| Intake | Derives | Only when |
|---|---|---|
| inventory host-observation ingest | a MAC from every EUI-64 address (link-local included) | the sighting stated no MAC at all |
| device-interrogation `peerObservation` | a MAC from an EUI-64 address or a 12-hex serial | the peer carries no MAC |
| device-interrogation Devices form (`deviceObservation`) | a MAC from a 12-hex serial | always (the form has no MAC field) |

A derived identifier is marked `Source.Kind = inferred`, `Source.Ref =
derived:eui64:<addr>` or `derived:serial:<serial>`, confidence 0.9. It is the
ONE per-identifier provenance the engine keeps rather than overwriting with the
observation's — a caller can weaken an identifier's provenance, never
strengthen it — so it lands in `asset_identifiers.source_kind/source_ref`, and
the asset page shows it as "Derived from IPv6 address …" / "Derived from serial
…". The stores keep that honest in both directions: a native sighting of a value
held as derived upgrades it to the native provenance; a derived re-sighting of a
value held natively changes neither its source nor its ref.

A derived identifier **votes** (owner decision D3), under three guards:

1. **It never creates.** An observation whose only NEW identifiers are derived
   falls through to the floor as if they were absent, so adding one to a
   sighting can never turn "another sighting of X" into a new asset; and every
   create (`resolveCreate`, the conflict's observation asset,
   `resolveProvisional`) refuses an asset of derived identifiers only
   (`ErrNoUsableIdentifier`).
2. **Native first within a kind.** `groupByKind` puts observed identifiers
   before derived ones, so the walk's "first match decides" lets a derived value
   decide only when no observed value of its kind matched. Otherwise it can only
   corroborate or conflict. `Resolution.DecidedByInferred` and the history key
   `decided_by_inferred` (naming the evidence) say when a derived value decided.
3. **The categorical rules are unchanged.** A singleton disagreement is still a
   proposal, a kept-separate pair is still suppressed, an address in a dynamic
   scope still does not vote — whatever the derived value matched.

And it is **not direct evidence**: `AssessAdmission` ignores it (a MAC worked
out from an address is not "a directly observed interface"), and a match it
decided moves **no lease** — the lease rule's decider must be observed, because
a derivation says which device a record describes, not which device holds the
lease now. It **does** count as naming a device where that is the refusing
direction: the address-only link (C1) attaches nothing to a record linked by a
lease alone when the sighting carries any device binding, derived included, and
1c lets a record with a derived MAC be created on a dynamic segment because it
has something besides the lease to be recognised by.

## Provisional identity

`Config.ProvisionalInventory` (off by default; inventory-service's production
constructor is the only caller that turns it on) adds a third identity status
and two outcomes, for the case #1898 names: a sensor on VLAN A hears a
*reflected* mDNS advert for a printer that lives on VLAN B. The advert is
hearsay — nothing touched the device — so admission refuses to establish
anything from it, and without this the evidence is an observation no inventory
surface can show and nothing can ever join to.

**D2 — creation.** An advertisement becomes a `provisional` asset when ALL of:
the observation is `measured`, admission returned NOT established, it carries a
`hostname`, `fqdn` or `ip_address` whose scope is a REAL segment (never
`tenant`), the store reports that segment eligible
(`ProvisionalScopeChecker`: an active `cidr` segment with no other active cidr
segment overlapping it and no cloud network ref), and no identifier is owned by
anybody. The asset is `pending_approval` with `identity_status = provisional`,
in that segment, and the observation stays `unresolved` so enrichment keeps
working on it. Anything else stays an observation with a reason
(`network_scope_unresolved`,
`overlapping_network_scope_requires_source_resolution`,
`no_device_or_address_binding`, `dynamic_address_without_device_binding`); a
repository that cannot answer the eligibility question is treated as answering
**no**.

**No IP-only provisional record on a dynamic segment (#2081 1c).** When the
placement segment is dynamic and the observation carries no name kind
(`hostname`, `fqdn`, `name`) and no device-binding kind, nothing is created:
the outcome is `unresolved`, reason `dynamic_address_without_device_binding`.
A record whose only identity is a DHCP lease is recognised by nothing but that
lease, so the next device handed the address becomes "another sighting" of it.
Since #2081 D1 a synthetic name (UUID-form, IP-encoded, `none-N`) is an
attribute and not an identifier, so a sighting whose only name was synthetic
reaches the engine as exactly this address-only shape and is refused too. A
name or a device binding alongside the address is still created as before, and
an address alone on a static segment still is.

It carries **no allowance check** — the one create in this package that does
not. A guess must not spend a customer's paid `max_assets`, and a chatty
reflector that could exhaust it would then block the creation of assets that
are real. The check moves to promotion, where the platform asserts the thing
is real; an exhausted allowance there leaves the asset provisional, keeps the
evidence, and records `asset_allowance_exhausted`.

**D3 — what later evidence does.**

| The observation | Against the provisional asset P | Outcome |
|---|---|---|
| Established (direct / authoritative / operator-confirmed) | at least one **name** kind agreed (`hostname`, `fqdn`, `name`) — or anything stronger than an address, a MAC included | `matched`. Ordinary match on P, plus `corroborated_provisional` in history. The observation then promotes P. |
| Established | **only** `ip_address` agreed | **Hearsay yields.** The decision is re-run with P's addresses muted, the observation creates or matches on its own remaining evidence, and each address is then MOVED to that asset (`IdentifierReassigner`), with `identifier_reassigned` history on both. P emptied of every identifier is archived, reason `superseded_by_direct_evidence` — not merged; nothing was combined. |
| Established, but an interface or singleton disagrees | — | Unchanged: a merge proposal. |
| Not established, every owned identifier belongs to ONE asset X | the observation is a **sighting** | `supporting`. Touch X at the observation's own time; attach the new identifiers only when X is itself provisional, because an alias nobody checked must not join an identity somebody did. |
| Not established, every owned identifier belongs to ONE asset X | the observation is **not** a sighting | `supporting`, and nothing is written: no touch, no attach, and a history entry carrying `sighting: false`. |
| Not established (or the floor), every owned identifier belongs to ONE asset X | the only link is `ip_address`, and the observation carries a device-binding identifier **or** every linking address is in a dynamic scope | **Address-only link** (#2081 C1): nothing attached — no device identifier, no name — no touch, a history entry on X with `supporting: true, address_only_link: true, unattached: [...]`, and the resolution is `unresolved` with a ZERO asset. Whatever X's identity status. |
| Not established (or the floor), every owned identifier belongs to ONE asset X | the only link is **generic names** (#2081 B2) | No link at all: nothing attached, no touch, no history; `unresolved` with a ZERO asset. |
| Not established, identifiers owned by two or more assets | — | The contested path, after dropping every asset linked by generic names alone (#2081 B2): none left is `unresolved`, one left is the single-owner rows above. |

**The address-only link rule (#2081 C1).** An address is a lease, not an
identity. When the ONLY thing tying an observation to an asset is `ip_address`
(`Engine.leaseOnlyLink` — any name, MAC or stronger kind in common is
corroboration and the rule does not apply), and either the observation names a
device — `mac_address`, `ssh_host_key_fingerprint`, `serial_number`,
`agent_id`, `sensor_id` or `cloud_resource_id`, which the asset evidently does
not hold, or it would be part of the link — or every linking address is in a
dynamic scope, the sighting is about whatever holds the lease NOW. So
`resolveSupporting` attaches nothing (names included: they came with the same
device), does not advance last-seen, records the link in X's history, and
returns `unresolved` with a zero asset. The zero asset is deliberate: every
intake path writes facts, segment placement, class evidence and relationship
edges onto a resolution's asset, and all of those came from the other device;
`unresolved` with no asset is the outcome every caller already treats as
"evidence retained, nothing to write to", and the observation stays unlinked.
This is the path that once fused an access point's MAC and serial onto a
laptop's advertised name because the two held one DHCP lease at different
times: the MAC was attached to the laptop's provisional record, and the
controller's next report then "corroborated" the record by that MAC. The rule
is status-independent — against an established asset it keeps a departed
device from being kept fresh by the next lease holder's traffic. A name link
(the observation also carries X's name) is still corroboration and fills a
provisional sketch in as before.

Inside a hearsay-yields re-run (the provisional asset's addresses muted),
`resolveSupporting` writes nothing and returns no asset: the outer resolution
owns the observation and falls back to an ordinary match.

An address is a lease and a MAC is a NIC, which is why only `ip_address`
counts as "address alone": a provisional asset matched by MAC was met at the
very interface the advert described, and moving that MAC to a second asset
would duplicate the thing the rule exists to keep whole.

**A sighting is evidence the THING was there**, not evidence about its name:
every passive observation, and an active one that produced an endpoint. An
ACTIVE observation with NO endpoint is a lookup — inventory-service's scoped
DNS enrichment (`sensor:identity-dns:<id>`) answers "what does this name
resolve to" on every rescan cycle without anything going near the device — and
letting that advance last-seen would keep a device unplugged months ago
permanently fresh and out of the stale lens. It still links to the asset, and
its history entry says `sighting: false` so the timeline explains why an entry
that looks like every other supporting one left the clock alone.

## The floor: never an asset with no identifier

`Resolve` will not create an asset that would carry no identifier. Such an asset
can never be recognised again, so every re-observation of the same thing makes
another one — the duplicate problem this package exists to end, one level below
the dedupe keys it replaced.

- **Everything owned by ONE asset** (none may vote — a kind the class drops,
  an address in a dynamic scope): the **single-owner floor rule** (#2081 A1).
  It is another sighting of that asset, not a question, so it is `supporting`
  evidence — whatever `Config.ProvisionalInventory` says — and no proposal is
  opened. A merge proposal with one candidate can only be "kept separate" from
  nothing: the Approvals UI needs two live records to offer a merge. Nothing
  new can be attached (every identifier is already the asset's), and a link
  that is a lease alone follows the address-only link rule above.
  `resolveContested` additionally refuses to open a proposal with fewer than
  two candidates, whatever routes one there.
- **Everything contested** (the identifiers belong to TWO OR MORE other
  assets, none may vote): a merge proposal against the owners, nothing
  created, `Resolution.Asset` is zero. Callers check `AssetRef.Zero()` before
  writing anything about "the" asset.
- **Nothing to identify it by at all**: `ErrNoUsableIdentifier`. The caller logs
  a finding it could not place, rather than an inventory that grows at the
  collector's polling rate.

## The same-device rule (#2081 Phase 4, owner decisions D1 + D4)

A rule — fixed conditions, no score, so on the "a rule or a human approves" side
of ADR-0008 D5 — under which the platform merges two EXISTING records it is sure
are one device, without asking. It exists because nothing else ever merges two
existing assets: the auto-accept threshold only files the NEW sighting into a
candidate, so two partial records of one laptop (one known by its name, one by
its NIC and address) stayed two until a person noticed.

**The rule** is `identity.SameDeviceVerdict(obs, candidates, summaries, link)`
(`samedevice.go`). True only when ALL of these hold:

1. exactly two LIVE candidates (not archived, denied or gone) — after the
   generic-name pruning of the conflict paths;
2. the observation matched at least one identifier to EACH of them — it is the
   sighting that links them;
3. at least one of those matched identifiers is a device-binding kind
   (`deviceBindingKinds`: MAC, SSH host key, serial, agent, sensor, cloud
   resource id — observed — or a MAC the intake DERIVED from an EUI-64
   address or a serial, `Identifier.Inferred()`; no other derived kind:
   `bindsDevice`), and the sighting is **direct and not relayed, or
   authoritative** (`DirectEvidence`, carried as `SameDeviceLink.Direct`);
   - **3a.** a record the sighting reached by ADDRESSES ALONE must itself hold
     nothing but addresses (the IP-only record a device's NIC should absorb —
     the lease rule's `holderLostALease` "nothing but addresses" arm). An
     address is a lease: a record with a name that merely held the address
     before is another device (#2081 C1, on a static segment where the address
     votes and the conflict path is reached);
   - **3b.** a record the sighting did NOT reach through a device binding must
     not carry a device-binding identifier of its own that the sighting did not
     match — a reused lease, or a re-imaged or renamed box. (A sighting that
     matched BOTH of a record's NICs links it; two interfaces are one device.)
4. no singleton disagreement between the two records (same singleton kind,
   same scope, different value);
5. both in the same real segment, or at least one has none (a declared record
   may not; the tenant-wide default scope is not a segment);
6. both `monitoring`, or one `monitoring` and the other `pending_approval` —
   never two pending records: admitting a record and merging two are two
   decisions;
7. no reviewer EVER kept the pair separate (`SameDeviceLink.KeptSeparate`). The
   conflict paths read decision memory once (`Engine.keptSeparate`) and use it
   twice: filtered by evidence kinds it suppresses a re-proposal, unfiltered it
   is this condition — new evidence re-asks a person, it never licenses the rule
   (guard rail 4);
8. neither record's only link is a generic (`Identifier.Generic`) or synthetic
   (`hostnamequality.IsIdentityName` false) name.

The evidence it returns is plain sentences in the order established ("MAC
address … held by the record …, seen directly by …", "the same sighting carried
…, which belongs to …", "same segment", "no one-per-asset identifier
disagrees") — runtime data about the tenant's own records, which becomes the
audit reason and the "Merged automatically" row's explanation.

**The engine only stamps.** `Engine.WithAutoMergeExisting(on)` carries the
tenant's setting for one observation (read on the resolving transaction by both
inventory-service and device-interrogation-service, exactly like the
threshold; a freshly built engine is OFF). On a conflict — `resolveConflict`
or `resolveContested` — `withSameDeviceVerdict` evaluates the rule over the
ranked candidates and their summaries; when it holds, the proposal is opened
EXACTLY as before and stamped `rule_verdict: same_device` + `rule_evidence`,
and `Resolution.MergeRecommended` is set. Nothing is merged inside `Resolve`
(guard rail 2). An auto-accept still happens as before and still carries the
verdict: the matcher filing the observation into a candidate and the rule
merging the two records are different acts. A reused proposal folds the verdict
in (`FoldMergeProposal`: sticky, newest evidence wins). The Postgres payload
writes `rule_verdict`/`rule_evidence` only when set, and matched identifiers
carry `generic: true` when marked and a derived identifier's `source` — the
executor re-evaluates conditions 3 and 8 from the stored row, and the evidence
says "(derived from the IPv6 address …)" when a derived MAC is the link.

**The executor** is inventory-service's `RuleMergeExecutor`
(`internal/services/rule_merge_executor.go`), started by
`services.StartRuleMergeExecutor` from `cmd/main.go`; operator kill switch
`IDENTITY_RULE_MERGE_WORKER_ENABLED` (default on; chart `extraEnv` +
`env.example`). Every 30 s, under a cross-replica advisory lock, for each live
tenant with stamped pending proposals (a bounded batch per tenant and per
tick; a failure on one proposal does not stop the rest):

1. in ONE tenant transaction, claim the proposal (`FOR UPDATE SKIP LOCKED`),
   read the tenant's switch — OFF clears the verdict and leaves an ordinary
   pending question — and re-evaluate the rule on current data: summaries
   re-read, deleted records dropped, a matched identifier counts only if the
   candidate STILL holds it, decision memory re-read. Not holding → the
   verdict is cleared (`rule_verdict_cleared` + reason) and a person decides;
2. choose the survivor: a `monitoring` record over a pending one (the survivor's
   approval status is what the merged record keeps), then a declared record
   (`class_source_kind` / `metadata.name_source_kind` / an identifier
   `source_kind` of `declared`, a `declaration_id`, or an operator-confirmed
   identity — the manual paths resolve with `Source{declared, manual}`, which
   stamps all three; there is no `metadata.source = manual`), then established
   over provisional, then earlier `first_discovered_at`, then more
   identifiers, then the lower id. The sighting's own pending observation
   asset, when the conflict created one, is merged in too;
3. `PreviewMerge`; every conflict that `RequiresResolution` is resolved to the
   declared value — the survivor's when it is declared (or nothing else is),
   otherwise the other record's declared value (guard rail 5, D4); preview
   again so the revision covers the resolutions;
4. `ExecuteMerge` with actor `uuid.Nil`, reason
   `"rule: same_device — " + evidence`, and an unexported rule decision (no
   API caller can claim a merge was the rule's) whose re-check runs INSIDE the
   merge transaction under its locks (`postgres.Bind` binds the identity
   repository to that transaction). The audit and the survivor's `merged_from`
   carry `decided_by: rule` and the evidence, and their `asset_history.source`
   is `identity:same_device_rule`, not `manual` (the name-provenance readers
   treat a `manual` row carrying a name as a declaration; a rule is not one);
   the merge event's `DecidedBy` is
   `rule`;
5. `reconcileMergeProposals` closes the launching proposal in the storage
   contract below. A refused merge whose records merely changed under it is
   retried next tick; any other refusal hands the question back to a person.

## The rule-merge setting and the "Merged automatically" contract

**The setting.** `tenant_admin_settings.config.identity.auto_merge_existing`, a
JSON boolean beside `auto_accept_threshold`. **Absent means TRUE** — owner
decision D1: a rule (fixed conditions, no score) may merge two existing assets it
is sure are one device, and the tenant's lever is a way to say no. That is the
opposite default to the threshold, which is off until a tenant says otherwise,
because the threshold lets a *model* decide (ADR-0008 D5) and the rule does not.

`identitysettings.ReadAutoMergeExisting(ctx, q, tenant)` reads it the way
`ReadAutoAcceptThreshold` reads the threshold: per observation, on the resolving
transaction, never cached. What it returns:

| stored | reads as |
|---|---|
| no row / no `identity` block / no key / JSON `null` | `true` |
| `true` / `false` | that |
| anything else (`"false"`, `0`, `{}`) | `true`, **and logged** |
| the database will not answer | an **error** (carrying `true`) — the observation is retried, not resolved under a setting nobody chose |

The malformed row is the sharp edge: a hand-edited *string* `"false"` still reads
ON. The settings API only ever writes a JSON boolean, so this is reachable only by
editing the jsonb by hand, and the log line is how someone finds out.

**The list.** `MergeProposalService.ListAutoAccepted` (Discovery → Approvals →
"Merged automatically") returns proposals with `auto_accepted = true` **or**
`status = merged AND decided_by = rule`. Each item carries `decided_by`
(`matcher` | `rule`) and, for a rule merge, `rule_evidence` and `merged_into`.

**The storage contract the rule-merge executor writes to.** When it resolves a
proposal as merged, the proposal's `asset_history` row
(`action = merge_proposed`, `changes_json.kind = merge_proposal`) must carry, in
`changes_json`, in the **same** JSONB merge `resolveProposal` already performs:

```
"status":        "merged"
"merged_into":   "<survivor asset id>"
"resolved_at":   "<RFC 3339 UTC>"      -- the MERGE time; the 30-day window runs from it
"decided_by":    "rule"
"rule_evidence": ["<sentence>", ...]   -- plain strings, in the order established
```

and **no** `resolved_by` (a rule has no user). `rule_evidence` is also stamped on
the still-pending proposal beside `rule_verdict: same_device` when the engine
records its verdict; the resolution-time write restates it so the merged row is
self-contained. A row with `decided_by: rule` whose status is not `merged` is not
listed — a verdict awaiting its executor has done nothing yet. The window for a
rule row is measured from `resolved_at` (falling back to when the proposal was
opened if it is missing or unreadable), because a rule can merge a proposal that
has been pending for weeks and that merge must be visible on the day it happens.

## Invariants

1. **An identifier value maps to at most one asset per tenant.** The engine
   looks up the owner of every identifier before it writes any, and reports
   the ones belonging to somebody else in `Resolution.Unattached` rather than
   provoking the unique index. A conflict path therefore creates its pending
   asset with only the *uncontested* identifiers — the contested ones are
   evidence on the proposal, which is where a reviewer reads them.
2. **The engine never approves.** It writes `pending_approval` and nothing
   else. An engine that could approve its own creations would be the
   auto-merge ADR-0002 D5 forbids, wearing a different hat.
3. **Nothing is decided silently.** Every path writes history with the
   observation's provenance, and every identifier the engine declined to use
   comes back in the resolution.

## When identical evidence resolves to a different asset

Under durable admission every sighting is stored first
(`ObservationRepository.StoreObservation`): one `identity_observations` row per
`(tenant, fingerprint)`, one receipt per sighting. The row's `asset_id` is where
everything retained with it is materialized — management context (encrypted
credentials), host inventories, cloud and peer context, payloads — by workers
that read `o.asset_id` when they run.

Identical evidence can resolve to a different asset later. The case that
forced the rule: a segment's DHCP posture changes (#2081 Phase 1a), and "VIP
is-at node M" stops being a floating-address sighting of the VIP's holder and
becomes a match on the node. `FinishObservation` used to fail the whole ingest
("observation missing or linked to another asset"). It now settles the row
first (`postgres/observation_split.go`) and **returns the row id the sighting
ended up on**, which the engine reports as `Resolution.ObservationID`:

- a **new sighting** (a receipt inserted in this transaction) of a row holding
  other receipts is **split** onto a row of its own, linked to the new asset;
  the earlier receipts and everything retained with them stay with the asset
  they were resolved to, and the new row takes over the fingerprint;
- a **re-read** of stored evidence (a retried delivery, an enrichment pass
  re-resolving the row), or a row that is only this sighting, **moves as a
  whole**;
- a row an **operator confirmed** is never moved by the engine: it splits when
  it has other receipts, and otherwise keeps its link.

Each move writes `observation_split` / `observation_relinked` (or
`observation_kept_operator_link`) history on both assets. `LinkObservation`'s
own "linked to another asset" guard is unchanged: it protects the operator and
corroboration paths, which link a specific row on purpose.

## Strict by default, lenient on purpose

`Resolve` returns `ErrInvalidObservation` for an identifier that does not
normalise. An intake path that must not fail a whole batch for one bad MAC
calls `Observation.Sanitize()` first, which returns the cleaned observation
plus the rejects and their reasons — so leniency is a visible decision at the
call site rather than a default nobody can see.

## Dependent identity

Endpoints, applications and services have no identity of their own and are
never matched on their own. `Engine.ResolveDependent` derives their keys —
endpoint `(asset, address|fqdn, port, transport)`, application
`(host, product, instance)`, service `(tenant, name)` — so phase 1 has one
spelling of each instead of inventing one per call site. Build the `key`
argument with `EndpointKey`, `ApplicationKey` or `ServiceKey`. It derives; it
does not query, because the tables it keys into are phase-1 shapes.

## The observation query target

`Observation` carries the fields the `observation` target of QUERY_LANGUAGE
§4.1 exposes to approval rules, so the same predicate language that filters
assets filters an in-flight discovery (§8):

| Predicate | Field |
|---|---|
| `source:sensor` | `Source.Producer()` |
| `network.ownership:internal` | `Network.Ownership` |
| `network.type:corporate` | `Network.Type` |
| `confidence >= 0.8` | `Confidence` |
| `network.segment_id=<uuid>` / `exists(network.segment_id)` | `Network.SegmentID` |

`require_network_space_match` has no equivalent and is dropped, per §8.

## Testing against it

`shared/identity/memory` is an in-memory `Repository` that enforces the
uniqueness invariant and returns the same errors the SQL one will. Its
`Corrupt` method is the only way to produce a two-owner identifier — which is
what makes `FindByIdentifier`'s slice return a shape a test can actually
reach, rather than a check that cannot fail.

`identitytest.RunRepositoryContract(t, newRepo)` is the behavioural contract.
The Postgres implementation in workstream 1.2 must call it too; two
implementations of one storage contract tested by two different suites is how
they drift. It requires the implementation to satisfy
`identitytest.LastSeenReader` and `identitytest.HistoryReader` as well — two
read-backs the engine itself never needs, but without which the contract
cannot check that `Touch` is monotonic or that history comes back in order.
Skipping those assertions when the read-back is missing would make them checks
that cannot fail, so their absence is a hard failure instead.

## Notes for the workstreams that consume this

- **0.2 (schema):** `asset_history.action` needs `merge_proposed`. DATA_MODEL
  §2's action list predates this engine and does not carry it.
- **1.2 (wiring):** `FromLegacyAsset` is a documented starting point, not a
  finished builder. The legacy shape has no segment, so the hostname and IP it
  produces carry the **tenant-wide default scope** — they match each other, but
  cannot tell one segment's `printer-2` from another's. A real builder resolves
  `Repository.ScopeForAddress` and sets the result as their scope.
- **1.3 (approvals):** `MergeProposal` is the row the queue renders. Executing
  an accepted merge — moving identifiers, endpoints, findings and edges —
  belongs there, not here.
