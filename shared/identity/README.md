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
| `matched` | Exactly one existing asset resolved from the identifiers | Attached the new identifiers, upserted the endpoints, advanced last-seen, history `updated`. `DecidedBy` names the highest-precedence kind that matched. |
| `created` | Nothing matched | Created a `pending_approval` asset with the class hint, or `unknown_host` / `external` per the network ownership. History `created`. |
| `provisional` | Evidence that cannot establish anything, placed on a configured and unambiguous tenant segment, owned by nobody — and `Config.ProvisionalInventory` is on | Created a `pending_approval` asset with `identity_status = provisional`, WITHOUT an allowance check. See **Provisional identity** below. |
| `supporting` | Evidence that cannot establish anything, every owned identifier belonging to ONE asset — and `Config.ProvisionalInventory` is on | Linked the observation to that asset. Advanced its last-seen — and, if the asset is itself provisional, attached the new identifiers — but ONLY when the observation is a sighting. Not a match: nothing was allowed to decide. |
| `conflict` | One kind matched several assets, **or** two kinds matched different assets, **or** every identifier is owned by somebody else and none may vote | Opened a merge proposal listing every candidate with the identifiers that matched it. The observation becomes its own pending asset ONLY if it carries an identifier nobody owns (history `created` then `merge_proposed`); when everything is contested nothing is created and `Resolution.Asset` is ZERO — see the floor. **Never auto-merged.** |

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
losing candidates is the approvals path's job (workstream 1.3).

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
spoofed host, and still gets the proposal. Virtual router MACs (VRRP, HSRP,
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
`no_device_or_address_binding`); a repository that cannot answer the
eligibility question is treated as answering **no**.

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
| Not established, identifiers owned by two or more assets | — | Unchanged: the contested path. |

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

- **Everything contested** (all the identifiers belong to other assets, none may
  vote): a merge proposal against the owners, nothing created,
  `Resolution.Asset` is zero. Callers check `AssetRef.Zero()` before writing
  anything about "the" asset.
- **Nothing to identify it by at all**: `ErrNoUsableIdentifier`. The caller logs
  a finding it could not place, rather than an inventory that grows at the
  collector's polling rate.

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
