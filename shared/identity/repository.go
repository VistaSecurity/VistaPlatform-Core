package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
)

// AssetRef names one asset, tenant included.
//
// The tenant travels with the id deliberately: [Repository.AttachIdentifiers],
// [Repository.UpsertEndpoints] and [Repository.Touch] take a ref and no
// separate tenant argument, so there is no call shape in this interface that
// can write to an asset without saying whose it is. The SQL implementation
// sets `app.tenant_id` from it.
type AssetRef struct {
	TenantID string `json:"tenant_id"`
	ID       string `json:"id"`
}

// Zero reports whether the ref names nothing.
func (r AssetRef) Zero() bool { return r.ID == "" }

// AssetSummary is what the repository returns for a candidate: enough to rank
// it and to show a reviewer what they are being asked about, and no more. It
// is not the asset — a seam gets what it needs to score a candidate, not the
// tenant's inventory (the same posture as seams.AssetSummary, which it is
// converted to at the matcher call).
type AssetSummary struct {
	Ref         AssetRef     `json:"ref"`
	ClassKey    string       `json:"class_key"`
	DisplayName string       `json:"display_name"`
	Identifiers []Identifier `json:"identifiers,omitempty"`
	Status      string       `json:"status"`

	// NetworkSegment is the segment the asset belongs to, empty when it is in
	// none. It is what a scoped identifier (`hostname`, `ip_address`)
	// identifies WITHIN, so two records agreeing on a hostname while
	// disagreeing about the segment are probably two things — every segment
	// has a `db01`.
	NetworkSegment string `json:"network_segment_id,omitempty"`

	// LastSeenAt is the asset's last sighting. Zero means unknown.
	LastSeenAt time.Time `json:"last_seen_at,omitzero"`

	// Attributes are the FEW comparable class attributes a matcher may read —
	// `vendor` and `model`. Not the asset's whole attribute map: the summary is
	// what a candidate needs to be ranked and reviewed, not the asset.
	Attributes map[string]any `json:"attributes,omitempty"`
}

// SummaryAttributeKeys are the class attributes [Repository.LoadSummaries]
// populates [AssetSummary.Attributes] from.
//
// Vendor and model, and no more. They are stable properties of the physical
// thing, so a disagreement is real evidence of two things — and unlike an
// address or a name they do not change when somebody re-cables a rack. Widening
// this list widens what a matcher can see, which is a decision to take
// deliberately rather than by adding a key.
var SummaryAttributeKeys = []string{"vendor", "model"}

// Asset status values. The engine only ever writes [StatusPendingApproval];
// promotion to monitoring is the approvals path's job (workstream 1.3), and an
// engine that could approve its own creations would be the auto-merge ADR-0002
// D5 forbids, wearing a different hat.
const (
	StatusPendingApproval = "pending_approval"
	StatusMonitoring      = "monitoring"
	StatusDenied          = "denied"
	StatusArchived        = "archived"
)

// NewAsset is the row [Repository.CreateAsset] writes.
type NewAsset struct {
	ClassKey string `json:"class_key"`
	// ClassSourceKind and ClassConfidence are the provenance of the CLASS, not
	// of the asset: DATA_MODEL §2 stores them per asset because ADR-0002 D4
	// reconciles class on its own precedence table. A fallback class
	// (`unknown_host`, `external`) carries confidence 0 — nothing classified
	// it, and 0 here means NOT ASSESSED, exactly as it does in risk scoring.
	ClassSourceKind ClassSourceKind `json:"class_source_kind"`
	ClassConfidence float64         `json:"class_confidence"`

	// ClassSourceRef is WHO or WHAT decided the class, when that is not the
	// observation's own producer: the `classification_rules` row id for a
	// rule-derived class, the user id for a declared one. Empty falls back to
	// Source.Ref, which is what every pre-2.10b caller relied on.
	ClassSourceRef string `json:"class_source_ref,omitempty"`

	DisplayName    string `json:"display_name"`
	Hostname       string `json:"hostname,omitempty"`
	PrimaryAddress string `json:"primary_address,omitempty"`

	Status          string  `json:"status"`
	Ownership       string  `json:"ownership,omitempty"`
	NetworkSegment  string  `json:"network_segment_id,omitempty"`
	DiscoveryMethod string  `json:"discovery_method,omitempty"`
	Confidence      float64 `json:"confidence"`
	Source          Source  `json:"source"`

	Identifiers []Identifier          `json:"identifiers,omitempty"`
	Endpoints   []EndpointObservation `json:"endpoints,omitempty"`

	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

// HistoryAction is an `asset_history.action` value (DATA_MODEL §2).
type HistoryAction string

const (
	// ActionCreated — a new asset row.
	ActionCreated HistoryAction = "created"
	// ActionUpdated — an observation landed on an existing asset.
	ActionUpdated HistoryAction = "updated"
	// ActionMergedFrom — this asset absorbed an observation that also matched
	// other candidates, because a matcher scored the merge above the tenant's
	// auto-accept threshold.
	ActionMergedFrom HistoryAction = "merged_from"
	// ActionMergedInto — the other half of a merge, written by the approvals
	// path when a proposal is accepted (workstream 1.3). The engine never
	// writes it: it does not execute merges.
	ActionMergedInto HistoryAction = "merged_into"
	// ActionMergeProposed — a conflict opened a merge proposal.
	//
	// NOTE for workstream 0.2: DATA_MODEL §2's action list predates this
	// engine and does not include this value. Any CHECK constraint on
	// `asset_history.action` must carry it.
	ActionMergeProposed HistoryAction = "merge_proposed"
	// ActionApproved, ActionDenied, ActionClassified, ActionEndpointAdded,
	// ActionEdgeAdded and ActionArchived are the rest of DATA_MODEL §2's list,
	// written by the paths that own those transitions.
	ActionApproved      HistoryAction = "approved"
	ActionDenied        HistoryAction = "denied"
	ActionClassified    HistoryAction = "classified"
	ActionEndpointAdded HistoryAction = "endpoint_added"
	ActionEdgeAdded     HistoryAction = "edge_added"
	ActionArchived      HistoryAction = "archived"

	// The rest of the edge lifecycle (workstream 2.8, ADR-0003). `edge_added`
	// alone could not tell the three apart, and "who decided this relationship
	// and which way did they decide" is the question the timeline exists to
	// answer six months later.
	//
	// They are written on the edge's FROM asset — the edge is stored once in
	// the canonical direction (ADR-0003 D1), so the from asset is the one end
	// the change is unambiguously attributable to.
	//
	// NOTE: adding a value here needs the matching edit to the `actions` array
	// in schema.sql's `asset_history_action_check` convergence block, and to
	// [AllHistoryActions] below. One array, in one block, in both schema
	// copies — a second copy of the list drifts, and it drifts in the direction
	// that fails silently, because the history writer LOGS a rejected insert
	// rather than returning it.
	//
	// ActionEdgeRemoved — a DECLARED edge deleted by a user. A measured edge is
	// never removed this way; it goes stale and is archived.
	ActionEdgeRemoved HistoryAction = "edge_removed"
	// ActionEdgeAccepted — a relationship proposal accepted in Approvals.
	ActionEdgeAccepted HistoryAction = "edge_accepted"
	// ActionEdgeRejected — a relationship proposal rejected. The row survives
	// rejection, so the same inference is not re-proposed with nothing
	// recording that it was already answered.
	ActionEdgeRejected HistoryAction = "edge_rejected"
	// The class-proposal lifecycle (workstream 2.10b, ADR-0004 D6 + ADR-0008
	// D3). A rule-derived class reaches an EXISTING asset as a proposal rather
	// than as a write, because ADR-0008 D3 says a machine proposal goes through
	// Approvals and because overwriting a class somebody already looked at is
	// the auto-decide the whole design refuses.
	//
	// Like the merge proposals above, these are rows in this table rather than
	// a `class_proposals` table of their own. The proposal, its outcome and the
	// class change it caused are three entries in one timeline, which is what a
	// reviewer six months later actually reads — and a second proposals table
	// is a second place a queue can be forgotten in.
	//
	// ActionClassProposed — the rules argued a class this asset does not have.
	// changes_json carries `proposed_class_key`, the rule ids behind it, the
	// confidence, and any conflicting classes.
	ActionClassProposed HistoryAction = "class_proposed"
	// ActionClassAccepted — a reviewer took the proposed class. The asset's
	// class, class_source_kind and class_source_ref move with it.
	ActionClassAccepted HistoryAction = "class_accepted"
	// ActionClassRejected — a reviewer said no. The row SURVIVES rejection and
	// is what stops the same class being proposed again on the next
	// observation of unchanged evidence; without it a printer that advertises
	// `_ipp._tcp` every coalescing window would refill the queue with a
	// question already answered.
	ActionClassRejected HistoryAction = "class_rejected"

	// ActionSBOMImported — a bill of materials was ingested against this asset
	// (workstream 2.6b). It is an asset-level event rather than a per-install
	// one: one upload writes hundreds of `software_installs` rows, and a
	// history entry per row would bury every other thing the timeline records.
	// The counts and the parser's warnings ride in changes_json, so the entry
	// answers "what did that upload actually do" without a second lookup.
	ActionSBOMImported HistoryAction = "sbom_imported"
)

// AllHistoryActions returns every action this package writes, in declaration
// order.
//
// It exists so the `asset_history_action_check` CHECK constraint can be tested
// against the Go vocabulary rather than eyeballed. That matters more here than
// it would elsewhere: the history writer LOGS a failed insert rather than
// returning it — deliberately, because history is evidence of a change that
// already happened and failing the caller afterwards would report a failure
// that did not occur — so an action missing from the constraint is REJECTED IN
// SILENCE. The row is simply never there, and the first person to notice is
// whoever reads the timeline six months later.
func AllHistoryActions() []HistoryAction {
	return []HistoryAction{
		ActionCreated, ActionUpdated, ActionMergedFrom, ActionMergedInto,
		ActionMergeProposed, ActionApproved, ActionDenied, ActionClassified,
		ActionEndpointAdded, ActionEdgeAdded, ActionEdgeRemoved, ActionEdgeAccepted,
		ActionEdgeRejected, ActionArchived, ActionSBOMImported,
		ActionClassProposed, ActionClassAccepted, ActionClassRejected,
	}
}

// HistoryEntry is one row of `asset_history`, which this engine is the first
// writer of. The survey found the table had no writer at all, in Go or in a
// trigger: the change history an inventory needs was a table with only a read
// path.
type HistoryEntry struct {
	TenantID string        `json:"tenant_id"`
	AssetID  string        `json:"asset_id"`
	Action   HistoryAction `json:"action"`
	Source   Source        `json:"source"`
	// ActorUserID is set when a person caused the change; empty for a
	// collector. Empty is not "system": it is "no person was involved".
	ActorUserID string `json:"actor_user_id,omitempty"`
	// Changes is the `changes_json` payload. The engine writes the identifiers
	// it attached, the endpoints it upserted, the kind that decided a match,
	// and any identifier it declined to attach.
	Changes map[string]any `json:"changes,omitempty"`
	At      time.Time      `json:"at"`
}

// MergeCandidate is one existing asset an observation could be, with the
// evidence for it.
type MergeCandidate struct {
	Ref AssetRef `json:"ref"`
	// MatchedIdentifiers are the observation's identifiers that resolved to
	// this asset. This is the evidence a reviewer reads; a proposal listing
	// candidates with no reason can only be rubber-stamped.
	MatchedIdentifiers []Identifier `json:"matched_identifiers"`
	// Score is the matcher seam's score, 0..1, and 0 when no matcher made a
	// proposal. Zero means "unscored", not "certainly wrong" — the null
	// matcher scores nothing and the rule-based decision stands on its own.
	Score float64 `json:"score"`
	// Reason is the matcher's human-readable phrase, empty when unscored.
	Reason string `json:"reason,omitempty"`

	// Explanation is the score's working: the signals that moved it, strongest
	// first, each with its signed contribution. Empty when unscored, or when
	// the configured matcher cannot explain itself.
	//
	// It is on the CANDIDATE rather than the proposal because it is about this
	// pairing. A proposal with three candidates is three comparisons, and one
	// explanation for all of them would explain none of them.
	Explanation []seams.MatchFactor `json:"explanation,omitempty"`

	// modelID and sourceRef are the matcher's provenance (ADR-0008 D4.1),
	// carried from seams.Proposal onto the merge proposal so a reviewer — or
	// an audit six months later — can see WHICH implementation proposed a
	// merge that was auto-accepted. Unexported because only the engine fills
	// them and only the proposal reads them; a caller constructing a candidate
	// has no provenance to claim.
	modelID   string
	sourceRef string
}

// ModelID and SourceRef report the matcher's provenance for this candidate,
// empty when nothing scored it.
//
// Read-only accessors rather than exported fields: only the engine may set
// them, because a caller CONSTRUCTING a candidate has no provenance to claim —
// and a struct literal with a ModelID field invites exactly that. Callers that
// need to record which model proposed a merge (the audit event on an
// auto-accept) read them here.
func (c MergeCandidate) ModelID() string   { return c.modelID }
func (c MergeCandidate) SourceRef() string { return c.sourceRef }

// MergeProposal is the row the Approvals queue shows a reviewer (ADR-0002 D5,
// ADR-0006 D6).
type MergeProposal struct {
	// ObservationAssetID is the new pending asset the observation was created
	// as. Empty when AutoAccepted is true, because in that case the
	// observation went into AcceptedAssetID and no third asset was made.
	ObservationAssetID string `json:"observation_asset_id,omitempty"`

	Candidates []MergeCandidate `json:"candidates"`
	Source     Source           `json:"source"`
	Reason     string           `json:"reason"`
	ProposedAt time.Time        `json:"proposed_at"`

	// ModelID and SourceRef name the matcher that RANKED this proposal, whether
	// or not it was auto-accepted (ADR-0008 D4.1). Empty when nothing scored it.
	//
	// Separate from AcceptedModelID below, which records the matcher behind an
	// auto-ACCEPT specifically. They are usually the same value and are
	// different facts: "a model ordered these candidates for you" and "a model
	// decided this" are not the same claim, and a proposal a human resolves
	// should still say which model put the winner at the top.
	ModelID   string `json:"model_id,omitempty"`
	SourceRef string `json:"source_ref,omitempty"`

	// AutoAccepted records that a matcher scored the top candidate at or above
	// the tenant's threshold and the engine wrote the observation into it. The
	// proposal is still opened — the evidence and the executor's work item are
	// the same row — and the merge of the remaining candidates is still the
	// approvals path's job. See [Engine.Resolve].
	AutoAccepted      bool    `json:"auto_accepted,omitempty"`
	AcceptedAssetID   string  `json:"accepted_asset_id,omitempty"`
	AcceptedScore     float64 `json:"accepted_score,omitempty"`
	AcceptedModelID   string  `json:"accepted_model_id,omitempty"`
	AcceptedSourceRef string  `json:"accepted_source_ref,omitempty"`

	// PreserveObservationStatus says the observation asset ALREADY EXISTED and
	// was not created by whatever opened this proposal, so its status is not
	// this proposal's to change.
	//
	// The default — false — is the engine's case: the observation asset is the
	// pending row the conflict just created, and pinning it `pending_approval`
	// is what keeps a contested thing out of inventory until a human settles
	// it. The exception is an edit to an asset that is already in service: a
	// person typing a serial that turns out to belong to another asset has
	// raised a question, not demoted a monitored host, and taking that host out
	// of service on the strength of one unverified keystroke would be a far
	// larger act than the one they performed.
	PreserveObservationStatus bool `json:"preserve_observation_status,omitempty"`
}

// ProposalRef names one merge proposal.
type ProposalRef struct {
	TenantID string `json:"tenant_id"`
	ID       string `json:"id"`

	// Reused is true when [Repository.OpenMergeProposal] found a PENDING
	// proposal asking the same question ([MergeProposalFingerprint]) and
	// returned it instead of opening another.
	//
	// The engine reads it to decide whether to write its `merge_proposed`
	// pointer entry: a question already in the queue does not get a fresh
	// history row on every observation that re-asks it. Before this flag the
	// proposal itself was deduplicated but the note about it was not, so a
	// contested host on a one-minute coalescing window wrote 1,440 identical
	// history rows a day against the first candidate.
	Reused bool `json:"reused,omitempty"`
}

// Announcement is the evidence behind a floating address (see
// [Resolution.FloatingAddress]): one asset's NIC announced an address that
// belongs to another asset.
type Announcement struct {
	// MACs are the announcer's hardware addresses as observed — the
	// identifiers the engine deliberately did NOT write onto the holder. One
	// in practice; a slice because an observation may carry several.
	MACs []string `json:"macs"`
	// Addresses are the floating addresses announced, canonical form.
	Addresses []string `json:"addresses"`
	// Gratuitous is true when the frame was a gratuitous ARP — the announcer
	// claiming the address as its own, rather than answering a request for
	// it. Corroborating, not required: a plain ARP reply for the VIP from the
	// node's MAC is the same fact.
	Gratuitous bool `json:"gratuitous,omitempty"`

	Source Source    `json:"source"`
	At     time.Time `json:"at"`
}

// AnnouncementRecord is what a store holds for one announcer/holder pair after
// [Repository.RecordAnnouncement]: the pair, the latest evidence and how many
// times it was observed. Read back by tests through
// identitytest.AnnouncementReader; nothing in production reads it through this
// package.
type AnnouncementRecord struct {
	Announcer AssetRef     `json:"announcer"`
	Holder    AssetRef     `json:"holder"`
	Latest    Announcement `json:"latest"`
	Count     int          `json:"count"`
}

// PriorDecision is a human's earlier answer about a set of assets: a merge
// proposal naming them that a reviewer resolved `kept_separate`.
type PriorDecision struct {
	ProposalID string `json:"proposal_id"`
	// ObservationAssetID is the pending asset that proposal was opened FOR,
	// empty when it was a floor proposal that created nothing.
	ObservationAssetID string `json:"observation_asset_id,omitempty"`
	// Candidates are the assets the proposal named, in the order it named
	// them.
	Candidates []string `json:"candidates"`
	// MatchedKinds are the identifier kinds that were the proposal's
	// evidence — the kinds whose values matched a candidate. The engine treats
	// a later conflict carrying a kind NOT in this set as a NEW question.
	MatchedKinds []Kind `json:"matched_kinds"`
	// DecidedAt and DecidedBy are when and by whom, as the proposal recorded
	// them. DecidedBy is empty when the proposal did not record an actor.
	DecidedAt time.Time `json:"decided_at,omitzero"`
	DecidedBy string    `json:"decided_by,omitempty"`
}

// Covers reports whether the decision was about every one of these assets —
// each is either the proposal's observation asset or one of its candidates.
// Order is irrelevant: the same two assets found the other way round are the
// same pair.
func (d PriorDecision) Covers(assetIDs []string) bool {
	if len(assetIDs) == 0 {
		return false
	}
	named := make(map[string]bool, len(d.Candidates)+1)
	for _, c := range d.Candidates {
		named[c] = true
	}
	if d.ObservationAssetID != "" {
		named[d.ObservationAssetID] = true
	}
	for _, id := range assetIDs {
		if !named[id] {
			return false
		}
	}
	return true
}

// SameEvidence reports whether every kind in kinds was already part of the
// decision's evidence. A kind the reviewer never saw — an SSH host key where
// they weighed a MAC against an address — is new evidence, and a decision made
// without it does not answer the question it raises.
func (d PriorDecision) SameEvidence(kinds []Kind) bool {
	seen := make(map[Kind]bool, len(d.MatchedKinds))
	for _, k := range d.MatchedKinds {
		seen[k] = true
	}
	for _, k := range kinds {
		if !seen[k] {
			return false
		}
	}
	return true
}

// Repository is the storage the engine needs, and nothing else.
//
// It is small on purpose: phase 1 (workstream 1.2) had to supply only a
// Postgres implementation of eight methods, and
// identitytest.RunRepositoryContract holds it to the same behaviour the
// in-memory one has. Everything with an opinion — precedence, scope rules,
// conflict detection, reconciliation — is in the engine, where it is testable
// without a database.
//
// Two methods joined the eight with the floating-address rule
// ([Resolution.FloatingAddress]) and decision memory
// ([Resolution.Suppressed]): [Repository.RecordAnnouncement] and
// [Repository.LastKeptSeparate]. They are on the interface rather than
// behind an optional type assertion because an optional seam that silently
// no-ops when an implementation forgets it is a check that cannot fail —
// exactly the shape that let seven services' revocation check compile, pass
// its tests and never run.
type Repository interface {
	// FindByIdentifier returns the assets carrying this identifier value.
	//
	// DATA_MODEL §2 makes that at most one, by unique index. It returns a
	// SLICE anyway so a store that has lost the invariant is DETECTABLE: an
	// interface that could only return one would force the implementation to
	// pick, and picking is how a corrupted store looks healthy. The engine
	// treats len > 1 as a conflict.
	//
	// An unknown identifier returns an empty slice and no error. Not found is
	// a normal answer, not a failure.
	FindByIdentifier(ctx context.Context, tenantID string, kind Kind, value, scope string) ([]AssetRef, error)

	// LoadSummaries returns the summaries for these asset ids, in the order
	// asked, skipping ids that do not exist in the tenant. A missing id is not
	// an error: the caller is loading candidates, and a candidate deleted
	// between the lookup and the load is a smaller set, not a failure.
	LoadSummaries(ctx context.Context, tenantID string, ids []string) ([]AssetSummary, error)

	// CreateAsset writes a new asset with its identifiers and endpoints, and
	// returns its ref. It returns ErrIdentifierConflict if any identifier
	// already belongs to another asset in the tenant.
	CreateAsset(ctx context.Context, tenantID string, a NewAsset) (AssetRef, error)

	// AttachIdentifiers records identifiers against an existing asset,
	// idempotently: an identifier the asset already carries has its last-seen
	// and confidence refreshed rather than being duplicated.
	//
	// It returns ErrIdentifierConflict if any identifier belongs to a
	// different asset. The engine never provokes that — it resolves ownership
	// first and reports foreign identifiers in Resolution.Unattached — so a
	// caller that sees it has gone around the engine.
	AttachIdentifiers(ctx context.Context, asset AssetRef, ids []Identifier) error

	// UpsertEndpoints writes endpoints under the asset, keyed by
	// EndpointObservation.Key. Endpoints are dependent identity: they are
	// never matched on their own.
	UpsertEndpoints(ctx context.Context, asset AssetRef, eps []EndpointObservation) error

	// Touch advances the asset's last-seen. It never moves it backwards: a
	// late-arriving old observation is still evidence the asset existed then,
	// not evidence it has not been seen since.
	Touch(ctx context.Context, asset AssetRef, seenAt time.Time) error

	// RecordHistory appends one `asset_history` row.
	RecordHistory(ctx context.Context, e HistoryEntry) error

	// OpenMergeProposal records a merge proposal for the Approvals queue and
	// returns its ref.
	//
	// It is idempotent over [MergeProposalFingerprint] while the proposal is
	// PENDING: re-asking a question a human already has in the queue returns
	// the existing ref with [ProposalRef.Reused] set. A RESOLVED proposal does
	// not suppress a new one — the engine consults [Repository.LastKeptSeparate]
	// for that.
	OpenMergeProposal(ctx context.Context, tenantID string, p MergeProposal) (ProposalRef, error)

	// LastKeptSeparate returns the most recent merge proposal a reviewer
	// resolved `kept_separate` that named EVERY one of these assets — as its
	// observation asset or among its candidates — and false when there is
	// none. Order of assetIDs is irrelevant. It is the engine's decision
	// memory: without it a human's "no" is write-only, and the same proposal
	// is re-raised on the next observation of unchanged evidence.
	//
	// A pending or merged proposal is never returned: pending is handled by
	// OpenMergeProposal's idempotency, and after a merge one of the assets is
	// gone.
	LastKeptSeparate(ctx context.Context, tenantID string, assetIDs []string) (PriorDecision, bool, error)

	// RecordAnnouncement records that announcer's NIC announced an address
	// belonging to holder — the floating-address fact — as a relationship
	// between the two assets, idempotently: a re-observation bumps the edge's
	// last-seen and count rather than adding a row. The engine calls it
	// INSTEAD of attaching the announcer's MAC to the holder; the knowledge
	// has to land somewhere, and an identifier it must not be.
	//
	// The SQL implementation writes `asset_relationships` type `hosted_on`,
	// holder → announcer (the VIP's asset rests on the node that currently
	// announces it; reverse label "hosts"). It returns an error for
	// announcer == holder: that is not a floating address, it is the same
	// asset, and the engine never asks.
	RecordAnnouncement(ctx context.Context, announcer, holder AssetRef, a Announcement) error

	// ScopeForAddress answers the one question every observation builder has
	// to ask before it can produce a hostname or ip_address identifier: WHERE
	// was I standing?
	//
	// It returns the id of the tenant's network segment the address falls
	// inside, and [ScopeTenantDefault] when it falls inside none — including
	// when the tenant has configured no segments at all, which is every fresh
	// tenant. It never returns an empty scope: "no segment" is an answer about
	// the tenant's topology, not an absence of one, and treating it as an
	// absence is what made one host observed three times into three assets.
	//
	// `dynamic` reports that the segment hands addresses out dynamically, in
	// which case an ip_address must not decide a match (ADR-0002 D3) — today's
	// DHCP lease is tomorrow's other host. The tenant-wide default scope is
	// never dynamic: it is not a DHCP range, it is "everywhere else".
	//
	// It lives on the Repository, rather than in each service that builds
	// observations, so inventory-service and device-interrogation-service
	// cannot disagree about which segment an address is in — one more spelling
	// of a lookup is one more dedupe key, which is the failure this package
	// exists to end.
	//
	// `cloudNetworkRef` is the cloud network (VPC / VNet / GCP network) the
	// observation was made INSIDE, as the provider's own resource id, and is
	// empty for every LAN observation — a sensor on the wire, an agent on a
	// desk, an operator typing an address into a form.
	//
	// It exists because a CIDR is not unique in a cloud account. Two VPCs from
	// one Terraform module both get 10.0.0.0/16 and their subnets both get
	// 10.0.1.0/24, so "which segment is 10.0.1.20 in" has TWO answers and the
	// old signature could not express the question. Collapsing them into one
	// segment is what made two instances at the same private address resolve
	// to one scope — and then, through `ip_address`, to one ASSET.
	//
	// The rules:
	//
	//   - with a ref: only segments belonging to THAT network, or to none, are
	//     considered. Most specific prefix wins, and a network-matched segment
	//     beats an unscoped one of the same prefix length;
	//   - without a ref, and the matching segments agree (all unscoped, or all
	//     in one network): that segment. This is every LAN tenant, unchanged,
	//     and it is also what lets an agent INSIDE an instance — which knows
	//     its address and not its VPC — reach the same segment the cloud
	//     collector used;
	//   - without a ref, and the matching segments name two DIFFERENT cloud
	//     networks: [ScopeTenantDefault]. The caller did not say where it was
	//     standing and the topology has two answers; picking one would be a
	//     coin flip that decides an asset's identity.
	ScopeForAddress(ctx context.Context, tenantID string, addr netip.Addr, cloudNetworkRef string) (scope string, dynamic bool, err error)
}

// MergeProposalFingerprint is the idempotency key of a merge proposal: what
// makes two proposals THE SAME QUESTION rather than two questions.
//
// # Why a proposal needs one at all
//
// The floor — every identifier already belongs to some other asset and none of
// them may decide for this class — opens a proposal and creates nothing.
// Nothing about that changes between observations, so a collector on a
// fifteen-minute schedule asked the identical question ninety-six times a day
// and the Approvals queue filled with rows a reviewer could not clear by
// deciding any one of them.
//
// # What "the same question" means
//
// Three things, in a stable spelling:
//
//   - the observation asset, when there is one (a conflict that DID create a
//     pending asset is about that asset, and the next observation matches it
//     rather than reaching here again);
//   - the candidate set, SORTED — the same two candidates found in the other
//     order are the same two candidates;
//   - the identifiers that matched them, sorted and de-duplicated. Without
//     these, two DIFFERENT things contested against the same candidate would
//     collapse into one proposal, and the second would be dropped rather than
//     reviewed.
//
// Scores and reasons are deliberately NOT in it: a matcher that scores the same
// candidates 0.71 today and 0.72 tomorrow has not asked a new question.
//
// The value is hex SHA-256 — fixed-width and index-friendly — and is stored on
// the proposal payload rather than derived in SQL, because sorting a JSON array
// inside an index expression would need an immutable helper function for no
// gain.
func MergeProposalFingerprint(p MergeProposal) string {
	candidates := make([]string, 0, len(p.Candidates))
	idKeys := make([]string, 0, len(p.Candidates))
	seenID := map[string]bool{}
	for _, c := range p.Candidates {
		candidates = append(candidates, c.Ref.ID)
		for _, id := range c.MatchedIdentifiers {
			k := id.Key()
			if seenID[k] {
				continue
			}
			seenID[k] = true
			idKeys = append(idKeys, k)
		}
	}
	sort.Strings(candidates)
	sort.Strings(idKeys)

	h := sha256.New()
	// Length-prefixed sections, so a value containing the separator cannot be
	// confused with a section boundary.
	//
	// hash.Hash.Write is documented never to return an error, which is why the
	// writes are unchecked — spelled as Write rather than Fprintf so that is
	// visible at the call site instead of being an ignored return value.
	write := func(label string, parts []string) {
		h.Write([]byte(label + ":" + strconv.Itoa(len(parts)) + ":"))
		for _, part := range parts {
			h.Write([]byte(strconv.Itoa(len(part)) + ":" + part))
		}
	}
	write("obs", []string{p.ObservationAssetID})
	write("cand", candidates)
	write("ids", idKeys)
	return hex.EncodeToString(h.Sum(nil))
}
