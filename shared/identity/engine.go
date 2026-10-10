package identity

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity/hostnamequality"
	"github.com/vistasecurity/vistaplatform/shared/identity/matcher"
)

// Outcome is what [Engine.Resolve] decided.
type Outcome string

const (
	// OutcomeMatched — exactly one existing asset was identified. The engine
	// attached the observation's identifiers, upserted its endpoints and
	// advanced last-seen.
	OutcomeMatched Outcome = "matched"
	// OutcomeCreated — nothing matched, so the observation is a new asset in
	// `pending_approval`.
	OutcomeCreated Outcome = "created"
	// OutcomeConflict — the identifiers disagree, either within one kind or
	// across kinds. The observation was created as its own pending asset and a
	// merge proposal was opened. NEVER auto-merged (ADR-0002 D5).
	OutcomeConflict   Outcome = "conflict"
	OutcomeUnresolved Outcome = "unresolved"
	// OutcomeProvisional — the evidence could not establish a new entity, but
	// it placed a name or address on a configured, unambiguous tenant segment
	// and no other asset owns any of it. The engine created the asset with
	// [IdentityProvisional] and NO allowance check, and the observation stays
	// `unresolved` so enrichment keeps working on it ( D2).
	OutcomeProvisional Outcome = "provisional"
	// OutcomeSupporting — the evidence could not establish anything either,
	// but every identifier it carries already belongs to exactly ONE asset,
	// so it is another sighting of a thing we already know about rather than
	// a question. The engine advanced that asset's last-seen and, when the
	// asset is provisional, attached the identifiers the observation added
	// ( D3). It is NOT a match: nothing here was allowed to decide.
	//
	// On an ESTABLISHED asset nothing is attached at all — not the
	// identifiers and not the endpoints ([Resolution.EvidenceHeld]): the
	// sockets stay on the observation until an operator links or confirms it
	// (platform ADR-0003 D2).
	OutcomeSupporting Outcome = "supporting"
)

// Resolution is the answer, with the evidence for it.
//
// Which fields are set depends on Outcome:
//
//	matched   Asset, DecidedBy; Candidates, Proposal, AutoAccepted and
//	          TopScore only on an auto-accepted merge
//	created   Asset, ClassKey
//	conflict  Asset (the new pending asset), Proposal, Candidates
//
// Unattached is set on any outcome.
type Resolution struct {
	Outcome         Outcome `json:"outcome"`
	ObservationID   string  `json:"observation_id,omitempty"`
	AdmissionReason string  `json:"admission_reason,omitempty"`

	// Asset is the asset the observation ended up on: the matched one, the
	// created one, or the new pending one a conflict produced.
	Asset AssetRef `json:"asset"`

	// ClassKey is the class of a created asset, empty for a match (the engine
	// does not reclassify an existing asset — that is the classifier seam's
	// proposal and the reconciliation rules' decision).
	ClassKey string `json:"class_key,omitempty"`

	// DecidedBy is the identifier kind that decided a match: the
	// HIGHEST-precedence kind that resolved to the asset. Empty on create.
	DecidedBy Kind `json:"decided_by,omitempty"`

	// DecidedByInferred is true when the identifier that decided the match was
	// one the intake DERIVED ([Identifier.Inferred]) rather than observed — a
	// MAC worked out from an EUI-64 address or a serial. Such a match is still
	// a match; it is not direct evidence, so it moves no lease.
	DecidedByInferred bool `json:"decided_by_inferred,omitempty"`

	// Candidates are the assets a conflict was between, ranked by matcher
	// score when a matcher scored them (highest first), otherwise in
	// precedence order of the identifier that matched them.
	Candidates []MergeCandidate `json:"candidates,omitempty"`

	// Proposal names the merge proposal that was opened. Set on conflict, and
	// on an auto-accepted merge.
	Proposal ProposalRef `json:"proposal,omitzero"`

	// AutoAccepted is true only when a tenant set Config.AutoAcceptThreshold
	// above zero AND a matcher scored the top candidate at or above it. At the
	// default threshold of zero this is never true, whatever a matcher says.
	AutoAccepted bool `json:"auto_accepted,omitempty"`

	// TopScore is the top matcher score considered, 0 when no matcher scored.
	TopScore float64 `json:"top_score,omitempty"`

	// Unattached are identifiers the engine did NOT write, because they belong
	// to a different asset in the tenant and the unique index of DATA_MODEL §2
	// says an identifier value maps to at most one asset. They are reported
	// rather than dropped: an identifier that vanishes without a trace is how
	// an inventory quietly becomes wrong.
	Unattached []Identifier `json:"unattached,omitempty"`

	// FloatingAddress is set on a match the floating-address rule decided:
	// the observation's MAC belongs to one asset and its address to another,
	// and it was L2-only, so it landed on the address's asset with the MAC
	// unattached and an announcement recorded between the two. No proposal
	// was opened. See floating.go.
	FloatingAddress *FloatingAddress `json:"floating_address,omitempty"`

	// Suppressed is set on a match that WOULD have been a conflict, had a
	// reviewer not already resolved a proposal for the same assets on the
	// same kinds of evidence as `kept_separate`. Candidates carries the
	// assets the proposal would have named. See floating.go.
	Suppressed *SuppressedProposal `json:"suppressed_proposal,omitempty"`

	// MergeRecommended is set on a conflict (or an auto-accept) for which the
	// same-device rule held and the tenant lets rule merges run: the proposal
	// carries `rule_verdict: same_device` and the evidence. The engine did NOT
	// merge anything — it never does inside Resolve (guard rail 2). The
	// rule-merge executor in inventory-service acts on the verdict later,
	// outside this transaction, through the audited merge path.
	MergeRecommended bool `json:"merge_recommended,omitempty"`

	// Drift is set on a match the drift classifier decided was the same
	// device changing — a rotated host key, a moved address, a reimage, or an
	// unverified key change flagged for review (drift.go). The engine has
	// already written the timeline entry; the caller publishes the event after
	// its transaction commits.
	Drift *Drift `json:"drift,omitempty"`

	// EvidenceHeld is set when the observation was linked to Asset but the
	// engine wrote NOTHING from it: supporting evidence for an established
	// asset, or a non-sighting (a DNS answer) for any asset. Its endpoints
	// stay on the observation (platform ADR-0003 D2: endpoints follow the
	// identity decision), so a caller must not write anything from it onto
	// the asset either — no service identification on its sockets, no crypto
	// configuration, no deferred finding. Link or Confirm on the observation
	// is what materialises them.
	EvidenceHeld bool `json:"evidence_held,omitempty"`

	// SupportingEndpoints is set on a supporting outcome that attached the
	// observation's endpoints to its single owner (D4 of, see
	// [Engine.resolveSupporting]): the identifiers are still held, the sockets
	// are the asset's. EvidenceHeld is false then, because something was
	// written, so a caller may hang service identification and crypto off
	// those sockets.
	SupportingEndpoints bool `json:"supporting_endpoints,omitempty"`

	// EndpointsClosed is how many of the asset's endpoints this observation
	// closed because they were absent from the complete set it carried
	// ([Observation.EndpointsComplete]). Only a match reconciles; zero
	// otherwise.
	EndpointsClosed int `json:"endpoints_closed,omitempty"`

	// OperatorScanJob is set on a match a person's scan request decided
	// ([Engine.WithOperatorScanRequest]): the job that carried it. DecidedBy
	// is empty then, because no identifier decided.
	OperatorScanJob string `json:"operator_scan_job,omitempty"`

	// OperatorScanRefused says why a person's scan request supplied for this
	// observation did NOT decide it (operator_scan.go). The rest of the
	// Resolution is what the engine decided without the request.
	OperatorScanRefused string `json:"operator_scan_refused,omitempty"`
}

// ObservationEndpoints is the observation's endpoints as the engine would
// write them at time at: sanitized, deduplicated, and stamped with the
// observation's source. For a caller that materialises an observation the
// engine held ([Resolution.EvidenceHeld]) after an operator decides it.
func ObservationEndpoints(obs Observation, at time.Time) []EndpointObservation {
	return stampEndpoints(obs.Endpoints, obs.Source, at)
}

// Config configures an [Engine].
type Config struct {
	// AdmissionEnabled is a release capability, separate from tenant rollout
	// policy. Producers and consumers must opt in together after their nullable
	// asset contracts are deployed.
	AdmissionEnabled bool
	// Repo is required.
	Repo Repository

	// Matcher is the ADR-0008 matcher seam. Nil means seams.Default().Matcher,
	// the null matcher, which makes no proposals. It is consulted ONLY in the
	// conflict path: the rule-based decision in ADR-0002 D3 is not a model's
	// to make, and a matcher that could veto a serial-number match would be
	// AI in a place ADR-0008 D5 keeps it out of.
	Matcher seams.Matcher

	// AutoAcceptThreshold is the score at or above which a matcher's top
	// candidate is auto-accepted. ZERO — the default — means never
	// auto-accept, which is ADR-0002 D3's stated default and today's
	// behaviour. A learned score never bypasses the proposal at zero,
	// regardless of how confident it is.
	AutoAcceptThreshold float64

	// ProvisionalInventory turns on's provisional inventory: rule D2
	// (an advertisement on a configured, unambiguous segment becomes a
	// provisional asset instead of an observation nobody can see) and the
	// provisional half of rule D3 (corroboration of a provisional asset and
	// the hearsay-yields reassignment).
	//
	// It does NOT gate "supporting evidence": evidence whose every identifier
	// belongs to ONE asset is OutcomeSupporting with the flag off too (
	// decision 3) — that shortcut is about ownership, not provisional
	// inventory. A caller therefore has to handle OutcomeSupporting whatever
	// this is set to.
	//
	// Default FALSE, and every caller but inventory-service's production
	// constructor leaves it so. The rules it enables change what Resolve
	// RETURNS for evidence that today produces `unresolved`, and a caller
	// that has not learned the two new outcomes would read a provisional
	// asset as an established one.
	ProvisionalInventory bool

	// DynamicScopes is the set of scope ids (network segments) whose addresses
	// are handed out dynamically. An ip_address never matches within one:
	// today's DHCP lease is tomorrow's other host, and matching on it merges
	// two machines (ADR-0002 D3).
	DynamicScopes map[string]bool

	// LeaseWindow is how long a device confirmation keeps an address in a
	// dynamic scope deciding a match for its owner (leasefresh.go, ADR-0002
	// D3 erratum "the lease-fresh address"). ZERO means [DefaultLeaseWindow];
	// a NEGATIVE value turns the rule off, which is the kill-switch: every
	// address in a dynamic scope is then a lease to the vote, as before.
	LeaseWindow time.Duration

	// Precedence overrides the per-class identifier order. ADR-0002 D3 makes
	// the order "editable per tenant under Settings → Identification rules",
	// and a tenant leaf subclass is a runtime row the generated registry does
	// not carry — both need this hook. Returning false falls back to the class
	// registry, and then to the ADR's default order.
	Precedence func(ctx context.Context, tenantID, classKey string) ([]Kind, bool)

	// Now is the clock, for tests. Nil means time.Now.
	Now func() time.Time
}

// Engine is the identification engine. It is safe for concurrent use if the
// Repository is.
type Engine struct {
	admissionEnabled   bool
	provisional        bool
	admissionDecision  *AdmissionDecision
	admissionCandidate *AssetRef
	// observationID is the durable evidence row this resolution is for, when
	// the caller stored one. It rides on the engine COPY the admission path
	// makes per observation (see admission_resolve.go), never on a shared
	// engine, and it exists so the history entries a provisional creation or a
	// reassignment writes can name the evidence a reviewer should read.
	observationID string
	// muted are identifier keys that must not decide a match in THIS
	// resolution, keyed by [Identifier.Key]. Only the hearsay-yields path sets
	// it ( D3): a provisional asset's address is still owned — so nothing
	// tries to write it — but it is not allowed to speak for that asset while
	// the direct evidence is being resolved on its own merits.
	muted     map[string]bool
	repo      Repository
	matcher   seams.Matcher
	threshold float64
	// autoMerge is the tenant's `auto_merge_existing` setting for THIS
	// observation ([Engine.WithAutoMergeExisting]). False on a freshly built
	// engine: a caller that has not read the tenant's setting stamps no
	// verdicts, the same "unset means never" the threshold has.
	autoMerge bool
	dynamic   map[string]bool
	// leaseWindow is Config.LeaseWindow with zero replaced by the default;
	// negative is "off" (leasefresh.go).
	leaseWindow time.Duration
	prec        func(ctx context.Context, tenantID, classKey string) ([]Kind, bool)
	now         func() time.Time

	// operatorScan is a verified person's scan request for THIS resolution
	// ([Engine.WithOperatorScanRequest]). Like observationID it rides only on a
	// per-observation copy, never on the shared engine.
	operatorScan *OperatorScanRequest

	// ownerSnapshot is the identifier owners the caller already read on this
	// resolution's transaction ([Engine.WithOwnerSnapshot]). Per-observation
	// copy only, like operatorScan, and consulted only before the first write.
	ownerSnapshot *OwnerSnapshot
}

// New builds an engine. It fails only on a missing repository: every other
// field has a documented default, and the defaults are the ones a deployment
// with no AI and no tenant overrides runs — which is most of them.
func New(cfg Config) (*Engine, error) {
	if cfg.Repo == nil {
		return nil, errors.New("identity: Config.Repo is required")
	}
	if cfg.AutoAcceptThreshold < 0 || cfg.AutoAcceptThreshold > 1 {
		return nil, fmt.Errorf("identity: Config.AutoAcceptThreshold %v is outside 0..1", cfg.AutoAcceptThreshold)
	}
	e := &Engine{
		admissionEnabled: cfg.AdmissionEnabled,
		provisional:      cfg.ProvisionalInventory,
		repo:             cfg.Repo,
		matcher:          cfg.Matcher,
		threshold:        cfg.AutoAcceptThreshold,
		dynamic:          cfg.DynamicScopes,
		leaseWindow:      cfg.LeaseWindow,
		prec:             cfg.Precedence,
		now:              cfg.Now,
	}
	if e.leaseWindow == 0 {
		e.leaseWindow = DefaultLeaseWindow
	}
	if e.matcher == nil {
		e.matcher = seams.Default().Matcher
	}
	if e.now == nil {
		e.now = time.Now
	}
	return e, nil
}

// WithRepository returns a copy of the engine that stores through repo,
// keeping every other setting — matcher, threshold, dynamic scopes, precedence
// override, clock.
//
// It exists because [Repository] has no transaction seam and one Resolve makes
// up to five writes that must land together: an observation resolved half-way —
// the pending asset created, the merge proposal not — is a permanent
// inconsistency, because the NEXT observation matches the asset that was created
// and never reaches the conflict path again. A SQL implementation supplies a
// per-transaction Repository (shared/identity/postgres's RunInTx) and the caller
// runs one observation through this:
//
//	err := repo.RunInTx(ctx, tenantID, func(r *postgres.Repository) error {
//	        res, err = engine.WithRepository(r).Resolve(ctx, obs)
//	        return err
//	})
//
// The engine is not mutated: the returned value is a shallow copy, so an engine
// shared across goroutines stays safe while each observation gets its own
// storage handle.
func (e *Engine) WithRepository(repo Repository) *Engine {
	if repo == nil {
		// A nil repository would panic on the first write, several calls deep,
		// with nothing naming the caller that supplied it. Refusing to swap is
		// the same answer New gives for the same mistake.
		return e
	}
	cp := *e
	cp.repo = repo
	return &cp
}

// WithAutoAcceptThreshold returns a copy of the engine using this tenant's
// auto-accept threshold.
//
// It exists because the threshold is a PER-TENANT setting
// (`tenant_admin_settings.config.identity.auto_accept_threshold`, edited under
// Settings → Identification rules) while an engine is built once per service
// and shared. Handing the value in per observation is the only way for one
// engine to serve tenants who have decided differently — and the alternative,
// an engine per tenant, would make the threshold a fact fixed at start-up, so a
// tenant turning auto-accept off would keep auto-merging until the next deploy.
//
// A value outside 0..1 is REFUSED into the default of zero — never auto-accept
// — rather than clamped. A stored setting of 1.5 means something wrote a value
// nobody validated, and the safe reading of a corrupt threshold is the one that
// merges nothing.
//
// The engine is not mutated; the returned value is a shallow copy.
func (e *Engine) WithAutoAcceptThreshold(threshold float64) *Engine {
	cp := *e
	if threshold < 0 || threshold > 1 {
		cp.threshold = 0
		return &cp
	}
	cp.threshold = threshold
	return &cp
}

// AutoAcceptThreshold reports the threshold this engine is using.
func (e *Engine) AutoAcceptThreshold() float64 { return e.threshold }

// WithAutoMergeExisting returns a copy of the engine carrying this tenant's
// `auto_merge_existing` setting ( Phase 4, owner decision D1), read per
// observation on the resolving transaction exactly as the threshold is
// (identitysettings.ReadAutoMergeExisting).
//
// On, a conflict for which the same-device rule holds opens its proposal as
// always and stamps `rule_verdict: same_device` on it ([SameDeviceVerdict]);
// the rule-merge executor merges it later, outside Resolve. Off, nothing is
// stamped and the proposal is an ordinary question for a person — today's
// behaviour.
//
// The engine is not mutated; the returned value is a shallow copy.
func (e *Engine) WithAutoMergeExisting(on bool) *Engine {
	cp := *e
	cp.autoMerge = on
	return &cp
}

// AutoMergeExisting reports whether this engine stamps same-device verdicts.
func (e *Engine) AutoMergeExisting() bool { return e.autoMerge }

// (Whether a scope is dynamic is per-observation, not per-engine: see
// [Observation.DynamicScopes] and [Engine.kindVotes].)

// Resolve identifies an observation, implementing ADR-0002 D3.
//
// The walk, in full:
//
//  1. Normalise every identifier. A value that does not normalise is an error;
//     [Observation.Sanitize] is the explicit way to be lenient.
//  2. Look up the owner of EVERY identifier, not only the ones the class
//     identifies by. The extra kinds do not vote — that is the precedence
//     list's job — but knowing who owns them is what lets the engine avoid
//     writing an identifier that belongs to somebody else.
//  3. Walk the class's precedence in order. A kind that matches more than one
//     asset is a conflict outright. The FIRST kind that matches exactly one
//     asset decides; a later, lower-precedence kind matching the SAME asset is
//     corroboration, and one matching a DIFFERENT asset is a cross-kind
//     conflict.
//  4. Act on the outcome, and write history whichever way it went.
//
// Kinds requiring a scope (hostname, ip_address) do not vote without one, and
// ip_address does not vote inside a scope flagged dynamic. Their identifiers
// are still recorded.
func (e *Engine) resolve(ctx context.Context, obs Observation) (Resolution, error) {
	if strings.TrimSpace(obs.TenantID) == "" {
		return Resolution{}, fmt.Errorf("%w: no tenant", ErrInvalidObservation)
	}
	if obs.EndpointsComplete != nil {
		if err := obs.EndpointsComplete.Validate(obs.Source, obs.Endpoints); err != nil {
			return Resolution{}, fmt.Errorf("%w: %w", ErrInvalidObservation, err)
		}
	}
	at := obs.ObservedAt
	if at.IsZero() {
		at = e.now().UTC()
	}

	ids := make([]Identifier, 0, len(obs.Identifiers))
	for _, raw := range obs.Identifiers {
		n, err := raw.Normalized()
		if err != nil {
			return Resolution{}, fmt.Errorf("%w: %w", ErrInvalidObservation, err)
		}
		n.Source = identifierSource(raw, obs.Source)
		if n.SeenAt.IsZero() {
			n.SeenAt = at
		}
		ids = append(ids, n)
	}
	ids = dedupeIdentifiers(ids)

	// Step 2: ownership of every identifier present, keyed by identifier key.
	owners := make(map[string][]AssetRef, len(ids))
	for _, id := range ids {
		refs, err := e.ownersOf(ctx, obs.TenantID, id)
		if err != nil {
			return Resolution{}, fmt.Errorf("identity: looking up %s=%q: %w", id.Kind, id.Value, err)
		}
		owners[id.Key()] = refs
	}

	// A person's scan of a named asset (operator_scan.go) decides before the
	// walk, or not at all: a refused request resolves the observation exactly
	// as it would have been resolved without one.
	if e.operatorScan != nil {
		res, refused, err := e.resolveOperatorScan(ctx, obs, at, ids, owners)
		if err != nil || refused == "" {
			return res, err
		}
		plain := *e
		plain.operatorScan = nil
		// The refused attempt may have read past the snapshot's moment; the
		// re-run reads the owners afresh.
		plain.ownerSnapshot = nil
		res, err = plain.resolve(ctx, obs)
		res.OperatorScanRefused = refused
		return res, err
	}

	// Claimed addresses (claimed.go): before the walk, because a
	// claimed address that will re-home must not vote for its old holder, and
	// one whose holder keeps it must vote even in a dynamic scope.
	claims, err := e.decideAddressClaims(ctx, obs, ids, owners)
	if err != nil {
		return Resolution{}, err
	}
	obs.claims = claims

	// Step 3: the precedence walk.
	precedence := e.precedenceFor(ctx, obs.TenantID, obs.ClassHint)
	if obs.Admission.Authoritative {
		// A validated source identity remains usable before classification is
		// known. In particular unknown_host's normal precedence omits CMDB IDs.
		precedence = append([]Kind{KindAgentID, KindSensorID, KindCloudResourceID, KindCMDBSysID, KindSerialNumber}, precedence...)
	}
	if obs.Source.Kind == SourceDeclared && obs.Admission.OperatorConfirmed {
		precedence = append([]Kind{KindDeclarationID}, precedence...)
	}
	byKind := groupByKind(ids)

	var (
		decided   string
		decidedBy Kind
		// decider is the identifier that decided: which one, not only which
		// kind, because a match decided by an INFERRED identifier is not
		// direct evidence and must not move a lease ( Phase 2).
		decider      Identifier
		conflicting  bool
		corrupt      bool // one identifier value owned by several assets
		conflictWhy  string
		evidence     = map[string][]Identifier{} // asset id → identifiers that matched it
		candidateSeq []string                    // candidate ids in discovery order
	)
	note := func(assetID string, id Identifier) {
		if _, seen := evidence[assetID]; !seen {
			candidateSeq = append(candidateSeq, assetID)
		}
		evidence[assetID] = append(evidence[assetID], id)
	}
	if e.admissionCandidate != nil {
		decided, decidedBy = e.admissionCandidate.ID, KindDeclarationID
		candidateSeq = append(candidateSeq, decided)
		evidence[decided] = nil
	}

	for _, kind := range precedence {
		for _, id := range byKind[kind] {
			if !e.kindVotes(obs, id) {
				continue
			}
			refs := owners[id.Key()]
			if len(refs) == 0 {
				continue
			}
			if decided != "" && refs[0].ID != decided && e.dynamicAddress(obs, id) && obs.addressLeaseFresh(id) {
				// A lease-fresh address is a FALLBACK (leasefresh.go): it
				// decides when nothing stronger did, and never contradicts a
				// kind ranked above it. B's name, or B's derived MAC, seen at
				// A's recently confirmed address is B, with A's lease left
				// where it was for lease.go to judge — not a cross-kind
				// conflict, and not a floating address.
				continue
			}
			if len(refs) == 1 && refs[0].ID != decided {
				shared, err := e.sharedNameDoesNotVote(ctx, AssetRef{TenantID: obs.TenantID, ID: decided}, decidedBy, decider, id)
				if err != nil {
					return Resolution{}, err
				}
				if shared {
					// A device-binding identifier (MAC, serial, host key, agent
					// id) decided, and the asset it decided was CREATED beside
					// this name's holder precisely because they only share the
					// name (distinct_device.go). The name resolving to the
					// other asset is then a shared name, not evidence of a
					// different device: without this, replaying the second
					// plug's report reopens the proposal the distinct-device
					// row exists to avoid. Strong kinds are untouched: two
					// serials remain two devices.
					continue
				}
			}
			for _, r := range refs {
				note(r.ID, id)
			}
			if len(refs) > 1 {
				// One identifier value owned by several assets: the unique
				// index of DATA_MODEL §2 says this cannot happen, so seeing it
				// means the store has lost the invariant. That is precisely
				// why FindByIdentifier returns a slice.
				conflicting = true
				corrupt = true
				conflictWhy = fmt.Sprintf("%s=%q resolves to %d assets", id.Kind, id.Value, len(refs))
				continue
			}
			switch {
			case decided == "":
				// The highest-precedence kind that matched. It decides. Within
				// the kind, groupByKind put native identifiers first, so an
				// inferred one decides only when no native one of its kind
				// matched anything (guard 2 of Phase 2).
				decided = refs[0].ID
				decidedBy = kind
				decider = id
			case decided != refs[0].ID:
				conflicting = true
				if conflictWhy == "" {
					conflictWhy = fmt.Sprintf("%s matched one asset and %s another", decidedBy, id.Kind)
				}
			}
		}
	}

	// A host's own report decided by the installation identity we issued is
	// that installation's host (installation_claims.go): a weaker identifier
	// another asset holds does not detach it. The other asset is proposed
	// beside the match instead, after it is applied.
	installation := decided != "" && !corrupt && installationDecides(obs, decidedBy)

	// The floating-address rule, BEFORE the conflict path (floating.go). A MAC
	// resolving to one asset and an address to another is a cross-kind
	// conflict in every case but one: when that is ALL the observation says,
	// it is a node announcing an address that floats — and the floor below
	// would otherwise turn it into a merge proposal on every gratuitous ARP.
	if conflicting && !corrupt && !installation {
		if pair, ok := e.floatingAddress(obs, ids, owners, decided, decidedBy, candidateSeq); ok {
			return e.resolveFloating(ctx, obs, at, ids, owners, pair)
		}
	}

	switch {
	case conflicting && !installation:
		return e.resolveConflict(ctx, obs, at, ids, owners, evidence, candidateSeq, conflictWhy)
	case decided != "":
		ref := AssetRef{TenantID: obs.TenantID, ID: decided}

		// The singleton guard (ADR-0002 D3 erratum). A match decided by some
		// kind does NOT license writing a second value of a kind an asset may
		// only hold one of. If the observation carries a singleton identifier
		// the decided asset disagrees with, these are two things that share a
		// weaker identifier, and saying so is a merge proposal — not a silent
		// second ARN on one asset.
		observed, existing, disagrees, sErr := e.singletonConflict(ctx, ids, ref)
		if sErr != nil {
			return Resolution{}, sErr
		}
		if disagrees {
			why := fmt.Sprintf(
				"%s decided this match, but the observation's %s=%q disagrees with the %q the asset already carries, and an asset holds at most one %s",
				decidedBy, observed.Kind, observed.Value, existing.Value, observed.Kind)
			return e.resolveSingletonConflict(ctx, obs, at, ids, owners, ref, why)
		}
		// Owner Decision 4 (drift.go): a device binding or the address
		// changing under a decided match is CLASSIFIED — rotated, moved,
		// reimaged, unverified or replaced — rather than vetoed or waved
		// through by whichever kind the walk checked first.
		drift, err := e.classifyDrift(ctx, obs, at, ids, ref)
		if err != nil {
			return Resolution{}, err
		}
		if drift.result.Verdict == matcher.DriftDistinct {
			if e.distinctDeviceCreates(obs, decidedBy, decider, installation) {
				res, handled, err := e.resolveDistinctDevice(ctx, obs, at, ids, owners)
				if err != nil || handled {
					return res, err
				}
			}
			// The table's opinion needs a direct measurement to act on; any
			// other source gets what it got before the row existed.
			drift = driftCheck{}
		}
		switch {
		case drift.result.Verdict == matcher.DriftReplaced:
			return e.resolveSingletonConflict(ctx, obs, at, ids, owners, ref, "a different device now answers here: "+drift.result.Explanation)
		case drift.result.Verdict.Matches():
			// The classifier has read the interfaces too and called it the
			// same device; the interface check below would only repeat a
			// coarser version of that question.
		case e.admissionDecision != nil && (e.admissionCandidate != nil || decidedBy == KindHostname || decidedBy == KindFQDN || decidedBy == KindIPAddress):
			// No drift row applies (a name, not an address, decided; or the
			// change is not one the table has an opinion on): the interface
			// rule as it always was.
			if disagrees, err := e.interfaceBindingConflict(ctx, ids, ref); err != nil {
				return Resolution{}, err
			} else if disagrees {
				return e.resolveSingletonConflict(ctx, obs, at, ids, owners, ref, "a name or address matches, but the directly observed interface differs from the asset's known interfaces")
			}
		}

		// D3: an established observation landing on a PROVISIONAL asset
		// is either corroboration — the guess was right and this is the same
		// item, met directly at last — or hearsay yielding, when all the two
		// agree about is an address. Nothing here changes what an established
		// asset does, and with Config.ProvisionalInventory off the mode is
		// always `none`.
		changes := map[string]any{"decided_by": string(decidedBy)}
		if decider.Inferred() {
			// The timeline says the match was made through a DERIVED value and
			// names the evidence, so a reviewer reading "decided by
			// mac_address" knows the MAC was worked out, not seen.
			changes["decided_by_inferred"] = decider.Source.Ref
		}
		if decidedBy == KindIPAddress && obs.addressLeaseFresh(decider) {
			// A reviewer reading "decided by ip_address" on a DHCP segment
			// needs to see why that was allowed (leasefresh.go).
			changes["lease_fresh"] = true
		}
		mode, err := e.provisionalMatchMode(ctx, ref, evidence[decided])
		if err != nil {
			return Resolution{}, err
		}
		switch mode {
		case provisionalCorroborate:
			changes["corroborated_provisional"] = true
		case provisionalYield:
			res, handled, err := e.yieldToDirectEvidence(ctx, obs, at, ref, evidence[decided])
			if err != nil {
				return Resolution{}, err
			}
			if handled {
				return res, nil
			}
			// The re-run found nowhere honest to move the address to. Fall
			// through to the ordinary match, which keeps the observation
			// attached to something a reviewer can find and undo.
		}

		// Identifiers owned by another asset cannot be written here: one
		// identifier value, at most one asset.
		attach, unattached := splitByOwner(ids, owners, decided)

		// 1b — the address follows the MAC. A lease in a dynamic scope,
		// still owned by whoever held it before, moves to the device this
		// observation met there, when lease.go's conditions all hold. The moved
		// addresses are then attached like any other, which is what stamps
		// their last-seen with this observation.
		moves, unattached, err := e.leaseMoves(ctx, obs, precedence, decider, decidedBy, owners, unattached)
		if err != nil {
			return Resolution{}, err
		}
		if len(moves) > 0 {
			if err := e.applyLeaseMoves(ctx, obs, at, decidedBy, ref, moves); err != nil {
				return Resolution{}, err
			}
			movedKeys := make([]string, 0, len(moves))
			for _, m := range moves {
				attach = append(attach, m.id)
				movedKeys = append(movedKeys, m.id.Key())
			}
			changes["lease_moved"] = movedKeys
		}

		// — a claimed address held by a provisional or address-only
		// record moves to the device that reported it as its own (claimed.go).
		claimed, unattached, err := e.applyAddressClaims(ctx, obs, at, ref, unattached)
		if err != nil {
			return Resolution{}, err
		}
		if len(claimed) > 0 {
			attach = append(attach, claimed...)
			changes["claimed_rehomed"] = identifierKeys(claimed)
		}

		// A match an observed device binding decided confirms the device at
		// every address it attaches (leasefresh.go): that is what lets the
		// next address-only probe of it match inside a dynamic scope.
		attach = stampDeviceConfirmation(at, attach, deviceDecided(obs, decidedBy, decider))

		if err := e.applyToAsset(ctx, ref, obs, at, attach, unattached, ActionUpdated, changes); err != nil {
			return Resolution{}, err
		}
		if err := e.retireEmptiedLeaseHolders(ctx, obs, at, moves); err != nil {
			return Resolution{}, err
		}
		if err := e.retireClaimedHolders(ctx, obs, at, claimed); err != nil {
			return Resolution{}, err
		}
		applied, err := e.applyDrift(ctx, obs, at, ref, drift)
		if err != nil {
			return Resolution{}, err
		}
		res := Resolution{
			Outcome:           OutcomeMatched,
			Asset:             ref,
			DecidedBy:         decidedBy,
			DecidedByInferred: decider.Inferred(),
			Unattached:        unattached,
			Drift:             applied,
			EndpointsClosed:   closedEndpointCount(changes),
		}
		if installation {
			p, err := e.proposeSameInstallation(ctx, obs, at, ref, decidedBy, ids, owners, evidence, candidateSeq, unattached)
			if err != nil {
				return Resolution{}, err
			}
			res.Candidates = p.candidates
			res.Proposal = p.proposal
			res.TopScore = p.topScore
			res.MergeRecommended = p.mergeRecommended
			res.Suppressed = p.suppressed
		}
		return res, nil
	default:
		if e.admissionDecision != nil && !e.admissionDecision.Established {
			claimed := ownerSet(owners)
			if len(claimed) > 1 {
				return e.resolveContested(ctx, obs, at, ids, owners)
			}
			if len(claimed) == 1 {
				// D3 /: every identifier anybody owns is owned by
				// the SAME asset. This is another sighting of a thing we
				// already know about, not a question — supporting evidence.
				// Unconditional, like the floor below: the shortcut is about
				// ownership, not about Config.ProvisionalInventory.
				for id := range claimed {
					return e.resolveSupporting(ctx, obs, at, ids, owners, AssetRef{TenantID: obs.TenantID, ID: id})
				}
			}
			if e.provisional && len(claimed) == 0 && obs.Source.Kind == SourceMeasured {
				// D2: an advertisement nobody else claims, placed on a
				// configured and unambiguous tenant segment, becomes a
				// PROVISIONAL asset rather than evidence no inventory surface
				// can show.
				placement, err := e.provisionalScopeFor(ctx, obs, ids)
				if err != nil {
					return Resolution{}, err
				}
				if placement.segment != "" {
					return e.resolveProvisional(ctx, obs, at, ids, placement.segment)
				}
				return Resolution{Outcome: OutcomeUnresolved, Unattached: ids, AdmissionReason: placement.reason}, nil
			}
			// Matching has run, but this evidence cannot establish a new
			// entity. The caller already stored it in this transaction.
			return Resolution{Outcome: OutcomeUnresolved, Unattached: ids}, nil
		}
		// Nothing DECIDED. That is not the same as nothing being known, and the
		// difference is the floor below.
		attach, unattached := splitByOwner(ids, owners, "")
		// An observation whose only NEW identifiers are derived ones creates
		// nothing (guard 1, Phase 2): it falls through to the floor as if
		// they were not there, so adding a derived MAC to a sighting can never
		// turn "another sighting of X" into a new asset.
		if len(attach) > 0 && !allInferred(attach) {
			return e.resolveCreate(ctx, obs, at, attach, unattached)
		}

		// The floor: never create an asset with no identifier.
		//
		// An asset carrying none can never be matched again, so every
		// re-observation of the same thing makes another one. Two ways to get
		// here, and they are different facts:
		if len(unattached) > 0 {
			// Every identifier we saw is owned by somebody else, but none of
			// them was allowed to decide — a kind this class drops, or an IP in
			// a dynamic segment.
			//
			// When all of them belong to ONE asset ( A1) there is no
			// question to ask: this is another sighting of a thing we already
			// know about, and a proposal naming a single candidate is a work
			// item a reviewer can only "keep separate" from nothing. It is
			// supporting evidence, whatever Config.ProvisionalInventory says —
			// the shortcut is about ownership, not about provisional inventory.
			// Nothing new can be attached here: every identifier is already
			// that asset's, which is how the floor was reached.
			if claimed := ownerSet(owners); len(claimed) == 1 {
				for only := range claimed {
					return e.resolveSupporting(ctx, obs, at, ids, owners, AssetRef{TenantID: obs.TenantID, ID: only})
				}
			}
			// Two or more owners: we know the observation is related to those
			// assets and we do not know how. That is ADR-0002 D3's third
			// outcome, so it opens a merge proposal against the owners; it does
			// NOT create, because the thing it would create is the empty asset
			// this floor exists to prevent.
			return e.resolveContested(ctx, obs, at, ids, owners)
		}
		// Nothing at all to identify it by. Refusing is the honest answer.
		return Resolution{}, fmt.Errorf("%w: class %q identifies by %v and the observation carries none of them",
			ErrNoUsableIdentifier, obs.ClassHint, precedence)
	}
}

// singletonConflict reports the first identifier of a SINGLETON kind in the
// observation whose value disagrees with one the matched asset already carries
// in the same scope.
//
// Three outcomes, and the difference between the last two is the whole point:
//
//   - the asset carries the SAME value — corroboration, not a conflict;
//   - the asset carries NO value of that kind — the observation is telling us
//     something new about it, which is exactly how a cloud resource and the
//     same host seen by the sensor become ONE asset. Attach it;
//   - the asset carries a DIFFERENT value — two things, one of which happens
//     to answer to a weaker identifier the other has. Contested.
//
// Scope is part of the comparison: `cmdb_sys_id` is scoped to its sync profile,
// so one asset legitimately holds one sys_id per profile, and only two in the
// SAME profile are a contradiction.
//
// It reads the asset only when the observation actually carries a singleton, so
// the common path costs no extra query.
func (e *Engine) singletonConflict(ctx context.Context, ids []Identifier, ref AssetRef) (observed, existing Identifier, disagrees bool, err error) {
	var singletons []Identifier
	for _, id := range ids {
		if id.Kind.Singleton() {
			singletons = append(singletons, id)
		}
	}
	if len(singletons) == 0 {
		return Identifier{}, Identifier{}, false, nil
	}

	summaries, err := e.repo.LoadSummaries(ctx, ref.TenantID, []string{ref.ID})
	if err != nil {
		return Identifier{}, Identifier{}, false, fmt.Errorf("identity: reading %s's identifiers for the singleton check: %w", ref.ID, err)
	}
	if len(summaries) == 0 {
		// The asset the precedence walk just matched is gone. Not this
		// function's failure to report: the caller's write will say so.
		return Identifier{}, Identifier{}, false, nil
	}

	held := make(map[string]Identifier, len(summaries[0].Identifiers))
	for _, id := range summaries[0].Identifiers {
		if id.Kind.Singleton() {
			held[string(id.Kind)+"\x00"+id.Scope] = id
		}
	}
	for _, id := range singletons {
		if h, ok := held[string(id.Kind)+"\x00"+id.Scope]; ok && h.Value != id.Value {
			return id, h, true, nil
		}
	}
	return Identifier{}, Identifier{}, false, nil
}

// resolveSingletonConflict is outcome three of ADR-0002 D3, reached because a
// singleton identifier disagreed rather than because two kinds matched two
// assets.
//
// It deliberately does NOT offer the auto-accept threshold. A tenant's
// auto-accept says "a high enough matcher score may settle an ambiguity without
// me"; a singleton disagreement is not an ambiguity. Two different ARNs are two
// different resources whatever a matcher scores the pair, and accepting would
// put the second singleton value on the asset — the exact state this guard
// exists to prevent. Every other conflict keeps the threshold it always had.
func (e *Engine) resolveSingletonConflict(
	ctx context.Context,
	obs Observation,
	at time.Time,
	ids []Identifier,
	owners map[string][]AssetRef,
	matched AssetRef,
	why string,
) (Resolution, error) {
	candidates := []MergeCandidate{{Ref: matched, MatchedIdentifiers: matchedAgainst(ids, owners, matched.ID)}}
	r, err := e.rank(ctx, obs, at, candidates)
	if err != nil {
		return Resolution{}, err
	}
	return e.conflictOutcome(ctx, obs, at, ids, owners, r, why)
}

// matchedAgainst is the evidence for one candidate: the observation's
// identifiers that this asset already owns. A candidate with no evidence can
// only be rubber-stamped, so a proposal always carries it.
func matchedAgainst(ids []Identifier, owners map[string][]AssetRef, assetID string) []Identifier {
	var out []Identifier
	for _, id := range ids {
		for _, r := range owners[id.Key()] {
			if r.ID == assetID {
				out = append(out, id)
				break
			}
		}
	}
	return out
}

// resolveContested is the floor's conflict half: every identifier the
// observation carries is already owned, and none of them may vote.
//
// It opens a merge proposal naming the owners and writes NOTHING to any asset.
// The Resolution's Asset is deliberately ZERO — no asset took this observation,
// and returning one of the candidates would invite the caller to apply context
// and status to an asset the engine did not match. Callers check
// [AssetRef.Zero].
func (e *Engine) resolveContested(
	ctx context.Context,
	obs Observation,
	at time.Time,
	ids []Identifier,
	owners map[string][]AssetRef,
) (Resolution, error) {
	evidence := map[string][]Identifier{}
	var candidateSeq []string
	for _, id := range ids {
		for _, ref := range owners[id.Key()] {
			if _, seen := evidence[ref.ID]; !seen {
				candidateSeq = append(candidateSeq, ref.ID)
			}
			evidence[ref.ID] = append(evidence[ref.ID], id)
		}
	}
	// B2: an asset whose ONLY link to this observation is a generic name
	// is not a candidate. `iphone` on two records says nothing about whether
	// either is the phone seen now, and a proposal built on it asks a reviewer
	// to consider merging two phones because neither was renamed.
	candidateSeq = withoutGenericOnly(candidateSeq, evidence)
	if len(candidateSeq) == 0 {
		// Every owner was linked by a generic name alone: nothing identifies
		// the observation, and there is no question to ask. The evidence is
		// retained by the caller; nothing is written to any asset.
		return Resolution{Outcome: OutcomeUnresolved, Unattached: ids}, nil
	}
	if len(candidateSeq) == 1 {
		// Belt and braces for A1. A merge proposal with ONE candidate is
		// not a question — the Approvals UI needs two live records to offer a
		// merge, so the only answer a reviewer could give is "keep separate"
		// from nothing. Both callers route a single owner to supporting
		// evidence before reaching here; this holds for any future caller.
		return e.resolveSupporting(ctx, obs, at, ids, owners, AssetRef{TenantID: obs.TenantID, ID: candidateSeq[0]})
	}
	candidates := make([]MergeCandidate, 0, len(candidateSeq))
	for _, id := range candidateSeq {
		candidates = append(candidates, MergeCandidate{
			Ref:                AssetRef{TenantID: obs.TenantID, ID: id},
			MatchedIdentifiers: evidence[id],
		})
	}
	why := fmt.Sprintf("every identifier this observation carries already belongs to another asset, and none of them may decide for class %q", obs.ClassHint)

	// Decision memory, before ranking and before the auto-accept: a pair a
	// human already kept separate is neither re-proposed nor auto-merged on a
	// model's score.
	prior, keptApart, err := e.keptSeparate(ctx, obs, candidates)
	if err != nil {
		return Resolution{}, err
	}
	if keptApart {
		if d := prior.appliesTo(candidates); d != nil {
			return e.resolveSuppressed(ctx, obs, at, ids, owners, candidates, *d, why)
		}
	}

	r, err := e.rank(ctx, obs, at, candidates)
	if err != nil {
		return Resolution{}, err
	}
	r = e.withSameDeviceVerdict(obs, r, keptApart)

	// An auto-accept threshold a tenant deliberately set still applies: the
	// observation goes into the winner rather than nowhere.
	if ok, _ := e.autoAcceptable(ids, r); ok {
		return e.acceptMerge(ctx, obs, at, r, ids, owners, why)
	}
	return e.proposeWithoutCreating(ctx, obs, at, ids, r, why)
}

// proposeWithoutCreating opens a merge proposal and writes no asset.
//
// It is the tail both floor paths share: a conflict whose every identifier is
// already owned, and a contested observation none of whose identifiers may
// vote. In both, the asset the older code would have created carries no
// identifier at all.
//
// The proposal hangs off the first candidate — [Repository.OpenMergeProposal]'s
// subject fallback when there is no observation asset — and so does the history
// entry, because it is the only asset in the picture.
func (e *Engine) proposeWithoutCreating(
	ctx context.Context,
	obs Observation,
	at time.Time,
	ids []Identifier,
	r ranking,
	why string,
) (Resolution, error) {
	candidates, top := r.candidates, r.top
	if len(candidates) == 0 {
		// Unreachable from either caller — both are here BECAUSE identifiers
		// resolved to owners — but a proposal with no candidate would be a
		// work item naming nothing.
		return Resolution{}, fmt.Errorf("%w: %s", ErrNoUsableIdentifier, why)
	}
	proposal, err := e.openMergeProposal(ctx, obs.TenantID, r, MergeProposal{
		Candidates:   candidates,
		Source:       obs.Source,
		Reason:       why,
		ProposedAt:   at,
		ModelID:      rankedBy(top).ModelID,
		SourceRef:    rankedBy(top).SourceRef,
		RuleVerdict:  r.ruleVerdict(),
		RuleEvidence: r.ruleEvidence,
	})
	if err != nil {
		return Resolution{}, fmt.Errorf("identity: opening the merge proposal for a fully-owned observation: %w", err)
	}
	// The pointer entry is written ONCE per question. A proposal the store
	// found already pending has its note already; re-noting it on every
	// observation is how one contested host wrote a history row per
	// coalescing window against an asset it does not belong to.
	if !proposal.Reused {
		if err := e.history(ctx, candidates[0].Ref, obs, at, ActionMergeProposed, map[string]any{
			"proposal_id": proposal.ID,
			"candidates":  candidateIDs(candidates),
			"reason":      why,
			"contested":   identifierKeys(ids),
			"created":     false,
		}); err != nil {
			return Resolution{}, err
		}
	}
	return Resolution{
		Outcome:          OutcomeConflict,
		Candidates:       candidates,
		Proposal:         proposal,
		TopScore:         topScore(top),
		Unattached:       ids,
		MergeRecommended: r.mergeRecommended(),
	}, nil
}

// kindVotes reports whether an identifier may decide a match, as opposed to
// merely being recorded. The two scope rules of ADR-0002 D3 live here, the
// dynamic-scope one with its pinned-address exception ([Engine.dynamicAddress]).
//
// The empty-scope guard is belt and braces: [Identifier.Normalized] gives every
// scoped kind [ScopeTenantDefault] when the caller supplied nothing, so this
// should be unreachable. It stays because the consequence of reaching it —
// silently, on one kind, in one intake path — was three assets for one host.
func (e *Engine) kindVotes(obs Observation, id Identifier) bool {
	if e.muted[id.Key()] || obs.claimMuted(id) {
		return false
	}
	if id.Generic {
		// B2: a name many unrelated devices carry (`iphone`, `printer`,
		// or one the tenant already sees on three or more assets) is recorded —
		// it is true — but it says nothing about WHICH device this is, so it
		// never decides. Ingest marks it ([GenericNames.Mark]); the engine needs
		// no lookup.
		return false
	}
	if e.admissionDecision != nil && !e.admissionDecision.Established {
		// Weak aliases can be retained and compared for review, but cannot
		// decide ownership. Direct device identifiers may still match an
		// existing entity when its network placement is not yet resolved.
		if id.Kind != KindMACAddress || !obs.Admission.Direct || obs.Admission.Relayed {
			return false
		}
	}
	if id.Kind.RequiresScope() && id.Scope == "" {
		return false
	}
	if !e.addressDecides(obs, id) {
		// ADR-0002 D3: an address in a dynamic scope decides nothing — unless
		// its owner holds it pinned (pinned.go, decision 1) or was
		// device-confirmed there within the lease window (leasefresh.go).
		return false
	}
	return true
}

// precedenceFor resolves the effective identifier precedence: the tenant's
// override, else the class registry's order, else the ADR's default.
func (e *Engine) precedenceFor(ctx context.Context, tenantID, classKey string) []Kind {
	if e.prec != nil {
		if ks, ok := e.prec(ctx, tenantID, classKey); ok {
			return ks
		}
	}
	if classKey != "" {
		if ks, ok := classPrecedence(classKey); ok {
			// An empty (not absent) precedence is an answer: this class has no
			// independent identity and is matched by dependent identity
			// instead. Falling back to the default order here would give a
			// business service an IP-address identity, which is the opposite
			// of what the registry said.
			return ks
		}
	}
	return defaultPrecedence
}

func (e *Engine) resolveCreate(ctx context.Context, obs Observation, at time.Time, attach, unattached []Identifier, extra ...map[string]any) (Resolution, error) {
	if e.admissionDecision != nil {
		guard, ok := e.repo.(interface {
			CheckAdmissionAllowance(context.Context, string) (bool, error)
		})
		if !ok {
			return Resolution{}, fmt.Errorf("admission requires an asset allowance guard")
		}
		allowed, err := guard.CheckAdmissionAllowance(ctx, obs.TenantID)
		if err != nil {
			return Resolution{}, err
		}
		if !allowed {
			return Resolution{Outcome: OutcomeUnresolved, Unattached: append(attach, unattached...), AdmissionReason: "asset_allowance_exhausted"}, nil
		}
	}
	// The floor, restated at the only place that creates. Resolve's default
	// branch already routes an empty attach elsewhere; this is here so a future
	// caller cannot reach the INSERT without one, because an asset with no
	// identifier is the one thing this package must never write.
	if len(attach) == 0 {
		return Resolution{}, fmt.Errorf("%w: refusing to create an asset with no identifier", ErrNoUsableIdentifier)
	}
	// Guard 1 of Phase 2: an inferred identifier never CREATES. A value
	// the intake worked out (a MAC read from an EUI-64 address or a serial) is
	// evidence about a thing something else established; an asset held
	// together by nothing else would be minted by a derivation. The emitters
	// only add a derived MAC beside real evidence, so this is unreachable from
	// them — it is here so no future caller can reach the INSERT around it.
	if allInferred(attach) {
		return Resolution{}, fmt.Errorf("%w: refusing to create an asset whose only identifiers are derived (%v)",
			ErrNoUsableIdentifier, identifierKeys(attach))
	}
	classKey, classSource, classRef, classConf := e.classForCreate(obs)
	// A device met directly, by an observed device binding, is confirmed at
	// the addresses it is created with (leasefresh.go) — the first sighting
	// is as good a confirmation as any later one.
	attach = stampDeviceConfirmation(at, attach, deviceMet(obs, attach))
	newAsset := NewAsset{
		ClassKey:        classKey,
		ClassSourceKind: classSource,
		ClassSourceRef:  classRef,
		ClassConfidence: classConf,
		DisplayName:     displayNameFor(obs, attach),
		Hostname:        hostnameFor(obs, attach),
		PrimaryAddress:  primaryAddressFor(obs, attach),
		Status:          StatusPendingApproval,
		Ownership:       obs.Network.Ownership,
		NetworkSegment:  obs.Network.SegmentID,
		DiscoveryMethod: obs.Source.Ref,
		Confidence:      obs.Confidence,
		Source:          obs.Source,
		Identifiers:     attach,
		Endpoints:       stampEndpoints(obs.Endpoints, obs.Source, at),
		FirstSeenAt:     at,
		LastSeenAt:      at,
	}
	ref, err := e.repo.CreateAsset(ctx, obs.TenantID, newAsset)
	if err != nil {
		return Resolution{}, fmt.Errorf("identity: creating asset: %w", err)
	}
	created := map[string]any{
		"class_key":   classKey,
		"identifiers": identifierKeys(attach),
		"endpoints":   endpointKeys(newAsset.Endpoints),
		"unattached":  identifierKeys(unattached),
	}
	for _, x := range extra {
		for k, v := range x {
			created[k] = v
		}
	}
	if err := e.history(ctx, ref, obs, at, ActionCreated, created); err != nil {
		return Resolution{}, err
	}
	return Resolution{
		Outcome:    OutcomeCreated,
		Asset:      ref,
		ClassKey:   classKey,
		Unattached: unattached,
	}, nil
}

// resolveConflict implements outcome three of ADR-0002 D3.
//
// The observation becomes its own pending asset and a merge proposal lists
// every candidate with the identifiers that matched it. The conflicting
// identifiers are NOT attached to the new asset — they belong to the
// candidates, and one identifier value maps to at most one asset — so the
// evidence lives on the proposal, which is where a reviewer reads it.
func (e *Engine) resolveConflict(
	ctx context.Context,
	obs Observation,
	at time.Time,
	ids []Identifier,
	owners map[string][]AssetRef,
	evidence map[string][]Identifier,
	candidateSeq []string,
	why string,
) (Resolution, error) {
	// B2, the same pruning resolveContested does. The walk only notes
	// identifiers that VOTED and a generic name never votes ([Engine.kindVotes]),
	// so no candidate here should be linked by one alone; this keeps the rule
	// in force for any evidence that reaches the conflict path another way.
	if kept := withoutGenericOnly(candidateSeq, evidence); len(kept) < len(candidateSeq) {
		switch len(kept) {
		case 0:
			return Resolution{Outcome: OutcomeUnresolved, Unattached: ids}, nil
		case 1:
			// One candidate is not a question ( A1): supporting evidence,
			// with the address-only link refusal (C1) that path applies.
			return e.resolveSupporting(ctx, obs, at, ids, owners, AssetRef{TenantID: obs.TenantID, ID: kept[0]})
		}
		candidateSeq = kept
	}
	candidates := make([]MergeCandidate, 0, len(candidateSeq))
	for _, id := range candidateSeq {
		candidates = append(candidates, MergeCandidate{
			Ref:                AssetRef{TenantID: obs.TenantID, ID: id},
			MatchedIdentifiers: evidence[id],
		})
	}

	// Decision memory (floating.go), before the matcher sees the pair: a
	// reviewer who already kept these apart is not asked again, and no score
	// overrides their answer.
	prior, keptApart, err := e.keptSeparate(ctx, obs, candidates)
	if err != nil {
		return Resolution{}, err
	}
	if keptApart {
		if d := prior.appliesTo(candidates); d != nil {
			return e.resolveSuppressed(ctx, obs, at, ids, owners, candidates, *d, why)
		}
	}

	// The matcher seam ranks; it does not decide. A null matcher leaves every
	// score at zero and the order as found, and the proposal is identical.
	r, err := e.rank(ctx, obs, at, candidates)
	if err != nil {
		return Resolution{}, err
	}
	r = e.withSameDeviceVerdict(obs, r, keptApart)

	if ok, _ := e.autoAcceptable(ids, r); ok {
		return e.acceptMerge(ctx, obs, at, r, ids, owners, why)
	}
	return e.conflictOutcome(ctx, obs, at, ids, owners, r, why)
}

// conflictOutcome writes outcome three: the observation becomes its own pending
// asset, and a merge proposal names the candidates it could also be.
//
// It is the tail shared by the two ways of reaching outcome three — two kinds
// matching two assets, and a singleton identifier disagreeing with the asset a
// weaker kind matched. Both produce the same shape and must keep producing the
// same shape, which is why there is one body rather than two.
func (e *Engine) conflictOutcome(
	ctx context.Context,
	obs Observation,
	at time.Time,
	ids []Identifier,
	owners map[string][]AssetRef,
	r ranking,
	why string,
) (Resolution, error) {
	if e.admissionDecision != nil {
		return e.proposeWithoutCreating(ctx, obs, at, ids, r, why)
	}
	candidates, top := r.candidates, r.top
	// The conflicting identifiers belong to the candidates, so the new pending
	// asset gets only the ones nobody owns. The evidence lives on the
	// proposal, which is where a reviewer reads it.
	attach, unattached := splitByOwner(ids, owners, "")

	// The floor again (see Resolve's default branch). When EVERY identifier is
	// already owned — the common shape of a cross-kind conflict, hostname on A
	// and serial on B — the "observation asset" this would create carries none
	// at all, and an asset with no identifier can never be matched again. The
	// proposal alone is the honest record: it names the candidates and the
	// evidence, and a human settles it. The same holds when the only unowned
	// identifiers are derived ones: they never create (guard 1, Phase 2).
	if len(attach) == 0 || allInferred(attach) {
		return e.proposeWithoutCreating(ctx, obs, at, ids, r, why)
	}

	classKey, classSource, classRef, classConf := e.classForCreate(obs)
	ref, err := e.repo.CreateAsset(ctx, obs.TenantID, NewAsset{
		ClassKey:        classKey,
		ClassSourceKind: classSource,
		ClassSourceRef:  classRef,
		ClassConfidence: classConf,
		DisplayName:     displayNameFor(obs, attach),
		Hostname:        hostnameFor(obs, attach),
		PrimaryAddress:  primaryAddressFor(obs, attach),
		Status:          StatusPendingApproval,
		Ownership:       obs.Network.Ownership,
		NetworkSegment:  obs.Network.SegmentID,
		DiscoveryMethod: obs.Source.Ref,
		Confidence:      obs.Confidence,
		Source:          obs.Source,
		Identifiers:     attach,
		Endpoints:       stampEndpoints(obs.Endpoints, obs.Source, at),
		FirstSeenAt:     at,
		LastSeenAt:      at,
	})
	if err != nil {
		return Resolution{}, fmt.Errorf("identity: creating the conflicting observation as its own asset: %w", err)
	}
	if err := e.history(ctx, ref, obs, at, ActionCreated, map[string]any{
		"identifiers": identifierKeys(attach),
		"unattached":  identifierKeys(unattached),
		"conflict":    why,
	}); err != nil {
		return Resolution{}, err
	}

	proposal, err := e.openMergeProposal(ctx, obs.TenantID, r, MergeProposal{
		ObservationAssetID: ref.ID,
		Candidates:         candidates,
		Source:             obs.Source,
		Reason:             why,
		ProposedAt:         at,
		ModelID:            rankedBy(top).ModelID,
		SourceRef:          rankedBy(top).SourceRef,
		RuleVerdict:        r.ruleVerdict(),
		RuleEvidence:       r.ruleEvidence,
	})
	if err != nil {
		return Resolution{}, fmt.Errorf("identity: opening merge proposal: %w", err)
	}
	// Never reused in practice — the observation asset was just created, so
	// the fingerprint is new — but the rule is the same as the floor's, and a
	// guard that exists on one path and not the other is no guard.
	if !proposal.Reused {
		if err := e.history(ctx, ref, obs, at, ActionMergeProposed, map[string]any{
			"proposal_id": proposal.ID,
			"candidates":  candidateIDs(candidates),
			"reason":      why,
		}); err != nil {
			return Resolution{}, err
		}
	}

	return Resolution{
		Outcome:          OutcomeConflict,
		Asset:            ref,
		Candidates:       candidates,
		Proposal:         proposal,
		TopScore:         topScore(top),
		Unattached:       unattached,
		MergeRecommended: r.mergeRecommended(),
	}, nil
}

// acceptMerge is the auto-accept path: a tenant set a threshold above zero and
// a matcher scored the top candidate at or above it.
//
// The observation goes into the winning asset and the proposal is STILL
// opened, marked accepted. Two reasons. The evidence is what a human reviews
// later if the merge was wrong, and physically absorbing the losing candidates
// — moving their identifiers, endpoints, findings and edges — is the approvals
// path's job (workstream 1.3). Nothing in this package deletes or rewrites
// another asset.
func (e *Engine) acceptMerge(
	ctx context.Context,
	obs Observation,
	at time.Time,
	r ranking,
	ids []Identifier,
	owners map[string][]AssetRef,
	why string,
) (Resolution, error) {
	top, candidates := *r.top, r.candidates
	// Only identifiers unowned or already the winner's may be written. The
	// losing candidates keep theirs until the approvals path executes the
	// merge.
	attach, unattached := splitByOwner(ids, owners, top.Ref.ID)

	merged := map[string]any{
		"merged_candidates": candidateIDs(candidates),
		"score":             top.Score,
		"reason":            top.Reason,
		"conflict":          why,
	}
	if err := e.applyToAsset(ctx, top.Ref, obs, at, attach, unattached, ActionMergedFrom, merged); err != nil {
		return Resolution{}, err
	}

	proposal, err := e.openMergeProposal(ctx, obs.TenantID, r, MergeProposal{
		Candidates:        candidates,
		Source:            obs.Source,
		Reason:            why,
		ProposedAt:        at,
		ModelID:           top.modelID,
		SourceRef:         top.sourceRef,
		AutoAccepted:      true,
		AcceptedAssetID:   top.Ref.ID,
		AcceptedScore:     top.Score,
		AcceptedModelID:   top.modelID,
		AcceptedSourceRef: top.sourceRef,
		// The matcher filed the OBSERVATION into the winner; merging the two
		// existing records is a different act, and the rule's verdict (if it
		// held) is still the executor's work item.
		RuleVerdict:  r.ruleVerdict(),
		RuleEvidence: r.ruleEvidence,
	})
	if err != nil {
		return Resolution{}, fmt.Errorf("identity: opening the accepted merge proposal: %w", err)
	}
	// The same merge_proposed entry the conflict path writes. Without it the
	// auto-accept path is the ONE outcome whose history cannot be joined to its
	// proposal: `merged_from` names the candidates and the score but not the
	// row a reviewer would open, so "why is this asset like this?" dead-ends at
	// exactly the outcome a model decided. Once per proposal, as on the other
	// paths: `merged_from` above already records this observation.
	if !proposal.Reused {
		if err := e.history(ctx, top.Ref, obs, at, ActionMergeProposed, map[string]any{
			"proposal_id":   proposal.ID,
			"candidates":    candidateIDs(candidates),
			"reason":        why,
			"auto_accepted": true,
			"score":         top.Score,
			"model_id":      top.modelID,
		}); err != nil {
			return Resolution{}, err
		}
	}

	return Resolution{
		Outcome:          OutcomeMatched,
		Asset:            top.Ref,
		Candidates:       candidates,
		Proposal:         proposal,
		AutoAccepted:     true,
		TopScore:         top.Score,
		Unattached:       unattached,
		MergeRecommended: r.mergeRecommended(),
		EndpointsClosed:  closedEndpointCount(merged),
	}, nil
}

// applyToAsset is the update half of a match: attach, upsert, touch, history.
//
// An `updated` timeline row is written only when the match changed something
// about the asset ([Engine.recordIfChanged]): an identifier or endpoint the
// store reports it newly wrote, a better name, or an outcome the caller put in
// `changes`. A pure re-observation still refreshes every last-seen above; it
// just leaves the timeline alone.
func (e *Engine) applyToAsset(ctx context.Context, ref AssetRef, obs Observation, at time.Time, attach, unattached []Identifier, action HistoryAction, changes map[string]any) error {
	var added, epsChanged int
	if len(attach) > 0 {
		n, err := e.repo.AttachIdentifiers(ctx, ref, attach)
		if err != nil {
			return fmt.Errorf("identity: attaching identifiers to %s: %w", ref.ID, err)
		}
		added = n
	}
	eps := stampEndpoints(obs.Endpoints, obs.Source, at)
	if len(eps) > 0 {
		n, err := e.repo.UpsertEndpoints(ctx, ref, eps)
		if err != nil {
			return fmt.Errorf("identity: upserting endpoints on %s: %w", ref.ID, err)
		}
		epsChanged = n
	}
	if changes == nil {
		changes = map[string]any{}
	}
	// A COMPLETE set (a host's own socket table) closes this source's
	// endpoints it no longer lists, in the same transaction that wrote the
	// ones it does ( WP7 F12). Supporting evidence never gets here with
	// a set: resolveSupporting drops it.
	if set := obs.EndpointsComplete; set != nil {
		closed, err := e.repo.ReconcileSourceEndpoints(ctx, ref, set.SourcePrefix, eps, at)
		if err != nil {
			return fmt.Errorf("identity: reconciling %s's endpoints on %s: %w", set.SourcePrefix, ref.ID, err)
		}
		if len(closed) > 0 {
			changes[endpointsClosedKey] = closed
		}
	}
	if err := e.repo.Touch(ctx, ref, at); err != nil {
		return fmt.Errorf("identity: touching %s: %w", ref.ID, err)
	}
	before, err := e.repo.LoadSummaries(ctx, ref.TenantID, []string{ref.ID})
	if err != nil {
		return err
	}
	// A name belonging to another asset is not context for this one either.
	for _, id := range unattached {
		if id.Kind != KindHostname && id.Kind != KindFQDN && id.Kind != KindName {
			continue
		}
		if strings.EqualFold(obs.Hostname, id.Value) {
			obs.Hostname = ""
		}
		if strings.EqualFold(obs.DisplayName, id.Value) {
			obs.DisplayName = ""
		}
	}
	if err := e.repo.PromoteNames(ctx, ref, hostnameFor(obs, attach), hostnamequality.Best(nameCandidates(obs, attach)...), obs.Source.NameKind()); err != nil {
		return fmt.Errorf("identity: promoting names on %s: %w", ref.ID, err)
	}
	// What the caller already says about the outcome (a lease move, a
	// corroborated provisional, a floating address ...) is read BEFORE this
	// function adds its own keys below.
	changed := added > 0 || epsChanged > 0 || action != ActionUpdated || hasOutcomeKey(changes)
	after, err := e.repo.LoadSummaries(ctx, ref.TenantID, []string{ref.ID})
	if err != nil {
		return err
	}
	if len(before) == 1 && len(after) == 1 {
		if before[0].Hostname != after[0].Hostname {
			changes["hostname"] = map[string]string{"from": before[0].Hostname, "to": after[0].Hostname}
			changed = true
		}
		if before[0].DisplayName != after[0].DisplayName {
			changes["display_name"] = map[string]string{"from": before[0].DisplayName, "to": after[0].DisplayName}
			changed = true
		}
	}
	changes["identifiers"] = identifierKeys(attach)
	changes["endpoints"] = endpointKeys(eps)
	if len(unattached) > 0 {
		changes["unattached"] = identifierKeys(unattached)
	}
	// An import or a declaration listing an asset is a person's or a
	// connection's statement about it, and readers of the timeline treat "this
	// source has listed it" as a fact in its own right: the auto-scan consent
	// rule (shared/autoscan ImportedWithoutConsentSQL) lifts its withholding
	// when a spreadsheet lists an asset a connection created, even if the
	// spreadsheet's row carried nothing the asset lacked. So the FIRST listing
	// by each such source is written, once; a sensor's hundredth sighting is
	// not that kind of fact, which is why measured sources are left out.
	if (obs.Source.Kind == SourceImported || obs.Source.Kind == SourceDeclared) && obs.Source.Ref != "" {
		changes["listed_by"] = obs.Source.Ref
	}
	return e.recordIfChanged(ctx, ref, obs, at, action, changes, changed)
}

// Keys of an `updated` entry's changes that DESCRIBE how the match was made
// rather than say what it changed, or that carry per-observation noise.
// Anything else a caller puts there (`lease_moved`, `corroborated_provisional`,
// `claimed_rehomed` ...) is an outcome in its own right and always earns a row,
// so a key added later fails towards writing, not towards silence.
var descriptiveChangeKeys = map[string]bool{
	"decided_by":          true,
	"decided_by_inferred": true,
	"lease_fresh":         true,
	"supporting":          true,
	"sighting":            true,
	"observation_id":      true,
	// Written by applyToAsset itself from what the store reported.
	"identifiers": true,
	"endpoints":   true,
}

// conditionKeys are the entries that record a standing CONDITION of the
// evidence rather than a change to the asset: identifiers left unattached
// because another asset owns them, an address that floats, an observation held
// as address-only hearsay, a proposal kept separate, an import or declaration
// listing the asset (`listed_by`). They are worth one row the
// first time they appear and nothing after, so [Engine.recordIfChanged] asks
// the timeline whether it already says so.
var conditionKeys = []string{"listed_by", "unattached", "floating_address", "announces", "suppressed_proposal", "address_only_link"}

// qualifierKeys say what KIND of observation the condition was recorded under,
// so a sighting and a name-to-address answer about the same unattached
// identifiers are not mistaken for each other.
var qualifierKeys = []string{"supporting", "sighting"}

func hasOutcomeKey(changes map[string]any) bool {
	for k := range changes {
		if descriptiveChangeKeys[k] || isConditionKey(k) || k == "hostname" || k == "display_name" {
			continue
		}
		return true
	}
	return false
}

// endpointsClosedKey is the history key under which applyToAsset records the
// endpoints a complete set closed. It is an outcome, so it always earns a row.
const endpointsClosedKey = "endpoints_closed"

// closedEndpointCount reads back how many endpoints applyToAsset closed into
// changes, for the Resolution.
func closedEndpointCount(changes map[string]any) int {
	closed, _ := changes[endpointsClosedKey].([]string)
	return len(closed)
}

func isConditionKey(k string) bool {
	for _, c := range conditionKeys {
		if c == k {
			return true
		}
	}
	return false
}

// recordIfChanged writes the timeline row when the observation changed stored
// state on the asset (`changed`, decided by the caller from what the
// repository reported it wrote). When nothing changed it still writes the row
// the FIRST time a standing condition appears — see conditionKeys — and
// otherwise writes nothing: `asset_history` is the timeline people read, and a
// row per observation for a host seen every few seconds buries the few that
// say something.
func (e *Engine) recordIfChanged(ctx context.Context, ref AssetRef, obs Observation, at time.Time, action HistoryAction, changes map[string]any, changed bool) error {
	if !changed {
		memo := map[string]any{}
		hasCondition := false
		for _, k := range conditionKeys {
			if v, ok := changes[k]; ok {
				memo[k] = v
				hasCondition = true
			}
		}
		if !hasCondition {
			return nil
		}
		for _, k := range qualifierKeys {
			if v, ok := changes[k]; ok {
				memo[k] = v
			}
		}
		seen, err := e.repo.HistoryHasChange(ctx, ref, action, memo)
		if err != nil {
			return fmt.Errorf("identity: reading %s history for %s: %w", action, ref.ID, err)
		}
		if seen {
			return nil
		}
	}
	return e.history(ctx, ref, obs, at, action, changes)
}

func (e *Engine) history(ctx context.Context, ref AssetRef, obs Observation, at time.Time, action HistoryAction, changes map[string]any) error {
	if err := e.repo.RecordHistory(ctx, HistoryEntry{
		TenantID: ref.TenantID,
		AssetID:  ref.ID,
		Action:   action,
		Source:   obs.Source,
		Changes:  changes,
		At:       at,
	}); err != nil {
		return fmt.Errorf("identity: recording %s history for %s: %w", action, ref.ID, err)
	}
	return nil
}

// ranking is what one call to the matcher seam produced: the candidates in the
// order it put them, the top one when anything scored, and the summaries they
// were scored from.
//
// The summaries travel with the result because the auto-accept guard needs
// them — it refuses to merge into an asset that is not yet in service — and
// re-reading rows already in hand to answer that would be a second query whose
// answer could differ from the one the score was computed against.
type ranking struct {
	candidates []MergeCandidate
	top        *MergeCandidate
	summaries  map[string]AssetSummary

	// ruleEvidence is set when the same-device rule held for these candidates
	// and the tenant lets it merge ([Engine.withSameDeviceVerdict]); nil
	// otherwise. It rides with the ranking because it is computed from the
	// same summaries, and every tail that opens the proposal already takes one.
	ruleEvidence []string

	// pair is the matcher's score of the two top-ranked candidates against
	// each other ( Phase 5). Zero when nothing scored it.
	pair struct {
		score  float64
		ids    []string
		reason string
	}

	// observed and context are the observation side exactly as the seam saw
	// it, kept so the proposal can carry them (the lossless training export).
	observed []Identifier
	context  *MatcherSide
}

// ruleVerdict is the `rule_verdict` to stamp on the proposal: "" unless the
// same-device rule held.
func (r ranking) ruleVerdict() string {
	if r.ruleEvidence == nil {
		return ""
	}
	return RuleVerdictSameDevice
}

func (r ranking) mergeRecommended() bool { return r.ruleEvidence != nil }

// withSameDeviceVerdict evaluates the same-device rule over a ranked conflict
// ( Phase 4, owner decision D1) and records the verdict on the ranking
// when it holds and the tenant has not turned rule merges off
// ([Engine.WithAutoMergeExisting]).
//
// It decides nothing and writes nothing. The proposal is opened exactly as it
// would have been; the verdict is stamped on it and Resolution.MergeRecommended
// says so. Merging two existing assets is not something Resolve may do (guard
// rail 2): inventory-service's rule-merge executor picks the verdict up,
// re-evaluates the rule on the records as they are then, and merges through
// the audited merge path.
//
// `keptApart` is the decision-memory lookup the caller already made: ANY
// `kept_separate` decision about these candidates, whatever evidence it was
// taken on, stops the rule (guard rail 4).
func (e *Engine) withSameDeviceVerdict(obs Observation, r ranking, keptApart bool) ranking {
	if !e.autoMerge {
		return r
	}
	ok, evidence := SameDeviceVerdict(obs, r.candidates, r.summaries, SameDeviceLink{
		Direct:       DirectEvidence(obs),
		KeptSeparate: keptApart,
	})
	if ok {
		r.ruleEvidence = evidence
	}
	return r
}

// annotate stamps what ranking learned onto a proposal about to be opened: the
// pair score, the observation as the matcher saw it, and each candidate's
// snapshot. It adds EVIDENCE only — every field it sets is advisory, and no
// rule, threshold or auto-accept reads any of them (ADR-0008 D5).
func (r ranking) annotate(p MergeProposal) MergeProposal {
	if r.pair.score > 0 {
		p.PairScore, p.PairReason = r.pair.score, r.pair.reason
		p.PairAssetIDs = append([]string(nil), r.pair.ids...)
	}
	if len(r.observed) > 0 {
		p.ObservationIdentifiers = append([]Identifier(nil), r.observed...)
	}
	if r.context != nil {
		c := *r.context
		p.ObservationContext = &c
	}
	if len(r.summaries) > 0 {
		cs := make([]MergeCandidate, len(p.Candidates))
		copy(cs, p.Candidates)
		for i := range cs {
			if s, ok := r.summaries[cs[i].Ref.ID]; ok && cs[i].Snapshot == nil {
				cs[i].Snapshot = snapshotOf(s)
			}
		}
		p.Candidates = cs
	}
	return p
}

// openMergeProposal opens (or folds into) a proposal carrying what the ranking
// learned. Every engine path that opens a proposal goes through it, so the pair
// score and the training snapshot cannot exist on one conflict path and not
// another.
func (e *Engine) openMergeProposal(ctx context.Context, tenantID string, r ranking, p MergeProposal) (ProposalRef, error) {
	return e.repo.OpenMergeProposal(ctx, tenantID, r.annotate(p))
}

// snapshotOf is a candidate as the matcher compared it.
func snapshotOf(s AssetSummary) *MatcherSide {
	attrs := comparableAttributes(s.Attributes)
	vendor, _ := attrs["vendor"].(string)
	model, _ := attrs["model"].(string)
	return &MatcherSide{
		Name:        s.DisplayName,
		Class:       s.ClassKey,
		Segment:     s.NetworkSegment,
		Vendor:      vendor,
		Model:       model,
		SourceKind:  summarySourceKind(s),
		SeenAt:      s.LastSeenAt,
		Identifiers: append([]Identifier(nil), s.Identifiers...),
	}
}

// rank asks the matcher seam to score the candidates. The null matcher returns
// nothing, the candidates keep their discovery order, and every score stays
// zero — which is why the conflict path is identical with and without a model.
func (e *Engine) rank(ctx context.Context, obs Observation, at time.Time, candidates []MergeCandidate) (ranking, error) {
	if len(candidates) == 0 {
		return ranking{candidates: candidates}, nil
	}
	loaded, err := e.repo.LoadSummaries(ctx, obs.TenantID, candidateIDs(candidates))
	if err != nil {
		return ranking{}, fmt.Errorf("identity: loading merge candidates: %w", err)
	}
	summaries := make(map[string]AssetSummary, len(loaded))
	for _, s := range loaded {
		summaries[s.Ref.ID] = s
	}

	observed := seamIdentifiers(obs, at)
	seamObs := toSeamObservation(obs, at, observed)
	base := ranking{candidates: candidates, summaries: summaries, observed: observed, context: &MatcherSide{
		Name:       seamObs.Name,
		Class:      seamObs.Kind,
		Segment:    seamObs.Segment,
		Vendor:     attributeText(seamObs.Attributes, "vendor"),
		Model:      attributeText(seamObs.Attributes, "model"),
		SourceKind: seamObs.SourceKind,
		SeenAt:     seamObs.ObservedAt,
	}}

	scores, err := e.matcher.Match(ctx, seamObs, toSeamSummaries(loaded))
	if err != nil {
		// A seam that fails is a seam that made no proposal. It must not fail
		// identification: the rule-based outcome is complete without it.
		return base, nil
	}
	if len(scores) == 0 {
		return base, nil
	}
	byID := make(map[string]seams.MatchScore, len(scores))
	for _, s := range scores {
		if prev, ok := byID[s.AssetID]; ok && prev.Score >= s.Score {
			continue
		}
		byID[s.AssetID] = s
	}
	out := make([]MergeCandidate, len(candidates))
	copy(out, candidates)
	for i := range out {
		s, ok := byID[out[i].Ref.ID]
		if !ok {
			continue
		}
		out[i].Score = s.Score
		out[i].Reason = s.Reason
		out[i].Explanation = s.Explanation
		p := s.Provenance()
		out[i].modelID = p.ModelID
		out[i].sourceRef = p.SourceRef
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	r := base
	r.candidates = out
	if out[0].Score > 0 {
		top := out[0]
		r.top = &top
	}
	// A top score of zero means nothing was actually scored: no top candidate
	// is reported, so no threshold comparison can be made against a score
	// nobody produced.
	e.scorePair(ctx, &r, obs)
	return r, nil
}

// scorePair asks the matcher about the two top-ranked candidates THEMSELVES
// ( Phase 5): candidate A presented as the observation, candidate B as the
// asset. Every feature is symmetric, so which is which does not matter.
//
// When a sighting links two records — one's MAC, the other's address — the
// reviewer's real question is whether those two records are one thing, and the
// per-candidate scores answer a different one (is the SIGHTING each of them).
// The result is shown and stored; it never gates anything. A seam error, a
// candidate that could not be read, or no score at all leaves it unscored.
//
// The observation's generic-name verdicts travel with it: they are about the
// VALUE (the tenant sees it on many devices), whichever record carries it.
func (e *Engine) scorePair(ctx context.Context, r *ranking, obs Observation) {
	if len(r.candidates) < 2 {
		return
	}
	a, okA := r.summaries[r.candidates[0].Ref.ID]
	b, okB := r.summaries[r.candidates[1].Ref.ID]
	if !okA || !okB {
		return
	}
	as := toSeamSummaries([]AssetSummary{a})[0]
	scores, err := e.matcher.Match(ctx, seams.Observation{
		Kind:               as.Class,
		Identifiers:        as.Identifiers,
		DerivedIdentifiers: as.DerivedIdentifiers,
		GenericNames:       genericNames(obs.Identifiers),
		Attributes:         as.Attributes,
		ObservedAt:         as.LastSeenAt,
		Name:               as.Name,
		Segment:            as.Segment,
		SourceKind:         as.SourceKind,
	}, toSeamSummaries([]AssetSummary{b}))
	if err != nil {
		return
	}
	for _, s := range scores {
		if s.AssetID == b.Ref.ID && s.Score > 0 {
			r.pair.score, r.pair.reason = s.Score, s.Reason
			r.pair.ids = []string{a.Ref.ID, b.Ref.ID}
			return
		}
	}
}

// autoAcceptable reports whether the engine may accept the top candidate on its
// own, and why not when it may not.
//
// FOUR conditions, every one of which has to hold. They are gathered here
// rather than spread across the two conflict paths because a guard that exists
// on one path and not the other is a guard that does not exist.
//
//  1. **The tenant set a threshold above zero.** Zero is the default and means
//     never (ADR-0002 D3, ADR-0008 D5: "a rule or a human approves; a model
//     proposes"). A tenant that has not decided has decided no.
//  2. **Something scored, at or above it.**
//  3. **No singleton identifier disagrees.** ADR-0002 D3's singleton erratum is
//     categorical — "two ARNs are two resources whatever a matcher scores the
//     pair, and the auto-accept threshold does not apply". This is checked
//     against the top candidate's OWN identifiers, independently of any score,
//     so a model that scored the pair 1.0 changes nothing.
//  4. **Every candidate is already in service.** Merging into an asset still
//     in the approval queue settles, on a model's say-so, a question a human
//     has not yet been asked: whether that asset belongs in the inventory at
//     all. The approval and the merge are two decisions and this is only
//     licensed to make one of them.
func (e *Engine) autoAcceptable(ids []Identifier, r ranking) (bool, string) {
	if e.threshold <= 0 {
		return false, "the tenant's auto-accept threshold is zero, which means never"
	}
	if r.top == nil || r.top.Score < e.threshold {
		return false, fmt.Sprintf("the top score %v is below the tenant's threshold %v", topScore(r.top), e.threshold)
	}
	if kind, ok := singletonDisagreement(ids, r.summaries[r.top.Ref.ID]); ok {
		return false, fmt.Sprintf("the observation's %s disagrees with the candidate's, and an asset holds at most one", kind)
	}
	for _, c := range r.candidates {
		s, known := r.summaries[c.Ref.ID]
		if !known {
			return false, fmt.Sprintf("candidate %s could not be read", c.Ref.ID)
		}
		if s.Status != StatusMonitoring {
			return false, fmt.Sprintf("candidate %s is %s, not yet in service", c.Ref.ID, orUnknownStatus(s.Status))
		}
	}
	return true, ""
}

// singletonDisagreement reports the first singleton kind the observation and the
// summary both carry in the same scope with DIFFERENT values.
//
// It is the same comparison [Engine.singletonConflict] makes against a matched
// asset, over a summary already in hand rather than a fresh read. Both exist:
// that one guards the MATCH path, where a read is the only way to know; this one
// guards the auto-accept, where re-reading would let the answer drift from the
// rows the score was computed against.
func singletonDisagreement(ids []Identifier, summary AssetSummary) (Kind, bool) {
	held := make(map[string]Identifier, len(summary.Identifiers))
	for _, id := range summary.Identifiers {
		if id.Kind.Singleton() {
			held[string(id.Kind)+"\x00"+id.Scope] = id
		}
	}
	if len(held) == 0 {
		return "", false
	}
	for _, id := range ids {
		if !id.Kind.Singleton() {
			continue
		}
		if h, ok := held[string(id.Kind)+"\x00"+id.Scope]; ok && h.Value != id.Value {
			return id.Kind, true
		}
	}
	return "", false
}

func orUnknownStatus(s string) string {
	if s == "" {
		return "of unknown status"
	}
	return s
}

// classForCreate decides the class of a new asset (ADR-0002 D1), and how it came
// to be decided.
//
// The provenance is the observation's own unless it says otherwise. A collector
// that formed its own opinion is speaking with the authority of the measurement
// it took; the rule engine is not, and an intake that classified through it says
// so by setting [Observation.ClassProvenance] — which is what makes
// `class_source_kind = 'rule'` and a `class_source_ref` naming the rule row
// possible at all (workstream 2.10b).
//
// The FALLBACK class never carries the rule provenance, whatever the observation
// asked for. `unknown_host` is what we call a thing no rule decided; stamping it
// `rule` would claim a rule argued for not knowing.
func (e *Engine) classForCreate(obs Observation) (class string, kind ClassSourceKind, ref string, confidence float64) {
	kind, ref, confidence = ClassSourceFrom(obs.Source.Kind), obs.Source.Ref, classConfidence(obs)
	if p := obs.ClassProvenance; !p.IsZero() {
		if p.Kind != "" {
			kind = p.Kind
		}
		if p.Ref != "" {
			ref = p.Ref
		}
		if p.Confidence > 0 {
			confidence = p.Confidence
		}
	}
	if hint := hintedClass(obs.ClassHint); hint != "" {
		return hint, kind, ref, confidence
	}
	// No usable hint. `external` when the address is outside the tenant's
	// owned space, `unknown_host` when inside — and confidence 0, because
	// nothing classified this. Zero is NOT ASSESSED, the same distinction the
	// risk score and the PQC `unclassified` bucket keep.
	return fallbackClass(obs), ClassSourceFrom(obs.Source.Kind), obs.Source.Ref, 0
}

func fallbackClass(obs Observation) string {
	if obs.Network.IsExternal() {
		return assetclass.KeyExternal
	}
	return assetclass.KeyUnknownHost
}

// hintedClass returns the trimmed class hint, or "" when there is none.
//
// A hint the generated registry does not carry is deliberately still honoured:
// a tenant leaf subclass is a runtime row (ADR-0002 D2) and is not in the
// generated hierarchy. The class column is an FK-by-value to `asset_classes`,
// so a hint naming nothing at all is rejected by the store rather than
// silently downgraded here — a downgrade would hide the caller's bug.
func hintedClass(hint string) string {
	return strings.TrimSpace(hint)
}

func classConfidence(obs Observation) float64 {
	if obs.Confidence > 0 {
		return obs.Confidence
	}
	// A hint with no stated confidence from a measurement is a measurement's
	// claim; from an import it is the exporter's. Either way the caller did
	// not quantify it, so neither do we.
	return 0
}

// ── helpers ────────────────────────────────────────────────────────────────

// identifierSource is the provenance an identifier is stored with: the
// observation's, unless the caller marked the identifier as derived
// ([Identifier.Inferred]) — the one per-identifier provenance the engine
// honours, because it only ever WEAKENS the claim. A derived identifier with no
// ref of its own falls back to the observation's ref, so it still names a
// producer.
func identifierSource(raw Identifier, obs Source) Source {
	if !raw.Inferred() {
		// A LOWER stated provenance is honoured too: an Add device
		// sighting is declared, but the MAC its probe read off the device is
		// a measurement, and storing it as declared would claim a person
		// typed it. Never a higher one: an identifier cannot out-rank the
		// observation that carried it.
		if k := raw.Source.Kind; k != "" && k.Valid() && SourceRank(k) < SourceRank(obs.Kind) {
			src := obs
			src.Kind = k
			if ref := strings.TrimSpace(raw.Source.Ref); ref != "" {
				src.Ref = ref
			}
			return src
		}
		return obs
	}
	src := Source{Kind: SourceInferred, Ref: strings.TrimSpace(raw.Source.Ref), Mode: obs.Mode}
	if src.Ref == "" {
		src.Ref = obs.Ref
	}
	return src
}

// allInferred reports whether every identifier is a derived one. False for an
// empty list: "nothing" is the floor's question, not this one.
func allInferred(ids []Identifier) bool {
	if len(ids) == 0 {
		return false
	}
	for _, id := range ids {
		if !id.Inferred() {
			return false
		}
	}
	return true
}

func dedupeIdentifiers(ids []Identifier) []Identifier {
	seen := make(map[string]int, len(ids))
	out := make([]Identifier, 0, len(ids))
	for _, id := range ids {
		if i, ok := seen[id.Key()]; ok {
			if id.Confidence > out[i].Confidence {
				out[i].Confidence = id.Confidence
			}
			// Generic is a judgement about the VALUE ( B2), so one copy
			// marked generic makes the name generic; keeping only the first
			// copy's flag would let an unmarked duplicate vote.
			out[i].Generic = out[i].Generic || id.Generic
			if out[i].Generic && out[i].Confidence > GenericConfidence {
				out[i].Confidence = GenericConfidence
			}
			// The same value observed AND derived is an observed value: keep
			// the native provenance, whichever arrived first.
			if out[i].Inferred() && !id.Inferred() {
				out[i].Source = id.Source
			}
			if out[i].KeyAlgorithm == "" {
				out[i].KeyAlgorithm = id.KeyAlgorithm
			}
			out[i].Pinned = out[i].Pinned || id.Pinned
			out[i].Claimed = out[i].Claimed || id.Claimed
			continue
		}
		seen[id.Key()] = len(out)
		out = append(out, id)
	}
	return out
}

// groupByKind buckets identifiers by kind for the precedence walk. Within a
// kind, NATIVE identifiers come before inferred ones (stable otherwise): the
// walk's "first match decides" then gives guard 2 of Phase 2 — a derived
// value decides only when no observed value of its kind matched anything, and
// otherwise may only corroborate or conflict.
func groupByKind(ids []Identifier) map[Kind][]Identifier {
	out := make(map[Kind][]Identifier, len(ids))
	for _, id := range ids {
		out[id.Kind] = append(out[id.Kind], id)
	}
	for k, list := range out {
		sort.SliceStable(list, func(i, j int) bool { return !list[i].Inferred() && list[j].Inferred() })
		out[k] = list
	}
	return out
}

// ownerSet is the set of asset ids that own at least one of the observation's
// identifiers.
func ownerSet(owners map[string][]AssetRef) map[string]bool {
	claimed := map[string]bool{}
	for _, refs := range owners {
		for _, ref := range refs {
			claimed[ref.ID] = true
		}
	}
	return claimed
}

// splitByOwner divides identifiers into the ones it is legal to write against
// target (unowned, or already the target's) and the ones that belong to
// somebody else.
func splitByOwner(ids []Identifier, owners map[string][]AssetRef, target string) (attach, unattached []Identifier) {
	for _, id := range ids {
		refs := owners[id.Key()]
		foreign := false
		for _, r := range refs {
			if r.ID != target {
				foreign = true
				break
			}
		}
		if foreign {
			unattached = append(unattached, id)
			continue
		}
		attach = append(attach, id)
	}
	return attach, unattached
}

func stampEndpoints(eps []EndpointObservation, src Source, at time.Time) []EndpointObservation {
	if len(eps) == 0 {
		return nil
	}
	out := make([]EndpointObservation, 0, len(eps))
	seen := make(map[string]bool, len(eps))
	for _, ep := range eps {
		// Defense in depth: [Observation.Sanitize] already does this for a
		// caller that ran it, but stampEndpoints is the one funnel every
		// endpoint passes through on the way to [Repository.UpsertEndpoints]
		// regardless — Engine.Resolve does not require Sanitize to have been
		// called first (Sanitize's own strictness is about identifiers, which
		// DO error; an endpoint never does). An IP literal left in FQDN here
		// would otherwise survive to become a second row for an address
		// already recorded.
		ep = ep.Sanitized()
		if ep.Address == "" && ep.FQDN == "" {
			continue
		}
		if ep.Transport == "" {
			ep.Transport = "none"
		}
		if ep.Source.Ref == "" {
			ep.Source = src
		}
		if ep.SeenAt.IsZero() {
			ep.SeenAt = at
		}
		if seen[ep.Key()] {
			continue
		}
		seen[ep.Key()] = true
		out = append(out, ep)
	}
	return out
}

func displayNameFor(obs Observation, ids []Identifier) string {
	if picked := hostnamequality.Best(nameCandidates(obs, ids)...); picked != "" {
		return picked
	}
	for _, want := range []Kind{KindCloudResourceID, KindSerialNumber, KindIPAddress} {
		for _, id := range ids {
			if id.Kind == want {
				return id.Value
			}
		}
	}
	for _, ep := range obs.Endpoints {
		if ep.FQDN != "" {
			return ep.FQDN
		}
		if ep.Address != "" {
			return ep.Address
		}
	}
	return "unidentified"
}

func hostnameFor(obs Observation, ids []Identifier) string {
	obs.DisplayName = "" // display aliases are not hostnames
	return hostnamequality.BestHostname(nameCandidates(obs, ids)...)
}

func nameCandidates(obs Observation, ids []Identifier) []string {
	out := make([]string, 0, 4+len(ids))
	if obs.DisplayName != "" {
		out = append(out, obs.DisplayName)
	}
	if obs.Hostname != "" {
		out = append(out, obs.Hostname)
	}
	for _, id := range ids {
		switch id.Kind {
		case KindFQDN, KindHostname, KindName:
			out = append(out, id.Value)
		}
	}
	return out
}

func primaryAddressFor(obs Observation, ids []Identifier) string {
	for _, id := range ids {
		if id.Kind == KindIPAddress {
			return id.Value
		}
	}
	for _, ep := range obs.Endpoints {
		if ep.Address != "" {
			return ep.Address
		}
	}
	return ""
}

func identifierKeys(ids []Identifier) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.Key())
	}
	return out
}

func endpointKeys(eps []EndpointObservation) []string {
	out := make([]string, 0, len(eps))
	for _, ep := range eps {
		out = append(out, ep.Key())
	}
	return out
}

func candidateIDs(cs []MergeCandidate) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Ref.ID)
	}
	return out
}

func topScore(top *MergeCandidate) float64 {
	if top == nil {
		return 0
	}
	return top.Score
}

// rankedBy is the provenance of whatever ranked a proposal: the top candidate's
// matcher, or empty when nothing scored. Empty is not a model called unknown.
func rankedBy(top *MergeCandidate) (p struct{ ModelID, SourceRef string }) {
	if top == nil {
		return p
	}
	p.ModelID, p.SourceRef = top.modelID, top.sourceRef
	return p
}

// seamIdentifiers is the observation's identifiers as the matcher is shown
// them: normalised (so they compare equal to what a candidate stored — the
// engine only ever stores normalised values), provenance resolved the way the
// engine records it, duplicates folded. One that does not normalise is left
// out: Resolve has already refused such an observation, so this only drops
// what the rules would not have used either.
func seamIdentifiers(obs Observation, at time.Time) []Identifier {
	out := make([]Identifier, 0, len(obs.Identifiers))
	for _, raw := range obs.Identifiers {
		n, err := raw.Normalized()
		if err != nil {
			continue
		}
		n.Source = identifierSource(raw, obs.Source)
		if n.SeenAt.IsZero() {
			n.SeenAt = at
		}
		out = append(out, n)
	}
	return dedupeIdentifiers(out)
}

// seamIdentifierMaps spells identifiers the way the seam carries them: every
// value per kind, plus the subset that was derived rather than observed.
func seamIdentifierMaps(ids []Identifier) (all, derived map[string][]string) {
	all = make(map[string][]string, len(ids))
	for _, id := range ids {
		k := string(id.Kind)
		all[k] = append(all[k], id.Value)
		if id.Inferred() {
			if derived == nil {
				derived = map[string][]string{}
			}
			derived[k] = append(derived[k], id.Value)
		}
	}
	return all, derived
}

// genericNames lists the hostnames the intake marked generic ( B2).
func genericNames(ids []Identifier) []string {
	var out []string
	for _, id := range ids {
		if id.Generic && id.Kind == KindHostname {
			out = append(out, id.Value)
		}
	}
	return out
}

// attributeText reads one attribute as a string, "" for anything else — the
// same reading the matcher's adapter makes.
func attributeText(attrs map[string]any, key string) string {
	s, _ := attrs[key].(string)
	return s
}

func toSeamObservation(obs Observation, at time.Time, observed []Identifier) seams.Observation {
	ids, derived := seamIdentifierMaps(observed)
	observedAt := obs.ObservedAt
	if observedAt.IsZero() {
		// The engine already resolved "when" for every write it makes; handing
		// the matcher a zero time instead would make its recency feature read
		// "unknown" on every observation that arrived without a timestamp,
		// which is most of the manual ones.
		observedAt = at
	}
	return seams.Observation{
		Kind:               obs.ClassHint,
		Identifiers:        ids,
		DerivedIdentifiers: derived,
		GenericNames:       genericNames(observed),
		Attributes:         comparableAttributes(obs.Attributes),
		ObservedAt:         observedAt,
		Name:               displayNameFor(obs, obs.Identifiers),
		Segment:            obs.Network.SegmentID,
		SourceKind:         string(obs.Source.Kind),
	}
}

// toSeamSummaries converts candidates for the seam. Every identifier value is
// carried (v1 kept one per kind — whichever it met last — so a candidate whose
// SECOND MAC agreed with the observation scored as a disagreement), and the ones
// the asset holds as derived are named.
func toSeamSummaries(in []AssetSummary) []seams.AssetSummary {
	out := make([]seams.AssetSummary, 0, len(in))
	for _, s := range in {
		ids, derived := seamIdentifierMaps(s.Identifiers)
		out = append(out, seams.AssetSummary{
			ID:                 s.Ref.ID,
			Class:              s.ClassKey,
			Name:               s.DisplayName,
			Identifiers:        ids,
			DerivedIdentifiers: derived,
			Attributes:         comparableAttributes(s.Attributes),
			Segment:            s.NetworkSegment,
			SourceKind:         summarySourceKind(s),
			Status:             s.Status,
			LastSeenAt:         s.LastSeenAt,
		})
	}
	return out
}

// comparableAttributes narrows an attribute map to [SummaryAttributeKeys].
//
// It is a copy and an allowlist, not a pass-through. A seam gets what it needs
// to score a candidate, not the tenant's inventory — and an attribute map from
// a cloud collector is exactly the kind of object that has previously carried a
// PSK into a table nobody read ("collect posture, never key material").
func comparableAttributes(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	var out map[string]any
	for _, k := range SummaryAttributeKeys {
		v, ok := in[k]
		if !ok {
			continue
		}
		if out == nil {
			out = make(map[string]any, len(SummaryAttributeKeys))
		}
		out[k] = v
	}
	return out
}

// summarySourceKind is the provenance that supplied an asset's identifiers: the
// most common source kind among them.
//
// Most common rather than first, because the order LoadSummaries returns is the
// store's, and "whichever identifier sorted first" is not a fact about the
// asset. Ties break towards the earlier kind in the ADR-0005 vocabulary, so the
// answer does not depend on map iteration order.
func summarySourceKind(s AssetSummary) string {
	counts := map[SourceKind]int{}
	for _, id := range s.Identifiers {
		if id.Source.Kind != "" {
			counts[id.Source.Kind]++
		}
	}
	best, bestN := SourceKind(""), 0
	for _, kind := range []SourceKind{SourceMeasured, SourceImported, SourceDeclared, SourceInferred} {
		if counts[kind] > bestN {
			best, bestN = kind, counts[kind]
		}
	}
	return string(best)
}
