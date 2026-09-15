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
	OutcomeConflict Outcome = "conflict"
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
	Outcome Outcome `json:"outcome"`

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
}

// Config configures an [Engine].
type Config struct {
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

	// DynamicScopes is the set of scope ids (network segments) whose addresses
	// are handed out dynamically. An ip_address never matches within one:
	// today's DHCP lease is tomorrow's other host, and matching on it merges
	// two machines (ADR-0002 D3).
	DynamicScopes map[string]bool

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
	repo      Repository
	matcher   seams.Matcher
	threshold float64
	dynamic   map[string]bool
	prec      func(ctx context.Context, tenantID, classKey string) ([]Kind, bool)
	now       func() time.Time
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
		repo:      cfg.Repo,
		matcher:   cfg.Matcher,
		threshold: cfg.AutoAcceptThreshold,
		dynamic:   cfg.DynamicScopes,
		prec:      cfg.Precedence,
		now:       cfg.Now,
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
func (e *Engine) Resolve(ctx context.Context, obs Observation) (Resolution, error) {
	if strings.TrimSpace(obs.TenantID) == "" {
		return Resolution{}, fmt.Errorf("%w: no tenant", ErrInvalidObservation)
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
		n.Source = obs.Source
		if n.SeenAt.IsZero() {
			n.SeenAt = at
		}
		ids = append(ids, n)
	}
	ids = dedupeIdentifiers(ids)

	// Step 2: ownership of every identifier present, keyed by identifier key.
	owners := make(map[string][]AssetRef, len(ids))
	for _, id := range ids {
		refs, err := e.repo.FindByIdentifier(ctx, obs.TenantID, id.Kind, id.Value, id.Scope)
		if err != nil {
			return Resolution{}, fmt.Errorf("identity: looking up %s=%q: %w", id.Kind, id.Value, err)
		}
		owners[id.Key()] = refs
	}

	// Step 3: the precedence walk.
	precedence := e.precedenceFor(ctx, obs.TenantID, obs.ClassHint)
	byKind := groupByKind(ids)

	var (
		decided      string
		decidedBy    Kind
		conflicting  bool
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

	for _, kind := range precedence {
		for _, id := range byKind[kind] {
			if !e.kindVotes(obs, id) {
				continue
			}
			refs := owners[id.Key()]
			if len(refs) == 0 {
				continue
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
				conflictWhy = fmt.Sprintf("%s=%q resolves to %d assets", id.Kind, id.Value, len(refs))
				continue
			}
			switch {
			case decided == "":
				// The highest-precedence kind that matched. It decides.
				decided = refs[0].ID
				decidedBy = kind
			case decided != refs[0].ID:
				conflicting = true
				if conflictWhy == "" {
					conflictWhy = fmt.Sprintf("%s matched one asset and %s another", decidedBy, id.Kind)
				}
			}
		}
	}

	switch {
	case conflicting:
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

		// Identifiers owned by another asset cannot be written here: one
		// identifier value, at most one asset.
		attach, unattached := splitByOwner(ids, owners, decided)
		if err := e.applyToAsset(ctx, ref, obs, at, attach, unattached, ActionUpdated, map[string]any{
			"decided_by": string(decidedBy),
		}); err != nil {
			return Resolution{}, err
		}
		return Resolution{
			Outcome:    OutcomeMatched,
			Asset:      ref,
			DecidedBy:  decidedBy,
			Unattached: unattached,
		}, nil
	default:
		// Nothing DECIDED. That is not the same as nothing being known, and the
		// difference is the floor below.
		attach, unattached := splitByOwner(ids, owners, "")
		if len(attach) > 0 {
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
			// a dynamic segment. We know the observation is related to those
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
	candidates := make([]MergeCandidate, 0, len(candidateSeq))
	for _, id := range candidateSeq {
		candidates = append(candidates, MergeCandidate{
			Ref:                AssetRef{TenantID: obs.TenantID, ID: id},
			MatchedIdentifiers: evidence[id],
		})
	}
	why := fmt.Sprintf("every identifier this observation carries already belongs to another asset, and none of them may decide for class %q", obs.ClassHint)

	r, err := e.rank(ctx, obs, at, candidates)
	if err != nil {
		return Resolution{}, err
	}

	// An auto-accept threshold a tenant deliberately set still applies: the
	// observation goes into the winner rather than nowhere.
	if ok, _ := e.autoAcceptable(ids, r); ok {
		return e.acceptMerge(ctx, obs, at, *r.top, r.candidates, ids, owners, why)
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
	proposal, err := e.repo.OpenMergeProposal(ctx, obs.TenantID, MergeProposal{
		Candidates: candidates,
		Source:     obs.Source,
		Reason:     why,
		ProposedAt: at,
		ModelID:    rankedBy(top).ModelID,
		SourceRef:  rankedBy(top).SourceRef,
	})
	if err != nil {
		return Resolution{}, fmt.Errorf("identity: opening the merge proposal for a fully-owned observation: %w", err)
	}
	if err := e.history(ctx, candidates[0].Ref, obs, at, ActionMergeProposed, map[string]any{
		"proposal_id": proposal.ID,
		"candidates":  candidateIDs(candidates),
		"reason":      why,
		"contested":   identifierKeys(ids),
		"created":     false,
	}); err != nil {
		return Resolution{}, err
	}
	return Resolution{
		Outcome:    OutcomeConflict,
		Candidates: candidates,
		Proposal:   proposal,
		TopScore:   topScore(top),
		Unattached: ids,
	}, nil
}

// kindVotes reports whether an identifier may decide a match, as opposed to
// merely being recorded. The two scope rules of ADR-0002 D3 live here.
//
// The empty-scope guard is belt and braces: [Identifier.Normalized] gives every
// scoped kind [ScopeTenantDefault] when the caller supplied nothing, so this
// should be unreachable. It stays because the consequence of reaching it —
// silently, on one kind, in one intake path — was three assets for one host.
func (e *Engine) kindVotes(obs Observation, id Identifier) bool {
	if id.Kind.RequiresScope() && id.Scope == "" {
		return false
	}
	if id.Kind == KindIPAddress && (e.dynamic[id.Scope] || obs.DynamicScopes[id.Scope]) {
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

func (e *Engine) resolveCreate(ctx context.Context, obs Observation, at time.Time, attach, unattached []Identifier) (Resolution, error) {
	// The floor, restated at the only place that creates. Resolve's default
	// branch already routes an empty attach elsewhere; this is here so a future
	// caller cannot reach the INSERT without one, because an asset with no
	// identifier is the one thing this package must never write.
	if len(attach) == 0 {
		return Resolution{}, fmt.Errorf("%w: refusing to create an asset with no identifier", ErrNoUsableIdentifier)
	}
	classKey, classSource, classRef, classConf := e.classForCreate(obs)
	newAsset := NewAsset{
		ClassKey:        classKey,
		ClassSourceKind: classSource,
		ClassSourceRef:  classRef,
		ClassConfidence: classConf,
		DisplayName:     displayNameFor(obs, attach),
		Hostname:        obs.Hostname,
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
	if err := e.history(ctx, ref, obs, at, ActionCreated, map[string]any{
		"class_key":   classKey,
		"identifiers": identifierKeys(attach),
		"endpoints":   endpointKeys(newAsset.Endpoints),
		"unattached":  identifierKeys(unattached),
	}); err != nil {
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
	candidates := make([]MergeCandidate, 0, len(candidateSeq))
	for _, id := range candidateSeq {
		candidates = append(candidates, MergeCandidate{
			Ref:                AssetRef{TenantID: obs.TenantID, ID: id},
			MatchedIdentifiers: evidence[id],
		})
	}

	// The matcher seam ranks; it does not decide. A null matcher leaves every
	// score at zero and the order as found, and the proposal is identical.
	r, err := e.rank(ctx, obs, at, candidates)
	if err != nil {
		return Resolution{}, err
	}

	if ok, _ := e.autoAcceptable(ids, r); ok {
		return e.acceptMerge(ctx, obs, at, *r.top, r.candidates, ids, owners, why)
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
	// evidence, and a human settles it.
	if len(attach) == 0 {
		return e.proposeWithoutCreating(ctx, obs, at, ids, r, why)
	}

	classKey, classSource, classRef, classConf := e.classForCreate(obs)
	ref, err := e.repo.CreateAsset(ctx, obs.TenantID, NewAsset{
		ClassKey:        classKey,
		ClassSourceKind: classSource,
		ClassSourceRef:  classRef,
		ClassConfidence: classConf,
		DisplayName:     displayNameFor(obs, attach),
		Hostname:        obs.Hostname,
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

	proposal, err := e.repo.OpenMergeProposal(ctx, obs.TenantID, MergeProposal{
		ObservationAssetID: ref.ID,
		Candidates:         candidates,
		Source:             obs.Source,
		Reason:             why,
		ProposedAt:         at,
		ModelID:            rankedBy(top).ModelID,
		SourceRef:          rankedBy(top).SourceRef,
	})
	if err != nil {
		return Resolution{}, fmt.Errorf("identity: opening merge proposal: %w", err)
	}
	if err := e.history(ctx, ref, obs, at, ActionMergeProposed, map[string]any{
		"proposal_id": proposal.ID,
		"candidates":  candidateIDs(candidates),
		"reason":      why,
	}); err != nil {
		return Resolution{}, err
	}

	return Resolution{
		Outcome:    OutcomeConflict,
		Asset:      ref,
		Candidates: candidates,
		Proposal:   proposal,
		TopScore:   topScore(top),
		Unattached: unattached,
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
	top MergeCandidate,
	candidates []MergeCandidate,
	ids []Identifier,
	owners map[string][]AssetRef,
	why string,
) (Resolution, error) {
	// Only identifiers unowned or already the winner's may be written. The
	// losing candidates keep theirs until the approvals path executes the
	// merge.
	attach, unattached := splitByOwner(ids, owners, top.Ref.ID)

	if err := e.applyToAsset(ctx, top.Ref, obs, at, attach, unattached, ActionMergedFrom, map[string]any{
		"merged_candidates": candidateIDs(candidates),
		"score":             top.Score,
		"reason":            top.Reason,
		"conflict":          why,
	}); err != nil {
		return Resolution{}, err
	}

	proposal, err := e.repo.OpenMergeProposal(ctx, obs.TenantID, MergeProposal{
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
	})
	if err != nil {
		return Resolution{}, fmt.Errorf("identity: opening the accepted merge proposal: %w", err)
	}
	// The same merge_proposed entry the conflict path writes. Without it the
	// auto-accept path is the ONE outcome whose history cannot be joined to its
	// proposal: `merged_from` names the candidates and the score but not the
	// row a reviewer would open, so "why is this asset like this?" dead-ends at
	// exactly the outcome a model decided.
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

	return Resolution{
		Outcome:      OutcomeMatched,
		Asset:        top.Ref,
		Candidates:   candidates,
		Proposal:     proposal,
		AutoAccepted: true,
		TopScore:     top.Score,
		Unattached:   unattached,
	}, nil
}

// applyToAsset is the update half of a match: attach, upsert, touch, history.
func (e *Engine) applyToAsset(ctx context.Context, ref AssetRef, obs Observation, at time.Time, attach, unattached []Identifier, action HistoryAction, changes map[string]any) error {
	if len(attach) > 0 {
		if err := e.repo.AttachIdentifiers(ctx, ref, attach); err != nil {
			return fmt.Errorf("identity: attaching identifiers to %s: %w", ref.ID, err)
		}
	}
	eps := stampEndpoints(obs.Endpoints, obs.Source, at)
	if len(eps) > 0 {
		if err := e.repo.UpsertEndpoints(ctx, ref, eps); err != nil {
			return fmt.Errorf("identity: upserting endpoints on %s: %w", ref.ID, err)
		}
	}
	if err := e.repo.Touch(ctx, ref, at); err != nil {
		return fmt.Errorf("identity: touching %s: %w", ref.ID, err)
	}
	if changes == nil {
		changes = map[string]any{}
	}
	changes["identifiers"] = identifierKeys(attach)
	changes["endpoints"] = endpointKeys(eps)
	if len(unattached) > 0 {
		changes["unattached"] = identifierKeys(unattached)
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

	scores, err := e.matcher.Match(ctx, toSeamObservation(obs, at), toSeamSummaries(loaded))
	if err != nil {
		// A seam that fails is a seam that made no proposal. It must not fail
		// identification: the rule-based outcome is complete without it.
		return ranking{candidates: candidates, summaries: summaries}, nil
	}
	if len(scores) == 0 {
		return ranking{candidates: candidates, summaries: summaries}, nil
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
	r := ranking{candidates: out, summaries: summaries}
	if out[0].Score > 0 {
		top := out[0]
		r.top = &top
	}
	// A top score of zero means nothing was actually scored: no top candidate
	// is reported, so no threshold comparison can be made against a score
	// nobody produced.
	return r, nil
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

func dedupeIdentifiers(ids []Identifier) []Identifier {
	seen := make(map[string]int, len(ids))
	out := make([]Identifier, 0, len(ids))
	for _, id := range ids {
		if i, ok := seen[id.Key()]; ok {
			if id.Confidence > out[i].Confidence {
				out[i].Confidence = id.Confidence
			}
			continue
		}
		seen[id.Key()] = len(out)
		out = append(out, id)
	}
	return out
}

func groupByKind(ids []Identifier) map[Kind][]Identifier {
	out := make(map[Kind][]Identifier, len(ids))
	for _, id := range ids {
		out[id.Kind] = append(out[id.Kind], id)
	}
	return out
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
	if obs.DisplayName != "" {
		return obs.DisplayName
	}
	if obs.Hostname != "" {
		return obs.Hostname
	}
	for _, want := range []Kind{KindFQDN, KindHostname, KindCloudResourceID, KindSerialNumber, KindIPAddress} {
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

func toSeamObservation(obs Observation, at time.Time) seams.Observation {
	ids := make(map[string]string, len(obs.Identifiers))
	for _, id := range obs.Identifiers {
		ids[string(id.Kind)] = id.Value
	}
	observedAt := obs.ObservedAt
	if observedAt.IsZero() {
		// The engine already resolved "when" for every write it makes; handing
		// the matcher a zero time instead would make its recency feature read
		// "unknown" on every observation that arrived without a timestamp,
		// which is most of the manual ones.
		observedAt = at
	}
	return seams.Observation{
		Kind:        obs.ClassHint,
		Identifiers: ids,
		Attributes:  comparableAttributes(obs.Attributes),
		ObservedAt:  observedAt,
		Name:        displayNameFor(obs, obs.Identifiers),
		Segment:     obs.Network.SegmentID,
		SourceKind:  string(obs.Source.Kind),
	}
}

func toSeamSummaries(in []AssetSummary) []seams.AssetSummary {
	out := make([]seams.AssetSummary, 0, len(in))
	for _, s := range in {
		ids := make(map[string]string, len(s.Identifiers))
		for _, id := range s.Identifiers {
			ids[string(id.Kind)] = id.Value
		}
		out = append(out, seams.AssetSummary{
			ID:          s.Ref.ID,
			Class:       s.ClassKey,
			Name:        s.DisplayName,
			Identifiers: ids,
			Attributes:  comparableAttributes(s.Attributes),
			Segment:     s.NetworkSegment,
			SourceKind:  summarySourceKind(s),
			Status:      s.Status,
			LastSeenAt:  s.LastSeenAt,
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
