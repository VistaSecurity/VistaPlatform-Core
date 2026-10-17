// Package memory is an in-memory [identity.Repository].
//
// It exists for two jobs. It is what the engine's own tests run against, so
// the identification rules of ADR-0002 D3 are tested without a database; and
// it is the reference the Postgres implementation of workstream 1.2 is
// compared to, through identitytest.RunRepositoryContract, which both must
// pass.
//
// It enforces the one invariant the SQL side gets from a unique index — an
// identifier value maps to at most one asset per tenant (DATA_MODEL §2) — and
// returns the same [identity.ErrIdentifierConflict] the SQL side will. A fake
// that is more permissive than the real store is a test that proves nothing.
package memory

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/hostnamequality"
)

// Repository is an in-memory asset store. The zero value is not usable; build
// one with [New]. It is safe for concurrent use.
type Repository struct {
	mu sync.Mutex

	seq     int
	assets  map[string]*asset                 // tenant|id
	owners  map[string]identity.AssetRef      // tenant|kind|value|scope → owner
	history []identity.HistoryEntry           // append-only
	props   map[string]identity.MergeProposal // tenant|id
	propSeq []string                          // proposal ids in creation order
	// propState is a proposal's resolution: absent means pending. Only
	// [Repository.ResolveProposal] — a test hook standing in for the approvals
	// path — writes it, exactly as only the approvals service stamps the SQL
	// row.
	propState map[string]proposalState // tenant|id

	// announcements are the floating-address edges
	// [Repository.RecordAnnouncement] wrote, keyed tenant|announcer|holder,
	// in first-observation order.
	announcements map[string]*identity.AnnouncementRecord
	announceSeq   []string

	// multi holds the extra owners [Repository.Corrupt] planted, so a lost
	// uniqueness invariant can be simulated. Always empty in normal use.
	multi []multiOwner

	// tlsCerts are the leaf certificate fingerprints
	// [Repository.SetTLSCertificates] recorded, keyed tenant|asset.
	tlsCerts map[string][]string

	// prefixes are the tenant's IPAM prefixes ([Repository.AddPrefix],
	// [Repository.AddSegment]) for [Repository.ScopeForAddress]. Empty is the
	// normal state and the interesting one: a tenant with no prefixes must
	// still get a usable scope.
	prefixes map[string][]identity.NetworkSegment

	// posture is each prefix's DHCP posture, keyed tenant|scope; absent is
	// "nobody has said" (`prefixes.dhcp_managed IS NULL`).
	posture map[string]bool
	// learned marks a prefix a collector reported rather than a person
	// declared, keyed tenant|scope ([Repository.AddLearnedPrefix]).
	learned map[string]bool

	// unassigned are addresses an IPAM row holds with no interface
	// ([Repository.AddUnassignedAddress]): they name no asset.
	unassigned map[string]bool

	// provScopes is the answer [Repository.ProvisionalScope] gives for a
	// segment, keyed tenant|segment. Written through
	// [Repository.SetProvisionalScope]; an ABSENT segment is not eligible,
	// which is the same default the engine applies to a repository that cannot
	// answer the question at all.
	provScopes map[string]ProvisionalScopeAnswer

	// IDFunc generates asset and proposal ids. Nil means a deterministic
	// counter, which keeps test failures readable.
	IDFunc func(prefix string, n int) string
}

// ProvisionalScopeAnswer is one segment's eligibility for provisional asset
// creation, as [Repository.ProvisionalScope] will report it.
type ProvisionalScopeAnswer struct {
	Eligible bool
	// Reason is one of the identity package's reason constants and is what the
	// observation records when Eligible is false. It is ignored when eligible.
	Reason string
}

type asset struct {
	ref            identity.AssetRef
	classKey       string
	classConf      float64
	displayName    string
	hostname       string
	nameSourceKind string
	status         string
	// identityStatus mirrors `assets.identity_status`. Empty is the column's
	// default, `legacy`; [Repository.LoadSummaries] reports it so the engine's
	// corroboration rules can see that an asset is a guess ( D3).
	identityStatus string
	identifiers    map[string]identity.Identifier // identifier key → identifier
	identOrder     []string
	endpoints      map[string]identity.EndpointObservation
	epOrder        []string
	// closedEndpoints are the endpoint keys ReconcileSourceEndpoints closed
	// (`asset_endpoints.status = 'closed'`); an upsert reopens one.
	closedEndpoints map[string]bool
	firstSeen       time.Time
	lastSeen        time.Time
	// segment and attributes travel with the asset because a merge candidate's
	// SUMMARY carries them (identity.AssetSummary): the matcher seam compares
	// the segment and the comparable class attributes, and a fake that cannot
	// return them would make every engine test score as if a real store had no
	// segments at all.
	segment    string
	attributes map[string]any

	// ifaces are the asset's interfaces (DCIM row 1.4): where its MACs and
	// addresses are filed, by [identity.ResolveInterfaces] — the same rule the
	// SQL store applies — so the contract can read both back the same way.
	ifaces []identity.StoredInterface
}

// SetAttributes records the comparable class attributes of an existing asset.
//
// A test helper, and deliberately not part of CreateAsset: the engine does not
// write `assets.attributes` (reconciling an attribute against what the asset
// already holds is ADR-0002 D4's job and belongs to the intake path), so a fake
// whose create wrote them would let a test pass through a path production does
// not have. It exists because the merge candidate's SUMMARY carries vendor and
// model for the matcher to compare, and a test of that needs a way to put them
// there.
func (r *Repository) SetAttributes(ref identity.AssetRef, attrs map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]; ok {
		a.attributes = attrs
	}
}

// SetStatus moves an existing asset to a status. Also a test helper: the engine
// only ever writes `pending_approval`, and promotion to `monitoring` is the
// approvals path's job — but the auto-accept guard refuses to merge into
// anything NOT promoted, so a test of it has to be able to promote.
func (r *Repository) SetStatus(ref identity.AssetRef, status string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]; ok {
		a.status = status
	}
}

// SetIdentityStatus moves an existing asset's identity status. A test helper on
// the same terms as [Repository.SetStatus]: the engine writes `provisional` on
// a create and nothing else, and promotion to `established` is the observation
// link's job in the SQL store — but a test of the corroboration rules has to be
// able to put an asset into a status the engine did not write.
func (r *Repository) SetIdentityStatus(ref identity.AssetRef, status identity.IdentityStatus) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]; ok {
		a.identityStatus = string(status)
	}
}

// IdentityStatusOf reads an asset's identity status back. Also a test helper:
// the contract reads it through LoadSummaries, but a test asserting what the
// engine wrote wants the row and not the summary.
func (r *Repository) IdentityStatusOf(ref identity.AssetRef) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]; ok {
		return a.identityStatusOrDefault()
	}
	return ""
}

// proposalState is how a proposal was resolved, and by whom.
type proposalState struct {
	status     string
	resolvedAt time.Time
	resolvedBy string
}

// New builds an empty repository.
func New() *Repository {
	return &Repository{
		assets:        make(map[string]*asset),
		owners:        make(map[string]identity.AssetRef),
		props:         make(map[string]identity.MergeProposal),
		propState:     make(map[string]proposalState),
		announcements: make(map[string]*identity.AnnouncementRecord),
		posture:       make(map[string]bool),
		learned:       make(map[string]bool),
		prefixes:      make(map[string][]identity.NetworkSegment),
		unassigned:    make(map[string]bool),
		provScopes:    make(map[string]ProvisionalScopeAnswer),
	}
}

var _ identity.Repository = (*Repository)(nil)

func assetKey(tenantID, id string) string { return tenantID + "|" + id }

func ownerKey(tenantID string, id identity.Identifier) string {
	return tenantID + "|" + id.Key()
}

func (r *Repository) nextID(prefix string) string {
	r.seq++
	if r.IDFunc != nil {
		return r.IDFunc(prefix, r.seq)
	}
	return fmt.Sprintf("%s-%03d", prefix, r.seq)
}

// FindByIdentifier implements identity.Repository.
func (r *Repository) FindByIdentifier(_ context.Context, tenantID string, kind identity.Kind, value, scope string) ([]identity.AssetRef, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := ownerKey(tenantID, identity.Identifier{Kind: kind, Value: value, Scope: scope})
	var out []identity.AssetRef
	if ref, ok := r.owners[k]; ok {
		out = append(out, ref)
	}
	for _, m := range r.multi {
		if m.key == k {
			out = append(out, m.ref)
		}
	}
	if kind == identity.KindMACAddress {
		out = r.withInterfaceMACOwners(tenantID, value, out)
	}
	return out, nil
}

// LoadSummaries implements identity.Repository.
func (r *Repository) LoadSummaries(_ context.Context, tenantID string, ids []string) ([]identity.AssetSummary, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]identity.AssetSummary, 0, len(ids))
	for _, id := range ids {
		a, ok := r.assets[assetKey(tenantID, id)]
		if !ok {
			continue
		}
		out = append(out, identity.AssetSummary{
			Ref:            a.ref,
			ClassKey:       a.classKey,
			DisplayName:    a.displayName,
			Hostname:       a.hostname,
			Identifiers:    a.identifierList(),
			Status:         a.status,
			IdentityStatus: a.identityStatusOrDefault(),
			NetworkSegment: a.segment,
			LastSeenAt:     a.lastSeen,
			Attributes:     a.attributes,
		})
	}
	return out, nil
}

// identityStatusOrDefault is the column's default made explicit: a row written
// without an identity status is `legacy`, which is "we never asked", not an
// assertion about anything.
func (a *asset) identityStatusOrDefault() string {
	if a.identityStatus == "" {
		return string(identity.IdentityLegacy)
	}
	return a.identityStatus
}

func (a *asset) identifierList() []identity.Identifier {
	out := make([]identity.Identifier, 0, len(a.identOrder))
	for _, k := range a.identOrder {
		out = append(out, a.identifiers[k])
	}
	return out
}

// CreateAsset implements identity.Repository.
func (r *Repository) CreateAsset(_ context.Context, tenantID string, in identity.NewAsset) (identity.AssetRef, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if tenantID == "" {
		return identity.AssetRef{}, fmt.Errorf("memory: CreateAsset: no tenant")
	}
	// Check every identifier before writing anything: a partial create would
	// leave an asset holding half its identity with no way to tell.
	for _, id := range in.Identifiers {
		if owner, ok := r.owners[ownerKey(tenantID, id)]; ok {
			return identity.AssetRef{}, fmt.Errorf("%w: %s=%q is %s's", identity.ErrIdentifierConflict, id.Kind, id.Value, owner.ID)
		}
	}
	ref := identity.AssetRef{TenantID: tenantID, ID: r.nextID("asset")}
	a := &asset{
		ref:            ref,
		classKey:       in.ClassKey,
		classConf:      in.ClassConfidence,
		displayName:    in.DisplayName,
		hostname:       in.Hostname,
		nameSourceKind: in.Source.NameKind(),
		status:         in.Status,
		identityStatus: in.IdentityStatus,
		identifiers:    make(map[string]identity.Identifier, len(in.Identifiers)),
		endpoints:      make(map[string]identity.EndpointObservation, len(in.Endpoints)),
		firstSeen:      in.FirstSeenAt,
		lastSeen:       in.LastSeenAt,
		segment:        in.NetworkSegment,
	}
	r.assets[assetKey(tenantID, ref.ID)] = a
	for _, id := range in.Identifiers {
		a.putIdentifier(id)
		r.owners[ownerKey(tenantID, id)] = ref
	}
	a.fileInterfaces(in.Identifiers)
	for _, ep := range in.Endpoints {
		a.putEndpoint(ep)
	}
	return ref, nil
}

// putIdentifier reports whether the identifier was new to the asset.
func (a *asset) putIdentifier(id identity.Identifier) bool {
	k := id.Key()
	prev, ok := a.identifiers[k]
	if !ok {
		a.identOrder = append(a.identOrder, k)
		id.Assignment = id.StoredAssignment()
		a.identifiers[k] = id
		return true
	}
	// A re-sighting folds into the stored copy under the SQL upsert's
	// provenance rules (identity.UpsertIdentifier): last-seen never moves
	// backwards (Repository.IdentifierLastSeen and the lease rule of 1b
	// compare against it), source kind moves only up declared > measured >
	// inferred with its ref travelling alongside, and a pinned address is
	// never unpinned by a weaker or silent sighting.
	a.identifiers[k] = identity.UpsertIdentifier(prev, id)
	return false
}

// putEndpoint reports whether the endpoint is new, or an existing one whose
// protocol or service name this sighting changed — the same two cases
// [postgres.Repository.UpsertEndpoints] counts. An empty incoming value never
// counts as a change, because it never overwrites there either.
func (a *asset) putEndpoint(ep identity.EndpointObservation) bool {
	k := ep.Key()
	changed := true
	if prev, ok := a.endpoints[k]; ok {
		changed = (ep.Protocol != "" && ep.Protocol != prev.Protocol) ||
			(ep.ServiceName != "" && ep.ServiceName != prev.ServiceName)
		// Empty never wins here either: the SQL store coalesces these two, and
		// the change count above would otherwise drift from it.
		if ep.Protocol == "" {
			ep.Protocol = prev.Protocol
		}
		if ep.ServiceName == "" {
			ep.ServiceName = prev.ServiceName
		}
		// Upsert: keep the earliest sighting's first-seen semantics by not
		// moving SeenAt backwards.
		if ep.SeenAt.Before(prev.SeenAt) {
			ep.SeenAt = prev.SeenAt
		}
		// "Empty never wins": FQDN is an attribute of the endpoint, not part
		// of its identity (ep.Key() already ignores it once an address is
		// set). A later observation that does not know the name — or one
		// whose IP-literal FQDN [EndpointObservation.Sanitized] just
		// stripped — must not blank a name a prior observation established.
		// This is the same rule [postgres.Repository.UpsertEndpoints] applies
		// when it matches an existing row by address rather than by the full
		// (address, fqdn, port, transport) tuple; the two implementations
		// must agree, or shared/identity/identitytest's contract would pass
		// one backend and fail the other for the same sequence of calls.
		if ep.FQDN == "" && prev.FQDN != "" {
			ep.FQDN = prev.FQDN
		}
	} else {
		a.epOrder = append(a.epOrder, k)
	}
	a.endpoints[k] = ep
	delete(a.closedEndpoints, k)
	return changed
}

// AttachIdentifiers implements identity.Repository.
func (r *Repository) AttachIdentifiers(_ context.Context, ref identity.AssetRef, ids []identity.Identifier) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]
	if !ok {
		return 0, fmt.Errorf("%w: %s", identity.ErrAssetNotFound, ref.ID)
	}
	for _, id := range ids {
		if owner, ok := r.owners[ownerKey(ref.TenantID, id)]; ok && owner.ID != ref.ID {
			return 0, fmt.Errorf("%w: %s=%q is %s's", identity.ErrIdentifierConflict, id.Kind, id.Value, owner.ID)
		}
	}
	added := 0
	for _, id := range ids {
		if a.putIdentifier(id) {
			added++
		}
		r.owners[ownerKey(ref.TenantID, id)] = a.ref
	}
	a.fileInterfaces(ids)
	return added, nil
}

// UpsertEndpoints implements identity.Repository.
func (r *Repository) UpsertEndpoints(_ context.Context, ref identity.AssetRef, eps []identity.EndpointObservation) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]
	if !ok {
		return 0, fmt.Errorf("%w: %s", identity.ErrAssetNotFound, ref.ID)
	}
	changed := 0
	for _, ep := range eps {
		// Defense in depth, mirroring postgres.Repository.UpsertEndpoints: a
		// caller of the repository directly (bypassing the engine's
		// stampEndpoints, as the identitytest contract itself does) must get
		// the same "an IP is never a name" treatment.
		ep = ep.Sanitized()
		if ep.Address == "" && ep.FQDN == "" {
			return 0, fmt.Errorf("memory: UpsertEndpoints: endpoint has neither address nor fqdn")
		}
		if a.putEndpoint(ep) {
			changed++
		}
	}
	return changed, nil
}

// ReconcileSourceEndpoints implements identity.Repository, with
// [postgres.Repository.ReconcileSourceEndpoints]'s rules: only the source's own
// endpoints (source ref under sourcePrefix), only those absent from observed,
// only those last seen no later than at; closed, never removed.
func (r *Repository) ReconcileSourceEndpoints(_ context.Context, ref identity.AssetRef, sourcePrefix string, observed []identity.EndpointObservation, at time.Time) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]
	if !ok {
		return nil, fmt.Errorf("%w: %s", identity.ErrAssetNotFound, ref.ID)
	}
	if strings.TrimSpace(sourcePrefix) == "" {
		return nil, fmt.Errorf("memory: ReconcileSourceEndpoints: empty source prefix")
	}
	keep := make(map[string]bool, len(observed))
	for _, ep := range observed {
		keep[ep.Sanitized().Key()] = true
	}
	var closed []string
	for _, k := range a.epOrder {
		ep := a.endpoints[k]
		if keep[k] || a.closedEndpoints[k] || !strings.HasPrefix(ep.Source.Ref, sourcePrefix) || ep.SeenAt.After(at) {
			continue
		}
		if a.closedEndpoints == nil {
			a.closedEndpoints = map[string]bool{}
		}
		a.closedEndpoints[k] = true
		closed = append(closed, k)
	}
	sort.Strings(closed)
	return closed, nil
}

// ClosedEndpoints returns the keys of an asset's closed endpoints, sorted.
func (r *Repository) ClosedEndpoints(ref identity.AssetRef) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(a.closedEndpoints))
	for k := range a.closedEndpoints {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Touch implements identity.Repository.
func (r *Repository) Touch(_ context.Context, ref identity.AssetRef, seenAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]
	if !ok {
		return fmt.Errorf("%w: %s", identity.ErrAssetNotFound, ref.ID)
	}
	if seenAt.After(a.lastSeen) {
		a.lastSeen = seenAt
	}
	return nil
}

// PromoteNames implements identity.Repository.
func (r *Repository) PromoteNames(_ context.Context, ref identity.AssetRef, hostname, displayName, sourceKind string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]
	if !ok {
		return fmt.Errorf("%w: %s", identity.ErrAssetNotFound, ref.ID)
	}
	changed := false
	if hostnamequality.ShouldPromote(a.hostname, hostname, a.nameSourceKind, sourceKind) {
		a.hostname = strings.TrimSpace(hostname)
		changed = true
	}
	if hostnamequality.ShouldPromote(a.displayName, displayName, a.nameSourceKind, sourceKind) {
		a.displayName = strings.TrimSpace(displayName)
		changed = true
	}
	if changed {
		a.nameSourceKind = hostnamequality.NormalizeSource(sourceKind)
	}
	return nil
}

// Hostname is a test helper: the engine does not read hostname back except
// through [Repository.LoadSummaries].
func (r *Repository) Hostname(ref identity.AssetRef) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]; ok {
		return a.hostname
	}
	return ""
}

// DisplayName is a test helper matching [Repository.Hostname].
func (r *Repository) DisplayName(ref identity.AssetRef) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]; ok {
		return a.displayName
	}
	return ""
}

// SetNameSourceDeclared is a test helper standing in for a human edit.
func (r *Repository) SetNameSourceDeclared(ref identity.AssetRef) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]; ok {
		a.nameSourceKind = hostnamequality.SourceDeclared
	}
}

// RecordHistory implements identity.Repository.
func (r *Repository) RecordHistory(_ context.Context, e identity.HistoryEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.history = append(r.history, e)
	return nil
}

// HistoryHasChange implements identity.Repository.
func (r *Repository) HistoryHasChange(_ context.Context, ref identity.AssetRef, action identity.HistoryAction, subset map[string]any) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.history {
		if e.TenantID == ref.TenantID && e.AssetID == ref.ID && e.Action == action &&
			identity.ChangesContain(e.Changes, subset) {
			return true, nil
		}
	}
	return false, nil
}

// OpenMergeProposal implements identity.Repository.
func (r *Repository) OpenMergeProposal(_ context.Context, tenantID string, p identity.MergeProposal) (identity.ProposalRef, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if tenantID == "" {
		return identity.ProposalRef{}, fmt.Errorf("memory: OpenMergeProposal: no tenant")
	}
	// Idempotent by fingerprint, exactly as the SQL implementation is (see
	// identity.MergeProposalFingerprint and the partial unique index). Two
	// implementations of one storage contract drift the moment one of them is
	// allowed a behaviour the other is not, and "the fake lets you open the
	// same proposal a hundred times" is precisely the kind of difference that
	// makes a test suite green about a queue nobody can clear.
	//
	// Only a PENDING proposal suppresses a new one, exactly as the SQL
	// index's partial predicate says: a resolved proposal drops out, and a
	// later recurrence of the question is the engine's decision memory's
	// business, not this method's.
	fp := identity.MergeProposalFingerprint(p)
	for _, k := range r.propSeq {
		if !strings.HasPrefix(k, tenantID+"|") {
			continue
		}
		if _, resolved := r.propState[k]; resolved {
			continue
		}
		if identity.MergeProposalFingerprint(r.props[k]) == fp {
			// The same question re-asked: fold the new evidence in, with
			// the same rule the SQL implementation applies ( A3).
			r.props[k] = identity.FoldMergeProposal(r.props[k], p)
			return identity.ProposalRef{TenantID: tenantID, ID: strings.TrimPrefix(k, tenantID+"|"), Reused: true}, nil
		}
	}
	ref := identity.ProposalRef{TenantID: tenantID, ID: r.nextID("proposal")}
	key := assetKey(tenantID, ref.ID)
	r.props[key] = p
	r.propSeq = append(r.propSeq, key)
	return ref, nil
}

// LastKeptSeparate implements identity.Repository.
//
// Newest first, as the SQL implementation orders by `seq DESC`: when a pair
// was kept separate twice, the later decision carries the later evidence.
func (r *Repository) LastKeptSeparate(_ context.Context, tenantID string, assetIDs []string) (identity.PriorDecision, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if tenantID == "" {
		return identity.PriorDecision{}, false, fmt.Errorf("memory: LastKeptSeparate: no tenant")
	}
	for i := len(r.propSeq) - 1; i >= 0; i-- {
		k := r.propSeq[i]
		if !strings.HasPrefix(k, tenantID+"|") {
			continue
		}
		st, resolved := r.propState[k]
		if !resolved || st.status != "kept_separate" {
			continue
		}
		d := priorDecisionOf(strings.TrimPrefix(k, tenantID+"|"), r.props[k], st)
		if d.Covers(assetIDs) {
			return d, true, nil
		}
	}
	return identity.PriorDecision{}, false, nil
}

// IdentifierLastSeen implements identity.Repository.
func (r *Repository) IdentifierLastSeen(_ context.Context, tenantID string, id identity.Identifier) (time.Time, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if tenantID == "" {
		return time.Time{}, false, fmt.Errorf("memory: IdentifierLastSeen: no tenant")
	}
	owner, ok := r.owners[ownerKey(tenantID, id)]
	if !ok {
		return time.Time{}, false, nil
	}
	a, ok := r.assets[assetKey(tenantID, owner.ID)]
	if !ok {
		return time.Time{}, false, nil
	}
	held, ok := a.identifiers[id.Key()]
	if !ok {
		return time.Time{}, false, nil
	}
	return held.SeenAt, true, nil
}

func priorDecisionOf(id string, p identity.MergeProposal, st proposalState) identity.PriorDecision {
	d := identity.PriorDecision{
		ProposalID:         id,
		ObservationAssetID: p.ObservationAssetID,
		DecidedAt:          st.resolvedAt,
		DecidedBy:          st.resolvedBy,
	}
	seen := map[identity.Kind]bool{}
	for _, c := range p.Candidates {
		d.Candidates = append(d.Candidates, c.Ref.ID)
		for _, mid := range c.MatchedIdentifiers {
			if !seen[mid.Kind] {
				seen[mid.Kind] = true
				d.MatchedKinds = append(d.MatchedKinds, mid.Kind)
			}
		}
	}
	return d
}

// ResolveProposal stamps a proposal's outcome — `kept_separate` or `merged` —
// the way the approvals path stamps the SQL row.
//
// A TEST HOOK, not part of identity.Repository: the engine never resolves a
// proposal (ADR-0002 D5). It exists so the decision-memory contract can put a
// human's answer where [Repository.LastKeptSeparate] will find it. It refuses
// an unknown proposal rather than inventing one.
func (r *Repository) ResolveProposal(ref identity.ProposalRef, status, actor string, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := assetKey(ref.TenantID, ref.ID)
	if _, ok := r.props[key]; !ok {
		return fmt.Errorf("memory: ResolveProposal: no proposal %s in tenant %s", ref.ID, ref.TenantID)
	}
	r.propState[key] = proposalState{status: status, resolvedAt: at, resolvedBy: actor}
	return nil
}

// RecordAnnouncement implements identity.Repository.
func (r *Repository) RecordAnnouncement(_ context.Context, announcer, holder identity.AssetRef, a identity.Announcement) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if announcer.TenantID != holder.TenantID {
		return fmt.Errorf("memory: RecordAnnouncement: announcer and holder are in different tenants")
	}
	if announcer.ID == holder.ID {
		return fmt.Errorf("memory: RecordAnnouncement: %s cannot announce its own address as floating", announcer.ID)
	}
	for _, ref := range []identity.AssetRef{announcer, holder} {
		if _, ok := r.assets[assetKey(ref.TenantID, ref.ID)]; !ok {
			return fmt.Errorf("%w: %s", identity.ErrAssetNotFound, ref.ID)
		}
	}
	key := announcer.TenantID + "|" + announcer.ID + "|" + holder.ID
	if rec, ok := r.announcements[key]; ok {
		rec.Count++
		if !a.At.Before(rec.Latest.At) {
			rec.Latest = a
		}
		return nil
	}
	r.announcements[key] = &identity.AnnouncementRecord{Announcer: announcer, Holder: holder, Latest: a, Count: 1}
	r.announceSeq = append(r.announceSeq, key)
	return nil
}

// AddressAnnounced implements identity.Repository.
func (r *Repository) AddressAnnounced(_ context.Context, holder identity.AssetRef, address string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if holder.TenantID == "" {
		return false, fmt.Errorf("memory: AddressAnnounced: no tenant")
	}
	// The same two sources the SQL store reads: the latest announcement per
	// announcer (the edge), and the holder's history entries the engine's
	// floating-address path writes (append-only).
	for _, rec := range r.announcements {
		if rec.Holder == holder && containsString(rec.Latest.Addresses, address) {
			return true, nil
		}
	}
	for _, e := range r.history {
		if e.TenantID != holder.TenantID || e.AssetID != holder.ID {
			continue
		}
		fa, ok := e.Changes["floating_address"].(map[string]any)
		if !ok {
			continue
		}
		if addrs, ok := fa["addresses"].([]string); ok && containsString(addrs, address) {
			return true, nil
		}
	}
	return false, nil
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// ── test accessors ─────────────────────────────────────────────────────────

// History returns every recorded history entry, in order.
func (r *Repository) History() []identity.HistoryEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]identity.HistoryEntry(nil), r.history...)
}

// HistoryFor returns the history entries for one asset, in order. Scoped by
// tenant as well as asset, so it cannot answer about another tenant's rows even
// in a fake.
func (r *Repository) HistoryFor(ref identity.AssetRef) []identity.HistoryEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []identity.HistoryEntry
	for _, e := range r.history {
		if e.AssetID == ref.ID && e.TenantID == ref.TenantID {
			out = append(out, e)
		}
	}
	return out
}

// Announcements returns the floating-address records naming this asset as
// announcer or holder, in first-observation order.
func (r *Repository) Announcements(ref identity.AssetRef) []identity.AnnouncementRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []identity.AnnouncementRecord
	for _, k := range r.announceSeq {
		rec := r.announcements[k]
		if rec.Announcer.TenantID != ref.TenantID {
			continue
		}
		if rec.Announcer.ID == ref.ID || rec.Holder.ID == ref.ID {
			out = append(out, *rec)
		}
	}
	return out
}

// PendingProposal is identitytest.ProposalReader: the stored proposal, folds
// included, while it is still pending.
func (r *Repository) PendingProposal(ref identity.ProposalRef) (identity.MergeProposal, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := assetKey(ref.TenantID, ref.ID)
	p, ok := r.props[k]
	if !ok {
		return identity.MergeProposal{}, false
	}
	if _, resolved := r.propState[k]; resolved {
		return identity.MergeProposal{}, false
	}
	return p, true
}

// Proposals returns every merge proposal, in creation order.
func (r *Repository) Proposals() []identity.MergeProposal {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]identity.MergeProposal, 0, len(r.propSeq))
	for _, k := range r.propSeq {
		out = append(out, r.props[k])
	}
	return out
}

// AssetCount returns how many assets exist across all tenants.
func (r *Repository) AssetCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.assets)
}

// Identifiers returns the identifiers attached to an asset, in attach order.
func (r *Repository) Identifiers(ref identity.AssetRef) []identity.Identifier {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]
	if !ok {
		return nil
	}
	return a.identifierList()
}

// Endpoints returns the endpoints under an asset, in upsert order.
func (r *Repository) Endpoints(ref identity.AssetRef) []identity.EndpointObservation {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]
	if !ok {
		return nil
	}
	out := make([]identity.EndpointObservation, 0, len(a.epOrder))
	for _, k := range a.epOrder {
		out = append(out, a.endpoints[k])
	}
	return out
}

// LastSeen returns an asset's last-seen timestamp.
func (r *Repository) LastSeen(ref identity.AssetRef) time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]
	if !ok {
		return time.Time{}
	}
	return a.lastSeen
}

// ClassOf returns an asset's class key.
func (r *Repository) ClassOf(ref identity.AssetRef) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]
	if !ok {
		return ""
	}
	return a.classKey
}

// ClassConfidence returns an asset's stored class confidence.
func (r *Repository) ClassConfidence(ref identity.AssetRef) float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]
	if !ok {
		return 0
	}
	return a.classConf
}

// Corrupt binds an identifier to a second asset, breaking the uniqueness
// invariant on purpose.
//
// It exists because [Repository.FindByIdentifier] returns a slice precisely so
// a store that has lost the invariant is detectable, and a return shape no
// test can ever exercise is a check that cannot fail. This is the only way to
// produce that state; nothing in the normal API can.
func (r *Repository) Corrupt(tenantID string, id identity.Identifier, extra identity.AssetRef) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.multi = append(r.multi, multiOwner{key: ownerKey(tenantID, id), ref: extra})
}

type multiOwner struct {
	key string
	ref identity.AssetRef
}

// AddSegment registers a declared prefix for a tenant under a caller-chosen
// scope id, so [Repository.ScopeForAddress] has something to resolve against.
// A more specific prefix wins, the same rule the SQL lookup applies.
//
// `dynamic` true is a stated DHCP posture; false is "nobody has said", which on
// a declared prefix reads as static — the SQL store's
// `coalesce(dhcp_managed, source_kind <> 'declared')`.
func (r *Repository) AddSegment(tenantID, cidr, scope string, dynamic bool) error {
	return r.AddCloudSegment(tenantID, cidr, scope, dynamic, "")
}

// AddCloudSegment is AddSegment for a prefix that belongs to a cloud network.
//
// Two VPCs may use the same CIDR, so the network ref is what tells their
// prefixes apart.
func (r *Repository) AddCloudSegment(tenantID, cidr, scope string, dynamic bool, networkRef string) error {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("memory: prefix %q is not a CIDR: %w", cidr, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prefixes[tenantID] = append(r.prefixes[tenantID], identity.NetworkSegment{
		ID: scope, Type: identity.SegmentTypeCIDR, Value: p.Masked().String(),
		CloudNetworkRef: strings.TrimSpace(networkRef),
	})
	if dynamic {
		r.posture[tenantID+"|"+scope] = true
	}
	return nil
}

// AddLearnedPrefix registers a prefix a collector reported (`source_kind =
// 'measured'`) with no DHCP posture stated, under a caller-chosen scope id. It
// implements identitytest.PrefixPostureWriter.
func (r *Repository) AddLearnedPrefix(tenantID, cidr, scope string) error {
	if err := r.AddSegment(tenantID, cidr, scope, false); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.learned[tenantID+"|"+scope] = true
	return nil
}

// RecordPrefixPosture is the in-memory twin of
// shared/identity/postgres.RecordPrefixPosture: a DHCP posture is written only
// where nobody has said yet, so the first statement — a person's through the
// IPAM API, or a collector's — stands. It implements
// identitytest.PrefixPostureWriter.
func (r *Repository) RecordPrefixPosture(tenantID, scope string, dynamic bool) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.prefixes[tenantID] {
		if p.ID != scope {
			continue
		}
		key := tenantID + "|" + scope
		if _, said := r.posture[key]; said {
			return false, nil
		}
		r.posture[key] = dynamic
		return true, nil
	}
	return false, fmt.Errorf("memory: no prefix %q in tenant %q", scope, tenantID)
}

// SegmentSnapshot implements [identity.Repository]: the tenant's prefixes in
// registration order, with their stored posture.
func (r *Repository) SegmentSnapshot(_ context.Context, tenantID string) (identity.SegmentSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	snap := identity.SegmentSnapshot{TenantID: tenantID}
	for _, p := range r.prefixes[tenantID] {
		key := tenantID + "|" + p.ID
		// coalesce(dhcp_managed, source_kind <> 'declared'): a learned prefix
		// nobody has stated a posture for reads as dynamic.
		p.Dynamic = r.learned[key]
		if v, said := r.posture[key]; said {
			p.Dynamic = v
		}
		snap.Prefixes = append(snap.Prefixes, p)
	}
	return snap, nil
}

// ScopeForAddress implements [identity.Repository], through
// [identity.SegmentSnapshot.ScopeForAddress] — the one implementation of the
// rule, shared with the SQL store and identity.Intake.
//
// It returns the most specific matching prefix's scope, and
// [identity.ScopeTenantDefault] when nothing matches — including for a tenant
// with no prefixes at all, which is the case that matters: an empty scope there
// is what made one host observed three times into three assets.
func (r *Repository) ScopeForAddress(ctx context.Context, tenantID string, addr netip.Addr, cloudNetworkRef string) (string, bool, error) {
	snap, err := r.SegmentSnapshot(ctx, tenantID)
	if err != nil {
		return "", false, err
	}
	scope, dynamic := snap.ScopeForAddress(addr, cloudNetworkRef)
	return scope, dynamic, nil
}

// ── provisional inventory ──────────────────────────────────────────

// SetProvisionalScope records the answer [Repository.ProvisionalScope] will
// give for a segment.
//
// The SQL store derives the same answer from `prefixes` — a live, non-container
// cidr segment, nothing else active overlapping it, no cloud network ref — and
// a fake that computed its own version of that query would be testing this
// package's reading of the rule rather than the rule. A settable answer keeps
// the two implementations held to the same CONTRACT (an eligible segment, an
// ineligible one with a reason, an unknown one) without pretending to share
// the derivation.
func (r *Repository) SetProvisionalScope(tenantID, segmentID string, answer ProvisionalScopeAnswer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.provScopes[tenantID+"|"+segmentID] = answer
}

// SetProvisionalScopeAnswer is [identitytest.ProvisionalScopeWriter]: the same
// thing as [Repository.SetProvisionalScope] in the two-value shape the contract
// package can express without importing this one.
func (r *Repository) SetProvisionalScopeAnswer(tenantID, segmentID string, eligible bool, reason string) {
	r.SetProvisionalScope(tenantID, segmentID, ProvisionalScopeAnswer{Eligible: eligible, Reason: reason})
}

// ProvisionalScope implements [identity.ProvisionalScopeChecker].
//
// A segment nobody has said anything about is NOT eligible, and the reason is
// `network_scope_unresolved`. Defaulting to eligible would make every test that
// forgot to configure a segment create provisional assets, which is the failure
// direction that ends with an inventory of guesses.
func (r *Repository) ProvisionalScope(_ context.Context, tenantID, segmentID string) (bool, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	answer, ok := r.provScopes[tenantID+"|"+segmentID]
	switch {
	case !ok:
		return false, identity.ReasonNetworkScopeUnresolved, nil
	case !answer.Eligible:
		reason := answer.Reason
		if reason == "" {
			reason = identity.ReasonNetworkScopeUnresolved
		}
		return false, reason, nil
	}
	return true, "", nil
}

// ReassignIdentifier implements [identity.IdentifierReassigner].
//
// It moves the value in one step, keeping the owners map and the uniqueness
// invariant true at every point a caller could observe — which is the whole
// reason this is a repository method rather than a detach and an attach in the
// engine.
//
// A `from` that is not the current owner is REFUSED. The engine computes the
// move from an ownership lookup it made earlier in the same transaction, so a
// disagreement here means that lookup is stale, and a reassignment computed
// against stale ownership is how two assets swap halves of their identity.
func (r *Repository) ReassignIdentifier(_ context.Context, id identity.Identifier, from, to identity.AssetRef) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if from.TenantID != to.TenantID {
		return fmt.Errorf("memory: ReassignIdentifier: %s and %s are in different tenants", from.ID, to.ID)
	}
	if from.ID == to.ID {
		return fmt.Errorf("memory: ReassignIdentifier: %s=%q is already %s's", id.Kind, id.Value, to.ID)
	}
	src, ok := r.assets[assetKey(from.TenantID, from.ID)]
	if !ok {
		return fmt.Errorf("%w: %s", identity.ErrAssetNotFound, from.ID)
	}
	dst, ok := r.assets[assetKey(to.TenantID, to.ID)]
	if !ok {
		return fmt.Errorf("%w: %s", identity.ErrAssetNotFound, to.ID)
	}
	key := ownerKey(from.TenantID, id)
	owner, owned := r.owners[key]
	if !owned || owner.ID != from.ID {
		return fmt.Errorf("%w: %s=%q is not %s's", identity.ErrIdentifierConflict, id.Kind, id.Value, from.ID)
	}
	held, ok := src.identifiers[id.Key()]
	if !ok {
		return fmt.Errorf("%w: %s does not carry %s=%q", identity.ErrIdentifierConflict, from.ID, id.Kind, id.Value)
	}
	src.dropIdentifier(id.Key())
	src.unfile(held)
	dst.putIdentifier(held)
	dst.fileInterfaces([]identity.Identifier{held})
	r.owners[key] = dst.ref
	return nil
}

// ArchiveAsset implements [identity.AssetArchiver]: the one status change this
// package's engine makes, for a provisional asset a reassignment left holding
// no identifier at all.
func (r *Repository) ArchiveAsset(_ context.Context, ref identity.AssetRef) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]
	if !ok {
		return fmt.Errorf("%w: %s", identity.ErrAssetNotFound, ref.ID)
	}
	a.status = identity.StatusArchived
	return nil
}

// StatusOf reads an asset's approval status back. A test helper, matching
// [Repository.IdentityStatusOf].
func (r *Repository) StatusOf(ref identity.AssetRef) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]; ok {
		return a.status
	}
	return ""
}

// HostnameCardinality implements identity.Repository: the number of distinct
// live assets in the tenant with a `hostname` identifier of this value, in any
// scope. Archived and denied assets are not live, the same set the SQL store and
// the merge approvals count.
func (r *Repository) HostnameCardinality(_ context.Context, tenantID, value string) (int, error) {
	want := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, a := range r.assets {
		if a.ref.TenantID != tenantID || a.status == identity.StatusArchived || a.status == identity.StatusDenied {
			continue
		}
		for _, id := range a.identifiers {
			if id.Kind == identity.KindHostname && id.Value == want {
				n++
				break
			}
		}
	}
	return n, nil
}

func (a *asset) dropIdentifier(key string) {
	if _, ok := a.identifiers[key]; !ok {
		return
	}
	delete(a.identifiers, key)
	kept := a.identOrder[:0]
	for _, k := range a.identOrder {
		if k != key {
			kept = append(kept, k)
		}
	}
	a.identOrder = kept
}

// RetireIdentifier implements [identity.IdentifierRetirer]: the drift verdicts'
// "replace the key" and "release the old address". A value the asset does not
// hold is refused, as the postgres store refuses it.
func (r *Repository) RetireIdentifier(_ context.Context, ref identity.AssetRef, id identity.Identifier) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]
	if !ok {
		return fmt.Errorf("%w: %s", identity.ErrAssetNotFound, ref.ID)
	}
	key := ownerKey(ref.TenantID, id)
	if owner, owned := r.owners[key]; !owned || owner.ID != ref.ID {
		return fmt.Errorf("%w: %s=%q is not %s's", identity.ErrIdentifierConflict, id.Kind, id.Value, ref.ID)
	}
	if _, held := a.identifiers[id.Key()]; !held {
		return fmt.Errorf("%w: %s does not carry %s=%q", identity.ErrIdentifierConflict, ref.ID, id.Kind, id.Value)
	}
	a.dropIdentifier(id.Key())
	a.unfile(id)
	delete(r.owners, key)
	return nil
}

// SetTLSCertificates records the leaf certificate fingerprints an asset
// presents. A test helper: certificates are written by inventory-service's
// crypto path, never by the engine, so the fake has no other way to hold them.
func (r *Repository) SetTLSCertificates(ref identity.AssetRef, fingerprints ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tlsCerts == nil {
		r.tlsCerts = map[string][]string{}
	}
	r.tlsCerts[assetKey(ref.TenantID, ref.ID)] = fingerprints
}

// DriftMaterial implements [identity.DriftMaterialReader]: the certificates
// [Repository.SetTLSCertificates] recorded, and the ports of the asset's
// stored endpoints.
func (r *Repository) DriftMaterial(_ context.Context, ref identity.AssetRef) (identity.StoredDriftMaterial, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]
	if !ok {
		return identity.StoredDriftMaterial{}, nil
	}
	out := identity.StoredDriftMaterial{TLSCertFingerprints: append([]string(nil), r.tlsCerts[assetKey(ref.TenantID, ref.ID)]...)}
	seen := map[string]bool{}
	for _, k := range a.epOrder {
		ep := a.endpoints[k]
		if ep.Port <= 0 {
			continue
		}
		t := strings.ToLower(ep.Transport)
		if t == "" {
			t = "tcp"
		}
		p := strconv.Itoa(ep.Port) + "/" + t
		if !seen[p] {
			seen[p] = true
			out.Ports = append(out.Ports, p)
		}
	}
	return out, nil
}
