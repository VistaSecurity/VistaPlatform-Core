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

	// segments are the tenant's network segments, keyed by CIDR, for
	// [Repository.ScopeForAddress]. Empty is the normal state and the
	// interesting one: a tenant with no segments must still get a usable scope.
	segments map[string][]memSegment

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

// memSegment is one configured network segment: a prefix, the scope id an
// address inside it carries, and whether the segment hands addresses out
// dynamically.
type memSegment struct {
	prefix  netip.Prefix
	scope   string
	dynamic bool
	// networkRef is the cloud network (VPC / VNet) the segment belongs to,
	// empty for a LAN segment. It is part of the segment's identity on the SQL
	// side (the unique index is over it), and it is here so this store can run
	// the same scoping contract.
	networkRef string
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
	firstSeen      time.Time
	lastSeen       time.Time
	// segment and attributes travel with the asset because a merge candidate's
	// SUMMARY carries them (identity.AssetSummary): the matcher seam compares
	// the segment and the comparable class attributes, and a fake that cannot
	// return them would make every engine test score as if a real store had no
	// segments at all.
	segment    string
	attributes map[string]any
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
		segments:      make(map[string][]memSegment),
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
	for _, ep := range in.Endpoints {
		a.putEndpoint(ep)
	}
	return ref, nil
}

func (a *asset) putIdentifier(id identity.Identifier) {
	k := id.Key()
	if _, ok := a.identifiers[k]; !ok {
		a.identOrder = append(a.identOrder, k)
	}
	a.identifiers[k] = id
}

func (a *asset) putEndpoint(ep identity.EndpointObservation) {
	k := ep.Key()
	if prev, ok := a.endpoints[k]; ok {
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
}

// AttachIdentifiers implements identity.Repository.
func (r *Repository) AttachIdentifiers(_ context.Context, ref identity.AssetRef, ids []identity.Identifier) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]
	if !ok {
		return fmt.Errorf("%w: %s", identity.ErrAssetNotFound, ref.ID)
	}
	for _, id := range ids {
		if owner, ok := r.owners[ownerKey(ref.TenantID, id)]; ok && owner.ID != ref.ID {
			return fmt.Errorf("%w: %s=%q is %s's", identity.ErrIdentifierConflict, id.Kind, id.Value, owner.ID)
		}
	}
	for _, id := range ids {
		a.putIdentifier(id)
		r.owners[ownerKey(ref.TenantID, id)] = a.ref
	}
	return nil
}

// UpsertEndpoints implements identity.Repository.
func (r *Repository) UpsertEndpoints(_ context.Context, ref identity.AssetRef, eps []identity.EndpointObservation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.assets[assetKey(ref.TenantID, ref.ID)]
	if !ok {
		return fmt.Errorf("%w: %s", identity.ErrAssetNotFound, ref.ID)
	}
	for _, ep := range eps {
		// Defense in depth, mirroring postgres.Repository.UpsertEndpoints: a
		// caller of the repository directly (bypassing the engine's
		// stampEndpoints, as the identitytest contract itself does) must get
		// the same "an IP is never a name" treatment.
		ep = ep.Sanitized()
		if ep.Address == "" && ep.FQDN == "" {
			return fmt.Errorf("memory: UpsertEndpoints: endpoint has neither address nor fqdn")
		}
		a.putEndpoint(ep)
	}
	return nil
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

// AddSegment registers a network segment for a tenant, so
// [Repository.ScopeForAddress] has something to resolve against. Keyed by CIDR,
// which is how the SQL side stores the commonest segment type.
//
// A more specific prefix wins, the same rule the SQL lookup applies: a /28
// carved out of a /24 is the more precise answer about where an address is.
func (r *Repository) AddSegment(tenantID, cidr, scope string, dynamic bool) error {
	return r.AddCloudSegment(tenantID, cidr, scope, dynamic, "")
}

// AddCloudSegment is AddSegment for a segment that belongs to a cloud network.
//
// Two VPCs may use the same CIDR, so the network ref is what tells their
// segments apart — the same thing the SQL store's unique index does.
func (r *Repository) AddCloudSegment(tenantID, cidr, scope string, dynamic bool, networkRef string) error {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("memory: segment %q is not a CIDR: %w", cidr, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.segments[tenantID] = append(r.segments[tenantID], memSegment{
		prefix: p.Masked(), scope: scope, dynamic: dynamic, networkRef: strings.TrimSpace(networkRef),
	})
	return nil
}

// ScopeForAddress implements [identity.Repository].
//
// It returns the most specific matching segment's scope, and
// [identity.ScopeTenantDefault] when nothing matches — including for a tenant
// with no segments at all, which is the case that matters: an empty scope there
// is what made one host observed three times into three assets.
func (r *Repository) ScopeForAddress(_ context.Context, tenantID string, addr netip.Addr, cloudNetworkRef string) (string, bool, error) {
	if !addr.IsValid() {
		// Not an address, so not inside any segment. The default scope is still
		// the truthful answer about where we were standing.
		return identity.ScopeTenantDefault, false, nil
	}
	a := addr.Unmap().WithZone("")
	want := strings.TrimSpace(cloudNetworkRef)
	r.mu.Lock()
	defer r.mu.Unlock()

	// Matches are collected per prefix length, not reduced to one as they
	// arrive: the ambiguity that matters is between EQUALLY specific segments
	// (10.0.1.0/24 in vpc-a and in vpc-b), and keeping only the first would
	// hide it. Same shape as the SQL implementation, deliberately.
	best := -1
	var bestSegs []memSegment
	for _, seg := range r.segments[tenantID] {
		if want != "" && seg.networkRef != "" && seg.networkRef != want {
			continue
		}
		if seg.prefix.Addr().BitLen() != a.BitLen() || !seg.prefix.Contains(a) {
			continue
		}
		switch {
		case seg.prefix.Bits() > best:
			best, bestSegs = seg.prefix.Bits(), []memSegment{seg}
		case seg.prefix.Bits() == best:
			bestSegs = append(bestSegs, seg)
		}
	}
	chosen, ok := pickMemSegment(bestSegs, want)
	if !ok {
		return identity.ScopeTenantDefault, false, nil
	}
	return chosen.scope, chosen.dynamic, nil
}

// pickMemSegment mirrors the SQL store's pickSegment: a network-matched segment
// beats an unscoped one, and equally specific matches in two DIFFERENT cloud
// networks are a question the caller did not answer — so no segment is chosen
// and the address falls to the tenant default, where it decides nothing.
func pickMemSegment(matches []memSegment, want string) (memSegment, bool) {
	switch len(matches) {
	case 0:
		return memSegment{}, false
	case 1:
		return matches[0], true
	}
	if want != "" {
		for _, m := range matches {
			if m.networkRef == want {
				return m, true
			}
		}
		return matches[0], true
	}
	for _, m := range matches {
		if m.networkRef != matches[0].networkRef {
			return memSegment{}, false
		}
	}
	return matches[0], true
}

// ── provisional inventory ──────────────────────────────────────────

// SetProvisionalScope records the answer [Repository.ProvisionalScope] will
// give for a segment.
//
// The SQL store derives the same answer from `network_segments` — an active
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
	dst.putIdentifier(held)
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
