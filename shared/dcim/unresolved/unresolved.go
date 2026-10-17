// Package unresolved parks an edge whose far end is known only by identity and
// materialises it when the far object arrives (asset-inventory ADR-0010 D6;
// DCIM DATA_MODEL §4 `unresolved_terminations`).
//
// LLDP names a neighbour by chassis id and port id before that switch is in the
// inventory; a cloud API says an instance sits in a subnet the run has not
// enumerated; a NetBox import references a device by NetBox id. Each of those
// producers PARKS a [Termination] — "connect my origin to whatever turns out to
// have this identity" — instead of dropping the edge or inventing a far end.
// The [Resolver] runs after every intake batch and on a schedule, asks a
// [Matcher] whether anything now carries the identity, hands the match to an
// [Applier] (which writes the cable, relationship or assignment as `pending`,
// measured) and deletes the parked row.
//
// What ships in row 0.3 is the contract: the interfaces, an in-memory
// [Repository], a [NullMatcher], and dcimtest.RunResolverContract — the one
// suite the phase-1 SQL repository must also pass. The real matchers arrive
// with interfaces (1.4) and cables (3.3); the real appliers with the objects
// they write.
package unresolved

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// DefaultTTL is how long a parked termination waits for its far end after the
// last observation (DATA_MODEL §4: expiry defaults to 30 days).
const DefaultTTL = 30 * 24 * time.Hour

// Identity keys the resolver knows how to match (Matcher methods). A producer
// may park other keys — they are stored and searchable — but only these drive
// a match today.
const (
	KeyMACAddress      = "mac_address"
	KeyChassisID       = "chassis_id"
	KeyCloudResourceID = "cloud_resource_id"
	// KeySyncPrefix starts a sync key: "sync:<peer>:<object>" → the peer's id,
	// e.g. "sync:netbox:interface" = "77".
	KeySyncPrefix = "sync:"

	// The rest of an LLDP / CDP neighbour's far identity (row 3.3; DATA_MODEL
	// §4): the far port and the other names the far device advertised. They
	// are matched together, by a [TerminationMatcher], because a cable's far
	// end is an interface — a chassis id alone names only the device.
	KeyPortID      = "port_id"
	KeyPortDescr   = "port_descr"
	KeySystemName  = "system_name"
	KeyMgmtAddress = "mgmt_address"
)

// Intents a parked termination may carry.
const (
	IntentCable              = "cable"
	IntentAssignment         = "assignment"
	IntentRelationshipPrefix = "relationship:"
)

var (
	producerPattern = regexp.MustCompile(`^[a-z0-9_]+$`)
	intentPattern   = regexp.MustCompile(`^(cable|assignment|relationship:[a-z_]+)$`)
)

// Termination is what a producer knows: the object it has (origin), the
// identity of the far end it does not (FarIdentity, a flat string map), and
// what to write once the far end exists (Intent + Attributes).
type Termination struct {
	Producer    string
	OriginKind  dcim.ObjectKind
	OriginID    uuid.UUID
	FarIdentity map[string]string
	Intent      string
	Attributes  map[string]any
}

// Parked is a stored termination.
type Parked struct {
	ID       uuid.UUID
	TenantID uuid.UUID
	Termination
	FirstSeenAt      time.Time
	LastSeenAt       time.Time
	ObservationCount int
	ExpiresAt        time.Time
}

// RelationshipType returns the relationship type of a `relationship:<type>`
// intent.
func (t Termination) RelationshipType() (string, bool) {
	if !strings.HasPrefix(t.Intent, IntentRelationshipPrefix) {
		return "", false
	}
	return strings.TrimPrefix(t.Intent, IntentRelationshipPrefix), true
}

// ErrInvalid is returned by Park for a termination the schema would refuse.
var ErrInvalid = errors.New("unresolved: invalid termination")

// Validate checks t against the rules the schema CHECKs.
func (t Termination) Validate() error {
	if !producerPattern.MatchString(t.Producer) {
		return fmt.Errorf("%w: producer %q", ErrInvalid, t.Producer)
	}
	if _, ok := dcim.ParseObjectKind(string(t.OriginKind)); !ok {
		return fmt.Errorf("%w: origin kind %q", ErrInvalid, t.OriginKind)
	}
	if t.OriginID == uuid.Nil {
		return fmt.Errorf("%w: origin id is required", ErrInvalid)
	}
	if len(t.FarIdentity) == 0 {
		return fmt.Errorf("%w: far identity is empty", ErrInvalid)
	}
	for k, v := range t.FarIdentity {
		if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			return fmt.Errorf("%w: far identity has an empty key or value", ErrInvalid)
		}
	}
	if !intentPattern.MatchString(t.Intent) {
		return fmt.Errorf("%w: intent %q (cable, assignment or relationship:<type>)", ErrInvalid, t.Intent)
	}
	return nil
}

// IdentityKey is one key/value of a far identity.
type IdentityKey struct {
	Key   string
	Value string
}

// IdentityKeys returns t's far identity as sorted key/value pairs.
func (t Termination) IdentityKeys() []IdentityKey {
	out := make([]IdentityKey, 0, len(t.FarIdentity))
	for k, v := range t.FarIdentity {
		out = append(out, IdentityKey{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Repository stores parked terminations. Every method is tenant-scoped.
type Repository interface {
	// Park stores t, or — when the same producer, origin, intent and far
	// identity are already parked — bumps observation_count, moves
	// last_seen_at to seenAt and extends expires_at to seenAt + DefaultTTL.
	// Attributes are replaced by the latest observation's.
	Park(ctx context.Context, tenant uuid.UUID, t Termination, seenAt time.Time) (Parked, error)
	// ListByIdentityKeys returns parked rows whose far identity carries ANY of
	// keys (exact key and value), ordered by first_seen_at then id.
	ListByIdentityKeys(ctx context.Context, tenant uuid.UUID, keys []IdentityKey) ([]Parked, error)
	// List returns up to limit rows with id greater than after (uuid.Nil = from
	// the start), ordered by id, for the resolver's walk.
	List(ctx context.Context, tenant uuid.UUID, after uuid.UUID, limit int) ([]Parked, error)
	// Delete removes one row. Deleting a row that is gone is not an error.
	Delete(ctx context.Context, tenant, id uuid.UUID) error
	// ExpireBefore deletes rows whose expires_at is before cutoff and returns
	// how many went.
	ExpireBefore(ctx context.Context, tenant uuid.UUID, cutoff time.Time) (int, error)
}

// Match is the object a far identity resolved to.
type Match struct {
	Kind dcim.ObjectKind
	ID   uuid.UUID
}

// Matcher answers "does anything carry this identity yet?". Each method
// returns ok=false when nothing does. Implementations must be tenant-scoped.
type Matcher interface {
	MatchInterfaceByMAC(ctx context.Context, tenant uuid.UUID, mac string) (Match, bool, error)
	MatchAssetByChassisID(ctx context.Context, tenant uuid.UUID, chassisID string) (Match, bool, error)
	MatchAssetByCloudResourceID(ctx context.Context, tenant uuid.UUID, resourceID string) (Match, bool, error)
	// MatchBySyncKey resolves a sync key ("sync:netbox:interface") and the
	// peer's id for the object.
	MatchBySyncKey(ctx context.Context, tenant uuid.UUID, key, value string) (Match, bool, error)
}

// TerminationMatcher is implemented by a Matcher that resolves a parked row
// from its WHOLE far identity rather than one key at a time (row 3.3: an LLDP
// neighbour's far end is the interface named by chassis id or system name or
// management address AND port id, and "the device exists but that port does
// not yet" must stay parked rather than fail an apply). The resolver asks it
// right after the sync keys; ok=false falls through to the per-key methods.
type TerminationMatcher interface {
	MatchTermination(ctx context.Context, tenant uuid.UUID, p Parked) (Match, bool, error)
}

// NullMatcher never matches. It is the matcher until phase 1 supplies real
// ones, and the one a test uses to prove nothing resolves by accident.
type NullMatcher struct{}

func (NullMatcher) MatchInterfaceByMAC(context.Context, uuid.UUID, string) (Match, bool, error) {
	return Match{}, false, nil
}
func (NullMatcher) MatchAssetByChassisID(context.Context, uuid.UUID, string) (Match, bool, error) {
	return Match{}, false, nil
}
func (NullMatcher) MatchAssetByCloudResourceID(context.Context, uuid.UUID, string) (Match, bool, error) {
	return Match{}, false, nil
}
func (NullMatcher) MatchBySyncKey(context.Context, uuid.UUID, string, string) (Match, bool, error) {
	return Match{}, false, nil
}

// Applier writes the intended object once the far end is known. Phase 3
// implements ApplyCable, phase 1 the other two.
type Applier interface {
	ApplyCable(ctx context.Context, tenant uuid.UUID, p Parked, far Match) error
	ApplyRelationship(ctx context.Context, tenant uuid.UUID, p Parked, relType string, far Match) error
	ApplyAssignment(ctx context.Context, tenant uuid.UUID, p Parked, far Match) error
}

// ResolvedCount is what one Resolve pass did.
type ResolvedCount struct {
	Examined  int
	Resolved  int
	Expired   int
	Unmatched int
}

// Resolver resolves a tenant's parked terminations.
type Resolver interface {
	Resolve(ctx context.Context, tenant uuid.UUID) (ResolvedCount, error)
}

// NewResolver returns the resolver over repo. now is the clock (time.Now when
// nil); a test passes a fixed one.
func NewResolver(repo Repository, m Matcher, a Applier, now func() time.Time) Resolver {
	if now == nil {
		now = time.Now
	}
	return &resolver{repo: repo, m: m, a: a, now: now}
}

type resolver struct {
	repo Repository
	m    Matcher
	a    Applier
	now  func() time.Time
}

// pageSize bounds one List call of the walk.
const pageSize = 500

// Resolve expires stale rows first — an expired identity is not matched late —
// then walks every parked row: the first identity key that matches (sync key,
// whole-termination match when the matcher is a [TerminationMatcher], cloud
// resource id, MAC, chassis id, in that order: the most specific identity
// wins) is applied and the row deleted. A row whose apply fails stays
// parked for the next pass; the errors are joined and returned after the walk.
func (r *resolver) Resolve(ctx context.Context, tenant uuid.UUID) (ResolvedCount, error) {
	var n ResolvedCount
	expired, err := r.repo.ExpireBefore(ctx, tenant, r.now())
	if err != nil {
		return n, fmt.Errorf("unresolved: expire: %w", err)
	}
	n.Expired = expired

	var errs []error
	after := uuid.Nil
	for {
		page, err := r.repo.List(ctx, tenant, after, pageSize)
		if err != nil {
			return n, fmt.Errorf("unresolved: list: %w", err)
		}
		for _, p := range page {
			n.Examined++
			far, ok, err := r.match(ctx, tenant, p)
			if err != nil {
				errs = append(errs, fmt.Errorf("unresolved: match %s: %w", p.ID, err))
				continue
			}
			if !ok {
				n.Unmatched++
				continue
			}
			if err := r.apply(ctx, tenant, p, far); err != nil {
				errs = append(errs, fmt.Errorf("unresolved: apply %s: %w", p.ID, err))
				continue
			}
			if err := r.repo.Delete(ctx, tenant, p.ID); err != nil {
				errs = append(errs, fmt.Errorf("unresolved: delete %s: %w", p.ID, err))
				continue
			}
			n.Resolved++
		}
		if len(page) < pageSize {
			break
		}
		after = page[len(page)-1].ID
	}
	return n, errors.Join(errs...)
}

func (r *resolver) match(ctx context.Context, tenant uuid.UUID, p Parked) (Match, bool, error) {
	keys := p.IdentityKeys()
	for _, k := range keys {
		if strings.HasPrefix(k.Key, KeySyncPrefix) {
			if m, ok, err := r.m.MatchBySyncKey(ctx, tenant, k.Key, k.Value); err != nil || ok {
				return m, ok, err
			}
		}
	}
	if tm, ok := r.m.(TerminationMatcher); ok {
		if m, ok, err := tm.MatchTermination(ctx, tenant, p); err != nil || ok {
			return m, ok, err
		}
	}
	ordered := []struct {
		key string
		fn  func(context.Context, uuid.UUID, string) (Match, bool, error)
	}{
		{KeyCloudResourceID, r.m.MatchAssetByCloudResourceID},
		{KeyMACAddress, r.m.MatchInterfaceByMAC},
		{KeyChassisID, r.m.MatchAssetByChassisID},
	}
	for _, o := range ordered {
		if v, ok := p.FarIdentity[o.key]; ok {
			if m, ok, err := o.fn(ctx, tenant, v); err != nil || ok {
				return m, ok, err
			}
		}
	}
	return Match{}, false, nil
}

func (r *resolver) apply(ctx context.Context, tenant uuid.UUID, p Parked, far Match) error {
	switch p.Intent {
	case IntentCable:
		return r.a.ApplyCable(ctx, tenant, p, far)
	case IntentAssignment:
		return r.a.ApplyAssignment(ctx, tenant, p, far)
	default:
		rt, ok := p.RelationshipType()
		if !ok {
			return fmt.Errorf("%w: intent %q", ErrInvalid, p.Intent)
		}
		return r.a.ApplyRelationship(ctx, tenant, p, rt, far)
	}
}
