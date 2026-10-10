// Package identitytest holds the behavioural contract every
// [identity.Repository] implementation must satisfy.
//
// It is an ordinary (non-_test) package so that the Postgres implementation in
// workstream 1.2, which lives in another module, can run exactly the same
// assertions the in-memory one does. Two implementations of a storage contract
// tested by two different test suites is how they drift, and the drift is
// invisible until production.
package identitytest

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// LastSeenReader and HistoryReader are the read-backs the contract needs to
// check two properties [identity.Repository] states but does not expose:
// that Touch never moves last-seen backwards, and that history is appended in
// order.
//
// They are separate from Repository because the ENGINE does not need them —
// nothing in production reads an asset's history through this interface. They
// are required of an implementation under test all the same: a store whose
// writes cannot be read back cannot be contract-tested, and an assertion that
// quietly skips itself when the read-back is missing is a check that cannot
// fail, which is worse than no check. Both are trivially satisfiable (the
// in-memory store already has them, and a SQL store has a query).
type (
	// LastSeenReader returns an asset's last-seen timestamp, zero if unknown.
	LastSeenReader interface {
		LastSeen(ref identity.AssetRef) time.Time
	}
	// SegmentWriter registers a network segment, so the ScopeForAddress
	// subtests have something to resolve against. OPTIONAL: an implementation
	// that cannot be given segments (because it reads them from somewhere the
	// contract cannot write) skips that subtest and is still held to the
	// no-segment contract, which is the one that matters.
	SegmentWriter interface {
		AddSegment(tenantID, cidr, scope string, dynamic bool) error
	}
	// CloudSegmentWriter registers a segment that belongs to a cloud network,
	// so the scoping subtests can build the case a LAN never produces: two
	// segments with the SAME CIDR in two different VPCs. OPTIONAL, on the same
	// terms as SegmentWriter.
	CloudSegmentWriter interface {
		AddSegment(tenantID, cidr, scope string, dynamic bool) error
		AddCloudSegment(tenantID, cidr, scope string, dynamic bool, networkRef string) error
	}
	// HistoryReader returns one asset's history entries, oldest first.
	//
	// It takes the whole ref, tenant included: a read-back that took a bare
	// asset id could only be implemented unscoped, and an unscoped read of a
	// tenant-policied table is a hole whether or not production calls it.
	HistoryReader interface {
		HistoryFor(ref identity.AssetRef) []identity.HistoryEntry
	}
	// EndpointReader returns the endpoints under an asset, oldest first. Like
	// HistoryReader, it exists only so the contract can assert what
	// [identity.Repository.UpsertEndpoints] does not expose through the
	// interface itself: in particular, that an address-bearing endpoint
	// upserted twice under two different fqdn spellings converges to ONE row
	// rather than accumulating a second — the IP-literal-fqdn defect this
	// method's subtest is named for.
	EndpointReader interface {
		Endpoints(ref identity.AssetRef) []identity.EndpointObservation
	}
)

// RunRepositoryContract exercises an implementation against the contract in
// [identity.Repository]'s documentation.
//
// newRepo must return a FRESH, empty repository on every call: each subtest
// gets its own so a failure in one cannot cascade. The implementation must
// also satisfy [LastSeenReader], [HistoryReader] and [EndpointReader].
func RunRepositoryContract(t *testing.T, newRepo func() identity.Repository) {
	t.Helper()

	const tenant = "tenant-a"
	const otherTenant = "tenant-b"
	ctx := context.Background()
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

	ident := func(kind identity.Kind, value, scope string) identity.Identifier {
		return identity.Identifier{
			Kind: kind, Value: value, Scope: scope,
			Confidence: 1,
			Source:     identity.Source{Kind: identity.SourceMeasured, Ref: "contract"},
			SeenAt:     now,
		}
	}
	newAsset := func(name string, ids ...identity.Identifier) identity.NewAsset {
		return identity.NewAsset{
			ClassKey:        "server",
			ClassSourceKind: identity.ClassSourceMeasured,
			DisplayName:     name,
			Status:          identity.StatusPendingApproval,
			Source:          identity.Source{Kind: identity.SourceMeasured, Ref: "contract"},
			Identifiers:     ids,
			FirstSeenAt:     now,
			LastSeenAt:      now,
		}
	}

	t.Run("CreateAsset returns a ref carrying the tenant", func(t *testing.T) {
		r := newRepo()
		ref, err := r.CreateAsset(ctx, tenant, newAsset("host-1"))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		if ref.ID == "" {
			t.Error("CreateAsset returned an empty id")
		}
		if ref.TenantID != tenant {
			t.Errorf("ref.TenantID = %q, want %q", ref.TenantID, tenant)
		}
	})

	t.Run("FindByIdentifier finds an attached identifier and nothing else", func(t *testing.T) {
		r := newRepo()
		id := ident(identity.KindSerialNumber, "SN-1", "")
		ref, err := r.CreateAsset(ctx, tenant, newAsset("host-1", id))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		got, err := r.FindByIdentifier(ctx, tenant, id.Kind, id.Value, id.Scope)
		if err != nil {
			t.Fatalf("FindByIdentifier: %v", err)
		}
		if len(got) != 1 || got[0].ID != ref.ID {
			t.Fatalf("FindByIdentifier = %+v, want exactly [%s]", got, ref.ID)
		}
		// An unknown identifier is a normal empty answer, not an error.
		missing, err := r.FindByIdentifier(ctx, tenant, identity.KindSerialNumber, "SN-nope", "")
		if err != nil {
			t.Fatalf("FindByIdentifier(unknown): %v", err)
		}
		if len(missing) != 0 {
			t.Errorf("FindByIdentifier(unknown) = %+v, want empty", missing)
		}
	})

	t.Run("an identifier value maps to at most one asset", func(t *testing.T) {
		r := newRepo()
		id := ident(identity.KindSerialNumber, "SN-1", "")
		if _, err := r.CreateAsset(ctx, tenant, newAsset("host-1", id)); err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		if _, err := r.CreateAsset(ctx, tenant, newAsset("host-2", id)); !errors.Is(err, identity.ErrIdentifierConflict) {
			t.Fatalf("CreateAsset with a taken identifier: err = %v, want ErrIdentifierConflict", err)
		}
		second, err := r.CreateAsset(ctx, tenant, newAsset("host-2"))
		if err != nil {
			t.Fatalf("CreateAsset(host-2): %v", err)
		}
		if _, err := r.AttachIdentifiers(ctx, second, []identity.Identifier{id}); !errors.Is(err, identity.ErrIdentifierConflict) {
			t.Fatalf("AttachIdentifiers with a taken identifier: err = %v, want ErrIdentifierConflict", err)
		}
	})

	t.Run("a failed create writes nothing", func(t *testing.T) {
		r := newRepo()
		taken := ident(identity.KindSerialNumber, "SN-1", "")
		free := ident(identity.KindMACAddress, "aa:bb:cc:dd:ee:01", "")
		if _, err := r.CreateAsset(ctx, tenant, newAsset("host-1", taken)); err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		if _, err := r.CreateAsset(ctx, tenant, newAsset("host-2", free, taken)); !errors.Is(err, identity.ErrIdentifierConflict) {
			t.Fatalf("err = %v, want ErrIdentifierConflict", err)
		}
		// The free identifier must not have been claimed by the asset that
		// was never created.
		got, err := r.FindByIdentifier(ctx, tenant, free.Kind, free.Value, free.Scope)
		if err != nil {
			t.Fatalf("FindByIdentifier: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("a rolled-back create left %s claimed by %+v", free.Value, got)
		}
	})

	t.Run("scope distinguishes identifiers", func(t *testing.T) {
		r := newRepo()
		a, err := r.CreateAsset(ctx, tenant, newAsset("printer-2", ident(identity.KindHostname, "printer-2", "segment-1")))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		b, err := r.CreateAsset(ctx, tenant, newAsset("printer-2", ident(identity.KindHostname, "printer-2", "segment-2")))
		if err != nil {
			t.Fatalf("CreateAsset in a second segment: %v", err)
		}
		got, err := r.FindByIdentifier(ctx, tenant, identity.KindHostname, "printer-2", "segment-2")
		if err != nil {
			t.Fatalf("FindByIdentifier: %v", err)
		}
		if len(got) != 1 || got[0].ID != b.ID {
			t.Fatalf("segment-2 lookup = %+v, want [%s] (and not %s)", got, b.ID, a.ID)
		}
	})

	t.Run("tenants are isolated", func(t *testing.T) {
		r := newRepo()
		id := ident(identity.KindSerialNumber, "SN-1", "")
		mine, err := r.CreateAsset(ctx, tenant, newAsset("host-1", id))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		theirs, err := r.CreateAsset(ctx, otherTenant, newAsset("host-1", id))
		if err != nil {
			t.Fatalf("CreateAsset in another tenant with the same serial: %v", err)
		}
		got, err := r.FindByIdentifier(ctx, otherTenant, id.Kind, id.Value, id.Scope)
		if err != nil {
			t.Fatalf("FindByIdentifier: %v", err)
		}
		if len(got) != 1 || got[0].ID != theirs.ID {
			t.Fatalf("other tenant lookup = %+v, want [%s] (and never %s)", got, theirs.ID, mine.ID)
		}
		if s, err := r.LoadSummaries(ctx, otherTenant, []string{mine.ID}); err != nil || len(s) != 0 {
			t.Fatalf("LoadSummaries across tenants = %+v (err %v), want empty", s, err)
		}
	})

	t.Run("PromoteNames raises quality and never demotes", func(t *testing.T) {
		r := newRepo()
		ref, err := r.CreateAsset(ctx, tenant, identity.NewAsset{
			ClassKey:        "server",
			ClassSourceKind: identity.ClassSourceMeasured,
			DisplayName:     "4c6e0a87d480.local",
			Hostname:        "4c6e0a87d480.local",
			Status:          identity.StatusPendingApproval,
			Source:          identity.Source{Kind: identity.SourceMeasured, Ref: "contract", Mode: identity.ModePassive},
			Identifiers:     []identity.Identifier{ident(identity.KindHostname, "4c6e0a87d480.local", "segment-1")},
			FirstSeenAt:     now,
			LastSeenAt:      now,
		})
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		if err := r.PromoteNames(ctx, ref, "linux-2", "linux-2", "measured-passive"); err != nil {
			t.Fatalf("PromoteNames linux-2: %v", err)
		}
		sums, err := r.LoadSummaries(ctx, tenant, []string{ref.ID})
		if err != nil || len(sums) != 1 {
			t.Fatalf("LoadSummaries = %+v (err %v)", sums, err)
		}
		if sums[0].Hostname != "linux-2" || sums[0].DisplayName != "linux-2" {
			t.Fatalf("after linux-2 promote hostname=%q display=%q, want linux-2", sums[0].Hostname, sums[0].DisplayName)
		}
		if err := r.PromoteNames(ctx, ref, "4c6e0a87d480.local", "4c6e0a87d480.local", "measured-passive"); err != nil {
			t.Fatalf("PromoteNames hex: %v", err)
		}
		sums, err = r.LoadSummaries(ctx, tenant, []string{ref.ID})
		if err != nil || len(sums) != 1 {
			t.Fatalf("LoadSummaries after hex: %+v (err %v)", sums, err)
		}
		if sums[0].Hostname != "linux-2" || sums[0].DisplayName != "linux-2" {
			t.Fatalf("hex mDNS reverted the name: hostname=%q display=%q", sums[0].Hostname, sums[0].DisplayName)
		}
	})

	t.Run("AttachIdentifiers is idempotent", func(t *testing.T) {
		r := newRepo()
		ref, err := r.CreateAsset(ctx, tenant, newAsset("host-1"))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		id := ident(identity.KindSerialNumber, "SN-1", "")
		for i := range 3 {
			if _, err := r.AttachIdentifiers(ctx, ref, []identity.Identifier{id}); err != nil {
				t.Fatalf("AttachIdentifiers pass %d: %v", i, err)
			}
		}
		sums, err := r.LoadSummaries(ctx, tenant, []string{ref.ID})
		if err != nil || len(sums) != 1 {
			t.Fatalf("LoadSummaries = %+v (err %v)", sums, err)
		}
		if n := countKind(sums[0].Identifiers, identity.KindSerialNumber); n != 1 {
			t.Errorf("after 3 attaches the asset carries %d serials, want 1", n)
		}
	})

	// Phase 2: a derived identifier's provenance is what the asset page
	// shows as "derived from <evidence>". A derived re-sighting of a value held
	// natively must not relabel it, and a native sighting of a value held as
	// derived must upgrade it — otherwise the page says "worked out" about a
	// MAC a controller has since reported.
	t.Run("AttachIdentifiers: a derived re-sighting never demotes native provenance, a native one upgrades it", func(t *testing.T) {
		r := newRepo()
		derived := func(value, ref string) identity.Identifier {
			d := ident(identity.KindMACAddress, value, "")
			d.Source = identity.Source{Kind: identity.SourceInferred, Ref: ref}
			d.Confidence = 0.9
			return d
		}
		provenance := func(ref identity.AssetRef, value string) identity.Source {
			t.Helper()
			sums, err := r.LoadSummaries(ctx, tenant, []string{ref.ID})
			if err != nil || len(sums) != 1 {
				t.Fatalf("LoadSummaries = %+v (err %v)", sums, err)
			}
			for _, id := range sums[0].Identifiers {
				if id.Kind == identity.KindMACAddress && id.Value == value {
					return id.Source
				}
			}
			t.Fatalf("%s not on the asset", value)
			return identity.Source{}
		}

		native, err := r.CreateAsset(ctx, tenant, newAsset("host-native", ident(identity.KindMACAddress, "aa:bb:cc:dd:ee:01", "")))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		if _, err := r.AttachIdentifiers(ctx, native, []identity.Identifier{derived("aa:bb:cc:dd:ee:01", "derived:eui64:2001:db8::a8bb:ccff:fedd:ee01")}); err != nil {
			t.Fatalf("AttachIdentifiers(derived over native): %v", err)
		}
		if got := provenance(native, "aa:bb:cc:dd:ee:01"); got.Kind != identity.SourceMeasured || got.Ref != "contract" {
			t.Errorf("a derived re-sighting relabelled a native MAC: %+v, want measured/contract", got)
		}

		held, err := r.CreateAsset(ctx, tenant, newAsset("host-derived", derived("aa:bb:cc:dd:ee:02", "derived:serial:AABBCCDDEE02")))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		if got := provenance(held, "aa:bb:cc:dd:ee:02"); got.Kind != identity.SourceInferred || got.Ref != "derived:serial:AABBCCDDEE02" {
			t.Fatalf("a derived MAC was stored as %+v, want inferred with its evidence", got)
		}
		if _, err := r.AttachIdentifiers(ctx, held, []identity.Identifier{ident(identity.KindMACAddress, "aa:bb:cc:dd:ee:02", "")}); err != nil {
			t.Fatalf("AttachIdentifiers(native over derived): %v", err)
		}
		if got := provenance(held, "aa:bb:cc:dd:ee:02"); got.Kind != identity.SourceMeasured || got.Ref != "contract" {
			t.Errorf("a native sighting did not upgrade a derived MAC: %+v, want measured/contract", got)
		}
	})

	//: the identifier upsert's provenance ladder (identity.UpsertIdentifier)
	// is declared > measured = imported > inferred, source_ref travels with
	// source_kind, and a pinned address is never unpinned by a weaker or silent
	// sighting. Before, only `inferred` could move: an operator declaring an
	// address a sensor had measured left the row `measured` with the
	// declaration's ref — and the gateway's own LAN address could never be told
	// apart from a lease.
	t.Run("AttachIdentifiers: a declaration upgrades a measured row, a weaker sighting never rewrites it, a pin is never lost", func(t *testing.T) {
		r := newRepo()
		stored := func(ref identity.AssetRef, kind identity.Kind, value string) identity.Identifier {
			t.Helper()
			sums, err := r.LoadSummaries(ctx, tenant, []string{ref.ID})
			if err != nil || len(sums) != 1 {
				t.Fatalf("LoadSummaries = %+v (err %v)", sums, err)
			}
			for _, id := range sums[0].Identifiers {
				if id.Kind == kind && id.Value == value {
					return id
				}
			}
			t.Fatalf("%s=%s not on the asset", kind, value)
			return identity.Identifier{}
		}
		with := func(id identity.Identifier, kind identity.SourceKind, ref string, a identity.AddressAssignment) identity.Identifier {
			id.Source = identity.Source{Kind: kind, Ref: ref}
			id.Assignment = a
			return id
		}
		attach := func(ref identity.AssetRef, id identity.Identifier) {
			t.Helper()
			if _, err := r.AttachIdentifiers(ctx, ref, []identity.Identifier{id}); err != nil {
				t.Fatalf("AttachIdentifiers(%s %s/%s %q): %v", id.Value, id.Source.Kind, id.Source.Ref, id.Assignment, err)
			}
		}
		want := func(step string, got identity.Identifier, kind identity.SourceKind, ref string, a identity.AddressAssignment) {
			t.Helper()
			if got.Source.Kind != kind || got.Source.Ref != ref || got.Assignment != a {
				t.Errorf("%s: stored %s/%s assignment %q, want %s/%s assignment %q",
					step, got.Source.Kind, got.Source.Ref, got.Assignment, kind, ref, a)
			}
		}

		// A sensor measured the gateway's address; then an operator declared it.
		addr := ident(identity.KindIPAddress, "192.0.2.1", "seg-pin")
		gw, err := r.CreateAsset(ctx, tenant, newAsset("gateway", with(addr, identity.SourceMeasured, "sensor:1", "")))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		want("measured on create", stored(gw, identity.KindIPAddress, "192.0.2.1"), identity.SourceMeasured, "sensor:1", "")
		attach(gw, with(addr, identity.SourceDeclared, "manual", ""))
		want("declared over measured", stored(gw, identity.KindIPAddress, "192.0.2.1"), identity.SourceDeclared, "manual", identity.AssignmentStatic)

		// Every weaker sighting refreshes the row without rewriting who vouched
		// for it, and none of them unpins it — not the sensor (which says
		// nothing), not an agent saying "dhcp", not a derived value.
		attach(gw, with(addr, identity.SourceMeasured, "sensor:2", ""))
		want("measured over declared", stored(gw, identity.KindIPAddress, "192.0.2.1"), identity.SourceDeclared, "manual", identity.AssignmentStatic)
		attach(gw, with(addr, identity.SourceMeasured, "agent:1", identity.AssignmentDynamic))
		want("agent dhcp over declared", stored(gw, identity.KindIPAddress, "192.0.2.1"), identity.SourceDeclared, "manual", identity.AssignmentStatic)
		attach(gw, with(addr, identity.SourceInferred, "derived:x", ""))
		want("inferred over declared", stored(gw, identity.KindIPAddress, "192.0.2.1"), identity.SourceDeclared, "manual", identity.AssignmentStatic)
		attach(gw, with(addr, identity.SourceDeclared, "operator:2", ""))
		want("declared refresh", stored(gw, identity.KindIPAddress, "192.0.2.1"), identity.SourceDeclared, "operator:2", identity.AssignmentStatic)

		// A host's own agent: its report is the assignment, and a later report
		// of equal standing replaces it — the host was reconfigured. Silence
		// (a sensor) never clears it.
		hostAddr := ident(identity.KindIPAddress, "192.0.2.20", "seg-pin")
		host, err := r.CreateAsset(ctx, tenant, newAsset("host", with(hostAddr, identity.SourceMeasured, "agent:1", identity.AssignmentStatic)))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		want("agent static on create", stored(host, identity.KindIPAddress, "192.0.2.20"), identity.SourceMeasured, "agent:1", identity.AssignmentStatic)
		attach(host, with(hostAddr, identity.SourceMeasured, "sensor:1", ""))
		want("sensor over agent static", stored(host, identity.KindIPAddress, "192.0.2.20"), identity.SourceMeasured, "sensor:1", identity.AssignmentStatic)
		attach(host, with(hostAddr, identity.SourceMeasured, "agent:1", identity.AssignmentDynamic))
		want("agent dhcp over agent static", stored(host, identity.KindIPAddress, "192.0.2.20"), identity.SourceMeasured, "agent:1", identity.AssignmentDynamic)
		attach(host, with(hostAddr, identity.SourceInferred, "derived:y", identity.AssignmentStatic))
		want("inferred static over measured dynamic", stored(host, identity.KindIPAddress, "192.0.2.20"), identity.SourceMeasured, "agent:1", identity.AssignmentDynamic)
		attach(host, with(hostAddr, identity.SourceDeclared, "manual", ""))
		want("declared over agent dhcp", stored(host, identity.KindIPAddress, "192.0.2.20"), identity.SourceDeclared, "manual", identity.AssignmentStatic)

		// Intake's marker (Identifier.Pinned, PR 2210) is the same pin; an
		// explicit "dhcp" from the host wins over it, because Intake marks
		// every self-reported address Pinned.
		marked := ident(identity.KindIPAddress, "192.0.2.21", "seg-pin")
		marked.Pinned = true
		mk, err := r.CreateAsset(ctx, tenant, newAsset("marked", marked))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		want("Pinned on create", stored(mk, identity.KindIPAddress, "192.0.2.21"), identity.SourceMeasured, "contract", identity.AssignmentStatic)
		leased := ident(identity.KindIPAddress, "192.0.2.22", "seg-pin")
		leased.Pinned, leased.Assignment = true, identity.AssignmentDynamic
		ls, err := r.CreateAsset(ctx, tenant, newAsset("leased", leased))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		want("Pinned but dhcp", stored(ls, identity.KindIPAddress, "192.0.2.22"), identity.SourceMeasured, "contract", identity.AssignmentDynamic)

		// Sideways: an import of a value a collector measured keeps the
		// measured provenance and its ref — equal standing, first writer wins.
		mac := ident(identity.KindMACAddress, "aa:bb:cc:dd:ee:30", "")
		side, err := r.CreateAsset(ctx, tenant, newAsset("side", with(mac, identity.SourceMeasured, "sensor:1", "")))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		attach(side, with(mac, identity.SourceImported, "cmdb:1", ""))
		want("imported over measured", stored(side, identity.KindMACAddress, "aa:bb:cc:dd:ee:30"), identity.SourceMeasured, "sensor:1", "")
		// A declared MAC is upgraded like any identifier, and carries no
		// assignment: that is a fact about addresses only.
		attach(side, with(mac, identity.SourceDeclared, "manual", ""))
		want("declared MAC", stored(side, identity.KindMACAddress, "aa:bb:cc:dd:ee:30"), identity.SourceDeclared, "manual", "")
	})

	t.Run("AttachIdentifiers and Touch reject an unknown asset", func(t *testing.T) {
		r := newRepo()
		ghost := identity.AssetRef{TenantID: tenant, ID: "no-such-asset"}
		if _, err := r.AttachIdentifiers(ctx, ghost, []identity.Identifier{ident(identity.KindSerialNumber, "SN-x", "")}); !errors.Is(err, identity.ErrAssetNotFound) {
			t.Errorf("AttachIdentifiers on a ghost: err = %v, want ErrAssetNotFound", err)
		}
		if err := r.Touch(ctx, ghost, now); !errors.Is(err, identity.ErrAssetNotFound) {
			t.Errorf("Touch on a ghost: err = %v, want ErrAssetNotFound", err)
		}
		if err := r.PromoteNames(ctx, ghost, "linux-2", "linux-2", "measured-passive"); !errors.Is(err, identity.ErrAssetNotFound) {
			t.Errorf("PromoteNames on a ghost: err = %v, want ErrAssetNotFound", err)
		}
		if _, err := r.UpsertEndpoints(ctx, ghost, []identity.EndpointObservation{{Address: "192.0.2.1", Port: 443, Transport: "tcp"}}); !errors.Is(err, identity.ErrAssetNotFound) {
			t.Errorf("UpsertEndpoints on a ghost: err = %v, want ErrAssetNotFound", err)
		}
	})

	t.Run("ReconcileSourceEndpoints closes only the source's absent, older endpoints", func(t *testing.T) {
		r := newRepo()
		ref, err := r.CreateAsset(ctx, tenant, newAsset("host-1"))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		src := func(ref string) identity.Source {
			return identity.Source{Kind: identity.SourceMeasured, Ref: ref, Mode: identity.ModeActive}
		}
		kept := identity.EndpointObservation{Address: "192.0.2.10", Port: 22, Transport: "tcp", Source: src("agent:a:run1"), SeenAt: now}
		dropped := identity.EndpointObservation{Address: "192.0.2.10", Port: 443, Transport: "tcp", Source: src("agent:a:run1"), SeenAt: now}
		other := identity.EndpointObservation{Address: "192.0.2.10", Port: 9443, Transport: "tcp", Source: src("sensor:scan"), SeenAt: now}
		newer := identity.EndpointObservation{Address: "192.0.2.10", Port: 8080, Transport: "tcp", Source: src("agent:a:run9"), SeenAt: now.Add(2 * time.Hour)}
		if _, err := r.UpsertEndpoints(ctx, ref, []identity.EndpointObservation{kept, dropped, other, newer}); err != nil {
			t.Fatalf("UpsertEndpoints: %v", err)
		}
		at := now.Add(time.Hour)
		closed, err := r.ReconcileSourceEndpoints(ctx, ref, "agent:a:", []identity.EndpointObservation{kept}, at)
		if err != nil {
			t.Fatalf("ReconcileSourceEndpoints: %v", err)
		}
		if len(closed) != 1 || closed[0] != dropped.Key() {
			t.Errorf("closed = %v, want only %s (another source's :9443 and a socket seen after the set stay open)", closed, dropped.Key())
		}
		if again, err := r.ReconcileSourceEndpoints(ctx, ref, "agent:a:", []identity.EndpointObservation{kept}, at); err != nil || len(again) != 0 {
			t.Errorf("second reconcile = %v, %v; a closed endpoint is not closed twice", again, err)
		}
		if _, err := r.UpsertEndpoints(ctx, ref, []identity.EndpointObservation{dropped}); err != nil {
			t.Fatalf("UpsertEndpoints (reopen): %v", err)
		}
		if reopened, err := r.ReconcileSourceEndpoints(ctx, ref, "agent:a:", []identity.EndpointObservation{kept}, at); err != nil || len(reopened) != 1 {
			t.Errorf("after the socket came back, reconcile = %v, %v; want it closable again (an upsert reopens)", reopened, err)
		}
		if _, err := r.ReconcileSourceEndpoints(ctx, ref, "", nil, at); err == nil {
			t.Error("an empty source prefix was accepted; it would close every source's endpoints")
		}
	})

	t.Run("UpsertEndpoints deduplicates on the endpoint key", func(t *testing.T) {
		r := newRepo()
		ref, err := r.CreateAsset(ctx, tenant, newAsset("host-1"))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		ep := identity.EndpointObservation{Address: "192.0.2.10", Port: 443, Transport: "tcp", SeenAt: now}
		if _, err := r.UpsertEndpoints(ctx, ref, []identity.EndpointObservation{ep}); err != nil {
			t.Fatalf("UpsertEndpoints: %v", err)
		}
		later := ep
		later.Protocol = "https"
		later.SeenAt = now.Add(time.Hour)
		if _, err := r.UpsertEndpoints(ctx, ref, []identity.EndpointObservation{later}); err != nil {
			t.Fatalf("UpsertEndpoints again: %v", err)
		}
		reader, ok := r.(EndpointReader)
		if !ok {
			t.Fatalf("%T does not implement identitytest.EndpointReader, so the contract cannot check that the second upsert merged rather than added a row", r)
		}
		if eps := reader.Endpoints(ref); len(eps) != 1 {
			t.Errorf("endpoints after a repeat upsert = %v, want exactly 1", eps)
		}
	})

	// The engine writes an `updated` timeline row only when a match changed
	// something, and decides that from these counts — so the two backends must
	// agree on what "changed" means.
	t.Run("AttachIdentifiers and UpsertEndpoints report what they newly wrote", func(t *testing.T) {
		r := newRepo()
		ref, err := r.CreateAsset(ctx, tenant, newAsset("host-count"))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		serial := ident(identity.KindSerialNumber, "SN-count", "")
		mac := ident(identity.KindMACAddress, "aa:bb:cc:dd:ee:41", "")
		added, err := r.AttachIdentifiers(ctx, ref, []identity.Identifier{serial})
		if err != nil || added != 1 {
			t.Fatalf("attaching a new identifier: added=%d err=%v, want 1", added, err)
		}
		serial.SeenAt = now.Add(time.Hour)
		added, err = r.AttachIdentifiers(ctx, ref, []identity.Identifier{serial})
		if err != nil || added != 0 {
			t.Errorf("re-attaching a held identifier: added=%d err=%v, want 0 (a refreshed last-seen is not new)", added, err)
		}
		added, err = r.AttachIdentifiers(ctx, ref, []identity.Identifier{serial, mac})
		if err != nil || added != 1 {
			t.Errorf("one held and one new identifier: added=%d err=%v, want 1", added, err)
		}

		ep := identity.EndpointObservation{Address: "192.0.2.41", Port: 443, Transport: "tcp", SeenAt: now}
		changed, err := r.UpsertEndpoints(ctx, ref, []identity.EndpointObservation{ep})
		if err != nil || changed != 1 {
			t.Fatalf("a new endpoint: changed=%d err=%v, want 1", changed, err)
		}
		again := ep
		again.SeenAt = now.Add(time.Hour)
		changed, err = r.UpsertEndpoints(ctx, ref, []identity.EndpointObservation{again})
		if err != nil || changed != 0 {
			t.Errorf("the same endpoint again: changed=%d err=%v, want 0", changed, err)
		}
		named := again
		named.Protocol = "https"
		named.ServiceName = "nginx"
		changed, err = r.UpsertEndpoints(ctx, ref, []identity.EndpointObservation{named})
		if err != nil || changed != 1 {
			t.Errorf("the endpoint gaining a protocol and service: changed=%d err=%v, want 1", changed, err)
		}
		changed, err = r.UpsertEndpoints(ctx, ref, []identity.EndpointObservation{named, again})
		if err != nil || changed != 0 {
			t.Errorf("the identified endpoint re-seen, once by name and once by a source that does not know the service: changed=%d err=%v, want 0 (empty never wins)", changed, err)
		}
		other := identity.EndpointObservation{Address: "192.0.2.41", Port: 8443, Transport: "tcp", SeenAt: now}
		changed, err = r.UpsertEndpoints(ctx, ref, []identity.EndpointObservation{named, other})
		if err != nil || changed != 1 {
			t.Errorf("one held endpoint and one on another port: changed=%d err=%v, want 1", changed, err)
		}
	})

	t.Run("HistoryHasChange answers by JSON containment, scoped to asset and action", func(t *testing.T) {
		r := newRepo()
		ref, err := r.CreateAsset(ctx, tenant, newAsset("host-hist"))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		other, err := r.CreateAsset(ctx, tenant, newAsset("host-hist-other"))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		if err := r.RecordHistory(ctx, identity.HistoryEntry{
			TenantID: tenant, AssetID: ref.ID, Action: identity.ActionUpdated,
			Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor"}, At: now,
			Changes: map[string]any{
				"unattached": []string{"mac_address|aa:bb:cc:dd:ee:51", "ip_address|192.0.2.51"},
				"supporting": true,
				"nested":     map[string]any{"announcer": "x", "macs": []string{"m1", "m2"}},
			},
		}); err != nil {
			t.Fatalf("RecordHistory: %v", err)
		}
		for _, c := range []struct {
			name   string
			asset  identity.AssetRef
			action identity.HistoryAction
			subset map[string]any
			want   bool
		}{
			{"the whole set", ref, identity.ActionUpdated, map[string]any{"unattached": []string{"mac_address|aa:bb:cc:dd:ee:51", "ip_address|192.0.2.51"}}, true},
			{"a subset of the array", ref, identity.ActionUpdated, map[string]any{"unattached": []string{"ip_address|192.0.2.51"}}, true},
			{"an element it does not hold", ref, identity.ActionUpdated, map[string]any{"unattached": []string{"ip_address|192.0.2.99"}}, false},
			{"a superset of the array", ref, identity.ActionUpdated, map[string]any{"unattached": []string{"ip_address|192.0.2.51", "ip_address|192.0.2.99"}}, false},
			{"a scalar that differs", ref, identity.ActionUpdated, map[string]any{"supporting": false}, false},
			{"a nested object", ref, identity.ActionUpdated, map[string]any{"nested": map[string]any{"macs": []string{"m2"}}}, true},
			{"another action", ref, identity.ActionCreated, map[string]any{"supporting": true}, false},
			{"another asset", other, identity.ActionUpdated, map[string]any{"supporting": true}, false},
		} {
			got, err := r.HistoryHasChange(ctx, c.asset, c.action, c.subset)
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
				continue
			}
			if got != c.want {
				t.Errorf("%s: HistoryHasChange = %v, want %v", c.name, got, c.want)
			}
		}
	})

	t.Run("UpsertEndpoints folds an IP-literal fqdn into one row, name wins", func(t *testing.T) {
		// The defect: an active-scan path that does not know a name writes
		// its scan target into fqdn even when the target is an IP literal.
		// Three observations of the SAME listener arrive over time — first a
		// passive one with no name, then an active scan that only knows the
		// address (and, before the fix, spelled that address into fqdn), then
		// something that finally resolves a real name — and all three must
		// converge on ONE asset_endpoints row: an endpoint identified by an
		// address is identified by (address, port, transport), and fqdn is an
		// attribute of it, not part of what identifies it.
		r := newRepo()
		reader, ok := r.(EndpointReader)
		if !ok {
			t.Fatalf("%T does not implement identitytest.EndpointReader, so this subtest cannot check what it exists to check", r)
		}
		ref, err := r.CreateAsset(ctx, tenant, newAsset("host-1"))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}

		// 1. Passive observation: address known, no name.
		passive := identity.EndpointObservation{Address: "192.0.2.230", Port: 443, Transport: "tcp", SeenAt: now}
		if _, err := r.UpsertEndpoints(ctx, ref, []identity.EndpointObservation{passive}); err != nil {
			t.Fatalf("UpsertEndpoints (passive): %v", err)
		}

		// 2. Active scan: no name resolved, so the intake path that has not
		// been fixed would hand back the scan target itself as the "hostname"
		// — an IP literal, spelled into FQDN here to simulate exactly that
		// unfixed caller. A correct repository must not let this survive as a
		// name, and must not create a second row for it either.
		activeScanNoName := identity.EndpointObservation{
			Address: "192.0.2.230", FQDN: "192.0.2.230", Port: 443, Transport: "tcp",
			SeenAt: now.Add(time.Minute),
		}
		if _, err := r.UpsertEndpoints(ctx, ref, []identity.EndpointObservation{activeScanNoName}); err != nil {
			t.Fatalf("UpsertEndpoints (active scan, ip-literal fqdn): %v", err)
		}
		if eps := reader.Endpoints(ref); len(eps) != 1 {
			t.Fatalf("endpoints after the ip-literal-fqdn observation = %v, want exactly 1", eps)
		} else if eps[0].FQDN == "192.0.2.230" {
			t.Errorf("endpoint fqdn = %q, an IP literal is never a name — it must be dropped, not stored", eps[0].FQDN)
		}

		// 3. Something resolves a real name for the same listener.
		named := identity.EndpointObservation{
			Address: "192.0.2.230", FQDN: "host.corp.example", Port: 443, Transport: "tcp",
			SeenAt: now.Add(2 * time.Minute),
		}
		if _, err := r.UpsertEndpoints(ctx, ref, []identity.EndpointObservation{named}); err != nil {
			t.Fatalf("UpsertEndpoints (named): %v", err)
		}

		eps := reader.Endpoints(ref)
		if len(eps) != 1 {
			t.Fatalf("endpoints after all three observations = %v, want exactly 1 row for one listener", eps)
		}
		if eps[0].FQDN != "host.corp.example" {
			t.Errorf("endpoint fqdn = %q, want %q", eps[0].FQDN, "host.corp.example")
		}
		if eps[0].Address != "192.0.2.230" {
			t.Errorf("endpoint address = %q, want %q", eps[0].Address, "192.0.2.230")
		}
	})

	t.Run("Touch never moves last-seen backwards", func(t *testing.T) {
		r := newRepo()
		ref, err := r.CreateAsset(ctx, tenant, newAsset("host-1"))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		if err := r.Touch(ctx, ref, now.Add(time.Hour)); err != nil {
			t.Fatalf("Touch: %v", err)
		}
		if err := r.Touch(ctx, ref, now.Add(-time.Hour)); err != nil {
			t.Fatalf("Touch with an older sighting must be accepted, not rejected: %v", err)
		}
		// Accepting the older sighting is only half the contract, and the half
		// a broken implementation also satisfies. The half that matters is that
		// it did not take effect: a late-arriving old observation is evidence
		// the asset existed then, not evidence it has not been seen since.
		reader, ok := r.(LastSeenReader)
		if !ok {
			t.Fatalf("%T does not implement identitytest.LastSeenReader, so the contract cannot check that Touch is monotonic — the only property this subtest exists for", r)
		}
		if got := reader.LastSeen(ref); !got.Equal(now.Add(time.Hour)) {
			t.Errorf("last seen = %v after an older Touch, want it unchanged at %v", got, now.Add(time.Hour))
		}
		if err := r.Touch(ctx, ref, now.Add(2*time.Hour)); err != nil {
			t.Fatalf("Touch: %v", err)
		}
		if got := reader.LastSeen(ref); !got.Equal(now.Add(2 * time.Hour)) {
			t.Errorf("last seen = %v after a newer Touch, want it advanced to %v", got, now.Add(2*time.Hour))
		}
	})

	// 1b compares an observation's time against this value to decide
	// whether a lease has moved. A store that let an older attach drag it
	// backwards would let a replayed sighting move an address back to a device
	// that no longer holds it; one that answered for another tenant's row, or
	// for a value nobody holds, would move addresses on evidence that is not
	// there.
	t.Run("IdentifierLastSeen reports the newest attach and never moves backwards", func(t *testing.T) {
		r := newRepo()
		addr := ident(identity.KindIPAddress, "192.0.2.7", "segment-1")
		ref, err := r.CreateAsset(ctx, tenant, newAsset("host-1", addr))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		// The identifier's SeenAt is ignored by the lookup: only kind, value
		// and scope select the row.
		probe := addr
		probe.SeenAt = time.Time{}
		probe.Source = identity.Source{}

		got, ok, err := r.IdentifierLastSeen(ctx, tenant, probe)
		if err != nil || !ok || !got.Equal(now) {
			t.Fatalf("IdentifierLastSeen after create = %v, %v (err %v), want %v, true", got, ok, err, now)
		}

		later := addr
		later.SeenAt = now.Add(time.Hour)
		if _, err := r.AttachIdentifiers(ctx, ref, []identity.Identifier{later}); err != nil {
			t.Fatalf("AttachIdentifiers(later): %v", err)
		}
		if got, _, _ := r.IdentifierLastSeen(ctx, tenant, probe); !got.Equal(now.Add(time.Hour)) {
			t.Errorf("last seen = %v after a newer attach, want it advanced to %v", got, now.Add(time.Hour))
		}

		earlier := addr
		earlier.SeenAt = now.Add(-time.Hour)
		if _, err := r.AttachIdentifiers(ctx, ref, []identity.Identifier{earlier}); err != nil {
			t.Fatalf("AttachIdentifiers(earlier): %v", err)
		}
		if got, _, _ := r.IdentifierLastSeen(ctx, tenant, probe); !got.Equal(now.Add(time.Hour)) {
			t.Errorf("last seen = %v after an OLDER attach, want it unchanged at %v: a late sighting "+
				"is evidence the value existed then, not that it has not been seen since", got, now.Add(time.Hour))
		}

		if _, ok, err := r.IdentifierLastSeen(ctx, tenant, ident(identity.KindIPAddress, "192.0.2.8", "segment-1")); err != nil || ok {
			t.Errorf("IdentifierLastSeen(unheld value) = found %v (err %v), want not found", ok, err)
		}
		if _, ok, err := r.IdentifierLastSeen(ctx, tenant, ident(identity.KindIPAddress, "192.0.2.7", "segment-2")); err != nil || ok {
			t.Errorf("IdentifierLastSeen(same value, other scope) = found %v (err %v), want not found", ok, err)
		}
		if _, ok, err := r.IdentifierLastSeen(ctx, otherTenant, probe); err != nil || ok {
			t.Errorf("IdentifierLastSeen(other tenant) = found %v (err %v), want not found: tenants are isolated", ok, err)
		}
	})

	t.Run("FindByIdentifier round-trips every kind", func(t *testing.T) {
		// One asset per kind, so a store that mishandles a particular kind —
		// an enum it does not carry, a column it truncates, a value it folds —
		// fails on that kind rather than hiding behind the two the rest of this
		// contract happens to use.
		values := map[identity.Kind]string{
			identity.KindSensorID:              "sensor-1",
			identity.KindAgentID:               "agent-7f3a",
			identity.KindCloudResourceID:       "arn:aws:ec2:us-east-1:1:instance/i-0AbC",
			identity.KindSerialNumber:          "J7K2L9",
			identity.KindCMDBSysID:             "a1b2C3",
			identity.KindSSHHostKeyFingerprint: "SHA256:aZ0+/bQ",
			identity.KindMACAddress:            "aa:bb:cc:dd:ee:01",
			identity.KindFQDN:                  "host.example.com",
			identity.KindHostname:              "printer-2",
			identity.KindIPAddress:             "192.0.2.10",
		}
		r := newRepo()
		refs := make(map[identity.Kind]identity.AssetRef, len(values))
		for _, kind := range identity.DefaultPrecedenceList() {
			value, ok := values[kind]
			if !ok {
				t.Fatalf("no contract value for kind %s: a kind was added without extending this table", kind)
			}
			scope := ""
			if kind.AcceptsScope() {
				scope = "scope-1"
			}
			ref, err := r.CreateAsset(ctx, tenant, newAsset(string(kind), ident(kind, value, scope)))
			if err != nil {
				t.Fatalf("CreateAsset for %s: %v", kind, err)
			}
			refs[kind] = ref
		}
		for kind, ref := range refs {
			scope := ""
			if kind.AcceptsScope() {
				scope = "scope-1"
			}
			got, err := r.FindByIdentifier(ctx, tenant, kind, values[kind], scope)
			if err != nil {
				t.Errorf("FindByIdentifier(%s): %v", kind, err)
				continue
			}
			if len(got) != 1 || got[0].ID != ref.ID {
				t.Errorf("FindByIdentifier(%s, %q) = %+v, want exactly [%s]", kind, values[kind], got, ref.ID)
			}
		}
	})

	t.Run("RecordHistory appends in order", func(t *testing.T) {
		// The engine writes two entries for one observation on the conflict
		// path (created, then merge_proposed) and reads them back in that
		// order to reconstruct what happened. A store that returns them in
		// insertion-agnostic order — no ORDER BY, or an ORDER BY on a
		// second-resolution timestamp — reverses the story it tells.
		r := newRepo()
		ref, err := r.CreateAsset(ctx, tenant, newAsset("host-1"))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		want := []identity.HistoryAction{
			identity.ActionCreated,
			identity.ActionUpdated,
			identity.ActionMergeProposed,
			identity.ActionUpdated,
		}
		for i, action := range want {
			err := r.RecordHistory(ctx, identity.HistoryEntry{
				TenantID: tenant,
				AssetID:  ref.ID,
				Action:   action,
				Source:   identity.Source{Kind: identity.SourceMeasured, Ref: "contract"},
				Changes:  map[string]any{"n": i},
				At:       now, // identical timestamps: insertion order is the only signal.
			})
			if err != nil {
				t.Fatalf("RecordHistory(%s): %v", action, err)
			}
		}
		reader, ok := r.(HistoryReader)
		if !ok {
			t.Fatalf("%T does not implement identitytest.HistoryReader, so the contract cannot check that history is appended in order", r)
		}
		got := reader.HistoryFor(ref)
		if len(got) != len(want) {
			t.Fatalf("%d history entries, want %d: %+v", len(got), len(want), got)
		}
		for i, w := range want {
			if got[i].Action != w {
				t.Errorf("history[%d] = %s, want %s (entries must come back oldest first)", i, got[i].Action, w)
			}
			if got[i].Source.Ref != "contract" {
				t.Errorf("history[%d] lost its source: %+v", i, got[i].Source)
			}
		}
	})

	t.Run("LoadSummaries preserves order and skips unknown ids", func(t *testing.T) {
		r := newRepo()
		a, err := r.CreateAsset(ctx, tenant, newAsset("host-a"))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		b, err := r.CreateAsset(ctx, tenant, newAsset("host-b"))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		got, err := r.LoadSummaries(ctx, tenant, []string{b.ID, "gone", a.ID})
		if err != nil {
			t.Fatalf("LoadSummaries: %v", err)
		}
		if len(got) != 2 || got[0].Ref.ID != b.ID || got[1].Ref.ID != a.ID {
			t.Fatalf("LoadSummaries = %+v, want [%s %s]", got, b.ID, a.ID)
		}
		if got[0].DisplayName != "host-b" || got[0].ClassKey != "server" || got[0].Status != identity.StatusPendingApproval {
			t.Errorf("summary lost fields: %+v", got[0])
		}
	})

	// A summary without identifiers is not a smaller answer, it is a wrong one
	// in two places: a merge proposal whose candidates carry no evidence can
	// only be rubber-stamped, and the engine's singleton guard reads exactly
	// this list to decide whether an observation's ARN disagrees with the one
	// the matched asset already holds. An implementation that returned the
	// asset row and no identifiers would make that guard silently pass
	// everything — a check that cannot fail.
	t.Run("LoadSummaries carries each asset's identifiers", func(t *testing.T) {
		r := newRepo()
		ref, err := r.CreateAsset(ctx, tenant, newAsset("host-a",
			ident(identity.KindCloudResourceID, "arn:aws:ec2:us-east-1:1:instance/i-01", ""),
			ident(identity.KindIPAddress, "10.0.1.20", identity.ScopeTenantDefault),
		))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		got, err := r.LoadSummaries(ctx, tenant, []string{ref.ID})
		if err != nil {
			t.Fatalf("LoadSummaries: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("LoadSummaries returned %d summaries, want 1", len(got))
		}
		if countKind(got[0].Identifiers, identity.KindCloudResourceID) != 1 ||
			countKind(got[0].Identifiers, identity.KindIPAddress) != 1 {
			t.Fatalf("summary identifiers = %+v, want the cloud_resource_id and the ip_address", got[0].Identifiers)
		}
		for _, id := range got[0].Identifiers {
			if id.Kind == identity.KindCloudResourceID && id.Value != "arn:aws:ec2:us-east-1:1:instance/i-01" {
				t.Errorf("cloud_resource_id value = %q, want the stored one — the singleton guard compares VALUES", id.Value)
			}
		}
	})

	t.Run("RecordHistory accepts every action the engine writes", func(t *testing.T) {
		r := newRepo()
		ref, err := r.CreateAsset(ctx, tenant, newAsset("host-1"))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		for _, action := range []identity.HistoryAction{
			identity.ActionCreated,
			identity.ActionUpdated,
			identity.ActionMergedFrom,
			identity.ActionMergeProposed,
		} {
			err := r.RecordHistory(ctx, identity.HistoryEntry{
				TenantID: tenant,
				AssetID:  ref.ID,
				Action:   action,
				Source:   identity.Source{Kind: identity.SourceMeasured, Ref: "contract"},
				Changes:  map[string]any{"k": "v"},
				At:       now,
			})
			if err != nil {
				t.Errorf("RecordHistory(%s): %v", action, err)
			}
		}
	})

	t.Run("OpenMergeProposal returns a ref", func(t *testing.T) {
		r := newRepo()
		a, err := r.CreateAsset(ctx, tenant, newAsset("host-a"))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		p, err := r.OpenMergeProposal(ctx, tenant, identity.MergeProposal{
			ObservationAssetID: a.ID,
			Candidates:         []identity.MergeCandidate{{Ref: a}},
			Source:             identity.Source{Kind: identity.SourceMeasured, Ref: "contract"},
			Reason:             "contract",
			ProposedAt:         now,
		})
		if err != nil {
			t.Fatalf("OpenMergeProposal: %v", err)
		}
		if p.ID == "" {
			t.Error("OpenMergeProposal returned an empty id")
		}
		if p.TenantID != tenant {
			t.Errorf("proposal.TenantID = %q, want %q", p.TenantID, tenant)
		}
	})

	// One PENDING proposal per question, not one per poll.
	//
	// The floor path opens a proposal and creates nothing, and nothing about a
	// contested observation changes between observations — so a collector on a
	// fifteen-minute schedule asked the identical question ninety-six times a
	// day. The second call must return the EXISTING proposal's ref: a caller is
	// about to tell somebody "review the merge proposal", and it has to name the
	// one that is actually in the queue.
	t.Run("OpenMergeProposal is idempotent for the same question", func(t *testing.T) {
		r := newRepo()
		a, err := r.CreateAsset(ctx, tenant, newAsset("host-idem"))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		b, err := r.CreateAsset(ctx, tenant, newAsset("host-idem-2"))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		question := identity.MergeProposal{
			Candidates: []identity.MergeCandidate{
				{Ref: a, MatchedIdentifiers: []identity.Identifier{ident(identity.KindSerialNumber, "SN-IDEM", "")}},
				{Ref: b, MatchedIdentifiers: []identity.Identifier{ident(identity.KindMACAddress, "aa:bb:cc:dd:ee:01", "")}},
			},
			Source:     identity.Source{Kind: identity.SourceMeasured, Ref: "contract"},
			Reason:     "contested",
			ProposedAt: now,
		}
		first, err := r.OpenMergeProposal(ctx, tenant, question)
		if err != nil {
			t.Fatalf("OpenMergeProposal (first): %v", err)
		}
		// Same question, candidates in the other order and with a different
		// reason: neither changes WHAT is being asked.
		again := question
		again.Candidates = []identity.MergeCandidate{question.Candidates[1], question.Candidates[0]}
		again.Reason = "contested (seen again)"
		second, err := r.OpenMergeProposal(ctx, tenant, again)
		if err != nil {
			t.Fatalf("OpenMergeProposal (again): %v", err)
		}
		if second.ID != first.ID {
			t.Errorf("re-opening the same proposal made a new one (%s then %s); the Approvals queue fills "+
				"with identical rows a reviewer cannot clear by deciding any one of them", first.ID, second.ID)
		}

		// A DIFFERENT question — a different candidate set — must still get its
		// own proposal, or the second thing is silently dropped instead of
		// reviewed. (Different identifiers against the SAME candidates are the
		// same question since A3; the fold contract below pins that the
		// evidence is kept rather than dropped.)
		c, err := r.CreateAsset(ctx, tenant, newAsset("host-idem-3"))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		other := question
		other.Candidates = []identity.MergeCandidate{
			question.Candidates[0],
			{Ref: c, MatchedIdentifiers: []identity.Identifier{ident(identity.KindMACAddress, "aa:bb:cc:dd:ee:02", "")}},
		}
		third, err := r.OpenMergeProposal(ctx, tenant, other)
		if err != nil {
			t.Fatalf("OpenMergeProposal (other): %v", err)
		}
		if third.ID == first.ID {
			t.Error("two different candidate sets collapsed into one proposal; the second question was never reviewed")
		}
	})

	// A3: one pair, one pending row, whatever identifiers each sighting
	// happened to carry — and every identifier any of them carried is kept.
	t.Run("OpenMergeProposal folds new evidence into the pending proposal for the same pair", func(t *testing.T) {
		r := newRepo()
		reader, ok := r.(ProposalReader)
		if !ok {
			t.Fatalf("%T does not implement identitytest.ProposalReader; the fold contract cannot read back what it folded", r)
		}
		a, err := r.CreateAsset(ctx, tenant, newAsset("host-fold-a"))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		b, err := r.CreateAsset(ctx, tenant, newAsset("host-fold-b"))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		serial := ident(identity.KindSerialNumber, "SN-FOLD", "")
		mac := ident(identity.KindMACAddress, "aa:bb:cc:dd:ee:31", "")
		host := ident(identity.KindHostname, "fold-host", identity.ScopeTenantDefault)
		addr := ident(identity.KindIPAddress, "198.51.100.31", identity.ScopeTenantDefault)
		src := identity.Source{Kind: identity.SourceMeasured, Ref: "contract"}

		first, err := r.OpenMergeProposal(ctx, tenant, identity.MergeProposal{
			Candidates: []identity.MergeCandidate{
				{Ref: a, MatchedIdentifiers: []identity.Identifier{serial}, Score: 0.4, Reason: "first"},
				{Ref: b, MatchedIdentifiers: []identity.Identifier{host}, Score: 0.3, Reason: "first"},
			},
			Source: src, Reason: "contested", ProposedAt: now,
		})
		if err != nil {
			t.Fatalf("OpenMergeProposal (first): %v", err)
		}
		// A later sighting of the same pair carrying MORE identifiers: a
		// higher score for a, a lower one for b.
		later := now.Add(3 * time.Hour)
		second, err := r.OpenMergeProposal(ctx, tenant, identity.MergeProposal{
			Candidates: []identity.MergeCandidate{
				{Ref: b, MatchedIdentifiers: []identity.Identifier{host, addr}, Score: 0.2, Reason: "second"},
				{Ref: a, MatchedIdentifiers: []identity.Identifier{serial, mac}, Score: 0.7, Reason: "second"},
			},
			Source: src, Reason: "contested", ProposedAt: later,
		})
		if err != nil {
			t.Fatalf("OpenMergeProposal (second): %v", err)
		}
		if second.ID != first.ID || !second.Reused {
			t.Fatalf("second sighting opened %s (reused %v) beside %s; one pair is one question", second.ID, second.Reused, first.ID)
		}
		// An OLDER sighting delivered late: its time must not move the
		// latest-evidence clock backwards.
		if _, err := r.OpenMergeProposal(ctx, tenant, identity.MergeProposal{
			Candidates: []identity.MergeCandidate{
				{Ref: a, MatchedIdentifiers: []identity.Identifier{serial}, Score: 0.1},
				{Ref: b, MatchedIdentifiers: []identity.Identifier{host}, Score: 0.1},
			},
			Source: src, Reason: "contested", ProposedAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatalf("OpenMergeProposal (late): %v", err)
		}

		got, ok := reader.PendingProposal(first)
		if !ok {
			t.Fatalf("proposal %s is not pending any more", first.ID)
		}
		byID := map[string]identity.MergeCandidate{}
		for _, c := range got.Candidates {
			byID[c.Ref.ID] = c
		}
		if len(got.Candidates) != 2 {
			t.Fatalf("candidates = %+v, want the two records", got.Candidates)
		}
		keys := func(ids []identity.Identifier) map[string]bool {
			out := map[string]bool{}
			for _, id := range ids {
				out[string(id.Kind)+"="+id.Value] = true
			}
			return out
		}
		wantA := map[string]bool{"serial_number=SN-FOLD": true, "mac_address=aa:bb:cc:dd:ee:31": true}
		wantB := map[string]bool{"hostname=fold-host": true, "ip_address=198.51.100.31": true}
		if gotA := keys(byID[a.ID].MatchedIdentifiers); !reflect.DeepEqual(gotA, wantA) {
			t.Errorf("candidate a matched %v, want the union %v — a later sighting's evidence was dropped", gotA, wantA)
		}
		if gotB := keys(byID[b.ID].MatchedIdentifiers); !reflect.DeepEqual(gotB, wantB) {
			t.Errorf("candidate b matched %v, want the union %v — a later sighting's evidence was dropped", gotB, wantB)
		}
		if byID[a.ID].Score != 0.7 || byID[a.ID].Reason != "second" {
			t.Errorf("candidate a score %v (%q), want the higher 0.7 (\"second\")", byID[a.ID].Score, byID[a.ID].Reason)
		}
		if byID[b.ID].Score != 0.3 || byID[b.ID].Reason != "first" {
			t.Errorf("candidate b score %v (%q), want 0.3 kept: a weaker re-run must not erase the stronger case", byID[b.ID].Score, byID[b.ID].Reason)
		}
		if !got.ProposedAt.Equal(now) {
			t.Errorf("proposed_at = %s, want the first time the question was asked (%s)", got.ProposedAt, now)
		}
		if !got.LatestEvidenceAt.Equal(later) {
			t.Errorf("latest_evidence_at = %s, want the newest sighting's time %s", got.LatestEvidenceAt, later)
		}
	})

	// Phase 5: the pair score and the matcher's view of both sides
	// survive the store, and fold like the rest of the evidence — the higher
	// pair score wins, the observation's identifiers are the union, and the
	// derived / generic marks the matcher reads come back as they went in.
	t.Run("OpenMergeProposal carries and folds the pair score and the training snapshot", func(t *testing.T) {
		r := newRepo()
		reader, ok := r.(ProposalReader)
		if !ok {
			t.Fatalf("%T does not implement identitytest.ProposalReader", r)
		}
		a, err := r.CreateAsset(ctx, tenant, newAsset("host-pair-a"))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		b, err := r.CreateAsset(ctx, tenant, newAsset("host-pair-b"))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		src := identity.Source{Kind: identity.SourceMeasured, Ref: "contract"}
		derivedMAC := ident(identity.KindMACAddress, "aa:bb:cc:dd:ee:41", "")
		derivedMAC.Source = identity.Source{Kind: identity.SourceInferred, Ref: "derived:eui64:2001:db8::a8bb:ccff:fedd:ee41"}
		genericHost := ident(identity.KindHostname, "iphone", identity.ScopeTenantDefault)
		genericHost.Generic = true
		addr := ident(identity.KindIPAddress, "198.51.100.41", identity.ScopeTenantDefault)
		serial := ident(identity.KindSerialNumber, "SN-PAIR", "")
		seen := now.Add(-time.Hour)

		open := func(pair float64, reason string, at time.Time, observed ...identity.Identifier) identity.ProposalRef {
			t.Helper()
			ref, err := r.OpenMergeProposal(ctx, tenant, identity.MergeProposal{
				Candidates: []identity.MergeCandidate{
					{Ref: a, MatchedIdentifiers: []identity.Identifier{serial}, Snapshot: &identity.MatcherSide{
						Name: "host-pair-a", Class: "server", Segment: "seg-1", Vendor: "Dell", SourceKind: "measured",
						SeenAt: seen, Identifiers: []identity.Identifier{serial},
					}},
					{Ref: b, MatchedIdentifiers: []identity.Identifier{addr}},
				},
				Source: src, Reason: "contested", ProposedAt: at,
				PairScore: pair, PairAssetIDs: []string{a.ID, b.ID}, PairReason: reason,
				ObservationIdentifiers: observed,
				ObservationContext:     &identity.MatcherSide{Name: "iphone", Class: "mobile", Segment: "seg-1", SourceKind: "measured", SeenAt: at},
			})
			if err != nil {
				t.Fatalf("OpenMergeProposal: %v", err)
			}
			return ref
		}
		first := open(0.3, "first", now, derivedMAC, genericHost)
		open(0.6, "second", now.Add(time.Hour), genericHost, addr)
		open(0.1, "third", now.Add(2*time.Hour), serial)

		got, ok := reader.PendingProposal(first)
		if !ok {
			t.Fatalf("proposal %s is not pending", first.ID)
		}
		if got.PairScore != 0.6 || got.PairReason != "second" || !reflect.DeepEqual(got.PairAssetIDs, []string{a.ID, b.ID}) {
			t.Errorf("pair = %v %q %v, want the highest (0.6, \"second\") with its ids", got.PairScore, got.PairReason, got.PairAssetIDs)
		}
		byKey := map[string]identity.Identifier{}
		for _, id := range got.ObservationIdentifiers {
			byKey[string(id.Kind)+"="+id.Value] = id
		}
		if len(byKey) != 4 {
			t.Errorf("observation identifiers = %+v, want the union of four across the three sightings", got.ObservationIdentifiers)
		}
		if id := byKey["mac_address=aa:bb:cc:dd:ee:41"]; !id.Inferred() {
			t.Errorf("the derived MAC came back as %+v, no longer marked derived", id)
		}
		if id := byKey["hostname=iphone"]; !id.Generic {
			t.Errorf("the generic hostname came back as %+v, no longer marked generic", id)
		}
		if id := byKey["ip_address=198.51.100.41"]; id.Inferred() || id.Generic {
			t.Errorf("an ordinary address came back marked: %+v", id)
		}
		if got.ObservationContext == nil || got.ObservationContext.Class != "mobile" || got.ObservationContext.Name != "iphone" {
			t.Errorf("observation context = %+v, want the matcher's view of the observation", got.ObservationContext)
		}
		var snap *identity.MatcherSide
		for _, c := range got.Candidates {
			if c.Ref.ID == a.ID {
				snap = c.Snapshot
			}
		}
		if snap == nil || snap.Vendor != "Dell" || snap.Segment != "seg-1" || len(snap.Identifiers) != 1 || !snap.SeenAt.Equal(seen) {
			t.Errorf("candidate a's snapshot = %+v, want the candidate as the matcher compared it", snap)
		}
	})

	// ScopeForAddress is the one lookup every observation builder makes before
	// it can produce a hostname or ip_address identifier, and the contract that
	// matters most is the boring one: it NEVER returns an empty scope. An empty
	// scope is an identifier that cannot decide anything, and that is what made
	// one host, observed three times in a tenant with no segments, into three
	// assets.
	t.Run("ScopeForAddress never returns an empty scope", func(t *testing.T) {
		r := newRepo()
		for _, addr := range []string{"192.0.2.10", "2001:db8::1", "10.0.0.1"} {
			a := netip.MustParseAddr(addr)
			scope, dynamic, err := r.ScopeForAddress(ctx, tenant, a, "")
			if err != nil {
				t.Fatalf("ScopeForAddress(%s): %v", addr, err)
			}
			if scope == "" {
				t.Errorf("ScopeForAddress(%s) returned an empty scope; a tenant with no segments still "+
					"has one place to stand, and an unscoped hostname or IP can never decide a match", addr)
			}
			if scope != identity.ScopeTenantDefault {
				t.Errorf("ScopeForAddress(%s) = %q for a tenant with no segments, want %q",
					addr, scope, identity.ScopeTenantDefault)
			}
			if dynamic {
				t.Errorf("ScopeForAddress(%s) reported the tenant default as dynamic; it is not a DHCP "+
					"range, it is everywhere else", addr)
			}
		}
	})

	t.Run("ScopeForAddress tolerates the zero address", func(t *testing.T) {
		// Not an address, so inside no segment. It must answer, not error: a
		// builder holding an unparseable address still has to scope the
		// hostname it also holds.
		r := newRepo()
		scope, _, err := r.ScopeForAddress(ctx, tenant, netip.Addr{}, "")
		if err != nil {
			t.Fatalf("ScopeForAddress(zero): %v", err)
		}
		if scope != identity.ScopeTenantDefault {
			t.Errorf("ScopeForAddress(zero) = %q, want %q", scope, identity.ScopeTenantDefault)
		}
	})

	t.Run("ScopeForAddress resolves a configured segment, most specific first", func(t *testing.T) {
		r := newRepo()
		seg, ok := r.(SegmentWriter)
		if !ok {
			t.Skipf("%T cannot register segments, so only the no-segment contract above applies to it", r)
		}
		if err := seg.AddSegment(tenant, "192.0.2.0/24", "seg-wide", false); err != nil {
			t.Fatalf("AddSegment: %v", err)
		}
		if err := seg.AddSegment(tenant, "192.0.2.0/28", "seg-narrow", true); err != nil {
			t.Fatalf("AddSegment: %v", err)
		}

		// Inside both: the /28 is the more precise answer about where it is.
		scope, dynamic, err := r.ScopeForAddress(ctx, tenant, netip.MustParseAddr("192.0.2.5"), "")
		if err != nil {
			t.Fatalf("ScopeForAddress: %v", err)
		}
		if scope != "seg-narrow" {
			t.Errorf("scope = %q, want seg-narrow: the most specific containing segment wins", scope)
		}
		if !dynamic {
			t.Error("dynamic = false for an address in a segment flagged dynamic; an ip_address must not " +
				"decide a match inside one")
		}

		// Inside only the /24.
		scope, dynamic, err = r.ScopeForAddress(ctx, tenant, netip.MustParseAddr("192.0.2.200"), "")
		if err != nil {
			t.Fatalf("ScopeForAddress: %v", err)
		}
		if scope != "seg-wide" || dynamic {
			t.Errorf("scope = %q dynamic = %v, want seg-wide and static", scope, dynamic)
		}

		// Outside every segment: the tenant default, NOT an empty scope.
		scope, _, err = r.ScopeForAddress(ctx, tenant, netip.MustParseAddr("198.51.100.7"), "")
		if err != nil {
			t.Fatalf("ScopeForAddress: %v", err)
		}
		if scope != identity.ScopeTenantDefault {
			t.Errorf("scope = %q for an address outside every segment, want %q — an address the tenant "+
				"has not described is still somewhere", scope, identity.ScopeTenantDefault)
		}

		// Another tenant sees none of it.
		scope, _, err = r.ScopeForAddress(ctx, otherTenant, netip.MustParseAddr("192.0.2.5"), "")
		if err != nil {
			t.Fatalf("ScopeForAddress(other tenant): %v", err)
		}
		if scope != identity.ScopeTenantDefault {
			t.Errorf("another tenant resolved %q for an address in THIS tenant's segment", scope)
		}
	})

	// A CIDR is not unique in a cloud account. Two VPCs built from one
	// Terraform module both get 10.0.0.0/16 and their subnets both get
	// 10.0.1.0/24, so "which segment is 10.0.1.20 in" has two answers and the
	// caller has to say which network it was standing on. Collapsing the two
	// into one segment is what made two EC2 instances at the same private
	// address resolve to one scope, and then to one ASSET.
	t.Run("ScopeForAddress separates two cloud networks sharing a CIDR", func(t *testing.T) {
		r := newRepo()
		seg, ok := r.(CloudSegmentWriter)
		if !ok {
			t.Skipf("%T cannot register cloud-scoped segments", r)
		}
		const vpcA, vpcB = "vpc-aaaa", "vpc-bbbb"
		if err := seg.AddCloudSegment(tenant, "10.0.1.0/24", "seg-a", false, vpcA); err != nil {
			t.Fatalf("AddCloudSegment(a): %v", err)
		}
		if err := seg.AddCloudSegment(tenant, "10.0.1.0/24", "seg-b", false, vpcB); err != nil {
			t.Fatalf("AddCloudSegment(b): %v", err)
		}
		addr := netip.MustParseAddr("10.0.1.20")

		// The whole point: the same address in two networks is two scopes.
		scopeA, _, err := r.ScopeForAddress(ctx, tenant, addr, vpcA)
		if err != nil {
			t.Fatalf("ScopeForAddress(vpc-a): %v", err)
		}
		scopeB, _, err := r.ScopeForAddress(ctx, tenant, addr, vpcB)
		if err != nil {
			t.Fatalf("ScopeForAddress(vpc-b): %v", err)
		}
		if scopeA != "seg-a" || scopeB != "seg-b" {
			t.Fatalf("scopes = %q and %q, want seg-a and seg-b — one address in two VPCs is two places",
				scopeA, scopeB)
		}

		// A caller that did NOT say which network it was on is asking a
		// question with two answers. The tenant default is the honest one:
		// the address is still recorded, and it decides nothing.
		scope, _, err := r.ScopeForAddress(ctx, tenant, addr, "")
		if err != nil {
			t.Fatalf("ScopeForAddress(no network): %v", err)
		}
		if scope != identity.ScopeTenantDefault {
			t.Errorf("scope = %q for an ambiguous address with no network ref, want %q — picking one of two "+
				"VPCs would make an asset's identity depend on query order", scope, identity.ScopeTenantDefault)
		}
	})

	// A segment in ANOTHER network must be excluded before specificity is
	// considered, not merely deprioritised after it.
	//
	// The distinction is the whole filter: here vpc-b's /24 is the MOST
	// SPECIFIC segment containing the address, and an implementation that
	// ranked by prefix length and only then preferred a network match would
	// return it — placing an observation made in vpc-a inside vpc-b's segment,
	// which is a cross-VPC identity claim. The correct answer is the LESS
	// specific unscoped segment, because it is the most specific one that
	// could possibly apply.
	t.Run("ScopeForAddress never crosses into another network's segment", func(t *testing.T) {
		r := newRepo()
		seg, ok := r.(CloudSegmentWriter)
		if !ok {
			t.Skipf("%T cannot register cloud-scoped segments", r)
		}
		if err := seg.AddSegment(tenant, "10.20.0.0/16", "seg-unscoped", false); err != nil {
			t.Fatalf("AddSegment: %v", err)
		}
		if err := seg.AddCloudSegment(tenant, "10.20.1.0/24", "seg-other-vpc", false, "vpc-bbbb"); err != nil {
			t.Fatalf("AddCloudSegment: %v", err)
		}
		addr := netip.MustParseAddr("10.20.1.20")

		scope, _, err := r.ScopeForAddress(ctx, tenant, addr, "vpc-aaaa")
		if err != nil {
			t.Fatalf("ScopeForAddress(vpc-a): %v", err)
		}
		if scope == "seg-other-vpc" {
			t.Fatal("an observation in vpc-a resolved into vpc-b's segment because that segment was more " +
				"specific; a segment in another network is not a candidate at all")
		}
		if scope != "seg-unscoped" {
			t.Errorf("scope = %q, want seg-unscoped — the most specific segment that CAN apply", scope)
		}

		// And from vpc-b, the /24 is right and still wins.
		scope, _, err = r.ScopeForAddress(ctx, tenant, addr, "vpc-bbbb")
		if err != nil {
			t.Fatalf("ScopeForAddress(vpc-b): %v", err)
		}
		if scope != "seg-other-vpc" {
			t.Errorf("scope = %q from vpc-b, want seg-other-vpc — excluding other networks must not exclude "+
				"the caller's own", scope)
		}
	})

	// The other polarity: scoping must not become mandatory. One cloud segment
	// and no ambiguity is the ordinary case, and an agent INSIDE an instance
	// knows its address and not its VPC — it still has to reach the segment the
	// cloud collector created, or the join this engine exists for is lost.
	t.Run("ScopeForAddress still resolves one cloud segment without a network ref", func(t *testing.T) {
		r := newRepo()
		seg, ok := r.(CloudSegmentWriter)
		if !ok {
			t.Skipf("%T cannot register cloud-scoped segments", r)
		}
		if err := seg.AddCloudSegment(tenant, "10.9.1.0/24", "seg-only", false, "vpc-only"); err != nil {
			t.Fatalf("AddCloudSegment: %v", err)
		}
		addr := netip.MustParseAddr("10.9.1.20")

		scope, _, err := r.ScopeForAddress(ctx, tenant, addr, "")
		if err != nil {
			t.Fatalf("ScopeForAddress(no network): %v", err)
		}
		if scope != "seg-only" {
			t.Errorf("scope = %q, want seg-only — one unambiguous segment answers whether or not the "+
				"caller named a network, which is how an agent inside the instance reaches the same asset", scope)
		}

		// And a LAN segment is reachable from a cloud observation too: an
		// unscoped segment is a candidate for any network, because an operator
		// may legitimately have drawn one over the same space.
		if err := seg.AddSegment(tenant, "10.9.2.0/24", "seg-lan", false); err != nil {
			t.Fatalf("AddSegment: %v", err)
		}
		scope, _, err = r.ScopeForAddress(ctx, tenant, netip.MustParseAddr("10.9.2.20"), "vpc-only")
		if err != nil {
			t.Fatalf("ScopeForAddress(lan segment from a cloud observation): %v", err)
		}
		if scope != "seg-lan" {
			t.Errorf("scope = %q, want seg-lan — an unscoped segment belongs to no network and so excludes none", scope)
		}
	})

	runDecisionMemoryContract(t, newRepo, tenant, now, ident, newAsset)
	runAnnouncementContract(t, newRepo, tenant, now, ident, newAsset)
	runProvisionalContract(t, newRepo, tenant, ident, newAsset)
	runHostnameCardinalityContract(t, newRepo, tenant, otherTenant, ident, newAsset)
}

// ProposalResolver stamps a proposal's outcome the way the approvals path does
// in production. REQUIRED of an implementation under test: the decision-memory
// subtests cannot put a human's answer where [identity.Repository.LastKeptSeparate]
// looks without it, and a contract that skipped itself for lack of a hook would
// be a check that cannot fail. It is not part of identity.Repository — the
// engine never resolves a proposal (ADR-0002 D5).
type ProposalResolver interface {
	ResolveProposal(ref identity.ProposalRef, status, actor string, at time.Time) error
}

// ProposalReader reads a PENDING proposal back as the store holds it: its
// candidates with their matched identifiers and scores, ProposedAt (when the
// question was first asked) and LatestEvidenceAt. REQUIRED of an
// implementation under test: A3's fold is a read-modify-write on the
// stored row, and only reading the row back shows the union was kept. False
// when the proposal is unknown or no longer pending.
type ProposalReader interface {
	PendingProposal(ref identity.ProposalRef) (identity.MergeProposal, bool)
}

// AnnouncementReader reads back what [identity.Repository.RecordAnnouncement]
// wrote for one asset, as announcer or holder. Also required.
type AnnouncementReader interface {
	Announcements(ref identity.AssetRef) []identity.AnnouncementRecord
}

// runDecisionMemoryContract is the contract for [identity.ProposalRef.Reused]
// and [identity.Repository.LastKeptSeparate]: the two halves of "a human's no
// has to stick".
func runDecisionMemoryContract(
	t *testing.T,
	newRepo func() identity.Repository,
	tenant string,
	now time.Time,
	ident func(identity.Kind, string, string) identity.Identifier,
	newAsset func(string, ...identity.Identifier) identity.NewAsset,
) {
	t.Helper()
	ctx := context.Background()
	src := identity.Source{Kind: identity.SourceMeasured, Ref: "contract"}

	// A floor-shaped proposal between two candidates: no observation asset,
	// evidence a serial on one and a hostname on the other.
	openPair := func(t *testing.T, r identity.Repository) (a, b identity.AssetRef, p identity.MergeProposal) {
		t.Helper()
		serial := ident(identity.KindSerialNumber, "SN-DM-1", "")
		host := ident(identity.KindHostname, "dm-host", identity.ScopeTenantDefault)
		var err error
		if a, err = r.CreateAsset(ctx, tenant, newAsset("dm-a", serial)); err != nil {
			t.Fatalf("CreateAsset(a): %v", err)
		}
		if b, err = r.CreateAsset(ctx, tenant, newAsset("dm-b", host)); err != nil {
			t.Fatalf("CreateAsset(b): %v", err)
		}
		p = identity.MergeProposal{
			Candidates: []identity.MergeCandidate{
				{Ref: a, MatchedIdentifiers: []identity.Identifier{serial}},
				{Ref: b, MatchedIdentifiers: []identity.Identifier{host}},
			},
			Source: src, Reason: "contract", ProposedAt: now,
		}
		return a, b, p
	}
	resolver := func(t *testing.T, r identity.Repository) ProposalResolver {
		t.Helper()
		pr, ok := r.(ProposalResolver)
		if !ok {
			t.Fatalf("%T does not implement identitytest.ProposalResolver; the decision-memory contract cannot run without a way to record a reviewer's answer", r)
		}
		return pr
	}

	t.Run("OpenMergeProposal reports a pending proposal it reused, and stops once it is resolved", func(t *testing.T) {
		r := newRepo()
		_, _, p := openPair(t, r)
		first, err := r.OpenMergeProposal(ctx, tenant, p)
		if err != nil {
			t.Fatalf("OpenMergeProposal: %v", err)
		}
		if first.Reused {
			t.Error("the first proposal for a question reports Reused; nothing existed to reuse")
		}
		again, err := r.OpenMergeProposal(ctx, tenant, p)
		if err != nil {
			t.Fatalf("OpenMergeProposal(again): %v", err)
		}
		if again.ID != first.ID {
			t.Fatalf("re-asking the same question opened proposal %s beside %s; a pending proposal is idempotent by fingerprint", again.ID, first.ID)
		}
		if !again.Reused {
			t.Error("the reused proposal does not say so; the engine uses Reused to write its pointer entry once, not once per observation")
		}

		if err := resolver(t, r).ResolveProposal(first, "kept_separate", "reviewer-1", now.Add(time.Hour)); err != nil {
			t.Fatalf("ResolveProposal: %v", err)
		}
		third, err := r.OpenMergeProposal(ctx, tenant, p)
		if err != nil {
			t.Fatalf("OpenMergeProposal(after resolution): %v", err)
		}
		if third.ID == first.ID || third.Reused {
			t.Errorf("after resolution, re-asking returned %+v; a RESOLVED proposal drops out of the idempotency predicate (whether to re-ask is decision memory's call, not this method's)", third)
		}
	})

	t.Run("LastKeptSeparate remembers the pair, unordered, only once resolved kept_separate", func(t *testing.T) {
		r := newRepo()
		a, b, p := openPair(t, r)
		ref, err := r.OpenMergeProposal(ctx, tenant, p)
		if err != nil {
			t.Fatalf("OpenMergeProposal: %v", err)
		}

		if _, found, err := r.LastKeptSeparate(ctx, tenant, []string{a.ID, b.ID}); err != nil {
			t.Fatalf("LastKeptSeparate(pending): %v", err)
		} else if found {
			t.Fatal("a PENDING proposal was returned as a decision; nobody has decided anything yet")
		}

		decidedAt := now.Add(2 * time.Hour)
		if err := resolver(t, r).ResolveProposal(ref, "kept_separate", "reviewer-7", decidedAt); err != nil {
			t.Fatalf("ResolveProposal: %v", err)
		}
		for _, order := range [][]string{{a.ID, b.ID}, {b.ID, a.ID}} {
			d, found, err := r.LastKeptSeparate(ctx, tenant, order)
			if err != nil {
				t.Fatalf("LastKeptSeparate(%v): %v", order, err)
			}
			if !found {
				t.Fatalf("LastKeptSeparate(%v) found nothing; the pair is unordered and was kept separate", order)
			}
			if d.ProposalID != ref.ID {
				t.Errorf("decision names proposal %s, want %s", d.ProposalID, ref.ID)
			}
			if !d.Covers([]string{a.ID, b.ID}) || len(d.Candidates) != 2 {
				t.Errorf("decision candidates = %v, want both of %s and %s", d.Candidates, a.ID, b.ID)
			}
			if len(d.MatchedKinds) != 2 || !d.SameEvidence([]identity.Kind{identity.KindSerialNumber, identity.KindHostname}) {
				t.Errorf("decision matched kinds = %v, want serial_number and hostname — the engine compares today's evidence against them", d.MatchedKinds)
			}
			if d.SameEvidence([]identity.Kind{identity.KindSSHHostKeyFingerprint}) {
				t.Error("a kind the reviewer never saw counts as the same evidence")
			}
			if !d.DecidedAt.Equal(decidedAt) {
				t.Errorf("DecidedAt = %v, want %v", d.DecidedAt, decidedAt)
			}
			if d.DecidedBy != "reviewer-7" {
				t.Errorf("DecidedBy = %q, want reviewer-7", d.DecidedBy)
			}
		}

		// A third asset the proposal never named is not covered.
		c, err := r.CreateAsset(ctx, tenant, newAsset("dm-c", ident(identity.KindSerialNumber, "SN-DM-3", "")))
		if err != nil {
			t.Fatalf("CreateAsset(c): %v", err)
		}
		if _, found, err := r.LastKeptSeparate(ctx, tenant, []string{a.ID, c.ID}); err != nil {
			t.Fatalf("LastKeptSeparate(a, c): %v", err)
		} else if found {
			t.Error("a decision about (a, b) was returned for (a, c)")
		}
		// And another tenant sees nothing.
		if _, found, err := r.LastKeptSeparate(ctx, "tenant-b", []string{a.ID, b.ID}); err != nil {
			t.Fatalf("LastKeptSeparate(other tenant): %v", err)
		} else if found {
			t.Error("another tenant can read this tenant's decisions")
		}
	})

	t.Run("LastKeptSeparate counts the observation asset as one of the pair, and ignores a merge", func(t *testing.T) {
		r := newRepo()
		a, _, p := openPair(t, r)
		z, err := r.CreateAsset(ctx, tenant, newAsset("dm-z", ident(identity.KindMACAddress, "aa:bb:cc:dd:ee:d1", "")))
		if err != nil {
			t.Fatalf("CreateAsset(z): %v", err)
		}
		// Z is the pending asset a conflict created; A is the one candidate.
		withObs := identity.MergeProposal{
			ObservationAssetID: z.ID,
			Candidates:         p.Candidates[:1],
			Source:             p.Source, Reason: "contract", ProposedAt: now,
		}
		ref, err := r.OpenMergeProposal(ctx, tenant, withObs)
		if err != nil {
			t.Fatalf("OpenMergeProposal: %v", err)
		}
		if err := resolver(t, r).ResolveProposal(ref, "kept_separate", "", now.Add(time.Hour)); err != nil {
			t.Fatalf("ResolveProposal: %v", err)
		}
		d, found, err := r.LastKeptSeparate(ctx, tenant, []string{a.ID, z.ID})
		if err != nil {
			t.Fatalf("LastKeptSeparate: %v", err)
		}
		if !found {
			t.Fatal("the pair (observation asset, candidate) was not found; the observation asset is one end of the decision")
		}
		if d.ObservationAssetID != z.ID {
			t.Errorf("ObservationAssetID = %q, want %s — the engine resolves a suppressed recurrence to it", d.ObservationAssetID, z.ID)
		}

		// A MERGE is not a kept-separate decision.
		merged, err := r.OpenMergeProposal(ctx, tenant, p)
		if err != nil {
			t.Fatalf("OpenMergeProposal(pair): %v", err)
		}
		if err := resolver(t, r).ResolveProposal(merged, "merged", "", now.Add(time.Hour)); err != nil {
			t.Fatalf("ResolveProposal(merged): %v", err)
		}
		if _, found, err := r.LastKeptSeparate(ctx, tenant, []string{p.Candidates[0].Ref.ID, p.Candidates[1].Ref.ID}); err != nil {
			t.Fatalf("LastKeptSeparate(merged pair): %v", err)
		} else if found {
			t.Error("a proposal resolved `merged` was returned as a kept-separate decision")
		}
	})
}

// runAnnouncementContract is the contract for
// [identity.Repository.RecordAnnouncement].
func runAnnouncementContract(
	t *testing.T,
	newRepo func() identity.Repository,
	tenant string,
	now time.Time,
	ident func(identity.Kind, string, string) identity.Identifier,
	newAsset func(string, ...identity.Identifier) identity.NewAsset,
) {
	t.Helper()
	ctx := context.Background()
	src := identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:contract", Mode: identity.ModePassive}

	t.Run("RecordAnnouncement is idempotent per pair and readable from both ends", func(t *testing.T) {
		r := newRepo()
		reader, ok := r.(AnnouncementReader)
		if !ok {
			t.Fatalf("%T does not implement identitytest.AnnouncementReader; the announcement contract cannot assert what was written", r)
		}
		node, err := r.CreateAsset(ctx, tenant, newAsset("node", ident(identity.KindMACAddress, "aa:bb:cc:dd:ee:a1", "")))
		if err != nil {
			t.Fatalf("CreateAsset(node): %v", err)
		}
		vip, err := r.CreateAsset(ctx, tenant, newAsset("vip", ident(identity.KindIPAddress, "192.0.2.230", identity.ScopeTenantDefault)))
		if err != nil {
			t.Fatalf("CreateAsset(vip): %v", err)
		}
		a := identity.Announcement{
			MACs: []string{"aa:bb:cc:dd:ee:a1"}, Addresses: []string{"192.0.2.230"},
			Gratuitous: true, Source: src, At: now,
		}
		if err := r.RecordAnnouncement(ctx, node, vip, a); err != nil {
			t.Fatalf("RecordAnnouncement: %v", err)
		}
		later := a
		later.At = now.Add(time.Minute)
		if err := r.RecordAnnouncement(ctx, node, vip, later); err != nil {
			t.Fatalf("RecordAnnouncement(again): %v", err)
		}

		for _, end := range []identity.AssetRef{node, vip} {
			recs := reader.Announcements(end)
			if len(recs) != 1 {
				t.Fatalf("Announcements(%s) = %d records, want 1 — a re-observation bumps the record, it does not add one", end.ID, len(recs))
			}
			rec := recs[0]
			if rec.Announcer.ID != node.ID || rec.Holder.ID != vip.ID {
				t.Errorf("record joins %s → %s, want announcer %s and holder %s", rec.Announcer.ID, rec.Holder.ID, node.ID, vip.ID)
			}
			if rec.Count != 2 {
				t.Errorf("Count = %d, want 2", rec.Count)
			}
			if len(rec.Latest.Addresses) != 1 || rec.Latest.Addresses[0] != "192.0.2.230" || !rec.Latest.Gratuitous {
				t.Errorf("latest evidence = %+v, want the announced address and the gratuitous flag", rec.Latest)
			}
		}

		if err := r.RecordAnnouncement(ctx, node, node, a); err == nil {
			t.Error("an asset announcing its own address was recorded as a floating address; that is a self-edge")
		}
		ghost := identity.AssetRef{TenantID: tenant, ID: "asset-that-does-not-exist"}
		if err := r.RecordAnnouncement(ctx, node, ghost, a); err == nil {
			t.Error("an announcement to an asset that does not exist was recorded")
		}
	})

	// 1b reads this to keep a VIP from "following" the MAC of whichever
	// node announces it. A store that answered no would let a failover move
	// the service's address onto a node; one that answered yes for the wrong
	// holder or address would freeze an ordinary lease.
	t.Run("AddressAnnounced remembers every address announced for a holder, and only those", func(t *testing.T) {
		r := newRepo()
		node, err := r.CreateAsset(ctx, tenant, newAsset("node", ident(identity.KindMACAddress, "aa:bb:cc:dd:ee:a2", "")))
		if err != nil {
			t.Fatalf("CreateAsset(node): %v", err)
		}
		vip, err := r.CreateAsset(ctx, tenant, newAsset("vip", ident(identity.KindIPAddress, "192.0.2.231", identity.ScopeTenantDefault)))
		if err != nil {
			t.Fatalf("CreateAsset(vip): %v", err)
		}
		ask := func(holder identity.AssetRef, addr string) bool {
			t.Helper()
			got, err := r.AddressAnnounced(ctx, holder, addr)
			if err != nil {
				t.Fatalf("AddressAnnounced(%s, %s): %v", holder.ID, addr, err)
			}
			return got
		}
		if ask(vip, "192.0.2.231") {
			t.Fatal("an address nothing ever announced reads as announced")
		}

		// The edge: the latest announcement per announcer.
		if err := r.RecordAnnouncement(ctx, node, vip, identity.Announcement{
			MACs: []string{"aa:bb:cc:dd:ee:a2"}, Addresses: []string{"192.0.2.231"}, Source: src, At: now,
		}); err != nil {
			t.Fatalf("RecordAnnouncement: %v", err)
		}
		// The history entry the engine's floating-address path writes on the
		// holder, for an address no edge carries any more.
		if err := r.RecordHistory(ctx, identity.HistoryEntry{
			TenantID: tenant, AssetID: vip.ID, Action: identity.ActionUpdated, Source: src, At: now,
			Changes: map[string]any{"floating_address": map[string]any{
				"announcer_asset_id": node.ID, "addresses": []string{"192.0.2.229"},
			}},
		}); err != nil {
			t.Fatalf("RecordHistory: %v", err)
		}

		if !ask(vip, "192.0.2.231") {
			t.Error("the address on the holder's announcement edge does not read as announced")
		}
		if !ask(vip, "192.0.2.229") {
			t.Error("an address only the holder's history records as announced does not read as announced")
		}
		if ask(vip, "192.0.2.232") {
			t.Error("an address never announced reads as announced")
		}
		if ask(node, "192.0.2.231") {
			t.Error("the ANNOUNCER reads as holding an announced address; only the holder does")
		}
	})
}

func countKind(ids []identity.Identifier, kind identity.Kind) int {
	n := 0
	for _, id := range ids {
		if id.Kind == kind {
			n++
		}
	}
	return n
}

// RunSingletonGuardContract holds an implementation to the singleton rule of
// ADR-0002 D3's errata: an asset may carry at most one value of a SINGLETON
// kind (agent_id, cloud_resource_id, serial_number, cmdb_sys_id), and an
// observation that disagrees with the one it already has is a merge proposal
// rather than a second value.
//
// It drives the ENGINE rather than the repository directly, because the rule is
// the engine's — but it runs against whichever store it is handed, because the
// guard reads the matched asset's identifiers back through
// [identity.Repository.LoadSummaries] and a store that returns them differently
// breaks it. Two implementations of one rule tested by two suites is how they
// drift.
//
// newRepo must return a FRESH, empty repository on every call.
func RunSingletonGuardContract(t *testing.T, newRepo func() identity.Repository) {
	t.Helper()

	const tenant = "tenant-a"
	ctx := context.Background()
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

	ident := func(kind identity.Kind, value, scope string) identity.Identifier {
		return identity.Identifier{
			Kind: kind, Value: value, Scope: scope,
			Confidence: 1,
			Source:     identity.Source{Kind: identity.SourceMeasured, Ref: "contract"},
			SeenAt:     now,
		}
	}
	observe := func(class string, ids ...identity.Identifier) identity.Observation {
		return identity.Observation{
			TenantID:    tenant,
			ClassHint:   class,
			Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "contract"},
			ObservedAt:  now,
			Confidence:  1,
			Identifiers: ids,
		}
	}
	engineOver := func(r identity.Repository) *identity.Engine {
		eng, err := identity.New(identity.Config{Repo: r})
		if err != nil {
			t.Fatalf("identity.New: %v", err)
		}
		return eng
	}

	// The reproduction from the cloud-enumeration review, at engine level: two
	// EC2 instances with different ARNs that share a private address, because
	// the address was reused after a termination. The ARN cannot decide (the
	// engine has never seen the second one, so it owns nothing), ip_address
	// decides, and without the guard the first asset silently acquires the
	// second ARN.
	t.Run("a disagreeing singleton contests a lower-precedence match", func(t *testing.T) {
		r := newRepo()
		eng := engineOver(r)

		first, err := eng.Resolve(ctx, observe("compute_instance",
			ident(identity.KindCloudResourceID, "arn:aws:ec2:us-east-1:1:instance/i-01", ""),
			ident(identity.KindIPAddress, "10.0.1.20", identity.ScopeTenantDefault),
		))
		if err != nil {
			t.Fatalf("first Resolve: %v", err)
		}
		if first.Outcome != identity.OutcomeCreated {
			t.Fatalf("first outcome = %q, want created", first.Outcome)
		}

		second, err := eng.Resolve(ctx, observe("compute_instance",
			ident(identity.KindCloudResourceID, "arn:aws:ec2:us-east-1:1:instance/i-02", ""),
			ident(identity.KindIPAddress, "10.0.1.20", identity.ScopeTenantDefault),
		))
		if err != nil {
			t.Fatalf("second Resolve: %v", err)
		}
		if second.Outcome != identity.OutcomeConflict {
			t.Fatalf("second outcome = %q, want conflict — two ARNs are two resources, whatever address they share", second.Outcome)
		}
		if second.Asset.Zero() {
			t.Error("the second instance got no asset at all; it exists and belongs in the inventory, pending approval")
		}
		if second.Asset.ID == first.Asset.ID {
			t.Fatal("the second instance was absorbed into the first asset — this is the silent auto-merge the guard exists to stop")
		}
		if second.Proposal.ID == "" {
			t.Error("no merge proposal was opened; a contested identity that nobody is asked about is a silent decision")
		}
		if len(second.Candidates) == 0 || second.Candidates[0].Ref.ID != first.Asset.ID {
			t.Errorf("candidates = %+v, want the first asset", second.Candidates)
		}

		// The first asset is untouched: it still owns exactly its own ARN.
		summaries, err := r.LoadSummaries(ctx, tenant, []string{first.Asset.ID})
		if err != nil {
			t.Fatalf("LoadSummaries: %v", err)
		}
		if n := countKind(summaries[0].Identifiers, identity.KindCloudResourceID); n != 1 {
			t.Errorf("the first asset carries %d cloud_resource_id identifiers, want 1 — an asset holds one", n)
		}
		for _, id := range summaries[0].Identifiers {
			if id.Kind == identity.KindCloudResourceID && id.Value != "arn:aws:ec2:us-east-1:1:instance/i-01" {
				t.Errorf("the first asset's ARN changed to %q", id.Value)
			}
		}
	})

	// The LAN twin of the same shape, and the reason the rule is written over
	// KINDS rather than over cloud resources: two chassis behind one address
	// (an address reused after a decommission, or a NAT) must not become one
	// asset with two serials.
	t.Run("a disagreeing serial_number contests just as a cloud id does", func(t *testing.T) {
		r := newRepo()
		eng := engineOver(r)

		first, err := eng.Resolve(ctx, observe("server",
			ident(identity.KindSerialNumber, "CHASSIS-AAA", ""),
			ident(identity.KindIPAddress, "192.0.2.40", identity.ScopeTenantDefault),
		))
		if err != nil {
			t.Fatalf("first Resolve: %v", err)
		}
		second, err := eng.Resolve(ctx, observe("server",
			ident(identity.KindSerialNumber, "CHASSIS-BBB", ""),
			ident(identity.KindIPAddress, "192.0.2.40", identity.ScopeTenantDefault),
		))
		if err != nil {
			t.Fatalf("second Resolve: %v", err)
		}
		if second.Outcome != identity.OutcomeConflict {
			t.Fatalf("second outcome = %q, want conflict — two serials are two chassis", second.Outcome)
		}
		if second.Asset.ID == first.Asset.ID {
			t.Fatal("two chassis became one asset")
		}
	})

	// The other polarity, and the one a too-eager guard breaks: an asset that
	// carries NO value of the kind is being told something new about itself.
	// This is exactly how a cloud resource and the same host seen by the sensor
	// become ONE asset, which is the feature.
	t.Run("a singleton the asset does not yet carry is attached, not contested", func(t *testing.T) {
		r := newRepo()
		eng := engineOver(r)

		first, err := eng.Resolve(ctx, observe("compute_instance",
			ident(identity.KindIPAddress, "10.0.2.30", identity.ScopeTenantDefault),
			ident(identity.KindMACAddress, "0a:1b:2c:3d:4e:5f", ""),
		))
		if err != nil {
			t.Fatalf("first Resolve: %v", err)
		}
		second, err := eng.Resolve(ctx, observe("compute_instance",
			ident(identity.KindCloudResourceID, "arn:aws:ec2:us-east-1:1:instance/i-09", ""),
			ident(identity.KindIPAddress, "10.0.2.30", identity.ScopeTenantDefault),
		))
		if err != nil {
			t.Fatalf("second Resolve: %v", err)
		}
		if second.Outcome != identity.OutcomeMatched {
			t.Fatalf("second outcome = %q, want matched — learning a resource id is not a disagreement", second.Outcome)
		}
		if second.Asset.ID != first.Asset.ID {
			t.Fatal("the sensor's host and its cloud record became two assets; that is the merge this engine exists to avoid")
		}
		summaries, err := r.LoadSummaries(ctx, tenant, []string{first.Asset.ID})
		if err != nil {
			t.Fatalf("LoadSummaries: %v", err)
		}
		if countKind(summaries[0].Identifiers, identity.KindCloudResourceID) != 1 {
			t.Errorf("the ARN was not attached: %+v", summaries[0].Identifiers)
		}
	})

	// And re-observing the SAME singleton is corroboration, not a conflict —
	// otherwise every second run of every collector would open a proposal.
	t.Run("the same singleton re-observed is idempotent", func(t *testing.T) {
		r := newRepo()
		eng := engineOver(r)
		obs := observe("compute_instance",
			ident(identity.KindCloudResourceID, "arn:aws:ec2:us-east-1:1:instance/i-77", ""),
			ident(identity.KindIPAddress, "10.0.3.10", identity.ScopeTenantDefault),
		)
		first, err := eng.Resolve(ctx, obs)
		if err != nil {
			t.Fatalf("first Resolve: %v", err)
		}
		second, err := eng.Resolve(ctx, obs)
		if err != nil {
			t.Fatalf("second Resolve: %v", err)
		}
		if second.Outcome != identity.OutcomeMatched || second.Asset.ID != first.Asset.ID {
			t.Fatalf("re-running one collector produced %q on %s, want matched on %s",
				second.Outcome, second.Asset.ID, first.Asset.ID)
		}
	})

	// Scope is part of the comparison. A cmdb_sys_id is scoped to its sync
	// profile, so one asset legitimately holds one per profile; treating the
	// kind alone as the key would make a second CMDB connector contest every
	// asset the first one had already recorded.
	t.Run("two singleton values in different scopes coexist", func(t *testing.T) {
		r := newRepo()
		eng := engineOver(r)

		first, err := eng.Resolve(ctx, observe("server",
			ident(identity.KindCMDBSysID, "sys-1", "profile-a"),
			ident(identity.KindIPAddress, "192.0.2.77", identity.ScopeTenantDefault),
		))
		if err != nil {
			t.Fatalf("first Resolve: %v", err)
		}
		second, err := eng.Resolve(ctx, observe("server",
			ident(identity.KindCMDBSysID, "sys-2", "profile-b"),
			ident(identity.KindIPAddress, "192.0.2.77", identity.ScopeTenantDefault),
		))
		if err != nil {
			t.Fatalf("second Resolve: %v", err)
		}
		if second.Outcome != identity.OutcomeMatched || second.Asset.ID != first.Asset.ID {
			t.Fatalf("outcome = %q on %s: a sys_id in ANOTHER profile is a different namespace, not a contradiction",
				second.Outcome, second.Asset.ID)
		}
	})
}

// RunUnknownHostSerialContract holds an implementation to ADR-0002 D3's
// erratum: `unknown_host` identifies by `serial_number`, at the head
// of its precedence.
//
// The rule it encodes is that a serial is a globally unique SINGLETON — two
// observations sharing one are one device WHATEVER their class — so the least
// identified class is exactly the one that must not refuse it. Refusing it did
// not make `unknown_host` more honest: a serial-only device was created on the
// first run and then hit the engine's contested floor on every run after, the
// serial being owned by the asset it had just made and unable to vote. That is
// a fresh merge proposal per scheduled run for a box nobody had touched.
//
// It runs against whichever store it is handed for the same reason the
// singleton contract does: the decisions read identifiers and class back
// through [identity.Repository], and two implementations of one rule tested by
// two suites is how they drift.
//
// newRepo must return a FRESH, empty repository on every call.
func RunUnknownHostSerialContract(t *testing.T, newRepo func() identity.Repository) {
	t.Helper()

	const tenant = "tenant-a"
	ctx := context.Background()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	ident := func(kind identity.Kind, value, scope string) identity.Identifier {
		return identity.Identifier{
			Kind: kind, Value: value, Scope: scope,
			Confidence: 1,
			Source:     identity.Source{Kind: identity.SourceImported, Ref: "contract"},
			SeenAt:     now,
		}
	}
	observe := func(class string, ids ...identity.Identifier) identity.Observation {
		return identity.Observation{
			TenantID:    tenant,
			ClassHint:   class,
			Source:      identity.Source{Kind: identity.SourceImported, Ref: "contract"},
			ObservedAt:  now,
			Confidence:  1,
			Identifiers: ids,
		}
	}
	engineOver := func(r identity.Repository) *identity.Engine {
		eng, err := identity.New(identity.Config{Repo: r})
		if err != nil {
			t.Fatalf("identity.New: %v", err)
		}
		return eng
	}
	summaryOf := func(r identity.Repository, ref identity.AssetRef) identity.AssetSummary {
		t.Helper()
		summaries, err := r.LoadSummaries(ctx, tenant, []string{ref.ID})
		if err != nil {
			t.Fatalf("LoadSummaries: %v", err)
		}
		if len(summaries) != 1 {
			t.Fatalf("LoadSummaries returned %d summaries for one id", len(summaries))
		}
		return summaries[0]
	}

	// The regression itself: a DCIM's spare chassis, which has a serial and
	// nothing else, re-imported on the connector's schedule.
	t.Run("a serial-only unknown_host is ONE asset across two runs", func(t *testing.T) {
		r := newRepo()
		eng := engineOver(r)
		obs := observe("unknown_host", ident(identity.KindSerialNumber, "SPARE-5XJ2K95", ""))

		first, err := eng.Resolve(ctx, obs)
		if err != nil {
			t.Fatalf("first Resolve: %v", err)
		}
		if first.Outcome != identity.OutcomeCreated {
			t.Fatalf("first outcome = %q, want created", first.Outcome)
		}

		second, err := eng.Resolve(ctx, obs)
		if err != nil {
			t.Fatalf("second Resolve: %v", err)
		}
		if second.Outcome != identity.OutcomeMatched {
			t.Fatalf("second outcome = %q, want matched — a serial is how this chassis is recognised again", second.Outcome)
		}
		if second.Asset.ID != first.Asset.ID {
			t.Fatalf("the second run landed on %s, not %s; one chassis became two assets",
				second.Asset.ID, first.Asset.ID)
		}
		if second.DecidedBy != identity.KindSerialNumber {
			t.Errorf("decided_by = %q, want serial_number", second.DecidedBy)
		}
		if second.Proposal.ID != "" {
			t.Errorf("the second run opened merge proposal %q; re-importing an unchanged estate must ask nobody anything",
				second.Proposal.ID)
		}
	})

	// The cross-class half, and the reason the erratum is written over the KIND
	// rather than over the class: the serial decides, and the asset keeps the
	// class something already worked out for it. A match is not a reclassify.
	t.Run("an unknown_host observation matches a server holding the serial, and does not downgrade it", func(t *testing.T) {
		r := newRepo()
		eng := engineOver(r)

		first, err := eng.Resolve(ctx, observe("server",
			ident(identity.KindSerialNumber, "CHASSIS-KNOWN", ""),
			ident(identity.KindHostname, "db01", identity.ScopeTenantDefault),
		))
		if err != nil {
			t.Fatalf("first Resolve: %v", err)
		}
		if first.ClassKey != "server" {
			t.Fatalf("the first asset is %q, want server", first.ClassKey)
		}

		second, err := eng.Resolve(ctx, observe("unknown_host",
			ident(identity.KindSerialNumber, "CHASSIS-KNOWN", ""),
		))
		if err != nil {
			t.Fatalf("second Resolve: %v", err)
		}
		if second.Outcome != identity.OutcomeMatched || second.Asset.ID != first.Asset.ID {
			t.Fatalf("outcome = %q on %s, want matched on %s — the serial names the same chassis whatever class asked",
				second.Outcome, second.Asset.ID, first.Asset.ID)
		}
		if got := summaryOf(r, first.Asset).ClassKey; got != "server" {
			t.Errorf("class = %q after an unknown_host observation matched it, want server — "+
				"a match records what was seen, it does not un-classify the asset", got)
		}
	})

	// The other polarity, and the one this change must not have loosened: the
	// serial leading the precedence is not a licence to write a SECOND serial
	// on an asset that already has one. A restored image or a cloned VM carries
	// the agent id onto different hardware, and that is outcome three.
	t.Run("a differing serial on an agent_id match is still contested", func(t *testing.T) {
		r := newRepo()
		eng := engineOver(r)

		first, err := eng.Resolve(ctx, observe("unknown_host",
			ident(identity.KindAgentID, "agent-0001", ""),
			ident(identity.KindSerialNumber, "CHASSIS-AAA", ""),
		))
		if err != nil {
			t.Fatalf("first Resolve: %v", err)
		}
		if first.Outcome != identity.OutcomeCreated {
			t.Fatalf("first outcome = %q, want created", first.Outcome)
		}

		second, err := eng.Resolve(ctx, observe("unknown_host",
			ident(identity.KindAgentID, "agent-0001", ""),
			ident(identity.KindSerialNumber, "CHASSIS-BBB", ""),
		))
		if err != nil {
			t.Fatalf("second Resolve: %v", err)
		}
		if second.Outcome != identity.OutcomeConflict {
			t.Fatalf("second outcome = %q, want conflict — the agent id says one host and the serial says another chassis",
				second.Outcome)
		}
		if second.Asset.ID == first.Asset.ID {
			t.Fatal("the second chassis was absorbed into the first asset; that is the silent auto-merge D5 forbids")
		}
		if second.Proposal.ID == "" {
			t.Error("no merge proposal was opened; a contested identity nobody is asked about is a silent decision")
		}
		summary := summaryOf(r, first.Asset)
		if n := countKind(summary.Identifiers, identity.KindSerialNumber); n != 1 {
			t.Errorf("the first asset carries %d serial_number identifiers, want 1 — one chassis, one serial", n)
		}
		for _, id := range summary.Identifiers {
			if id.Kind == identity.KindSerialNumber && id.Value != "CHASSIS-AAA" {
				t.Errorf("the first asset's serial changed to %q", id.Value)
			}
		}
	})
}

// ── provisional inventory ──────────────────────────────────────────

// ProvisionalScopeWriter configures the answer
// [identity.ProvisionalScopeChecker] will give for a segment.
//
// OPTIONAL, on the same terms as [SegmentWriter]: an implementation that reads
// its segments from somewhere the contract cannot write skips the eligibility
// subtests. The MOVE and the identity-status subtests are not optional — they
// need no configuration, and an implementation that could skip them would be
// held to nothing.
type ProvisionalScopeWriter interface {
	SetProvisionalScopeAnswer(tenantID, segmentID string, eligible bool, reason string)
}

// runProvisionalContract holds every implementation to the three storage
// capabilities the provisional rules of rest on:
//
//  1. an asset can be CREATED with an identity status, and the summary the
//     engine reads reports it. Without that the corroboration rule cannot see
//     that an asset is a guess, and every provisional asset would be treated as
//     an ordinary one;
//  2. an identifier can be MOVED between assets atomically, and a move computed
//     against the wrong owner is refused. A store that moved it anyway would let
//     two assets swap halves of their identity under a stale lookup;
//  3. a segment's eligibility can be ASKED, and an unknown segment answers no.
func runProvisionalContract(
	t *testing.T,
	newRepo func() identity.Repository,
	tenant string,
	ident func(identity.Kind, string, string) identity.Identifier,
	newAsset func(string, ...identity.Identifier) identity.NewAsset,
) {
	t.Helper()
	ctx := context.Background()

	t.Run("CreateAsset records an identity status the summary reports", func(t *testing.T) {
		r := newRepo()
		provisional := newAsset("advertised-host", ident(identity.KindHostname, "printer.local", "seg-b"))
		provisional.IdentityStatus = string(identity.IdentityProvisional)
		p, err := r.CreateAsset(ctx, tenant, provisional)
		if err != nil {
			t.Fatalf("CreateAsset(provisional): %v", err)
		}
		ordinary, err := r.CreateAsset(ctx, tenant, newAsset("met-host", ident(identity.KindSerialNumber, "SN-PROV-1", "")))
		if err != nil {
			t.Fatalf("CreateAsset(default): %v", err)
		}

		sums, err := r.LoadSummaries(ctx, tenant, []string{p.ID, ordinary.ID})
		if err != nil {
			t.Fatalf("LoadSummaries: %v", err)
		}
		if len(sums) != 2 {
			t.Fatalf("LoadSummaries returned %d summaries, want 2", len(sums))
		}
		byID := map[string]identity.AssetSummary{sums[0].Ref.ID: sums[0], sums[1].Ref.ID: sums[1]}
		if got := byID[p.ID].IdentityStatus; got != string(identity.IdentityProvisional) {
			t.Errorf("IdentityStatus = %q, want provisional — the corroboration rule cannot see that "+
				"an asset is a guess without it", got)
		}
		if got := byID[ordinary.ID].IdentityStatus; got != string(identity.IdentityLegacy) {
			t.Errorf("IdentityStatus = %q for an asset created without one, want the store's default %q",
				got, identity.IdentityLegacy)
		}
	})

	t.Run("ReassignIdentifier moves ownership and refuses a foreign from", func(t *testing.T) {
		r := newRepo()
		mover, ok := r.(identity.IdentifierReassigner)
		if !ok {
			t.Fatalf("%T does not implement identity.IdentifierReassigner; the hearsay-yields rule of "+
				"#1898 D3 cannot run against it", r)
		}
		addr := ident(identity.KindIPAddress, "192.168.1.50", "seg-b")
		from, err := r.CreateAsset(ctx, tenant, newAsset("guess",
			ident(identity.KindHostname, "printer.local", "seg-b"), addr))
		if err != nil {
			t.Fatalf("CreateAsset(from): %v", err)
		}
		to, err := r.CreateAsset(ctx, tenant, newAsset("met", ident(identity.KindMACAddress, "02:00:00:00:be:ef", "")))
		if err != nil {
			t.Fatalf("CreateAsset(to): %v", err)
		}
		stranger, err := r.CreateAsset(ctx, tenant, newAsset("stranger", ident(identity.KindSerialNumber, "SN-PROV-2", "")))
		if err != nil {
			t.Fatalf("CreateAsset(stranger): %v", err)
		}

		// A move computed against the WRONG owner is refused, and changes
		// nothing. This polarity first, so a store that simply always moves
		// cannot pass by being asked the easy question only.
		if err := mover.ReassignIdentifier(ctx, addr, stranger, to); err == nil {
			t.Error("ReassignIdentifier accepted a `from` that does not own the identifier; a move " +
				"computed against stale ownership is how two assets swap halves of their identity")
		}
		owners, err := r.FindByIdentifier(ctx, tenant, addr.Kind, addr.Value, addr.Scope)
		if err != nil {
			t.Fatalf("FindByIdentifier after the refused move: %v", err)
		}
		if len(owners) != 1 || owners[0].ID != from.ID {
			t.Fatalf("owners = %+v after a REFUSED move, want the original owner %s", owners, from.ID)
		}

		if err := mover.ReassignIdentifier(ctx, addr, from, to); err != nil {
			t.Fatalf("ReassignIdentifier: %v", err)
		}
		owners, err = r.FindByIdentifier(ctx, tenant, addr.Kind, addr.Value, addr.Scope)
		if err != nil {
			t.Fatalf("FindByIdentifier: %v", err)
		}
		if len(owners) != 1 {
			t.Fatalf("owners = %+v, want exactly one — an identifier value maps to at most one asset, "+
				"and a move must not leave it on both or on neither", owners)
		}
		if owners[0].ID != to.ID {
			t.Errorf("owner = %s, want %s", owners[0].ID, to.ID)
		}
		sums, err := r.LoadSummaries(ctx, tenant, []string{from.ID, to.ID})
		if err != nil {
			t.Fatalf("LoadSummaries: %v", err)
		}
		for _, s := range sums {
			held := countKind(s.Identifiers, identity.KindIPAddress)
			if s.Ref.ID == from.ID && held != 0 {
				t.Errorf("%s still carries %d ip_address identifier(s) after the move", from.ID, held)
			}
			if s.Ref.ID == to.ID && held != 1 {
				t.Errorf("%s carries %d ip_address identifier(s) after the move, want 1", to.ID, held)
			}
		}
	})

	t.Run("RetireIdentifier removes one value and refuses a foreign owner", func(t *testing.T) {
		r := newRepo()
		retirer, ok := r.(identity.IdentifierRetirer)
		if !ok {
			t.Fatalf("%T does not implement identity.IdentifierRetirer; the drift verdicts of #2205 "+
				"Decision 4 cannot replace a rotated key or release a moved-away address against it", r)
		}
		oldKey := ident(identity.KindSSHHostKeyFingerprint, "SHA256:contract-retire-old", "")
		newKey := ident(identity.KindSSHHostKeyFingerprint, "SHA256:contract-retire-new", "")
		holder, err := r.CreateAsset(ctx, tenant, newAsset("host", oldKey, newKey))
		if err != nil {
			t.Fatalf("CreateAsset(holder): %v", err)
		}
		stranger, err := r.CreateAsset(ctx, tenant, newAsset("stranger", ident(identity.KindSerialNumber, "SN-RETIRE-2", "")))
		if err != nil {
			t.Fatalf("CreateAsset(stranger): %v", err)
		}
		// The refusing polarity first, so a store that deletes by value alone
		// cannot pass.
		if err := retirer.RetireIdentifier(ctx, stranger, oldKey); err == nil {
			t.Error("RetireIdentifier removed a value from an asset that does not hold it")
		}
		if owners, err := r.FindByIdentifier(ctx, tenant, oldKey.Kind, oldKey.Value, oldKey.Scope); err != nil || len(owners) != 1 {
			t.Fatalf("owners after a REFUSED retire = %+v (%v), want the holder", owners, err)
		}
		if err := retirer.RetireIdentifier(ctx, holder, oldKey); err != nil {
			t.Fatalf("RetireIdentifier: %v", err)
		}
		if owners, err := r.FindByIdentifier(ctx, tenant, oldKey.Kind, oldKey.Value, oldKey.Scope); err != nil || len(owners) != 0 {
			t.Errorf("owners of a retired value = %+v (%v), want none", owners, err)
		}
		sums, err := r.LoadSummaries(ctx, tenant, []string{holder.ID})
		if err != nil || len(sums) != 1 {
			t.Fatalf("LoadSummaries: %+v %v", sums, err)
		}
		if got := countKind(sums[0].Identifiers, identity.KindSSHHostKeyFingerprint); got != 1 {
			t.Errorf("the holder carries %d host keys after retiring one of two, want 1", got)
		}
		if err := retirer.RetireIdentifier(ctx, holder, oldKey); err == nil {
			t.Error("retiring the same value twice succeeded; the second must report it is gone")
		}
	})

	t.Run("an SSH host key's algorithm is stored and never forgotten", func(t *testing.T) {
		r := newRepo()
		known := ident(identity.KindSSHHostKeyFingerprint, "SHA256:contract-alg-known", "")
		known.KeyAlgorithm = "ed25519"
		legacy := ident(identity.KindSSHHostKeyFingerprint, "SHA256:contract-alg-legacy", "")
		ref, err := r.CreateAsset(ctx, tenant, newAsset("keys", known, legacy))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		algOf := func() map[string]string {
			sums, err := r.LoadSummaries(ctx, tenant, []string{ref.ID})
			if err != nil || len(sums) != 1 {
				t.Fatalf("LoadSummaries: %+v %v", sums, err)
			}
			out := map[string]string{}
			for _, id := range sums[0].Identifiers {
				out[id.Value] = id.KeyAlgorithm
			}
			return out
		}
		if got := algOf(); got[known.Value] != "ed25519" || got[legacy.Value] != "" {
			t.Fatalf("algorithms = %v, want ed25519 and unknown", got)
		}
		// A re-sighting that does not say the algorithm keeps it; one that
		// does fills in a row stored without it.
		bare := known
		bare.KeyAlgorithm = ""
		filled := legacy
		filled.KeyAlgorithm = "rsa"
		if _, err := r.AttachIdentifiers(ctx, ref, []identity.Identifier{bare, filled}); err != nil {
			t.Fatalf("AttachIdentifiers: %v", err)
		}
		if got := algOf(); got[known.Value] != "ed25519" || got[legacy.Value] != "rsa" {
			t.Errorf("algorithms after re-sighting = %v, want ed25519 kept and rsa filled in", got)
		}
	})

	t.Run("DriftMaterial reports the ports an asset listens on", func(t *testing.T) {
		r := newRepo()
		reader, ok := r.(identity.DriftMaterialReader)
		if !ok {
			t.Fatalf("%T does not implement identity.DriftMaterialReader", r)
		}
		ref, err := r.CreateAsset(ctx, tenant, newAsset("ports", ident(identity.KindSerialNumber, "SN-DRIFT-PORTS", "")))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		if _, err := r.UpsertEndpoints(ctx, ref, []identity.EndpointObservation{
			{Address: "192.0.2.77", Port: 22, Transport: "tcp"},
			{Address: "192.0.2.77", Port: 443, Transport: "tcp"},
			{Address: "192.0.2.77", Port: 0, Transport: "none"},
		}); err != nil {
			t.Fatalf("UpsertEndpoints: %v", err)
		}
		got, err := reader.DriftMaterial(ctx, ref)
		if err != nil {
			t.Fatalf("DriftMaterial: %v", err)
		}
		if len(got.Ports) != 2 || got.Ports[0] != "22/tcp" || got.Ports[1] != "443/tcp" {
			t.Errorf("ports = %v, want [22/tcp 443/tcp] — a port-less endpoint is not a listener", got.Ports)
		}
		if len(got.TLSCertFingerprints) != 0 {
			t.Errorf("certificates = %v for an asset that presented none", got.TLSCertFingerprints)
		}
	})

	t.Run("ArchiveAsset retires an emptied guess", func(t *testing.T) {
		r := newRepo()
		archiver, ok := r.(identity.AssetArchiver)
		if !ok {
			t.Fatalf("%T does not implement identity.AssetArchiver", r)
		}
		ref, err := r.CreateAsset(ctx, tenant, newAsset("guess", ident(identity.KindHostname, "ghost.local", "seg-b")))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		if err := archiver.ArchiveAsset(ctx, ref); err != nil {
			t.Fatalf("ArchiveAsset: %v", err)
		}
		sums, err := r.LoadSummaries(ctx, tenant, []string{ref.ID})
		if err != nil {
			t.Fatalf("LoadSummaries: %v", err)
		}
		if len(sums) != 1 || sums[0].Status != identity.StatusArchived {
			t.Errorf("status = %+v, want archived", sums)
		}
	})

	t.Run("ProvisionalScope answers, and an unknown segment answers no", func(t *testing.T) {
		r := newRepo()
		checker, ok := r.(identity.ProvisionalScopeChecker)
		if !ok {
			t.Fatalf("%T does not implement identity.ProvisionalScopeChecker; the engine would treat "+
				"every segment as ineligible and no provisional asset would ever be created", r)
		}

		// The default polarity FIRST: a store that has not been told about a
		// segment must not invent assets against it.
		eligible, reason, err := checker.ProvisionalScope(ctx, tenant, "seg-nobody-configured")
		if err != nil {
			t.Fatalf("ProvisionalScope(unknown): %v", err)
		}
		if eligible {
			t.Error("an unconfigured segment reported ELIGIBLE; the default direction is the one " +
				"that ends with an inventory of guesses")
		}
		if reason != identity.ReasonNetworkScopeUnresolved {
			t.Errorf("reason = %q, want %q", reason, identity.ReasonNetworkScopeUnresolved)
		}

		// The other polarity needs an implementation that can be TOLD which
		// segments are eligible. It is a nested subtest so an implementation
		// that derives the answer from its own rows (the SQL one, which pins
		// that derivation in its own package) skips only this half and still
		// reports the default above as run rather than skipped.
		t.Run("a configured segment answers yes, and a bad one says why", func(t *testing.T) {
			writer, ok := r.(ProvisionalScopeWriter)
			if !ok {
				t.Skipf("%T derives eligibility and cannot be told which segments are eligible", r)
			}
			writer.SetProvisionalScopeAnswer(tenant, "seg-ok", true, "")
			writer.SetProvisionalScopeAnswer(tenant, "seg-overlap", false, identity.ReasonOverlappingNetworkScope)

			eligible, reason, err := checker.ProvisionalScope(ctx, tenant, "seg-ok")
			if err != nil {
				t.Fatalf("ProvisionalScope(eligible): %v", err)
			}
			if !eligible || reason != "" {
				t.Errorf("ProvisionalScope(eligible) = %v / %q, want true with no reason", eligible, reason)
			}

			eligible, reason, err = checker.ProvisionalScope(ctx, tenant, "seg-overlap")
			if err != nil {
				t.Fatalf("ProvisionalScope(overlapping): %v", err)
			}
			if eligible || reason != identity.ReasonOverlappingNetworkScope {
				t.Errorf("ProvisionalScope(overlapping) = %v / %q, want false with %q",
					eligible, reason, identity.ReasonOverlappingNetworkScope)
			}
		})
	})
}

// runHostnameCardinalityContract holds every implementation to
// [identity.Repository.HostnameCardinality] ( B2): the count is of distinct
// LIVE assets, across every scope, case-insensitive, for `hostname` identifiers
// only, and never crosses a tenant.
func runHostnameCardinalityContract(
	t *testing.T,
	newRepo func() identity.Repository,
	tenant, otherTenant string,
	ident func(identity.Kind, string, string) identity.Identifier,
	newAsset func(string, ...identity.Identifier) identity.NewAsset,
) {
	t.Helper()
	ctx := context.Background()

	t.Run("HostnameCardinality counts distinct live assets across scopes", func(t *testing.T) {
		r := newRepo()
		const name = "lobby-display"

		count := func(tenantID, value string) int {
			t.Helper()
			n, err := r.HostnameCardinality(ctx, tenantID, value)
			if err != nil {
				t.Fatalf("HostnameCardinality(%q): %v", value, err)
			}
			return n
		}

		// An unknown value is a normal answer: zero, no error.
		if got := count(tenant, name); got != 0 {
			t.Fatalf("empty store: cardinality = %d, want 0", got)
		}

		a, err := r.CreateAsset(ctx, tenant, newAsset("a", ident(identity.KindHostname, name, "segment-1")))
		if err != nil {
			t.Fatalf("CreateAsset(a): %v", err)
		}
		if _, err := r.CreateAsset(ctx, tenant, newAsset("b", ident(identity.KindHostname, name, "segment-2"))); err != nil {
			t.Fatalf("CreateAsset(b): %v", err)
		}
		if got := count(tenant, name); got != 2 {
			t.Errorf("one value under two scopes on two assets: cardinality = %d, want 2 (any scope counts)", got)
		}

		// The same asset carrying the value under a second scope is still ONE
		// asset. The count is of assets, not of identifier rows.
		if _, err := r.AttachIdentifiers(ctx, a, []identity.Identifier{ident(identity.KindHostname, name, "segment-3")}); err != nil {
			t.Fatalf("AttachIdentifiers: %v", err)
		}
		if got := count(tenant, name); got != 2 {
			t.Errorf("one asset under two scopes: cardinality = %d, want 2 (distinct assets, not rows)", got)
		}

		// Stored hostnames are lower case with no trailing dot, so the question
		// is folded the same way.
		if got := count(tenant, "  LOBBY-Display. "); got != 2 {
			t.Errorf("case and a trailing dot changed the answer: cardinality = %d, want 2", got)
		}

		// A different kind with the same text is a different fact.
		if _, err := r.CreateAsset(ctx, tenant, newAsset("c", ident(identity.KindName, name, "server"))); err != nil {
			t.Fatalf("CreateAsset(c): %v", err)
		}
		if got := count(tenant, name); got != 2 {
			t.Errorf("a `name` identifier counted as a hostname: cardinality = %d, want 2", got)
		}

		// Tenants do not see each other.
		if _, err := r.CreateAsset(ctx, otherTenant, newAsset("d", ident(identity.KindHostname, name, "segment-1"))); err != nil {
			t.Fatalf("CreateAsset(d): %v", err)
		}
		if got := count(tenant, name); got != 2 {
			t.Errorf("another tenant's asset leaked into the count: cardinality = %d, want 2", got)
		}
		if got := count(otherTenant, name); got != 1 {
			t.Errorf("other tenant: cardinality = %d, want 1", got)
		}
	})

	t.Run("HostnameCardinality stops counting an archived asset", func(t *testing.T) {
		r := newRepo()
		archiver, ok := r.(identity.AssetArchiver)
		if !ok {
			t.Fatalf("%T does not implement identity.AssetArchiver", r)
		}
		const name = "lobby-display"
		a, err := r.CreateAsset(ctx, tenant, newAsset("a", ident(identity.KindHostname, name, "segment-1")))
		if err != nil {
			t.Fatalf("CreateAsset(a): %v", err)
		}
		if _, err := r.CreateAsset(ctx, tenant, newAsset("b", ident(identity.KindHostname, name, "segment-2"))); err != nil {
			t.Fatalf("CreateAsset(b): %v", err)
		}
		if err := archiver.ArchiveAsset(ctx, a); err != nil {
			t.Fatalf("ArchiveAsset: %v", err)
		}
		got, err := r.HostnameCardinality(ctx, tenant, name)
		if err != nil {
			t.Fatalf("HostnameCardinality: %v", err)
		}
		if got != 1 {
			t.Errorf("cardinality = %d after archiving one of two, want 1: a retired record still testified that the name is common", got)
		}
	})
}

// RunPinnedAddressContract holds an implementation to the pinned-address rule
// (owner decision 1; ADR-0002 D3 erratum): an `ip_address` inside a
// scope flagged dynamic still decides a match when its OWNER holds it as
// [identity.AssignmentStatic], and helps no other asset.
//
// It runs against whichever store it is handed because the rule reads the
// owner's copy back through [identity.Repository.LoadSummaries]: a store that
// dropped `address_assignment` on the way out would make every pinned address
// a lease again, silently, and only running the same assertions over both
// stores says it does not.
//
// newRepo must return a FRESH, empty repository on every call.
func RunPinnedAddressContract(t *testing.T, newRepo func() identity.Repository) {
	t.Helper()

	const (
		tenant  = "tenant-a"
		dynamic = "seg-dhcp"
	)
	ctx := context.Background()
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

	ident := func(kind identity.Kind, value, scope string, src identity.SourceKind) identity.Identifier {
		return identity.Identifier{
			Kind: kind, Value: value, Scope: scope, Confidence: 1,
			Source: identity.Source{Kind: src, Ref: "contract"}, SeenAt: now,
		}
	}
	holder := func(r identity.Repository, name string, ids ...identity.Identifier) identity.AssetRef {
		t.Helper()
		ref, err := r.CreateAsset(ctx, tenant, identity.NewAsset{
			ClassKey: "server", ClassSourceKind: identity.ClassSourceMeasured, DisplayName: name,
			Status: identity.StatusMonitoring, Source: identity.Source{Kind: identity.SourceMeasured, Ref: "contract"},
			Identifiers: ids, FirstSeenAt: now, LastSeenAt: now,
		})
		if err != nil {
			t.Fatalf("CreateAsset(%s): %v", name, err)
		}
		return ref
	}
	// A plain sensor scan: measured, nothing declared, nothing pinned by the
	// observation itself. The scope is dynamic per the OBSERVATION, which is
	// how every intake adapter reports a DHCP segment today.
	scan := func(ids ...identity.Identifier) identity.Observation {
		return identity.Observation{
			TenantID: tenant, ClassHint: "server",
			Source:     identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:scan"},
			ObservedAt: now.Add(time.Hour), Confidence: 1, Identifiers: ids,
			DynamicScopes: map[string]bool{dynamic: true},
		}
	}
	engineOver := func(r identity.Repository) *identity.Engine {
		eng, err := identity.New(identity.Config{Repo: r})
		if err != nil {
			t.Fatalf("identity.New: %v", err)
		}
		return eng
	}
	addr := func(v string) identity.Identifier {
		return identity.Identifier{Kind: identity.KindIPAddress, Value: v, Scope: dynamic, Confidence: 1}
	}

	t.Run("an address the operator declared matches its owner inside a dynamic scope", func(t *testing.T) {
		r := newRepo()
		gw := holder(r, "gateway", ident(identity.KindIPAddress, "192.0.2.1", dynamic, identity.SourceDeclared))

		res, err := engineOver(r).Resolve(ctx, scan(addr("192.0.2.1")))
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Outcome != identity.OutcomeMatched || res.Asset.ID != gw.ID || res.DecidedBy != identity.KindIPAddress {
			t.Fatalf("resolution = %s on %q by %s, want matched on the gateway by ip_address", res.Outcome, res.Asset.ID, res.DecidedBy)
		}
	})

	t.Run("an address the host's agent reported static matches its owner inside a dynamic scope", func(t *testing.T) {
		r := newRepo()
		pinned := ident(identity.KindIPAddress, "192.0.2.2", dynamic, identity.SourceMeasured)
		pinned.Assignment = identity.AssignmentStatic
		host := holder(r, "host", pinned)

		res, err := engineOver(r).Resolve(ctx, scan(addr("192.0.2.2")))
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Outcome != identity.OutcomeMatched || res.Asset.ID != host.ID {
			t.Fatalf("resolution = %s on %q, want matched on the host", res.Outcome, res.Asset.ID)
		}
	})

	// The rule's other half, unchanged: an address nobody pinned is still a
	// lease and still decides nothing. The single owner makes it supporting
	// evidence ( A1) — never `matched`.
	t.Run("an address merely measured, or reported dhcp, still does not decide inside a dynamic scope", func(t *testing.T) {
		for _, a := range []identity.AddressAssignment{"", identity.AssignmentDynamic} {
			r := newRepo()
			held := ident(identity.KindIPAddress, "192.0.2.3", dynamic, identity.SourceMeasured)
			held.Assignment = a
			holder(r, "leased", held)

			res, err := engineOver(r).Resolve(ctx, scan(addr("192.0.2.3")))
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if res.Outcome == identity.OutcomeMatched {
				t.Fatalf("assignment %q: a lease decided a match (%s on %s)", a, res.Outcome, res.Asset.ID)
			}
		}
	})

	// A pin is a fact about its owner's copy. An observation whose own
	// device identifier names B, carrying A's pinned address, is two records
	// named at once — a question for a reviewer, never a match for B on the
	// strength of A's pin and never a silent match for A.
	t.Run("an address pinned on one asset does not help an observation onto another", func(t *testing.T) {
		r := newRepo()
		a := holder(r, "a", ident(identity.KindIPAddress, "192.0.2.4", dynamic, identity.SourceDeclared))
		b := holder(r, "b", ident(identity.KindSerialNumber, "SN-PIN-B", "", identity.SourceMeasured))

		res, err := engineOver(r).Resolve(ctx, scan(
			identity.Identifier{Kind: identity.KindSerialNumber, Value: "SN-PIN-B", Confidence: 1},
			addr("192.0.2.4")))
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Outcome == identity.OutcomeMatched {
			t.Fatalf("resolution = matched on %s; want a conflict between %s and %s", res.Asset.ID, a.ID, b.ID)
		}
		owners, err := r.FindByIdentifier(ctx, tenant, identity.KindIPAddress, "192.0.2.4", dynamic)
		if err != nil || len(owners) != 1 || owners[0].ID != a.ID {
			t.Fatalf("the pinned address is held by %+v (err %v), want only %s", owners, err, a.ID)
		}

		// And the pin did not make B's own unpinned address in the same
		// scope vote: a plain scan of it is still not a match.
		r2 := newRepo()
		holder(r2, "a2", ident(identity.KindIPAddress, "192.0.2.5", dynamic, identity.SourceDeclared))
		holder(r2, "b2", ident(identity.KindIPAddress, "192.0.2.6", dynamic, identity.SourceMeasured))
		res, err = engineOver(r2).Resolve(ctx, scan(addr("192.0.2.6")))
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Outcome == identity.OutcomeMatched {
			t.Fatalf("an unpinned neighbour of a pinned address decided a match (%s)", res.Asset.ID)
		}
	})
}
