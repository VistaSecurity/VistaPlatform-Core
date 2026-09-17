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
		if err := r.AttachIdentifiers(ctx, second, []identity.Identifier{id}); !errors.Is(err, identity.ErrIdentifierConflict) {
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

	t.Run("AttachIdentifiers is idempotent", func(t *testing.T) {
		r := newRepo()
		ref, err := r.CreateAsset(ctx, tenant, newAsset("host-1"))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		id := ident(identity.KindSerialNumber, "SN-1", "")
		for i := range 3 {
			if err := r.AttachIdentifiers(ctx, ref, []identity.Identifier{id}); err != nil {
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

	t.Run("AttachIdentifiers and Touch reject an unknown asset", func(t *testing.T) {
		r := newRepo()
		ghost := identity.AssetRef{TenantID: tenant, ID: "no-such-asset"}
		if err := r.AttachIdentifiers(ctx, ghost, []identity.Identifier{ident(identity.KindSerialNumber, "SN-x", "")}); !errors.Is(err, identity.ErrAssetNotFound) {
			t.Errorf("AttachIdentifiers on a ghost: err = %v, want ErrAssetNotFound", err)
		}
		if err := r.Touch(ctx, ghost, now); !errors.Is(err, identity.ErrAssetNotFound) {
			t.Errorf("Touch on a ghost: err = %v, want ErrAssetNotFound", err)
		}
		if err := r.UpsertEndpoints(ctx, ghost, []identity.EndpointObservation{{Address: "192.0.2.1", Port: 443, Transport: "tcp"}}); !errors.Is(err, identity.ErrAssetNotFound) {
			t.Errorf("UpsertEndpoints on a ghost: err = %v, want ErrAssetNotFound", err)
		}
	})

	t.Run("UpsertEndpoints deduplicates on the endpoint key", func(t *testing.T) {
		r := newRepo()
		ref, err := r.CreateAsset(ctx, tenant, newAsset("host-1"))
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		ep := identity.EndpointObservation{Address: "192.0.2.10", Port: 443, Transport: "tcp", SeenAt: now}
		if err := r.UpsertEndpoints(ctx, ref, []identity.EndpointObservation{ep}); err != nil {
			t.Fatalf("UpsertEndpoints: %v", err)
		}
		later := ep
		later.Protocol = "https"
		later.SeenAt = now.Add(time.Hour)
		if err := r.UpsertEndpoints(ctx, ref, []identity.EndpointObservation{later}); err != nil {
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
		if err := r.UpsertEndpoints(ctx, ref, []identity.EndpointObservation{passive}); err != nil {
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
		if err := r.UpsertEndpoints(ctx, ref, []identity.EndpointObservation{activeScanNoName}); err != nil {
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
		if err := r.UpsertEndpoints(ctx, ref, []identity.EndpointObservation{named}); err != nil {
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

	t.Run("FindByIdentifier round-trips every kind", func(t *testing.T) {
		// One asset per kind, so a store that mishandles a particular kind —
		// an enum it does not carry, a column it truncates, a value it folds —
		// fails on that kind rather than hiding behind the two the rest of this
		// contract happens to use.
		values := map[identity.Kind]string{
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

		// A DIFFERENT question — different identifiers against the same
		// candidates — must still get its own proposal, or the second thing is
		// silently dropped instead of reviewed.
		other := question
		other.Candidates = []identity.MergeCandidate{
			{Ref: a, MatchedIdentifiers: []identity.Identifier{ident(identity.KindSerialNumber, "SN-OTHER", "")}},
			{Ref: b, MatchedIdentifiers: []identity.Identifier{ident(identity.KindMACAddress, "aa:bb:cc:dd:ee:02", "")}},
		}
		third, err := r.OpenMergeProposal(ctx, tenant, other)
		if err != nil {
			t.Fatalf("OpenMergeProposal (other): %v", err)
		}
		if third.ID == first.ID {
			t.Error("two different contested observations collapsed into one proposal; the second was never reviewed")
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
