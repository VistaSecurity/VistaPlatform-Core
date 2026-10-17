package dcimtest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/unresolved"
)

// RunResolverContract holds an unresolved.Repository implementation to what
// the resolver needs of it, by driving the REAL resolver
// (unresolved.NewResolver) over it with a FakeMatcher and a RecordingApplier.
//
// newRepo must return an empty repository each call. A SQL implementation
// returns one scoped to a fresh database or fresh tenants; tenants here are
// random uuids, so an implementation that needs real tenant rows can wrap
// newRepo to create them (see the tenant argument of each method).
//
// The clauses, each a subtest so a failure names the rule it broke:
//
//   - park, then the identity-key lookup finds it — and only for its tenant,
//     and not by a value it does not carry;
//   - the same identity parked twice is ONE row with observation_count 2,
//     first_seen kept and last_seen/expiry moved;
//   - a different intent, origin or producer is a different row;
//   - resolve: the fake matcher matches, the applier is called once with the
//     intent's method, and the row is deleted — a second pass applies nothing;
//   - unmatched rows stay parked (NullMatcher resolves nothing);
//   - a failing apply leaves the row parked and Resolve returns the error;
//   - expiry: ExpireBefore removes exactly the rows past expires_at, and
//     Resolve expires before it matches, so a late identity is not applied;
//   - invalid terminations are refused;
//   - every method is tenant-scoped: the same identity parked by two tenants
//     is two rows, and List, Delete, ExpireBefore and Resolve for one tenant
//     never see or touch the other's;
//   - a matcher error is returned and the row stays parked;
//   - List pages by id (limit, then after the last id) without gaps or
//     repeats, and ListByIdentityKeys matches ANY key, oldest first;
//   - the most specific identity wins (sync key, then cloud resource id, MAC,
//     chassis id) and each intent reaches its own applier method.
func RunResolverContract(t *testing.T, newRepo func() unresolved.Repository) {
	t.Helper()
	ctx := context.Background()
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

	lldp := func(origin uuid.UUID, chassis string) unresolved.Termination {
		return unresolved.Termination{
			Producer: "lldp", OriginKind: dcim.ObjectKindInterface, OriginID: origin,
			FarIdentity: map[string]string{unresolved.KeyChassisID: chassis, "port_id": "Gi1/0/24"},
			Intent:      unresolved.IntentCable,
			Attributes:  map[string]any{"observed_by": "sensor-a"},
		}
	}

	t.Run("park then find by identity key", func(t *testing.T) {
		repo := newRepo()
		tenant, other := uuid.New(), uuid.New()
		p, err := repo.Park(ctx, tenant, lldp(uuid.New(), "00:11:22:33:44:55"), t0)
		if err != nil {
			t.Fatalf("park: %v", err)
		}
		if p.ID == uuid.Nil || p.ObservationCount != 1 || !p.FirstSeenAt.Equal(t0) || !p.ExpiresAt.Equal(t0.Add(unresolved.DefaultTTL)) {
			t.Fatalf("parked row = %+v", p)
		}
		got, err := repo.ListByIdentityKeys(ctx, tenant, []unresolved.IdentityKey{{Key: unresolved.KeyChassisID, Value: "00:11:22:33:44:55"}})
		if err != nil || len(got) != 1 || got[0].ID != p.ID {
			t.Fatalf("lookup by chassis id: %v, %+v", err, got)
		}
		if got[0].FarIdentity["port_id"] != "Gi1/0/24" || got[0].Attributes["observed_by"] != "sensor-a" {
			t.Errorf("identity/attributes not stored: %+v", got[0])
		}
		got, _ = repo.ListByIdentityKeys(ctx, tenant, []unresolved.IdentityKey{{Key: unresolved.KeyChassisID, Value: "ff:ff:ff:ff:ff:ff"}})
		if len(got) != 0 {
			t.Errorf("a different value matched: %+v", got)
		}
		got, _ = repo.ListByIdentityKeys(ctx, other, []unresolved.IdentityKey{{Key: unresolved.KeyChassisID, Value: "00:11:22:33:44:55"}})
		if len(got) != 0 {
			t.Errorf("another tenant saw the row: %+v", got)
		}
	})

	t.Run("same identity parked twice increments observation_count", func(t *testing.T) {
		repo := newRepo()
		tenant, origin := uuid.New(), uuid.New()
		first, err := repo.Park(ctx, tenant, lldp(origin, "aa"), t0)
		if err != nil {
			t.Fatal(err)
		}
		later := t0.Add(48 * time.Hour)
		again := lldp(origin, "aa")
		again.Attributes = map[string]any{"observed_by": "sensor-b"}
		second, err := repo.Park(ctx, tenant, again, later)
		if err != nil {
			t.Fatal(err)
		}
		if second.ID != first.ID {
			t.Fatalf("second park made a new row %s (first %s)", second.ID, first.ID)
		}
		if second.ObservationCount != 2 || !second.FirstSeenAt.Equal(t0) || !second.LastSeenAt.Equal(later) ||
			!second.ExpiresAt.Equal(later.Add(unresolved.DefaultTTL)) {
			t.Errorf("after re-park: %+v", second)
		}
		if second.Attributes["observed_by"] != "sensor-b" {
			t.Errorf("attributes not replaced by the latest observation: %+v", second.Attributes)
		}
		all, _ := repo.List(ctx, tenant, uuid.Nil, 100)
		if len(all) != 1 {
			t.Errorf("rows = %d, want 1", len(all))
		}
	})

	t.Run("different intent, origin or producer is a different row", func(t *testing.T) {
		repo := newRepo()
		tenant, origin := uuid.New(), uuid.New()
		base := lldp(origin, "bb")
		rel := base
		rel.Intent = "relationship:connected_to"
		otherOrigin := lldp(uuid.New(), "bb")
		cdp := base
		cdp.Producer = "cdp"
		for _, tm := range []unresolved.Termination{base, rel, otherOrigin, cdp} {
			if _, err := repo.Park(ctx, tenant, tm, t0); err != nil {
				t.Fatal(err)
			}
		}
		all, _ := repo.List(ctx, tenant, uuid.Nil, 100)
		if len(all) != 4 {
			t.Errorf("rows = %d, want 4", len(all))
		}
	})

	t.Run("resolve applies once and deletes", func(t *testing.T) {
		repo := newRepo()
		tenant := uuid.New()
		far := unresolved.Match{Kind: dcim.ObjectKindAsset, ID: uuid.New()}
		p, err := repo.Park(ctx, tenant, lldp(uuid.New(), "cc"), t0)
		if err != nil {
			t.Fatal(err)
		}
		cloud := unresolved.Termination{
			Producer: "cloud", OriginKind: dcim.ObjectKindAsset, OriginID: uuid.New(),
			FarIdentity: map[string]string{unresolved.KeyCloudResourceID: "arn:aws:ec2:us-east-1:1:subnet/s-1"},
			Intent:      "relationship:contained_in",
		}
		pc, err := repo.Park(ctx, tenant, cloud, t0)
		if err != nil {
			t.Fatal(err)
		}
		farCloud := unresolved.Match{Kind: dcim.ObjectKindAsset, ID: uuid.New()}
		m := &FakeMatcher{
			ByChassis: map[string]unresolved.Match{"cc": far},
			ByCloud:   map[string]unresolved.Match{"arn:aws:ec2:us-east-1:1:subnet/s-1": farCloud},
		}
		a := &RecordingApplier{}
		res := unresolved.NewResolver(repo, m, a, func() time.Time { return t0.Add(time.Hour) })
		n, err := res.Resolve(ctx, tenant)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if n.Resolved != 2 || n.Examined != 2 || n.Unmatched != 0 {
			t.Errorf("count = %+v, want 2 resolved of 2", n)
		}
		if len(a.Calls) != 2 {
			t.Fatalf("applier calls = %d, want 2: %+v", len(a.Calls), a.Calls)
		}
		for _, c := range a.Calls {
			switch c.Parked.ID {
			case p.ID:
				if c.Method != "cable" || c.Far != far || c.Tenant != tenant {
					t.Errorf("cable apply = %+v", c)
				}
			case pc.ID:
				if c.Method != "relationship" || c.RelationshipType != "contained_in" || c.Far != farCloud {
					t.Errorf("relationship apply = %+v", c)
				}
			default:
				t.Errorf("applied an unknown row %+v", c)
			}
		}
		if left, _ := repo.List(ctx, tenant, uuid.Nil, 100); len(left) != 0 {
			t.Errorf("resolved rows were not deleted: %+v", left)
		}
		if _, err := res.Resolve(ctx, tenant); err != nil {
			t.Fatal(err)
		}
		if len(a.Calls) != 2 {
			t.Errorf("a second pass applied again: %d calls", len(a.Calls))
		}
	})

	t.Run("unmatched stays parked", func(t *testing.T) {
		repo := newRepo()
		tenant := uuid.New()
		if _, err := repo.Park(ctx, tenant, lldp(uuid.New(), "dd"), t0); err != nil {
			t.Fatal(err)
		}
		a := &RecordingApplier{}
		n, err := unresolved.NewResolver(repo, unresolved.NullMatcher{}, a, func() time.Time { return t0 }).Resolve(ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		if n.Unmatched != 1 || n.Resolved != 0 || len(a.Calls) != 0 {
			t.Errorf("count = %+v, calls = %d", n, len(a.Calls))
		}
		if left, _ := repo.List(ctx, tenant, uuid.Nil, 100); len(left) != 1 {
			t.Errorf("an unmatched row was removed")
		}
	})

	t.Run("failed apply leaves the row parked", func(t *testing.T) {
		repo := newRepo()
		tenant := uuid.New()
		if _, err := repo.Park(ctx, tenant, lldp(uuid.New(), "ee"), t0); err != nil {
			t.Fatal(err)
		}
		boom := errors.New("boom")
		a := &RecordingApplier{Err: boom}
		m := &FakeMatcher{ByChassis: map[string]unresolved.Match{"ee": {Kind: dcim.ObjectKindAsset, ID: uuid.New()}}}
		_, err := unresolved.NewResolver(repo, m, a, func() time.Time { return t0 }).Resolve(ctx, tenant)
		if !errors.Is(err, boom) {
			t.Errorf("err = %v, want the applier's", err)
		}
		if left, _ := repo.List(ctx, tenant, uuid.Nil, 100); len(left) != 1 {
			t.Errorf("a row whose apply failed was deleted")
		}
	})

	t.Run("expiry", func(t *testing.T) {
		repo := newRepo()
		tenant := uuid.New()
		old, err := repo.Park(ctx, tenant, lldp(uuid.New(), "ff"), t0)
		if err != nil {
			t.Fatal(err)
		}
		fresh, err := repo.Park(ctx, tenant, lldp(uuid.New(), "gg"), t0.Add(20*24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		n, err := repo.ExpireBefore(ctx, tenant, old.ExpiresAt) // not BEFORE its own expiry
		if err != nil || n != 0 {
			t.Fatalf("expire at the boundary removed %d (%v)", n, err)
		}
		n, err = repo.ExpireBefore(ctx, tenant, old.ExpiresAt.Add(time.Second))
		if err != nil || n != 1 {
			t.Fatalf("expire after old's expiry removed %d (%v), want 1", n, err)
		}
		left, _ := repo.List(ctx, tenant, uuid.Nil, 100)
		if len(left) != 1 || left[0].ID != fresh.ID {
			t.Fatalf("left = %+v, want only the fresh row", left)
		}

		// Resolve expires BEFORE matching: an identity that arrives after
		// the row expired is not applied.
		m := &FakeMatcher{ByChassis: map[string]unresolved.Match{"gg": {Kind: dcim.ObjectKindAsset, ID: uuid.New()}}}
		a := &RecordingApplier{}
		cnt, err := unresolved.NewResolver(repo, m, a, func() time.Time { return fresh.ExpiresAt.Add(time.Minute) }).Resolve(ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		if cnt.Expired != 1 || len(a.Calls) != 0 {
			t.Errorf("count = %+v, calls = %d — an expired row was matched", cnt, len(a.Calls))
		}
	})

	t.Run("invalid terminations are refused", func(t *testing.T) {
		repo := newRepo()
		tenant := uuid.New()
		bad := []func(*unresolved.Termination){
			func(tm *unresolved.Termination) { tm.Producer = "LLDP!" },
			func(tm *unresolved.Termination) { tm.OriginKind = "switch_port" },
			func(tm *unresolved.Termination) { tm.OriginID = uuid.Nil },
			func(tm *unresolved.Termination) { tm.FarIdentity = nil },
			func(tm *unresolved.Termination) { tm.Intent = "connect" },
		}
		for i, mut := range bad {
			tm := lldp(uuid.New(), "hh")
			mut(&tm)
			if _, err := repo.Park(ctx, tenant, tm, t0); !errors.Is(err, unresolved.ErrInvalid) {
				t.Errorf("case %d: err = %v, want ErrInvalid", i, err)
			}
		}
	})

	t.Run("every method is tenant-scoped", func(t *testing.T) {
		repo := newRepo()
		a, b := uuid.New(), uuid.New()
		origin := uuid.New()
		pa, err := repo.Park(ctx, a, lldp(origin, "ii"), t0)
		if err != nil {
			t.Fatal(err)
		}
		pb, err := repo.Park(ctx, b, lldp(origin, "ii"), t0)
		if err != nil {
			t.Fatal(err)
		}
		if pa.ID == pb.ID || pb.ObservationCount != 1 || pb.TenantID != b {
			t.Fatalf("the same identity parked by another tenant bumped the first tenant's row: a=%+v b=%+v", pa, pb)
		}
		if got, _ := repo.List(ctx, a, uuid.Nil, 100); len(got) != 1 || got[0].ID != pa.ID {
			t.Errorf("List(a) = %+v, want only a's row", got)
		}
		if err := repo.Delete(ctx, a, pb.ID); err != nil {
			t.Fatalf("delete of another tenant's id: %v", err)
		}
		if got, _ := repo.List(ctx, b, uuid.Nil, 100); len(got) != 1 {
			t.Fatalf("Delete(a, b's id) removed b's row")
		}
		if n, err := repo.ExpireBefore(ctx, a, t0.Add(365*24*time.Hour)); err != nil || n != 1 {
			t.Fatalf("ExpireBefore(a) = %d (%v), want 1", n, err)
		}
		if got, _ := repo.List(ctx, b, uuid.Nil, 100); len(got) != 1 {
			t.Fatalf("ExpireBefore(a) removed b's row")
		}
		if _, err := repo.Park(ctx, a, lldp(origin, "ii"), t0); err != nil {
			t.Fatal(err)
		}
		m := &FakeMatcher{ByChassis: map[string]unresolved.Match{"ii": {Kind: dcim.ObjectKindAsset, ID: uuid.New()}}}
		ap := &RecordingApplier{}
		n, err := unresolved.NewResolver(repo, m, ap, func() time.Time { return t0 }).Resolve(ctx, a)
		if err != nil {
			t.Fatal(err)
		}
		if n.Examined != 1 || len(ap.Calls) != 1 || ap.Calls[0].Tenant != a || ap.Calls[0].Parked.TenantID != a {
			t.Errorf("Resolve(a) examined %d, applied %+v — want only a's row", n.Examined, ap.Calls)
		}
		if got, _ := repo.List(ctx, b, uuid.Nil, 100); len(got) != 1 || got[0].ID != pb.ID {
			t.Errorf("Resolve(a) touched b's row: %+v", got)
		}
	})

	t.Run("a matcher error is returned and the row stays", func(t *testing.T) {
		repo := newRepo()
		tenant := uuid.New()
		if _, err := repo.Park(ctx, tenant, lldp(uuid.New(), "jj"), t0); err != nil {
			t.Fatal(err)
		}
		boom := errors.New("matcher down")
		ap := &RecordingApplier{}
		n, err := unresolved.NewResolver(repo, &FakeMatcher{Err: boom}, ap, func() time.Time { return t0 }).Resolve(ctx, tenant)
		if !errors.Is(err, boom) {
			t.Errorf("err = %v, want the matcher's", err)
		}
		if n.Resolved != 0 || len(ap.Calls) != 0 {
			t.Errorf("count = %+v, calls = %d after a matcher error", n, len(ap.Calls))
		}
		if left, _ := repo.List(ctx, tenant, uuid.Nil, 100); len(left) != 1 {
			t.Errorf("a row whose match failed was removed")
		}
	})

	t.Run("List pages by id; ListByIdentityKeys matches any key, oldest first", func(t *testing.T) {
		repo := newRepo()
		tenant := uuid.New()
		var parked []unresolved.Parked
		for i, chassis := range []string{"k1", "k2", "k3"} {
			p, err := repo.Park(ctx, tenant, lldp(uuid.New(), chassis), t0.Add(time.Duration(3-i)*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			parked = append(parked, p)
		}
		first, err := repo.List(ctx, tenant, uuid.Nil, 2)
		if err != nil || len(first) != 2 {
			t.Fatalf("List(limit 2) = %d rows (%v), want 2", len(first), err)
		}
		if first[0].ID.String() >= first[1].ID.String() {
			t.Errorf("List is not ordered by id: %s, %s", first[0].ID, first[1].ID)
		}
		rest, err := repo.List(ctx, tenant, first[1].ID, 2)
		if err != nil || len(rest) != 1 {
			t.Fatalf("List(after the second id) = %d rows (%v), want 1", len(rest), err)
		}
		seen := map[uuid.UUID]bool{first[0].ID: true, first[1].ID: true, rest[0].ID: true}
		for _, p := range parked {
			if !seen[p.ID] {
				t.Errorf("paging skipped %s", p.ID)
			}
		}
		got, err := repo.ListByIdentityKeys(ctx, tenant, []unresolved.IdentityKey{
			{Key: unresolved.KeyChassisID, Value: "k1"}, {Key: unresolved.KeyChassisID, Value: "k3"}, {Key: unresolved.KeyMACAddress, Value: "k2"},
		})
		if err != nil || len(got) != 2 {
			t.Fatalf("ListByIdentityKeys(k1 | k3) = %d rows (%v), want 2", len(got), err)
		}
		// k3 was parked first (t0+1h), k1 last (t0+3h).
		if got[0].ID != parked[2].ID || got[1].ID != parked[0].ID {
			t.Errorf("ListByIdentityKeys is not oldest first: %s, %s", got[0].FarIdentity, got[1].FarIdentity)
		}
	})

	t.Run("most specific identity wins; each intent reaches its method", func(t *testing.T) {
		repo := newRepo()
		tenant := uuid.New()
		bySync := unresolved.Match{Kind: dcim.ObjectKindInterface, ID: uuid.New()}
		byChassis := unresolved.Match{Kind: dcim.ObjectKindAsset, ID: uuid.New()}
		tm := lldp(uuid.New(), "ll")
		tm.FarIdentity["sync:netbox:interface"] = "77"
		tm.Intent = unresolved.IntentAssignment
		p, err := repo.Park(ctx, tenant, tm, t0)
		if err != nil {
			t.Fatal(err)
		}
		m := &FakeMatcher{
			ByChassis: map[string]unresolved.Match{"ll": byChassis},
			BySync:    map[string]unresolved.Match{"sync:netbox:interface=77": bySync},
		}
		ap := &RecordingApplier{}
		if _, err := unresolved.NewResolver(repo, m, ap, func() time.Time { return t0 }).Resolve(ctx, tenant); err != nil {
			t.Fatal(err)
		}
		if len(ap.Calls) != 1 || ap.Calls[0].Parked.ID != p.ID || ap.Calls[0].Method != "assignment" || ap.Calls[0].Far != bySync {
			t.Errorf("applied %+v, want one assignment to the sync-key match", ap.Calls)
		}
	})
}
