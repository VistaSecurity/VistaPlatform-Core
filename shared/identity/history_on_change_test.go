package identity_test

import (
	"context"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/memory"
)

// The asset timeline (`asset_history`) is what a person reads to learn what
// happened to an asset. A match that changed nothing is not something that
// happened, so it leaves no `updated` row — while every last-seen still moves.
//
// Mutation check: make recordIfChanged write unconditionally (`if true`) →
// every test below that counts rows fails.

func updatedRows(repo *memory.Repository, ref identity.AssetRef) []identity.HistoryEntry {
	var out []identity.HistoryEntry
	for _, h := range repo.HistoryFor(ref) {
		if h.Action == identity.ActionUpdated {
			out = append(out, h)
		}
	}
	return out
}

func identifierSeen(t *testing.T, repo *memory.Repository, ident identity.Identifier) time.Time {
	t.Helper()
	at, ok, err := repo.IdentifierLastSeen(context.Background(), tenant, ident)
	if err != nil || !ok {
		t.Fatalf("IdentifierLastSeen(%s): ok=%v err=%v", ident.Key(), ok, err)
	}
	return at
}

func TestHistory_PureReobservationWritesNoUpdatedRow(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	serial := id(identity.KindSerialNumber, "SN-hist-1")
	mac := id(identity.KindMACAddress, "aa:bb:cc:00:30:01")

	first := mustResolve(t, e, obs(assetclass.KeyServer, serial, mac))
	if first.Outcome != identity.OutcomeCreated {
		t.Fatalf("first outcome = %s, want created", first.Outcome)
	}
	seenFirst := identifierSeen(t, repo, serial)

	for i := 1; i <= 5; i++ {
		o := obs(assetclass.KeyServer, serial, mac)
		o.ObservedAt = observedAt.Add(time.Duration(i) * time.Hour)
		res := mustResolve(t, e, o)
		if res.Outcome != identity.OutcomeMatched || res.Asset.ID != first.Asset.ID {
			t.Fatalf("observation %d: outcome = %s on %s, want matched on %s", i, res.Outcome, res.Asset.ID, first.Asset.ID)
		}
	}

	if rows := updatedRows(repo, first.Asset); len(rows) != 0 {
		t.Errorf("%d `updated` rows after five pure re-observations, want 0: %+v", len(rows), rows)
	}
	if n := len(repo.HistoryFor(first.Asset)); n != 1 {
		t.Errorf("%d history rows, want exactly the one `created`: %v", n, historyActions(repo.HistoryFor(first.Asset)))
	}
	// Only the timeline row is suppressed: the clocks still move.
	if got := identifierSeen(t, repo, serial); !got.After(seenFirst) {
		t.Errorf("identifier last-seen = %s, want it advanced past %s", got, seenFirst)
	}
	if got, want := repo.LastSeen(first.Asset), observedAt.Add(5*time.Hour); !got.Equal(want) {
		t.Errorf("asset last-seen = %s, want %s", got, want)
	}
}

func TestHistory_NewIdentifierWritesExactlyOneRowNamingIt(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	serial := id(identity.KindSerialNumber, "SN-hist-2")
	first := mustResolve(t, e, obs(assetclass.KeyServer, serial))

	extra := id(identity.KindMACAddress, "aa:bb:cc:00:30:02")
	for i := 1; i <= 4; i++ {
		o := obs(assetclass.KeyServer, serial, extra)
		o.ObservedAt = observedAt.Add(time.Duration(i) * time.Hour)
		mustResolve(t, e, o)
	}

	rows := updatedRows(repo, first.Asset)
	if len(rows) != 1 {
		t.Fatalf("%d `updated` rows, want exactly 1 (the observation that brought the MAC): %+v", len(rows), rows)
	}
	ids, _ := rows[0].Changes["identifiers"].([]string)
	found := false
	for _, k := range ids {
		if k == extra.Key() {
			found = true
		}
	}
	if !found {
		t.Errorf("the row's identifiers = %v, want it to name %s", ids, extra.Key())
	}
}

func TestHistory_EndpointWritesARowOnlyWhenNewOrIdentified(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	serial := id(identity.KindSerialNumber, "SN-hist-3")
	first := mustResolve(t, e, obs(assetclass.KeyServer, serial))

	observe := func(hour int, protocol string) {
		o := obs(assetclass.KeyServer, serial)
		o.ObservedAt = observedAt.Add(time.Duration(hour) * time.Hour)
		o.Endpoints = []identity.EndpointObservation{{Address: "192.0.2.80", Port: 443, Transport: "tcp", Protocol: protocol}}
		mustResolve(t, e, o)
	}
	step := func(name string, want int) {
		t.Helper()
		if got := len(updatedRows(repo, first.Asset)); got != want {
			t.Fatalf("%s: %d `updated` rows, want %d", name, got, want)
		}
	}

	observe(1, "")
	step("a new endpoint", 1)
	observe(2, "")
	observe(3, "")
	step("the same endpoint again", 1)
	observe(4, "https")
	step("the endpoint gaining a protocol", 2)
	observe(5, "https")
	observe(6, "")
	step("the identified endpoint re-seen", 2)
}

func TestHistory_BetterNameWritesARow(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	serial := id(identity.KindSerialNumber, "SN-hist-4")
	first := mustResolve(t, e, obs(assetclass.KeyServer, serial))

	named := obs(assetclass.KeyServer, serial)
	named.ObservedAt = observedAt.Add(time.Hour)
	named.Hostname = "web-4.example.test"
	named.DisplayName = "web-4.example.test"
	mustResolve(t, e, named)

	rows := updatedRows(repo, first.Asset)
	if len(rows) != 1 {
		t.Fatalf("%d `updated` rows, want 1 for the name the asset gained: %+v", len(rows), rows)
	}
	if rows[0].Changes["hostname"] == nil && rows[0].Changes["display_name"] == nil {
		t.Errorf("the row does not record the name change: %+v", rows[0].Changes)
	}
	again := named
	again.ObservedAt = observedAt.Add(2 * time.Hour)
	mustResolve(t, e, again)
	if n := len(updatedRows(repo, first.Asset)); n != 1 {
		t.Errorf("%d `updated` rows after the same name was seen again, want still 1", n)
	}
}

// A sighting whose every identifier belongs to one asset but may not decide
// (the floor's single-owner branch) is the "supporting" row of the real
// installs. The condition is worth one row, the first time; N sightings are not
// N rows, and the asset's last-seen still follows them.
func TestHistory_RepeatedSupportingSightingDoesNotGrowTheTimeline(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	cloudMAC := id(identity.KindMACAddress, "aa:bb:cc:00:30:05")
	cloudARN := id(identity.KindCloudResourceID, "arn:aws:ec2:us-east-1:1:instance/i-3005")
	owner := mustResolve(t, e, obs(assetclass.KeyCloudResource, cloudARN, cloudMAC))

	for i := 1; i <= 6; i++ {
		o := obs(assetclass.KeyCloudResource, cloudMAC)
		o.ObservedAt = observedAt.Add(time.Duration(i) * time.Hour)
		res := mustResolve(t, e, o)
		if res.Outcome != identity.OutcomeSupporting {
			t.Fatalf("sighting %d: outcome = %s, want supporting", i, res.Outcome)
		}
	}

	var supporting int
	for _, h := range updatedRows(repo, owner.Asset) {
		if h.Changes["supporting"] == true {
			supporting++
		}
	}
	if supporting != 1 {
		t.Errorf("%d supporting rows after six sightings, want 1 (the first appearance of the condition)", supporting)
	}
	if got, want := repo.LastSeen(owner.Asset), observedAt.Add(6*time.Hour); !got.Equal(want) {
		t.Errorf("asset last-seen = %s, want %s: suppressing the row must not stop the clock", got, want)
	}
}

// A DIFFERENT condition on the same asset is a new fact and gets its row: the
// memo is "this condition", not "any unattached ever".
func TestHistory_ANewUnattachedConditionStillWritesARow(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	macA := id(identity.KindMACAddress, "aa:bb:cc:00:30:06")
	macB := id(identity.KindMACAddress, "aa:bb:cc:00:30:07")
	arn := id(identity.KindCloudResourceID, "arn:aws:ec2:us-east-1:1:instance/i-3006")
	owner := mustResolve(t, e, obs(assetclass.KeyCloudResource, arn, macA, macB))

	for _, m := range []identity.Identifier{macA, macA, macB, macB} {
		mustResolve(t, e, obs(assetclass.KeyCloudResource, m))
	}
	n := 0
	for _, h := range updatedRows(repo, owner.Asset) {
		if h.Changes["supporting"] == true {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d supporting rows for two distinct held-back identifiers each seen twice, want 2", n)
	}
}

// An import or declaration listing an asset is read off the timeline (the
// auto-scan consent rule counts "a spreadsheet has listed it"), so the FIRST
// listing by each source is written even when it carried nothing new — and only
// the first. A measured source is not that kind of fact.
func TestHistory_ImportListingIsWrittenOncePerSource(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	serial := id(identity.KindSerialNumber, "SN-hist-7")
	first := mustResolve(t, e, obs(assetclass.KeyServer, serial))

	listed := func(ref string, hour int) {
		o := obs(assetclass.KeyServer, serial)
		o.Source = identity.Source{Kind: identity.SourceImported, Ref: ref}
		o.ObservedAt = observedAt.Add(time.Duration(hour) * time.Hour)
		mustResolve(t, e, o)
	}
	listed("import", 1)
	listed("import", 2)
	listed("import", 3)
	if n := len(updatedRows(repo, first.Asset)); n != 1 {
		t.Fatalf("%d updated rows after a spreadsheet listed the asset three times, want 1", n)
	}
	if !hasChange(updatedRows(repo, first.Asset), identity.ActionUpdated, "listed_by", "import") {
		t.Error("the row does not say which source listed the asset")
	}
	listed("cmdb:profile-1", 4)
	listed("cmdb:profile-1", 5)
	if n := len(updatedRows(repo, first.Asset)); n != 2 {
		t.Errorf("%d updated rows after a second source listed it, want 2", n)
	}
	for h := 6; h < 9; h++ {
		o := obs(assetclass.KeyServer, serial)
		o.ObservedAt = observedAt.Add(time.Duration(h) * time.Hour)
		mustResolve(t, e, o)
	}
	if n := len(updatedRows(repo, first.Asset)); n != 2 {
		t.Errorf("%d updated rows after measured sightings, want still 2", n)
	}
}

func TestChangesContain_FollowsJSONBContainment(t *testing.T) {
	stored := map[string]any{
		"a": []string{"x", "y"},
		"b": map[string]any{"c": true, "d": []any{1, 2}},
		"e": "s",
	}
	for _, tc := range []struct {
		name   string
		subset map[string]any
		want   bool
	}{
		{"empty subset", map[string]any{}, true},
		{"array subset", map[string]any{"a": []string{"y"}}, true},
		{"array superset", map[string]any{"a": []string{"y", "z"}}, false},
		{"nested", map[string]any{"b": map[string]any{"c": true}}, true},
		{"nested mismatch", map[string]any{"b": map[string]any{"c": false}}, false},
		{"number array", map[string]any{"b": map[string]any{"d": []any{2}}}, true},
		{"missing key", map[string]any{"zz": 1}, false},
		{"scalar vs array", map[string]any{"e": []string{"s"}}, false},
	} {
		if got := identity.ChangesContain(stored, tc.subset); got != tc.want {
			t.Errorf("%s: ChangesContain = %v, want %v", tc.name, got, tc.want)
		}
	}
}
