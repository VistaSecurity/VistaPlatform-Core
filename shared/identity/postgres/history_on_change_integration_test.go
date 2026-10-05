package postgres_test

// The asset timeline against a real Postgres: a decided match writes an
// `updated` row only when the observation changed something on the asset, the
// decision is read from what the SQL write reported (rows inserted vs rows
// merely touched), and every last-seen still advances.
//
// Skips without TEST_DATABASE_URL.
//
// Mutation check: make Engine.recordIfChanged write unconditionally → the
// "no growth" assertions below fail; make attach() report 0 inserted → the
// "new identifier names itself" assertions fail.

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgrepo "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_AssetHistory_WrittenOnlyWhenTheMatchChangedSomething(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db).String()
	repo := pgrepo.New(db)
	ctx := context.Background()
	engine, err := identity.New(identity.Config{Repo: repo, AutoAcceptThreshold: 0.6})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)

	resolve := func(hour int, mutate func(*identity.Observation), macs ...string) identity.Resolution {
		t.Helper()
		o := observation(tenant, "HIST-SN-1", "")
		for _, m := range macs {
			o.Identifiers = append(o.Identifiers, identity.Identifier{Kind: identity.KindMACAddress, Value: m, Confidence: 1})
		}
		o.ObservedAt = base.Add(time.Duration(hour) * time.Hour)
		if mutate != nil {
			mutate(&o)
		}
		var res identity.Resolution
		if err := repo.RunInTx(ctx, tenant, func(r *pgrepo.Repository) error {
			var e error
			res, e = engine.WithRepository(r).Resolve(ctx, o)
			return e
		}); err != nil {
			t.Fatal(err)
		}
		return res
	}
	count := func(asset, action string) int {
		t.Helper()
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM asset_history WHERE tenant_id=$1 AND asset_id=$2 AND action=$3`,
			tenant, asset, action).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	serialSeen := func(asset string) time.Time {
		t.Helper()
		var at time.Time
		if err := db.QueryRow(`SELECT last_seen_at FROM asset_identifiers WHERE tenant_id=$1 AND asset_id=$2 AND kind='serial_number'`,
			tenant, asset).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	assetSeen := func(asset string) time.Time {
		t.Helper()
		var at time.Time
		if err := db.QueryRow(`SELECT last_seen_at FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, asset).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}

	first := resolve(0, nil, "aa:bb:cc:00:40:01")
	if first.Outcome != identity.OutcomeCreated {
		t.Fatalf("first outcome = %s, want created", first.Outcome)
	}
	asset := first.Asset.ID
	if n := count(asset, "created"); n != 1 {
		t.Fatalf("%d created rows, want 1", n)
	}
	seen0 := serialSeen(asset)

	// 1. The same host again, five times: no `updated` row, clocks advance.
	for h := 1; h <= 5; h++ {
		if res := resolve(h, nil, "aa:bb:cc:00:40:01"); res.Outcome != identity.OutcomeMatched || res.Asset.ID != asset {
			t.Fatalf("re-observation %d: %s on %s, want matched on %s", h, res.Outcome, res.Asset.ID, asset)
		}
	}
	if n := count(asset, "updated"); n != 0 {
		t.Errorf("%d updated rows after five pure re-observations, want 0", n)
	}
	if got := serialSeen(asset); !got.After(seen0) {
		t.Errorf("identifier last-seen = %s, want it advanced past %s", got, seen0)
	}
	if got, want := assetSeen(asset), base.Add(5*time.Hour); !got.Equal(want) {
		t.Errorf("asset last-seen = %s, want %s", got, want)
	}

	// 2. A new identifier: exactly one row, and it names the identifier.
	for h := 6; h <= 9; h++ {
		resolve(h, nil, "aa:bb:cc:00:40:01", "aa:bb:cc:00:40:02")
	}
	if n := count(asset, "updated"); n != 1 {
		t.Fatalf("%d updated rows after a new identifier seen four times, want exactly 1", n)
	}
	var named bool
	if err := db.QueryRow(`SELECT changes_json->'identifiers' @> to_jsonb($3::text) FROM asset_history WHERE tenant_id=$1 AND asset_id=$2 AND action='updated'`,
		tenant, asset, "mac_address|aa:bb:cc:00:40:02|").Scan(&named); err != nil || !named {
		t.Errorf("the row does not name the new MAC: named=%v err=%v", named, err)
	}

	// 3. A new endpoint, then the same again, then it gaining a protocol.
	ep := func(protocol string) func(*identity.Observation) {
		return func(o *identity.Observation) {
			o.Endpoints = []identity.EndpointObservation{{Address: "192.0.2.90", Port: 443, Transport: "tcp", Protocol: protocol}}
		}
	}
	resolve(10, ep(""), "aa:bb:cc:00:40:01", "aa:bb:cc:00:40:02")
	if n := count(asset, "updated"); n != 2 {
		t.Fatalf("%d updated rows after a new endpoint, want 2", n)
	}
	resolve(11, ep(""), "aa:bb:cc:00:40:01", "aa:bb:cc:00:40:02")
	resolve(12, ep(""), "aa:bb:cc:00:40:01", "aa:bb:cc:00:40:02")
	if n := count(asset, "updated"); n != 2 {
		t.Errorf("%d updated rows after the same endpoint twice more, want still 2", n)
	}
	resolve(13, ep("TLS"), "aa:bb:cc:00:40:01", "aa:bb:cc:00:40:02")
	if n := count(asset, "updated"); n != 3 {
		t.Errorf("%d updated rows after the endpoint gained a protocol, want 3", n)
	}
	resolve(14, ep(""), "aa:bb:cc:00:40:01", "aa:bb:cc:00:40:02")
	if n := count(asset, "updated"); n != 3 {
		t.Errorf("%d updated rows after a source that does not know the protocol re-saw it, want still 3", n)
	}
	var lastSeen sql.NullTime
	if err := db.QueryRow(`SELECT last_seen_at FROM asset_endpoints WHERE tenant_id=$1 AND asset_id=$2 AND port=443`, tenant, asset).Scan(&lastSeen); err != nil {
		t.Fatal(err)
	}
	if !lastSeen.Valid || !lastSeen.Time.Equal(base.Add(14*time.Hour)) {
		t.Errorf("endpoint last-seen = %v, want %s: the suppressed row must not stop the clock", lastSeen, base.Add(14*time.Hour))
	}

	// 4. A better name is a change.
	resolve(15, func(o *identity.Observation) {
		o.Hostname = "hist-1.example.test"
		o.DisplayName = "hist-1.example.test"
	}, "aa:bb:cc:00:40:01", "aa:bb:cc:00:40:02")
	var withName int
	if err := db.QueryRow(`SELECT count(*) FROM asset_history WHERE tenant_id=$1 AND asset_id=$2 AND action='updated' AND changes_json ? 'hostname'`,
		tenant, asset).Scan(&withName); err != nil || withName != 1 {
		t.Errorf("rows recording a hostname change = %d (err %v), want 1", withName, err)
	}
	if strings.TrimSpace(asset) == "" {
		t.Fatal("no asset")
	}
}
