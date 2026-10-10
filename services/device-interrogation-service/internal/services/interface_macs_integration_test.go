package services

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// An interrogated gateway reports a MAC per interface; the real ingest must
// leave the asset owning each, and none of the skipped ones.
func TestIntegration_InterfaceMACs_InterrogationAttachesEveryInterfaceMAC(t *testing.T) {
	f := newGatewayFixture(t)
	err := NewObservationSink(f.db).Persist(context.Background(), f.tenant, f.gateway, interrogationSource(uuid.New()), InterrogationObservations{
		ObservedAt: time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC),
		Facts: []di.FactObservation{{Key: facts.KeyNetInterfaces, Confidence: 1, Value: []map[string]any{
			{"name": "eth0", "mac": gwMAC},
			{"name": "eth1", "mac": "00:00:5e:00:53:ab"},
			{"name": "eth2", "mac": "00:00:5e:00:53:ac"},
			{"name": "laa", "mac": "02:00:5e:00:53:ad"},
			{"name": "zero", "mac": "00:00:00:00:00:00"},
		}}},
	})
	if err != nil {
		t.Fatalf("Persist: %v", err)
	}
	rows, err := f.db.Query(`SELECT value FROM asset_identifiers WHERE tenant_id=$1 AND asset_id=$2 AND kind::text=$3`,
		f.tenant, f.gateway, string(identity.KindMACAddress))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	got := map[string]bool{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		got[v] = true
	}
	for _, want := range []string{gwMAC, "00:00:5e:00:53:ab", "00:00:5e:00:53:ac"} {
		if !got[want] {
			t.Errorf("the gateway does not own interface MAC %s: %v", want, got)
		}
	}
	for _, skip := range []string{"02:00:5e:00:53:ad", "00:00:00:00:00:00"} {
		if got[skip] {
			t.Errorf("the gateway owns skipped MAC %s", skip)
		}
	}
}

// Interrogating the same device again must not grow the retained identity
// observations: a sighting is sent only for an interface MAC new to the asset.
// The source ref of a sighting is the job, so each run's sighting of an owned
// MAC is a new fingerprint and, under enforced admission, a new retained row
// that never expires.
func TestIntegration_InterfaceMACs_RepeatedInterrogationDoesNotGrowObservations(t *testing.T) {
	f := newGatewayFixture(t)
	ctx := context.Background()
	if _, err := f.db.Exec(`INSERT INTO tenant_entitlements(tenant_id,item_id,override_value,reason)
		SELECT $1,id,'{"quantity":500}'::jsonb,'interface MAC growth test' FROM billable_items WHERE key='max_assets'`, f.tenant); err != nil {
		t.Fatalf("asset allowance: %v", err)
	}
	if _, err := f.db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"}}')
		ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, f.tenant); err != nil {
		t.Fatalf("enforce admission: %v", err)
	}

	const macB, macC, macD = "00:00:5e:00:53:ab", "00:00:5e:00:53:ac", "00:00:5e:00:53:ae"
	run := func(day int, macs ...string) {
		t.Helper()
		ifaces := []map[string]any{{"name": "eth0", "mac": gwMAC}}
		for i, m := range macs {
			ifaces = append(ifaces, map[string]any{"name": fmt.Sprintf("eth%d", i+1), "mac": m})
		}
		err := NewObservationSink(f.db).Persist(ctx, f.tenant, f.gateway, interrogationSource(uuid.New()), InterrogationObservations{
			ObservedAt: time.Date(2026, 10, day, 9, 0, 0, 0, time.UTC),
			Facts:      []di.FactObservation{{Key: facts.KeyNetInterfaces, Confidence: 1, Value: ifaces}},
		})
		if err != nil {
			t.Fatalf("Persist (day %d): %v", day, err)
		}
	}
	owned := func() map[string]bool {
		t.Helper()
		rows, err := f.db.Query(`SELECT value FROM asset_identifiers WHERE tenant_id=$1 AND asset_id=$2 AND kind::text=$3`,
			f.tenant, f.gateway, string(identity.KindMACAddress))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		got := map[string]bool{}
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				t.Fatal(err)
			}
			got[v] = true
		}
		return got
	}
	observations := func() int {
		t.Helper()
		var n int
		if err := f.db.QueryRow(`SELECT count(*) FROM identity_observations WHERE tenant_id=$1 AND asset_id=$2`, f.tenant, f.gateway).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	run(3, macB, macC)
	got := owned()
	for _, want := range []string{gwMAC, macB, macC} {
		if !got[want] {
			t.Errorf("after run 1 the gateway does not own %s: %v", want, got)
		}
	}
	afterFirst := observations()

	run(4, macB, macC)
	if n := observations(); n != afterFirst {
		t.Errorf("identity_observations for the gateway grew from %d to %d on an identical second run", afterFirst, n)
	}

	run(5, macB, macC, macD)
	got = owned()
	if !got[macD] || len(got) != 4 {
		t.Errorf("after run 3 the gateway should own exactly its four MACs, owns %v", got)
	}
	if n := observations(); n > afterFirst+1 {
		t.Errorf("a run with one new interface MAC added %d observations (%d -> %d), want at most 1", n-afterFirst, afterFirst, n)
	}
}

// The serial an interrogation reads is sighted the same way: once it is the
// device's, re-reading it each run adds no retained observation.
func TestIntegration_SelfSerial_RepeatedInterrogationDoesNotGrowObservations(t *testing.T) {
	f := newGatewayFixture(t)
	ctx := context.Background()
	if _, err := f.db.Exec(`INSERT INTO tenant_entitlements(tenant_id,item_id,override_value,reason)
		SELECT $1,id,'{"quantity":500}'::jsonb,'self serial growth test' FROM billable_items WHERE key='max_assets'`, f.tenant); err != nil {
		t.Fatalf("asset allowance: %v", err)
	}
	if _, err := f.db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"}}')
		ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, f.tenant); err != nil {
		t.Fatalf("enforce admission: %v", err)
	}
	run := func(day int, serial string) {
		t.Helper()
		err := NewObservationSink(f.db).Persist(ctx, f.tenant, f.gateway, interrogationSource(uuid.New()), InterrogationObservations{
			ObservedAt:     time.Date(2026, 10, day, 9, 0, 0, 0, time.UTC),
			DeviceIdentity: &di.DeviceIdentity{SerialNumber: serial},
		})
		if err != nil {
			t.Fatalf("Persist (day %d): %v", day, err)
		}
	}
	observations := func() int {
		t.Helper()
		var n int
		if err := f.db.QueryRow(`SELECT count(*) FROM identity_observations WHERE tenant_id=$1 AND asset_id=$2`, f.tenant, f.gateway).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	run(3, gwSerial)
	first := observations()
	run(4, gwSerial)
	run(5, gwSerial)
	if n := observations(); n != first {
		t.Errorf("identity_observations grew from %d to %d re-reading a serial the device already holds", first, n)
	}
}
