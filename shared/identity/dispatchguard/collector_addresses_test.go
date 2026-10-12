package dispatchguard

import (
	"context"
	"net/netip"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestCollectorAddressesWithoutSensorsReadsNothing(t *testing.T) {
	// A nil queryer would panic if the helper queried for an empty id list.
	got, err := CollectorAddresses(context.Background(), nil)
	if err != nil || got != nil {
		t.Fatalf("got=%v err=%v, want nil, nil", got, err)
	}
}

// Every address row counts: no interface-name or freshness filter, a deleted
// sensor and another tenant's sensor do not.
func TestIntegration_CollectorAddresses_EveryRowOfTheNamedSensors(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant, other := testdb.NewTenant(t, db), testdb.NewTenant(t, db)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	sensor := func(tenant uuid.UUID, deleted bool, rows ...[2]string) uuid.UUID {
		id := uuid.New()
		exec(`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status) VALUES($1,$2,$3,'linux','1.0','datacenter_host','active')`, id, tenant, "s-"+id.String()[:8])
		if deleted {
			exec(`UPDATE sensors SET deleted_at=now() WHERE id=$1`, id)
		}
		for _, r := range rows {
			exec(`INSERT INTO agent_addresses(sensor_id,interface_name,address,prefix_length,last_seen_at) VALUES($1,$2,$3,24,now()-interval '3 days')`, id, r[0], r[1])
		}
		return id
	}
	a := sensor(tenant, false, [2]string{"eth0", "192.0.2.4"}, [2]string{"docker0", "172.17.0.1"})
	sensor(tenant, false, [2]string{"Ethernet", "192.0.2.5"})
	sensor(tenant, true, [2]string{"eth0", "192.0.2.6"})
	sensor(other, false, [2]string{"eth0", "192.0.2.7"})

	has := func(got []netip.Prefix, want ...string) {
		t.Helper()
		set := map[string]bool{}
		for _, p := range got {
			set[p.String()] = true
		}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for _, w := range want {
			if !set[w+"/32"] {
				t.Fatalf("got %v, want %v", got, want)
			}
		}
	}
	got, err := CollectorAddresses(context.Background(), db, a)
	if err != nil {
		t.Fatal(err)
	}
	has(got, "192.0.2.4", "172.17.0.1")
	got, err = TenantCollectorAddresses(context.Background(), db, tenant)
	if err != nil {
		t.Fatal(err)
	}
	has(got, "192.0.2.4", "172.17.0.1", "192.0.2.5")
}
