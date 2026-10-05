package sensorrouting

// The offline-observer fall-through end to end: real sensors, agent_addresses
// and sensor_discoveries rows read by Store.Resolve as the non-owner app role
// (so RLS applies as in production), then planned by Route. Unit tests pin the
// rule; this pins that the inputs the store reads produce it — liveness from
// last_heartbeat, coverage from agent_addresses, the own-host guard from the
// primary address, air-gapped and system sensors excluded, and the fleet
// scoped to the one tenant.

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type routingFixture struct {
	t     *testing.T
	owner *sql.DB
	now   time.Time
}

// sensor inserts one sensor. heartbeatAge decides liveness: the reporting
// interval is 30s, so seconds are live and an hour is offline.
func (f routingFixture) sensor(tenant uuid.UUID, name string, heartbeatAge time.Duration, primary string, opts ...string) uuid.UUID {
	f.t.Helper()
	id := uuid.New()
	platform, tags, airGapped := "linux", "{}", false
	for _, o := range opts {
		switch o {
		case "system":
			platform, tags = "platform", "{system}"
		case "air-gapped":
			airGapped = true
		}
	}
	if _, err := f.owner.Exec(`INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status, last_heartbeat, reporting_interval, ip_address, tags, air_gapped)
		VALUES ($1, $2, $3, $4, '4.4.0', 'datacenter_host', 'active', $5, 30, NULLIF($6, ''), $7::text[], $8)`,
		id, tenant, name, platform, f.now.Add(-heartbeatAge), primary, tags, airGapped); err != nil {
		f.t.Fatalf("insert sensor %s: %v", name, err)
	}
	return id
}

func (f routingFixture) bound(sensorID uuid.UUID, address string, prefix int) {
	f.t.Helper()
	if _, err := f.owner.Exec(`INSERT INTO agent_addresses (sensor_id, interface_name, address, prefix_length, last_seen_at) VALUES ($1, 'eth0', $2::inet, $3, $4)`,
		sensorID, address, prefix, f.now); err != nil {
		f.t.Fatalf("insert agent address %s: %v", address, err)
	}
}

func (f routingFixture) observed(tenant, sensorID uuid.UUID, destIP string, age time.Duration) {
	f.t.Helper()
	if _, err := f.owner.Exec(`INSERT INTO sensor_discoveries (sensor_id, tenant_id, batch_id, protocol, dest_ip, port, "timestamp", created_at)
		VALUES ($1, $2, $3, 'TLS', $4::inet, 443, $5, $5)`,
		sensorID, tenant, "routing-it-"+uuid.NewString(), destIP, f.now.Add(-age)); err != nil {
		f.t.Fatalf("insert discovery of %s: %v", destIP, err)
	}
}

func TestIntegration_Resolve_OfflineObserverFallsThroughToALiveSegmentSensorNeverThePlatform(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	tenant := testdb.NewTenant(t, owner)
	foreign := testdb.NewTenant(t, owner)
	f := routingFixture{t: t, owner: owner, now: time.Now().UTC().Truncate(time.Microsecond)}

	const live, gone = 20 * time.Second, time.Hour

	// The observer: registered, last heard from an hour ago.
	observer := f.sensor(tenant, "observer-sensor", gone, "198.51.100.10")
	f.bound(observer, "198.51.100.10", 24)
	// A live sensor on the same /24. Its own host is 198.51.100.20 (primary
	// address, no asset link yet), which it must never be handed.
	branch := f.sensor(tenant, "branch-sensor", live, "198.51.100.20")
	f.bound(branch, "198.51.100.20", 24)
	// A sensor covering 192.0.2.0/24 that is itself offline.
	stale := f.sensor(tenant, "stale-sensor", gone, "192.0.2.10")
	f.bound(stale, "192.0.2.10", 24)
	// 203.0.113.0/24 is covered only by sensors that never take a job: one
	// air-gapped, one the platform's own.
	vault := f.sensor(tenant, "vault-sensor", live, "203.0.113.10", "air-gapped")
	f.bound(vault, "203.0.113.10", 24)
	platformOwn := f.sensor(tenant, "Platform Discovery Sensor", live, "203.0.113.11", "system")
	f.bound(platformOwn, "203.0.113.11", 24)
	// A live observer elsewhere: its host stays with it, unchanged.
	edge := f.sensor(tenant, "edge-sensor", live, "10.20.0.10")
	f.bound(edge, "10.20.0.10", 16)
	// ANOTHER tenant's live sensor covering every network above. The fleet
	// the router sees is tenant-scoped, so it must never appear in the plan.
	other := f.sensor(foreign, "aaa-foreign-sensor", live, "192.0.2.99")
	for _, p := range []string{"198.51.100.99", "192.0.2.99", "203.0.113.99"} {
		f.bound(other, p, 24)
	}

	f.observed(tenant, observer, "198.51.100.42", time.Minute) // → branch, same_segment
	f.observed(tenant, observer, "192.0.2.7", time.Minute)     // covered only by an offline sensor → skipped
	f.observed(tenant, observer, "203.0.113.5", time.Minute)   // covered only by air-gapped/system → skipped
	f.observed(tenant, observer, "198.51.100.20", time.Minute) // branch's own host, nobody else live → skipped
	f.observed(tenant, observer, "198.51.100.50", 2*time.Hour) // older sighting by the offline observer…
	f.observed(tenant, edge, "198.51.100.50", time.Minute)     // …the NEWEST observer is live → edge
	f.observed(tenant, observer, "172.16.0.9", time.Minute)    // nobody covers → skipped, never the platform

	store := NewStore(&database.DB{DB: sqlx.NewDb(testdb.ConnectAsAppRole(t, owner), "postgres")})
	targets := []string{"198.51.100.42", "192.0.2.7", "203.0.113.5", "198.51.100.20", "198.51.100.50", "172.16.0.9", "10.9.9.9", "db.internal"}
	plan, err := store.Resolve(context.Background(), tenant, targets, f.now)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	byName := map[string]Group{}
	for _, g := range plan.Groups {
		if g.Sensor.ID == other {
			t.Fatalf("another tenant's sensor was given a job: %+v", g)
		}
		byName[g.Sensor.Name] = g
	}
	if len(plan.Groups) != 2 {
		t.Fatalf("groups = %+v, want branch-sensor and edge-sensor only", plan.Groups)
	}
	if g := byName["branch-sensor"]; strings.Join(g.Targets, ",") != "198.51.100.42" || g.Reasons["198.51.100.42"] != ReasonSegment {
		t.Errorf("branch-sensor = %+v, want 198.51.100.42 by same_segment", g)
	}
	if g := byName["edge-sensor"]; strings.Join(g.Targets, ",") != "198.51.100.50" || g.Reasons["198.51.100.50"] != ReasonObserved {
		t.Errorf("edge-sensor = %+v, want 198.51.100.50 as its live observer", g)
	}

	// Only targets NO tenant sensor observed reach the platform.
	if strings.Join(plan.Platform, ",") != "10.9.9.9,db.internal" {
		t.Errorf("platform = %v, want only the unobserved targets", plan.Platform)
	}

	var skipped []string
	for _, sk := range plan.Skipped {
		if sk.Sensor.ID != observer || sk.Reason != ReasonObserverOffline {
			t.Errorf("skip = %+v, want observing_sensor_offline naming observer-sensor", sk)
		}
		if msg := sk.Message(); !strings.Contains(msg, "observer-sensor is offline") || !strings.Contains(msg, sk.Target) {
			t.Errorf("skip message %q", msg)
		}
		skipped = append(skipped, sk.Target)
	}
	if strings.Join(skipped, ",") != "192.0.2.7,203.0.113.5,198.51.100.20,172.16.0.9" {
		t.Errorf("skipped = %v", skipped)
	}
}
