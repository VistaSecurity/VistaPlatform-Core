package store_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig/store"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The store is tested against a real Postgres because everything that can go
// wrong with it is SQL: the partial unique indexes that make "one override per
// device" true, the RLS policies that make a tenant's settings its own, and the
// jsonb round trip that has to preserve the difference between absent and false.

func newSensor(t *testing.T, db *sql.DB, tenant uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := db.Exec(`INSERT INTO public.sensors (id, tenant_id, name, platform, version, profile, status)
		VALUES ($1, $2, $3, 'linux', '1.0.0', 'datacenter_host', 'active')`, id, tenant, "sensor-"+id.String()[:8])
	if err != nil {
		t.Fatalf("seeding sensor: %v", err)
	}
	return id
}

func newAgent(t *testing.T, db *sql.DB, tenant uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := db.Exec(`INSERT INTO public.device_agents (id, tenant_id, name, version, platform, status, registration_key)
		VALUES ($1, $2, $3, '1.0.0', 'windows', 'active', $4)`, id, tenant, "agent-"+id.String()[:8], uuid.NewString())
	if err != nil {
		t.Fatalf("seeding agent: %v", err)
	}
	return id
}

func TestIntegration_AgentConfigStore_InheritanceAndOverride(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	ctx := context.Background()

	s := store.New(admin)
	agentID := newAgent(t, admin, tenant)
	owner := store.AgentOwner(agentID)

	// Nothing set: everything is a built-in default.
	got, err := s.Load(ctx, tenant, owner)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if v := got.Values[agentconfig.KeyHostInventoryEnabled]; v.B == nil || *v.B {
		t.Errorf("host inventory = %v, want the built-in false", v)
	}
	if got.Status.State != agentconfig.StateNeverReported {
		t.Errorf("state = %s, want never_reported for a device that has not checked in", got.Status.State)
	}

	// Fleet default turns it on for everyone.
	if err := s.SaveDefaults(ctx, tenant, agentconfig.RuntimeAgent,
		agentconfig.Values{agentconfig.KeyHostInventoryEnabled: agentconfig.Bool(true)}, uuid.New()); err != nil {
		t.Fatalf("SaveDefaults: %v", err)
	}
	got, err = s.Load(ctx, tenant, owner)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if v := got.Values[agentconfig.KeyHostInventoryEnabled]; v.B == nil || !*v.B {
		t.Fatalf("host inventory = %v, want the fleet default true", v)
	}

	// The device opts out explicitly. An explicit false must survive the round
	// trip through jsonb and beat the fleet default — if it decays to "unset"
	// anywhere in the stack, this device can never be turned off.
	if err := s.SaveOverride(ctx, tenant, owner,
		agentconfig.Values{agentconfig.KeyHostInventoryEnabled: agentconfig.Bool(false)}, uuid.New()); err != nil {
		t.Fatalf("SaveOverride: %v", err)
	}
	got, err = s.Load(ctx, tenant, owner)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if v := got.Values[agentconfig.KeyHostInventoryEnabled]; v.B == nil || *v.B {
		t.Errorf("host inventory = %v, want the device's explicit false to win", v)
	}
	for _, r := range got.Resolved {
		if r.Key == agentconfig.KeyHostInventoryEnabled && r.Origin != agentconfig.OriginDevice {
			t.Errorf("origin = %s, want device — the console cannot offer 'revert to fleet default' without it", r.Origin)
		}
	}
}

func TestIntegration_AgentConfigStore_ReportDrivesState(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	ctx := context.Background()

	s := store.New(admin)
	owner := store.SensorOwner(newSensor(t, admin, tenant))

	if err := s.SaveOverride(ctx, tenant, owner,
		agentconfig.Values{agentconfig.KeyDedupTTLMinutes: agentconfig.Int(15)}, uuid.New()); err != nil {
		t.Fatalf("SaveOverride: %v", err)
	}
	want, err := s.Load(ctx, tenant, owner)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if want.Status.State != agentconfig.StateNeverReported {
		t.Fatalf("state = %s, want never_reported", want.Status.State)
	}

	// The device reports an older revision: pending, not applied.
	if err := s.RecordReport(ctx, tenant, owner, agentconfig.Report{Revision: "stale", At: time.Now()}); err != nil {
		t.Fatalf("RecordReport: %v", err)
	}
	got, err := s.Load(ctx, tenant, owner)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Status.State != agentconfig.StatePending {
		t.Errorf("state = %s, want pending", got.Status.State)
	}

	// Now it reports the real one.
	if err := s.RecordReport(ctx, tenant, owner, agentconfig.Report{Revision: want.Revision, At: time.Now()}); err != nil {
		t.Fatalf("RecordReport: %v", err)
	}
	got, err = s.Load(ctx, tenant, owner)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Status.State != agentconfig.StateApplied {
		t.Errorf("state = %s, want applied", got.Status.State)
	}

	// A failure on a matching revision is a failure, and the device's own
	// reason must reach the console.
	if err := s.RecordReport(ctx, tenant, owner, agentconfig.Report{
		Revision: want.Revision, At: time.Now(),
		Failures: map[agentconfig.Key]string{agentconfig.KeyDedupTTLMinutes: "rejected by the capture engine"},
	}); err != nil {
		t.Fatalf("RecordReport: %v", err)
	}
	got, err = s.Load(ctx, tenant, owner)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Status.State != agentconfig.StateFailed {
		t.Fatalf("state = %s, want failed", got.Status.State)
	}
	if got.Status.Failures[agentconfig.KeyDedupTTLMinutes] != "rejected by the capture engine" {
		t.Errorf("the device's reason was lost: %v", got.Status.Failures)
	}
}

// One override row per device, enforced by the partial unique index — not by
// the store remembering to check.
func TestIntegration_AgentConfigStore_OverrideIsUpsertedNotDuplicated(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	ctx := context.Background()

	s := store.New(admin)
	sensorID := newSensor(t, admin, tenant)
	owner := store.SensorOwner(sensorID)

	for _, ttl := range []int64{5, 10, 20} {
		if err := s.SaveOverride(ctx, tenant, owner,
			agentconfig.Values{agentconfig.KeyDedupTTLMinutes: agentconfig.Int(ttl)}, uuid.New()); err != nil {
			t.Fatalf("SaveOverride(%d): %v", ttl, err)
		}
	}
	var rows int
	if err := admin.QueryRow(`SELECT count(*) FROM public.agent_config_overrides WHERE sensor_id = $1`, sensorID).Scan(&rows); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if rows != 1 {
		t.Errorf("override rows = %d, want 1", rows)
	}
	got, err := s.Load(ctx, tenant, owner)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if v := got.Values[agentconfig.KeyDedupTTLMinutes]; v.I == nil || *v.I != 20 {
		t.Errorf("dedup ttl = %v, want the last write", v)
	}
}

// Every change is audited, and a no-op save is not. The audit trail is the
// condition on which host-observation DNS became remotely settable at all.
func TestIntegration_AgentConfigStore_AuditsRealChangesOnly(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	ctx := context.Background()

	s := store.New(admin)
	owner := store.SensorOwner(newSensor(t, admin, tenant))
	actor := uuid.New()

	dns := agentconfig.Values{agentconfig.KeyHostObservationDNS: agentconfig.Bool(true)}
	if err := s.SaveOverride(ctx, tenant, owner, dns, actor); err != nil {
		t.Fatalf("SaveOverride: %v", err)
	}
	// Same values again: nothing changed, so nothing is recorded.
	if err := s.SaveOverride(ctx, tenant, owner, dns, actor); err != nil {
		t.Fatalf("SaveOverride (repeat): %v", err)
	}

	var (
		count int
		who   uuid.UUID
		after []byte
	)
	if err := admin.QueryRow(`SELECT count(*) FROM public.agent_config_audit WHERE tenant_id = $1`, tenant).Scan(&count); err != nil {
		t.Fatalf("counting audit: %v", err)
	}
	if count != 1 {
		t.Fatalf("audit rows = %d, want 1 — a save that changed nothing must not be recorded", count)
	}
	if err := admin.QueryRow(`SELECT changed_by, values_after FROM public.agent_config_audit WHERE tenant_id = $1`, tenant).
		Scan(&who, &after); err != nil {
		t.Fatalf("reading audit: %v", err)
	}
	if who != actor {
		t.Errorf("changed_by = %s, want the acting user %s", who, actor)
	}
	if string(after) == "" || string(after) == "{}" {
		t.Errorf("values_after = %q, want the new settings", after)
	}
}

// RLS: one tenant's settings are invisible to another, through the app role the
// services actually connect as. Reading this with the owner role would prove
// nothing, since the owner bypasses policies.
func TestIntegration_AgentConfigStore_TenantIsolation(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenantA := testdb.NewTenant(t, admin)
	tenantB := testdb.NewTenant(t, admin)
	ctx := context.Background()

	app := testdb.ConnectAsAppRole(t, admin)
	s := store.New(app)

	ownerA := store.SensorOwner(newSensor(t, admin, tenantA))
	if err := s.SaveOverride(ctx, tenantA, ownerA,
		agentconfig.Values{agentconfig.KeyDedupTTLMinutes: agentconfig.Int(5)}, uuid.New()); err != nil {
		t.Fatalf("SaveOverride as tenant A: %v", err)
	}

	// Tenant B asking about tenant A's sensor sees no override, so it resolves
	// to defaults rather than to A's values.
	got, err := s.Load(ctx, tenantB, ownerA)
	if err != nil {
		t.Fatalf("Load as tenant B: %v", err)
	}
	if v := got.Values[agentconfig.KeyDedupTTLMinutes]; v.I == nil || *v.I == 5 {
		t.Errorf("tenant B read tenant A's override: %v", v)
	}

	// And cannot write one.
	if err := s.SaveOverride(ctx, tenantB, ownerA,
		agentconfig.Values{agentconfig.KeyDedupTTLMinutes: agentconfig.Int(99)}, uuid.New()); err == nil {
		t.Error("tenant B wrote an override onto tenant A's sensor")
	}
}

// A restart request has to survive the round trip and reach the device, and it
// must NOT disturb the desired revision — a restart is not a setting, and
// folding it into the content hash would leave every device that was ever
// restarted permanently disagreeing with its own configuration.
func TestIntegration_AgentConfigStore_RestartRequest(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	ctx := context.Background()

	s := store.New(admin)
	owner := store.AgentOwner(newAgent(t, admin, tenant))
	actor := uuid.New()

	before, err := s.Load(ctx, tenant, owner)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !before.Restart.At.IsZero() {
		t.Errorf("a device nobody asked to restart carries a request: %v", before.Restart.At)
	}

	at, err := s.RequestRestart(ctx, tenant, owner, actor)
	if err != nil {
		t.Fatalf("RequestRestart: %v", err)
	}

	after, err := s.Load(ctx, tenant, owner)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if after.Restart.At.IsZero() {
		t.Fatal("the request did not survive the round trip")
	}
	if after.Restart.At.Sub(at).Abs() > time.Second {
		t.Errorf("stored %v, returned %v — the console would report the wrong time", after.Restart.At, at)
	}
	if after.Revision != before.Revision {
		t.Errorf("the desired revision changed from %q to %q; a restart is not a setting and must not move it",
			before.Revision, after.Revision)
	}

	// It works on a device with no settings of its own — a fleet member that
	// inherits everything still has to be restartable.
	var overrides int
	if err := admin.QueryRow(`SELECT count(*) FROM public.agent_config_overrides WHERE device_agent_id = $1`,
		owner.AgentID).Scan(&overrides); err != nil {
		t.Fatalf("counting overrides: %v", err)
	}
	if overrides != 1 {
		t.Errorf("override rows = %d, want the request upserted exactly one", overrides)
	}

	// And it is audited: a restart is an action on somebody's host.
	var by uuid.UUID
	if err := admin.QueryRow(`SELECT changed_by FROM public.agent_config_audit
		WHERE tenant_id = $1 AND device_agent_id = $2 ORDER BY changed_at DESC LIMIT 1`,
		tenant, owner.AgentID).Scan(&by); err != nil {
		t.Fatalf("reading the audit trail: %v", err)
	}
	if by != actor {
		t.Errorf("audit changed_by = %s, want the acting user %s", by, actor)
	}
}

// The history an operator reads: this device's own changes AND the fleet
// defaults that move it, with the values, under RLS.
//
// The audit table was write-only until LoadHistory existed. This is the test
// that would have failed if the rows were being written somewhere nobody could
// scope a read to — which is the interesting way a write-only table stays
// write-only after you give it a reader.
func TestIntegration_AgentConfigStore_HistoryIsReadableAndScoped(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenantA := testdb.NewTenant(t, admin)
	tenantB := testdb.NewTenant(t, admin)
	ctx := context.Background()

	s := store.New(admin)
	owner := store.SensorOwner(newSensor(t, admin, tenantA))
	other := store.SensorOwner(newSensor(t, admin, tenantA))
	actor := uuid.New()

	// A fleet default, a change to this device, and a change to a DIFFERENT
	// device of the same tenant — which must not appear.
	if err := s.SaveDefaults(ctx, tenantA, agentconfig.RuntimeSensor,
		agentconfig.Values{agentconfig.KeyActiveProbing: agentconfig.Bool(true)}, actor); err != nil {
		t.Fatalf("SaveDefaults: %v", err)
	}
	if err := s.SaveOverride(ctx, tenantA, owner,
		agentconfig.Values{agentconfig.KeyHostObservationDNS: agentconfig.Bool(true)}, actor); err != nil {
		t.Fatalf("SaveOverride: %v", err)
	}
	if err := s.SaveOverride(ctx, tenantA, other,
		agentconfig.Values{agentconfig.KeyNetworkDiscovery: agentconfig.Bool(true)}, actor); err != nil {
		t.Fatalf("SaveOverride (other device): %v", err)
	}

	changes, err := s.LoadHistory(ctx, tenantA, owner, 50)
	if err != nil {
		t.Fatalf("LoadHistory: %v", err)
	}
	if len(changes) != 2 {
		t.Fatalf("history has %d entries, want 2 — this device's change plus the fleet default that moves it", len(changes))
	}
	// Newest first.
	if changes[0].At.Before(changes[1].At) {
		t.Errorf("history is not newest-first: %v then %v", changes[0].At, changes[1].At)
	}

	var sawDevice, sawFleet bool
	for _, c := range changes {
		if c.By != actor {
			t.Errorf("changed_by = %s, want the acting user %s — a confirmation nobody can attribute is not a record", c.By, actor)
		}
		switch c.Scope {
		case "device":
			sawDevice = true
			// The value, not merely the fact: "DNS decoding was turned ON" is
			// the sentence the owner's confirmation obligation is about.
			if got := c.After[agentconfig.KeyHostObservationDNS]; !got.Equal(agentconfig.Bool(true)) {
				t.Errorf("device change after-value = %v, want DNS on", got)
			}
			if keys := c.Changed(); len(keys) != 1 || keys[0] != agentconfig.KeyHostObservationDNS {
				t.Errorf("Changed() = %v, want exactly the DNS key", keys)
			}
		case "fleet":
			sawFleet = true
		default:
			t.Errorf("unexpected scope %q", c.Scope)
		}
		if _, ok := c.After[agentconfig.KeyNetworkDiscovery]; ok {
			t.Error("another device's change leaked into this device's history")
		}
	}
	if !sawDevice || !sawFleet {
		t.Errorf("device change seen = %v, fleet default seen = %v; both must appear", sawDevice, sawFleet)
	}

	// Another tenant reads nothing, through the app role where RLS is real.
	app := testdb.ConnectAsAppRole(t, admin)
	if got, err := store.New(app).LoadHistory(ctx, tenantB, owner, 50); err != nil {
		t.Fatalf("LoadHistory (other tenant): %v", err)
	} else if len(got) != 0 {
		t.Errorf("another tenant read %d history entries, want 0", len(got))
	}
}

// RLS on agent_config_audit, tested where it is actually observable.
//
// HistoryIsReadableAndScoped cannot see RLS at all: LoadHistory carries its own
// `WHERE tenant_id = $1` and withTenant sets app.tenant_id to that same
// parameter, so the predicate and the policy can never disagree and dropping
// the policy changes nothing. Review of pointed that out — the test is
// not inert (removing the predicate fails it), but it proves the predicate, not
// the policy.
//
// The policy is the backstop for the day somebody writes a query here that
// forgets the predicate. So this asserts it the only way that can fail: a read
// with NO tenant predicate at all, through the app role, with app.tenant_id set
// to the other tenant.
func TestIntegration_AgentConfigStore_AuditRowsAreRLSProtected(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenantA := testdb.NewTenant(t, admin)
	tenantB := testdb.NewTenant(t, admin)
	ctx := context.Background()

	owner := store.SensorOwner(newSensor(t, admin, tenantA))
	if err := store.New(admin).SaveOverride(ctx, tenantA, owner,
		agentconfig.Values{agentconfig.KeyHostObservationDNS: agentconfig.Bool(true)}, uuid.New()); err != nil {
		t.Fatalf("SaveOverride: %v", err)
	}

	app := testdb.ConnectAsAppRole(t, admin)
	count := func(tenant uuid.UUID) int {
		t.Helper()
		tx, err := app.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.ExecContext(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenant.String()); err != nil {
			t.Fatalf("set tenant: %v", err)
		}
		var n int
		// Deliberately unfiltered: the POLICY is the only thing that can scope
		// this. A tenant_id predicate here would make the test pass with RLS
		// disabled, which is exactly the shape being corrected.
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.agent_config_audit`).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}

	if n := count(tenantA); n != 1 {
		t.Errorf("the owning tenant sees %d audit rows, want 1 — the policy must not hide a tenant's own history", n)
	}
	if n := count(tenantB); n != 0 {
		t.Errorf("another tenant sees %d audit rows, want 0 — configuration history names who changed what on somebody's fleet", n)
	}
}
