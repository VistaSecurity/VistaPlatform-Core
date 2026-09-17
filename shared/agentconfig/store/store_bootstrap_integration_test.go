package store_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig/store"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Bootstrapping a device's own starting position, against a real Postgres
// because everything that can go wrong with it is SQL: the one-row-per-device
// partial index the upsert lands on, the jsonb round trip that has to keep an
// explicit true distinct from an absent key, and the audit row that has to say
// nobody made this change.
//
// The regression: an agent running with host inventory turned on in its file
// was answered on its first heartbeat with the built-in default (off), applied
// it, and stopped collecting for good.

func TestIntegration_AgentConfigBootstrap_FirstReportBecomesTheDeviceOverride(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	ctx := context.Background()

	s := store.New(admin)
	agentID := newAgent(t, admin, tenant)
	owner := store.AgentOwner(agentID)

	running := agentconfig.Values{
		agentconfig.KeyHostInventoryEnabled:  agentconfig.Bool(true),
		agentconfig.KeyHostInventoryInterval: agentconfig.Int(21600),
	}

	seeded, err := s.BootstrapFromReport(ctx, tenant, owner, running)
	if err != nil {
		t.Fatalf("BootstrapFromReport: %v", err)
	}
	if len(seeded) != 2 {
		t.Fatalf("seeded = %v, want the two values the agent reported", seeded)
	}

	got, err := s.Load(ctx, tenant, owner)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if v := got.Values[agentconfig.KeyHostInventoryEnabled]; v.B == nil || !*v.B {
		t.Errorf("host inventory = %v, want the agent's own true — "+
			"this is the bug: the first heartbeat answered with the built-in default and switched it off", v)
	}
	if v := got.Values[agentconfig.KeyHostInventoryInterval]; v.I == nil || *v.I != 21600 {
		t.Errorf("host inventory interval = %v, want the agent's own 21600", v)
	}
	for _, r := range got.Resolved {
		if r.Key == agentconfig.KeyHostInventoryEnabled && r.Origin != agentconfig.OriginDevice {
			t.Errorf("origin = %s, want device: an operator has to see the real starting position", r.Origin)
		}
	}

	// The revision the device is handed describes what it is ALREADY running,
	// so it converges without changing anything.
	if want := agentconfig.Revision(agentconfig.RuntimeAgent,
		agentconfig.Effective(agentconfig.RuntimeAgent, nil, running)); got.Revision != want {
		t.Errorf("revision = %s, want %s — the answer must describe what the agent is already doing", got.Revision, want)
	}

	// Audited, and attributed to nobody: the device was already like this.
	var (
		scope sql.NullString
		who   sql.NullString
	)
	if err := admin.QueryRow(`SELECT scope, changed_by::text FROM public.agent_config_audit
		 WHERE tenant_id = $1 AND device_agent_id = $2`, tenant, agentID).Scan(&scope, &who); err != nil {
		t.Fatalf("reading the audit row: %v — a bootstrap must leave a trail", err)
	}
	if scope.String != "bootstrap" {
		t.Errorf("audit scope = %q, want bootstrap", scope.String)
	}
	if who.Valid {
		t.Errorf("changed_by = %q, want NULL: nobody made this change", who.String)
	}
}

// One report is the whole window. After the device has checked in, what it
// reports is a measurement, not a request — and an operator's later decision,
// including clearing an override back to "inherit", must survive every
// subsequent beat.
func TestIntegration_AgentConfigBootstrap_DoesNotOverwriteALaterOperatorChange(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	ctx := context.Background()

	s := store.New(admin)
	agentID := newAgent(t, admin, tenant)
	owner := store.AgentOwner(agentID)
	operator := uuid.New()

	running := agentconfig.Values{agentconfig.KeyHostInventoryEnabled: agentconfig.Bool(true)}
	if _, err := s.BootstrapFromReport(ctx, tenant, owner, running); err != nil {
		t.Fatalf("BootstrapFromReport: %v", err)
	}
	if err := s.RecordReport(ctx, tenant, owner, agentconfig.Report{Revision: "rev-1"}); err != nil {
		t.Fatalf("RecordReport: %v", err)
	}

	// The operator turns it off.
	if err := s.SaveOverride(ctx, tenant, owner,
		agentconfig.Values{agentconfig.KeyHostInventoryEnabled: agentconfig.Bool(false)}, operator); err != nil {
		t.Fatalf("SaveOverride: %v", err)
	}

	// The agent beats again, still reporting that it is running. It has not
	// applied the change yet — that is what the next answer is for.
	if _, err := s.BootstrapFromReport(ctx, tenant, owner, running); err != nil {
		t.Fatalf("BootstrapFromReport (second): %v", err)
	}

	got, err := s.Load(ctx, tenant, owner)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if v := got.Values[agentconfig.KeyHostInventoryEnabled]; v.B == nil || *v.B {
		t.Fatalf("host inventory = %v, want the operator's false — "+
			"a device's report reinstated a setting an operator had turned off", v)
	}

	// And clearing the override back to "inherit" is not undone on the next
	// beat either: the device already had its one chance.
	if err := s.SaveOverride(ctx, tenant, owner, agentconfig.Values{}, operator); err != nil {
		t.Fatalf("SaveOverride (clear): %v", err)
	}
	if _, err := s.BootstrapFromReport(ctx, tenant, owner, running); err != nil {
		t.Fatalf("BootstrapFromReport (third): %v", err)
	}
	got, err = s.Load(ctx, tenant, owner)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, r := range got.Resolved {
		if r.Key == agentconfig.KeyHostInventoryEnabled && r.Origin != agentconfig.OriginBuiltIn {
			t.Errorf("origin = %s after the override was cleared, want built_in — "+
				"the device's local value was reinstated behind the operator's back", r.Origin)
		}
	}
}

// An older device reports no running values. Reading that silence as "running
// nothing" would write an override it never described.
func TestIntegration_AgentConfigBootstrap_AnOlderDeviceSeedsNothing(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	ctx := context.Background()

	s := store.New(admin)
	agentID := newAgent(t, admin, tenant)
	owner := store.AgentOwner(agentID)

	seeded, err := s.BootstrapFromReport(ctx, tenant, owner, nil)
	if err != nil {
		t.Fatalf("BootstrapFromReport: %v", err)
	}
	if len(seeded) != 0 {
		t.Errorf("seeded %v from a device that reported nothing", seeded)
	}

	var rows int
	if err := admin.QueryRow(`SELECT count(*) FROM public.agent_config_overrides WHERE device_agent_id = $1`, agentID).Scan(&rows); err != nil {
		t.Fatalf("counting overrides: %v", err)
	}
	if rows != 0 {
		t.Errorf("override rows = %d, want 0 for a device that reported nothing", rows)
	}
	if err := admin.QueryRow(`SELECT count(*) FROM public.agent_config_audit WHERE device_agent_id = $1`, agentID).Scan(&rows); err != nil {
		t.Fatalf("counting audit rows: %v", err)
	}
	if rows != 0 {
		t.Errorf("audit rows = %d, want 0", rows)
	}
}

// A sensor reaches the same code by the same route — one store, one rule. If
// the two runtimes ever diverge here, one of them starts undoing local
// configuration again.
func TestIntegration_AgentConfigBootstrap_CoversSensorsToo(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	ctx := context.Background()

	s := store.New(admin)
	owner := store.SensorOwner(newSensor(t, admin, tenant))

	running := agentconfig.Values{
		agentconfig.KeyActiveProbing:   agentconfig.Bool(false),
		agentconfig.KeyDedupTTLMinutes: agentconfig.Int(15),
	}
	if _, err := s.BootstrapFromReport(ctx, tenant, owner, running); err != nil {
		t.Fatalf("BootstrapFromReport: %v", err)
	}

	got, err := s.Load(ctx, tenant, owner)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// An explicit false has to survive the jsonb round trip as false, not decay
	// into "unset" and resolve back to the built-in true.
	if v := got.Values[agentconfig.KeyActiveProbing]; v.B == nil || *v.B {
		t.Errorf("active_probing = %v, want the sensor's own false", v)
	}
	if v := got.Values[agentconfig.KeyDedupTTLMinutes]; v.I == nil || *v.I != 15 {
		t.Errorf("dedup_ttl_minutes = %v, want the sensor's own 15", v)
	}
}
