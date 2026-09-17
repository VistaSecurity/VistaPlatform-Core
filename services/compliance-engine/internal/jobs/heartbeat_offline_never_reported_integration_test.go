package jobs

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The regression tests for the never-reported offline gap.
//
// A sensor or discovery agent that registers and then never sends a heartbeat
// was unalertable: the offline predicate carried `AND last_heartbeat IS NOT
// NULL`, so the row it most needed to return was the one it threw away. The
// console showed the subject 'active' indefinitely — the exact shape of a
// failed install, where the operator runs the installer, registration succeeds,
// and the service then fails to start or is firewalled outbound.
//
// Confirmed on a live 1.0.0 deployment: a tenant held a discovery agent with
// status='active', last_heartbeat NULL and created_at 30+ minutes old — twice
// the dwell — and that tenant had zero alerts of any kind. Three sensors in the
// same tenant, also with NULL heartbeats, HAD been flipped to status='offline'
// by sensor-manager's reaper, which has always used
// COALESCE(last_heartbeat, created_at). The two code paths disagreed; this is
// the alert path adopting the reaper's form.
//
// These need TEST_DATABASE_URL and therefore skip in the PR gate; they run
// nightly and locally via `make test-integration-db`. The predicate and the
// never-reported rendering are also pinned by the plain unit tests in
// heartbeat_offline_scan_job_test.go, which do run on every PR.

// subjectAlert returns the title+message of the one open alert of a type, for
// asserting how a never-reported subject is described.
func (h *jobHarness) subjectAlert(t *testing.T, tenantID uuid.UUID, alertType string) (title, message string) {
	t.Helper()
	if err := h.owner.QueryRow(
		`SELECT title, message FROM alerts
		 WHERE tenant_id = $1 AND alert_type = $2 AND status <> 'resolved'`,
		tenantID, alertType).Scan(&title, &message); err != nil {
		t.Fatalf("read open alert: %v", err)
	}
	return title, message
}

func TestIntegration_SensorOfflineScan_FiresOnSensorThatNeverReported(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)

	// Every negative control below is past the dwell with a NULL heartbeat, so
	// each one is excluded ONLY by its own exclusion — nothing here passes by
	// being too recent.
	//
	// pending: a registration key nothing has claimed yet.
	h.exec(t, `INSERT INTO sensors (tenant_id, name, platform, version, profile, status, created_at)
	           VALUES ($1,'never-pending','linux','1.0','standard','pending', NOW() - INTERVAL '40 minutes')`, tenant)
	// inactive: an operator switched it off.
	h.exec(t, `INSERT INTO sensors (tenant_id, name, platform, version, profile, status, created_at)
	           VALUES ($1,'never-inactive','linux','1.0','standard','inactive', NOW() - INTERVAL '40 minutes')`, tenant)
	// platform-owned: serves all tenants, not a tenant subject.
	h.exec(t, `INSERT INTO sensors (tenant_id, name, platform, version, profile, status, created_at)
	           VALUES ($1,'never-platform','platform','1.0','standard','active', NOW() - INTERVAL '40 minutes')`, tenant)
	// air-gapped: the column's meaning is "not expected to check in at all".
	h.exec(t, `INSERT INTO sensors (tenant_id, name, platform, version, profile, status, air_gapped, created_at)
	           VALUES ($1,'never-airgapped','linux','1.0','standard','active', true, NOW() - INTERVAL '40 minutes')`, tenant)
	// registered 30 seconds ago: inside the dwell, not yet late.
	h.exec(t, `INSERT INTO sensors (tenant_id, name, platform, version, profile, status, created_at)
	           VALUES ($1,'just-registered','linux','1.0','standard','active', NOW() - INTERVAL '30 seconds')`, tenant)

	job := NewSensorOfflineScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)
	job.ScanAll()
	if got := h.alertCount(t, tenant, "sensor_offline"); got != 0 {
		t.Fatalf("an intentionally quiet or freshly registered sensor alarmed: got %d alerts, want 0", got)
	}

	// The subject of the bug: registered, active, never checked in, past dwell.
	h.exec(t, `INSERT INTO sensors (tenant_id, name, platform, version, profile, status, created_at)
	           VALUES ($1,'never-reported','linux','1.0','standard','active', NOW() - INTERVAL '40 minutes')`, tenant)
	job.ScanAll()
	if got := h.alertCount(t, tenant, "sensor_offline"); got != 1 {
		t.Fatalf("sensor that registered and never reported did not raise an alert: got %d, want 1", got)
	}

	title, message := h.subjectAlert(t, tenant, "sensor_offline")
	if !strings.Contains(message, "has never sent a heartbeat") {
		t.Fatalf("never-reported alert does not say the sensor never reported: %q", message)
	}
	for _, bad := range []string{"0001-01-01", "1970-01-01"} {
		if strings.Contains(message, bad) || strings.Contains(title, bad) {
			t.Fatalf("never-reported alert rendered a placeholder timestamp (%q): title=%q message=%q", bad, title, message)
		}
	}
}

func TestIntegration_DiscoveryAgentOfflineScan_FiresOnAgentThatNeverReported(t *testing.T) {
	h := newJobHarness(t)
	tenant := testdb.NewTenant(t, h.owner)

	// Negative controls, both past the dwell with a NULL heartbeat.
	h.exec(t, `INSERT INTO device_agents (tenant_id, registration_key, name, platform, version, status, created_at)
	           VALUES ($1,$2,'never-inactive-agent','linux','1.0','inactive', NOW() - INTERVAL '40 minutes')`,
		tenant, uuid.NewString())
	h.exec(t, `INSERT INTO device_agents (tenant_id, registration_key, name, platform, version, status, created_at)
	           VALUES ($1,$2,'just-registered-agent','linux','1.0','active', NOW() - INTERVAL '30 seconds')`,
		tenant, uuid.NewString())

	job := NewDiscoveryAgentOfflineScanJob(h.app, h.bypass, h.catlg, h.engine, time.Hour)
	job.ScanAll()
	if got := h.alertCount(t, tenant, "discovery_agent_offline"); got != 0 {
		t.Fatalf("an inactive or freshly registered agent alarmed: got %d alerts, want 0", got)
	}

	// That deployment's row, reproduced: AgentService's registration INSERT
	// writes status='active' and leaves last_heartbeat NULL.
	var agentID uuid.UUID
	if err := h.owner.QueryRow(
		`INSERT INTO device_agents (tenant_id, registration_key, name, platform, version, status, created_at)
		 VALUES ($1,$2,'qa-agent.example.com','linux','1.0','active', NOW() - INTERVAL '40 minutes')
		 RETURNING id`, tenant, uuid.NewString()).Scan(&agentID); err != nil {
		t.Fatalf("seed never-reported agent: %v", err)
	}

	job.ScanAll()
	if got := h.alertCount(t, tenant, "discovery_agent_offline"); got != 1 {
		t.Fatalf("agent that registered and never reported did not raise an alert: got %d, want 1", got)
	}
	title, message := h.subjectAlert(t, tenant, "discovery_agent_offline")
	if !strings.Contains(message, "has never sent a heartbeat") || !strings.Contains(title, "never reported") {
		t.Fatalf("never-reported agent alert reads wrong: title=%q message=%q", title, message)
	}

	// And it clears when the agent finally checks in — the first heartbeat has
	// to auto-resolve a never-reported alert exactly like a returning one
	// clears a stale-heartbeat alert, or the operator is left with an alert
	// that outlives the condition.
	h.exec(t, `UPDATE device_agents SET last_heartbeat = NOW() WHERE id = $1`, agentID)
	job.ScanAll()
	if got := h.alertCount(t, tenant, "discovery_agent_offline"); got != 0 {
		t.Fatalf("alert did not auto-resolve after the agent's first heartbeat: got %d open, want 0", got)
	}

	var observed string
	if err := h.owner.QueryRow(
		`SELECT COALESCE(resolution_observation->>'observed', '') FROM alerts
		  WHERE tenant_id = $1 AND alert_type = $2 AND subject_id = $3`,
		tenant, "discovery_agent_offline", agentID).Scan(&observed); err != nil {
		t.Fatalf("read resolve observation: %v", err)
	}
	if observed != "heartbeat resumed" {
		t.Fatalf("resolve observation = %q, want \"heartbeat resumed\"", observed)
	}
}
