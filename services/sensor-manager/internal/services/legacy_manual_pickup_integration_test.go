package services

// A person's protocols x ports scan is re-authorized when its sensor collects
// it (authorizeLegacyManualPickup), against the tenant's scope as it is then:
// a command that waited, or a retry, must not scan a range the tenant has since
// excluded. Driven through the real GetPendingCommands.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

func (f *identityPickupFixture) queueManualLegacy(t *testing.T, targets ...string) (job, command uuid.UUID) {
	t.Helper()
	job, command = uuid.New(), uuid.New()
	f.exec(t, `INSERT INTO discovery_jobs(id,tenant_id,execution_mode,status,assigned_sensor_id) VALUES($1,$2,'sensors','awaiting_sensor',$3)`, job, f.tenant, f.sensor)
	for _, target := range targets {
		f.exec(t, `INSERT INTO discovery_targets(job_id,tenant_id,input,protocols,ports,status) VALUES($1,$2,$3,'{TLS}','{443}','pending')`, job, f.tenant, target)
	}
	raw, err := json.Marshal(sensordispatch.Payload{JobID: job.String(), TenantID: f.tenant.String(), Targets: targets, Protocols: []string{"TLS"}, Ports: []int{443}}.ToMap())
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `INSERT INTO sensor_commands(id,sensor_id,command_type,payload,expires_at) VALUES($1,$2,$3,$4,now()+interval '5 minutes')`, command, f.sensor, sensordispatch.CommandType, string(raw))
	return job, command
}

func (f *identityPickupFixture) excludeRanges(t *testing.T, cidrs ...string) {
	t.Helper()
	quoted := `"` + strings.Join(cidrs, `","`) + `"`
	f.exec(t, `UPDATE tenant_admin_settings SET config=$2::jsonb WHERE tenant_id=$1`, f.tenant, `{"identity_enrichment":{"excluded_cidrs":[`+quoted+`]}}`)
}

// Mutation: make authorizeCommandPickup return true for a manual legacy payload
// again (the old `return true, nil`) and the last two subtests go red.
func TestIntegration_LegacyManualPickup_ReauthorizesAtCollection(t *testing.T) {
	t.Run("authorized targets are delivered untouched", func(t *testing.T) {
		f := newIdentityPickupFixture(t)
		_, cmd := f.queueManualLegacy(t, "10.40.0.5", "10.40.0.6")
		got, err := f.svc.GetPendingCommands(f.sensor.String())
		if err != nil || len(got) != 1 || got[0].ID != cmd {
			t.Fatalf("pickup = %v, err %v, want the command", got, err)
		}
		if targets, _ := got[0].Payload["targets"].([]interface{}); len(targets) != 2 {
			t.Fatalf("targets = %v, want both", got[0].Payload["targets"])
		}
	})

	t.Run("a target excluded since creation is dropped and named", func(t *testing.T) {
		f := newIdentityPickupFixture(t)
		job, cmd := f.queueManualLegacy(t, "10.40.0.5", "10.40.0.6")
		f.excludeRanges(t, "10.40.0.6/32")
		got, err := f.svc.GetPendingCommands(f.sensor.String())
		if err != nil || len(got) != 1 || got[0].ID != cmd {
			t.Fatalf("pickup = %v, err %v, want the command", got, err)
		}
		var stored string
		f.scan(t, `SELECT payload->>'targets' FROM sensor_commands WHERE id=$1`, []any{cmd}, &stored)
		if !strings.Contains(stored, "10.40.0.5") || strings.Contains(stored, "10.40.0.6") {
			t.Fatalf("stored targets = %s, want only the authorized one", stored)
		}
		if delivered, _ := got[0].Payload["targets"].([]string); len(delivered) != 1 || delivered[0] != "10.40.0.5" {
			t.Fatalf("delivered targets = %#v", got[0].Payload["targets"])
		}
		var note, target string
		f.scan(t, `SELECT COALESCE(metadata->>'note','') FROM discovery_jobs WHERE id=$1`, []any{job}, &note)
		f.scan(t, `SELECT status FROM discovery_targets WHERE job_id=$1 AND input='10.40.0.6'`, []any{job}, &target)
		if !strings.Contains(note, "10.40.0.6") || target != "failed" {
			t.Fatalf("note %q, dropped target row %q: the dropped target is not visible on the job", note, target)
		}
	})

	t.Run("no authorized target left: the command is failed, never delivered", func(t *testing.T) {
		f := newIdentityPickupFixture(t)
		_, cmd := f.queueManualLegacy(t, "10.40.0.5", "10.40.0.6")
		f.excludeRanges(t, "10.40.0.0/24")
		got, err := f.svc.GetPendingCommands(f.sensor.String())
		if err != nil || len(got) != 0 {
			t.Fatalf("pickup = %v, err %v, want nothing delivered", got, err)
		}
		var state, reason string
		f.scan(t, `SELECT status, COALESCE(error_message,'') FROM sensor_commands WHERE id=$1`, []any{cmd}, &state, &reason)
		if state != "failed" || !strings.Contains(reason, "no target is still authorized") {
			t.Fatalf("command = %s / %q, want failed with the reason", state, reason)
		}
	})
}

func (f *identityPickupFixture) scan(t *testing.T, query string, args []any, dest ...any) {
	t.Helper()
	if err := f.db.QueryRow(query, args...).Scan(dest...); err != nil {
		t.Fatal(err)
	}
}
