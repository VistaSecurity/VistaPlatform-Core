package services

import (
	"database/sql"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type identityPickupFixture struct {
	db                                   *sql.DB
	svc                                  *SensorService
	tenant, sensor, segment, observation uuid.UUID
}

func newIdentityPickupFixture(t *testing.T) *identityPickupFixture {
	t.Helper()
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	sensor := insertAddrTestSensor(t, db, tenant, "identity-pickup")
	f := &identityPickupFixture{db: db, tenant: tenant, sensor: sensor, segment: uuid.New(), observation: uuid.New()}
	app := testdb.ConnectAsAppRole(t, db)
	app.SetMaxOpenConns(1)
	f.svc = NewSensorService(app, db)
	f.svc.enrichmentAvailable = true
	f.exec(t, `UPDATE sensors SET status='active',last_heartbeat=now(),reported_capabilities=ARRAY['identity_dns_v1'],reported_dns_interfaces=ARRAY['eth0'] WHERE id=$1`, sensor)
	f.exec(t, `INSERT INTO agent_addresses(sensor_id,interface_name,address,prefix_length) VALUES($1,'eth0','192.168.80.4',24)`, sensor)
	f.exec(t, `INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"},"identity_enrichment":{"enabled":true}}') ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant)
	f.exec(t, `INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment) VALUES($1,$2,'test network','cidr','192.168.80.0/24','production')`, f.segment, tenant)
	e, _ := json.Marshal(identity.Observation{TenantID: tenant.String(), Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:" + sensor.String()}, Network: identity.Network{SegmentID: f.segment.String()}, Identifiers: []identity.Identifier{{Kind: identity.KindHostname, Value: "host.local", Scope: f.segment.String()}}})
	f.exec(t, `INSERT INTO identity_observations(id,tenant_id,fingerprint,source_kind,source_ref,evidence,first_seen_at,last_seen_at) VALUES($1::uuid,$2,$1::text,'measured',$3,$4,now(),now())`, f.observation, tenant, "sensor:"+sensor.String(), string(e))
	return f
}
func (f *identityPickupFixture) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := f.db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}
func (f *identityPickupFixture) queue(t *testing.T, kind string) uuid.UUID {
	t.Helper()
	var payload any
	switch kind {
	case sensordispatch.IdentityDNSCommand:
		payload = sensordispatch.IdentityDNSRequest{RequestID: uuid.NewString(), ObservationID: f.observation.String(), NetworkScope: f.segment.String(), SegmentCIDR: "192.168.80.0/24", Hostname: "host.local", TimeoutMS: 2000, MaxAddresses: 8}
	case sensordispatch.CommandType:
		payload = sensordispatch.Payload{JobID: uuid.NewString(), TenantID: f.tenant.String(), Targets: []string{"192.168.80.20"}, Protocols: []string{"TLS"}, Ports: []int{443}, Options: map[string]interface{}{"identity_enrichment_request_id": uuid.NewString(), "identity_observation_id": f.observation.String(), "identity_network_scope": f.segment.String()}}
	default:
		payload = map[string]interface{}{}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	f.exec(t, `INSERT INTO sensor_commands(id,sensor_id,command_type,payload,expires_at) VALUES($1,$2,$3,$4,now()+interval '5 minutes')`, id, f.sensor, kind, string(raw))
	return id
}
func (f *identityPickupFixture) pending(t *testing.T, id uuid.UUID) {
	t.Helper()
	var state string
	if err := f.db.QueryRow(`SELECT status FROM sensor_commands WHERE id=$1`, id).Scan(&state); err != nil || state != "pending" {
		t.Fatalf("command=%s state=%s err=%v", id, state, err)
	}
}

func TestIntegration_IdentityCommandPickupPauseResumeAndConcurrency(t *testing.T) {
	f := newIdentityPickupFixture(t)
	dns, probe := f.queue(t, sensordispatch.IdentityDNSCommand), f.queue(t, sensordispatch.CommandType)
	f.exec(t, `UPDATE tenant_admin_settings SET config=jsonb_set(config,'{identity_enrichment,enabled}','false') WHERE tenant_id=$1`, f.tenant)
	// Paused automation cannot prevent ordinary administrative commands being delivered.
	manual := f.queue(t, "status")
	got, err := f.svc.GetPendingCommands(f.sensor.String())
	if err != nil || len(got) != 1 || got[0].ID != manual {
		t.Fatalf("paused pickup=%v err=%v", got, err)
	}
	f.pending(t, dns)
	f.pending(t, probe)
	f.exec(t, `UPDATE tenant_admin_settings SET config=jsonb_set(config,'{identity_enrichment,enabled}','true') WHERE tenant_id=$1`, f.tenant)
	var wg sync.WaitGroup
	results := make(chan []uuid.UUID, 4)
	errors := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			commands, e := f.svc.GetPendingCommands(f.sensor.String())
			errors <- e
			ids := []uuid.UUID{}
			for _, c := range commands {
				ids = append(ids, c.ID)
			}
			results <- ids
		}()
	}
	wg.Wait()
	close(results)
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	seen := map[uuid.UUID]int{}
	for ids := range results {
		for _, id := range ids {
			seen[id]++
		}
	}
	if len(seen) != 2 || seen[dns] != 1 || seen[probe] != 1 {
		t.Fatalf("claim counts=%v", seen)
	}
	// A delayed legacy mark call must not overwrite an acknowledgement.
	f.exec(t, `UPDATE sensor_commands SET status='completed' WHERE id=$1`, dns)
	if err := f.svc.MarkCommandsAsDelivered(f.sensor.String(), []string{dns.String()}); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := f.db.QueryRow(`SELECT status FROM sensor_commands WHERE id=$1`, dns).Scan(&state); err != nil || state != "completed" {
		t.Fatalf("ack overwritten=%s %v", state, err)
	}
}

func TestIntegration_IdentityCommandPickupRechecksAuthorization(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, *identityPickupFixture, uuid.UUID, string)
	}{
		{"release_gate", func(t *testing.T, f *identityPickupFixture, id uuid.UUID, kind string) {
			f.svc.enrichmentAvailable = false
		}},
		{"admission_paused", func(t *testing.T, f *identityPickupFixture, id uuid.UUID, kind string) {
			f.exec(t, `UPDATE tenant_admin_settings SET config=jsonb_set(config,'{identity_admission,mode}','"retain"') WHERE tenant_id=$1`, f.tenant)
		}},
		{"automatic_scan_paused", func(t *testing.T, f *identityPickupFixture, id uuid.UUID, kind string) {
			f.exec(t, `UPDATE tenant_admin_settings SET config=config||'{"discovery_auto_scan":{"enabled":false}}' WHERE tenant_id=$1`, f.tenant)
		}},
		{"expired", func(t *testing.T, f *identityPickupFixture, id uuid.UUID, kind string) {
			f.exec(t, `UPDATE sensor_commands SET expires_at=now()-interval '1 second' WHERE id=$1`, id)
		}},
		{"no_expiry", func(t *testing.T, f *identityPickupFixture, id uuid.UUID, kind string) {
			f.exec(t, `UPDATE sensor_commands SET expires_at=NULL WHERE id=$1`, id)
		}},
		{"excluded_scope", func(t *testing.T, f *identityPickupFixture, id uuid.UUID, kind string) {
			f.exec(t, `UPDATE tenant_admin_settings SET config=jsonb_set(config,'{identity_enrichment,excluded_cidrs}','["192.168.80.0/24"]') WHERE tenant_id=$1`, f.tenant)
		}},
		{"sensitive_segment", func(t *testing.T, f *identityPickupFixture, id uuid.UUID, kind string) {
			f.exec(t, `UPDATE network_segments SET metadata='{"sensitive":true}' WHERE id=$1`, f.segment)
		}},
		{"overlapping_segment", func(t *testing.T, f *identityPickupFixture, id uuid.UUID, kind string) {
			f.exec(t, `INSERT INTO network_segments(tenant_id,name,segment_type,value,environment) VALUES($1,'overlap','cidr','192.168.80.0/25','production')`, f.tenant)
		}},
		{"scope_changed", func(t *testing.T, f *identityPickupFixture, id uuid.UUID, kind string) {
			f.exec(t, `UPDATE network_segments SET value='192.168.81.0/24' WHERE id=$1`, f.segment)
		}},
		{"sensor_unreachable", func(t *testing.T, f *identityPickupFixture, id uuid.UUID, kind string) {
			f.exec(t, `DELETE FROM agent_addresses WHERE sensor_id=$1`, f.sensor)
		}},
		{"sensor_airgapped", func(t *testing.T, f *identityPickupFixture, id uuid.UUID, kind string) {
			f.exec(t, `UPDATE sensors SET air_gapped=true WHERE id=$1`, f.sensor)
		}},
		{"dismissed", func(t *testing.T, f *identityPickupFixture, id uuid.UUID, kind string) {
			f.exec(t, `UPDATE identity_observations SET state='dismissed' WHERE id=$1`, f.observation)
		}},
		{"stale_evidence", func(t *testing.T, f *identityPickupFixture, id uuid.UUID, kind string) {
			f.exec(t, `UPDATE identity_observations SET first_seen_at=now()-interval '32 days',last_seen_at=now()-interval '31 days' WHERE id=$1`, f.observation)
		}},
		{"cross_tenant_observation", func(t *testing.T, f *identityPickupFixture, id uuid.UUID, kind string) {
			f.exec(t, `UPDATE identity_observations SET tenant_id=$2 WHERE id=$1`, f.observation, testdb.NewTenant(t, f.db))
		}},
		{"dns_capability_or_probe_protocol_revoked", func(t *testing.T, f *identityPickupFixture, id uuid.UUID, kind string) {
			if kind == sensordispatch.IdentityDNSCommand {
				f.exec(t, `UPDATE sensors SET reported_capabilities=ARRAY[]::text[] WHERE id=$1`, f.sensor)
			} else {
				f.exec(t, `UPDATE tenant_admin_settings SET config=config||'{"discovery_auto_scan":{"protocols":["SSH"],"ports":[22]}}' WHERE tenant_id=$1`, f.tenant)
			}
		}},
		{"dns_name_or_probe_tenant_changed", func(t *testing.T, f *identityPickupFixture, id uuid.UUID, kind string) {
			if kind == sensordispatch.IdentityDNSCommand {
				f.exec(t, `UPDATE sensor_commands SET payload=jsonb_set(payload,'{hostname}','"other.local"') WHERE id=$1`, id)
			} else {
				f.exec(t, `UPDATE sensor_commands SET payload=jsonb_set(payload,'{tenant_id}',to_jsonb($2::text)) WHERE id=$1`, id, uuid.NewString())
			}
		}},
	}
	for _, kind := range []string{sensordispatch.IdentityDNSCommand, sensordispatch.CommandType} {
		for _, tc := range cases {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				f := newIdentityPickupFixture(t)
				id := f.queue(t, kind)
				tc.mutate(t, f, id, kind)
				got, err := f.svc.GetPendingCommands(f.sensor.String())
				if err != nil || len(got) != 0 {
					t.Fatalf("unauthorized pickup=%v err=%v", got, err)
				}
				f.pending(t, id)
			})
		}
	}
}

func TestIntegration_IdentityCommandPickupExpiresWhilePolicyLocked(t *testing.T) {
	f := newIdentityPickupFixture(t)
	id := f.queue(t, sensordispatch.IdentityDNSCommand)
	tx, err := f.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`UPDATE tenant_admin_settings SET updated_at=now() WHERE tenant_id=$1`, f.tenant); err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE sensor_commands SET expires_at=clock_timestamp()+interval '150 milliseconds' WHERE id=$1`, id)
	done := make(chan error, 1)
	go func() {
		commands, e := f.svc.GetPendingCommands(f.sensor.String())
		if e == nil && len(commands) != 0 {
			e = sql.ErrNoRows
		}
		done <- e
	}()
	time.Sleep(250 * time.Millisecond)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pickup did not resume")
	}
	f.pending(t, id)
}
