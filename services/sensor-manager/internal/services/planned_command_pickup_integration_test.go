package services

// A PLANNED automatic scan or identity probe ( WP2) is re-authorized when
// the sensor collects it, exactly as a legacy one is: the addresses and ports
// in its plan pass the same tenant, evidence, sensitivity, exclusion and
// reachability checks, and a command that cannot be authorized stays pending.
// Driven through the real GetPendingCommands (authorizeCommandPickup).

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

const plannedPickupPolicy = `{"discovery_auto_scan":{"enabled":true,"protocols":["TLS"],"ports":[443,8443]},"identity_admission":{"mode":"enforce"},"identity_enrichment":{"enabled":true}}`

// newPlannedPickupFixture is the identity pickup fixture moved to
// 10.188.0.0/24, with an automatic-scan policy allowing 443 and 8443 only and
// an eligible tenant asset at 10.188.0.20.
func newPlannedPickupFixture(t *testing.T) (*identityPickupFixture, uuid.UUID) {
	t.Helper()
	f := newIdentityPickupFixture(t)
	f.exec(t, `UPDATE agent_addresses SET address='10.188.0.4' WHERE sensor_id=$1`, f.sensor)
	f.exec(t, `UPDATE network_segments SET value='10.188.0.0/24' WHERE id=$1`, f.segment)
	f.exec(t, `UPDATE tenant_admin_settings SET config=$2::jsonb WHERE tenant_id=$1`, f.tenant, plannedPickupPolicy)
	asset := uuid.New()
	f.exec(t, `INSERT INTO assets(id,tenant_id,hostname,primary_address,class_key,class_path,asset_status) VALUES($1,$2,'planned','10.188.0.20','server','hardware.computer.server','monitoring')`, asset, f.tenant)
	return f, asset
}

type plannedCommand struct {
	identity bool
	target   string
	depth    shareddisc.ScanDepth
	tcp, udp string
	ot       []string
}

func (f *identityPickupFixture) queuePlanned(t *testing.T, c plannedCommand) uuid.UUID {
	t.Helper()
	options := map[string]interface{}{"origin": "auto_scan"}
	if c.identity {
		options = map[string]interface{}{"identity_enrichment_request_id": uuid.NewString(), "identity_observation_id": f.observation.String(), "identity_network_scope": f.segment.String()}
	}
	if c.target == "" {
		c.target = "10.188.0.20"
	}
	if c.depth == "" {
		c.depth = shareddisc.DepthCustom
	}
	if c.tcp == "" && c.udp == "" {
		c.tcp = "443"
	}
	payload := sensordispatch.Payload{JobID: uuid.NewString(), TenantID: f.tenant.String(), Options: options, Plan: &sensordispatch.PlanPayload{
		Version: sensordispatch.PlanPayloadVersion, Attempt: 1, Pace: shareddisc.PaceNormal, OTProbeProtocols: c.ot,
		Targets: []sensordispatch.PlanTargetWork{{TargetID: uuid.NewString(), PlanTarget: shareddisc.PlanTarget{Target: c.target, Depth: c.depth, TCPPorts: c.tcp, UDPPorts: c.udp}}},
	}}
	raw, err := json.Marshal(payload.ToMap())
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	f.exec(t, `INSERT INTO sensor_commands(id,sensor_id,command_type,payload,expires_at) VALUES($1,$2,$3,$4,now()+interval '5 minutes')`, id, f.sensor, sensordispatch.CommandType, string(raw))
	return id
}

func TestIntegration_PlannedCommandPickup_AuthorizedPlanIsDelivered(t *testing.T) {
	for _, identity := range []bool{false, true} {
		name := map[bool]string{false: "automatic", true: "identity"}[identity]
		t.Run(name, func(t *testing.T) {
			f, _ := newPlannedPickupFixture(t)
			if !identity {
				f.svc.enrichmentAvailable = false // the older scanner does not depend on the identity rollout
			}
			id := f.queuePlanned(t, plannedCommand{identity: identity})
			got, err := f.svc.GetPendingCommands(f.sensor.String())
			if err != nil || len(got) != 1 || got[0].ID != id {
				t.Fatalf("authorized planned %s pickup = %+v err = %v, want the command", name, got, err)
			}
		})
	}
}

func TestIntegration_PlannedCommandPickup_RefusedPlanStaysPending(t *testing.T) {
	cases := []struct {
		name    string
		command plannedCommand
		mutate  func(*testing.T, *identityPickupFixture, uuid.UUID)
	}{
		{name: "excluded", mutate: func(t *testing.T, f *identityPickupFixture, _ uuid.UUID) {
			f.exec(t, `UPDATE tenant_admin_settings SET config=jsonb_set(config,'{identity_enrichment,excluded_cidrs}','["10.188.0.20/32"]') WHERE tenant_id=$1`, f.tenant)
		}},
		{name: "paused", mutate: func(t *testing.T, f *identityPickupFixture, _ uuid.UUID) {
			f.exec(t, `UPDATE tenant_admin_settings SET config=jsonb_set(config,'{discovery_auto_scan,enabled}','false') WHERE tenant_id=$1`, f.tenant)
		}},
		{name: "segment sensitive", mutate: func(t *testing.T, f *identityPickupFixture, _ uuid.UUID) {
			f.exec(t, `UPDATE network_segments SET metadata='{"sensitive":true}' WHERE id=$1`, f.segment)
		}},
		{name: "port withdrawn from the policy", mutate: func(t *testing.T, f *identityPickupFixture, _ uuid.UUID) {
			f.exec(t, `UPDATE tenant_admin_settings SET config=jsonb_set(config,'{discovery_auto_scan,ports}','[8443]') WHERE tenant_id=$1`, f.tenant)
		}},
		{name: "port never in the policy", command: plannedCommand{tcp: "22"}},
		{name: "UDP port", command: plannedCommand{tcp: "443", udp: "161"}},
		{name: "UDP only", command: plannedCommand{udp: "161"}},
		{name: "standard depth", command: plannedCommand{depth: shareddisc.DepthStandard}},
		{name: "OT opt-in", command: plannedCommand{ot: []string{"Modbus"}}},
		{name: "range target", command: plannedCommand{target: "10.188.0.16/29"}},
	}
	for _, identity := range []bool{false, true} {
		for _, tc := range cases {
			name := map[bool]string{false: "automatic/", true: "identity/"}[identity] + tc.name
			t.Run(name, func(t *testing.T) {
				f, asset := newPlannedPickupFixture(t)
				if !identity {
					f.svc.enrichmentAvailable = false
				}
				c := tc.command
				c.identity = identity
				id := f.queuePlanned(t, c)
				if tc.mutate != nil {
					tc.mutate(t, f, asset)
				}
				got, err := f.svc.GetPendingCommands(f.sensor.String())
				if err != nil || len(got) != 0 {
					t.Fatalf("refused planned pickup = %+v err = %v, want nothing delivered", got, err)
				}
				f.pending(t, id)
			})
		}
	}
	// Automatic only: a sensitive asset, and an address with no tenant asset.
	t.Run("automatic/sensitive asset", func(t *testing.T) {
		f, asset := newPlannedPickupFixture(t)
		f.svc.enrichmentAvailable = false
		id := f.queuePlanned(t, plannedCommand{})
		f.exec(t, `UPDATE tenant_admin_settings SET config=jsonb_set(config,'{identity_enrichment,sensitive_asset_ids}',jsonb_build_array($2::text)) WHERE tenant_id=$1`, f.tenant, asset)
		if got, err := f.svc.GetPendingCommands(f.sensor.String()); err != nil || len(got) != 0 {
			t.Fatalf("pickup = %+v err = %v", got, err)
		}
		f.pending(t, id)
	})
	t.Run("automatic/no eligible asset", func(t *testing.T) {
		f, _ := newPlannedPickupFixture(t)
		f.svc.enrichmentAvailable = false
		id := f.queuePlanned(t, plannedCommand{target: "10.188.0.99"})
		if got, err := f.svc.GetPendingCommands(f.sensor.String()); err != nil || len(got) != 0 {
			t.Fatalf("pickup = %+v err = %v", got, err)
		}
		f.pending(t, id)
	})
	// Identity only: the collector's own address.
	t.Run("identity/collector address", func(t *testing.T) {
		f, _ := newPlannedPickupFixture(t)
		id := f.queuePlanned(t, plannedCommand{identity: true, target: "10.188.0.4"})
		if got, err := f.svc.GetPendingCommands(f.sensor.String()); err != nil || len(got) != 0 {
			t.Fatalf("pickup = %+v err = %v", got, err)
		}
		f.pending(t, id)
	})
}
