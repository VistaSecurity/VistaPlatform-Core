package dispatchguard

// The identity-enrichment guard authorizes the OBSERVER (where the evidence
// came from) and the EXECUTOR (the collector the work is dispatched to)
// separately, for both of its entry points — AuthorizeProbe and AuthorizeDNS —
// inside a tenant-scoped app-role transaction, as the services call it.
//
// Skips without TEST_DATABASE_URL (make test-integration-db).

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_IdentityGuard_ObserverAndExecutorAuthorizedSeparately(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	testdb.EnsureRLSAppRole(t, db)
	tenant := testdb.NewTenant(t, db)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"discovery_auto_scan":{"enabled":true,"protocols":["TLS"],"ports":[443]},"identity_admission":{"mode":"enforce"},"identity_enrichment":{"enabled":true}}')`, tenant)
	segment := uuid.New()
	exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment) VALUES($1,$2,'target','cidr','10.190.0.0/24','production')`, segment, tenant)
	collector := func(tenant uuid.UUID, address string) uuid.UUID {
		t.Helper()
		id := uuid.New()
		exec(`INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status, reporting_interval, last_heartbeat, reported_dns_interfaces, reported_capabilities)
			VALUES ($1,$2,$3,'linux','1.0.0','datacenter_host','active',30,now(),ARRAY['eth0'],ARRAY[$4])`, id, tenant, "c-"+id.String()[:8], sensordispatch.IdentityDNSCapability)
		exec(`INSERT INTO agent_addresses(sensor_id,interface_name,address,prefix_length) VALUES($1,'eth0',$2,24)`, id, address)
		return id
	}
	observer := collector(tenant, "10.191.0.4") // another network
	executor := collector(tenant, "10.190.0.4") // the target network
	foreign := collector(testdb.NewTenant(t, db), "10.191.0.5")

	observation := func(observer uuid.UUID) uuid.UUID {
		t.Helper()
		id := uuid.New()
		evidence, err := json.Marshal(identity.Observation{TenantID: tenant.String(),
			Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:" + observer.String()},
			Network:     identity.Network{SegmentID: segment.String()},
			Identifiers: []identity.Identifier{{Kind: identity.KindHostname, Value: "printer.local", Scope: segment.String()}},
		})
		if err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO identity_observations(id,tenant_id,fingerprint,source_kind,source_ref,evidence,first_seen_at,last_seen_at) VALUES($1::uuid,$2,$1::text,'measured',$3,$4,now(),now())`,
			id, tenant, "sensor:"+observer.String(), string(evidence))
		return id
	}
	probe := func(obs, sensor uuid.UUID) (err error) {
		testdb.AsTenant(t, db, tenant, func(tx *sql.Tx) {
			err = AuthorizeProbe(tx, sensordispatch.Payload{TenantID: tenant.String(), Targets: []string{"10.190.0.20"}, Protocols: []string{"TLS"}, Ports: []int{443},
				Options: map[string]interface{}{"identity_enrichment_request_id": uuid.NewString(), "identity_observation_id": obs.String(), "identity_network_scope": segment.String()}}, sensor)
		})
		return err
	}
	dns := func(obs, sensor uuid.UUID) (err error) {
		testdb.AsTenant(t, db, tenant, func(tx *sql.Tx) {
			err = AuthorizeDNS(tx, tenant, sensor, sensordispatch.IdentityDNSRequest{RequestID: uuid.NewString(), ObservationID: obs.String(), NetworkScope: segment.String(),
				SegmentCIDR: "10.190.0.0/24", Hostname: "printer.local", TimeoutMS: 2000, MaxAddresses: 8})
		})
		return err
	}

	crossNetwork, ownNetwork, foreignObserver := observation(observer), observation(executor), observation(foreign)
	for name, check := range map[string]func(obs, sensor uuid.UUID) error{"probe": probe, "dns": dns} {
		t.Run(name, func(t *testing.T) {
			if err := check(ownNetwork, executor); err != nil {
				t.Errorf("observer == executor: %v, want authorized", err)
			}
			if err := check(crossNetwork, executor); err != nil {
				t.Errorf("observer on another network, executor on the target network: %v, want authorized", err)
			}
			if err := check(crossNetwork, observer); !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), "no longer reachable") {
				t.Errorf("executor with no interface on the target network: %v, want refused as unreachable", err)
			}
			if err := check(foreignObserver, executor); !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), "not a collector of this tenant") {
				t.Errorf("observer of another tenant: %v, want refused", err)
			}
		})
	}
}
