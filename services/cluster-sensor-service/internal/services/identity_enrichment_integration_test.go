package services

import (
	"encoding/json"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
)

func TestIntegration_IdentityEnrichmentDiscoveryRequestIsIdempotent(t *testing.T) {
	f := newDispatchFixture(t)
	now := time.Now()
	sensor := f.insertSensor(t, "enrichment", "active", &now, nil, "linux")
	req := models.CreateDiscoveryJobRequest{Targets: []string{"192.0.2.10"}, Protocols: []string{"TLS"}, Ports: []int{443}, ExecutionMode: "sensors", PreferredSensorIDs: []string{sensor.String()}, Options: map[string]interface{}{"identity_enrichment_request_id": uuid.NewString()}}
	prepareEnrichmentDispatch(t, f, sensor, &req)
	const parallel = 6
	jobs := make(chan string, parallel)
	errs := make(chan error, parallel)
	var wg sync.WaitGroup
	for range parallel {
		wg.Add(1)
		go func() {
			defer wg.Done()
			j, err := f.svc.CreateJob(f.tenant.String(), "system", req)
			if j != nil {
				jobs <- j.ID
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(jobs)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var id string
	for got := range jobs {
		if id != "" && id != got {
			t.Fatal("replay created a second probe job")
		}
		id = got
	}
	var count int
	if err := f.raw.QueryRow(`SELECT count(*) FROM discovery_targets WHERE tenant_id=$1 AND job_id=$2`, f.tenant, id).Scan(&count); err != nil || count != 1 {
		t.Fatalf("targets=%d %v", count, err)
	}
	if _, err := f.raw.Exec(`UPDATE sensors SET status='offline' WHERE id=$1`, sensor); err != nil {
		t.Fatal(err)
	}
	replay, err := f.svc.CreateJob(f.tenant.String(), "system", req)
	if err != nil || replay.ID != id {
		t.Fatalf("offline replay lost committed job: %+v %v", replay, err)
	}
	req.Targets = []string{"192.0.2.11"}
	if _, err := f.svc.CreateJob(f.tenant.String(), "system", req); err == nil {
		t.Fatal("same request ID accepted changed probe targets")
	}
}

func prepareEnrichmentDispatch(t *testing.T, f *dispatchFixture, sensor uuid.UUID, req *models.CreateDiscoveryJobRequest) {
	t.Helper()
	observation, segment := uuid.New(), uuid.New()
	req.Targets = []string{"192.168.80.20"}
	req.Options["identity_observation_id"] = observation.String()
	req.Options["identity_network_scope"] = segment.String()
	if _, err := f.raw.Exec(`UPDATE sensors SET reported_dns_interfaces=ARRAY['eth0'] WHERE id=$1`, sensor); err != nil {
		t.Fatal(err)
	}
	if _, err := f.raw.Exec(`INSERT INTO agent_addresses(sensor_id,interface_name,address,prefix_length) VALUES($1,'eth0','192.168.80.4',24)`, sensor); err != nil {
		t.Fatal(err)
	}
	evidence, _ := json.Marshal(identity.Observation{TenantID: f.tenant.String(), Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:" + sensor.String()}, Network: identity.Network{SegmentID: segment.String()}})
	if _, err := f.raw.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"},"identity_enrichment":{"enabled":true}}') ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, f.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.raw.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment) VALUES($1,$2,'probe network','cidr','192.168.80.0/24','production')`, segment, f.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.raw.Exec(`INSERT INTO identity_observations(id,tenant_id,fingerprint,source_kind,source_ref,evidence,first_seen_at,last_seen_at) VALUES($1::uuid,$2,$1::text,'measured',$3,$4,now(),now())`, observation, f.tenant, "sensor:"+sensor.String(), string(evidence)); err != nil {
		t.Fatal(err)
	}
}

func TestIntegration_IdentityEnrichmentDispatchRechecksPauseAndExclusions(t *testing.T) {
	for _, mode := range []string{"pause", "exclude"} {
		t.Run(mode, func(t *testing.T) {
			f := newDispatchFixture(t)
			now := time.Now()
			sensor := f.insertSensor(t, "enrichment", "active", &now, nil, "linux")
			req := models.CreateDiscoveryJobRequest{Protocols: []string{"TLS"}, Ports: []int{443}, ExecutionMode: "sensors", PreferredSensorIDs: []string{sensor.String()}, Options: map[string]interface{}{"identity_enrichment_request_id": uuid.NewString()}}
			prepareEnrichmentDispatch(t, f, sensor, &req)
			job, err := f.svc.CreateJob(f.tenant.String(), "system", req)
			if err != nil {
				t.Fatal(err)
			}
			mutation := `jsonb_set(config,'{identity_enrichment,enabled}','false')`
			if mode == "exclude" {
				mutation = `jsonb_set(config,'{identity_enrichment,excluded_cidrs}','["192.168.80.20/32"]')`
			}
			if _, err := f.raw.Exec(`UPDATE tenant_admin_settings SET config=`+mutation+` WHERE tenant_id=$1`, f.tenant); err != nil {
				t.Fatal(err)
			}
			if err := f.jp.dispatchToSensor(job); err != nil {
				t.Fatal(err)
			}
			var count int
			if err := f.raw.QueryRow(`SELECT count(*) FROM sensor_commands WHERE sensor_id=$1`, sensor).Scan(&count); err != nil || count != 0 {
				t.Fatalf("unauthorized command count %d %v", count, err)
			}
			req.Options["identity_enrichment_request_id"] = uuid.NewString()
			if _, err := f.svc.CreateJob(f.tenant.String(), "system", req); err == nil {
				t.Fatal("new unauthorized job accepted")
			}
			if mode == "pause" {
				var status string
				if err := f.raw.QueryRow(`SELECT status FROM discovery_jobs WHERE id=$1`, job.ID).Scan(&status); err != nil || status != "queued" {
					t.Fatalf("paused work lost %s %v", status, err)
				}
				if _, err := f.raw.Exec(`UPDATE tenant_admin_settings SET config=jsonb_set(config,'{identity_enrichment,enabled}','true') WHERE tenant_id=$1`, f.tenant); err != nil {
					t.Fatal(err)
				}
				if err := f.jp.dispatchToSensor(job); err != nil {
					t.Fatal(err)
				}
				if err := f.raw.QueryRow(`SELECT count(*) FROM sensor_commands WHERE sensor_id=$1`, sensor).Scan(&count); err != nil || count != 1 {
					t.Fatalf("resume commands %d %v", count, err)
				}
			}
		})
	}
}
