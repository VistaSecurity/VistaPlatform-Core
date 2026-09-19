package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/database"
	pgrepo "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_IdentityDNSQueueScopeReplayAndCapabilities(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	other := testdb.NewTenant(t, db)
	sensor, segment, observation := uuid.New(), uuid.New(), uuid.New()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status,last_heartbeat,network_interfaces,reported_capabilities,reported_dns_interfaces) VALUES($1,$2,'DNS sensor','linux','test','datacenter_host','active',now(),ARRAY['pcap-interface'],ARRAY['identity_dns_v1'],ARRAY['eth0'])`, []any{sensor, tenant}},
		{`INSERT INTO agent_addresses(sensor_id,interface_name,address) VALUES($1,'eth0','192.0.2.4')`, []any{sensor}},
		{`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment) VALUES($1,$2,'Scoped DNS','cidr','192.0.2.0/24','production')`, []any{segment, tenant}},
		{`INSERT INTO identity_observations(id,tenant_id,fingerprint,source_kind,source_ref,evidence,first_seen_at,last_seen_at) VALUES($1::uuid,$2,$1::text,'measured','test','{}',now(),now())`, []any{observation, tenant}},
	} {
		if _, err := db.Exec(q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	req := sensordispatch.IdentityDNSRequest{RequestID: uuid.NewString(), ObservationID: observation.String(), NetworkScope: segment.String(), Hostname: "host.local", SegmentCIDR: "192.0.2.0/24", TimeoutMS: 2000, MaxAddresses: 8}
	ctx := context.Background()
	var command uuid.UUID
	enqueue := func(owner uuid.UUID, request sensordispatch.IdentityDNSRequest) error {
		return database.WithTenantTx(ctx, db, owner, func(tx *sql.Tx) error {
			var err error
			command, err = pgrepo.EnqueueIdentityDNS(ctx, tx, owner, sensor, request)
			return err
		})
	}
	if err := enqueue(tenant, req); err != nil {
		t.Fatal(err)
	}
	first := command
	if err := enqueue(tenant, req); err != nil || command != first {
		t.Fatalf("replay command=%s err=%v", command, err)
	}
	changed := req
	changed.Hostname = "different.local"
	if err := enqueue(tenant, changed); !errors.Is(err, pgrepo.ErrIdentityDNSReplay) {
		t.Fatalf("mismatched replay=%v", err)
	}
	if err := enqueue(other, req); !errors.Is(err, pgrepo.ErrIdentityDNSUnavailable) {
		t.Fatalf("cross-tenant enqueue=%v", err)
	}
	result := sensordispatch.IdentityDNSResult{RequestID: req.RequestID, ObservationID: req.ObservationID, Hostname: req.Hostname, NetworkScope: req.NetworkScope, Addresses: []string{"192.0.2.8"}, CollectorVersion: "test"}
	if _, err := db.Exec(`UPDATE sensor_commands SET status='completed',response_data=jsonb_build_object('request_id',$2::text,'observation_id',$3::text,'hostname',$4::text,'network_scope',$5::text,'addresses',jsonb_build_array('192.0.2.8'),'collector_version','test','observed_at',now()) WHERE id=$1`, first, result.RequestID, result.ObservationID, result.Hostname, result.NetworkScope); err != nil {
		t.Fatal(err)
	}
	if err := database.WithTenantTx(ctx, db, tenant, func(tx *sql.Tx) error {
		status, got, err := pgrepo.PollIdentityDNS(ctx, tx, tenant, sensor, first)
		if err != nil {
			return err
		}
		if status != "completed" || got == nil || len(got.Addresses) != 1 {
			t.Fatalf("poll=%s %+v", status, got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.WithTenantTx(ctx, db, other, func(tx *sql.Tx) error { _, _, err := pgrepo.PollIdentityDNS(ctx, tx, other, sensor, first); return err }); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("cross-tenant poll=%v", err)
	}
	if _, err := db.Exec(`UPDATE sensors SET reported_capabilities='{}' WHERE id=$1`, sensor); err != nil {
		t.Fatal(err)
	}
	req.RequestID = uuid.NewString()
	if err := enqueue(tenant, req); !errors.Is(err, pgrepo.ErrIdentityDNSUnavailable) {
		t.Fatalf("outdated sensor enqueue=%v", err)
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM sensor_commands WHERE sensor_id=$1`, sensor).Scan(&count); err != nil || count != 1 {
		t.Fatalf("command count=%d err=%v", count, err)
	}
}
