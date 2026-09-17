package jobs

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Drive the real scheduler on a tenant with no managed assets. Failure rolls the
// entire bounded batch back, and the next ordinary tenant pass retries it.
func TestIntegration_ExternalReassessment_JobRetryAndExternalOnlyTenant(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	tenant := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	job, err := NewFindingProducerJob(app, owner)
	if err != nil {
		t.Fatal(err)
	}
	testdb.WithSchemaShareLock(t, owner, func() {
		first, last := uuid.New(), uuid.New()
		if first.String() > last.String() {
			first, last = last, first
		}
		for i, id := range []uuid.UUID{first, last} {
			_, e := owner.Exec(`INSERT INTO external_connections(id,tenant_id,source_ip,dest_ip,dest_port,protocol,cipher_suite,key_exchange_algorithm,key_size,observation_count) VALUES($1,$2,'192.0.2.16','198.51.100.16',$3,'TLS','TLS_AES_256_GCM_SHA384','ECDHE',256,7)`, id, tenant, 443+i)
			if e != nil {
				t.Fatal(e)
			}
		}
		tenants, e := job.tenantsToProcess()
		if e != nil {
			t.Fatal(e)
		}
		found := false
		for _, id := range tenants {
			found = found || id == tenant
		}
		if !found {
			t.Fatal("external-only tenant absent from startup/nightly enumeration")
		}
		// Test-local trigger injects a deterministic failure after the first row's
		// update, proving transaction rollback rather than merely an early return.
		name := "external_retry_" + last.String()[:8]
		_, e = owner.Exec(`CREATE FUNCTION ` + name + `() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.id='` + last.String() + `'::uuid THEN RAISE EXCEPTION 'injected external reassessment failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER ` + name + ` BEFORE UPDATE ON external_connections FOR EACH ROW EXECUTE FUNCTION ` + name + `()`)
		if e != nil {
			t.Fatal(e)
		}
		defer func() {
			_, _ = owner.Exec(`DROP TRIGGER IF EXISTS ` + name + ` ON external_connections; DROP FUNCTION IF EXISTS ` + name + `()`)
		}()
		if job.runTenant(context.Background(), tenant) {
			t.Fatal("failed reassessment reported successful tenant pass")
		}
		for _, id := range []uuid.UUID{first, last} {
			var grade sql.NullString
			if e := owner.QueryRow(`SELECT crypto_strength FROM external_connections WHERE id=$1`, id).Scan(&grade); e != nil || grade.Valid {
				t.Fatalf("failed batch committed partially: %v %v", grade, e)
			}
		}
		if _, e := owner.Exec(`DROP TRIGGER ` + name + ` ON external_connections`); e != nil {
			t.Fatal(e)
		}
		if !job.runTenant(context.Background(), tenant) {
			t.Fatal("ordinary tenant retry failed")
		}
		if !job.runTenant(context.Background(), tenant) {
			t.Fatal("idempotent tenant retry failed")
		}
		for _, id := range []uuid.UUID{first, last} {
			var grade string
			var observations, hist int
			if e := owner.QueryRow(`SELECT crypto_strength,observation_count,(SELECT count(*) FROM external_connection_history WHERE external_connection_id=ec.id) FROM external_connections ec WHERE id=$1`, id).Scan(&grade, &observations, &hist); e != nil {
				t.Fatal(e)
			}
			if grade != "strong" || observations != 7 || hist != 1 {
				t.Fatalf("retry/convergence grade=%s observations=%d histories=%d", grade, observations, hist)
			}
		}
	})
}
