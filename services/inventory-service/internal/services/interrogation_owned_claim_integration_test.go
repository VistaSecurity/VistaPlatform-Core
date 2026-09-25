package services

// The ownership claim of an interrogation finding ( W2.2) against the
// attacks the adversarial review of ran, adopted from its probes
// (review2027_adversarial_integration_test.go) and extended to the fixes:
//
//	B1a  the claim is bound to a real device job for exactly that asset
//	B1b  only a platform_managed sensor's rows may claim — never a tenant
//	     sensor that tagged itself `system` or took the profile
//
// plus the retired-owner and host-inventory cases the review found untested.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func claimConfigsOn(t *testing.T, f ownedIngestFixture, asset uuid.UUID) int {
	t.Helper()
	var n int
	if err := f.raw.QueryRow(`SELECT count(*) FROM crypto_implementations WHERE tenant_id=$1 AND asset_id=$2 AND deleted_at IS NULL`, f.tenant, asset).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func claimServer(t *testing.T, f ownedIngestFixture, tenant uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := f.raw.Exec(`
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1, $2, 'payroll-db', 'server', 'hardware.server', 'monitoring', NOW(), NOW(), NOW(), NOW())`, id, tenant); err != nil {
		t.Fatalf("seed server: %v", err)
	}
	return id
}

// weakAddressLess is an RC4 configuration with no address: exactly what an
// attacker would want to pin on somebody else's asset to drag its score down.
func weakAddressLess(f ownedIngestFixture) IngestFinding {
	fin := f.interrogationFinding("", "", 0, "TLS", "TLS 1.0", "TLS_RSA_WITH_RC4_128_MD5", map[string]interface{}{"config_name": "injected"})
	fin.IPAddress = nil
	fin.Port = nil
	return fin
}

func assertRejectedNothingLanded(t *testing.T, f ownedIngestFixture, victim uuid.UUID, fin IngestFinding) {
	t.Helper()
	report, err := f.svc.IngestFindingsReport(f.tenant, []IngestFinding{fin}, "monitoring")
	if err != nil {
		t.Fatalf("IngestFindingsReport: %v", err)
	}
	if n := claimConfigsOn(t, f, victim); n != 0 {
		t.Errorf("the claim attached %d configuration(s) to %s", n, victim)
	}
	if report.Results[0].Outcome != "rejected" || report.Results[0].AssetID != "" {
		t.Errorf("result = %+v, want rejected with no asset", report.Results[0])
	}
	if n := countExternalConnections(t, f.raw, f.tenant); n != 0 {
		t.Errorf("a refused claim was routed to external_connections (%d rows)", n)
	}
}

// B1a — the claim names an asset the job did not interrogate.
func TestIntegration_InterrogationClaim_AssetMustBeTheJobsAsset(t *testing.T) {
	f := newOwnedIngestFixture(t)
	server := claimServer(t, f, f.tenant)
	fin := weakAddressLess(f)
	fin.RawData["source_asset_id"] = server.String() // the job interrogated f.device
	assertRejectedNothingLanded(t, f, server, fin)
}

// B1a — every way the named job can fail to be a real interrogation of the
// claimed asset.
func TestIntegration_InterrogationClaim_JobMustBeARealInterrogation(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(t *testing.T, f ownedIngestFixture, fin IngestFinding) IngestFinding
	}{
		{"no device job named", func(t *testing.T, f ownedIngestFixture, fin IngestFinding) IngestFinding {
			delete(fin.RawData, "device_job_id")
			return fin
		}},
		{"a job id that does not exist", func(t *testing.T, f ownedIngestFixture, fin IngestFinding) IngestFinding {
			fin.RawData["device_job_id"] = uuid.NewString()
			return fin
		}},
		{"a job that never ran", func(t *testing.T, f ownedIngestFixture, fin IngestFinding) IngestFinding {
			if _, err := f.raw.Exec(`UPDATE device_jobs SET status='pending' WHERE id=$1`, f.job); err != nil {
				t.Fatal(err)
			}
			return fin
		}},
		{"a failed job", func(t *testing.T, f ownedIngestFixture, fin IngestFinding) IngestFinding {
			if _, err := f.raw.Exec(`UPDATE device_jobs SET status='failed' WHERE id=$1`, f.job); err != nil {
				t.Fatal(err)
			}
			return fin
		}},
		{"another tenant's job for the same claim", func(t *testing.T, f ownedIngestFixture, fin IngestFinding) IngestFinding {
			other := testdb.NewTenant(t, f.raw)
			otherAsset := claimServer(t, f, other)
			job := uuid.New()
			if _, err := f.raw.Exec(`INSERT INTO device_jobs (id, tenant_id, job_type, asset_id, status) VALUES ($1,$2,'device_interrogation',$3,'completed')`, job, other, otherAsset); err != nil {
				t.Fatal(err)
			}
			fin.RawData["device_job_id"] = job.String()
			return fin
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newOwnedIngestFixture(t)
			assertRejectedNothingLanded(t, f, f.device, c.setup(t, f, weakAddressLess(f)))
		})
	}
}

// B1b — a tenant sensor that looks exactly like the platform's (review A2):
// registered with profile device_interrogation, tags {system, platform},
// platform `platform`. None of that is the marker any more; the claim is
// refused even though its device job is real.
func TestIntegration_InterrogationClaim_SelfTaggedTenantSensorIsRefused(t *testing.T) {
	f := newOwnedIngestFixture(t)
	rogue := uuid.New()
	if _, err := f.raw.Exec(`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status,tags)
		VALUES($1,$2,'Platform Device Interrogation Agent','platform','system','device_interrogation','active',ARRAY['system','platform','device_interrogation'])`,
		rogue, f.tenant); err != nil {
		t.Fatal(err)
	}
	fin := weakAddressLess(f)
	rs := rogue.String()
	fin.SourceSensorID = &rs
	fin.RawData["sensor_id"] = rs
	assertRejectedNothingLanded(t, f, f.device, fin)
}

// Review A3 — a claim on another tenant's asset.
func TestIntegration_InterrogationClaim_CrossTenantIsRefused(t *testing.T) {
	f := newOwnedIngestFixture(t)
	other := testdb.NewTenant(t, f.raw)
	victim := claimServer(t, f, other)
	fin := f.interrogationFinding("203.0.113.40", "", 443, "TLS", "TLS 1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", nil)
	fin.RawData["source_asset_id"] = victim.String()
	report, err := f.svc.IngestFindingsReport(f.tenant, []IngestFinding{fin}, "monitoring")
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f.raw.QueryRow(`SELECT count(*) FROM crypto_implementations WHERE asset_id=$1`, victim).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 || report.Results[0].Outcome != "rejected" {
		t.Errorf("cross-tenant: result=%+v victim-configs=%d", report.Results[0], n)
	}
}

// Review A4 + non-blocking #4 — a retired owner. Soft-deleted: the claim does
// not verify. Archived or denied: the claim verifies, but nothing is
// materialised, so the answer is `rejected` with a reason — not a `matched`
// that landed nothing.
func TestIntegration_InterrogationClaim_RetiredOwnerIsRejected(t *testing.T) {
	for name, stmt := range map[string]string{
		"soft-deleted": `UPDATE assets SET deleted_at=NOW() WHERE tenant_id=$1 AND id=$2`,
		"archived":     `UPDATE assets SET asset_status='archived' WHERE tenant_id=$1 AND id=$2`,
		"denied":       `UPDATE assets SET asset_status='denied' WHERE tenant_id=$1 AND id=$2`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newOwnedIngestFixture(t)
			if _, err := f.raw.Exec(stmt, f.tenant, f.device); err != nil {
				t.Fatal(err)
			}
			fin := f.interrogationFinding("203.0.113.41", "", 443, "TLS", "TLS 1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", nil)
			assertRejectedNothingLanded(t, f, f.device, fin)
		})
	}
}

// Non-blocking #2 — a host-inventory row shares the platform sensor and also
// carries source_asset_id, but it is not an interrogation finding: it must
// never take the owned path. Its public connection still goes to
// external_connections, attributed to the host.
func TestIntegration_InterrogationClaim_HostInventoryRowIsNotAnInterrogationClaim(t *testing.T) {
	f := newOwnedIngestFixture(t)
	fin := f.interrogationFinding("203.0.113.50", "", 443, "tcp", "", "", map[string]interface{}{
		"discovery_method": "host_inventory",
		"discovery_type":   "host_connection",
	})
	if _, err := f.svc.IngestFindingsReport(f.tenant, []IngestFinding{fin}, "monitoring"); err != nil {
		t.Fatal(err)
	}
	if n := claimConfigsOn(t, f, f.device); n != 0 {
		t.Errorf("a host-inventory row was attached to the device through the interrogation path (%d configs)", n)
	}
	if n := countExternalConnections(t, f.raw, f.tenant); n != 1 {
		t.Errorf("external_connections = %d, want the host's one public connection", n)
	}
}

// Review A5 — the whole owned path as the RLS-bound app role, with a second
// tenant present.
func TestIntegration_InterrogationClaim_WorksAsTheAppRole(t *testing.T) {
	f := newOwnedIngestFixture(t)
	app := testdb.ConnectAsAppRole(t, f.raw)
	svc := newCloudRoutingAssetService(&database.DB{DB: sqlx.NewDb(app, "postgres")})
	_ = testdb.NewTenant(t, f.raw)
	const own = "10.20.30.1"
	if _, err := f.raw.Exec(`UPDATE assets SET primary_address = $3::inet WHERE tenant_id=$1 AND id=$2`, f.tenant, f.device, own); err != nil {
		t.Fatal(err)
	}
	pub := f.interrogationFinding("203.0.113.42", "", 443, "TLS", "TLS 1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", map[string]interface{}{"config_name": "pub"})
	mine := f.interrogationFinding(own, "", 22, "SSH", "SSH-2.0", "", map[string]interface{}{"ssh_banner": "SSH-2.0-OpenSSH_9.6"})
	report, err := svc.IngestFindingsReport(f.tenant, []IngestFinding{pub, mine}, "monitoring")
	if err != nil {
		t.Fatalf("app role ingest: %v", err)
	}
	for i, r := range report.Results {
		if r.AssetID != f.device.String() {
			t.Errorf("app role: finding %d = %+v, want the device", i, r)
		}
	}
	if n := claimConfigsOn(t, f, f.device); n != 2 {
		t.Errorf("app role: device configs = %d, want 2", n)
	}
}
