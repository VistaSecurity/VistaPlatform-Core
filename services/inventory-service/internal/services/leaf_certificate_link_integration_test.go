package services

// Integration proof, against a real Postgres with the real schema and seed,
// that a certificate discovered by ingest is REACHABLE FROM ITS ASSET.
//
// The bug this pins: `crypto_implementations.certificate_id` (the leaf
// denormalisation) and `crypto_implementation_certificates` (the junction) were
// written by two different statements in two different transactions — the column
// by the ingest INSERT/UPDATE, the junction row by a later, best-effort
// `LinkCertificateToImplementation` call that only logged on failure. They
// diverged: the original `valid_certificate_role` CHECK rejected the literal
// 'leaf', so on every sensor-discovered certificate the column landed, the
// junction insert was refused, and ingest reported success.
//
// Everything that walks DOWN from an asset to its certificates goes through the
// junction and only the junction — `shared/findings.AssetSubjects`' certificate
// descendant path (which is what `finding:(…)` and the `has_findings` facet
// compile through), and the `asset/cert` shape the query language's `cert:(…)`
// sub-predicate translates to. So the certificate existed, carried its risk, and
// was invisible from the asset it was served on.
//
// Both halves are asserted here because they fail independently and both are
// live product surfaces. The mutation that proves the test is real: delete the
// `linkLeafCertificate` call from `upsertCryptoImplementation` (crypto_dedup.go)
// — every subtest below goes red.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// leafLinkFixture drives the REAL ingest entry point. certificateService is
// wired because without it processDiscoveryCryptoData materializes no
// certificate at all and every assertion below would pass vacuously;
// algorithmService is wired so the configuration is classified the way a real
// one is.
type leafLinkFixture struct {
	svc    *AssetService
	db     *database.DB
	tenant uuid.UUID
}

func newLeafLinkFixture(t *testing.T) leafLinkFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	return leafLinkFixture{
		svc: &AssetService{
			db:                 db,
			algorithmService:   NewAlgorithmService(db),
			certificateService: &CertificateService{db: db},
		},
		db:     db,
		tenant: testdb.NewTenant(t, raw),
	}
}

// leafCertFinding is a TLS observation carrying a leaf certificate in the
// canonical `"certificates"` array — the one format every discovery path emits
// (CLAUDE.md, "Single certificate format").
func leafCertFinding(host, ip string, port int, fingerprint string) IngestFinding {
	p := port
	return IngestFinding{
		Hostname:        &host,
		IPAddress:       &ip,
		Port:            &p,
		Protocol:        "TLS",
		ProtocolVersion: strPtr("TLS 1.2"),
		CipherSuite:     strPtr("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
		AssetType:       "server",
		RawData: map[string]interface{}{
			"source":           "sensor",
			"discovery_method": "active",
			"certificates": []interface{}{
				map[string]interface{}{
					"subject_dn":           "CN=" + host,
					"issuer_dn":            "CN=Leaf Link Test CA",
					"fingerprint_sha256":   fingerprint,
					"not_before":           time.Now().Add(-24 * time.Hour).Format(time.RFC3339),
					"not_after":            time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339),
					"public_key_algorithm": "RSA",
					"public_key_size":      float64(2048),
					"signature_algorithm":  "SHA256-RSA",
				},
			},
		},
	}
}

// ingestLeafCert runs one observation through the production entry point and
// returns the asset and certificate it materialized.
func (f leafLinkFixture) ingestLeafCert(t *testing.T, host, ip string, port int, fingerprint string) (assetID, certID uuid.UUID) {
	t.Helper()
	if _, err := f.svc.IngestFindings(f.tenant, []IngestFinding{leafCertFinding(host, ip, port, fingerprint)}, "monitoring"); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}
	if err := f.db.QueryRow(
		`SELECT id FROM assets WHERE tenant_id = $1 AND hostname = $2 AND deleted_at IS NULL`,
		f.tenant, host).Scan(&assetID); err != nil {
		t.Fatalf("read back asset %s: %v", host, err)
	}
	if err := f.db.QueryRow(
		`SELECT id FROM certificates WHERE tenant_id = $1 AND fingerprint_sha256 = $2`,
		f.tenant, fingerprint).Scan(&certID); err != nil {
		t.Fatalf("read back certificate %s: %v — ingest materialized no certificate, so every "+
			"reachability assertion below would be vacuous", fingerprint, err)
	}
	return assetID, certID
}

// TestIntegration_Ingest_LeafCertificateIsReachableFromTheAsset is the headline
// regression: a certificate ingest attached to a configuration must be findable
// by walking down from the asset, not only by naming it.
func TestIntegration_Ingest_LeafCertificateIsReachableFromTheAsset(t *testing.T) {
	f := newLeafLinkFixture(t)
	fp := hexFingerprint("leaf-link-reachable")
	assetID, certID := f.ingestLeafCert(t, "leaf-link.example.test", "198.51.100.21", 443, fp)

	t.Run("the column and the junction agree", func(t *testing.T) {
		// The invariant itself. `certificate_id` without its junction row is
		// the exact shape of the bug: the configuration knows its certificate
		// and nothing that reads the junction can see it.
		var column, junction int
		if err := f.db.QueryRow(`
			SELECT count(*) FILTER (WHERE ci.certificate_id = $2),
			       count(*) FILTER (WHERE EXISTS (
			         SELECT 1 FROM crypto_implementation_certificates cic
			          WHERE cic.crypto_implementation_id = ci.id
			            AND cic.certificate_id = $2
			            AND cic.certificate_role = 'leaf'))
			  FROM crypto_implementations ci
			 WHERE ci.tenant_id = $1 AND ci.asset_id = $3 AND ci.deleted_at IS NULL`,
			f.tenant, certID, assetID).Scan(&column, &junction); err != nil {
			t.Fatalf("read configuration links: %v", err)
		}
		if column == 0 {
			t.Fatal("no configuration names the certificate in certificate_id; the fixture did not ingest what it claims to")
		}
		if junction != column {
			t.Errorf("%d configurations carry certificate_id but only %d carry the matching 'leaf' junction row — "+
				"the two halves of the link are written apart again, and everything that walks down from "+
				"the asset reads the junction", column, junction)
		}
	})

	t.Run("findings.AssetSubjects reaches it", func(t *testing.T) {
		// The certificate descendant path, exactly as the per-asset findings
		// read and the has_findings facet compile it.
		var certPath string
		for _, s := range findings.AssetSubjects("a", leafLinkAliases()) {
			if s.Type == findings.SubjectCertificate {
				certPath = s.IDs
			}
		}
		if certPath == "" {
			t.Fatal("AssetSubjects declares no certificate path")
		}
		var reachable bool
		q := `SELECT EXISTS (SELECT 1 FROM assets a
		       WHERE a.tenant_id = $1 AND a.id = $2 AND $3::uuid IN (` + certPath + `))`
		testdb.RetryTransient(t, func() error {
			return f.db.QueryRow(q, f.tenant, assetID, certID).Scan(&reachable)
		})
		if !reachable {
			t.Error("findings.AssetSubjects cannot reach the certificate from its own asset — " +
				"a finding on this certificate is invisible to finding:(…) and uncounted by the has_findings facet")
		}
	})

	t.Run("the query language's cert:(…) matches", func(t *testing.T) {
		// GetAssets is the real list read: the predicate is parsed, validated
		// and translated through the asset/cert shape in shared/query/sql.
		assets, total, err := f.svc.GetAssets(f.tenant, models.AssetFilters{
			Query: fmt.Sprintf("cert:(fingerprint_sha256:%s)", fp),
		})
		if err != nil {
			t.Fatalf("GetAssets: %v", err)
		}
		if total != 1 || len(assets) != 1 || assets[0].ID != assetID {
			t.Fatalf("cert:(fingerprint_sha256:…) matched %d assets (%d rows), want the one serving it — "+
				"the asset/cert shape walks the junction, so a missing leaf row makes the certificate "+
				"unsearchable from the inventory", total, len(assets))
		}
	})
}

// TestIntegration_Ingest_ReObservationKeepsTheLeafLink covers the OTHER branch
// of upsertCryptoImplementation. The first observation INSERTs the
// configuration; every one after it takes the refresh path, which writes
// certificate_id through a COALESCE. Both branches have to establish the
// junction row, and a fix applied to only one of them would pass the test above
// and still lose the link on a renewal.
func TestIntegration_Ingest_ReObservationKeepsTheLeafLink(t *testing.T) {
	f := newLeafLinkFixture(t)
	const host, ip, port = "leaf-link-renew.example.test", "198.51.100.22", 443

	first := hexFingerprint("leaf-link-renew-1")
	assetID, firstCert := f.ingestLeafCert(t, host, ip, port, first)

	// A renewal: same socket, same negotiated parameters, new certificate. The
	// configuration's natural key does not include the certificate, so this
	// takes the refresh branch rather than inserting a second configuration.
	renewed := hexFingerprint("leaf-link-renew-2")
	_, renewedCert := f.ingestLeafCert(t, host, ip, port, renewed)
	if renewedCert == firstCert {
		t.Fatal("the renewal reused the first certificate row; this test would not exercise the refresh branch")
	}

	var configurations int
	if err := f.db.QueryRow(
		`SELECT count(*) FROM crypto_implementations WHERE tenant_id = $1 AND asset_id = $2 AND deleted_at IS NULL`,
		f.tenant, assetID).Scan(&configurations); err != nil {
		t.Fatalf("count configurations: %v", err)
	}
	if configurations != 1 {
		t.Fatalf("%d configurations after a renewal, want 1 — the refresh branch was not taken, "+
			"so this test is not covering what it claims", configurations)
	}

	// Both certificates keep a junction row: the renewed one because it is the
	// current leaf, the first because it was, and the junction is append-only.
	for _, tc := range []struct {
		name string
		cert uuid.UUID
	}{{"first", firstCert}, {"renewed", renewedCert}} {
		var linked bool
		if err := f.db.QueryRow(`
			SELECT EXISTS (SELECT 1 FROM crypto_implementation_certificates cic
			                JOIN crypto_implementations ci ON ci.id = cic.crypto_implementation_id
			               WHERE ci.tenant_id = $1 AND ci.asset_id = $2 AND cic.certificate_id = $3)`,
			f.tenant, assetID, tc.cert).Scan(&linked); err != nil {
			t.Fatalf("read %s junction row: %v", tc.name, err)
		}
		if !linked {
			t.Errorf("the %s certificate has no junction row; it is unreachable from the asset", tc.name)
		}
	}

	var current uuid.UUID
	if err := f.db.QueryRow(
		`SELECT certificate_id FROM crypto_implementations WHERE tenant_id = $1 AND asset_id = $2 AND deleted_at IS NULL`,
		f.tenant, assetID).Scan(&current); err != nil {
		t.Fatalf("read certificate_id: %v", err)
	}
	if current != renewedCert {
		t.Errorf("certificate_id = %s after the renewal, want the renewed certificate %s — "+
			"the leaf denormalisation must track the current leaf", current, renewedCert)
	}
}

// TestIntegration_Schema_BackfillsLeafJunctionFromCertificateID is the belt for
// rows that already exist. Installs written before the two writers were made
// atomic hold configurations whose certificate_id has no junction row; the
// POST-MIGRATIONS convergence block in schema.sql repairs them on the next
// apply. Written as "plant the legacy shape, re-apply the schema, assert it
// converged" because that is exactly what a `helm upgrade` does.
func TestIntegration_Schema_BackfillsLeafJunctionFromCertificateID(t *testing.T) {
	f := newLeafLinkFixture(t)
	fp := hexFingerprint("leaf-link-backfill")
	assetID, certID := f.ingestLeafCert(t, "leaf-link-legacy.example.test", "198.51.100.23", 443, fp)

	var implID uuid.UUID
	if err := f.db.QueryRow(
		`SELECT id FROM crypto_implementations WHERE tenant_id = $1 AND asset_id = $2 AND deleted_at IS NULL`,
		f.tenant, assetID).Scan(&implID); err != nil {
		t.Fatalf("read configuration: %v", err)
	}

	// Reproduce the legacy shape: the column set, the junction row absent.
	if _, err := f.db.Exec(
		`DELETE FROM crypto_implementation_certificates WHERE crypto_implementation_id = $1`, implID); err != nil {
		t.Fatalf("strip junction rows: %v", err)
	}
	var junctionRows int
	if err := f.db.QueryRow(
		`SELECT count(*) FROM crypto_implementation_certificates WHERE crypto_implementation_id = $1`,
		implID).Scan(&junctionRows); err != nil {
		t.Fatalf("count junction rows: %v", err)
	}
	if junctionRows != 0 {
		t.Fatalf("the legacy shape was not planted (%d junction rows remain); the backfill would have nothing to prove",
			junctionRows)
	}

	// FORCE: the re-apply is the assertion. The plain helper skips when the
	// database already carries this schema's content hash.
	testdb.ForceApplySchema(t, f.db.DB.DB)

	var role string
	if err := f.db.QueryRow(
		`SELECT certificate_role FROM crypto_implementation_certificates
		  WHERE crypto_implementation_id = $1 AND certificate_id = $2`,
		implID, certID).Scan(&role); err != nil {
		t.Fatalf("the schema re-apply did not converge the legacy row onto the junction: %v", err)
	}
	if role != "leaf" {
		t.Errorf("backfilled junction row carries role %q, want \"leaf\"", role)
	}

	// Idempotent: a second apply must not raise on the unique constraint.
	testdb.ForceApplySchema(t, f.db.DB.DB)
	var rows int
	if err := f.db.QueryRow(
		`SELECT count(*) FROM crypto_implementation_certificates WHERE crypto_implementation_id = $1`,
		implID).Scan(&rows); err != nil {
		t.Fatalf("count junction rows after second apply: %v", err)
	}
	if rows != 1 {
		t.Errorf("%d junction rows after two schema applies, want 1", rows)
	}
}

// leafLinkAliases mints the unique table aliases findings.AssetSubjects needs.
func leafLinkAliases() func(string) string {
	n := 0
	return func(prefix string) string {
		n++
		return "llk_" + prefix + fmt.Sprint(n)
	}
}

// Delayed delivery must preserve source freshness and the currently served leaf,
// while keeping both historical certificates reachable from the asset.
func TestIntegration_Ingest_OlderCertificateCannotReplaceNewerLeaf(t *testing.T) {
	f := newLeafLinkFixture(t)
	const host, ip = "out-of-order.example.test", "198.51.100.29"
	newer := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	older := newer.Add(-24 * time.Hour)
	for _, observation := range []struct {
		name string
		at   time.Time
	}{{"newer", newer}, {"older", older}, {"older", older}} {
		finding := leafCertFinding(host, ip, 443, hexFingerprint(observation.name))
		finding.RawData["observed_at"] = observation.at.Format(time.RFC3339Nano)
		finding.RawData["measurement"] = observation.name
		if _, err := f.svc.IngestFindings(f.tenant, []IngestFinding{finding}, "monitoring"); err != nil {
			t.Fatal(err)
		}
	}
	var fingerprint, measurement string
	var first, last time.Time
	if err := f.db.QueryRow(`SELECT c.fingerprint_sha256,ci.raw_data->>'measurement',ci.first_discovered_at,ci.last_verified_at
 FROM crypto_implementations ci JOIN certificates c ON c.id=ci.certificate_id
 WHERE ci.tenant_id=$1 AND ci.deleted_at IS NULL`, f.tenant).Scan(&fingerprint, &measurement, &first, &last); err != nil {
		t.Fatal(err)
	}
	if fingerprint != hexFingerprint("newer") || measurement != "newer" || !first.Equal(older) || !last.Equal(newer) {
		t.Fatalf("delayed evidence changed latest selection/freshness: fingerprint=%s measurement=%s first=%s last=%s", fingerprint, measurement, first, last)
	}
	var links int
	if err := f.db.QueryRow(`SELECT count(*) FROM crypto_implementation_certificates cic
 JOIN crypto_implementations ci ON ci.id=cic.crypto_implementation_id WHERE ci.tenant_id=$1`, f.tenant).Scan(&links); err != nil {
		t.Fatal(err)
	}
	if links != 2 {
		t.Fatalf("historical certificate attachments=%d, want 2", links)
	}
}

func TestIntegration_Ingest_ProspectiveReceiptsSurvivePendingApproval(t *testing.T) {
	f := newLeafLinkFixture(t)
	f.svc.networkSegmentService = NewNetworkSegmentService(f.db, nil)
	if _, err := f.db.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment)
 VALUES($1,$2,'Receipt test','cidr','192.0.2.0/24','production')`, uuid.New(), f.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"}}')
 ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, f.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO tenant_entitlements(tenant_id,item_id,override_value,reason)
 SELECT $1,id,'{"quantity":1}'::jsonb,'retained receipt regression' FROM billable_items WHERE key='max_assets'`, f.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.identityEngine(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.svc.identityEng, err = identity.New(identity.Config{Repo: f.svc.identityRepo, AdmissionEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	seen := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	batch := make([]IngestFinding, 51)
	for i := range batch {
		batch[i] = leafCertFinding("receipt-device.example.test", "192.0.2.39", 443, hexFingerprint("receipt-cert"))
		batch[i].RawData["observed_at"] = seen.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)
		batch[i].RawData["discovery_id"] = fmt.Sprintf("receipt-%d", i)
	}
	for replay := 0; replay < 2; replay++ {
		if _, err := f.svc.IngestFindings(f.tenant, batch, "pending_approval"); err != nil {
			t.Fatal(err)
		}
	}
	var asset uuid.UUID
	var deferred, receipts, materialized int
	if err := f.db.QueryRow(`SELECT id,jsonb_array_length(COALESCE(metadata->'deferred_findings','[]')) FROM assets WHERE tenant_id=$1`, f.tenant).Scan(&asset, &deferred); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRow(`SELECT count(*),count(materialized_at) FROM identity_observation_payloads WHERE tenant_id=$1`, f.tenant).Scan(&receipts, &materialized); err != nil {
		t.Fatal(err)
	}
	if receipts != 51 || materialized != 0 || deferred != 0 {
		t.Fatalf("receipts=%d materialized=%d metadata buffer=%d", receipts, materialized, deferred)
	}
	if n, err := f.svc.SweepIdentityEvidence(context.Background(), f.tenant); err != nil || n != 0 {
		t.Fatalf("unapproved replay=%d: %v", n, err)
	}
	if err := f.svc.ApproveAssets(f.tenant, []uuid.UUID{asset}, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	for _, want := range []int{50, 1, 0} {
		if n, err := f.svc.SweepIdentityEvidence(context.Background(), f.tenant); err != nil || n != want {
			t.Fatalf("replay=%d want %d: %v", n, want, err)
		}
	}
	if err := f.db.QueryRow(`SELECT count(*) FROM crypto_implementations WHERE tenant_id=$1`, f.tenant).Scan(&materialized); err != nil {
		t.Fatal(err)
	}
	if materialized != 1 {
		t.Fatalf("duplicate materialization: %d", materialized)
	}
}

func TestIntegration_Ingest_CertificateClockIgnoresChainlessSightings(t *testing.T) {
	for _, path := range []string{"exact", "partial", "enrich"} {
		t.Run(path, func(t *testing.T) {
			f := newLeafLinkFixture(t)
			start := time.Now().UTC().Add(-4 * time.Hour).Truncate(time.Microsecond)
			for _, step := range []struct {
				name   string
				offset int
				cert   bool
			}{{"A", 0, true}, {"chainless", 2, false}, {"B", 1, true}} {
				finding := leafCertFinding("certificate-clock.example.test", "198.51.100.30", 443, hexFingerprint(step.name))
				finding.RawData["observed_at"] = start.Add(time.Duration(step.offset) * time.Hour).Format(time.RFC3339Nano)
				if !step.cert {
					delete(finding.RawData, "certificates")
				}
				if (path == "partial" && step.name == "B") || (path == "enrich" && step.name != "B") {
					finding.CipherSuite = nil
				}
				if _, err := f.svc.IngestFindings(f.tenant, []IngestFinding{finding}, "monitoring"); err != nil {
					t.Fatal(err)
				}
			}
			var selected string
			var certAt, last time.Time
			if err := f.db.QueryRow(`SELECT c.fingerprint_sha256,ci.certificate_observed_at,ci.last_verified_at
   FROM crypto_implementations ci JOIN certificates c ON c.id=ci.certificate_id WHERE ci.tenant_id=$1`, f.tenant).Scan(&selected, &certAt, &last); err != nil {
				t.Fatal(err)
			}
			if selected != hexFingerprint("B") || !certAt.Equal(start.Add(time.Hour)) || !last.Equal(start.Add(2*time.Hour)) {
				t.Fatalf("chainless sighting blocked leaf replacement: %s certificate=%s configuration=%s", selected, certAt, last)
			}
		})
	}
}

func TestIntegration_Ingest_DirectMaterializationFollowsMergeAndApproval(t *testing.T) {
	f := newLeafLinkFixture(t)
	source := seedAsset(t, f.db, f.tenant, "merged-source", "server", "hardware.computer.server", "production", 0, 0)
	survivor := seedAsset(t, f.db, f.tenant, "surviving-host", "server", "hardware.computer.server", "production", 0, 0)
	if _, err := f.db.Exec(`UPDATE assets SET asset_status='monitoring' WHERE tenant_id=$1`, f.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`UPDATE assets SET asset_status='archived',metadata=jsonb_build_object('merged_into',$3::text)
 WHERE tenant_id=$1 AND id=$2`, f.tenant, source, survivor.String()); err != nil {
		t.Fatal(err)
	}
	finding := leafCertFinding("surviving-host.example.test", "198.51.100.32", 443, hexFingerprint("redirect-cert"))
	if err := f.svc.processApprovedDiscoveryCryptoData(f.tenant, source, finding, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	var owner uuid.UUID
	if err := f.db.QueryRow(`SELECT asset_id FROM crypto_implementations WHERE tenant_id=$1`, f.tenant).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if owner != survivor {
		t.Fatalf("crypto attached to merged source: %s", owner)
	}
	if _, err := f.db.Exec(`UPDATE assets SET asset_status='denied' WHERE tenant_id=$1 AND id=$2`, f.tenant, survivor); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.processApprovedDiscoveryCryptoData(f.tenant, source, finding, nil, nil, nil); err == nil {
		t.Fatal("denied survivor materialized new evidence")
	}
}

func TestIntegration_Ingest_AtRestReplayKeepsOriginalPostureClock(t *testing.T) {
	f := newLeafLinkFixture(t)
	asset := seedAsset(t, f.db, f.tenant, "bucket", "cloud_resource", "cloud_resource", "production", 0, 0)
	latest := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	for _, step := range []struct {
		at        time.Time
		encrypted bool
	}{{latest, false}, {latest.Add(-time.Hour), true}} {
		finding := IngestFinding{RawData: map[string]interface{}{"resource_type": "s3_bucket", "arn": "arn:aws:s3:::retained-test-bucket",
			"encrypted": step.encrypted, "encryption_determined": true, "observed_at": step.at.Format(time.RFC3339Nano)}}
		if err := f.svc.processDiscoveryCryptoData(f.tenant, asset, finding, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	var encrypted bool
	var first, last time.Time
	if err := f.db.QueryRow(`SELECT (configuration_data->>'encrypted')::boolean,first_discovered_at,last_verified_at
 FROM crypto_applications WHERE tenant_id=$1 AND asset_id=$2`, f.tenant, asset).Scan(&encrypted, &first, &last); err != nil {
		t.Fatal(err)
	}
	if encrypted || !first.Equal(latest.Add(-time.Hour)) || !last.Equal(latest) {
		t.Fatalf("older at-rest replay replaced current posture: encrypted=%v first=%s last=%s", encrypted, first, last)
	}
	if _, err := f.db.Exec(`UPDATE crypto_applications SET last_verified_at=NULL WHERE tenant_id=$1 AND asset_id=$2`, f.tenant, asset); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.processDiscoveryCryptoData(f.tenant, asset, IngestFinding{RawData: map[string]interface{}{
		"resource_type": "s3_bucket", "arn": "arn:aws:s3:::retained-test-bucket", "encrypted": true, "encryption_determined": true, "observed_at": latest.Format(time.RFC3339Nano),
	}}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRow(`SELECT (configuration_data->>'encrypted')::boolean FROM crypto_applications WHERE tenant_id=$1 AND asset_id=$2`, f.tenant, asset).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if !encrypted {
		t.Fatal("legacy NULL clock blocked the first measured posture")
	}
	if err := f.svc.produceAtRestApplication(f.tenant, uuid.New(), atRestPosture{ResourceType: "cloud_storage", ResourceIdentifier: "missing-asset"}, latest); err == nil {
		t.Fatal("failed at-rest write was acknowledged")
	}
}
