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
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/findings"
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
