package services

// Integration proof, against a real Postgres with the real schema and seed,
// that ingest defers on the status an asset HAS rather than the one the batch
// asked for.
//
// The bug: discovery-processor evaluates the tenant's auto-approval rules per
// DISCOVERY ROW and sends the answer along with the batch. That answer decides
// what a NEW asset lands as — and ingest was using it for a second, different
// question: whether to materialize this finding's certificates and crypto
// configuration or park them in `assets.metadata->'deferred_findings'`.
//
// For a finding that MATCHED an existing, already-approved asset the two
// questions have different answers. The same access point seen on an address in
// no registered segment (an IPv6 link-local, say), or a TLS endpoint reported by
// device interrogation, matches no rule, so the row arrives `pending_approval` —
// and its crypto was deferred onto an asset that is `monitoring`. Nothing ever
// replays a deferred finding except ApproveAssets, which runs only when a
// PENDING asset is approved, and this asset was approved long ago. Eleven access
// points with TLS-on-8443 rows had their crypto parked that way on a dev cluster
// and it never materialized.
//
// Mutation that proves this test: in IngestFindingsReport, delete the
// `res.Outcome == identity.OutcomeMatched` block that replaces assetStatus with
// the asset's real status (or restore the old `if assetStatus ==
// "pending_approval"` deferral test) — the first subtest goes red on all three
// assertions.
//
// Both polarities are pinned: a finding that matches a monitoring asset
// materializes, and a finding that creates a NEW asset under a pending batch
// still defers.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// effectiveStatusFinding is an ordinary TLS observation carrying a leaf
// certificate — the shape every discovery path emits.
func effectiveStatusFinding(host, ip string, port int, fingerprint string) IngestFinding {
	h, i, p := host, ip, port
	return IngestFinding{
		Hostname:        &h,
		IPAddress:       &i,
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
					"issuer_dn":            "CN=Effective Status Test CA",
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

func TestIntegration_Ingest_MonitoringAssetMaterializesUnderAPendingBatch(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewAssetService(db)

	const host = "ap-07.example.test"
	const addr = "198.51.100.37"

	// The asset as the tenant already has it: discovered on :443, approved,
	// monitoring.
	if _, err := svc.IngestFindings(tenant,
		[]IngestFinding{effectiveStatusFinding(host, addr, 443, hexFingerprint("effective-status-443"))},
		identity.StatusMonitoring); err != nil {
		t.Fatalf("seeding the monitoring asset: %v", err)
	}

	var assetID uuid.UUID
	var status string
	if err := db.QueryRow(
		`SELECT id, asset_status FROM assets WHERE tenant_id = $1 AND hostname = $2 AND deleted_at IS NULL`,
		tenant, host).Scan(&assetID, &status); err != nil {
		t.Fatalf("read back the asset: %v", err)
	}
	if status != identity.StatusMonitoring {
		t.Fatalf("the fixture asset is %q, not %q — every assertion below would be about the wrong thing",
			status, identity.StatusMonitoring)
	}

	// The same host on :8443, in a batch whose rule evaluation said
	// pending_approval. This is the row that was being deferred.
	report, err := svc.IngestFindingsReport(tenant,
		[]IngestFinding{effectiveStatusFinding(host, addr, 8443, hexFingerprint("effective-status-8443"))},
		identity.StatusPendingApproval)
	if err != nil {
		t.Fatalf("IngestFindingsReport: %v", err)
	}

	t.Run("it landed on the asset that already exists", func(t *testing.T) {
		var assets int
		if err := db.QueryRow(
			`SELECT count(*) FROM assets WHERE tenant_id = $1 AND hostname = $2 AND deleted_at IS NULL`,
			tenant, host).Scan(&assets); err != nil {
			t.Fatalf("count assets: %v", err)
		}
		if assets != 1 {
			t.Fatalf("%d assets for %s, want 1 — the second observation did not MATCH, so this test "+
				"is no longer exercising the matched path", assets, host)
		}
	})

	t.Run("the crypto configuration is materialized, not deferred", func(t *testing.T) {
		var ports []int
		if err := db.Select(&ports, `
			SELECT e.port
			  FROM crypto_implementations ci
			  JOIN asset_endpoints e ON e.tenant_id = ci.tenant_id AND e.id = ci.endpoint_id
			 WHERE ci.tenant_id = $1 AND ci.asset_id = $2 AND ci.deleted_at IS NULL
			 ORDER BY e.port`, tenant, assetID); err != nil {
			t.Fatalf("read configurations: %v", err)
		}
		found := false
		for _, p := range ports {
			if p == 8443 {
				found = true
			}
		}
		if !found {
			t.Fatalf("configurations exist on ports %v, none on 8443 — the finding's crypto was deferred "+
				"onto an asset that is already monitoring, where nothing will ever replay it", ports)
		}
	})

	t.Run("nothing was parked in deferred_findings", func(t *testing.T) {
		var deferred int
		if err := db.QueryRow(`
			SELECT COALESCE(jsonb_array_length(metadata->'deferred_findings'), 0)
			  FROM assets WHERE tenant_id = $1 AND id = $2`, tenant, assetID).Scan(&deferred); err != nil {
			t.Fatalf("read deferred_findings: %v", err)
		}
		if deferred != 0 {
			t.Fatalf("%d finding(s) sit in deferred_findings on a monitoring asset; ApproveAssets is the "+
				"only thing that replays them and it runs only for a PENDING asset", deferred)
		}
	})

	t.Run("the caller is told what actually happened", func(t *testing.T) {
		// This is what discovery-processor reads to stamp the discovery row.
		// Without it the row stays `pending` forever, invisible: Approvals
		// lists pending ASSETS, and there is no pending asset here.
		if len(report.EffectiveStatus) != 1 {
			t.Fatalf("report carries %d per-finding statuses, want 1", len(report.EffectiveStatus))
		}
		if report.EffectiveStatus[0] != identity.StatusMonitoring {
			t.Fatalf("report says the finding landed on a %q asset, want %q",
				report.EffectiveStatus[0], identity.StatusMonitoring)
		}
	})

	// The other polarity. A pending batch must still defer when it is genuinely
	// creating something new — that is the whole point of the deferral, and a
	// fix that materialized everything would be the same bug pointed the other
	// way.
	t.Run("a new asset under a pending batch still defers", func(t *testing.T) {
		const fresh = "ap-08.example.test"
		newReport, err := svc.IngestFindingsReport(tenant,
			[]IngestFinding{effectiveStatusFinding(fresh, "198.51.100.38", 443, hexFingerprint("effective-status-new"))},
			identity.StatusPendingApproval)
		if err != nil {
			t.Fatalf("IngestFindingsReport: %v", err)
		}

		var freshID uuid.UUID
		var freshStatus string
		if err := db.QueryRow(
			`SELECT id, asset_status FROM assets WHERE tenant_id = $1 AND hostname = $2 AND deleted_at IS NULL`,
			tenant, fresh).Scan(&freshID, &freshStatus); err != nil {
			t.Fatalf("read back the new asset: %v", err)
		}
		if freshStatus != identity.StatusPendingApproval {
			t.Fatalf("the new asset is %q, want %q", freshStatus, identity.StatusPendingApproval)
		}

		var configurations int
		if err := db.QueryRow(
			`SELECT count(*) FROM crypto_implementations WHERE tenant_id = $1 AND asset_id = $2 AND deleted_at IS NULL`,
			tenant, freshID).Scan(&configurations); err != nil {
			t.Fatalf("count configurations: %v", err)
		}
		if configurations != 0 {
			t.Errorf("%d crypto configuration(s) materialized for an asset awaiting approval — unapproved "+
				"discoveries must not reach the inventory tables", configurations)
		}

		var deferred int
		if err := db.QueryRow(`
			SELECT COALESCE(jsonb_array_length(metadata->'deferred_findings'), 0)
			  FROM assets WHERE tenant_id = $1 AND id = $2`, tenant, freshID).Scan(&deferred); err != nil {
			t.Fatalf("read deferred_findings: %v", err)
		}
		if deferred != 1 {
			t.Errorf("deferred_findings holds %d finding(s) for the pending asset, want 1", deferred)
		}

		if len(newReport.EffectiveStatus) != 1 || newReport.EffectiveStatus[0] != identity.StatusPendingApproval {
			t.Errorf("report says %v, want one %q — the discovery row must stay pending for a pending asset",
				newReport.EffectiveStatus, identity.StatusPendingApproval)
		}
	})
}

// The other half of "the batch does not decide what an existing asset is": a
// batch that asks for MONITORING must not resurrect an asset the tenant
// archived.
//
// The device was retired deliberately. It later reappears on a segment that has
// an auto-approval rule, so the rule fires and the row arrives `monitoring` —
// and the asset was silently promoted back out of the archive (an `approved`
// history entry naming no person) and its certificates and crypto configuration
// written into the live inventory. `denied` was hard-filtered earlier in the
// ingest for exactly this reason; `archived` was not.
//
// Mutation that proves it: put `setAssetStatus` back in place of
// `setStatusUnlessArchived` in resolveDiscoveryObservation — the asset is
// promoted, the corrective read then reports `monitoring`, and all four
// assertions in the archived subtest go red.
//
// Skips without TEST_DATABASE_URL.
func TestIntegration_Ingest_ArchivedAssetIsNotResurrectedByAnApprovingBatch(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewAssetService(db)

	t.Run("an archived asset stays archived, and its crypto is neither materialized nor deferred", func(t *testing.T) {
		const host = "retired-switch.example.test"
		const addr = "198.51.100.51"

		// Discovered and approved once, then retired by the tenant.
		if _, err := svc.IngestFindings(tenant,
			[]IngestFinding{effectiveStatusFinding(host, addr, 443, hexFingerprint("archived-443"))},
			identity.StatusMonitoring); err != nil {
			t.Fatalf("seeding the asset: %v", err)
		}
		var assetID uuid.UUID
		if err := db.QueryRow(
			`SELECT id FROM assets WHERE tenant_id = $1 AND hostname = $2 AND deleted_at IS NULL`,
			tenant, host).Scan(&assetID); err != nil {
			t.Fatalf("read back the asset: %v", err)
		}
		mustExec(t, raw, `UPDATE assets SET asset_status = 'archived' WHERE tenant_id = $1 AND id = $2`, tenant, assetID)

		// It reappears on a segment whose auto-approval rule fires: the batch
		// asks for monitoring.
		report, err := svc.IngestFindingsReport(tenant,
			[]IngestFinding{effectiveStatusFinding(host, addr, 8443, hexFingerprint("archived-8443"))},
			identity.StatusMonitoring)
		if err != nil {
			t.Fatalf("IngestFindingsReport: %v", err)
		}

		var status string
		if err := db.QueryRow(
			`SELECT asset_status FROM assets WHERE tenant_id = $1 AND id = $2`, tenant, assetID).Scan(&status); err != nil {
			t.Fatalf("read asset status: %v", err)
		}
		if status != identity.StatusArchived {
			t.Errorf("the asset is %q; a discovery matching an auto-approval rule un-archived a device "+
				"the tenant retired, and nobody asked it to", status)
		}

		var onNewPort int
		if err := db.QueryRow(`
			SELECT count(*)
			  FROM crypto_implementations ci
			  JOIN asset_endpoints e ON e.tenant_id = ci.tenant_id AND e.id = ci.endpoint_id
			 WHERE ci.tenant_id = $1 AND ci.asset_id = $2 AND e.port = 8443 AND ci.deleted_at IS NULL`,
			tenant, assetID).Scan(&onNewPort); err != nil {
			t.Fatalf("count configurations: %v", err)
		}
		if onNewPort != 0 {
			t.Errorf("%d crypto configuration(s) materialized on a retired device", onNewPort)
		}

		var deferred int
		if err := db.QueryRow(`
			SELECT COALESCE(jsonb_array_length(metadata->'deferred_findings'), 0)
			  FROM assets WHERE tenant_id = $1 AND id = $2`, tenant, assetID).Scan(&deferred); err != nil {
			t.Fatalf("read deferred_findings: %v", err)
		}
		if deferred != 0 {
			t.Errorf("%d finding(s) were deferred onto an archived asset, where no approval will ever "+
				"replay them — the same dead end, one status over", deferred)
		}

		if len(report.EffectiveStatus) != 1 || report.EffectiveStatus[0] != identity.StatusArchived {
			t.Errorf("report says %v, want one %q — reporting monitoring would stamp the discovery row "+
				"as approved on the strength of a promotion that did not happen",
				report.EffectiveStatus, identity.StatusArchived)
		}
	})

	t.Run("a monitoring asset under a monitoring batch still materializes", func(t *testing.T) {
		// The polarity that guards against over-correcting: the corrective read
		// now runs on EVERY match, and it must not turn the ordinary path off.
		const host = "live-switch.example.test"
		const addr = "198.51.100.52"

		if _, err := svc.IngestFindings(tenant,
			[]IngestFinding{effectiveStatusFinding(host, addr, 443, hexFingerprint("live-443"))},
			identity.StatusMonitoring); err != nil {
			t.Fatalf("seeding the asset: %v", err)
		}
		report, err := svc.IngestFindingsReport(tenant,
			[]IngestFinding{effectiveStatusFinding(host, addr, 8443, hexFingerprint("live-8443"))},
			identity.StatusMonitoring)
		if err != nil {
			t.Fatalf("IngestFindingsReport: %v", err)
		}

		var assetID uuid.UUID
		if err := db.QueryRow(
			`SELECT id FROM assets WHERE tenant_id = $1 AND hostname = $2 AND deleted_at IS NULL`,
			tenant, host).Scan(&assetID); err != nil {
			t.Fatalf("read back the asset: %v", err)
		}
		var onNewPort int
		if err := db.QueryRow(`
			SELECT count(*)
			  FROM crypto_implementations ci
			  JOIN asset_endpoints e ON e.tenant_id = ci.tenant_id AND e.id = ci.endpoint_id
			 WHERE ci.tenant_id = $1 AND ci.asset_id = $2 AND e.port = 8443 AND ci.deleted_at IS NULL`,
			tenant, assetID).Scan(&onNewPort); err != nil {
			t.Fatalf("count configurations: %v", err)
		}
		if onNewPort == 0 {
			t.Errorf("no crypto configuration materialized on :8443 for a monitoring asset in a monitoring batch")
		}
		if len(report.EffectiveStatus) != 1 || report.EffectiveStatus[0] != identity.StatusMonitoring {
			t.Errorf("report says %v, want one %q", report.EffectiveStatus, identity.StatusMonitoring)
		}
	})
}
