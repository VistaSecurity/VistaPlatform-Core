package services

// A cloud discovery must never leave its ingestion-queue row `pending` when the
// asset it landed on needs no approval decision ( slice F, owner decision
// D7).
//
// What went wrong on the demo host. A cloud discovery wrote six
// `sensor_discoveries` rows; all six were still `approval_status = 'pending'`
// days later, with no pending ASSET anywhere for a human to approve — Discovery
// → Approvals lists pending assets, not pending discoveries — and no user
// action that could clear them. Two different faults produced that one symptom:
//
//   - the two CloudFront rows were routed to `external_connections` by ingest
//     (a CDN necessarily has a public address), so they landed on no asset at
//     all and `EffectiveStatus` was empty for them, which discovery-processor
//     reads as "leave the row alone";
//   - the four S3 rows DID land on assets — ingest created them — but as
//     `pending_approval`, which was honest at that instant. Ninety seconds
//     later an operator approved the assets, and nothing told the queue rows.
//
// This file pins the first half: an ingest that lands on a `monitoring` asset
// must SAY `monitoring`, for both cloud shapes — the at-rest bucket with no
// address and the CDN with a routable one. adoptEffectiveStatus then turns that
// into `auto_approved` on the row (pinned in discovery-processor-service's
// import_chunking_test.go).
//
// The second half — the approval that arrives afterwards — is pinned by
// TestIntegration_ApprovalSettlesItsDiscoveryQueueRows below.
//
// Mutations that prove these tests:
//
//	delete `effective[i] = assetStatus` from the withResolvedAssetLifecycle
//	callback in IngestFindingsReport  → both status assertions go red
//	delete `isTenantOwnedCloudResource(f)` from the ownership override
//	                                   → the CDN case goes red (routed again)
//	delete the settleDiscoveryQueueRows call from ApproveAssets / DenyAssets
//	                                   → the settle test goes red
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// cloudBucketFinding is the shape the S3 at-rest collector emits: a per-resource
// hostname, the documented 0.0.0.0 placeholder for a resource that is not on a
// network, no port and no protocol, and the ARN as the resource's real
// identifier.
func cloudBucketFinding(bucket, integrationID string) IngestFinding {
	host, ip, port := bucket, "0.0.0.0", 0
	return IngestFinding{
		Hostname:  &host,
		IPAddress: &ip,
		Port:      &port,
		AssetType: "object_storage",
		RawData: map[string]interface{}{
			"source":                "cloud_discovery",
			"discovery_method":      "cloud_api",
			"integration_id":        integrationID,
			"cloud_provider":        "aws",
			"cloud_region":          "us-east-1",
			"device_type":           "aws_s3_bucket",
			"resource_type":         "s3_bucket",
			"arn":                   "arn:aws:s3:::" + bucket,
			"at_rest":               true,
			"encrypted":             true,
			"encryption_determined": true,
			"encryption_type":       "sse-s3",
			"algorithm":             "AES-256",
		},
	}
}

// cloudDistributionFinding is the CloudFront shape: a real, routable, PUBLIC
// address, which is what used to send it to external_connections.
func cloudDistributionFinding(hostname, ip, integrationID string) IngestFinding {
	host, addr, port := hostname, ip, 443
	version := "TLS 1.3"
	suite := "TLS_AES_128_GCM_SHA256"
	return IngestFinding{
		Hostname:        &host,
		IPAddress:       &addr,
		Port:            &port,
		AssetType:       "cdn",
		Protocol:        "TLS",
		ProtocolVersion: &version,
		CipherSuite:     &suite,
		RawData: map[string]interface{}{
			"source":           "cloud_discovery",
			"discovery_method": "cloud_api",
			"integration_id":   integrationID,
			"cloud_provider":   "aws",
			"cloud_region":     "us-east-1",
			"device_type":      "aws_cloudfront",
			"distribution_id":  "E00000000000AA",
		},
	}
}

func TestIntegration_CloudFindingOnMonitoringAsset_ReportsMonitoring(t *testing.T) {
	integrationID := uuid.NewString()

	cases := []struct {
		name    string
		finding func() IngestFinding
		// externalsAfter is how many external_connections rows the tenant
		// should have once both ingests have run. Zero for both: a resource
		// reached through the tenant's own cloud credential is theirs.
		externalsAfter int
		hostname       string
	}{
		{
			name:           "at-rest bucket with no address",
			finding:        func() IngestFinding { return cloudBucketFinding("example-bucket-123456789012", integrationID) },
			externalsAfter: 0,
			hostname:       "example-bucket-123456789012",
		},
		{
			name: "CDN distribution with a routable public address",
			finding: func() IngestFinding {
				return cloudDistributionFinding("d00000000000aa.example.net", "203.0.113.61", integrationID)
			},
			externalsAfter: 0,
			hostname:       "d00000000000aa.example.net",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := testdb.Connect(t)
			testdb.ApplySchemaAndSeed(t, raw)
			db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
			tenant := testdb.NewTenant(t, raw)
			svc := newCloudRoutingAssetService(db)

			// The resource as the tenant already has it: discovered by an
			// earlier run and since approved.
			if _, err := svc.IngestFindings(tenant, []IngestFinding{tc.finding()}, identity.StatusMonitoring); err != nil {
				t.Fatalf("seeding the monitoring asset: %v", err)
			}

			var assetID uuid.UUID
			var status string
			if err := raw.QueryRow(
				`SELECT id, asset_status FROM assets WHERE tenant_id = $1 AND hostname = $2 AND deleted_at IS NULL`,
				tenant, tc.hostname).Scan(&assetID, &status); err != nil {
				t.Fatalf("the cloud resource did not become an asset: %v", err)
			}
			if status != identity.StatusMonitoring {
				t.Fatalf("the fixture asset is %q, not %q — every assertion below would be about the wrong thing",
					status, identity.StatusMonitoring)
			}

			// The next run of the same discovery. No auto-approval rule matches
			// anything reached through a cloud API (the tenant's rules are
			// scoped to sensors and private segments), so the batch asks for
			// pending_approval — exactly the six rows' situation.
			report, err := svc.IngestFindingsReport(tenant, []IngestFinding{tc.finding()}, identity.StatusPendingApproval)
			if err != nil {
				t.Fatalf("IngestFindingsReport: %v", err)
			}

			if len(report.EffectiveStatus) != 1 {
				t.Fatalf("report carries %d per-finding statuses, want 1", len(report.EffectiveStatus))
			}
			if report.EffectiveStatus[0] != identity.StatusMonitoring {
				t.Fatalf("EffectiveStatus = %q, want %q — discovery-processor stamps the queue row from this, "+
					"and anything but %q leaves the row `pending` with nothing that can ever clear it",
					report.EffectiveStatus[0], identity.StatusMonitoring, identity.StatusMonitoring)
			}

			if len(report.Results) != 1 || report.Results[0].AssetID != assetID.String() {
				t.Fatalf("results = %+v, want one naming asset %s — the queue row's asset_id is read from this",
					report.Results, assetID)
			}

			if n := countExternalConnections(t, raw, tenant); n != tc.externalsAfter {
				t.Fatalf("%d external_connections row(s), want %d — a resource enumerated through the "+
					"tenant's own cloud credential is theirs, whatever its address", n, tc.externalsAfter)
			}

			var assets int
			if err := raw.QueryRow(
				`SELECT count(*) FROM assets WHERE tenant_id = $1 AND hostname = $2 AND deleted_at IS NULL`,
				tenant, tc.hostname).Scan(&assets); err != nil {
				t.Fatalf("count assets: %v", err)
			}
			if assets != 1 {
				t.Fatalf("%d assets for %s, want 1 — the second observation did not MATCH, so this test is "+
					"no longer exercising the case it exists for", assets, tc.hostname)
			}
		})
	}
}

// insertQueueRow writes one PROCESSED, `pending` ingestion-queue row pointing at
// assetID — the state discovery-processor leaves behind when the finding landed
// on an asset that was still awaiting approval.
func insertQueueRow(t *testing.T, db *database.DB, tenant, assetID uuid.UUID, hostname string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := db.Exec(`
		INSERT INTO sensor_discoveries (
			id, sensor_id, tenant_id, batch_id, protocol, dest_ip, port,
			confidence, metadata, hostname, processed_at, approval_status, asset_id
		) VALUES ($1, $2, $3, $4, '', '0.0.0.0'::inet, 0, 1.0,
			'{"discovery_method":"cloud_api","at_rest":true}'::jsonb, $5, now(), 'pending', $6)`,
		id, uuid.New(), tenant, "batch-"+id.String(), hostname, assetID)
	if err != nil {
		t.Fatalf("insert queue row: %v", err)
	}
	return id
}

func queueRowStatus(t *testing.T, db *database.DB, tenant, id uuid.UUID) string {
	t.Helper()
	var status string
	if err := db.QueryRow(`SELECT approval_status FROM sensor_discoveries WHERE tenant_id = $1 AND id = $2`,
		tenant, id).Scan(&status); err != nil {
		t.Fatalf("read queue row %s: %v", id, err)
	}
	return status
}

// The other half of D7: a row that was `pending` HONESTLY — its asset really was
// awaiting a human — must be settled when that human answers.
//
// This is what actually stranded the four S3 rows. Their assets were created
// `pending_approval` by the same ingest that wrote the rows, so `pending` was
// the truth; the operator then bulk-approved 68 assets and nothing wrote back to
// the queue. `EffectiveStatus` cannot fix that: it answers at ingest time, and
// the decision had not been made yet.
func TestIntegration_ApprovalSettlesItsDiscoveryQueueRows(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := newCloudRoutingAssetService(db)

	integrationID := uuid.NewString()

	// Two buckets, both arriving as pending assets — the first run's state.
	approved := cloudBucketFinding("settle-approved-123456789012", integrationID)
	denied := cloudBucketFinding("settle-denied-123456789012", integrationID)
	if _, err := svc.IngestFindings(tenant, []IngestFinding{approved, denied}, identity.StatusPendingApproval); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	assetOf := func(hostname string) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		var status string
		if err := raw.QueryRow(
			`SELECT id, asset_status FROM assets WHERE tenant_id = $1 AND hostname = $2 AND deleted_at IS NULL`,
			tenant, hostname).Scan(&id, &status); err != nil {
			t.Fatalf("read asset %q: %v", hostname, err)
		}
		if status != identity.StatusPendingApproval {
			t.Fatalf("fixture asset %q is %q, want %q", hostname, status, identity.StatusPendingApproval)
		}
		return id
	}

	approvedAsset := assetOf("settle-approved-123456789012")
	deniedAsset := assetOf("settle-denied-123456789012")

	approvedRow := insertQueueRow(t, db, tenant, approvedAsset, "settle-approved-123456789012")
	deniedRow := insertQueueRow(t, db, tenant, deniedAsset, "settle-denied-123456789012")
	// A row on an asset nobody decides about in this test. It must stay
	// `pending`: a settle that moved every row would be a check that cannot
	// fail, and would claim decisions nobody made.
	untouchedAsset := uuid.New()
	untouchedRow := insertQueueRow(t, db, tenant, untouchedAsset, "settle-untouched-123456789012")

	if err := svc.ApproveAssets(tenant, []uuid.UUID{approvedAsset}, uuid.New()); err != nil {
		t.Fatalf("ApproveAssets: %v", err)
	}
	if err := svc.DenyAssets(tenant, []uuid.UUID{deniedAsset}, uuid.New()); err != nil {
		t.Fatalf("DenyAssets: %v", err)
	}

	if got := queueRowStatus(t, db, tenant, approvedRow); got != "auto_approved" {
		t.Errorf("the approved asset's queue row is %q, want %q — the row that produced an asset the tenant "+
			"has now approved is not awaiting anything, and nothing else will ever clear it", got, "auto_approved")
	}
	if got := queueRowStatus(t, db, tenant, deniedRow); got != "suppressed" {
		t.Errorf("the denied asset's queue row is %q, want %q — nothing was materialized and no approval "+
			"decision will ever follow", got, "suppressed")
	}
	if got := queueRowStatus(t, db, tenant, untouchedRow); got != "pending" {
		t.Errorf("a queue row for an asset nobody decided about is %q, want %q", got, "pending")
	}

	// The approval must not credit a rule that never fired.
	var ruleID *uuid.UUID
	if err := db.QueryRow(`SELECT auto_approval_rule_id FROM sensor_discoveries WHERE tenant_id = $1 AND id = $2`,
		tenant, approvedRow).Scan(&ruleID); err != nil {
		t.Fatalf("read auto_approval_rule_id: %v", err)
	}
	if ruleID != nil {
		t.Errorf("auto_approval_rule_id = %v, want NULL — no auto-approval rule matched this row", *ruleID)
	}
}
