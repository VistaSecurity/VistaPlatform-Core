package services

// Hop 3 of the scheduled-cloud chain (integrations review W14).
//
// Input: shared/deviceinterrogation/testdata/pipeline/cloud-aws-scheduled/
// hop2_handoff.golden.json — the import requests discovery-processor posted for
// two runs of the platform worker's SCHEDULED cloud discovery, whose rows hop 1
// wrote through the same writer the interactive run uses.
//
// Each run's requests are replayed through the import handler's decode
// (ClusterSensorFinding.ToIngestFinding) and IngestFindingsReport into a tenant
// in ENFORCE identity admission. The claim: the S3 bucket becomes one
// object_storage asset and the RDS instance one managed_database asset,
// established on the provider resource id, and the second run MATCHES both —
// no duplicate, nothing parked.
//
// Before W14 the scheduled path wrote no row at all for either resource, so
// this chain had nothing to carry; with rows but without the resource id
// (buildSensorDiscoveryMetadata's shape) enforce admission parks both as
// `no_device_or_address_binding` ('s mutation).
//
// Skips unless TEST_DATABASE_URL is set.

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/pipelinetest"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type cloudHop3Asset struct {
	ResourceID     string `json:"resource_id"`
	Class          string `json:"class"`
	IdentityStatus string `json:"identity_status"`
}

type cloudHop3Summary struct {
	// Outcomes are the ingest outcomes of each run, in finding order.
	Outcomes [][]string `json:"outcomes"`
	// Assets are the tenant's live assets after both runs.
	Assets []cloudHop3Asset `json:"assets"`
	// Parked counts observations enforce admission retained without an asset.
	Parked int `json:"parked"`
}

func TestIntegration_CloudScheduledPipeline_Hop3_EnforceAdmissionEstablishesAndMatches(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	dir := filepath.Join(pipelinetest.Dir(t, vendorPipelineDir), pipelinetest.CloudScheduledScenario)
	inputPath := filepath.Join(dir, pipelinetest.Hop2HandoffFile)
	goldenPath := filepath.Join(dir, pipelinetest.Hop3InventoryFile)
	if !*pipelinetest.UpdateGolden {
		var previous pipelinetest.Hop3Inventory
		pipelinetest.ReadJSON(t, goldenPath, &previous)
		pipelinetest.CheckInput(t, previous.InputSHA256, inputPath)
	}
	var hop2 pipelinetest.CloudHop2Handoff
	pipelinetest.ReadJSON(t, inputPath, &hop2)
	if len(hop2.Runs) != 2 {
		t.Fatalf("hop 2 handed over %d run(s), want 2", len(hop2.Runs))
	}

	tenant := testdb.NewTenant(t, raw)
	enforceIdentityAdmission(t, raw, tenant)
	svc := newCloudRoutingAssetService(db)
	sensor := platformInterrogationSensor(t, raw, tenant)
	integration := uuid.NewString()

	var summary cloudHop3Summary
	for runIndex, run := range hop2.Runs {
		pairs := []string{
			pipelinetest.PlaceholderTenantID, tenant.String(),
			pipelinetest.PlaceholderSensorID, sensor,
			pipelinetest.PlaceholderBatchID, uuid.NewString(),
			pipelinetest.PlaceholderIntegrationID, integration,
			// A day apart: enforce mode needs a time on every observation, and
			// the rediscovery is later than the first sighting.
			pipelinetest.PlaceholderTimestamp, fmt.Sprintf("2026-09-%02dT03:00:00Z", 28+runIndex),
		}
		for i := range run.Rows {
			pairs = append(pairs, fmt.Sprintf(pipelinetest.PlaceholderDiscoveryIDFormat, i), uuid.NewString())
		}
		var outcomes []string
		for _, req := range run.Imports {
			substituted := pipelinetest.Walk(pipelinetest.Canonical(t, req.Findings), pipelinetest.Replacer(pairs...))
			rawFindings, _ := json.Marshal(substituted)
			var wire []json.RawMessage
			if err := json.Unmarshal(rawFindings, &wire); err != nil {
				t.Fatalf("findings: %v", err)
			}
			findings := make([]IngestFinding, 0, len(wire))
			for _, one := range wire {
				var csf ClusterSensorFinding
				if err := json.Unmarshal(one, &csf); err != nil {
					t.Fatalf("a finding hop 2 posted does not decode as the handler decodes it: %v", err)
				}
				findings = append(findings, csf.ToIngestFinding())
			}
			// The pipeline import: inventory classifies and evaluates the
			// tenant's rules itself ( WP3).
			report, err := svc.IngestPipelineFindingsReport(tenant, findings)
			if err != nil {
				t.Fatalf("run %d: IngestPipelineFindingsReport: %v", runIndex, err)
			}
			for _, r := range report.Results {
				outcomes = append(outcomes, string(r.Outcome))
			}
		}
		summary.Outcomes = append(summary.Outcomes, outcomes)
	}

	rows, err := raw.Query(`SELECT i.value, a.class_key, a.identity_status
		FROM assets a JOIN asset_identifiers i ON i.tenant_id=a.tenant_id AND i.asset_id=a.id AND i.kind='cloud_resource_id'
		WHERE a.tenant_id=$1 AND a.deleted_at IS NULL ORDER BY i.value`, tenant)
	if err != nil {
		t.Fatalf("read assets: %v", err)
	}
	for rows.Next() {
		var a cloudHop3Asset
		if err := rows.Scan(&a.ResourceID, &a.Class, &a.IdentityStatus); err != nil {
			t.Fatal(err)
		}
		summary.Assets = append(summary.Assets, a)
	}
	_ = rows.Close()
	var live int
	if err := raw.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id=$1 AND deleted_at IS NULL`, tenant).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if err := raw.QueryRow(`SELECT count(*) FROM identity_observations WHERE tenant_id=$1 AND asset_id IS NULL`, tenant).Scan(&summary.Parked); err != nil {
		t.Fatal(err)
	}

	// The claims.
	want := map[string]string{
		"arn:aws:s3:::example-audit-logs":                 "object_storage",
		"arn:aws:rds:us-east-1:123456789012:db:orders-db": "managed_database",
	}
	if live != len(want) || len(summary.Assets) != len(want) {
		t.Fatalf("%d live asset(s), %d with a resource id; want exactly %d (observations parked: %d)", live, len(summary.Assets), len(want), summary.Parked)
	}
	for _, a := range summary.Assets {
		if want[a.ResourceID] != a.Class {
			t.Errorf("%s: class %q, want %q", a.ResourceID, a.Class, want[a.ResourceID])
		}
		if a.IdentityStatus != string(identity.IdentityEstablished) {
			t.Errorf("%s: identity_status %q, want established", a.ResourceID, a.IdentityStatus)
		}
	}
	second := append([]string(nil), summary.Outcomes[1]...)
	sort.Strings(second)
	if len(second) != len(want) || second[0] != string(identity.OutcomeMatched) || second[len(second)-1] != string(identity.OutcomeMatched) {
		t.Errorf("the rediscovery's outcomes are %v, want every resource matched", summary.Outcomes[1])
	}
	if summary.Parked != 0 {
		t.Errorf("%d observation(s) parked without an asset under enforce admission, want 0", summary.Parked)
	}

	pipelinetest.CompareGolden(t, goldenPath, pipelinetest.Hop3Inventory{
		Vendor:      pipelinetest.CloudScheduledScenario,
		InputSHA256: pipelinetest.Hash(t, inputPath),
		Inventory:   summary,
	})
}
