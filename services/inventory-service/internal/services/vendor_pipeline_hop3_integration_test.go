package services

// Hop 3 of the chained per-vendor pipeline test ( W0.2).
//
// Input: hop 2's golden (shared/deviceinterrogation/testdata/pipeline/<vendor>/
// hop2_handoff.golden.json) — the import requests discovery-processor posted,
// byte for byte. Each finding is decoded the way the import handler decodes it
// (ClusterSensorFinding → ToIngestFinding) and handed to the REAL
// IngestFindingsReport of an AssetService built by NewAssetService: the
// weak-crypto detector wired, the seeded algorithm catalogue, a real Postgres.
// The tenant then approves what the ingest put in Discovery → Approvals
// (ApproveAssets), which is what materializes a pending asset's deferred
// crypto, and the result is read back through GetCryptoImplementations, the
// read path the Inventory UI uses.
//
// Output: hop3_inventory.golden.json, a summary of the inventory, and the
// per-vendor claims in vendorPipelineHop3Claims.
//
// It also holds hop 2's one stand-in honest: hop 2 classifies addresses with
// a fake of inventory's classify-asset endpoint, and here the REAL
// NetworkSegmentService.ClassifyAsset, over the same segments, must agree
// with every answer it gave.
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/cryptoassess"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/pipelinetest"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const vendorPipelineDir = "../../../../shared/deviceinterrogation/testdata/pipeline"

// hop3Config is one crypto configuration as the Inventory UI reads it.
type hop3Config struct {
	Asset          string              `json:"asset"`
	Protocol       string              `json:"protocol"`
	Port           *int                `json:"port"`
	Version        *string             `json:"protocol_version"`
	CipherSuite    *string             `json:"cipher_suite"`
	KeyExchange    *string             `json:"key_exchange_algorithm"`
	Hash           *string             `json:"hash_algorithm"`
	KeySize        *int                `json:"key_size"`
	RiskScore      *int                `json:"risk_score"`
	RiskLevel      string              `json:"risk_level"`
	RiskFactors    []string            `json:"risk_factors"`
	Links          map[string][]string `json:"algorithm_links"`
	PQCCategory    string              `json:"pqc_category"`
	HasCertificate bool                `json:"has_certificate"`
}

type hop3Summary struct {
	Assets         []map[string]any `json:"assets"`
	Configurations []hop3Config     `json:"crypto_configurations"`
	Certificates   []map[string]any `json:"certificates"`
	Findings       []map[string]any `json:"findings"`
	PQC            map[string]int   `json:"pqc_counts"`
	IngestOutcomes []string         `json:"ingest_outcomes"`
}

func TestIntegration_VendorPipeline_Hop3_IngestPayloadToInventory(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	dir := pipelinetest.Dir(t, vendorPipelineDir)

	for _, vendor := range pipelinetest.Vendors {
		t.Run(vendor, func(t *testing.T) {
			s := pipelinetest.LoadScenario(t, dir, vendor)
			inputPath := filepath.Join(dir, vendor, pipelinetest.Hop2HandoffFile)
			goldenPath := filepath.Join(dir, vendor, pipelinetest.Hop3InventoryFile)
			if !*pipelinetest.UpdateGolden {
				var previous pipelinetest.Hop3Inventory
				pipelinetest.ReadJSON(t, goldenPath, &previous)
				pipelinetest.CheckInput(t, previous.InputSHA256, inputPath)
			}
			var hop2 pipelinetest.Hop2Handoff
			pipelinetest.ReadJSON(t, inputPath, &hop2)

			summary := ingestVendorHop2(t, db, s, hop2)
			out := pipelinetest.Hop3Inventory{Vendor: vendor, InputSHA256: pipelinetest.Hash(t, inputPath), Inventory: summary}
			pipelinetest.CompareGolden(t, goldenPath, out)

			claims := vendorPipelineHop3Claims(t, vendor, summary)
			if len(claims) == 0 {
				t.Fatalf("no hop-3 claims for %s", vendor)
			}
			pipelinetest.Expect(t, claims...)
			if gaps := pipelinetest.GapIDs(claims); len(gaps) > 0 {
				t.Logf("%s hop 3 holds %d known gap(s) open: %s", vendor, len(gaps), strings.Join(gaps, "; "))
			}
		})
	}
}

// ingestVendorHop2 replays hop 2's import requests into a fresh tenant and
// summarises the inventory that results.
func ingestVendorHop2(t *testing.T, db *database.DB, s pipelinetest.Scenario, hop2 pipelinetest.Hop2Handoff) hop3Summary {
	t.Helper()
	tenant := testdb.NewTenant(t, db.DB.DB)
	svc := NewAssetService(db)
	segments := NewNetworkSegmentService(db, nil)

	// The tenant as hop 1 left it: its registered networks and the segments
	// the interrogation learned.
	segmentIDs := map[string]uuid.UUID{}
	for _, seg := range s.TenantSegments {
		id := uuid.New()
		segmentIDs[seg.CIDR] = id
		if _, err := db.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment,is_active)
			VALUES($1,$2,$3,'cidr',$4,'production',true)`, id, tenant, seg.Name, seg.CIDR); err != nil {
			t.Fatalf("seed segment %s: %v", seg.CIDR, err)
		}
	}
	device := uuid.New()
	for _, seg := range hop2.LearnedSegments {
		meta := pipelinetest.Substitute(pipelinetest.Canonical(t, seg.Metadata), s.ManagementPort,
			pipelinetest.PlaceholderDeviceAssetID, device.String())
		metaJSON, _ := json.Marshal(meta)
		id := uuid.New()
		segmentIDs[seg.Value] = id
		if _, err := db.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,network_type,environment,is_active,metadata)
			VALUES($1,$2,$3,$4,$5,$6,'production',true,$7::jsonb)`,
			id, tenant, "Learned "+seg.Value, seg.SegmentType, seg.Value, seg.NetworkType, string(metaJSON)); err != nil {
			t.Fatalf("seed learned segment %s: %v", seg.Value, err)
		}
	}

	// The assets hop 1 left — the device and the peers its observations
	// created. They are rows of this same table in production, so a finding
	// about one of them lands on it here exactly as it would there.
	known := insertPipelineAssets(t, db, tenant, device, s, hop2.Assets, segmentIDs)

	// Findings name the tenant's platform device-interrogation sensor as their
	// collector, and ingest refuses one that is not the tenant's own — nor
	// one that is not platform-managed, when the finding claims its device.
	var sensor uuid.UUID
	if err := db.QueryRow(`SELECT id FROM sensors WHERE tenant_id = $1 AND profile = 'device_interrogation'
		AND platform_managed AND deleted_at IS NULL LIMIT 1`, tenant).Scan(&sensor); err != nil {
		t.Fatalf("the tenant has no platform device-interrogation sensor: %v", err)
	}
	// The device job hop 1 ran. Each finding names it (device_job_id), and
	// ingest honours a finding's claim on the device only when that job is a
	// real interrogation of exactly that device in this tenant.
	deviceJob := uuid.New()
	if _, err := db.Exec(`INSERT INTO device_jobs (id, tenant_id, job_type, asset_id, status)
		VALUES ($1, $2, 'device_interrogation', $3, 'completed')`, deviceJob, tenant, device); err != nil {
		t.Fatalf("seed the device job: %v", err)
	}
	pairs := []string{
		pipelinetest.PlaceholderDeviceAssetID, device.String(),
		pipelinetest.PlaceholderDeviceJobID, deviceJob.String(),
		pipelinetest.PlaceholderTenantID, tenant.String(),
		pipelinetest.PlaceholderSensorID, sensor.String(),
		pipelinetest.PlaceholderBatchID, uuid.NewString(),
		pipelinetest.PlaceholderTimestamp, "2026-09-24T12:00:00Z",
	}
	for i := range hop2.Rows {
		pairs = append(pairs, fmt.Sprintf(pipelinetest.PlaceholderDiscoveryIDFormat, i), uuid.NewString())
	}

	var outcomes []string
	for _, req := range hop2.Imports {
		substituted := pipelinetest.Substitute(pipelinetest.Canonical(t, req.Findings), s.ManagementPort, pairs...)
		rawFindings, _ := json.Marshal(substituted)
		var wire []json.RawMessage
		if err := json.Unmarshal(rawFindings, &wire); err != nil {
			t.Fatalf("findings: %v", err)
		}
		// Exactly what IngestPipelineFindings does with the request body.
		findings := make([]IngestFinding, 0, len(wire))
		for _, one := range wire {
			var csf ClusterSensorFinding
			if err := json.Unmarshal(one, &csf); err != nil {
				t.Fatalf("a finding hop 2 posted does not decode as the handler decodes it: %v", err)
			}
			f := csf.ToIngestFinding()
			// Hop 2 classified this address with a stand-in; the real
			// classifier must agree, or hop 2's golden describes a pipeline
			// that does not exist.
			said, _ := f.RawData["network_ownership"].(string)
			real, err := segments.ClassifyAsset(tenant, f.IPAddress, f.Hostname, nil)
			if err != nil {
				t.Fatalf("ClassifyAsset: %v", err)
			}
			if said != real {
				t.Errorf("hop 2's classify stand-in said %q for %v, the real classifier says %q", said, hop3Str(f.IPAddress), real)
			}
			findings = append(findings, f)
		}
		report, err := svc.IngestFindingsReport(tenant, findings, req.AssetStatus)
		if err != nil {
			t.Fatalf("IngestFindingsReport: %v", err)
		}
		for _, r := range report.Results {
			outcomes = append(outcomes, string(r.Outcome))
		}
	}

	// Discovery → Approvals → Approve: what turns a pending asset's deferred
	// crypto into configurations.
	var pending []uuid.UUID
	if err := db.Select(&pending, `SELECT id FROM assets WHERE tenant_id = $1 AND asset_status = 'pending_approval' AND deleted_at IS NULL ORDER BY id`, tenant); err != nil {
		t.Fatalf("pending assets: %v", err)
	}
	if err := svc.ApproveAssets(tenant, pending, uuid.Nil); err != nil {
		t.Fatalf("ApproveAssets: %v", err)
	}

	summary := summariseInventory(t, db, svc, tenant, known)
	if outcomes == nil {
		outcomes = []string{}
	}
	summary.IngestOutcomes = outcomes

	// Back to placeholders for the golden.
	var back []string
	for i := 0; i+1 < len(pairs); i += 2 {
		back = append(back, pairs[i+1], pairs[i])
	}
	var normalized hop3Summary
	if err := json.Unmarshal(pipelinetest.Marshal(t, pipelinetest.Walk(pipelinetest.Canonical(t, summary), pipelinetest.Replacer(back...))), &normalized); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return normalized
}

// insertPipelineAssets recreates hop 1's assets and their identifiers, with
// hop 1's placeholders (the appliance address, segment scopes) mapped onto
// this tenant. It returns each asset's hop-1 label by its new id.
func insertPipelineAssets(t *testing.T, db *database.DB, tenant, device uuid.UUID, s pipelinetest.Scenario, records []pipelinetest.AssetRecord, segmentIDs map[string]uuid.UUID) map[uuid.UUID]string {
	t.Helper()
	if len(records) == 0 || records[0].Label != "device" {
		t.Fatalf("hop 1 handed over no device asset first: %+v", records)
	}
	resolve := func(v string) string {
		return strings.ReplaceAll(v, pipelinetest.PlaceholderApplianceIP, s.ManagementIP)
	}
	// Hop 1's fake listened on loopback, which is in no segment, so the
	// device's address was scoped tenant-wide there. At its scenario address
	// it IS in a segment, and CreateDevice scopes an address to the segment
	// that contains it — so that is the scope it gets here.
	applianceScope := ""
	if seg, err := NewNetworkSegmentService(db, nil).GetSegmentForIP(tenant, &s.ManagementIP, nil); err != nil {
		t.Fatalf("segment for %s: %v", s.ManagementIP, err)
	} else if seg != nil {
		applianceScope = seg.ID.String()
	}
	labels := map[uuid.UUID]string{}
	for i, rec := range records {
		id := uuid.New()
		if i == 0 {
			id = device
		}
		labels[id] = rec.Label
		class, ok := assetclass.Get(rec.ClassKey)
		if !ok {
			t.Fatalf("hop 1 asset %s has unknown class %q", rec.Label, rec.ClassKey)
		}
		var address, hostname *string
		if rec.PrimaryAddress != nil {
			a := resolve(*rec.PrimaryAddress)
			address = &a
		}
		if rec.Hostname != "" {
			h := rec.Hostname
			hostname = &h
		}
		if _, err := db.Exec(`
			INSERT INTO assets (id, tenant_id, hostname, display_name, primary_address, class_key, class_path, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
			VALUES ($1, $2, $3, $3, $4::inet, $5, $6, 'pending_approval', NOW(), NOW(), NOW(), NOW())`,
			id, tenant, hostname, address, rec.ClassKey, class.Path); err != nil {
			t.Fatalf("insert asset %s: %v", rec.Label, err)
		}
		for _, ident := range rec.Identifiers {
			var scope *string
			if ident.Kind == "ip_address" && ident.Value == pipelinetest.PlaceholderApplianceIP && applianceScope != "" {
				scope = &applianceScope
			} else if ident.Scope != nil {
				sc := *ident.Scope
				if cidr, ok := strings.CutPrefix(sc, "segment:"); ok {
					segID, known := segmentIDs[cidr]
					if !known {
						t.Fatalf("%s identifier scoped to segment %s, which this tenant does not have", rec.Label, cidr)
					}
					sc = segID.String()
				}
				scope = &sc
			}
			if _, err := db.Exec(`INSERT INTO asset_identifiers (tenant_id, asset_id, kind, value, scope, source_kind)
				VALUES ($1, $2, $3, $4, $5, $6)`, tenant, id, ident.Kind, resolve(ident.Value), scope, ident.SourceKind); err != nil {
				t.Fatalf("insert %s identifier %s=%s: %v", rec.Label, ident.Kind, ident.Value, err)
			}
		}
	}
	return labels
}

func hop3Str(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

// summariseInventory reads the tenant's inventory the way a tenant sees it.
func summariseInventory(t *testing.T, db *database.DB, svc *AssetService, tenant uuid.UUID, known map[uuid.UUID]string) hop3Summary {
	t.Helper()
	var out hop3Summary

	type assetRow struct {
		ID       uuid.UUID      `db:"id"`
		Hostname sql.NullString `db:"hostname"`
		Address  sql.NullString `db:"address"`
		Class    string         `db:"class_key"`
		Status   string         `db:"asset_status"`
	}
	var assets []assetRow
	if err := db.Select(&assets, `SELECT id, hostname, host(primary_address) AS address, class_key, asset_status::text AS asset_status
		FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant); err != nil {
		t.Fatalf("assets: %v", err)
	}
	labels := map[uuid.UUID]string{}
	for _, a := range assets {
		// An asset hop 1 left keeps its hop-1 label; one this ingest created
		// is marked new, so the golden says whether a finding landed on an
		// existing asset or minted another.
		label, existed := known[a.ID]
		if !existed {
			label = "new[" + a.Hostname.String + "|" + a.Address.String + "]"
		}
		labels[a.ID] = label
		out.Assets = append(out.Assets, map[string]any{"asset": label, "class_key": a.Class, "status": a.Status})
	}

	categories := pqcCategoriesByImplementation(t, db, tenant)
	for _, a := range assets {
		impls, err := svc.GetCryptoImplementations(tenant, a.ID)
		if err != nil {
			t.Fatalf("GetCryptoImplementations: %v", err)
		}
		for _, ci := range impls {
			c := hop3Config{
				Asset: labels[a.ID], Protocol: ci.Protocol, Version: ci.ProtocolVersion, CipherSuite: ci.CipherSuite,
				KeyExchange: ci.KeyExchangeAlgorithm, Hash: ci.HashAlgorithm, KeySize: ci.KeySize,
				RiskScore: ci.RiskScore, RiskLevel: ci.RiskLevel, RiskFactors: ci.RiskFactors,
				PQCCategory: categories[ci.ID], HasCertificate: ci.CertificateID != nil,
				Links: map[string][]string{},
			}
			if c.RiskFactors == nil {
				c.RiskFactors = []string{}
			}
			var port sql.NullInt64
			_ = db.QueryRow(`SELECT e.port FROM crypto_implementations ci JOIN asset_endpoints e ON e.tenant_id = ci.tenant_id AND e.id = ci.endpoint_id
				WHERE ci.tenant_id = $1 AND ci.id = $2`, tenant, ci.ID).Scan(&port)
			if port.Valid {
				p := int(port.Int64)
				c.Port = &p
			}
			rows, err := db.Query(`SELECT cia.algorithm_type, a.code FROM crypto_implementation_algorithms cia
				JOIN algorithms a ON a.id = cia.algorithm_id WHERE cia.crypto_implementation_id = $1 ORDER BY 1, 2`, ci.ID)
			if err != nil {
				t.Fatalf("links: %v", err)
			}
			for rows.Next() {
				var role, code string
				if err := rows.Scan(&role, &code); err != nil {
					t.Fatalf("scan link: %v", err)
				}
				c.Links[role] = append(c.Links[role], code)
			}
			_ = rows.Close()
			out.Configurations = append(out.Configurations, c)
		}
	}
	sort.Slice(out.Configurations, func(i, j int) bool {
		a, _ := json.Marshal(out.Configurations[i])
		b, _ := json.Marshal(out.Configurations[j])
		return string(a) < string(b)
	})

	// A certificate belongs to an asset through the configuration that
	// presents it.
	certs, err := db.Query(`
		SELECT c.subject_dn, c.fingerprint_sha256, ci.asset_id
		  FROM certificates c
		  LEFT JOIN crypto_implementations ci
		         ON ci.tenant_id = c.tenant_id AND ci.certificate_id = c.id AND ci.deleted_at IS NULL
		 WHERE c.tenant_id = $1`, tenant)
	if err != nil {
		t.Fatalf("certificates: %v", err)
	}
	for certs.Next() {
		var subject, fp string
		var asset uuid.NullUUID
		if err := certs.Scan(&subject, &fp, &asset); err != nil {
			t.Fatalf("scan certificate: %v", err)
		}
		label := ""
		if asset.Valid {
			label = labels[asset.UUID]
		}
		out.Certificates = append(out.Certificates, map[string]any{"subject_dn": subject, "fingerprint_sha256": fp, "asset": label})
	}
	_ = certs.Close()

	findings, err := db.Query(`SELECT producer, kind, severity, summary FROM findings WHERE tenant_id = $1`, tenant)
	if err != nil {
		t.Fatalf("findings: %v", err)
	}
	for findings.Next() {
		var producer, kind, severity, summary string
		if err := findings.Scan(&producer, &kind, &severity, &summary); err != nil {
			t.Fatalf("scan finding: %v", err)
		}
		out.Findings = append(out.Findings, map[string]any{"producer": producer, "kind": kind, "severity": severity, "summary": summary})
	}
	_ = findings.Close()

	counts, err := classifyTenantImplementationsPQC(db, tenant)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	out.PQC = map[string]int{
		"total": counts.Total, "needs_migration": counts.NeedsMigration, "pqc_ready": counts.PQCReady,
		"symmetric_safe": counts.SymmetricSafe, "unclassified": counts.Unclassified,
	}
	// The per-configuration categories must partition the same population
	// the tenant-wide classifier counts, or they are a second opinion.
	tally := map[string]int{"total": 0, "needs_migration": 0, "pqc_ready": 0, "symmetric_safe": 0, "unclassified": 0}
	for _, c := range categories {
		tally[c]++
		tally["total"]++
	}
	if !pipelinetest.Equal(t, tally, out.PQC) {
		t.Errorf("per-configuration PQC categories %v disagree with classifyTenantImplementationsPQC %v", tally, out.PQC)
	}

	for _, list := range []*[]map[string]any{&out.Assets, &out.Certificates, &out.Findings} {
		if *list == nil {
			*list = []map[string]any{}
		}
		l := *list
		sort.Slice(l, func(i, j int) bool {
			a, _ := json.Marshal(l[i])
			b, _ := json.Marshal(l[j])
			return string(a) < string(b)
		})
	}
	if out.Configurations == nil {
		out.Configurations = []hop3Config{}
	}
	return out
}

// pqcCategoriesByImplementation is classifyTenantImplementationsPQC's own CTE
// and precedence (pqcPartitionSQL), per configuration instead of counted.
func pqcCategoriesByImplementation(t *testing.T, db *database.DB, tenant uuid.UUID) map[uuid.UUID]string {
	t.Helper()
	query := `WITH ` + cryptoassess.PQCClassCTE(MonitoredConfigurationsSQL, "$2", "$3") + `
		SELECT impl_id,
		       CASE WHEN vulnerable THEN 'needs_migration'
		            WHEN has_pqc THEN 'pqc_ready'
		            WHEN known > 0 AND unknown = 0 THEN 'symmetric_safe'
		            ELSE 'unclassified' END
		  FROM impl_class`
	out := map[uuid.UUID]string{}
	err := database.WithTenantTx(context.Background(), db, tenant, func(tx *sqlx.Tx) error {
		rows, err := tx.Query(query, tenant, pq.Array(pqcComponentRoles), pq.Array(quantumVulnerablePrimitives))
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id uuid.UUID
			var category string
			if err := rows.Scan(&id, &category); err != nil {
				return err
			}
			out[id] = category
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatalf("PQC categories: %v", err)
	}
	return out
}
