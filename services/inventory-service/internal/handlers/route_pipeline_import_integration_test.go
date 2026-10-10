package handlers

// The discovery import is the one place a sensor discovery is classified,
// auto-approved and — when it is third party — written to external_connections
// ( WP3, F2 + F16). These tests drive the REAL import handler
// (IngestPipelineFindings) over a real Postgres, with the services wired the
// way cmd/main.go wires them, so the wiring is what is tested:
//
//   - a third-party finding becomes exactly ONE external_connections row
//     carrying the certificate quality set and the destination name with its
//     provenance;
//   - a third-party finding with no source address is dropped with a counted,
//     reported reason, and never stored with source 0.0.0.0 (D2);
//   - the tenant's auto-approval rules are evaluated HERE, against this
//     service's classification, and the matching rule is reported per finding;
//   - a status the caller sends is not read.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const routeImportPath = "/api/v1/inventory-service/discovery/jobs/%s/import"

// routePipelineFixture is the import handler over a real database, with the
// asset service wired as cmd/main.go wires it: segment classification and the
// external-connections writer both present. Without the segment service every
// finding classifies "unknown" and no third-party assertion below could fail.
type routePipelineFixture struct {
	engine *gin.Engine
	raw    *sql.DB
	segSvc *services.NetworkSegmentService
	tenant uuid.UUID
}

func newRoutePipelineFixture(t *testing.T) *routePipelineFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	segSvc := services.NewNetworkSegmentService(db, services.NewLocationService(db))
	assets := services.NewAssetService(db)
	assets.SetEnrichmentServices(segSvc, nil)
	assets.SetExternalConnectionsService(services.NewExternalConnectionsService(db, services.NewAlgorithmService(db)))

	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1")
	grp.Use(func(c *gin.Context) {
		// What RequireJWTAuth leaves on an HMAC-verified service call.
		c.Set("tenantID", tenant)
		c.Set(sharedmw.CtxKeyIsInternalCall, true)
		c.Next()
	})
	grp.POST("/inventory-service/discovery/jobs/:id/import", NewDiscoveryHandler(assets, nil).IngestPipelineFindings)
	return &routePipelineFixture{engine: r, raw: raw, segSvc: segSvc, tenant: tenant}
}

// routeImportResponse is the import handler's response shape.
type routeImportResponse struct {
	Imported      int                     `json:"imported"`
	AssetStatuses []string                `json:"asset_statuses"`
	Results       []identity.IngestResult `json:"results"`
}

// importBody posts a raw body to the real import route.
func (f *routePipelineFixture) importBody(t *testing.T, body map[string]interface{}) routeImportResponse {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	path := strings.Replace(routeImportPath, "%s", uuid.NewString(), 1)
	w := do(f.engine, http.MethodPost, path, bytes.NewReader(b))
	if w.Code != http.StatusOK {
		t.Fatalf("import returned %d: %s", w.Code, w.Body.String())
	}
	var resp routeImportResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode import response: %v (%s)", err, w.Body.String())
	}
	if len(resp.Results) != len(body["findings"].([]interface{})) {
		t.Fatalf("results = %d for %d findings: %s", len(resp.Results), len(body["findings"].([]interface{})), w.Body.String())
	}
	return resp
}

func (f *routePipelineFixture) importFindings(t *testing.T, findings ...map[string]interface{}) routeImportResponse {
	t.Helper()
	list := make([]interface{}, len(findings))
	for i := range findings {
		list[i] = findings[i]
	}
	return f.importBody(t, map[string]interface{}{"findings": list})
}

// routeFinding is one finding in discovery-processor's wire shape
// (converter.IngestFinding), as the converter produces it for a sensor row.
func routeFinding(ip, hostname string, raw map[string]interface{}) map[string]interface{} {
	rawData := map[string]interface{}{
		"source":           "sensor_discovery",
		"discovery_method": "passive",
		"confidence":       0.9,
		"sensor_id":        uuid.NewString(),
	}
	for k, v := range raw {
		rawData[k] = v
	}
	f := map[string]interface{}{
		"ip_address":       ip,
		"port":             443,
		"asset_type":       "server",
		"protocol":         "TLS",
		"protocol_version": "TLS 1.2",
		"cipher_suite":     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"raw_data":         rawData,
	}
	if hostname != "" {
		f["hostname"] = hostname
	}
	return f
}

type routeExternalRow struct {
	sourceIP, destHostname, destKind, validation, sctSource sql.NullString
	hygiene                                                 pq.StringArray
}

func (f *routePipelineFixture) externalRows(t *testing.T) []routeExternalRow {
	t.Helper()
	rows, err := f.raw.Query(`SELECT host(source_ip), dest_hostname, dest_hostname_source_kind, cert_validation_status,
		cert_sct_source, cert_hygiene_flags
		FROM external_connections WHERE tenant_id = $1`, f.tenant)
	if err != nil {
		t.Fatalf("read external_connections: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []routeExternalRow
	for rows.Next() {
		var r routeExternalRow
		if err := rows.Scan(&r.sourceIP, &r.destHostname, &r.destKind, &r.validation, &r.sctSource, &r.hygiene); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func routeContains(list []string, substr string) bool {
	for _, s := range list {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

// One third-party finding, one row, the full quality set — the flags the
// processor's deleted writer used to carry and this writer did not.
func TestIntegration_RoutePipelineImport_ThirdPartyRowCarriesQualityFlags(t *testing.T) {
	f := newRoutePipelineFixture(t)

	resp := f.importFindings(t, routeFinding("203.0.113.80", "edge-203-0-113-80.vendor.example", map[string]interface{}{
		"source_ip": "10.1.2.3",
		// The processor's PTR fill stamps this; the writer must keep it.
		"dest_hostname_source_kind": "inferred",
		"certificates": []interface{}{map[string]interface{}{
			"chain_order": 0, "subject_dn": "CN=api.vendor.example", "issuer_dn": "CN=Vendor CA",
			"fingerprint_sha256": "aa11", "serial_number": "01",
		}},
		"cert_validation_status": "expired",
		"cert_has_sct":           false,
		"cert_sct_source":        "none",
		"cert_known_bad_ca":      "Superfish",
		"cert_is_ev":             true,
		"ocsp_status":            "revoked",
	}))
	if got := resp.Results[0].Outcome; got != "routed" {
		t.Fatalf("outcome = %q, want routed: a third-party finding goes to external_connections", got)
	}

	rows := f.externalRows(t)
	if len(rows) != 1 {
		t.Fatalf("external_connections rows = %d, want exactly 1 (one writer)", len(rows))
	}
	r := rows[0]
	if r.sourceIP.String != "10.1.2.3" {
		t.Errorf("source_ip = %q", r.sourceIP.String)
	}
	if r.destHostname.String != "edge-203-0-113-80.vendor.example" || r.destKind.String != "inferred" {
		t.Errorf("dest hostname/provenance = %q/%q, want the PTR name labelled inferred", r.destHostname.String, r.destKind.String)
	}
	if r.validation.String != "expired" {
		t.Errorf("cert_validation_status = %q, want expired", r.validation.String)
	}
	if r.sctSource.String != "none" {
		t.Errorf("cert_sct_source = %q, want none", r.sctSource.String)
	}
	// cert_has_sct=false is persisted as a hygiene flag; it must arrive as
	// false, not as absent.
	if !routeContains(r.hygiene, "Signed Certificate Timestamps") {
		t.Errorf("cert_hygiene_flags = %v: cert_has_sct=false did not arrive as false", r.hygiene)
	}
	// Known-bad CA and OCSP revocation are recorded with the certificate
	// observations too (ExternalConnectionsService.assessCrypto).
	if !routeContains(r.hygiene, "known-bad CA: Superfish") {
		t.Errorf("cert_hygiene_flags = %v: cert_known_bad_ca lost", r.hygiene)
	}
	if !routeContains(r.hygiene, "revoked (OCSP)") {
		t.Errorf("cert_hygiene_flags = %v: ocsp_status lost", r.hygiene)
	}
}

// D2: a third-party finding with no source address is dropped, counted and
// reported — never written with the 0.0.0.0 that used to fill the upsert key.
func TestIntegration_RoutePipelineImport_ThirdPartyWithoutSourceIsDropped(t *testing.T) {
	f := newRoutePipelineFixture(t)

	resp := f.importFindings(t, routeFinding("203.0.113.81", "api.vendor.example", nil))
	res := resp.Results[0]
	if res.Outcome != "dropped" || res.Reason != "third_party_no_source_ip" {
		t.Fatalf("result = %+v, want outcome dropped with reason third_party_no_source_ip", res)
	}
	if n := len(f.externalRows(t)); n != 0 {
		t.Fatalf("external_connections rows = %d, want 0: a connection record needs both ends", n)
	}
	var zero int
	if err := f.raw.QueryRow(`SELECT COUNT(*) FROM external_connections WHERE tenant_id = $1 AND source_ip = '0.0.0.0'::inet`, f.tenant).Scan(&zero); err != nil {
		t.Fatal(err)
	}
	if zero != 0 {
		t.Fatalf("%d row(s) stored with source 0.0.0.0", zero)
	}
}

// routeSegmentWithAutoApproval registers a CIDR segment that auto-approves
// sensor discoveries and regenerates the tenant's rules — what Settings →
// Infrastructure → Network Segments does on save.
func (f *routePipelineFixture) routeSegmentWithAutoApproval(t *testing.T, cidr string) *models.NetworkSegment {
	t.Helper()
	on := true
	seg, err := f.segSvc.Create(f.tenant, models.NetworkSegmentInput{
		Name: "Route test " + cidr, SegmentType: "cidr", Value: cidr, NetworkType: "private",
		Environment: "production", AutoApproveDiscoveries: &on,
		AutoApproveSources: []string{models.AutoApproveSourceSensor},
	})
	if err != nil {
		t.Fatalf("create segment %s: %v", cidr, err)
	}
	if err := f.segSvc.ManageAutoApprovalRules(f.tenant, uuid.Nil); err != nil {
		t.Fatalf("regenerate auto-approval rules: %v", err)
	}
	return seg
}

// The rules run here now. Both polarities in one import: a finding inside the
// auto-approving segment lands monitoring and names its rule; one outside it
// lands pending and names none.
func TestIntegration_RoutePipelineImport_EvaluatesAutoApprovalRules(t *testing.T) {
	f := newRoutePipelineFixture(t)
	f.routeSegmentWithAutoApproval(t, "10.20.0.0/16")

	resp := f.importFindings(t,
		routeFinding("10.20.1.5", "inside.corp.example", nil),
		routeFinding("10.99.1.5", "outside.corp.example", nil),
	)
	if resp.AssetStatuses[0] != "monitoring" {
		t.Errorf("finding in the auto-approving segment landed %q, want monitoring", resp.AssetStatuses[0])
	}
	if _, err := uuid.Parse(resp.Results[0].AutoApprovalRuleID); err != nil {
		t.Errorf("auto_approval_rule_id = %q, want the segment's rule", resp.Results[0].AutoApprovalRuleID)
	}
	if resp.AssetStatuses[1] != "pending_approval" {
		t.Errorf("finding outside every segment landed %q, want pending_approval", resp.AssetStatuses[1])
	}
	if resp.Results[1].AutoApprovalRuleID != "" {
		t.Errorf("finding outside every segment credited rule %q", resp.Results[1].AutoApprovalRuleID)
	}
}

// A status the caller sends is not read: with no rule matching, a body that
// says "monitoring" still lands the new asset pending.
func TestIntegration_RoutePipelineImport_IgnoresSuppliedStatus(t *testing.T) {
	f := newRoutePipelineFixture(t)

	resp := f.importBody(t, map[string]interface{}{
		"asset_status": "monitoring",
		"auto_approve": true,
		"findings":     []interface{}{routeFinding("10.30.1.5", "nobody-approved.corp.example", nil)},
	})
	if resp.AssetStatuses[0] != "pending_approval" {
		t.Fatalf("asset landed %q, want pending_approval: the transport must not choose a status", resp.AssetStatuses[0])
	}
}

// The cloud hint is honoured for a cloud-API finding only (the rule the
// processor's cloudResourceHint applied before WP3). A SENSOR finding
// that happens to carry cloud_provider / cloud_region keys is classified by
// its address: a public one is third party, not a member of a cloud segment.
// The positive polarity is cloud_autoapproval_integration_test.go.
func TestIntegration_RoutePipelineImport_CloudHintNeedsACloudSource(t *testing.T) {
	f := newRoutePipelineFixture(t)

	resp := f.importFindings(t, routeFinding("203.0.113.90", "edge.vendor.example", map[string]interface{}{
		"source_ip":      "10.1.2.3",
		"cloud_provider": "aws",
		"cloud_region":   "us-east-1",
	}))
	if got := resp.Results[0].Outcome; got != "routed" {
		t.Fatalf("a sensor finding with stray cloud keys = %q, want routed: only a cloud-API finding is classified by its cloud segment", got)
	}
}
