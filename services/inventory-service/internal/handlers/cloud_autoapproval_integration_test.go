package handlers

// Pins auto-approval of CLOUD discoveries end to end, over a real Postgres:
// segment configuration → generated rule row → classification of a
// placeholder-addressed cloud resource → the shared evaluator's decision.
//
// Two things were broken and both are covered here, because fixing either
// alone leaves cloud auto-approval half-working:
//
//  1. Both writers of discovery_auto_approval_rules stamped
//     "source": "sensor_discoveries" and no API could author a rule by hand, so
//     the evaluator rejected every cloud discovery before ownership or segment
//     were considered — its "cloud_discovery" and "all" branches were dead code.
//  2. A cloud resource with no address of its own (a KMS key, a bucket, a
//     managed database) is written with an unspecified-address placeholder.
//     That address is neither RFC 1918 nor inside any CIDR segment, so
//     ownership resolved to third_party and was then forced to "unknown" —
//     which no segment rule can match, whatever its source condition says.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/approval"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// cloudFixture wires the REAL segment service and the REAL handler over a real
// database, so the classify route under test is the one the
// discovery-processor calls.
type cloudFixture struct {
	engine *gin.Engine
	segSvc *services.NetworkSegmentService
	approv *approval.Service
	raw    *sql.DB
	tenant uuid.UUID
}

func newCloudFixture(t *testing.T) *cloudFixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	segSvc := services.NewNetworkSegmentService(db, services.NewLocationService(db))

	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2/inventory-service")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", tenant)
		c.Next()
	})
	h := NewNetworkSegmentHandler(segSvc)
	grp.POST("/network-segments/classify-asset", h.ClassifyAsset)

	return &cloudFixture{engine: r, segSvc: segSvc, approv: approval.NewService(raw), raw: raw, tenant: tenant}
}

// classifyCloud calls the real classify-asset route the way discovery-processor
// does for a cloud discovery: the placeholder address plus the cloud
// account/region the row carries.
func (f *cloudFixture) classifyCloud(t *testing.T, provider, region, vpc string) *approval.Classification {
	t.Helper()
	body, err := json.Marshal(map[string]interface{}{
		"ip_address":     "0.0.0.0",
		"cloud_provider": provider,
		"cloud_region":   region,
		"vpc_id":         vpc,
		"environment":    "production",
	})
	if err != nil {
		t.Fatalf("marshal classify body: %v", err)
	}
	w := do(f.engine, http.MethodPost, "/api/v2/inventory-service/network-segments/classify-asset", bytes.NewReader(body))
	if w.Code != http.StatusOK {
		t.Fatalf("classify-asset returned %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Ownership   string  `json:"ownership"`
		NetworkType string  `json:"network_type"`
		SegmentID   *string `json:"segment_id"`
		SegmentName *string `json:"segment_name"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode classify response: %v (%s)", err, w.Body.String())
	}
	c := &approval.Classification{Ownership: resp.Ownership, Type: resp.NetworkType}
	if resp.SegmentID != nil {
		if id, err := uuid.Parse(*resp.SegmentID); err == nil {
			c.SegmentID = &id
		}
	}
	c.SegmentName = resp.SegmentName
	return c
}

// cloudDiscovery is what a cloud-API row projects onto for rule evaluation.
func cloudDiscovery(t *testing.T, tenant uuid.UUID) approval.Discovery {
	t.Helper()
	meta, err := json.Marshal(map[string]interface{}{
		"discovery_method": "cloud_api",
		"cloud_provider":   "aws",
		"cloud_region":     "us-east-1",
	})
	if err != nil {
		t.Fatalf("marshal discovery metadata: %v", err)
	}
	return approval.Discovery{TenantID: tenant, Confidence: 0.95, Metadata: meta}
}

// setSegmentAutoApproval turns auto-approve on for the segment the cloud
// resources resolve to, with the given sources, and regenerates the rules —
// exactly what Settings → Infrastructure → Network Segments does on save.
func (f *cloudFixture) setSegmentAutoApproval(t *testing.T, segID uuid.UUID, sources []string) {
	t.Helper()
	seg, err := f.segSvc.GetByID(f.tenant, segID)
	if err != nil || seg == nil {
		t.Fatalf("load segment %s: %v", segID, err)
	}
	on := true
	if _, err := f.segSvc.Update(f.tenant, segID, models.NetworkSegmentInput{
		Name: seg.Name, SegmentType: seg.SegmentType, Value: seg.Value,
		NetworkType: seg.NetworkType, Environment: seg.Environment,
		LocationID:             seg.LocationID,
		AutoApproveDiscoveries: &on,
		AutoApproveSources:     sources,
	}); err != nil {
		t.Fatalf("update segment %s: %v", segID, err)
	}
	if err := f.segSvc.ManageAutoApprovalRules(f.tenant, uuid.Nil); err != nil {
		t.Fatalf("regenerate auto-approval rules: %v", err)
	}
}

// The positive case. A cloud resource with no address of its own resolves
// ownership from its cloud segment, and a segment whose auto-approval includes
// the cloud source approves it.
func TestIntegration_CloudDiscovery_AutoApprovedWhenSegmentIncludesCloudSource(t *testing.T) {
	f := newCloudFixture(t)

	classification := f.classifyCloud(t, "aws", "us-east-1", "")
	if classification.Ownership != "internal" {
		t.Fatalf("a cloud resource classified ownership=%q, want internal — a placeholder address must not decide whose network a cloud resource is on", classification.Ownership)
	}
	if classification.SegmentID == nil {
		t.Fatal("a cloud resource resolved to no segment — nothing a segment rule can match")
	}

	f.setSegmentAutoApproval(t, *classification.SegmentID, []string{models.AutoApproveSourceCloud})

	auto, ruleID, err := f.approv.EvaluateAutoApprovalWithRules(
		f.rules(t), cloudDiscovery(t, f.tenant), classification)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !auto || ruleID == nil {
		t.Fatal("a cloud discovery on a segment that auto-approves cloud was NOT auto-approved")
	}
}

// The negative case, and the one that keeps the setting honest: the same cloud
// discovery, the same auto-approving segment, sources set to sensor only.
func TestIntegration_CloudDiscovery_NotAutoApprovedWhenSegmentIsSensorOnly(t *testing.T) {
	f := newCloudFixture(t)

	classification := f.classifyCloud(t, "aws", "us-east-1", "")
	if classification.SegmentID == nil {
		t.Fatal("a cloud resource resolved to no segment")
	}
	f.setSegmentAutoApproval(t, *classification.SegmentID, []string{models.AutoApproveSourceSensor})

	auto, _, err := f.approv.EvaluateAutoApprovalWithRules(
		f.rules(t), cloudDiscovery(t, f.tenant), classification)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if auto {
		t.Fatal("a cloud discovery was auto-approved by a segment whose auto-approval covers sensor discoveries only")
	}
}

// The upgrade case. A segment configured before this setting existed carries no
// stored sources. It must keep meaning exactly what it meant when the tenant
// switched it on — sensor discoveries — and must not start admitting cloud
// assets on the strength of an upgrade nobody asked for.
func TestIntegration_PreExistingSegment_DoesNotStartAutoApprovingCloud(t *testing.T) {
	f := newCloudFixture(t)

	classification := f.classifyCloud(t, "aws", "us-east-1", "")
	if classification.SegmentID == nil {
		t.Fatal("a cloud resource resolved to no segment")
	}
	segID := *classification.SegmentID

	// Turn auto-approve on, then strip the sources key straight out of the row
	// to reproduce a segment written before the setting existed.
	f.setSegmentAutoApproval(t, segID, []string{models.AutoApproveSourceCloud})
	f.stripStoredSources(t, segID)
	if err := f.segSvc.ManageAutoApprovalRules(f.tenant, uuid.Nil); err != nil {
		t.Fatalf("regenerate auto-approval rules: %v", err)
	}

	seg, err := f.segSvc.GetByID(f.tenant, segID)
	if err != nil || seg == nil {
		t.Fatalf("reload segment: %v", err)
	}
	if !seg.AutoApproveDiscoveries {
		t.Fatal("fixture lost the auto-approve flag; the rest of this test would pass vacuously")
	}
	if len(seg.AutoApproveSources) != 1 || seg.AutoApproveSources[0] != models.AutoApproveSourceSensor {
		t.Fatalf("a segment with no stored sources read back as %v, want [sensor]", seg.AutoApproveSources)
	}

	auto, _, err := f.approv.EvaluateAutoApprovalWithRules(
		f.rules(t), cloudDiscovery(t, f.tenant), classification)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if auto {
		t.Fatal("a segment configured before the per-source setting existed started auto-approving cloud assets")
	}
}

// Sensor discoveries on a cloud-enabled segment still behave: turning cloud on
// must widen the rule, not swap it.
func TestIntegration_SegmentWithBothSources_ApprovesSensorAndCloud(t *testing.T) {
	f := newCloudFixture(t)

	classification := f.classifyCloud(t, "aws", "us-east-1", "")
	if classification.SegmentID == nil {
		t.Fatal("a cloud resource resolved to no segment")
	}
	f.setSegmentAutoApproval(t, *classification.SegmentID,
		[]string{models.AutoApproveSourceSensor, models.AutoApproveSourceCloud})

	rules := f.rules(t)
	cloudAuto, _, err := f.approv.EvaluateAutoApprovalWithRules(rules, cloudDiscovery(t, f.tenant), classification)
	if err != nil {
		t.Fatalf("evaluate cloud: %v", err)
	}
	if !cloudAuto {
		t.Fatal("a cloud discovery was not auto-approved by a segment covering both sources")
	}

	// A sensor discovery is one with no cloud_api marker in its metadata.
	sensorAuto, _, err := f.approv.EvaluateAutoApprovalWithRules(rules,
		approval.Discovery{TenantID: f.tenant, Confidence: 0.9}, classification)
	if err != nil {
		t.Fatalf("evaluate sensor: %v", err)
	}
	if !sensorAuto {
		t.Fatal("enabling cloud coverage stopped sensor discoveries from being auto-approved — the setting must widen the rule, not replace it")
	}
}

func (f *cloudFixture) rules(t *testing.T) []*approval.Rule {
	t.Helper()
	rules, err := f.approv.GetActiveRulesForTenant(f.tenant)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("no active auto-approval rules for the tenant; the fixture did not generate one")
	}
	return rules
}

// stripStoredSources removes the per-source key from a segment's metadata,
// reproducing a row written before the setting existed.
func (f *cloudFixture) stripStoredSources(t *testing.T, segID uuid.UUID) {
	t.Helper()
	if _, err := f.raw.Exec(
		`UPDATE network_segments SET metadata = metadata - $1 WHERE id = $2 AND tenant_id = $3`,
		models.AutoApproveSourcesKey, segID, f.tenant); err != nil {
		t.Fatalf("strip stored sources: %v", err)
	}
}
