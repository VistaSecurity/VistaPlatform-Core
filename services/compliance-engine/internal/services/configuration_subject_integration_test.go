package services

// A compliance finding from a cryptographic-configuration measurement names the
// ASSET as its subject, and the asset's own surfaces can see it.
//
// This is the regression that a review caught before it shipped, reproduced as
// a test. The writer labelled these findings `crypto_configuration` while
// storing the ASSET's id in subject_id — `asset_id` had always been the asset's
// and `asset_type` named the measurement kind, not the id's type — and the
// per-asset read and the has_findings facet both resolve a
// `crypto_configuration` subject through `crypto_implementations`. An asset id
// is never a crypto_implementations id, so both silently returned nothing: the
// asset page's Findings tab went blank and the facet reported a clean bill of
// health for an asset with an open, violating TLS configuration.
//
// Nothing about it was an error. That is why it is pinned here with a fixture
// shaped the way production rows actually are, rather than with one built from
// the shape the code hoped for.
//
// Skips without TEST_DATABASE_URL.

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	sharedfindings "github.com/vistasecurity/vistaplatform/shared/findings"
)

// seedAssetWithTLSConfig builds the smallest real shape a configuration
// measurement is taken over: an asset, an endpoint, and one TLS 1.0
// configuration at that endpoint. Returns the asset id and the configuration id.
func seedAssetWithTLSConfig(t *testing.T, db *sqlx.DB, tenant uuid.UUID, hostname string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	assetID, endpointID, configID := uuid.New(), uuid.New(), uuid.New()
	if _, err := db.Exec(`
		INSERT INTO assets (id, tenant_id, class_key, class_path, hostname)
		VALUES ($1, $2, 'server', 'server', $3)`, assetID, tenant, hostname); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO asset_endpoints (id, tenant_id, asset_id, address, port)
		VALUES ($1, $2, $3, '192.0.2.10', 443)`, endpointID, tenant, assetID); err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO crypto_implementations
		    (id, tenant_id, asset_id, endpoint_id, protocol, protocol_version, discovery_method)
		VALUES ($1, $2, $3, $4, 'TLS', 'TLS 1.0', 'active')`,
		configID, tenant, assetID, endpointID); err != nil {
		t.Fatalf("seed configuration: %v", err)
	}
	return assetID, configID
}

// The asset page's Findings tab lists a configuration finding on the asset it
// was measured on.
//
// The subject is the ASSET, so the read finds it by the asset path. Before the
// subject question was settled the row said `crypto_configuration` while
// holding the asset's id, and GetFindingsByAsset — which resolves that subject
// type through crypto_implementations — returned an empty list for an asset
// with an open violation.
func TestIntegration_ConfigurationFinding_IsVisibleOnItsAsset(t *testing.T) {
	// newEvalFixture, not newFindingsServiceIT: the per-asset read gates
	// compliance rows on the tenant having ACTIVATED the framework their control
	// belongs to, so a finding on an invented control id is correctly invisible.
	// A fixture that skipped the licence would be testing a path no tenant has.
	fx := newEvalFixture(t)
	db, tenant, control := fx.db, fx.tenant, fx.critical
	svc := &FindingsService{db: db}
	assetID, configID := seedAssetWithTLSConfig(t, db, tenant, "tls10-host.example.test")

	f := activeViolation(control, assetID)
	f.SubjectType = SubjectAsset
	f.Evidence = map[string]any{
		"measurement_type":              "tls_version",
		"measurement_value":             "TLS 1.0",
		EvidenceCryptoImplementationIDs: []string{configID.String()},
	}
	mustUpsert(t, svc, tenant, control, assetID, f, "ACTIVE")

	got, err := svc.GetFindingsByAsset(tenant, assetID)
	if err != nil {
		t.Fatalf("GetFindingsByAsset: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("the asset page's Findings tab returned %d findings for an asset with one open "+
			"TLS 1.0 violation, want 1 — a configuration measurement's subject is the asset, and "+
			"an asset id is never a crypto_implementations id, so resolving it as one returns "+
			"nothing and reads as a clean asset", len(got))
	}
	if got[0].SubjectType != SubjectAsset || got[0].SubjectID != assetID {
		t.Errorf("finding names subject (%s, %s), want (%s, %s)",
			got[0].SubjectType, got[0].SubjectID, SubjectAsset, assetID)
	}
	// And the configuration that failed is still reachable from the finding —
	// which is the whole reason the subject may be the asset without losing it.
	ids := evidenceConfigIDs(&got[0])
	if len(ids) != 1 || ids[0] != configID.String() {
		t.Errorf("evidence.%s = %v, want exactly [%s] — the subject is the asset, so this list "+
			"is the only route from the finding to the configuration that failed",
			EvidenceCryptoImplementationIDs, ids, configID)
	}
}

// The same finding, seen through the registry's `open` definition: it is open,
// and a resolved one is not. This is the half the has_findings facet counts
// (the facet itself is pinned against the asset list in inventory-service's
// TestIntegration_HasFindingsFacet_AgreesWithQuery; what is pinned HERE is that
// a configuration finding is a row that definition can see at all).
func TestIntegration_ConfigurationFinding_CountsAsOpenOnItsAsset(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)
	assetID, configID := seedAssetWithTLSConfig(t, db, tenant, "open-count.example.test")
	control := uuid.New()

	f := activeViolation(control, assetID)
	f.SubjectType = SubjectAsset
	f.Evidence = map[string]any{EvidenceCryptoImplementationIDs: []string{configID.String()}}
	mustUpsert(t, svc, tenant, control, assetID, f, "ACTIVE")

	open := func() int {
		t.Helper()
		var n int
		q := `SELECT count(*) FROM findings cf
		       WHERE cf.tenant_id = $1 AND cf.subject_type = $2 AND cf.subject_id = $3
		         AND ` + sharedfindings.OpenSQL("cf")
		if err := db.Get(&n, q, tenant, SubjectAsset, assetID); err != nil {
			t.Fatalf("count open: %v", err)
		}
		return n
	}
	if got := open(); got != 1 {
		t.Fatalf("the asset has %d open findings, want 1", got)
	}

	// Closed by a person: still detected, no longer open. Counting only
	// detection_state would report work somebody already did as outstanding.
	if _, err := db.Exec(
		`UPDATE findings SET workflow_status = 'RESOLVED' WHERE tenant_id = $1 AND subject_id = $2`,
		tenant, assetID); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := open(); got != 0 {
		t.Fatalf("a RESOLVED finding still counts as open (%d) — both halves of the definition "+
			"are load-bearing", got)
	}
}

// Several configurations failing one control on one asset are ONE finding that
// names them all.
//
// The (control, asset) pair is the unit of triage, so the reconcile keeps one
// representative finding — and keeping only the first measurement's evidence
// would name one configuration and silently drop the rest, so the inspector's
// "which configurations failed?" would be wrong without looking wrong.
func TestIntegration_ConfigurationFinding_UnionsEveryFailingConfiguration(t *testing.T) {
	fx := newEvalFixture(t)
	db, tenant, control := fx.db, fx.tenant, fx.critical
	svc := &FindingsService{db: db}
	assetID, configA := seedAssetWithTLSConfig(t, db, tenant, "two-configs.example.test")
	configB := uuid.New()

	one := func(configID uuid.UUID) models.ComplianceFinding {
		f := activeViolation(control, assetID)
		f.SubjectType = SubjectAsset
		f.Evidence = map[string]any{EvidenceCryptoImplementationIDs: []string{configID.String()}}
		return *f
	}
	a, b := one(configA), one(configB)
	mergeSubjectEvidence(&a, &b)
	mustUpsert(t, svc, tenant, control, assetID, &a, "ACTIVE")

	got, err := svc.GetFindingsByAsset(tenant, assetID)
	if err != nil {
		t.Fatalf("GetFindingsByAsset: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("two failing configurations on one control produced %d findings, want 1 — the "+
			"(control, asset) pair is the unit of triage", len(got))
	}
	ids := evidenceConfigIDs(&got[0])
	if len(ids) != 2 {
		t.Fatalf("evidence.%s = %v, want both configurations — keeping only the first names one "+
			"of them and loses the other with no error anywhere",
			EvidenceCryptoImplementationIDs, ids)
	}
	seen := map[string]bool{ids[0]: true, ids[1]: true}
	if !seen[configA.String()] || !seen[configB.String()] {
		t.Errorf("evidence names %v, want %s and %s", ids, configA, configB)
	}

	// Idempotent: merging the same sibling again changes nothing, so a converged
	// re-run writes byte-identical evidence and the no-op update path holds.
	before := len(evidenceConfigIDs(&a))
	mergeSubjectEvidence(&a, &b)
	if after := len(evidenceConfigIDs(&a)); after != before {
		t.Errorf("re-merging the same sibling grew the list from %d to %d; a reconcile that "+
			"changes nothing must write nothing", before, after)
	}
}

// The subject label is stamped at write time, so a finding whose asset has been
// archived still reads as a name rather than a UUID. F-2: the column, the wire
// field, the OpenAPI description and the UI fallback all existed with no writer.
func TestIntegration_ConfigurationFinding_StampsTheSubjectLabel(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)
	assetID, configID := seedAssetWithTLSConfig(t, db, tenant, "labelled.example.test")
	control := uuid.New()

	f := activeViolation(control, assetID)
	f.SubjectType = SubjectAsset
	f.SubjectLabel = subjectLabelFrom(SubjectAsset, map[string]interface{}{
		"hostname": "labelled.example.test",
		"port":     int64(443),
	})
	f.Evidence = map[string]any{EvidenceCryptoImplementationIDs: []string{configID.String()}}
	mustUpsert(t, svc, tenant, control, assetID, f, "ACTIVE")

	var label *string
	if err := db.Get(&label,
		`SELECT subject_label FROM findings WHERE tenant_id = $1 AND subject_id = $2`,
		tenant, assetID); err != nil {
		t.Fatalf("read subject_label: %v", err)
	}
	if label == nil || *label != "labelled.example.test" {
		t.Fatalf("subject_label = %v, want the asset's hostname — a column nothing writes is a "+
			"fallback that never fires, and the UI renders a raw UUID instead", label)
	}

	// And nothing to name it writes NULL, not "". An empty string satisfies a
	// `!= ""` check and renders as a blank label; absent is the honest answer.
	if got := subjectLabelFrom(SubjectAsset, map[string]interface{}{"port": int64(443)}); got != nil {
		t.Errorf("subjectLabelFrom with nothing to name the subject = %q, want nil", *got)
	}
	if got := subjectLabelFrom(SubjectCertificate, map[string]interface{}{"common_name": "cn.example"}); got == nil || *got != "cn.example" {
		t.Errorf("a certificate subject is named by its common name, got %v", got)
	}
}

// The EXTRACTOR end, which is where the subject is decided.
//
// The tests above construct their finding directly, so they pin the read. This
// one drives the real extractor against real rows: a configuration measurement
// must come back naming the ASSET, with the configuration it was read from in
// its metadata. Flip any of the ten `SubjectType: "asset"` literals back to
// "crypto_configuration" and this fails — which the read-side tests would not,
// because they never ask the extractor anything.
func TestIntegration_ConfigurationMeasurement_NamesTheAssetAsItsSubject(t *testing.T) {
	_, db, tenant := newFindingsServiceIT(t)
	assetID, configID := seedAssetWithTLSConfig(t, db, tenant, "extractor.example.test")

	values, err := NewMeasurementExtractor(db).ExtractMeasurementsForAsset(tenant, assetID, "tls_version")
	if err != nil {
		t.Fatalf("extract tls_version: %v", err)
	}
	if len(values) != 1 {
		t.Fatalf("extracted %d TLS-version measurements for an asset with one TLS configuration, want 1", len(values))
	}
	v := values[0]

	if v.SubjectType != SubjectAsset {
		t.Errorf("subject_type = %q, want %q — the query selects na.id and scopes on na.id, so the "+
			"value is a statement about the asset. Calling it %q while carrying the asset's id is "+
			"what made the asset page and the has_findings facet resolve it through "+
			"crypto_implementations and find nothing.",
			v.SubjectType, SubjectAsset, sharedfindings.SubjectCryptoConfiguration)
	}
	if v.SubjectID != assetID {
		t.Errorf("subject_id = %s, want the asset %s", v.SubjectID, assetID)
	}
	if v.Value != "TLS 1.0" {
		t.Errorf("measured value = %v, want TLS 1.0", v.Value)
	}

	// And the configuration is not lost — this list is the only route from the
	// finding back to the thing that actually negotiated TLS 1.0.
	ids, ok := v.Metadata[EvidenceCryptoImplementationIDs].([]string)
	if !ok || len(ids) != 1 || ids[0] != configID.String() {
		t.Fatalf("metadata.%s = %v, want exactly [%s]",
			EvidenceCryptoImplementationIDs, v.Metadata[EvidenceCryptoImplementationIDs], configID)
	}

	// The label the finding will be stamped with comes from the same metadata.
	if got := subjectLabelFrom(v.SubjectType, v.Metadata); got == nil || *got != "extractor.example.test" {
		t.Errorf("subjectLabelFrom = %v, want the asset's hostname", got)
	}
}
