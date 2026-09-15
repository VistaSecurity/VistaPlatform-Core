package services

// Real-Postgres assertions for the Remediator seam's two database halves: the
// finding projection that crosses the provider boundary, and the accept path
// that records who admitted a drafted plan.
//
// Both need a real database for the same reason: they are about RLS, about jsonb
// columns, and about a NOT NULL foreign key to `users`. A unit test with a stub
// would prove the Go compiles and nothing about whether the row can be written
// or the tenant boundary holds.
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func newRemediationDraftIT(t *testing.T) (*RemediationDraftService, *RemediationPlanService, *sqlx.DB, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t) // skips if TEST_DATABASE_URL unset
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)
	return NewRemediationDraftService(db), &RemediationPlanService{db: db}, db, tenant
}

// seedUser inserts a platform user for the tenant. `remediation_plan_items`
// has a NOT NULL FK on added_by → users(id), which is exactly the constraint
// that makes "a human accepts" (ADR-0008 D5) enforceable rather than aspirational.
func seedUser(t *testing.T, db *sqlx.DB, tenant uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, is_active)
		VALUES ($1, $2, $3, 'x', 'Rem', 'Tester', true)`,
		id, tenant, "rem-"+id.String()[:8]+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

func seedCryptoFinding(t *testing.T, db *sqlx.DB, tenant uuid.UUID) (findingID, assetID uuid.UUID) {
	t.Helper()
	assetID, configID := seedAssetWithTLSConfig(t, db, tenant, "rem-host-"+uuid.New().String()[:8])

	// The two facts the projection is allowed to read, written the way a
	// producer writes them: jsonb, so a string arrives quoted.
	for key, value := range map[string]string{
		"os.name":    `"PAN-OS"`,
		"os.version": `"10.1.6"`,
		"hw.vendor":  `"Palo Alto Networks"`,
		"hw.model":   `"PA-3220"`,
		// Deliberately NOT in the allowlist. It must not reach the seam.
		"net.mac_address": `"00:11:22:33:44:55"`,
	} {
		if _, err := db.Exec(`
			INSERT INTO asset_facts (tenant_id, asset_id, key, value, source_kind, source_ref)
			VALUES ($1, $2, $3, $4::jsonb, 'measured', 'test')`,
			tenant, assetID, key, value); err != nil {
			t.Fatalf("seed fact %s: %v", key, err)
		}
	}

	findingID = uuid.New()
	if _, err := db.Exec(`
		INSERT INTO findings (id, tenant_id, producer, kind, subject_type, subject_id, subject_label,
		                      severity, score, summary, evidence)
		VALUES ($1, $2, 'crypto', 'weak_configuration', 'crypto_configuration', $3, $4,
		        'high', 70, 'Weak cryptographic configuration', $5::jsonb)`,
		findingID, tenant, configID, "rem-host:443",
		`{"protocol_version":"TLS 1.0","admin_password":"hunter2"}`); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	return findingID, assetID
}

// The projection reads what it is allowed to read, and nothing else.
//
// Every field here is one a remediation step needs to be specific — a vendor and
// a model name a product — and the two identifiers plus the MAC address are the
// half that buys a plan nothing and would leave the building forever.
func TestIntegration_ResolveFinding_ProjectsOnlyTheAllowlist(t *testing.T) {
	resolver, _, db, tenant := newRemediationDraftIT(t)
	findingID, _ := seedCryptoFinding(t, db, tenant)

	ref, err := resolver.ResolveFinding(context.Background(), tenant, findingID)
	if err != nil {
		t.Fatalf("ResolveFinding: %v", err)
	}

	if ref.Producer != "crypto" || ref.Kind != "weak_configuration" {
		t.Errorf("producer/kind = %s/%s", ref.Producer, ref.Kind)
	}
	if ref.SubjectLabel != "rem-host:443" {
		t.Errorf("subject_label = %q", ref.SubjectLabel)
	}
	// The guidance comes from the REGISTRY, keyed on producer+kind. Without it
	// there is nothing for a failure to degrade to.
	if ref.Guidance == "" {
		t.Error("no guidance resolved for crypto/weak_configuration")
	}

	if ref.Subject.OSName != "PAN-OS" || ref.Subject.OSVersion != "10.1.6" {
		t.Errorf("os = %q %q, want the facts", ref.Subject.OSName, ref.Subject.OSVersion)
	}
	if ref.Subject.HWVendor != "Palo Alto Networks" || ref.Subject.HWModel != "PA-3220" {
		t.Errorf("hw = %q %q, want the facts", ref.Subject.HWVendor, ref.Subject.HWModel)
	}
	if ref.Subject.ClassKey != "server" {
		t.Errorf("class_key = %q", ref.Subject.ClassKey)
	}
	// The configuration is SUMMARISED, not copied: the row carries raw_data, a
	// sensor id and a compliance blob that no step reads.
	if ref.Subject.Configuration != "TLS 1.0" {
		t.Errorf("configuration = %q, want the summary", ref.Subject.Configuration)
	}

	// The evidence arrives as the producer wrote it — including the secret,
	// which is the redactor's job at the boundary and NOT the projection's. Two
	// layers, and this is the wrong one to fix it in: a projection that also
	// redacted would be a second opinion about what a secret is.
	if ref.Evidence["protocol_version"] != "TLS 1.0" {
		t.Errorf("evidence = %v", ref.Evidence)
	}

	// What must NOT be here.
	if ref.Subject.ClassKey == "" && ref.Subject.OSName == "" {
		t.Fatal("nothing resolved at all; the rest of this test proves nothing")
	}
	for _, v := range []string{ref.Subject.OSName, ref.Subject.OSVersion, ref.Subject.HWVendor, ref.Subject.HWModel, ref.Subject.Configuration} {
		if v == "00:11:22:33:44:55" {
			t.Error("a fact outside the allowlist reached the projection")
		}
	}
}

// RLS: one tenant cannot resolve another's finding. The endpoint answers 404 for
// it, which is the same answer it gives for a finding that does not exist —
// "not yours" and "not there" must look identical from outside.
func TestIntegration_ResolveFinding_IsTenantIsolated(t *testing.T) {
	resolver, _, db, tenant := newRemediationDraftIT(t)
	findingID, _ := seedCryptoFinding(t, db, tenant)

	other := testdb.NewTenant(t, db.DB)
	if _, err := resolver.ResolveFinding(context.Background(), other, findingID); err == nil {
		t.Fatal("another tenant resolved this finding")
	}
}

// The accept path, end to end against a real table: the row is written, and it
// carries the three facts that make it readable a year later — what proposed it,
// which model, and which human admitted it (ADR-0008 D4.1 + D5).
func TestIntegration_AddDraftedItem_RecordsProvenanceAndTheActingUser(t *testing.T) {
	_, plans, db, tenant := newRemediationDraftIT(t)
	findingID, _ := seedCryptoFinding(t, db, tenant)
	user := seedUser(t, db, tenant)

	plan, err := plans.Create(tenant, user, models.CreatePlanInput{Title: "TLS cleanup"})
	if err != nil {
		t.Fatalf("Create plan: %v", err)
	}

	const notes = "1. Disable TLSv1.0 [ev:protocol_version]. [manual step]"
	item, err := plans.AddDraftedItem(tenant, plan.ID, user, findingID, notes,
		seams.SourceKindInferred, "remediator:mock-model-1")
	if err != nil {
		t.Fatalf("AddDraftedItem: %v", err)
	}

	if item.SourceKind == nil || *item.SourceKind != seams.SourceKindInferred {
		t.Errorf("source_kind = %v, want inferred", item.SourceKind)
	}
	if item.SourceRef == nil || *item.SourceRef != "remediator:mock-model-1" {
		t.Errorf("source_ref = %v", item.SourceRef)
	}
	if item.AddedBy != user {
		t.Errorf("added_by = %s, want %s", item.AddedBy, user)
	}

	// Read it back through the ordinary list path, which is what the Plans page
	// calls — the columns have to survive that query too, and an "AI drafted"
	// chip that reads a column the list does not select would render nothing.
	items, err := plans.ListItems(tenant, plan.ID)
	if err != nil {
		t.Fatalf("ListItems: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("%d items, want 1", len(items))
	}
	if items[0].SourceKind == nil || *items[0].SourceKind != seams.SourceKindInferred {
		t.Errorf("the list path dropped source_kind: %+v", items[0])
	}
	if items[0].Notes == nil || *items[0].Notes != notes {
		t.Errorf("notes round-tripped as %v", items[0].Notes)
	}
}

// An item added the ordinary way carries NULL provenance, and that is a distinct
// state rather than a default. It is what says "nobody has claimed a model wrote
// this", which is the whole point of the column being nullable.
//
// It uses a COMPLIANCE finding, because AddItem is producer-scoped and refuses
// anything else — see TestIntegration_AddDraftedItem_AcceptsAnyProducer, which
// pins that AddDraftedItem deliberately is not.
func TestIntegration_AddItem_LeavesProvenanceNull(t *testing.T) {
	_, plans, db, tenant := newRemediationDraftIT(t)
	findingID := seedComplianceFinding(t, db, tenant)
	user := seedUser(t, db, tenant)

	plan, err := plans.Create(tenant, user, models.CreatePlanInput{Title: "Hand-written"})
	if err != nil {
		t.Fatalf("Create plan: %v", err)
	}
	if _, err := plans.AddItem(tenant, plan.ID, user,
		models.AddPlanItemInput{FindingID: findingID.String()}); err != nil {
		t.Fatalf("AddItem: %v", err)
	}

	items, err := plans.ListItems(tenant, plan.ID)
	if err != nil {
		t.Fatalf("ListItems: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("%d items, want 1", len(items))
	}
	if items[0].SourceKind != nil {
		t.Errorf("a hand-added item claims source_kind %q", *items[0].SourceKind)
	}
}

// The same finding cannot be added to one plan twice, and the second attempt is
// a named error rather than a driver string the handler has to grep.
func TestIntegration_AddDraftedItem_RefusesADuplicate(t *testing.T) {
	_, plans, db, tenant := newRemediationDraftIT(t)
	findingID, _ := seedCryptoFinding(t, db, tenant)
	user := seedUser(t, db, tenant)

	plan, err := plans.Create(tenant, user, models.CreatePlanInput{Title: "Dupes"})
	if err != nil {
		t.Fatalf("Create plan: %v", err)
	}
	if _, err := plans.AddDraftedItem(tenant, plan.ID, user, findingID, "n", seams.SourceKindInferred, "remediator:m1"); err != nil {
		t.Fatalf("first AddDraftedItem: %v", err)
	}
	_, err = plans.AddDraftedItem(tenant, plan.ID, user, findingID, "n", seams.SourceKindInferred, "remediator:m1")
	if err == nil {
		t.Fatal("a duplicate was accepted")
	}
	if err.Error() != ErrItemAlreadyInPlan.Error() {
		t.Errorf("err = %v, want ErrItemAlreadyInPlan", err)
	}
}

// seedComplianceFinding writes the one producer/kind every read surface in this
// service is scoped to.
func seedComplianceFinding(t *testing.T, db *sqlx.DB, tenant uuid.UUID) uuid.UUID {
	t.Helper()
	assetID, _ := seedAssetWithTLSConfig(t, db, tenant, "cmp-host-"+uuid.New().String()[:8])
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO findings (id, tenant_id, producer, kind, subject_type, subject_id, subject_label,
		                      severity, score, summary, evidence)
		VALUES ($1, $2, 'compliance', 'control_noncompliant', 'asset', $3, 'cmp-host',
		        'high', 0, 'Control failed', '{}'::jsonb)`,
		id, tenant, assetID); err != nil {
		t.Fatalf("seed compliance finding: %v", err)
	}
	return id
}

// AddDraftedItem accepts a finding from ANY producer, unlike AddItem beside it.
//
// That difference is deliberate and load-bearing: the remediator drafts from any
// of the 21 registry kinds, so an accept path scoped to
// compliance/control_noncompliant would 404 for every crypto and end-of-life
// finding the moment the Findings page shows one. Pinned here in both
// directions, because "it happens to work today" and "it is meant to" read the
// same from the code.
func TestIntegration_AddDraftedItem_AcceptsAnyProducer(t *testing.T) {
	_, plans, db, tenant := newRemediationDraftIT(t)
	cryptoFinding, _ := seedCryptoFinding(t, db, tenant)
	user := seedUser(t, db, tenant)

	plan, err := plans.Create(tenant, user, models.CreatePlanInput{Title: "Crypto cleanup"})
	if err != nil {
		t.Fatalf("Create plan: %v", err)
	}

	if _, err := plans.AddDraftedItem(tenant, plan.ID, user, cryptoFinding, "n",
		seams.SourceKindInferred, "remediator:m1"); err != nil {
		t.Fatalf("AddDraftedItem refused a crypto finding: %v", err)
	}

	// The other half of the claim: the ordinary path still refuses it, so this
	// test describes a real difference rather than restating AddItem.
	other, err := plans.Create(tenant, user, models.CreatePlanInput{Title: "Ordinary"})
	if err != nil {
		t.Fatalf("Create plan: %v", err)
	}
	if _, err := plans.AddItem(tenant, other.ID, user,
		models.AddPlanItemInput{FindingID: cryptoFinding.String()}); err == nil {
		t.Error("AddItem accepted a crypto finding; the producer scope this test contrasts with is gone")
	}

	// And the drafted item is readable through the ordinary list path.
	items, err := plans.ListItems(tenant, plan.ID)
	if err != nil {
		t.Fatalf("ListItems: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("%d items, want 1", len(items))
	}
}
