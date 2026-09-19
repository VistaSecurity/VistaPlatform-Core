package services

// The identity half of `PUT /infrastructure-assets/{id}`, against a real
// Postgres.
//
// These assertions need the database because the whole defect was that the
// columns moved and the IDENTIFIER ROWS did not: a unit test over the input
// struct can see neither. Skips without TEST_DATABASE_URL.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// identifierRows reads one asset's identifiers as kind|value|scope → source_kind.
func identifierRows(t *testing.T, svc *AssetService, tenant, asset uuid.UUID) map[string]string {
	t.Helper()
	ids, err := svc.getAssetIdentifiers(tenant, asset)
	if err != nil {
		t.Fatalf("read identifiers: %v", err)
	}
	out := map[string]string{}
	for _, id := range ids {
		out[identifierKey(id)] = id.SourceKind
	}
	return out
}

func TestIntegration_UpdateAsset_CannotMintADeclarationIdentifier(t *testing.T) {
	svc, _, tenant := newIdentityFixture(t)
	created, err := svc.CreateAsset(tenant, models.AssetInput{ClassKey: assetclass.KeyServer, Hostname: ptr("declaration-guard.example.test")})
	if err != nil {
		t.Fatal(err)
	}
	scope := tenant.String()
	_, _, err = svc.UpdateAsset(tenant, created.ID, models.AssetInput{Identifiers: []models.AssetIdentifierInput{
		{Kind: string(identity.KindDeclarationID), Value: uuid.NewString(), Scope: &scope},
	}}, uuid.New())
	if err == nil || !strings.Contains(err.Error(), "issued only by identity confirmation") {
		t.Fatalf("declaration forgery accepted: %v", err)
	}
	for key := range identifierRows(t, svc, tenant, created.ID) {
		if strings.HasPrefix(key, "declaration_id|") {
			t.Fatalf("forged identifier persisted: %s", key)
		}
	}
}

// TestIntegration_UpdateAsset_AttachesDeclaredIdentifiers is the regression for
// B6 and C3 together: the form sent `identifiers` and the server dropped them,
// so editing an asset's identity was a silent no-op that reported success.
func TestIntegration_UpdateAsset_AttachesDeclaredIdentifiers(t *testing.T) {
	svc, _, tenant := newIdentityFixture(t)

	created, err := svc.CreateAsset(tenant, models.AssetInput{
		ClassKey: assetclass.KeyServer,
		Hostname: ptr("edit-me.example.test"),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	_, report, err := svc.UpdateAsset(tenant, created.ID, models.AssetInput{
		Identifiers: []models.AssetIdentifierInput{
			{Kind: "serial_number", Value: "SN-EDIT-1"},
			{Kind: "mac_address", Value: "aa:bb:cc:11:22:33"},
		},
	}, uuid.New())
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	rows := identifierRows(t, svc, tenant, created.ID)
	for _, want := range []string{"serial_number|SN-EDIT-1|", "mac_address|aa:bb:cc:11:22:33|"} {
		if _, ok := rows[want]; !ok {
			t.Errorf("identifier %q was not attached; rows = %v", want, rows)
		}
	}
	if len(report.Attached) != 2 {
		t.Errorf("report.Attached = %+v, want the two identifiers the edit added", report.Attached)
	}
}

// TestIntegration_UpdateAsset_RenameKeepsTheOldIdentifier: `hostname` is an
// identifier ALIAS. Setting it attaches the new name; it does not retire the
// old one, which was true when it was observed. Before this the column moved
// alone — the new name was not something the asset could be matched on, the old
// one still was, and the next sighting of the renamed host minted a duplicate.
func TestIntegration_UpdateAsset_RenameKeepsTheOldIdentifier(t *testing.T) {
	svc, _, tenant := newIdentityFixture(t)

	created, err := svc.CreateAsset(tenant, models.AssetInput{
		ClassKey: assetclass.KeyServer,
		Hostname: ptr("old-name.example.test"),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, _, err := svc.UpdateAsset(tenant, created.ID, models.AssetInput{
		Hostname: ptr("new-name.example.test"),
	}, uuid.Nil); err != nil {
		t.Fatalf("rename: %v", err)
	}

	rows := identifierRows(t, svc, tenant, created.ID)
	if _, ok := rows["fqdn|new-name.example.test|"]; !ok {
		t.Errorf("the new name is not an identifier, so the next sighting would mint a duplicate; rows = %v", rows)
	}
	if _, ok := rows["fqdn|old-name.example.test|"]; !ok {
		t.Errorf("the old name was true when it was observed and must survive a rename; rows = %v", rows)
	}
}

// TestIntegration_UpdateAsset_RetiresOnlyDeclaredIdentifiers is the C3 half: a
// person may retire what a person declared, and nothing else. A collector-minted
// identifier is a fact about the world; an edit form is not where facts get
// deleted — and the response has to SAY it kept them, or the UI reports a
// deletion that did not happen.
func TestIntegration_UpdateAsset_RetiresOnlyDeclaredIdentifiers(t *testing.T) {
	svc, db, tenant := newIdentityFixture(t)

	created, err := svc.CreateAsset(tenant, models.AssetInput{
		ClassKey: assetclass.KeyServer,
		Hostname: ptr("mixed.example.test"),
		Identifiers: []models.AssetIdentifierInput{
			{Kind: "serial_number", Value: "SN-DECLARED"},
		},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// A measured identifier and a collector-minted one, as a sensor and a cloud
	// collector would have written them.
	for _, row := range []struct{ kind, value, source string }{
		{"mac_address", "aa:bb:cc:44:55:66", "measured"},
		{"cloud_resource_id", "arn:aws:ec2:us-east-1:1:instance/i-0mixed", "measured"},
	} {
		if _, err := db.Exec(`
			INSERT INTO asset_identifiers (tenant_id, asset_id, kind, value, source_kind, source_ref, confidence)
			VALUES ($1, $2, $3, $4, $5, 'sensor', 1)`,
			tenant, created.ID, row.kind, row.value, row.source); err != nil {
			t.Fatalf("seed %s: %v", row.kind, err)
		}
	}

	// The edit submits ONLY the hostname identifier: everything else is asked
	// to go.
	_, report, err := svc.UpdateAsset(tenant, created.ID, models.AssetInput{
		Identifiers: []models.AssetIdentifierInput{
			{Kind: "fqdn", Value: "mixed.example.test"},
		},
	}, uuid.New())
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	rows := identifierRows(t, svc, tenant, created.ID)
	if _, gone := rows["serial_number|SN-DECLARED|"]; gone {
		t.Error("a declared identifier the edit dropped must be retired")
	}
	for _, kept := range []string{
		"mac_address|aa:bb:cc:44:55:66|",
		"cloud_resource_id|arn:aws:ec2:us-east-1:1:instance/i-0mixed|",
	} {
		if _, ok := rows[kept]; !ok {
			t.Errorf("%s was measured, not declared — an edit form must not delete it; rows = %v", kept, rows)
		}
	}
	if len(report.Kept) != 2 {
		t.Errorf("report.Kept = %+v, want the two collector-minted identifiers", report.Kept)
	}
	for _, k := range report.Kept {
		if k.Reason == "" {
			t.Errorf("kept %s=%s with no reason; a silent keep reads as a successful delete", k.Kind, k.Value)
		}
	}
	if len(report.Removed) != 1 || report.Removed[0].Value != "SN-DECLARED" {
		t.Errorf("report.Removed = %+v, want just the declared serial", report.Removed)
	}
}

// TestIntegration_UpdateAsset_ForeignIdentifierIsAConflictAndAProposal: the edit
// is refused, AND the proposal it points at survives the refusal. A 409 that
// rolled back the proposal it told the operator to go read is the exact shape
// gate 1 found in CreateDevice and the cloud upsert.
func TestIntegration_UpdateAsset_ForeignIdentifierIsAConflictAndAProposal(t *testing.T) {
	svc, _, tenant := newIdentityFixture(t)

	owner, err := svc.CreateAsset(tenant, models.AssetInput{
		ClassKey:    assetclass.KeyServer,
		Hostname:    ptr("owner.example.test"),
		Identifiers: []models.AssetIdentifierInput{{Kind: "serial_number", Value: "SN-CONTESTED"}},
	})
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	other, err := svc.CreateAsset(tenant, models.AssetInput{
		ClassKey: assetclass.KeyServer,
		Hostname: ptr("other.example.test"),
	})
	if err != nil {
		t.Fatalf("create other: %v", err)
	}
	// The edited asset is IN SERVICE. That is the point: a monitored asset must
	// not be taken out of service because somebody typed a serial that turns out
	// to belong to another asset.
	if _, err := svc.db.Exec(
		`UPDATE assets SET asset_status = 'monitoring' WHERE tenant_id = $1 AND id = $2`,
		tenant, other.ID); err != nil {
		t.Fatalf("promote: %v", err)
	}
	const beforeStatus = "monitoring"

	_, _, err = svc.UpdateAsset(tenant, other.ID, models.AssetInput{
		Identifiers: []models.AssetIdentifierInput{{Kind: "serial_number", Value: "SN-CONTESTED"}},
	}, uuid.New())
	conflict, ok := AsIdentifierConflict(err)
	if !ok {
		t.Fatalf("update: err = %v, want an *IdentifierConflictError", err)
	}
	if conflict.OwnerAssetID != owner.ID {
		t.Errorf("conflict names owner %s, want %s", conflict.OwnerAssetID, owner.ID)
	}
	if conflict.ProposalID == uuid.Nil {
		t.Fatal("the conflict must name a merge proposal; a 409 with nowhere to go is a dead end")
	}

	// The proposal COMMITTED, even though the edit did not.
	proposals, _, err := NewMergeProposalService(svc.db).ListPending(context.Background(), tenant, 50, 0)
	if err != nil {
		t.Fatalf("list proposals: %v", err)
	}
	found := false
	for _, p := range proposals {
		if p.ID == conflict.ProposalID {
			found = true
		}
	}
	if !found {
		t.Error("the merge proposal the 409 names is not in the queue; the refusal erased what it told the operator to read")
	}

	// The identifier did NOT move, and the edited asset was not demoted.
	rows := identifierRows(t, svc, tenant, other.ID)
	if _, taken := rows["serial_number|SN-CONTESTED|"]; taken {
		t.Error("a contested identifier must not be attached; the merge question is the reviewer's")
	}
	after, err := svc.GetAssetByID(tenant, other.ID)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if after.AssetStatus != beforeStatus {
		t.Errorf("asset_status moved %s → %s; one unverified keystroke must not take an asset out of service",
			beforeStatus, after.AssetStatus)
	}
}

// TestIntegration_UpdateAsset_RefusesToStripTheLastIdentifier: the engine's
// floor refuses to CREATE an asset with no identifiers because it could never be
// matched again. Subtraction is the same asset through a different door.
func TestIntegration_UpdateAsset_RefusesToStripTheLastIdentifier(t *testing.T) {
	svc, _, tenant := newIdentityFixture(t)

	created, err := svc.CreateAsset(tenant, models.AssetInput{
		ClassKey:    assetclass.KeyServer,
		Identifiers: []models.AssetIdentifierInput{{Kind: "serial_number", Value: "SN-ONLY"}},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	_, _, err = svc.UpdateAsset(tenant, created.ID, models.AssetInput{
		Identifiers: []models.AssetIdentifierInput{},
	}, uuid.New())
	if !errors.Is(err, ErrIdentifierFloor) {
		t.Fatalf("err = %v, want ErrIdentifierFloor", err)
	}
	rows := identifierRows(t, svc, tenant, created.ID)
	if len(rows) == 0 {
		t.Error("the refusal must leave the identifiers alone")
	}
}

// TestIntegration_UpdateAsset_NoIdentifiersArrayRemovesNothing: a partial update
// that never mentions identity must not delete any. `identifiers` absent and
// `identifiers: []` are different requests.
func TestIntegration_UpdateAsset_NoIdentifiersArrayRemovesNothing(t *testing.T) {
	svc, _, tenant := newIdentityFixture(t)

	created, err := svc.CreateAsset(tenant, models.AssetInput{
		ClassKey:    assetclass.KeyServer,
		Hostname:    ptr("partial.example.test"),
		Identifiers: []models.AssetIdentifierInput{{Kind: "serial_number", Value: "SN-KEEP"}},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	before := identifierRows(t, svc, tenant, created.ID)

	if _, _, err := svc.UpdateAsset(tenant, created.ID, models.AssetInput{
		OwnerEmail: ptr("ops@example.test"),
	}, uuid.Nil); err != nil {
		t.Fatalf("update: %v", err)
	}
	after := identifierRows(t, svc, tenant, created.ID)
	if len(after) != len(before) {
		t.Errorf("identifiers went %d → %d on an edit that never mentioned them", len(before), len(after))
	}
}

// TestIntegration_UpdateAsset_DeclaredNameIsScopedByClass pins B9 on the update
// path: a `name` identifies within a CLASS, not within a network segment.
// Scoping it to the segment would make one service in two segments two services.
func TestIntegration_UpdateAsset_DeclaredNameIsScopedByClass(t *testing.T) {
	svc, _, tenant := newIdentityFixture(t)

	created, err := svc.CreateAsset(tenant, models.AssetInput{
		ClassKey:    assetclass.KeyBusinessService,
		DisplayName: ptr("Payments API"),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, _, err := svc.UpdateAsset(tenant, created.ID, models.AssetInput{
		Identifiers: []models.AssetIdentifierInput{
			{Kind: string(identity.KindName), Value: "Payments API"},
			{Kind: string(identity.KindName), Value: "Payments Gateway"},
		},
	}, uuid.New()); err != nil {
		t.Fatalf("update: %v", err)
	}

	rows := identifierRows(t, svc, tenant, created.ID)
	for k := range rows {
		if !strings.HasPrefix(k, "name|") {
			continue
		}
		if !strings.HasSuffix(k, "|"+assetclass.KeyBusinessService) {
			t.Errorf("name identifier %q is not scoped by the class key; a name identifies within a class", k)
		}
	}
	if _, ok := rows["name|payments gateway|"+assetclass.KeyBusinessService]; !ok {
		t.Errorf("the second declared name was not attached; rows = %v", rows)
	}
}
