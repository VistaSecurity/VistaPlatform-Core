package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type captureRecorder struct{ got []ObjectChange }

func (c *captureRecorder) Record(_ context.Context, _ *sqlx.Tx, ch ObjectChange) error {
	c.got = append(c.got, ch)
	return nil
}

func buFixture(t *testing.T) (*BusinessUnitService, *captureRecorder, uuid.UUID, *database.DB) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	svc := NewBusinessUnitService(db)
	rec := &captureRecorder{}
	svc.SetChangeRecorder(rec)
	return svc, rec, tenant, db
}

func sp(s string) *string { return &s }

func TestIntegration_BusinessUnits_RLS(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	app := testdb.ConnectAsAppRole(t, raw)
	a, b := testdb.NewTenant(t, raw), testdb.NewTenant(t, raw)

	as := func(tenant uuid.UUID, fn func(tx *sqlx.Tx) error) error {
		tx, err := sqlx.NewDb(app, "postgres").Beginx()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`SELECT set_config('app.tenant_id', $1, true)`, tenant.String()); err != nil {
			t.Fatal(err)
		}
		if err := fn(tx); err != nil {
			return err
		}
		return tx.Commit()
	}
	if err := as(a, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(`INSERT INTO business_units (tenant_id, name, slug) VALUES ($1, 'Finance', 'finance')`, a)
		return e
	}); err != nil {
		t.Fatalf("insert as own tenant: %v", err)
	}
	var n int
	_ = as(b, func(tx *sqlx.Tx) error { return tx.Get(&n, `SELECT COUNT(*) FROM business_units`) })
	if n != 0 {
		t.Errorf("tenant B sees %d of tenant A's units", n)
	}
	if err := as(b, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(`INSERT INTO business_units (tenant_id, name, slug) VALUES ($1, 'Smuggled', 'smuggled')`, a)
		return e
	}); err == nil {
		t.Error("tenant B inserted a row owned by tenant A")
	}
	_ = as(a, func(tx *sqlx.Tx) error { return tx.Get(&n, `SELECT COUNT(*) FROM business_units`) })
	if n != 1 {
		t.Errorf("tenant A sees %d units, want 1", n)
	}
}

func TestIntegration_BusinessUnits_SlugUniquePerTenant(t *testing.T) {
	svc, _, tenant, db := buFixture(t)
	ctx := context.Background()
	other := testdb.NewTenant(t, db.DB.DB)

	if _, err := db.Exec(`INSERT INTO business_units (tenant_id, name, slug) VALUES ($1,'A','dup')`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO business_units (tenant_id, name, slug) VALUES ($1,'B','dup')`, tenant); err == nil {
		t.Error("two units in one tenant share a slug at the SQL level")
	}
	if _, err := db.Exec(`INSERT INTO business_units (tenant_id, name, slug) VALUES ($1,'C','dup')`, other); err != nil {
		t.Errorf("a different tenant may reuse the slug: %v", err)
	}
	// The service derives distinct slugs and refuses an explicit clash.
	u1, err := svc.Create(ctx, tenant, uuid.Nil, models.BusinessUnitInput{Name: sp("Retail Ops")})
	u2, err2 := svc.Create(ctx, tenant, uuid.Nil, models.BusinessUnitInput{Name: sp("Retail  Ops")})
	if err != nil || err2 != nil || u1.Slug != "retail-ops" || u2.Slug != "retail-ops-2" {
		t.Fatalf("derived slugs: %v %v %+v %+v", err, err2, u1, u2)
	}
	if _, err := svc.Create(ctx, tenant, uuid.Nil, models.BusinessUnitInput{Name: sp("X"), Slug: sp("dup")}); !errors.Is(err, ErrBusinessUnitSlugExists) {
		t.Errorf("explicit duplicate slug: %v, want ErrBusinessUnitSlugExists", err)
	}
}

func TestBusinessUnits_ParentDepthCapped(t *testing.T) {
	for _, c := range []struct {
		parent, sub int
		ok          bool
	}{{0, 1, true}, {3, 1, true}, {4, 1, false}, {2, 2, true}, {2, 3, false}, {1, 4, false}} {
		err := validateBusinessUnitDepth(c.parent, c.sub)
		if (err == nil) != c.ok {
			t.Errorf("parent=%d subtree=%d: err=%v, want ok=%v", c.parent, c.sub, err, c.ok)
		}
	}
}

func TestIntegration_BusinessUnits_DepthAndCycleThroughService(t *testing.T) {
	svc, _, tenant, _ := buFixture(t)
	ctx := context.Background()
	var parent *uuid.UUID
	var ids []uuid.UUID
	for i := 0; i < 4; i++ {
		u, err := svc.Create(ctx, tenant, uuid.Nil, models.BusinessUnitInput{Name: sp("L" + string(rune('1'+i))), ParentID: parent})
		if err != nil {
			t.Fatalf("level %d: %v", i+1, err)
		}
		parent = &u.ID
		ids = append(ids, u.ID)
	}
	if _, err := svc.Create(ctx, tenant, uuid.Nil, models.BusinessUnitInput{Name: sp("L5"), ParentID: parent}); !errors.Is(err, ErrBusinessUnitDepth) {
		t.Errorf("fifth level: %v, want ErrBusinessUnitDepth", err)
	}
	// Re-parenting the root under the leaf is a cycle.
	_, err := svc.Update(ctx, tenant, uuid.Nil, ids[0], models.BusinessUnitInput{ParentID: &ids[3], ParentSet: true})
	if !errors.Is(err, ErrBusinessUnitCycle) {
		t.Errorf("cycle: %v, want ErrBusinessUnitCycle", err)
	}
	// A 3-level subtree fits under a root (4 levels) but not under a 2-level chain (5).
	root2, _ := svc.Create(ctx, tenant, uuid.Nil, models.BusinessUnitInput{Name: sp("Other root")})
	kid2, _ := svc.Create(ctx, tenant, uuid.Nil, models.BusinessUnitInput{Name: sp("Other kid"), ParentID: &root2.ID})
	if _, err := svc.Update(ctx, tenant, uuid.Nil, ids[1], models.BusinessUnitInput{ParentID: &kid2.ID, ParentSet: true}); !errors.Is(err, ErrBusinessUnitDepth) {
		t.Errorf("moving a 3-level subtree under a 2-level chain: %v, want ErrBusinessUnitDepth", err)
	}
	if _, err := svc.Update(ctx, tenant, uuid.Nil, ids[1], models.BusinessUnitInput{ParentID: &root2.ID, ParentSet: true}); err != nil {
		t.Errorf("moving a 3-level subtree under a root: %v", err)
	}
}

func TestIntegration_BusinessUnits_DeleteRefusesWhenReferenced_ReassignsWhenAsked(t *testing.T) {
	svc, _, tenant, db := buFixture(t)
	ctx := context.Background()
	from, _ := svc.Create(ctx, tenant, uuid.Nil, models.BusinessUnitInput{Name: sp("From")})
	to, _ := svc.Create(ctx, tenant, uuid.Nil, models.BusinessUnitInput{Name: sp("To")})
	kid, _ := svc.Create(ctx, tenant, uuid.Nil, models.BusinessUnitInput{Name: sp("Kid"), ParentID: &from.ID})
	asset := uuid.New()
	if _, err := db.Exec(`INSERT INTO assets(id,tenant_id,hostname,class_key,class_path,asset_status,business_unit_id) VALUES($1,$2,'h','server','hardware.computer.server','monitoring',$3)`, asset, tenant, from.ID); err != nil {
		t.Fatal(err)
	}
	var inUse *BusinessUnitInUseError
	if err := svc.Delete(ctx, tenant, uuid.Nil, from.ID, nil); !errors.As(err, &inUse) || inUse.Assets != 1 {
		t.Fatalf("delete while referenced: %v, want BusinessUnitInUseError with 1 asset", err)
	}
	if _, err := svc.Get(ctx, tenant, from.ID); err != nil {
		t.Errorf("a refused delete removed the unit: %v", err)
	}
	if err := svc.Delete(ctx, tenant, uuid.Nil, from.ID, &from.ID); err == nil {
		t.Error("reassigning to the unit being deleted must be refused")
	}
	if err := svc.Delete(ctx, tenant, uuid.Nil, from.ID, &to.ID); err != nil {
		t.Fatalf("delete with reassign: %v", err)
	}
	var got uuid.UUID
	if err := db.Get(&got, `SELECT business_unit_id FROM assets WHERE id=$1`, asset); err != nil || got != to.ID {
		t.Errorf("asset moved to %v (%v), want %v", got, err, to.ID)
	}
	k, err := svc.Get(ctx, tenant, kid.ID)
	if err != nil || k.ParentID != nil {
		t.Errorf("child after deleting its root parent: %+v %v (want re-parented to the deleted unit's parent, here none)", k, err)
	}
	// An unreferenced unit deletes without a target.
	if err := svc.Delete(ctx, tenant, uuid.Nil, kid.ID, nil); err != nil {
		t.Errorf("delete unreferenced: %v", err)
	}
}

func TestIntegration_BusinessUnits_RecordsChanges(t *testing.T) {
	svc, rec, tenant, _ := buFixture(t)
	ctx := context.Background()
	u, err := svc.Create(ctx, tenant, uuid.Nil, models.BusinessUnitInput{Name: sp("Finance")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Update(ctx, tenant, uuid.Nil, u.ID, models.BusinessUnitInput{Description: sp("Money")}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, tenant, uuid.Nil, u.ID, nil); err != nil {
		t.Fatal(err)
	}
	if len(rec.got) != 3 {
		t.Fatalf("recorded %d changes, want 3 (create, update, delete)", len(rec.got))
	}
	for i, want := range []string{"create", "update", "delete"} {
		if rec.got[i].Action != want || rec.got[i].ObjectID != u.ID || rec.got[i].ObjectKind != "business_unit" {
			t.Errorf("change %d = %+v, want %s of %s", i, rec.got[i], want, u.ID)
		}
	}
	if _, ok := rec.got[1].Diff["description"]; !ok || len(rec.got[1].Diff) != 1 {
		t.Errorf("update diff = %v, want exactly description", rec.got[1].Diff)
	}
	if rec.got[0].Before != nil || rec.got[2].After != nil {
		t.Errorf("create must have no Before and delete no After")
	}
}

func TestIntegration_BusinessUnits_AssetAssignmentAndQuery(t *testing.T) {
	svc, rec, tenant, db := buFixture(t)
	ctx := context.Background()
	assets := NewAssetService(db)
	assets.SetBusinessUnitService(svc)

	corp, _ := svc.Create(ctx, tenant, uuid.Nil, models.BusinessUnitInput{Name: sp("Corporate")})
	fin, _ := svc.Create(ctx, tenant, uuid.Nil, models.BusinessUnitInput{Name: sp("Finance"), ParentID: &corp.ID})
	mk := func(host string) uuid.UUID {
		id := uuid.New()
		if _, err := db.Exec(`INSERT INTO assets(id,tenant_id,hostname,class_key,class_path,asset_status) VALUES($1,$2,$3,'server','hardware.computer.server','monitoring')`, id, tenant, host); err != nil {
			t.Fatal(err)
		}
		return id
	}
	a, b, c := mk("a.example.test"), mk("b.example.test"), mk("c.example.test")
	finID := fin.ID.String()
	if _, _, err := assets.UpdateAsset(tenant, a, models.AssetInput{BusinessUnitID: &finID}, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	// An import-style name resolves to the SAME unit, case-insensitively, and creates a new one when unknown.
	if _, _, err := assets.UpdateAsset(tenant, b, models.AssetInput{BusinessUnit: sp("corporate")}, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := assets.UpdateAsset(tenant, c, models.AssetInput{BusinessUnit: sp("Brand New")}, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	got, err := assets.GetAssetByID(tenant, a)
	if err != nil || got.BusinessUnit == nil || got.BusinessUnit.Name != "Finance" || got.BusinessUnit.Slug != "finance" {
		t.Fatalf("asset a business unit = %+v (%v)", got.BusinessUnit, err)
	}
	if bb, _ := assets.GetAssetByID(tenant, b); bb.BusinessUnit == nil || bb.BusinessUnit.ID != corp.ID {
		t.Errorf("name 'corporate' resolved to %+v, want the existing Corporate", bb.BusinessUnit)
	}
	if cc, _ := assets.GetAssetByID(tenant, c); cc.BusinessUnit == nil || cc.BusinessUnit.Name != "Brand New" {
		t.Errorf("unknown name should create the unit, got %+v", cc.BusinessUnit)
	}
	if _, _, err := assets.UpdateAsset(tenant, a, models.AssetInput{BusinessUnitID: sp("00000000-0000-0000-0000-00000000dead")}, uuid.Nil); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("unknown business_unit_id: %v, want ErrInvalidInput", err)
	}

	count := func(q string) int {
		_, total, err := assets.GetAssets(tenant, models.AssetFilters{Query: q, Page: 1, PageSize: 50, AssetStatus: []string{"monitoring"}})
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return total
	}
	for q, want := range map[string]int{
		`business_unit = "Finance"`:          1,
		`business_unit:finance`:              1,
		`business_unit.id = "` + finID + `"`: 1,
		`business_unit.parent = Corporate`:   2, // Corporate itself and Finance beneath it
		`business_unit.parent = Finance`:     1,
		`business_unit != Finance`:           2,
		`exists(business_unit)`:              3,
	} {
		if got := count(q); got != want {
			t.Errorf("%s -> %d assets, want %d", q, got, want)
		}
	}
	// The facet names the unit.
	buckets, err := assets.GetAssetFacets(tenant, models.AssetFilters{}, "business_unit", 20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, bk := range buckets {
		if bk.Key == "finance" && bk.Label == "Finance" && bk.ID == finID && bk.Count == 1 {
			found = true
		}
	}
	if !found {
		t.Errorf("facet buckets = %+v, want finance/Finance/%s/1", buckets, finID)
	}
	// The asset's own Changes tab got the assignment: a (Finance), b (Corporate), c (new).
	nAsset := 0
	for _, ch := range rec.got {
		if ch.ObjectKind == "asset" && ch.ObjectID == a {
			nAsset++
			if _, ok := ch.Diff["business_unit_id"]; !ok {
				t.Errorf("asset change without a business_unit_id diff: %+v", ch)
			}
		}
	}
	if nAsset != 1 {
		t.Errorf("recorded %d asset changes for a, want 1", nAsset)
	}
	// Clearing.
	if _, _, err := assets.UpdateAsset(tenant, a, models.AssetInput{BusinessUnitID: sp("")}, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := assets.GetAssetByID(tenant, a); got.BusinessUnit != nil {
		t.Errorf("cleared assignment still %+v", got.BusinessUnit)
	}
}

func TestIntegration_BusinessUnits_SchemaReappliesOverPopulatedData(t *testing.T) {
	svc, _, tenant, db := buFixture(t)
	ctx := context.Background()
	u, _ := svc.Create(ctx, tenant, uuid.Nil, models.BusinessUnitInput{Name: sp("Keep")})
	id := uuid.New()
	if _, err := db.Exec(`INSERT INTO assets(id,tenant_id,hostname,class_key,class_path,asset_status,business_unit_id) VALUES($1,$2,'h','server','hardware.computer.server','monitoring',$3)`, id, tenant, u.ID); err != nil {
		t.Fatal(err)
	}
	testdb.ForceApplySchema(t, db.DB.DB)
	var got uuid.UUID
	if err := db.Get(&got, `SELECT business_unit_id FROM assets WHERE id=$1`, id); err != nil || got != u.ID {
		t.Errorf("assignment after a second schema apply: %v %v", got, err)
	}
}

// The default recorder writes REAL object_changes rows: create -> update ->
// delete is three rows, the update carrying only the field that moved. Replace
// the recorder call in record() with nothing and this goes red.
func TestIntegration_BusinessUnits_WritesObjectChangesRows(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	svc := NewBusinessUnitService(db) // the real substrate recorder
	ctx := context.Background()

	user := uuid.New()
	if _, err := raw.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`, user, tenant, "bu-actor@example.com"); err != nil {
		t.Fatal(err)
	}
	u, err := svc.Create(ctx, tenant, user, models.BusinessUnitInput{Name: sp("Finance")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Update(ctx, tenant, user, u.ID, models.BusinessUnitInput{Description: sp("Money")}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, tenant, user, u.ID, nil); err != nil {
		t.Fatal(err)
	}
	rows, err := raw.Query(`SELECT action, changed_fields, source, user_id FROM object_changes WHERE tenant_id=$1 AND object_kind='business_unit' AND object_id=$2 ORDER BY created_at`, tenant, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var actions []string
	for rows.Next() {
		var a, src string
		var fields []byte
		var uid *uuid.UUID
		if err := rows.Scan(&a, &fields, &src, &uid); err != nil {
			t.Fatal(err)
		}
		actions = append(actions, a)
		if a == "update" && string(fields) != "{description}" {
			t.Errorf("update changed_fields = %s, want {description}", fields)
		}
		if src != "ui" || uid == nil || *uid != user {
			t.Errorf("%s attributed to source=%s user=%v, want ui/%s", a, src, uid, user)
		}
	}
	if len(actions) != 3 || actions[0] != "create" || actions[1] != "update" || actions[2] != "delete" {
		t.Errorf("object_changes actions = %v, want [create update delete]", actions)
	}
}
