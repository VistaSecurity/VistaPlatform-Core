package dcim_test

// DB-integration tests for the DCIM object substrate (BUILD_PLAN row 0.3):
// RLS on the six tables through the real writers as the non-owner app role,
// the object_changes partitioning, the object-kind CHECK, and a re-apply of the
// schema over populated substrate tables. They skip unless TEST_DATABASE_URL is
// set (`make test-integration-db`).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/dcim/journal"
	"github.com/vistasecurity/vistaplatform/shared/dcim/tags"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func actorCtx() context.Context {
	ctx := changes.WithActor(context.Background(), changes.Actor{UserID: uuid.New(), UserName: "it@example.test"})
	return changes.WithSource(changes.WithRequestID(ctx, uuid.New()), changes.SourceUI)
}

// Two tenants writing through the real writers as crypto_app. Each sees its own
// change rows and nothing of the other's; a write that names the other tenant
// is refused by the policy (USING doubles as WITH CHECK). Mutation: drop
// object_changes_tenant_isolation → with RLS on and no policy, the app role
// reads nothing at all and the own-tenant assertions fail.
func TestIntegration_ObjectChanges_RLS(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	a, b := testdb.NewTenant(t, owner), testdb.NewTenant(t, owner)
	ctx := actorCtx()
	objA, objB := uuid.New(), uuid.New()

	for _, tc := range []struct {
		tenant, obj uuid.UUID
	}{{a, objA}, {b, objB}} {
		err := database.WithTenantTx(ctx, app, tc.tenant, func(tx *sql.Tx) error {
			return changes.InTx(tx).Record(ctx, changes.Change{
				TenantID: tc.tenant, Kind: dcim.ObjectKindAsset, ID: tc.obj, Action: changes.ActionUpdate,
				Pre: map[string]any{"name": "x"}, Post: map[string]any{"name": "y"},
			})
		})
		if err != nil {
			t.Fatalf("record for tenant %s: %v", tc.tenant, err)
		}
	}

	read := func(scope uuid.UUID, filterTenant uuid.UUID) []changes.ObjectChange {
		t.Helper()
		var out []changes.ObjectChange
		err := database.WithTenantTx(context.Background(), app, scope, func(tx *sql.Tx) error {
			var err error
			out, _, err = changes.List(context.Background(), tx, changes.Filter{TenantID: filterTenant})
			return err
		})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		return out
	}
	if got := read(a, a); len(got) != 1 || got[0].ObjectID != objA || got[0].UserID == nil || got[0].RequestID == nil {
		t.Fatalf("tenant A reads its own changes: %+v", got)
	}
	// The explicit predicate names B but the transaction is A's: RLS is the
	// second layer and must hold on its own.
	if got := read(a, b); len(got) != 0 {
		t.Fatalf("tenant A read tenant B's changes through RLS: %+v", got)
	}

	// Insert path: scoped to A, writing a row for B.
	err := database.WithTenantTx(ctx, app, a, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO object_changes (tenant_id, object_kind, object_id, action, postchange_data, source)
			VALUES ($1, 'asset', $2, 'create', '{}', 'system')`, b, uuid.New())
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "row-level security") {
		t.Fatalf("a cross-tenant insert into object_changes was not refused by RLS: %v", err)
	}
}

// Every substrate table, both directions, through the app role.
func TestIntegration_Substrate_RLSOnAllTables(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	a, b := testdb.NewTenant(t, owner), testdb.NewTenant(t, owner)
	ctx := actorCtx()
	obj := uuid.New()

	err := database.WithTenantTx(ctx, app, a, func(tx *sql.Tx) error {
		rec := changes.InTx(tx)
		tg, err := tags.Create(ctx, tx, rec, a, tags.Input{Name: "Core Switch"})
		if err != nil {
			return fmt.Errorf("create tag: %w", err)
		}
		if _, err := tags.SetForObject(ctx, tx, rec, a, dcim.ObjectKindAsset, obj, []uuid.UUID{tg.ID}); err != nil {
			return fmt.Errorf("set tags: %w", err)
		}
		if _, err := journal.Add(ctx, tx, rec, a, dcim.ObjectKindAsset, obj, journal.KindWarning, "fan tray replaced"); err != nil {
			return fmt.Errorf("journal: %w", err)
		}
		if _, err := tx.Exec(`INSERT INTO image_attachments (tenant_id, object_kind, object_id, storage_ref, width, height, size_bytes)
			VALUES ($1, 'asset', $2, $3, 10, 10, 100)`, a, obj, "it/"+uuid.NewString()); err != nil {
			return fmt.Errorf("image: %w", err)
		}
		if _, err := tx.Exec(`INSERT INTO unresolved_terminations (tenant_id, producer, origin_kind, origin_id, far_identity, intent, expires_at)
			VALUES ($1, 'lldp', 'interface', $2, '{"chassis_id":"aa"}', 'cable', now() + interval '30 days')`, a, uuid.New()); err != nil {
			return fmt.Errorf("unresolved: %w", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("tenant A writes: %v", err)
	}

	tables := []string{"tags", "object_tags", "journal_entries", "object_changes", "image_attachments", "unresolved_terminations"}
	count := func(scope uuid.UUID, table string) int {
		var n int
		err := database.WithTenantTx(context.Background(), app, scope, func(tx *sql.Tx) error {
			return tx.QueryRow(`SELECT count(*) FROM `+table+` WHERE tenant_id = $1`, a).Scan(&n)
		})
		if err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		return n
	}
	for _, tbl := range tables {
		if n := count(a, tbl); n == 0 {
			t.Errorf("%s: tenant A cannot read its own rows", tbl)
		}
		if n := count(b, tbl); n != 0 {
			t.Errorf("%s: tenant B read %d of tenant A's rows", tbl, n)
		}
	}

	// Cross-tenant inserts, scoped to B, naming A.
	inserts := map[string]string{
		"tags":            `INSERT INTO tags (tenant_id, name, slug) VALUES ($1, 'x', 'x-` + uuid.NewString()[:8] + `')`,
		"journal_entries": `INSERT INTO journal_entries (tenant_id, object_kind, object_id, comments) VALUES ($1, 'asset', gen_random_uuid(), 'x')`,
		"image_attachments": `INSERT INTO image_attachments (tenant_id, object_kind, object_id, storage_ref, width, height, size_bytes)
			VALUES ($1, 'asset', gen_random_uuid(), 'x/` + uuid.NewString() + `', 1, 1, 1)`,
		"unresolved_terminations": `INSERT INTO unresolved_terminations (tenant_id, producer, origin_kind, origin_id, far_identity, intent, expires_at)
			VALUES ($1, 'lldp', 'interface', gen_random_uuid(), '{"chassis_id":"bb"}', 'cable', now())`,
	}
	for tbl, q := range inserts {
		err := database.WithTenantTx(context.Background(), app, b, func(tx *sql.Tx) error {
			_, err := tx.Exec(q, a)
			return err
		})
		if err == nil || !strings.Contains(err.Error(), "row-level security") {
			t.Errorf("%s: cross-tenant insert not refused by RLS: %v", tbl, err)
		}
	}
	// object_tags: B cannot attach A's tag — refused by RLS on the row, and by
	// the composite FK if it named its own tenant with A's tag id.
	var tagA uuid.UUID
	if err := owner.QueryRow(`SELECT id FROM tags WHERE tenant_id = $1`, a).Scan(&tagA); err != nil {
		t.Fatal(err)
	}
	err = database.WithTenantTx(context.Background(), app, b, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO object_tags (tenant_id, object_kind, object_id, tag_id) VALUES ($1, 'asset', gen_random_uuid(), $2)`, b, tagA)
		return err
	})
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) || pqErr.Code != "23503" {
		t.Errorf("tenant B attached tenant A's tag: %v", err)
	}
}

// The writers record what they did: tag create + object tag set + journal add
// leave three change rows with the right kinds and changed fields.
func TestIntegration_Substrate_WritersRecordChanges(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)
	ctx := actorCtx()
	obj := uuid.New()

	var got []changes.ObjectChange
	err := database.WithTenantTx(ctx, app, tenant, func(tx *sql.Tx) error {
		rec := changes.InTx(tx)
		tg, err := tags.Create(ctx, tx, rec, tenant, tags.Input{Name: "Edge", ObjectKinds: []dcim.ObjectKind{dcim.ObjectKindAsset}})
		if err != nil {
			return err
		}
		if _, err := tags.SetForObject(ctx, tx, rec, tenant, dcim.ObjectKindAsset, obj, []uuid.UUID{tg.ID}); err != nil {
			return err
		}
		// Re-setting the same tags changes nothing and records nothing.
		if _, err := tags.SetForObject(ctx, tx, rec, tenant, dcim.ObjectKindAsset, obj, []uuid.UUID{tg.ID}); err != nil {
			return err
		}
		// A tag restricted to assets cannot go on a rack.
		if _, err := tags.SetForObject(ctx, tx, rec, tenant, dcim.ObjectKindRack, uuid.New(), []uuid.UUID{tg.ID}); !errors.Is(err, tags.ErrNotApplicable) {
			return fmt.Errorf("restricted tag applied to a rack: %v", err)
		}
		if _, err := journal.Add(ctx, tx, rec, tenant, dcim.ObjectKindAsset, obj, "", "moved to rack 4"); err != nil {
			return err
		}
		got, _, err = changes.List(ctx, tx, changes.Filter{TenantID: tenant})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("changes = %d, want 3 (tag create, object tags, journal): %+v", len(got), got)
	}
	kinds := map[dcim.ObjectKind]changes.ObjectChange{}
	for _, c := range got {
		kinds[c.ObjectKind] = c
	}
	if c, ok := kinds[dcim.ObjectKindAsset]; !ok || c.ObjectID != obj || len(c.ChangedFields) != 1 || c.ChangedFields[0] != "tags" {
		t.Errorf("object tag change = %+v", c)
	}
	if c, ok := kinds[dcim.ObjectKindTag]; !ok || c.Action != changes.ActionCreate || c.PrechangeData != nil {
		t.Errorf("tag change = %+v", c)
	}
	if _, ok := kinds[dcim.ObjectKindJournalEntry]; !ok {
		t.Errorf("no journal_entry change")
	}
}

// The schema's object-kind list is the generated Go list, exactly. Mutation:
// add a kind to the Go list only (or delete one from the function) → fails.
func TestIntegration_ObjectKindCheck_MatchesGeneratedList(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)

	var inDB pq.StringArray
	if err := owner.QueryRow(`SELECT public.dcim_object_kinds()`).Scan(&inDB); err != nil {
		t.Fatal(err)
	}
	want := make([]string, 0, len(dcim.AllObjectKinds))
	for _, k := range dcim.AllObjectKinds {
		want = append(want, string(k))
	}
	if strings.Join(inDB, ",") != strings.Join(want, ",") {
		t.Fatalf("public.dcim_object_kinds() differs from dcim.AllObjectKinds\n db: %v\ngo: %v", inDB, want)
	}

	// And the CHECK is wired to it on every polymorphic column.
	tenant := testdb.NewTenant(t, owner)
	for _, q := range []string{
		`INSERT INTO journal_entries (tenant_id, object_kind, object_id, comments) VALUES ($1, 'switch_port', gen_random_uuid(), 'x')`,
		`INSERT INTO object_changes (tenant_id, object_kind, object_id, action, postchange_data, source) VALUES ($1, 'switch_port', gen_random_uuid(), 'create', '{}', 'system')`,
		`INSERT INTO image_attachments (tenant_id, object_kind, object_id, storage_ref, width, height, size_bytes) VALUES ($1, 'switch_port', gen_random_uuid(), 'x', 1, 1, 1)`,
		`INSERT INTO unresolved_terminations (tenant_id, producer, origin_kind, origin_id, far_identity, intent, expires_at) VALUES ($1, 'lldp', 'switch_port', gen_random_uuid(), '{"a":"b"}', 'cable', now())`,
		`INSERT INTO tags (tenant_id, name, slug, object_kinds) VALUES ($1, 'k', 'k', ARRAY['switch_port'])`,
		`INSERT INTO object_tags (tenant_id, object_kind, object_id, tag_id) VALUES ($1, 'switch_port', gen_random_uuid(), gen_random_uuid())`,
	} {
		_, err := owner.Exec(q, tenant)
		var pqErr *pq.Error
		if !errors.As(err, &pqErr) || pqErr.Code != "23514" {
			t.Errorf("an unknown object kind was accepted (%v): %s", err, q)
		}
	}
}

func partitionExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var ok bool
	if err := db.QueryRow(`SELECT to_regclass('public.' || $1) IS NOT NULL`, name).Scan(&ok); err != nil {
		t.Fatal(err)
	}
	return ok
}

func monthPartition(tm time.Time) string {
	return fmt.Sprintf("object_changes_y%dm%02d", tm.Year(), int(tm.Month()))
}

// A fresh apply leaves this month and the next three partitioned; a partition
// made later moves the default partition's rows for its month and is
// default-deny when named directly. Mutation: remove the
// `SELECT * FROM public.ensure_object_changes_partitions(3)` call → a fresh
// database has no monthly partition and this fails.
func TestIntegration_ObjectChanges_PartitionCreatedForNextMonth(t *testing.T) {
	db := testdb.ScratchDatabase(t)
	now := time.Now().UTC()
	firstOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i <= 3; i++ {
		name := monthPartition(firstOfMonth.AddDate(0, i, 0))
		if !partitionExists(t, db, name) {
			t.Errorf("fresh apply did not create %s", name)
		}
	}

	// A row for a month with no partition lands in the default …
	tenant := testdb.NewTenant(t, db)
	far := time.Date(2099, 7, 15, 0, 0, 0, 0, time.UTC)
	if _, err := db.Exec(`INSERT INTO object_changes (tenant_id, object_kind, object_id, action, postchange_data, source, created_at)
		VALUES ($1, 'asset', gen_random_uuid(), 'create', '{}', 'system', $2)`, tenant, far); err != nil {
		t.Fatalf("insert into an unpartitioned month: %v", err)
	}
	// … and moves when that month's partition is made.
	var made sql.NullString
	if err := db.QueryRow(`SELECT public.create_object_changes_partition(2099, 7)`).Scan(&made); err != nil {
		t.Fatalf("create partition over a populated default: %v", err)
	}
	if made.String != "object_changes_y2099m07" {
		t.Fatalf("made = %v", made)
	}
	var inPart, inDefault int
	_ = db.QueryRow(`SELECT count(*) FROM object_changes_y2099m07`).Scan(&inPart)
	_ = db.QueryRow(`SELECT count(*) FROM object_changes_default`).Scan(&inDefault)
	if inPart != 1 || inDefault != 0 {
		t.Errorf("rows: partition %d, default %d — want 1, 0", inPart, inDefault)
	}
	var rls bool
	if err := db.QueryRow(`SELECT relrowsecurity FROM pg_class WHERE relname = 'object_changes_y2099m07'`).Scan(&rls); err != nil || !rls {
		t.Errorf("new partition has RLS disabled (%v): naming it directly would bypass the parent's policy", err)
	}
	// Idempotent.
	if err := db.QueryRow(`SELECT public.create_object_changes_partition(2099, 7)`).Scan(&made); err != nil || made.Valid {
		t.Errorf("second create = %v, %v; want NULL", made, err)
	}

	// Retention follows the audit setting: no general policy, nothing dropped;
	// a 30-day general policy drops a partition that ended long ago.
	if _, err := db.Exec(`SELECT public.create_object_changes_partition(2020, 1)`); err != nil {
		t.Fatal(err)
	}
	var dropped pq.StringArray
	if err := db.QueryRow(`SELECT coalesce(array_agg(x), '{}') FROM public.drop_expired_object_changes_partitions() x`).Scan(&dropped); err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 0 || !partitionExists(t, db, "object_changes_y2020m01") {
		t.Fatalf("dropped %v with no retention policy", dropped)
	}
	if _, err := db.Exec(`INSERT INTO audit.retention_policies (policy_name, hot_storage_days, total_retention_days) VALUES ('it-general', 30, 30)`); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT coalesce(array_agg(x), '{}') FROM public.drop_expired_object_changes_partitions() x`).Scan(&dropped); err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 1 || dropped[0] != "object_changes_y2020m01" || partitionExists(t, db, "object_changes_y2020m01") {
		t.Errorf("dropped = %v, want only object_changes_y2020m01", dropped)
	}
	if !partitionExists(t, db, monthPartition(firstOfMonth)) {
		t.Error("retention dropped the current month")
	}
}

// Re-applying the schema over populated substrate tables exits clean (the
// chart re-applies the file on every upgrade).
func TestIntegration_Substrate_ReappliesOverPopulatedTables(t *testing.T) {
	db := testdb.ScratchDatabase(t)
	tenant := testdb.NewTenant(t, db)
	ctx := actorCtx()
	obj := uuid.New()
	err := database.WithTenantTx(ctx, db, tenant, func(tx *sql.Tx) error {
		rec := changes.InTx(tx)
		tg, err := tags.Create(ctx, tx, rec, tenant, tags.Input{Name: "Populated", ObjectKinds: []dcim.ObjectKind{dcim.ObjectKindAsset}})
		if err != nil {
			return err
		}
		if _, err := tags.SetForObject(ctx, tx, rec, tenant, dcim.ObjectKindAsset, obj, []uuid.UUID{tg.ID}); err != nil {
			return err
		}
		if _, err := journal.Add(ctx, tx, rec, tenant, dcim.ObjectKindAsset, obj, journal.KindInfo, "populated"); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO image_attachments (tenant_id, object_kind, object_id, storage_ref, width, height, size_bytes) VALUES ($1, 'asset', $2, 'p/1', 2, 2, 4)`, tenant, obj); err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO unresolved_terminations (tenant_id, producer, origin_kind, origin_id, far_identity, intent, expires_at)
			VALUES ($1, 'lldp', 'interface', $2, '{"chassis_id":"cc"}', 'cable', now() + interval '1 day')`, tenant, obj)
		return err
	})
	if err != nil {
		t.Fatalf("populate: %v", err)
	}
	// Also a row in the default partition, which the re-apply's partition call
	// must not trip over.
	if _, err := db.Exec(`INSERT INTO object_changes (tenant_id, object_kind, object_id, action, postchange_data, source, created_at)
		VALUES ($1, 'asset', $2, 'create', '{}', 'system', '2098-03-03')`, tenant, obj); err != nil {
		t.Fatal(err)
	}
	testdb.ForceApplySchema(t, db)
	testdb.ForceApplySchema(t, db)
	var n int
	if err := db.QueryRow(`SELECT (SELECT count(*) FROM tags WHERE tenant_id = $1) + (SELECT count(*) FROM object_tags WHERE tenant_id = $1)
		+ (SELECT count(*) FROM journal_entries WHERE tenant_id = $1) + (SELECT count(*) FROM object_changes WHERE tenant_id = $1)
		+ (SELECT count(*) FROM image_attachments WHERE tenant_id = $1) + (SELECT count(*) FROM unresolved_terminations WHERE tenant_id = $1)`, tenant).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1+1+1+4+1+1 {
		t.Errorf("rows after two re-applies = %d, want 9", n)
	}
}

// The change record commits or rolls back with the change it describes: a
// writer records, then the caller's work fails after it, and neither the
// object nor its change row survives. Mutation: let InTx take a pool and record
// through it (the change is written on its own connection) → the change row
// outlives the rolled-back tag and this fails.
func TestIntegration_ObjectChanges_RolledBackWithTheWrite(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)
	ctx := actorCtx()
	injected := errors.New("injected failure after Record")

	err := database.WithTenantTx(ctx, app, tenant, func(tx *sql.Tx) error {
		rec := changes.InTx(tx)
		tg, err := tags.Create(ctx, tx, rec, tenant, tags.Input{Name: "Rolled Back"})
		if err != nil {
			return err
		}
		if _, err := tags.SetForObject(ctx, tx, rec, tenant, dcim.ObjectKindAsset, uuid.New(), []uuid.UUID{tg.ID}); err != nil {
			return err
		}
		if _, err := journal.Add(ctx, tx, rec, tenant, dcim.ObjectKindAsset, uuid.New(), journal.KindInfo, "never happened"); err != nil {
			return err
		}
		var recorded int
		if err := tx.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1`, tenant).Scan(&recorded); err != nil {
			return err
		}
		if recorded != 3 {
			return fmt.Errorf("inside the transaction: %d change rows, want 3", recorded)
		}
		return injected
	})
	if !errors.Is(err, injected) {
		t.Fatalf("transaction err = %v, want the injected failure", err)
	}
	for _, tbl := range []string{"object_changes", "tags", "object_tags", "journal_entries"} {
		var n int
		if err := owner.QueryRow(`SELECT count(*) FROM `+tbl+` WHERE tenant_id = $1`, tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s: %d rows survived a rolled-back write", tbl, n)
		}
	}
}

// Secrets never reach the stored images, through the real recorder into the
// real table: a pre/post image carrying psk, password, secret and token
// (top level and nested in custom_fields) is stored with every value replaced,
// while the fields are still listed as changed. Mutation: drop the redact.Map
// calls in Diff → the values land in prechange_data/postchange_data and this
// fails.
func TestIntegration_ObjectChanges_StoredImagesCarryNoSecrets(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)
	ctx := actorCtx()
	obj := uuid.New()

	image := func(v string) map[string]any {
		return map[string]any{
			"name": "tunnel-a", "psk": "psk-" + v, "password": "pw-" + v, "secret": "sec-" + v, "token": "tok-" + v,
			"custom_fields": map[string]any{"api_token": "cf-" + v, "site_code": "lon-1"},
		}
	}
	err := database.WithTenantTx(ctx, app, tenant, func(tx *sql.Tx) error {
		return changes.InTx(tx).Record(ctx, changes.Change{
			TenantID: tenant, Kind: dcim.ObjectKindTunnel, ID: obj, Action: changes.ActionUpdate,
			Pre: image("OLD-9f2c"), Post: image("NEW-41aa"),
		})
	})
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	var pre, post string
	var fields pq.StringArray
	if err := owner.QueryRow(`SELECT prechange_data::text, postchange_data::text, changed_fields FROM object_changes WHERE tenant_id = $1 AND object_id = $2`,
		tenant, obj).Scan(&pre, &post, &fields); err != nil {
		t.Fatal(err)
	}
	for name, img := range map[string]string{"prechange_data": pre, "postchange_data": post} {
		for _, leak := range []string{"OLD-9f2c", "NEW-41aa"} {
			if strings.Contains(img, leak) {
				t.Errorf("%s stores a secret value (%s): %s", name, leak, img)
			}
		}
		if !strings.Contains(img, `"lon-1"`) || !strings.Contains(img, `"tunnel-a"`) {
			t.Errorf("%s lost a non-secret value: %s", name, img)
		}
	}
	want := map[string]bool{"psk": true, "password": true, "secret": true, "token": true, "custom_fields": true}
	for _, f := range fields {
		delete(want, f)
	}
	if len(want) != 0 {
		t.Errorf("changed_fields = %v, missing %v — a rotated secret is still a change", fields, want)
	}
}

// object_changes' partitions are default-deny when named directly: the
// parent's policy covers every query that names public.object_changes, and a
// partition named on its own must not be a way around it. Checked as the app
// role for the current month's partition (made by the schema apply) and the
// default partition, read and insert, across two tenants. Mutation: drop the
// ENABLE ROW LEVEL SECURITY from create_object_changes_partition (or from
// object_changes_default) → tenant B reads tenant A's row through the
// partition and this fails.
func TestIntegration_ObjectChanges_PartitionsDenyDirectAccess(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	a, b := testdb.NewTenant(t, owner), testdb.NewTenant(t, owner)
	ctx := actorCtx()
	if _, err := owner.Exec(`SELECT * FROM public.ensure_object_changes_partitions(0)`); err != nil {
		t.Fatal(err)
	}

	err := database.WithTenantTx(ctx, app, a, func(tx *sql.Tx) error {
		if err := changes.InTx(tx).Record(ctx, changes.Change{
			TenantID: a, Kind: dcim.ObjectKindAsset, ID: uuid.New(), Action: changes.ActionCreate, Post: map[string]any{"name": "now"},
		}); err != nil {
			return err
		}
		// A month no partition covers lands in the default.
		_, err := tx.Exec(`INSERT INTO object_changes (tenant_id, object_kind, object_id, action, postchange_data, source, created_at)
			VALUES ($1, 'asset', gen_random_uuid(), 'create', '{}', 'system', '2097-05-05')`, a)
		return err
	})
	if err != nil {
		t.Fatalf("tenant A writes: %v", err)
	}
	current := monthPartition(time.Now().UTC())
	for _, part := range []string{current, "object_changes_default"} {
		var ownerSees int
		if err := owner.QueryRow(`SELECT count(*) FROM `+part+` WHERE tenant_id = $1`, a).Scan(&ownerSees); err != nil || ownerSees == 0 {
			t.Fatalf("%s: the fixture row is not there (%d, %v)", part, ownerSees, err)
		}
		for _, scope := range []uuid.UUID{a, b} {
			var n int
			err := database.WithTenantTx(context.Background(), app, scope, func(tx *sql.Tx) error {
				return tx.QueryRow(`SELECT count(*) FROM ` + part).Scan(&n)
			})
			if err == nil && n != 0 {
				t.Errorf("%s named directly: the app role scoped to %s read %d rows (default-deny expected)", part, scope, n)
			}
		}
		err := database.WithTenantTx(context.Background(), app, b, func(tx *sql.Tx) error {
			_, err := tx.Exec(`INSERT INTO `+part+` (tenant_id, object_kind, object_id, action, postchange_data, source, created_at)
				VALUES ($1, 'asset', gen_random_uuid(), 'create', '{}', 'system', $2)`, a, map[string]time.Time{
				current: time.Now().UTC(), "object_changes_default": time.Date(2097, 5, 6, 0, 0, 0, 0, time.UTC)}[part])
			return err
		})
		if err == nil {
			t.Errorf("%s named directly: tenant B inserted a row for tenant A", part)
		}
	}
	// Through the parent, the policy still lets A read both of its rows.
	var n int
	if err := database.WithTenantTx(context.Background(), app, a, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT count(*) FROM object_changes`).Scan(&n)
	}); err != nil || n != 2 {
		t.Errorf("tenant A through the parent: %d rows (%v), want 2", n, err)
	}
}

// Setting an object's tags applies the difference: a tag that stays keeps its
// object_tags row (id and created_by — who attached it), only the added and
// removed links move, and the one change row on the object carries the slug
// lists before and after. Mutation: make SetForObject delete every link and
// re-insert the wanted set → the kept tag's link id changes and this fails.
func TestIntegration_Tags_SetForObjectAppliesADiff(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)
	ctx := actorCtx()
	obj := uuid.New()

	var keep, drop, add tags.Tag
	var keepLink uuid.UUID
	err := database.WithTenantTx(ctx, app, tenant, func(tx *sql.Tx) error {
		rec := changes.InTx(tx)
		var err error
		for _, p := range []struct {
			dst  *tags.Tag
			name string
		}{{&keep, "Keep"}, {&drop, "Drop"}, {&add, "Add"}} {
			if *p.dst, err = tags.Create(ctx, tx, rec, tenant, tags.Input{Name: p.name}); err != nil {
				return err
			}
		}
		if _, err := tags.SetForObject(ctx, tx, rec, tenant, dcim.ObjectKindAsset, obj, []uuid.UUID{keep.ID, drop.ID}); err != nil {
			return err
		}
		return tx.QueryRow(`SELECT id FROM object_tags WHERE tenant_id = $1 AND object_id = $2 AND tag_id = $3`, tenant, obj, keep.ID).Scan(&keepLink)
	})
	if err != nil {
		t.Fatal(err)
	}

	second := changes.WithActor(ctx, changes.Actor{UserID: uuid.New(), UserName: "second@example.test"})
	var linkAfter uuid.UUID
	var got []changes.ObjectChange
	err = database.WithTenantTx(second, app, tenant, func(tx *sql.Tx) error {
		after, err := tags.SetForObject(second, tx, changes.InTx(tx), tenant, dcim.ObjectKindAsset, obj, []uuid.UUID{keep.ID, add.ID})
		if err != nil {
			return err
		}
		if len(after) != 2 {
			return fmt.Errorf("after = %d tags, want 2", len(after))
		}
		if err := tx.QueryRow(`SELECT id FROM object_tags WHERE tenant_id = $1 AND object_id = $2 AND tag_id = $3`, tenant, obj, keep.ID).Scan(&linkAfter); err != nil {
			return err
		}
		got, _, err = changes.List(second, tx, changes.Filter{TenantID: tenant, ObjectKind: dcim.ObjectKindAsset, ObjectID: obj})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if linkAfter != keepLink {
		t.Errorf("the kept tag's link was deleted and re-inserted (%s → %s): a tag PUT must apply a diff", keepLink, linkAfter)
	}
	if len(got) != 2 {
		t.Fatalf("object changes = %d, want 2 (one per PUT that moved something)", len(got))
	}
	latest := got[0]
	compact := func(b []byte) string { return strings.ReplaceAll(string(b), " ", "") }
	if compact(latest.PrechangeData) != `{"tags":["drop","keep"]}` || compact(latest.PostchangeData) != `{"tags":["add","keep"]}` {
		t.Errorf("latest change images = %s → %s", latest.PrechangeData, latest.PostchangeData)
	}
}
