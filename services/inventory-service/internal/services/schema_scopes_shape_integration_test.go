package services

// The statement-ordering class of schema bug: a statement that is fine against
// today's table shape and fails against the shape a PREVIOUS release left
// behind.
//
// `scopes_audit_trigger`'s WHEN clause names `OLD.query` / `NEW.query`, and
// Postgres validates a trigger's WHEN clause at CREATE time. On a database that
// still had the pre-query `scopes` shape — a jsonb `predicate` column and no
// `query` — the CREATE TRIGGER failed, `ON_ERROR_STOP=1` stopped the file
// there, and the ALTERs that would have added the column were three thousand
// lines further down in POST-MIGRATIONS. The `DROP TRIGGER IF EXISTS` on the
// line above had already committed, so the database was left with no audit
// trigger on scopes AND no way to re-apply the file. Permanently wedged, and
// invisible to every fresh double-apply, because both of ITS passes build
// today's shape.
//
// This test builds the old shape deliberately and applies the file over it,
// which is what a customer's `helm upgrade` does.
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_Schema_AppliesOverThePreQueryScopesShape(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	schemaPath := filepath.Join(testdb.RepoRoot(t), "scripts", "database", "schema.sql")
	body, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}

	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("acquire connection: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// The same advisory lock every schema-mutating helper takes: this module's
	// packages run in parallel against one database.
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(889)`); err != nil {
		t.Fatalf("pg_advisory_lock: %v", err)
	}
	defer func() { _, _ = conn.ExecContext(ctx, `SELECT pg_advisory_unlock(889)`) }()

	// Rewind `scopes` and `scopes_audit` to the shape the previous release left:
	// jsonb predicate columns, no query columns. Spelled out rather than read
	// from `git show <tag>:schema.sql` so the test is readable and does not need
	// git history — the SHAPE is what matters, and it is three columns.
	rewind := []string{
		`DROP TRIGGER IF EXISTS scopes_audit_trigger ON public.scopes`,
		`ALTER TABLE public.scopes DROP COLUMN IF EXISTS query`,
		`ALTER TABLE public.scopes ADD COLUMN IF NOT EXISTS predicate jsonb NOT NULL DEFAULT '{}'::jsonb`,
		`ALTER TABLE public.scopes_audit DROP COLUMN IF EXISTS query_before`,
		`ALTER TABLE public.scopes_audit DROP COLUMN IF EXISTS query_after`,
		`ALTER TABLE public.scopes_audit ADD COLUMN IF NOT EXISTS predicate_before jsonb`,
		`ALTER TABLE public.scopes_audit ADD COLUMN IF NOT EXISTS predicate_after jsonb`,
	}
	for _, stmt := range rewind {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("rewind to the pre-query scopes shape (%s): %v", stmt, err)
		}
	}
	// Restore the shape for everyone else even if the apply below fails: this
	// database is shared with the other packages running in parallel.
	defer func() {
		for _, stmt := range []string{
			`ALTER TABLE public.scopes ADD COLUMN IF NOT EXISTS query text NOT NULL DEFAULT ''`,
			`ALTER TABLE public.scopes DROP COLUMN IF EXISTS predicate`,
			`ALTER TABLE public.scopes_audit ADD COLUMN IF NOT EXISTS query_before text NOT NULL DEFAULT ''`,
			`ALTER TABLE public.scopes_audit ADD COLUMN IF NOT EXISTS query_after text NOT NULL DEFAULT ''`,
			`ALTER TABLE public.scopes_audit DROP COLUMN IF EXISTS predicate_before`,
			`ALTER TABLE public.scopes_audit DROP COLUMN IF EXISTS predicate_after`,
		} {
			_, _ = conn.ExecContext(ctx, stmt)
		}
	}()

	if _, err := conn.ExecContext(ctx, string(body)); err != nil {
		t.Fatalf("schema.sql does not apply over the PREVIOUS release's scopes shape — a customer's "+
			"helm upgrade would abort here, with the audit trigger already dropped: %v", err)
	}

	// The trigger is back, and it is the one that reads `query`.
	var present bool
	if err := conn.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_trigger
			WHERE tgname = 'scopes_audit_trigger' AND NOT tgisinternal
			  AND tgrelid = 'public.scopes'::regclass)`).Scan(&present); err != nil {
		t.Fatalf("look for the trigger: %v", err)
	}
	if !present {
		t.Error("scopes_audit_trigger is missing after the apply; the file dropped it and never put it back")
	}

	var hasQuery bool
	if err := conn.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = 'scopes' AND column_name = 'query')`).Scan(&hasQuery); err != nil {
		t.Fatalf("look for scopes.query: %v", err)
	}
	if !hasQuery {
		t.Error("scopes.query is missing after the apply")
	}
}
