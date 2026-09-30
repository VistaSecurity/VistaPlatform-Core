package identitysettings

// ReadAutoMergeExisting against a real Postgres ( Phase 4).
//
// The unit tests pin the decode; this pins the QUERY — that `->` against a real
// jsonb column reaches the value, distinguishes the boolean false from the
// string "false", and survives the shapes a settings row can be in.
//
// Skips without TEST_DATABASE_URL (make test-integration-db / nightly).

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func setConfig(t *testing.T, db *sql.DB, tenant uuid.UUID, config string) {
	t.Helper()
	// The harness's connection is the table owner, so RLS does not gate this
	// setup write; the read under test goes through the same handle.
	if _, err := db.Exec(`
		INSERT INTO tenant_admin_settings (tenant_id, config, version, created_at, updated_at)
		VALUES ($1, $2::jsonb, 1, NOW(), NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET config = EXCLUDED.config`,
		tenant, config); err != nil {
		t.Fatalf("seed config %s: %v", config, err)
	}
}

func TestIntegration_ReadAutoMergeExisting(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	ctx := context.Background()

	var logged int
	prev := logf
	logf = func(string, ...any) { logged++ }
	t.Cleanup(func() { logf = prev })

	// A tenant with no settings row at all.
	noRow := testdb.NewTenant(t, db)
	if got, err := ReadAutoMergeExisting(ctx, db, noRow); err != nil || !got {
		t.Fatalf("no settings row: got (%v, %v), want (true, nil): a tenant who never opened Settings has the default ON", got, err)
	}

	cases := []struct {
		name       string
		config     string
		want       bool
		wantLogged bool
	}{
		{"row without an identity block", `{"onboarding_required":true}`, true, false},
		{"identity block without the key", `{"identity":{"auto_accept_threshold":0.9}}`, true, false},
		{"explicit true", `{"identity":{"auto_merge_existing":true}}`, true, false},
		{"explicit false", `{"identity":{"auto_merge_existing":false}}`, false, false},
		{"false beside a threshold", `{"identity":{"auto_accept_threshold":0.9,"auto_merge_existing":false}}`, false, false},
		{"json null", `{"identity":{"auto_merge_existing":null}}`, true, false},
		{"the STRING false is malformed, not an answer", `{"identity":{"auto_merge_existing":"false"}}`, true, true},
		{"a number is malformed", `{"identity":{"auto_merge_existing":0}}`, true, true},
		{"an object is malformed", `{"identity":{"auto_merge_existing":{}}}`, true, true},
		{"identity is not an object", `{"identity":"off"}`, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tenant := testdb.NewTenant(t, db)
			setConfig(t, db, tenant, c.config)
			logged = 0
			got, err := ReadAutoMergeExisting(ctx, db, tenant)
			if err != nil {
				t.Fatalf("ReadAutoMergeExisting(%s): %v", c.config, err)
			}
			if got != c.want {
				t.Errorf("%s read as %v, want %v", c.config, got, c.want)
			}
			if (logged > 0) != c.wantLogged {
				t.Errorf("%s logged %d times, want logged=%v", c.config, logged, c.wantLogged)
			}
			// The string-tenant variant must agree.
			if viaFor, err := ReadAutoMergeExistingFor(ctx, db, tenant.String()); err != nil || viaFor != c.want {
				t.Errorf("ReadAutoMergeExistingFor = (%v, %v), want (%v, nil)", viaFor, err, c.want)
			}
		})
	}
}

// One tenant's OFF must not turn another's off. The read is a primary-key
// lookup on the caller's transaction, so this is cheap to pin and expensive to
// discover: a leak here would switch off a rule merge for a tenant who never
// asked.
func TestIntegration_ReadAutoMergeExisting_IsPerTenant(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	ctx := context.Background()

	off, other := testdb.NewTenant(t, db), testdb.NewTenant(t, db)
	setConfig(t, db, off, `{"identity":{"auto_merge_existing":false}}`)

	if got, _ := ReadAutoMergeExisting(ctx, db, off); got {
		t.Error("the tenant that turned it off reads ON")
	}
	if got, _ := ReadAutoMergeExisting(ctx, db, other); !got {
		t.Error("another tenant reads OFF because a different tenant turned the rule off")
	}
}
