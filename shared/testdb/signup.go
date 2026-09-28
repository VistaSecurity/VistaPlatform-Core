package testdb

import (
	"database/sql"
	"testing"
)

// OpenSelfSignup records the operator choice "self-service sign-up is open"
// (platform_settings.registration_enabled = true) on db.
//
// Since a Core or Enterprise install with no recorded choice admits a
// sign-up only while it has no live tenant, and the shared test database
// always holds other suites' tenants. A test that exercises what a sign-up
// CREATES, rather than whether one is allowed, calls this first, which is how
// an operator running an open-sign-up install is configured.
//
// Safe on the shared database: every caller writes the same value, the write
// is an idempotent upsert on the unique setting_key, and nothing on the shared
// database tests the default. The gate's own tests use ScratchDatabase.
func OpenSelfSignup(t testing.TB, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`
		INSERT INTO platform_settings (setting_key, setting_value)
		VALUES ('registration_enabled', 'true'::jsonb)
		ON CONFLICT (setting_key) DO UPDATE SET setting_value = 'true'::jsonb`); err != nil {
		t.Fatalf("testdb.OpenSelfSignup: %v", err)
	}
}
