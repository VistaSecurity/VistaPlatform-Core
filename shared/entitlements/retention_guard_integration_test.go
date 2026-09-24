package entitlements_test

// The Enterprise retention cap (platform_settings "retention.max_days") is
// writable only by the bypass role or the table owner — the schema's
// guard_platform_retention_setting trigger. crypto_app keeps full DML on every
// other platform setting, and SELECT on this one (every service's resolver
// reads it through its app pool).
//
// Why it matters: the retention sweep deletes tenant data on this value,
// so an app-pool write — request-driven SQL — must not be able to lower it,
// delete it, or smuggle it in by renaming another key.
//
// Mutations (each turns a case red):
//   - drop the trigger                                  → every crypto_app write lands
//   - drop the DELETE branch (OLD on UPDATE/DELETE)     → delete / rename-away cases
//   - drop the INSERT/UPDATE NEW branch                 → insert / rename-to cases
//   - let everyone through the privilege test           → crypto_app cases
//
// Scratch database (it writes a global setting). Skips without
// TEST_DATABASE_URL.

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/entitlements"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// isInsufficientPrivilege reports SQLSTATE 42501.
func isInsufficientPrivilege(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "42501"
}

func TestIntegration_RetentionSetting_WritableOnlyByBypassOrOwner(t *testing.T) {
	owner := testdb.ScratchDatabase(t)
	app := testdb.ConnectScratchAsAppRole(t, owner)
	bypass := testdb.ConnectScratchAsBypassRole(t, owner)
	t.Cleanup(entitlements.FlushLicenseCache)
	ctx := context.Background()
	key := entitlements.RetentionSettingKey

	value := func() string {
		t.Helper()
		var v sql.NullString
		err := owner.QueryRow(`SELECT setting_value::text FROM platform_settings WHERE setting_key = $1`, key).Scan(&v)
		if errors.Is(err, sql.ErrNoRows) {
			return "<none>"
		}
		if err != nil {
			t.Fatal(err)
		}
		return v.String
	}
	refused := func(what string, db *sql.DB, q string, args ...any) {
		t.Helper()
		before := value()
		_, err := db.ExecContext(ctx, q, args...)
		if !isInsufficientPrivilege(err) {
			t.Errorf("crypto_app %s: err = %v, want insufficient_privilege (42501)", what, err)
		}
		if after := value(); after != before {
			t.Errorf("crypto_app %s changed the cap: %s → %s", what, before, after)
		}
	}

	// crypto_app cannot create it.
	refused("INSERT", app, `INSERT INTO platform_settings (setting_key, setting_value) VALUES ($1, '30'::jsonb)`, key)

	// The bypass role (admin-service's PUT /admin/license/retention) can.
	mustExec(t, bypass, `INSERT INTO platform_settings (setting_key, setting_value) VALUES ($1, '730'::jsonb)
		ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value`, key)
	if got := value(); got != "730" {
		t.Fatalf("bypass write: cap = %s, want 730", got)
	}

	// crypto_app can neither change nor remove it — directly, or by renaming.
	refused("UPDATE", app, `UPDATE platform_settings SET setting_value = '1'::jsonb WHERE setting_key = $1`, key)
	refused("DELETE", app, `DELETE FROM platform_settings WHERE setting_key = $1`, key)
	refused("rename away", app, `UPDATE platform_settings SET setting_key = 'retention.parked' WHERE setting_key = $1`, key)
	mustExec(t, owner, `INSERT INTO platform_settings (setting_key, setting_value) VALUES ('it.decoy', '1'::jsonb)`)
	mustExec(t, owner, `DELETE FROM platform_settings WHERE setting_key = $1`, key)
	refused("rename to", app, `UPDATE platform_settings SET setting_key = $1 WHERE setting_key = 'it.decoy'`, key)

	// crypto_app still reads it (every resolver does) and still writes every
	// other setting.
	mustExec(t, bypass, `INSERT INTO platform_settings (setting_key, setting_value) VALUES ($1, '365'::jsonb)`, key)
	var read string
	if err := app.QueryRow(`SELECT setting_value::text FROM platform_settings WHERE setting_key = $1`, key).Scan(&read); err != nil || read != "365" {
		t.Fatalf("crypto_app read = %q, %v; want 365", read, err)
	}
	mustExec(t, app, `UPDATE platform_settings SET setting_value = '2'::jsonb WHERE setting_key = 'it.decoy'`)
	mustExec(t, app, `DELETE FROM platform_settings WHERE setting_key = 'it.decoy'`)

	// The owner (superuser, or an install without the RLS roles) is not refused.
	mustExec(t, owner, `UPDATE platform_settings SET setting_value = 'null'::jsonb WHERE setting_key = $1`, key)
	mustExec(t, bypass, `DELETE FROM platform_settings WHERE setting_key = $1`, key)
	if got := value(); got != "<none>" {
		t.Fatalf("bypass delete: cap = %s, want none", got)
	}
}
