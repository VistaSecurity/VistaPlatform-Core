package authpolicy_test

import (
	"database/sql"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/shared/security/authpolicy"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The readers behind the admin-ui Security ▸ Policy fields, against a real
// Postgres.
//
// A mock cannot prove what matters here: that the JSON scalar admin-service
// writes into platform_settings.setting_value is the same shape these readers
// parse back out. The four settings were saved, redisplayed and enforced by
// nothing for a long time precisely because no test ever crossed that boundary.
//
// Skips unless TEST_DATABASE_URL is set — run `make test-integration-db`.

// setSetting writes one platform_settings row exactly the way
// admin-service's UpdatePlatformSettings does (json.Marshal of the scalar) and
// restores the prior state at test end. platform_settings is a global,
// process-wide table, so the restore matters.
func setSetting(t *testing.T, db *sql.DB, key, jsonValue string) {
	t.Helper()

	var prev []byte
	hadPrev := true
	if err := db.QueryRow(`SELECT setting_value FROM platform_settings WHERE setting_key = $1`, key).Scan(&prev); err != nil {
		if err != sql.ErrNoRows {
			t.Fatalf("read prior %s: %v", key, err)
		}
		hadPrev = false
	}

	if _, err := db.Exec(`
		INSERT INTO platform_settings (setting_key, setting_value, updated_at)
		VALUES ($1, $2::jsonb, NOW())
		ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value, updated_at = NOW()`,
		key, jsonValue); err != nil {
		t.Fatalf("set %s=%s: %v", key, jsonValue, err)
	}

	t.Cleanup(func() {
		if hadPrev {
			_, _ = db.Exec(`UPDATE platform_settings SET setting_value = $2 WHERE setting_key = $1`, key, prev)
			return
		}
		_, _ = db.Exec(`DELETE FROM platform_settings WHERE setting_key = $1`, key)
	})
}

func clearSetting(t *testing.T, db *sql.DB, key string) {
	t.Helper()
	var prev []byte
	hadPrev := true
	if err := db.QueryRow(`SELECT setting_value FROM platform_settings WHERE setting_key = $1`, key).Scan(&prev); err != nil {
		if err != sql.ErrNoRows {
			t.Fatalf("read prior %s: %v", key, err)
		}
		hadPrev = false
	}
	if _, err := db.Exec(`DELETE FROM platform_settings WHERE setting_key = $1`, key); err != nil {
		t.Fatalf("clear %s: %v", key, err)
	}
	t.Cleanup(func() {
		if hadPrev {
			_, _ = db.Exec(`
				INSERT INTO platform_settings (setting_key, setting_value, updated_at) VALUES ($1, $2, NOW())
				ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value`, key, prev)
		}
	})
}

// The headline assertion: a value the operator saved is the value in force.
func TestIntegration_Lockout_HonoursSavedSettings(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	setSetting(t, db, "max_login_attempts", "3")
	setSetting(t, db, "lockout_duration_minutes", "60")

	got := authpolicy.Lockout(db)
	if got.MaxAttempts != 3 {
		t.Errorf("MaxAttempts = %d, want 3 — the saved setting is not in force (this is the whole bug)", got.MaxAttempts)
	}
	if got.Duration != 60*time.Minute {
		t.Errorf("Duration = %v, want 60m", got.Duration)
	}
}

// No saved row → the behaviour every existing deployment already has.
func TestIntegration_Lockout_FallsBackToHistoricalDefaults(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	clearSetting(t, db, "max_login_attempts")
	clearSetting(t, db, "lockout_duration_minutes")

	got := authpolicy.Lockout(db)
	if got.MaxAttempts != authpolicy.DefaultMaxLoginAttempts {
		t.Errorf("MaxAttempts = %d, want the historical %d", got.MaxAttempts, authpolicy.DefaultMaxLoginAttempts)
	}
	if got.Duration != authpolicy.DefaultLockoutDuration {
		t.Errorf("Duration = %v, want the historical %v", got.Duration, authpolicy.DefaultLockoutDuration)
	}
}

// A nonsense stored value must not disable the control. 0 attempts would lock an
// account over a request that has not happened; a 100-year lockout is a
// permanent one. Both clamp, neither is honoured verbatim.
func TestIntegration_Lockout_ClampsNonsense(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	setSetting(t, db, "max_login_attempts", "0")
	setSetting(t, db, "lockout_duration_minutes", "999999999")

	got := authpolicy.Lockout(db)
	if got.MaxAttempts != authpolicy.MinMaxLoginAttempts {
		t.Errorf("MaxAttempts = %d, want the clamp %d", got.MaxAttempts, authpolicy.MinMaxLoginAttempts)
	}
	if got.Duration != authpolicy.MaxLockoutDuration {
		t.Errorf("Duration = %v, want the clamp %v", got.Duration, authpolicy.MaxLockoutDuration)
	}
}

// A value of the wrong JSON type must fall back, not panic or zero out.
func TestIntegration_Lockout_FallsBackOnWrongType(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	setSetting(t, db, "max_login_attempts", `"three"`)

	if got := authpolicy.Lockout(db).MaxAttempts; got != authpolicy.DefaultMaxLoginAttempts {
		t.Errorf("MaxAttempts = %d on a string value, want the safe default %d", got, authpolicy.DefaultMaxLoginAttempts)
	}
}

func TestIntegration_SessionLifetime_HonoursSavedSetting(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	const fallback = 7 * 24 * time.Hour
	setSetting(t, db, "session_timeout_minutes", "90")

	if got := authpolicy.SessionLifetime(db, fallback); got != 90*time.Minute {
		t.Errorf("SessionLifetime = %v, want 90m — the saved setting is not in force", got)
	}
}

func TestIntegration_SessionLifetime_FallsBackWhenUnset(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	const fallback = 7 * 24 * time.Hour
	clearSetting(t, db, "session_timeout_minutes")

	if got := authpolicy.SessionLifetime(db, fallback); got != fallback {
		t.Errorf("SessionLifetime = %v, want the caller's fallback %v", got, fallback)
	}
}

// A nil handle must not panic on a login path.
func TestNilDB_UsesDefaults(t *testing.T) {
	got := authpolicy.Lockout(nil)
	if got.MaxAttempts != authpolicy.DefaultMaxLoginAttempts || got.Duration != authpolicy.DefaultLockoutDuration {
		t.Errorf("Lockout(nil) = %+v, want the built-in defaults", got)
	}
	if got := authpolicy.SessionLifetime(nil, time.Hour); got != time.Hour {
		t.Errorf("SessionLifetime(nil) = %v, want the fallback 1h", got)
	}
}
