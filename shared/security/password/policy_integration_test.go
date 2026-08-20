package password_test

import (
	"database/sql"
	"strings"
	"testing"

	_ "github.com/lib/pq"
	passwordsvc "github.com/vistasecurity/vistaplatform/shared/security/password"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// platform_settings.password_min_length, end to end.
//
// The bug: the field saved, redisplayed on reload, and every password path
// enforced a hardcoded `len(password) < 8`. An operator who set 14 was told
// "Security policy saved." and the platform kept accepting 8-character
// passwords.
//
// Skips unless TEST_DATABASE_URL is set — run `make test-integration-db`.

func setMinLength(t *testing.T, db *sql.DB, jsonValue string) {
	t.Helper()
	const key = "password_min_length"

	var prev []byte
	hadPrev := true
	if err := db.QueryRow(`SELECT setting_value FROM platform_settings WHERE setting_key = $1`, key).Scan(&prev); err != nil {
		if err != sql.ErrNoRows {
			t.Fatalf("read prior: %v", err)
		}
		hadPrev = false
	}
	if jsonValue == "" {
		if _, err := db.Exec(`DELETE FROM platform_settings WHERE setting_key = $1`, key); err != nil {
			t.Fatalf("clear: %v", err)
		}
	} else if _, err := db.Exec(`
		INSERT INTO platform_settings (setting_key, setting_value, updated_at) VALUES ($1, $2::jsonb, NOW())
		ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value, updated_at = NOW()`,
		key, jsonValue); err != nil {
		t.Fatalf("set: %v", err)
	}

	t.Cleanup(func() {
		if hadPrev {
			_, _ = db.Exec(`
				INSERT INTO platform_settings (setting_key, setting_value, updated_at) VALUES ($1, $2, NOW())
				ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value`, key, prev)
			return
		}
		_, _ = db.Exec(`DELETE FROM platform_settings WHERE setting_key = $1`, key)
	})
}

// A 12-character password that satisfies every complexity rule. Long enough for
// the built-in floor, short enough to be rejected by a configured 14.
const twelveCharPassword = "Abcdef12!xyZ"

func TestIntegration_PasswordPolicy_ConfiguredMinimumIsEnforced(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	if len(twelveCharPassword) != 12 {
		t.Fatalf("fixture is %d chars, expected 12", len(twelveCharPassword))
	}

	// Baseline: at the built-in floor it is fine.
	setMinLength(t, db, "8")
	if err := passwordsvc.ValidatePasswordStrengthWithPolicy(db, twelveCharPassword); err != nil {
		t.Fatalf("12-char password rejected at min length 8: %v", err)
	}

	// Raise the floor. This is the assertion the old code could not satisfy.
	setMinLength(t, db, "14")
	err := passwordsvc.ValidatePasswordStrengthWithPolicy(db, twelveCharPassword)
	if err == nil {
		t.Fatal("12-char password accepted at a configured minimum of 14 — the saved policy is not enforced")
	}
	if !strings.Contains(err.Error(), "14") {
		t.Errorf("error %q does not name the configured minimum, so the operator cannot tell what to type", err)
	}

	// A password that clears the raised floor still passes.
	if err := passwordsvc.ValidatePasswordStrengthWithPolicy(db, "Abcdef12!xyZQrs"); err != nil {
		t.Errorf("15-char password rejected at min length 14: %v", err)
	}
}

// The setting may raise the floor, never lower it. A settings write must not be
// able to weaken authentication below what the code guarantees.
func TestIntegration_PasswordPolicy_CannotWeakenBelowBuiltInFloor(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	setMinLength(t, db, "4")

	if got := passwordsvc.PolicyMinLength(db); got != passwordsvc.MinPasswordLength {
		t.Errorf("PolicyMinLength = %d with a stored 4, want the floor %d", got, passwordsvc.MinPasswordLength)
	}
	if err := passwordsvc.ValidatePasswordStrengthWithPolicy(db, "Ab1!cd"); err == nil {
		t.Fatal("a 6-character password was accepted — a stored value below the floor weakened the policy")
	}
}

// No saved row → the behaviour every existing deployment already has.
func TestIntegration_PasswordPolicy_FallsBackToFloorWhenUnset(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	setMinLength(t, db, "")

	if got := passwordsvc.PolicyMinLength(db); got != passwordsvc.MinPasswordLength {
		t.Errorf("PolicyMinLength = %d with no row, want %d", got, passwordsvc.MinPasswordLength)
	}
	if err := passwordsvc.ValidatePasswordStrengthWithPolicy(db, twelveCharPassword); err != nil {
		t.Errorf("valid password rejected with no policy row: %v", err)
	}
}

// A nil handle must not panic on a password path.
func TestPasswordPolicy_NilDBUsesFloor(t *testing.T) {
	if got := passwordsvc.PolicyMinLength(nil); got != passwordsvc.MinPasswordLength {
		t.Errorf("PolicyMinLength(nil) = %d, want %d", got, passwordsvc.MinPasswordLength)
	}
}
