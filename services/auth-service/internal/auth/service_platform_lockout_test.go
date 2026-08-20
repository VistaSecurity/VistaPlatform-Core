package auth

//: platform-admin login must enforce the same failed-attempt lockout the
// tenant path has, against the platform_users table. These tests drive the real
// Login() platform branch over sqlmock.
//
// The threshold is no longer a constant: recordPlatformFailedLogin reads
// platform_settings via authpolicy.Lockout, so the value bound to $1 of the
// UPDATE is the operator-configured "Maximum login attempts". These tests pin
// BOTH ends of that -- the configured value when one is saved, and the
// historical 5 when none is.

import (
	"database/sql"
	"strconv"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/models"
	passwordsvc "github.com/vistasecurity/vistaplatform/shared/security/password"
)

func platformLoginService(t *testing.T) (*AuthService, sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	svc := &AuthService{db: db, bypassDB: db, password: passwordsvc.NewPasswordService()}
	return svc, mock, func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet SQL expectations: %v", err)
		}
		_ = db.Close()
	}
}

// expectFallThroughToPlatform mocks the two lookups that run before the
// platform lockout logic: the tenant-user lookup (miss → ErrUserNotFound) and
// the platform-user lookup (hit).
func expectFallThroughToPlatform(mock sqlmock.Sqlmock, email string, id uuid.UUID, hash string) {
	mock.ExpectQuery(`FROM users\s+WHERE email = \$1 AND deleted_at IS NULL`).
		WithArgs(email).
		WillReturnError(sql.ErrNoRows)

	now := time.Now()
	mock.ExpectQuery(`FROM platform_users pu\s+JOIN platform_roles`).
		WithArgs(email).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "email", "password_hash", "first_name", "last_name",
			"is_active", "email_verified", "last_login_at", "created_at", "role_name",
		}).AddRow(id, email, hash, "Plat", "Admin", true, true, now, now, "platform_admin"))
}

// expectLockoutPolicyLookup mocks the two platform_settings reads that
// authpolicy.Lockout performs. Pass -1 for either to simulate "never saved",
// which must yield the historical default.
func expectLockoutPolicyLookup(mock sqlmock.Sqlmock, maxAttempts, lockoutMinutes int) {
	q := `SELECT setting_value FROM platform_settings WHERE setting_key = \$1`
	if maxAttempts < 0 {
		mock.ExpectQuery(q).WithArgs("max_login_attempts").WillReturnError(sql.ErrNoRows)
	} else {
		mock.ExpectQuery(q).WithArgs("max_login_attempts").
			WillReturnRows(sqlmock.NewRows([]string{"setting_value"}).AddRow([]byte(strconv.Itoa(maxAttempts))))
	}
	if lockoutMinutes < 0 {
		mock.ExpectQuery(q).WithArgs("lockout_duration_minutes").WillReturnError(sql.ErrNoRows)
	} else {
		mock.ExpectQuery(q).WithArgs("lockout_duration_minutes").
			WillReturnRows(sqlmock.NewRows([]string{"setting_value"}).AddRow([]byte(strconv.Itoa(lockoutMinutes))))
	}
}

// A wrong password on the platform path records a failed attempt and returns
// ErrInvalidCredentials. With no saved policy, the threshold bound to $1 is the
// historical 5.
func TestPlatformLoginRecordsFailedAttempt(t *testing.T) {
	svc, mock, cleanup := platformLoginService(t)
	defer cleanup()

	email := "admin@vista.example"
	id := uuid.New()
	hash, err := svc.password.HashPassword("CorrectHorse9!")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	expectFallThroughToPlatform(mock, email, id, hash)
	// Not currently locked.
	mock.ExpectQuery(`SELECT locked_until FROM platform_users WHERE id = \$1`).
		WithArgs(id).
		WillReturnRows(sqlmock.NewRows([]string{"locked_until"}).AddRow(nil))
	// No policy saved -> the historical default is what reaches the UPDATE.
	expectLockoutPolicyLookup(mock, -1, -1)
	mock.ExpectExec(`UPDATE platform_users\s+SET failed_login_attempts = failed_login_attempts \+ 1`).
		WithArgs(5, sqlmock.AnyArg(), sqlmock.AnyArg(), id).
		WillReturnResult(sqlmock.NewResult(0, 1))

	_, loginErr := svc.Login(&models.LoginRequest{Email: email, Password: "WrongPass!"}, "ip", "ua")
	if loginErr != ErrInvalidCredentials {
		t.Fatalf("got %v, want ErrInvalidCredentials", loginErr)
	}
}

// A platform account whose locked_until is in the future is rejected with
// ErrAccountLocked before the password is even checked.
func TestPlatformLoginLockedReturnsErrAccountLocked(t *testing.T) {
	svc, mock, cleanup := platformLoginService(t)
	defer cleanup()

	email := "admin@vista.example"
	id := uuid.New()

	expectFallThroughToPlatform(mock, email, id, "irrelevant-hash")
	mock.ExpectQuery(`SELECT locked_until FROM platform_users WHERE id = \$1`).
		WithArgs(id).
		WillReturnRows(sqlmock.NewRows([]string{"locked_until"}).AddRow(time.Now().Add(10 * time.Minute)))

	_, loginErr := svc.Login(&models.LoginRequest{Email: email, Password: "whatever"}, "ip", "ua")
	if loginErr != ErrAccountLocked {
		t.Fatalf("got %v, want ErrAccountLocked", loginErr)
	}
}

// The enforcement assertion for this fix: a platform admin who saves "3" gets 3.
// Before it, the value persisted, redisplayed on reload, and the code locked at
// 5 regardless.
func TestPlatformLoginUsesConfiguredLockoutThreshold(t *testing.T) {
	svc, mock, cleanup := platformLoginService(t)
	defer cleanup()

	email := "admin@vista.example"
	id := uuid.New()
	hash, err := svc.password.HashPassword("CorrectHorse9!")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	expectFallThroughToPlatform(mock, email, id, hash)
	mock.ExpectQuery(`SELECT locked_until FROM platform_users WHERE id = \$1`).
		WithArgs(id).
		WillReturnRows(sqlmock.NewRows([]string{"locked_until"}).AddRow(nil))

	expectLockoutPolicyLookup(mock, 3, 60)
	// $1 is the threshold the UPDATE CASE compares against. Binding 3 here --
	// not 5 -- is the proof that the saved setting is what locks the account.
	mock.ExpectExec(`UPDATE platform_users\s+SET failed_login_attempts = failed_login_attempts \+ 1`).
		WithArgs(3, sqlmock.AnyArg(), sqlmock.AnyArg(), id).
		WillReturnResult(sqlmock.NewResult(0, 1))

	_, loginErr := svc.Login(&models.LoginRequest{Email: email, Password: "WrongPass!"}, "ip", "ua")
	if loginErr != ErrInvalidCredentials {
		t.Fatalf("got %v, want ErrInvalidCredentials", loginErr)
	}
}
