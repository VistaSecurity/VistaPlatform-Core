package auth

//: platform-admin login must enforce the same failed-attempt lockout the
// tenant path has, against the platform_users table. These tests drive the real
// Login() platform branch over sqlmock.

import (
	"database/sql"
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

// A wrong password on the platform path records a failed attempt (the UPDATE
// that locks at the 5th failure) and returns ErrInvalidCredentials.
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
	// Failed password → record the attempt. The maxAttempts arg ($1 = 5) proves
	// the lock-at-5-failures threshold is wired.
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
