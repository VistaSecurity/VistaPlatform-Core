package auth

import (
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/models"
	passwordsvc "github.com/vistasecurity/vistaplatform/shared/security/password"
)

func TestChangePasswordRevokesRefreshTokens(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	passwordService := passwordsvc.NewPasswordService()

	userID := uuid.New()
	tenantID := uuid.New()
	currentPassword := "Curr3ntPass!"
	newPassword := "N3wPassw0rd!"
	hashedCurrent, err := passwordService.HashPassword(currentPassword)
	if err != nil {
		t.Fatalf("failed to hash current password: %v", err)
	}

	now := time.Now()

	// Expect GetUserByID query (includes avatar_url, timezone, preferences columns)
	mock.ExpectQuery(`SELECT id, tenant_id, email, password_hash, first_name, last_name,\s+is_active, email_verified, last_login_at, avatar_url, timezone, preferences,\s*created_at, updated_at, deleted_at\s+FROM users\s+WHERE id = \$1 AND deleted_at IS NULL`).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "tenant_id", "email", "password_hash", "first_name", "last_name",
			"is_active", "email_verified", "last_login_at", "avatar_url", "timezone", "preferences",
			"created_at", "updated_at", "deleted_at",
		}).AddRow(
			userID, tenantID, "user@example.com", hashedCurrent, "First", "Last",
			true, true, now, nil, nil, nil,
			now, now, nil,
		))

	// Expect getUserPrimaryRole query. RLS Phase 3: getUserPrimaryRole now runs
	// inside WithTenantTx (the tenant is known once the user row is fetched), so
	// the role read is wrapped in Begin → set_tenant_context → query → Commit.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT tr.name\s+FROM tenant_roles tr\s+JOIN user_tenant_roles utr ON tr.id = utr.role_id`).
		WithArgs(userID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("tenant_admin"))
	mock.ExpectCommit()

	// Expect password update
	mock.ExpectExec(`UPDATE users SET password_hash = \$1, updated_at = \$2 WHERE id = \$3`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), userID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	// Expect refresh token revocation
	mock.ExpectExec(`UPDATE refresh_tokens\s+SET is_revoked = true, revoked_at = NOW\(\)\s+WHERE user_id = \$1 AND is_revoked = false`).
		WithArgs(userID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	authService := &AuthService{
		db:                  db,
		bypassDB:            db,
		password:            passwordService,
		refreshTokenService: NewRefreshTokenService(db),
	}

	req := &models.ChangePasswordRequest{
		CurrentPassword: currentPassword,
		NewPassword:     newPassword,
	}

	if err := authService.ChangePassword(userID, req); err != nil {
		t.Fatalf("ChangePassword returned error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}
