package auth

import (
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

func TestRefreshTokenRejectsInactiveTenantUser(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	jwtSvc := newTestJWTService()
	userID := uuid.New()
	tenantID := uuid.New()
	_, refreshToken, err := jwtSvc.GenerateTokens(userID, tenantID, "inactive@example.com", "viewer")
	if err != nil {
		t.Fatalf("failed to generate refresh token: %v", err)
	}

	now := time.Now()
	mock.ExpectQuery(`SELECT id, tenant_id, email, password_hash, first_name, last_name,\s+is_active, email_verified, last_login_at, avatar_url, timezone, preferences,\s*created_at, updated_at, deleted_at\s+FROM users\s+WHERE id = \$1 AND deleted_at IS NULL`).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "tenant_id", "email", "password_hash", "first_name", "last_name",
			"is_active", "email_verified", "last_login_at", "avatar_url", "timezone", "preferences",
			"created_at", "updated_at", "deleted_at",
		}).AddRow(
			userID, tenantID, "inactive@example.com", "hashed-password", "Inactive", "User",
			false, true, nil, nil, nil, nil,
			now, now, nil,
		))

	// GetUserByID resolves the user's primary role before RefreshToken enforces
	// activity status; no refresh_tokens expectations are registered because an
	// inactive user must be rejected before token rotation is attempted.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_tenant_context\(\$1\)`).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT tr.name\s+FROM tenant_roles tr\s+JOIN user_tenant_roles utr ON tr.id = utr.role_id`).
		WithArgs(userID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("viewer"))
	mock.ExpectCommit()

	authService := &AuthService{
		db:                  db,
		bypassDB:            db,
		jwt:                 jwtSvc,
		refreshTokenService: NewRefreshTokenService(db),
	}

	response, err := authService.RefreshToken(refreshToken, "127.0.0.1", "test-agent")
	if !errors.Is(err, ErrUserInactive) {
		t.Fatalf("expected ErrUserInactive, got response=%v err=%v", response, err)
	}
	if response != nil {
		t.Fatalf("expected no auth response for inactive user, got %#v", response)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}
