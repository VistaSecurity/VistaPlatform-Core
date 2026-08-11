package handlers

// Read/write seam for the platform-user handlers (ADR-0001 contract slice). The
// ListPlatformUsers/GetPlatformUser/... free-funcs previously ran SQL inline;
// this slice moves every query VERBATIM into platformUserRepository behind the
// platformUserStore interface, so the handlers become thin (parse → store →
// format) and stub-testable with no database. The public free-funcs keep their
// `(db *sql.DB) gin.HandlerFunc` signatures (they build the repo internally),
// so server.go wiring is unchanged.
//
// Scope note: the two email/SMTP/branding-coupled handlers (InvitePlatformUser,
// AdminSendPasswordReset) are intentionally NOT part of this slice — they need
// email + branding seams and are tracked for a follow-up. They keep their
// original inline-SQL implementations untouched.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/models"
)

// errPlatformUserExists is returned by CreatePlatformUser when the email already
// exists (unique-constraint violation), so the handler can map it to 409 without
// inspecting raw driver error strings.
var errPlatformUserExists = errors.New("platform user already exists")

// passwordHasher is the subset of the platform password service the user
// handlers need. The package-global platformPasswordService satisfies it.
type passwordHasher interface {
	HashPassword(password string) (string, error)
}

type platformUserListFilters struct {
	Search    string
	Role      string
	Status    string
	SortBy    string
	SortOrder string
	PageSize  int
	Offset    int
}

type platformUserInsert struct {
	Email               string
	PasswordHash        string
	FirstName           string
	LastName            string
	RoleID              uuid.UUID
	EmailVerified       bool
	ForcePasswordChange bool
}

// platformUserInviteInsert is the row written by InvitePlatformUser: an inactive
// invited user carrying a hashed one-time password-reset token. The placeholder
// hash is unusable for login; the user sets a real password via the invite link.
type platformUserInviteInsert struct {
	Email           string
	PlaceholderHash string
	FirstName       string
	LastName        string
	RoleID          uuid.UUID
	TokenHash       string
	TokenExpires    time.Time
	InvitedBy       *uuid.UUID
}

type platformUserUpdateFields struct {
	FirstName           *string
	LastName            *string
	RoleID              *uuid.UUID
	IsActive            *bool
	ForcePasswordChange *bool
}

// HasUpdates mirrors the original "No fields to update" 400 guard.
func (f platformUserUpdateFields) HasUpdates() bool {
	return f.FirstName != nil || f.LastName != nil || f.RoleID != nil ||
		f.IsActive != nil || f.ForcePasswordChange != nil
}

type platformUserStore interface {
	ListPlatformUsers(ctx context.Context, f platformUserListFilters) (users []models.PlatformUser, total int, err error)
	GetPlatformUser(ctx context.Context, id string) (user models.PlatformUser, found bool, err error)
	RoleExists(ctx context.Context, roleID string) (bool, error)
	AdminEmailVerificationRequired(ctx context.Context) bool
	CreatePlatformUser(ctx context.Context, in platformUserInsert) (id string, createdAt, updatedAt time.Time, err error)
	UpdatePlatformUser(ctx context.Context, id string, f platformUserUpdateFields) error
	UpdatePlatformUserPassword(ctx context.Context, id, hash string, forceChange bool) (affected int64, err error)
	DeletePlatformUser(ctx context.Context, id string) error

	// Invite/reset-flow seams (InvitePlatformUser, AdminSendPasswordReset).
	CreateInvitedPlatformUser(ctx context.Context, in platformUserInviteInsert) (id string, createdAt time.Time, err error)
	InviterDisplayName(ctx context.Context, inviterID string) string
	EnabledAdminSsoProviderLabels(ctx context.Context) []string
	ActiveUserEmail(ctx context.Context, id string) (email string, found bool, err error)
	StorePasswordResetToken(ctx context.Context, id, tokenHash string, expires time.Time) error
}

type platformUserRepository struct{ db *sql.DB }

func newPlatformUserRepository(db *sql.DB) platformUserStore {
	return &platformUserRepository{db: db}
}

func (r *platformUserRepository) ListPlatformUsers(ctx context.Context, f platformUserListFilters) ([]models.PlatformUser, int, error) {
	validSortFields := map[string]string{
		"email":      "pu.email",
		"first_name": "pu.first_name",
		"last_name":  "pu.last_name",
		"created_at": "pu.created_at",
		"role":       "pr.name",
	}
	sqlSortField := "pu.created_at"
	if sf, ok := validSortFields[f.SortBy]; ok {
		sqlSortField = sf
	}
	sortOrder := f.SortOrder
	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "desc"
	}

	baseQuery := `
		SELECT pu.id, pu.email, pu.first_name, pu.last_name, pu.role_id,
		       pu.is_active, pu.email_verified, pu.force_password_change,
		       pu.last_login_at, pu.invitation_accepted_at, pu.invited_by,
		       pu.created_at, pu.updated_at,
		       pr.id::text as role_table_id, pr.name as role_name, pr.display_name as role_display_name
		FROM platform_users pu
		LEFT JOIN platform_roles pr ON pu.role_id = pr.id
		WHERE pu.deleted_at IS NULL`

	countQuery := `SELECT COUNT(*) FROM platform_users pu LEFT JOIN platform_roles pr ON pu.role_id = pr.id WHERE pu.deleted_at IS NULL`

	args := []interface{}{}
	countArgs := []interface{}{}
	argIdx := 1

	if f.Search != "" {
		searchPattern := "%" + f.Search + "%"
		clause := " AND (pu.email ILIKE $" + strconv.Itoa(argIdx) +
			" OR pu.first_name ILIKE $" + strconv.Itoa(argIdx) +
			" OR pu.last_name ILIKE $" + strconv.Itoa(argIdx) + ")"
		baseQuery += clause
		countQuery += clause
		args = append(args, searchPattern)
		countArgs = append(countArgs, searchPattern)
		argIdx++
	}
	if f.Role != "" {
		clause := " AND pr.name = $" + strconv.Itoa(argIdx)
		baseQuery += clause
		countQuery += clause
		args = append(args, f.Role)
		countArgs = append(countArgs, f.Role)
		argIdx++
	}
	switch f.Status {
	case "active":
		baseQuery += " AND pu.is_active = true"
		countQuery += " AND pu.is_active = true"
	case "inactive":
		baseQuery += " AND pu.is_active = false"
		countQuery += " AND pu.is_active = false"
	}

	baseQuery += " ORDER BY " + sqlSortField + " " + strings.ToUpper(sortOrder)
	baseQuery += " LIMIT $" + strconv.Itoa(argIdx) + " OFFSET $" + strconv.Itoa(argIdx+1) //nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
	args = append(args, f.PageSize, f.Offset)

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()

	var users []models.PlatformUser
	for rows.Next() {
		var user models.PlatformUser
		var roleID uuid.UUID
		var roleName, roleDisplayName sql.NullString
		var roleTableID sql.NullString
		var invitedBy sql.NullString

		err := rows.Scan(
			&user.ID, &user.Email, &user.FirstName, &user.LastName, &roleID,
			&user.IsActive, &user.EmailVerified, &user.ForcePasswordChange,
			&user.LastLoginAt, &user.InvitationAcceptedAt, &invitedBy,
			&user.CreatedAt, &user.UpdatedAt,
			&roleTableID, &roleName, &roleDisplayName,
		)
		if err != nil {
			fmt.Printf("[ADMIN] ERROR: Failed to scan platform user: %v\n", err)
			continue
		}

		if invitedBy.Valid {
			if id, err := uuid.Parse(invitedBy.String); err == nil {
				user.InvitedBy = &id
			}
		}

		user.RoleID = roleID
		if roleTableID.Valid && roleName.Valid {
			if rID, err := uuid.Parse(roleTableID.String); err == nil {
				user.Role = &models.PlatformRole{
					ID:          rID,
					Name:        roleName.String,
					DisplayName: roleDisplayName.String,
				}
			}
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	var total int
	_ = r.db.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total)

	return users, total, nil
}

func (r *platformUserRepository) GetPlatformUser(ctx context.Context, id string) (models.PlatformUser, bool, error) {
	var user models.PlatformUser
	var roleID uuid.UUID
	var roleName, roleDisplayName sql.NullString
	var roleTableID sql.NullString

	err := r.db.QueryRowContext(ctx, `
		SELECT pu.id, pu.email, pu.first_name, pu.last_name, pu.role_id,
		       pu.is_active, pu.email_verified, pu.force_password_change,
		       pu.last_login_at, pu.created_at, pu.updated_at,
		       pr.id::text, pr.name, pr.display_name
		FROM platform_users pu
		LEFT JOIN platform_roles pr ON pu.role_id = pr.id
		WHERE pu.id = $1 AND pu.deleted_at IS NULL
	`, id).Scan(
		&user.ID, &user.Email, &user.FirstName, &user.LastName, &roleID,
		&user.IsActive, &user.EmailVerified, &user.ForcePasswordChange,
		&user.LastLoginAt, &user.CreatedAt, &user.UpdatedAt,
		&roleTableID, &roleName, &roleDisplayName,
	)
	if err == sql.ErrNoRows {
		return user, false, nil
	}
	if err != nil {
		return user, false, err
	}

	user.RoleID = roleID
	if roleTableID.Valid && roleName.Valid {
		if rID, err := uuid.Parse(roleTableID.String); err == nil {
			user.Role = &models.PlatformRole{
				ID:          rID,
				Name:        roleName.String,
				DisplayName: roleDisplayName.String,
			}
		}
	}

	return user, true, nil
}

func (r *platformUserRepository) RoleExists(ctx context.Context, roleID string) (bool, error) {
	var exists bool
	err := r.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM platform_roles WHERE id = $1)", roleID).Scan(&exists)
	return exists, err
}

func (r *platformUserRepository) AdminEmailVerificationRequired(ctx context.Context) bool {
	var raw []byte
	err := r.db.QueryRowContext(ctx, `
		SELECT setting_value FROM platform_settings
		WHERE setting_key = 'admin_email_verification_required'
	`).Scan(&raw)
	if err != nil {
		return false
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		return false
	}
	return b
}

func (r *platformUserRepository) CreatePlatformUser(ctx context.Context, in platformUserInsert) (string, time.Time, time.Time, error) {
	var userID string
	var createdAt, updatedAt time.Time
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO platform_users
		    (email, password_hash, first_name, last_name, role_id,
		     is_active, email_verified, force_password_change)
		VALUES ($1, $2, $3, $4, $5, true, $6, $7)
		RETURNING id, created_at, updated_at
	`, in.Email, in.PasswordHash, in.FirstName, in.LastName, in.RoleID,
		in.EmailVerified, in.ForcePasswordChange).Scan(&userID, &createdAt, &updatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			return "", time.Time{}, time.Time{}, errPlatformUserExists
		}
		return "", time.Time{}, time.Time{}, err
	}
	return userID, createdAt, updatedAt, nil
}

func (r *platformUserRepository) UpdatePlatformUser(ctx context.Context, id string, f platformUserUpdateFields) error {
	updates := []string{}
	args := []interface{}{}
	i := 1

	if f.FirstName != nil {
		updates = append(updates, "first_name = $"+strconv.Itoa(i))
		args = append(args, *f.FirstName)
		i++
	}
	if f.LastName != nil {
		updates = append(updates, "last_name = $"+strconv.Itoa(i))
		args = append(args, *f.LastName)
		i++
	}
	if f.RoleID != nil {
		updates = append(updates, "role_id = $"+strconv.Itoa(i))
		args = append(args, *f.RoleID)
		i++
	}
	if f.IsActive != nil {
		updates = append(updates, "is_active = $"+strconv.Itoa(i))
		args = append(args, *f.IsActive)
		i++
	}
	if f.ForcePasswordChange != nil {
		updates = append(updates, "force_password_change = $"+strconv.Itoa(i))
		args = append(args, *f.ForcePasswordChange)
		i++
	}

	updates = append(updates, "updated_at = NOW()")
	args = append(args, id)

	query := "UPDATE platform_users SET " + strings.Join(updates, ", ") +
		" WHERE id = $" + strconv.Itoa(i) + " AND deleted_at IS NULL" //nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice

	_, err := r.db.ExecContext(ctx, query, args...)
	return err
}

func (r *platformUserRepository) UpdatePlatformUserPassword(ctx context.Context, id, hash string, forceChange bool) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE platform_users
		SET password_hash = $1,
		    force_password_change = $2,
		    password_changed_at = NOW(),
		    password_reset_token = NULL,
		    password_reset_expires = NULL,
		    updated_at = NOW()
		WHERE id = $3 AND deleted_at IS NULL
	`, hash, forceChange, id)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (r *platformUserRepository) DeletePlatformUser(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE platform_users SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL",
		id,
	)
	return err
}

func (r *platformUserRepository) CreateInvitedPlatformUser(ctx context.Context, in platformUserInviteInsert) (string, time.Time, error) {
	var userID string
	var createdAt time.Time
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO platform_users
		    (email, password_hash, first_name, last_name, role_id,
		     is_active, email_verified, force_password_change,
		     password_reset_token, password_reset_expires, invited_by)
		VALUES ($1, $2, $3, $4, $5, true, false, false, $6, $7, $8)
		RETURNING id, created_at
	`, in.Email, in.PlaceholderHash, in.FirstName, in.LastName, in.RoleID,
		in.TokenHash, in.TokenExpires, in.InvitedBy).Scan(&userID, &createdAt)
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			return "", time.Time{}, errPlatformUserExists
		}
		return "", time.Time{}, err
	}
	return userID, createdAt, nil
}

// EnabledAdminSsoProviderLabels returns display labels ("Google", "Microsoft")
// for the enabled admin-login SSO providers, best-effort: empty on error, so
// the invite email simply omits the SSO hint. Invited platform_users rows are
// created is_active=true, so the staff-SSO email-match gate (staff_sso.go)
// already accepts them — this powers telling the invitee about that option.
func (r *platformUserRepository) EnabledAdminSsoProviderLabels(ctx context.Context) []string {
	rows, err := r.db.QueryContext(ctx, `
		SELECT provider_type FROM platform_sso_providers
		WHERE purpose = 'admin_login' AND is_enabled = true ORDER BY provider_type`)
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	var labels []string
	for rows.Next() {
		var pt string
		if rows.Scan(&pt) != nil {
			continue
		}
		switch pt {
		case "google":
			labels = append(labels, "Google")
		case "microsoft":
			labels = append(labels, "Microsoft")
		default:
			labels = append(labels, pt)
		}
	}
	return labels
}

// InviterDisplayName resolves an inviter's "First Last" name, best-effort.
// Returns "" when the id is empty, the row is missing, or the lookup errors —
// the handler falls back to a generic inviter label in that case.
func (r *platformUserRepository) InviterDisplayName(ctx context.Context, inviterID string) string {
	if inviterID == "" {
		return ""
	}
	var fn, ln string
	if err := r.db.QueryRowContext(ctx, "SELECT first_name, last_name FROM platform_users WHERE id = $1", inviterID).Scan(&fn, &ln); err != nil {
		return ""
	}
	if fn == "" && ln == "" {
		return ""
	}
	return strings.TrimSpace(fn + " " + ln)
}

// ActiveUserEmail returns the email of a non-deleted, active platform user.
// found is false when no such row exists (the handler maps that to 404).
func (r *platformUserRepository) ActiveUserEmail(ctx context.Context, id string) (string, bool, error) {
	var email string
	err := r.db.QueryRowContext(ctx,
		"SELECT email FROM platform_users WHERE id = $1 AND deleted_at IS NULL AND is_active = true",
		id,
	).Scan(&email)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return email, true, nil
}

func (r *platformUserRepository) StorePasswordResetToken(ctx context.Context, id, tokenHash string, expires time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE platform_users
		SET password_reset_token = $1, password_reset_expires = $2, updated_at = NOW()
		WHERE id = $3
	`, tokenHash, expires, id)
	return err
}
