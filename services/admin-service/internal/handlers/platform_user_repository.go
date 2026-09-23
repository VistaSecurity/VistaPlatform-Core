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
	passwordsvc "github.com/vistasecurity/vistaplatform/shared/security/password"
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
	// PasswordMinLength is the operator-configured password floor
	// (platform_settings.password_min_length, admin-ui Security ▸ Policy),
	// never below passwordsvc.MinPasswordLength.
	PasswordMinLength(ctx context.Context) int
	CreatePlatformUser(ctx context.Context, in platformUserInsert) (id string, createdAt, updatedAt time.Time, err error)

	// The writes below act on an EXISTING user whose rank the handler has just
	// checked (authorizeActOnPlatformUser). Each is conditional on the user
	// still holding expectedRole — the role that check saw (nil = no role) —
	// and returns errPlatformUserChanged, writing nothing, when they no longer
	// do (or no longer exist). Without that, a user promoted between the check
	// and the write would be acted on by someone who no longer outranks them.
	UpdatePlatformUser(ctx context.Context, id string, expectedRole *uuid.UUID, f platformUserUpdateFields) error
	UpdatePlatformUserPassword(ctx context.Context, id string, expectedRole *uuid.UUID, hash string, forceChange bool) error
	DeletePlatformUser(ctx context.Context, id string, expectedRole *uuid.UUID) error

	// Invite/reset-flow seams (InvitePlatformUser, AdminSendPasswordReset).
	CreateInvitedPlatformUser(ctx context.Context, in platformUserInviteInsert) (id string, createdAt time.Time, err error)
	InviterDisplayName(ctx context.Context, inviterID string) string
	EnabledAdminSsoProviderLabels(ctx context.Context) []string
	ActiveUserEmail(ctx context.Context, id string) (email string, found bool, err error)
	StorePasswordResetToken(ctx context.Context, id string, expectedRole *uuid.UUID, tokenHash string, expires time.Time) error

	// Role-assignment authorization seams (platform_roles.assign enforcement —
	// see platform_role_assignment.go). Every path that writes
	// platform_users.role_id consults these before writing.
	HasPlatformPermission(ctx context.Context, userID, permission string) (bool, error)
	RolePermissionsNotHeldBy(ctx context.Context, callerID, roleID string) (missing []string, err error)
	PlatformUserRole(ctx context.Context, userID string) (current platformUserRoleRef, found bool, err error)
}

// platformUserRoleRef is a platform user's current role: nil RoleID when the
// row has none. The schema declares platform_users.role_id NOT NULL, so that
// only happens for a row written outside the constraint; it is handled rather
// than assumed away because a nil here must mean "holds nothing".
type platformUserRoleRef struct {
	RoleID   *uuid.UUID
	RoleName string
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
		var roleID uuid.NullUUID
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

		user.RoleID = nullableUUID(roleID)
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
	var roleID uuid.NullUUID
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

	user.RoleID = nullableUUID(roleID)
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

// nullableUUID maps a uuid column read as NULL to a nil pointer. Should a
// platform_users row lack a role (the schema says NOT NULL, but see
// platformUserRoleRef), it must reach the API as "role_id": null — not
// as the zero UUID, which a client cannot tell from a real id.
func nullableUUID(v uuid.NullUUID) *uuid.UUID {
	if !v.Valid {
		return nil
	}
	id := v.UUID
	return &id
}

// expectedRoleArg is the query argument for "role_id IS NOT DISTINCT FROM $n":
// SQL NULL for a user the check saw with no role.
func expectedRoleArg(expectedRole *uuid.UUID) uuid.NullUUID {
	if expectedRole == nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: *expectedRole, Valid: true}
}

// execExpectingOneRow runs a conditional write and maps "matched nothing" to
// errPlatformUserChanged.
func execExpectingOneRow(ctx context.Context, ex interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
}, query string, args ...interface{}) error {
	res, err := ex.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errPlatformUserChanged
	}
	return nil
}

func (r *platformUserRepository) RoleExists(ctx context.Context, roleID string) (bool, error) {
	var exists bool
	err := r.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM platform_roles WHERE id = $1)", roleID).Scan(&exists)
	return exists, err
}

// HasPlatformPermission asks the same SECURITY DEFINER function the route
// middleware uses (RBACService.CheckPlatformPermission), so the handler-level
// check and the route gate can never disagree about what a user holds.
func (r *platformUserRepository) HasPlatformPermission(ctx context.Context, userID, permission string) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx, "SELECT platform_user_has_permission($1, $2)", userID, permission).Scan(&ok)
	return ok, err
}

// RolePermissionsNotHeldBy returns the permissions roleID grants that callerID
// does not currently hold — empty means the role is a subset of the caller's
// effective permissions. Evaluated through platform_user_has_permission so an
// inactive or deleted caller holds nothing.
func (r *platformUserRepository) RolePermissionsNotHeldBy(ctx context.Context, callerID, roleID string) ([]string, error) {
	return rolePermissionsNotHeldBy(ctx, r.db, callerID, roleID)
}

// rolePermissionsNotHeldBy is shared by the platform-user and platform-RBAC
// repositories, so "does this role outrank the caller?" has one definition.
func rolePermissionsNotHeldBy(ctx context.Context, db *sql.DB, callerID, roleID string) ([]string, error) {
	return permissionNames(ctx, db, `
		SELECT pp.name
		FROM platform_role_permissions prp
		JOIN platform_permissions pp ON pp.id = prp.permission_id
		WHERE prp.role_id = $2
		  AND NOT platform_user_has_permission($1, pp.name)
		ORDER BY pp.name
	`, callerID, roleID)
}

// permissionNames runs a query returning one permission name per row.
func permissionNames(ctx context.Context, db *sql.DB, query string, args ...interface{}) ([]string, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// PlatformUserRole reads a (non-deleted) platform user's current role.
func (r *platformUserRepository) PlatformUserRole(ctx context.Context, userID string) (platformUserRoleRef, bool, error) {
	var roleID uuid.NullUUID
	var roleName sql.NullString
	err := r.db.QueryRowContext(ctx, `
		SELECT pu.role_id, pr.name
		FROM platform_users pu
		LEFT JOIN platform_roles pr ON pr.id = pu.role_id
		WHERE pu.id = $1 AND pu.deleted_at IS NULL
	`, userID).Scan(&roleID, &roleName)
	if errors.Is(err, sql.ErrNoRows) {
		return platformUserRoleRef{}, false, nil
	}
	if err != nil {
		return platformUserRoleRef{}, false, err
	}
	ref := platformUserRoleRef{RoleName: roleName.String}
	if roleID.Valid {
		id := roleID.UUID
		ref.RoleID = &id
	}
	return ref, true, nil
}

// withLastSuperAdminGuard runs write in a transaction that first locks every
// active super_admin row, and refuses with errLastActiveSuperAdmin when userID
// is the only one left and removes(tx) says the write takes them out of that
// set (deactivation, deletion, or a role change away from super_admin).
//
// Why a lock and not a count: under READ COMMITTED two concurrent removals of
// DIFFERENT super_admins (A stepping down while B is deactivated) each count
// the other as still active and both commit, leaving none. SELECT ... FOR
// UPDATE OF pu makes the second transaction wait on the first's row; when it
// resumes, Postgres re-checks the WHERE clause against the committed row, so a
// super_admin the first transaction removed is no longer returned. ORDER BY
// fixes the lock order so two guarded writers cannot deadlock each other.
func (r *platformUserRepository) withLastSuperAdminGuard(
	ctx context.Context,
	userID string,
	removes func(tx *sql.Tx) (bool, error),
	write func(tx *sql.Tx) error,
) error {
	target, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
		SELECT pu.id
		FROM platform_users pu
		JOIN platform_roles pr ON pr.id = pu.role_id
		WHERE pr.name = $1
		  AND pu.is_active = true
		  AND pu.deleted_at IS NULL
		ORDER BY pu.id
		FOR UPDATE OF pu
	`, superAdminRoleName)
	if err != nil {
		return err
	}
	// Keyed by uuid value, not text, so no spelling of userID can miss.
	active := map[uuid.UUID]bool{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		active[id] = true
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if active[target] && len(active) == 1 {
		rm, err := removes(tx)
		if err != nil {
			return err
		}
		if rm {
			return errLastActiveSuperAdmin
		}
	}

	if err := write(tx); err != nil {
		return err
	}
	return tx.Commit()
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

// PasswordMinLength reads platform_settings.password_min_length. It fails SAFE
// (built-in floor on any error), because a password rule that silently
// evaporates is a weakening — the opposite bias to the signup toggles.
func (r *platformUserRepository) PasswordMinLength(ctx context.Context) int {
	var raw []byte
	err := r.db.QueryRowContext(ctx, `
		SELECT setting_value FROM platform_settings
		WHERE setting_key = 'password_min_length'
	`).Scan(&raw)
	if err != nil {
		return passwordsvc.MinPasswordLength
	}
	var n int
	if err := json.Unmarshal(raw, &n); err != nil {
		return passwordsvc.MinPasswordLength
	}
	if n < passwordsvc.MinPasswordLength {
		return passwordsvc.MinPasswordLength
	}
	if n > passwordsvc.MaxPasswordLength {
		return passwordsvc.MaxPasswordLength
	}
	return n
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

func (r *platformUserRepository) UpdatePlatformUser(ctx context.Context, id string, expectedRole *uuid.UUID, f platformUserUpdateFields) error {
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
	args = append(args, id, expectedRoleArg(expectedRole))

	query := "UPDATE platform_users SET " + strings.Join(updates, ", ") +
		" WHERE id = $" + strconv.Itoa(i) + " AND deleted_at IS NULL" +
		" AND role_id IS NOT DISTINCT FROM $" + strconv.Itoa(i+1) //nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice

	deactivates := f.IsActive != nil && !*f.IsActive
	if !deactivates && f.RoleID == nil {
		// Cannot take anyone out of the active super_admin set.
		return execExpectingOneRow(ctx, r.db, query, args...)
	}
	return r.withLastSuperAdminGuard(ctx, id,
		func(tx *sql.Tx) (bool, error) {
			if deactivates {
				return true, nil
			}
			var newRole string
			err := tx.QueryRowContext(ctx, `SELECT name FROM platform_roles WHERE id = $1`, *f.RoleID).Scan(&newRole)
			if errors.Is(err, sql.ErrNoRows) {
				return true, nil
			}
			return newRole != superAdminRoleName, err
		},
		func(tx *sql.Tx) error {
			return execExpectingOneRow(ctx, tx, query, args...)
		})
}

func (r *platformUserRepository) UpdatePlatformUserPassword(ctx context.Context, id string, expectedRole *uuid.UUID, hash string, forceChange bool) error {
	return execExpectingOneRow(ctx, r.db, `
		UPDATE platform_users
		SET password_hash = $1,
		    force_password_change = $2,
		    password_changed_at = NOW(),
		    password_reset_token = NULL,
		    password_reset_expires = NULL,
		    updated_at = NOW()
		WHERE id = $3 AND deleted_at IS NULL
		  AND role_id IS NOT DISTINCT FROM $4
	`, hash, forceChange, id, expectedRoleArg(expectedRole))
}

// DeletePlatformUser soft-deletes a user, refusing (errLastActiveSuperAdmin)
// when they are the last active super_admin.
func (r *platformUserRepository) DeletePlatformUser(ctx context.Context, id string, expectedRole *uuid.UUID) error {
	return r.withLastSuperAdminGuard(ctx, id,
		func(*sql.Tx) (bool, error) { return true, nil },
		func(tx *sql.Tx) error {
			return execExpectingOneRow(ctx, tx, `
				UPDATE platform_users SET deleted_at = NOW(), updated_at = NOW()
				WHERE id = $1 AND deleted_at IS NULL
				  AND role_id IS NOT DISTINCT FROM $2`,
				id, expectedRoleArg(expectedRole),
			)
		})
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

func (r *platformUserRepository) StorePasswordResetToken(ctx context.Context, id string, expectedRole *uuid.UUID, tokenHash string, expires time.Time) error {
	return execExpectingOneRow(ctx, r.db, `
		UPDATE platform_users
		SET password_reset_token = $1, password_reset_expires = $2, updated_at = NOW()
		WHERE id = $3 AND deleted_at IS NULL
		  AND role_id IS NOT DISTINCT FROM $4
	`, tokenHash, expires, id, expectedRoleArg(expectedRole))
}
