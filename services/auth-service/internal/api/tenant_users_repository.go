package api

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/sirupsen/logrus"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// tenantUsersStore is the persistence seam ListTenantUsers depends on. Declaring
// it as an interface (the *sql.DB-backed repo is the production impl) lets the
// contract test drive the handler with an in-memory stub — no database — per the
// spec-first contract recipe (ADR-0001). The SQL is the verbatim
// users + user_tenant_roles + user_auth_methods read that previously lived inline
// in the ListTenantUsers closure.
type tenantUsersStore interface {
	ListTenantUsers(ctx context.Context, tenantID uuid.UUID) ([]TenantUser, error)
}

type tenantUsersRepository struct {
	db *sql.DB
}

func newTenantUsersRepo(db *sql.DB) *tenantUsersRepository {
	return &tenantUsersRepository{db: db}
}

func (r *tenantUsersRepository) ListTenantUsers(ctx context.Context, tenantID uuid.UUID) ([]TenantUser, error) {
	// Query users with their roles from user_tenant_roles
	query := `
		SELECT
			u.id, u.tenant_id, u.email, u.first_name, u.last_name,
			COALESCE(
				(SELECT tr.name
				 FROM user_tenant_roles utr
				 JOIN tenant_roles tr ON utr.role_id = tr.id
				 WHERE utr.user_id = u.id
				   AND utr.tenant_id = u.tenant_id
				   AND utr.is_active = true
				 ORDER BY utr.assigned_at DESC
				 LIMIT 1),
				'viewer'
			) as role,
			COALESCE(
				(SELECT ARRAY_AGG(tr2.name ORDER BY utr2.assigned_at DESC)
				 FROM user_tenant_roles utr2
				 JOIN tenant_roles tr2 ON utr2.role_id = tr2.id
				 WHERE utr2.user_id = u.id
				   AND utr2.tenant_id = u.tenant_id
				   AND utr2.is_active = true),
				ARRAY[]::varchar[]
			) as roles,
			u.is_active, u.email_verified, u.last_login_at, u.created_at, u.updated_at
		FROM users u
		WHERE u.tenant_id = $1 AND u.deleted_at IS NULL
		ORDER BY u.created_at DESC
	`

	// RLS-scoped: the primary read (users + user_tenant_roles + tenant_roles) and
	// the follow-up password-presence read both hit tenant_isolation tables; the
	// tenant is known, so the whole method runs inside one WithTenantTx. The batch
	// user_auth_methods read (global table, keyed by user_id) is harmless inside
	// the same tx. Explicit WHERE tenant_id kept as the primary control.
	var users []TenantUser
	wrapErr := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, query, tenantID)
		if err != nil {
			return fmt.Errorf("failed to fetch tenant users: %w", err)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var user TenantUser
			var roles pq.StringArray
			if err := rows.Scan(
				&user.ID, &user.TenantID, &user.Email, &user.FirstName, &user.LastName,
				&user.Role, &roles, &user.IsActive, &user.EmailVerified, &user.LastLoginAt,
				&user.CreatedAt, &user.UpdatedAt,
			); err != nil {
				logrus.WithError(err).Error("Failed to scan user row")
				continue
			}
			user.Roles = []string(roles)
			if len(user.Roles) == 0 && user.Role != "" {
				user.Roles = []string{user.Role}
			}
			user.AuthMethods = []string{}
			users = append(users, user)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("failed to iterate tenant users: %w", err)
		}

		// Fetch auth methods for all users in batch
		if len(users) > 0 {
			userIDs := make([]interface{}, len(users))
			placeholders := ""
			for i, u := range users {
				if i > 0 {
					placeholders += ","
				}
				placeholders += fmt.Sprintf("$%d", i+1)
				userIDs[i] = u.ID
			}

			authMethodRows, err := tx.QueryContext(ctx, fmt.Sprintf(`
			SELECT user_id, auth_type FROM user_auth_methods
			WHERE user_id IN (%s)
			ORDER BY user_id, auth_type
		`, placeholders), userIDs...)
			if err == nil {
				defer func() { _ = authMethodRows.Close() }()
				authMethodMap := make(map[string][]string)
				for authMethodRows.Next() {
					var userID, authType string
					if err := authMethodRows.Scan(&userID, &authType); err == nil {
						authMethodMap[userID] = append(authMethodMap[userID], authType)
					}
				}
				for i := range users {
					if methods, ok := authMethodMap[users[i].ID.String()]; ok {
						users[i].AuthMethods = methods
					}
				}
			}

			// If user has a password_hash, add "password" to auth methods
			passwordRows, err := tx.QueryContext(ctx, fmt.Sprintf(`
			SELECT id FROM users
			WHERE id IN (%s) AND password_hash IS NOT NULL AND password_hash != ''
		`, placeholders), userIDs...)
			if err == nil {
				defer func() { _ = passwordRows.Close() }()
				passwordUsers := make(map[string]bool)
				for passwordRows.Next() {
					var uid string
					if err := passwordRows.Scan(&uid); err == nil {
						passwordUsers[uid] = true
					}
				}
				for i := range users {
					if passwordUsers[users[i].ID.String()] {
						hasPassword := false
						for _, m := range users[i].AuthMethods {
							if m == "password" {
								hasPassword = true
								break
							}
						}
						if !hasPassword {
							users[i].AuthMethods = append([]string{"password"}, users[i].AuthMethods...)
						}
					}
				}
			}
		}
		return nil
	})
	if wrapErr != nil {
		return nil, wrapErr
	}

	return users, nil
}
