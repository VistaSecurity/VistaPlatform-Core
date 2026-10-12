package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// ErrAmbiguousEmail means more than one live account carries the same address
// (compared case-insensitively). The schema only forbids duplicates WITHIN a
// tenant, so such rows can exist from before the invite/CreateUser paths checked
// global uniqueness. Login resolves the tenant FROM the email, so an ambiguous
// address cannot be resolved safely: callers fail CLOSED (no sign-in, no reset,
// no lockout against the wrong row) instead of picking an arbitrary one.
var ErrAmbiguousEmail = errors.New("email address is shared by more than one account")

// NormalizeEmail is the one canonical form of an address for storage and
// comparison: trimmed and lower-cased. Every insert and lookup of users.email
// goes through it, because login looks up the lower-cased form.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// RowQuerier is the subset of *sql.DB / *sql.Tx EmailInUseGlobally needs.
type RowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// EmailInUseGlobally reports whether any live account — in ANY tenant, or a
// platform user — already holds the address. Login and password reset resolve
// an account by email alone, so an address must identify exactly one account
// platform-wide; Register has always enforced that, and the invite, accept and
// admin-create paths now do too.
//
// q MUST be able to see every tenant's users (the BYPASSRLS handle): on the
// tenant-scoped app role users is filtered to the caller's tenant and the check
// would pass for exactly the cross-tenant collision it exists to catch.
func EmailInUseGlobally(ctx context.Context, q RowQuerier, email string) (bool, error) {
	var inUse bool
	err := q.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM users WHERE lower(email) = $1 AND deleted_at IS NULL)
		    OR EXISTS (SELECT 1 FROM platform_users WHERE lower(email) = $1 AND deleted_at IS NULL)`,
		NormalizeEmail(email)).Scan(&inUse)
	return inUse, err
}
