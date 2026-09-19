package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"sort"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// LockIdentifiers serializes ownership decisions, including decisions about an
// identifier that has no row yet. All keys precede observation and asset locks.
func (r *Repository) LockIdentifiers(ctx context.Context, tenant string, ids []identity.Identifier) error {
	if r.tx == nil {
		return fmt.Errorf("identity ownership locks require a bound transaction")
	}
	if err := r.checkTenant(tenant); err != nil {
		return err
	}
	return lockIdentifiers(ctx, r.tx, tenant, ids)
}

func lockIdentifiers(ctx context.Context, tx *sql.Tx, tenant string, ids []identity.Identifier) error {
	keys := make(map[string]bool, len(ids))
	for _, raw := range ids {
		id, err := raw.Normalized()
		if err != nil {
			return err
		}
		keys[tenant+":"+id.Key()] = true
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	for _, key := range ordered {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,72042))`, key); err != nil {
			return err
		}
	}
	return nil
}

// LockIdentifierOwnership serializes merge ownership transfers with admission.
// The caller must already have set the transaction's tenant context.
func LockIdentifierOwnership(ctx context.Context, tx *sql.Tx, tenant string, ids []identity.Identifier) error {
	return lockIdentifiers(ctx, tx, tenant, ids)
}
