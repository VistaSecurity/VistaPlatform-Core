package dcimfixture

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
)

// The contacts populator (DCIM BUILD_PLAN row 2.8): one contact per site
// ("Fixture NOC site-0000", an email and a phone), a tenant role "Fixture
// on-call", and every asset given its site's contact as the primary on-call
// contact — the rows the asset page's Contacts section and the object-contacts
// list read at scale.
func populateContacts(ctx context.Context, tx *sql.Tx, e *Env) (int, error) {
	if len(e.Assets) == 0 {
		return -1, nil
	}
	sites := e.Scale.Sites
	if sites < 1 {
		return -1, nil
	}
	ids := make([]uuid.UUID, sites)
	for i := range ids {
		name := "Fixture NOC " + SiteName(i)
		e.Witness(name)
		if err := tx.QueryRowContext(ctx, `INSERT INTO contacts (tenant_id, name, email, phone) VALUES ($1, $2, $3, $4) RETURNING id`,
			e.Tenant, name, fmt.Sprintf("noc-%04d@example.test", i), fmt.Sprintf("+1 555 %04d", i)).Scan(&ids[i]); err != nil {
			return 0, err
		}
	}
	var role uuid.UUID
	if err := tx.QueryRowContext(ctx, `INSERT INTO contact_roles (tenant_id, name, slug) VALUES ($1, 'Fixture on-call', 'fixture-on-call') RETURNING id`, e.Tenant).Scan(&role); err != nil {
		return 0, err
	}
	err := copyRows(ctx, tx, "contact_assignments", []string{"tenant_id", "object_kind", "object_id", "contact_id", "role_id", "priority"},
		len(e.Assets), func(i int) []any {
			a := e.Assets[i]
			return []any{e.Tenant, "asset", a.ID, ids[a.Site%sites], role, "primary"}
		})
	if err != nil {
		return 0, err
	}
	return sites, nil
}
