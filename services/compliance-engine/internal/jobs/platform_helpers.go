package jobs

import (
	"context"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// openAlertSubjects returns the subject_ids of non-resolved alerts for a
// (tenant, alert_type). Read via the bypass pool — used by platform-scoped
// detector scans that operate under the sentinel platform tenant.
func openAlertSubjects(ctx context.Context, bypassDB *sqlx.DB, tenantID uuid.UUID, alertType string) (map[uuid.UUID]bool, error) {
	rows, err := bypassDB.QueryContext(ctx, `
		SELECT subject_id FROM alerts
		WHERE tenant_id = $1 AND alert_type = $2 AND status <> 'resolved' AND subject_id IS NOT NULL
	`, tenantID, alertType)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[uuid.UUID]bool{}
	for rows.Next() {
		var sid uuid.UUID
		if err := rows.Scan(&sid); err == nil {
			out[sid] = true
		}
	}
	return out, rows.Err()
}
