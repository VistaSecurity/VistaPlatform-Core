package dcimfixture

import (
	"context"
	"database/sql"
)

// ConfigContextsPerTenant is how many config contexts the populator writes.
const ConfigContextsPerTenant = 3

// The config-contexts populator (DCIM BUILD_PLAN row 5.3): a base context that
// applies to every asset, a heavier syslog context that overrides part of it,
// and an inactive one the renderer must skip -- the rows the asset page's
// Config Context tab and Settings → Config Contexts read.
func populateConfigContexts(ctx context.Context, tx *sql.Tx, e *Env) (int, error) {
	rows := []struct {
		name   string
		weight int
		active bool
		data   string
	}{
		{"Fixture base", 100, true, `{"ntp":{"servers":["10.0.0.1","10.0.0.2"]},"syslog":{"host":"10.0.0.9","port":514}}`},
		{"Fixture syslog override", 500, true, `{"syslog":{"port":6514,"tls":true}}`},
		{"Fixture inactive", 900, false, `{"ntp":{"servers":["192.0.2.1"]}}`},
	}
	for _, r := range rows {
		e.Witness(r.name)
		if _, err := tx.ExecContext(ctx, `INSERT INTO config_contexts (tenant_id, name, weight, is_active, data) VALUES ($1, $2, $3, $4, $5::jsonb)`,
			e.Tenant, r.name, r.weight, r.active, r.data); err != nil {
			return 0, err
		}
	}
	return len(rows), nil
}
