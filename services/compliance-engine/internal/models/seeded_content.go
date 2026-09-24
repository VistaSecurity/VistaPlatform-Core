package models

import shareddb "github.com/vistasecurity/vistaplatform/shared/database"

// SeededContent is the ownership state of a row Vista ships (decision 4,
// RC-12): platform frameworks, their controls and measurement rules. It is
// embedded in the platform-catalogue models and populated only by the reads
// that select SeededContentColumns — the platform admin's catalogue. Every
// field is omitempty, so a read that does not select them (and the tenant
// custom-policy reads, which share some of these structs) serialises exactly
// as before.
//
// The database owns these columns: the seeded-content guard trigger in
// scripts/database/schema.sql writes them, and an application write cannot
// set them. See the "seeded content: admin edits win" POST-MIGRATIONS block.
type SeededContent struct {
	// ContentOrigin is "vista" for a row a seed pass shipped and "custom" for
	// one a platform admin created (or one that predates the marker and no
	// seed pass has touched).
	ContentOrigin string `json:"content_origin,omitempty" db:"content_origin"`
	// AdminModified reports that a platform admin changed shipped content.
	// Upgrades no longer apply shipped changes to such a row; they offer them.
	AdminModified bool `json:"admin_modified,omitempty" db:"admin_modified"`
	// UpdateAvailable is the "update available" flag: an upgrade shipped new
	// content for this row and kept the admin's instead.
	UpdateAvailable bool `json:"update_available,omitempty" db:"update_available"`
	// OfferedUpdate is that shipped content, column by column — what accepting
	// the update would write.
	OfferedUpdate shareddb.JSONMap `json:"offered_update,omitempty" db:"offered_update"`
}

// SeededContentColumns is the SELECT list that fills SeededContent, for the
// platform tables that carry the columns. It must not be appended to a query
// over a tenant table (tenant_framework_controls has none of them).
const SeededContentColumns = `CASE WHEN content_origin = 'seed' THEN 'vista' ELSE 'custom' END AS content_origin,
	       admin_modified_at IS NOT NULL AS admin_modified,
	       seed_offer IS NOT NULL AS update_available,
	       seed_offer AS offered_update`
