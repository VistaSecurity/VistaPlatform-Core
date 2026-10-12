package services

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
)

// The control-details findings page must be cut in SQL. Pins the query text so
// a regression to "load everything, slice in Go" fails without a database.
func TestControlFindingsPageSQL_CutsThePageInSQL(t *testing.T) {
	from, args := controlFindingsFrom(uuid.New(), uuid.New(), models.ScenarioFilters{Severity: "high"}, true)
	q := controlFindingsPageSQL(from, len(args))
	for _, want := range []string{"LIMIT $4", "OFFSET $5", "ORDER BY cf.last_seen DESC"} {
		if !strings.Contains(q, want) {
			t.Errorf("page query lacks %q:\n%s", want, q)
		}
	}
	if !strings.Contains(from, "workflow_status") || !strings.Contains(from, "suppressed_until") {
		t.Errorf("page query does not use the shared suppression predicate:\n%s", from)
	}
}
