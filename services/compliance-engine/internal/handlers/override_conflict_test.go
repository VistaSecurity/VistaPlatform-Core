package handlers

import (
	"net/http"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
)

// A second override for the same control and scenario must answer 409, not the
// generic 500: the duplicate is the caller's conflict, not a server fault.
func TestContract_CreateOverride_409_duplicate(t *testing.T) {
	eng := newWorkspaceEngine(&stubScenarioStore{}, &stubOverrideStore{createErr: services.ErrDuplicateOverride})
	body := `{"control_id":"` + fUUID + `","override_type":"disregard","rationale":"accepted risk"}`
	w := do(eng, http.MethodPost, cBase+"/overrides", strings.NewReader(body))
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
}
