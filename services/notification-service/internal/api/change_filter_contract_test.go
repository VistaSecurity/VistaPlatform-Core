package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
)

// An Inventory-changes rule's change_filter round-trips through the spec, and
// a filter naming an object kind or action that does not exist is refused at
// the handler with 400 rather than stored as a rule that silently matches
// nothing. Mutation: delete either req.ChangeFilter.Validate() call → the
// matching 400 test fails.
func TestContract_CreateTenantRule_ChangeFilter_201(t *testing.T) {
	sv := ncLoadSpec(t)
	rule := sampleRule(uuid.New())
	at := models.ObjectChangedAlertType
	rule.AlertType = &at
	rule.ChangeFilter = &models.ChangeFilter{ObjectKinds: []string{"cable"}, Actions: []string{"update"}, IncludeIntake: true}
	eng := ncEngine(&stubChannelManager{}, &stubRuleEngine{created: &rule})
	body := `{"rule_name":"r","alert_source":"inventory-service","alert_type":"object_changed","channel_ids":["` + ncAID + `"],` +
		`"change_filter":{"object_kinds":["cable"],"actions":["update"],"include_intake":true,"include_sync":false}}`
	w := ncDo(eng, http.MethodPost, ncBase+"/tenant/rules", strings.NewReader(body))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TenantNotificationRule", w.Body.Bytes())
}

func TestContract_TenantRule_UnknownChangeKind_400(t *testing.T) {
	sv := ncLoadSpec(t)
	eng := ncEngine(&stubChannelManager{}, &stubRuleEngine{})
	create := `{"rule_name":"r","alert_source":"inventory-service","alert_type":"object_changed","channel_ids":["` + ncAID + `"],` +
		`"change_filter":{"object_kinds":["cables"],"include_intake":false,"include_sync":false}}`
	w := ncDo(eng, http.MethodPost, ncBase+"/tenant/rules", strings.NewReader(create))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "cables") {
		t.Fatalf("create: status = %d, want 400 naming the kind; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())

	update := `{"change_filter":{"actions":["modify"],"include_intake":false,"include_sync":false}}`
	w = ncDo(eng, http.MethodPut, ncBase+"/tenant/rules/"+ncAID, strings.NewReader(update))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "modify") {
		t.Fatalf("update: status = %d, want 400 naming the action; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
