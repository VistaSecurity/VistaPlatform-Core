package handlers

// Seeded-content ownership on classification rules (decision 4, RC-12): the
// fields every rule now carries and the accept-update route, validated against
// api/openapi/admin-service.openapi.yaml, and the accept's audit record.

import (
	"net/http"
	"testing"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/classificationrules"
)

const seededRuleID = "11111111-1111-4111-8111-111111111111"

func seededRuleStore() *stubRuleStore {
	return &stubRuleStore{rules: []classificationrules.Rule{
		{ID: seededRuleID, RuleKind: "oui", Pattern: "00000C",
			ClassKey: ptr("network_device"), Vendor: ptr("Cisco Systems"), Confidence: 0.55,
			SourceURL: ptr("https://standards-oui.ieee.org/"),
			CreatedAt: "2026-09-01T00:00:00Z", UpdatedAt: "2026-09-01T00:00:00Z",
			ContentOrigin: "vista", AdminModified: true, UpdateAvailable: true,
			OfferedUpdate: map[string]any{"confidence": 0.75}},
	}}
}

func TestContract_ClassificationRule_SeededContent(t *testing.T) {
	sv := loadSpec(t)
	r := ruleRouter(seededRuleStore())
	base := "/admin/catalogs/classification-rules"

	w := doJSON(t, r, http.MethodGet, base, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	sv.assertConforms(t, "ClassificationRuleListResponse", w.Body.Bytes())

	w = doJSON(t, r, http.MethodGet, base+"/"+seededRuleID, nil)
	sv.assertConforms(t, "ClassificationRule", w.Body.Bytes())

	w = doJSON(t, r, http.MethodPost, base+"/"+seededRuleID+"/accept-update", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("accept: %d %s", w.Code, w.Body)
	}
	sv.assertConforms(t, "ClassificationRule", w.Body.Bytes())

	if w := doJSON(t, r, http.MethodPost, base+"/"+seededRuleID+"/accept-update", nil); w.Code != http.StatusConflict {
		t.Errorf("second accept: %d, want 409", w.Code)
	}
	if w := doJSON(t, r, http.MethodPost, base+"/22222222-2222-4222-8222-222222222222/accept-update", nil); w.Code != http.StatusNotFound {
		t.Errorf("accept on a missing rule: %d, want 404", w.Code)
	}
	if w := doJSON(t, r, http.MethodPost, base+"/not-a-uuid/accept-update", nil); w.Code != http.StatusBadRequest {
		t.Errorf("accept on a malformed id: %d, want 400", w.Code)
	}
}

// Accepting a shipped update rewrites a rule every tenant is classified
// against, so it is audited with what changed; a 409 (nothing on offer) is a
// non-event and is not.
func TestClassificationRuleAudit_AcceptUpdateIsRecorded(t *testing.T) {
	events := captureAudit(t)
	eng := auditedRuleEngine(seededRuleStore())

	w := ruleRequest(t, eng, http.MethodPost, ruleBase+"/"+seededRuleID+"/accept-update", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("accept: status = %d; body=%s", w.Code, w.Body)
	}
	body := awaitAudit(t, events)
	assertField(t, body, "event_type", "classification_rule.update_accepted")
	assertField(t, body, "action", "update")
	nv, _ := body["new_values"].(map[string]interface{})
	if nv["confidence"] != 0.75 {
		t.Errorf("the accept record does not carry the accepted value: new_values=%v", body["new_values"])
	}
	meta, _ := body["metadata"].(map[string]interface{})
	prev, _ := meta["previous"].(map[string]interface{})
	if prev["confidence"] != 0.55 {
		t.Errorf("the accept record does not carry the replaced value: metadata=%v", meta)
	}

	w = ruleRequest(t, eng, http.MethodPost, ruleBase+"/"+seededRuleID+"/accept-update", nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("second accept: status = %d, want 409", w.Code)
	}
	expectNoAudit(t, events)
}
