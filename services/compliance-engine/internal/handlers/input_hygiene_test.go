package handlers

// Invalid input answers a 4xx that names the problem, not a 500, and the lists
// that had no bound now have one. These drive the real handlers over httptest
// with the same stubs the contract tests use.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
)

const tBase = "/api/v1/compliance-engine"

func jsonBody(s string) *strings.Reader { return strings.NewReader(s) }

func TestListTickets_PageSizeIsClampedAndGarbageIs400(t *testing.T) {
	st := &stubTicketStore{}
	eng := newTicketEngine(st)

	w := do(eng, http.MethodGet, tBase+"/tickets?page_size=500", nil)
	if w.Code != http.StatusOK || st.lastFilters.PageSize != 100 {
		t.Fatalf("page_size=500: status %d, forwarded page size %d; want 200 and 100 (was silently 20)", w.Code, st.lastFilters.PageSize)
	}
	for _, q := range []string{"page_size=abc", "page=0", "page_size=-3", "page=x"} {
		if w := do(eng, http.MethodGet, tBase+"/tickets?"+q, nil); w.Code != http.StatusBadRequest {
			t.Errorf("?%s: status %d, want 400", q, w.Code)
		}
	}
}

func TestListComments_IsBoundedAndStrict(t *testing.T) {
	st := &stubTicketStore{}
	eng := newTicketEngine(st)
	path := tBase + "/tickets/" + aTicketUUID + "/comments"

	if w := do(eng, http.MethodGet, path, nil); w.Code != http.StatusOK || st.lastLimit != 100 {
		t.Fatalf("no page_size: status %d limit %d; want 200 and the 100 cap", w.Code, st.lastLimit)
	}
	if w := do(eng, http.MethodGet, path+"?page_size=100000&page=3", nil); w.Code != http.StatusOK || st.lastLimit != 100 || st.lastOffset != 200 {
		t.Fatalf("huge page_size: status %d limit %d offset %d; want 200, 100, 200", w.Code, st.lastLimit, st.lastOffset)
	}
	if w := do(eng, http.MethodGet, path+"?page_size=zzz", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("garbage page_size: status %d, want 400", w.Code)
	}
}

func TestGetFindingsByAsset_IsBoundedAndStrict(t *testing.T) {
	st := &stubFindingsStore{}
	eng := newFindingsEngine(st)
	path := tBase + "/assets/" + fUUID + "/findings"

	if w := do(eng, http.MethodGet, path+"?page_size=99999", nil); w.Code != http.StatusOK || st.lastAssetLimit != 100 {
		t.Fatalf("huge page_size: status %d limit %d; want 200 and 100", w.Code, st.lastAssetLimit)
	}
	if w := do(eng, http.MethodGet, path, nil); w.Code != http.StatusOK || st.lastAssetLimit != 100 {
		t.Fatalf("no page_size: status %d limit %d; want 200 and 100", w.Code, st.lastAssetLimit)
	}
	if w := do(eng, http.MethodGet, path+"?page=-1", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("garbage page: status %d, want 400", w.Code)
	}
}

func TestCreateTicket_BadReferencesAndLengthsAre400(t *testing.T) {
	good := uuid.NewString()
	cases := map[string]string{
		"finding_id":     `{"title":"t","finding_id":"nope"}`,
		"asset_id":       `{"title":"t","asset_id":"123"}`,
		"assigned_to":    `{"title":"t","assigned_to":"me"}`,
		"control_id":     `{"title":"t","control_id":"x"}`,
		"certificate_id": `{"title":"t","certificate_id":"x"}`,
		"due_date":       `{"title":"t","due_date":"tomorrow"}`,
		"title":          `{"title":"` + strings.Repeat("a", titleMax+1) + `"}`,
		"description":    `{"title":"t","description":"` + strings.Repeat("a", models.MaxTicketDescriptionLen+1) + `"}`,
	}
	for field, body := range cases {
		t.Run(field, func(t *testing.T) {
			st := &stubTicketStore{createResult: &models.Ticket{}}
			w := do(newTicketEngine(st), http.MethodPost, tBase+"/tickets", jsonBody(body))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400; body=%s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), field) {
				t.Errorf("error does not name %q: %s", field, w.Body.String())
			}
			if st.createCalled {
				t.Errorf("the store was called with input that should have been refused")
			}
		})
	}

	// And well-formed references still reach the store.
	st := &stubTicketStore{createResult: ptrTicket()}
	w := do(newTicketEngine(st), http.MethodPost, tBase+"/tickets",
		jsonBody(`{"title":"t","finding_id":"`+good+`","assigned_to":"`+good+`"}`))
	if w.Code != http.StatusCreated || !st.createCalled {
		t.Fatalf("valid refs: status %d called=%v, want 201", w.Code, st.createCalled)
	}
}

const titleMax = models.MaxTicketTitleLen

func ptrTicket() *models.Ticket { s := sampleTicket(); return &s }

func TestCreateTicket_ServiceInputErrorsMapTo400And422(t *testing.T) {
	missing := &services.InputError{Field: "assigned_to", Message: "does not exist in this tenant", Missing: true}
	st := &stubTicketStore{createErr: missing}
	w := do(newTicketEngine(st), http.MethodPost, tBase+"/tickets",
		jsonBody(`{"title":"t","assigned_to":"`+uuid.NewString()+`"}`))
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "assigned_to") {
		t.Fatalf("missing reference: status %d body %s, want 422 naming assigned_to", w.Code, w.Body.String())
	}

	st = &stubTicketStore{createErr: &services.InputError{Field: "due_date", Message: "bad"}}
	w = do(newTicketEngine(st), http.MethodPost, tBase+"/tickets", jsonBody(`{"title":"t"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("malformed field: status %d, want 400", w.Code)
	}
}

func TestUpdateTicket_BadAssigneeAndDueDateAre400(t *testing.T) {
	for _, body := range []string{`{"assigned_to":"nope"}`, `{"due_date":"soon"}`,
		`{"description":"` + strings.Repeat("a", models.MaxTicketDescriptionLen+1) + `"}`} {
		w := do(newTicketEngine(&stubTicketStore{updateResult: ptrTicket()}), http.MethodPut,
			tBase+"/tickets/"+aTicketUUID, jsonBody(body))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%.40s: status %d, want 400", body, w.Code)
		}
	}
	st := &stubTicketStore{updateErr: &services.InputError{Field: "assigned_to", Message: "x", Missing: true}}
	w := do(newTicketEngine(st), http.MethodPut, tBase+"/tickets/"+aTicketUUID,
		jsonBody(`{"assigned_to":"`+uuid.NewString()+`"}`))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("foreign assignee: status %d, want 422", w.Code)
	}
}

func TestAddComment_OversizedContentIs400(t *testing.T) {
	st := &stubTicketStore{}
	w := do(newTicketEngine(st), http.MethodPost, tBase+"/tickets/"+aTicketUUID+"/comments",
		jsonBody(`{"content":"`+strings.Repeat("a", models.MaxTicketCommentLen+1)+`"}`))
	if w.Code != http.StatusBadRequest || st.commentCalled {
		t.Fatalf("status %d called=%v, want 400 without touching the store", w.Code, st.commentCalled)
	}
}

func TestWorkflowStatus_ServiceInputErrorsAre400(t *testing.T) {
	// The refusals themselves are the service's (see
	// TestUpdateWorkflowStatus_RefusesBadInputAsInputErrors); this pins that the
	// handler turns them into 400 instead of the 500 they used to be.
	for _, field := range []string{"workflow_status", "suppression_reason", "suppressed_until"} {
		st := &stubFindingsStore{updWorkflowEr: &services.InputError{Field: field, Message: "bad"}}
		w := do(newFindingsEngine(st), http.MethodPut, tBase+"/findings/"+fUUID+"/workflow-status",
			jsonBody(`{"workflow_status":"SUPPRESSED"}`))
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), field) {
			t.Errorf("%s: status %d body %s, want 400 naming the field", field, w.Code, w.Body.String())
		}
	}
}

func TestAssignFinding_StrangerAssigneeIs422(t *testing.T) {
	st := &stubFindingsStore{assignErr: &services.InputError{Field: "assigned_to", Message: "does not exist in this tenant", Missing: true}}
	w := do(newFindingsEngine(st), http.MethodPost, tBase+"/findings/"+fUUID+"/assign",
		jsonBody(`{"assigned_to":"`+uuid.NewString()+`"}`))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422", w.Code)
	}
}

func TestCreateOverride_InvalidFrameworkTypeIs400(t *testing.T) {
	ov := &stubOverrideStore{}
	w := do(newWorkspaceEngine(&stubScenarioStore{}, ov), http.MethodPost, tBase+"/overrides",
		jsonBody(`{"control_id":"`+uuid.NewString()+`","override_type":"severity","severity_from":"low","severity_to":"high","rationale":"r","framework_type":"bogus"}`))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "framework_type") {
		t.Fatalf("status %d body %s, want 400 naming framework_type", w.Code, w.Body.String())
	}
	long := strings.Repeat("a", maxOverrideRationaleLen+1)
	w = do(newWorkspaceEngine(&stubScenarioStore{}, ov), http.MethodPost, tBase+"/overrides",
		jsonBody(`{"control_id":"`+uuid.NewString()+`","override_type":"severity","severity_from":"low","severity_to":"high","rationale":"`+long+`"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("huge rationale: status %d, want 400", w.Code)
	}
}
