package handlers

// Contract tests for the class-proposal surface (workstream 2.10b, ADR-0004 D6).
//
// Same harness as relationship_contract_test.go: the REAL gin handlers over
// httptest with an in-memory stub, every response body validated against
// api/openapi/inventory-service.openapi.yaml.
//
// The route table here mirrors cmd/main.go's v2 registrations EXACTLY, because
// a handler tested on a path nobody serves is a test of nothing.

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/classify"
)

// --- stub -------------------------------------------------------------------

type stubClassProposalStore struct {
	proposals []services.ClassProposalView
	total     int
	one       *services.ClassProposalView
	err       error

	// What the handler actually asked for, so a test can assert the clamp and
	// the parameter mapping rather than trusting an echo the handler computed
	// separately.
	gotLimit  int
	gotOffset int
	gotAccept bool
	gotClass  string
}

func (s *stubClassProposalStore) ListPending(_ context.Context, _ uuid.UUID, limit, offset int) ([]services.ClassProposalView, int, error) {
	s.gotLimit, s.gotOffset = limit, offset
	return s.proposals, s.total, s.err
}

func (s *stubClassProposalStore) Decide(_ context.Context, _, _, _ uuid.UUID, accept bool, chosen string) (*services.ClassProposalView, error) {
	s.gotAccept, s.gotClass = accept, chosen
	return s.one, s.err
}

func newClassProposalEngine(h *ClassProposalHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})
	grp.GET("/inventory-service/approvals/classes", h.ListClassProposals)
	grp.POST("/inventory-service/approvals/classes/:id/accept", h.AcceptClassProposal)
	grp.POST("/inventory-service/approvals/classes/:id/reject", h.RejectClassProposal)
	return r
}

func sampleClassProposal() services.ClassProposalView {
	return services.ClassProposalView{
		ID: uuid.New(), TenantID: uuid.New(), AssetID: uuid.New(),
		Status: "pending", Source: "classifier:rules",
		ProposedClassKey: "printer", ProposedClassLabel: "Printer",
		CurrentClassKey: "unknown_host", CurrentClassLabel: "Unknown host",
		CurrentSourceKind: "measured",
		MatchedRules: []classify.RuleRef{{
			ID: uuid.New().String(), Kind: classify.KindMDNSService, Pattern: "_ipp._tcp",
			Class: "printer", Confidence: 0.75, SourceURL: "https://www.rfc-editor.org/rfc/rfc8011.html",
		}},
		RuleIDs: []string{uuid.New().String()}, Confidence: 0.75,
		ProposedAt: time.Now().UTC(),
		AssetName:  "printer-2", AssetHost: "printer-2", AssetAddress: "192.0.2.31",
		AssetStatus: "monitoring",
	}
}

func classPath(id uuid.UUID, suffix string) string {
	return "/api/v2/inventory-service/approvals/classes/" + id.String() + suffix
}

// --- the queue ---------------------------------------------------------------

func TestContract_ListClassProposals_200(t *testing.T) {
	sv := loadSpec(t)
	store := &stubClassProposalStore{proposals: []services.ClassProposalView{sampleClassProposal()}, total: 1}
	w := do(newClassProposalEngine(NewClassProposalHandler(store)), http.MethodGet,
		"/api/v2/inventory-service/approvals/classes", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ClassProposalListResponse", w.Body.Bytes())
}

// An empty queue is an ANSWER and has to serialise as one: `[]`, not `null`.
// A client that reads `null` as "the read failed" shows a reviewer an error
// where there is simply no work.
func TestContract_ListClassProposals_EmptyIsAnAnswer(t *testing.T) {
	sv := loadSpec(t)
	store := &stubClassProposalStore{proposals: []services.ClassProposalView{}}
	w := do(newClassProposalEngine(NewClassProposalHandler(store)), http.MethodGet,
		"/api/v2/inventory-service/approvals/classes", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"class_proposals":[]`) {
		t.Errorf("empty queue serialised as %s, want an empty array", w.Body.String())
	}
	sv.assertConforms(t, "ClassProposalListResponse", w.Body.Bytes())
}

// Only `pending` is served. Answering 200 with pending rows for any other
// status would be the API agreeing to a question it did not answer.
func TestContract_ListClassProposals_RefusesAnotherStatus(t *testing.T) {
	store := &stubClassProposalStore{}
	w := do(newClassProposalEngine(NewClassProposalHandler(store)), http.MethodGet,
		"/api/v2/inventory-service/approvals/classes?status=accepted", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

// The page the SERVER used is echoed, not the one the caller asked for.
func TestContract_ListClassProposals_ClampsThePage(t *testing.T) {
	store := &stubClassProposalStore{proposals: []services.ClassProposalView{}}
	w := do(newClassProposalEngine(NewClassProposalHandler(store)), http.MethodGet,
		"/api/v2/inventory-service/approvals/classes?limit=100000&offset=-5", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if store.gotLimit != 100000 || store.gotOffset != -5 {
		t.Errorf("the handler passed limit=%d offset=%d; it must hand the request through and let the service clamp",
			store.gotLimit, store.gotOffset)
	}
	if !strings.Contains(w.Body.String(), `"limit":50`) || !strings.Contains(w.Body.String(), `"offset":0`) {
		t.Errorf("echoed %s, want the clamped page", w.Body.String())
	}
}

// --- deciding ----------------------------------------------------------------

func TestContract_AcceptClassProposal_200(t *testing.T) {
	sv := loadSpec(t)
	decided := sampleClassProposal()
	decided.Status, decided.AcceptedClassKey = "accepted", "printer"
	store := &stubClassProposalStore{one: &decided}
	w := do(newClassProposalEngine(NewClassProposalHandler(store)), http.MethodPost,
		classPath(uuid.New(), "/accept"), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	if !store.gotAccept {
		t.Error("accept did not reach the service as an acceptance")
	}
	sv.assertConforms(t, "ClassProposalResponse", w.Body.Bytes())
}

// The chosen class travels. A conflict proposal offers a choice, and a handler
// that dropped the body would accept something the reviewer did not pick.
func TestContract_AcceptClassProposal_CarriesTheChosenClass(t *testing.T) {
	decided := sampleClassProposal()
	decided.Status, decided.AcceptedClassKey = "accepted", "switch"
	store := &stubClassProposalStore{one: &decided}
	w := do(newClassProposalEngine(NewClassProposalHandler(store)), http.MethodPost,
		classPath(uuid.New(), "/accept"), jsonReader(`{"class_key":"switch"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	if store.gotClass != "switch" {
		t.Errorf("the service was asked for class %q, want switch", store.gotClass)
	}
}

func TestContract_RejectClassProposal_200(t *testing.T) {
	sv := loadSpec(t)
	decided := sampleClassProposal()
	decided.Status = "rejected"
	store := &stubClassProposalStore{one: &decided}
	w := do(newClassProposalEngine(NewClassProposalHandler(store)), http.MethodPost,
		classPath(uuid.New(), "/reject"), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	if store.gotAccept {
		t.Error("reject reached the service as an acceptance")
	}
	sv.assertConforms(t, "ClassProposalResponse", w.Body.Bytes())
}

// 409 and not 404: a second click on a stale page has to say what happened, and
// "no such proposal" says the row never existed.
func TestContract_DecideClassProposal_409WhenAlreadyDecided(t *testing.T) {
	store := &stubClassProposalStore{err: services.ErrClassProposalDecided}
	w := do(newClassProposalEngine(NewClassProposalHandler(store)), http.MethodPost,
		classPath(uuid.New(), "/accept"), nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (body %s)", w.Code, w.Body.String())
	}
}

func TestContract_DecideClassProposal_404(t *testing.T) {
	store := &stubClassProposalStore{err: services.ErrClassProposalNotFound}
	w := do(newClassProposalEngine(NewClassProposalHandler(store)), http.MethodPost,
		classPath(uuid.New(), "/reject"), nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

// A conflict proposal accepted with no class named is a 400 that NAMES the
// choices, not a server error and not a silent pick.
func TestContract_AcceptClassProposal_400WhenItNeedsAChoice(t *testing.T) {
	store := &stubClassProposalStore{err: services.ErrClassProposalNeedsChoice}
	w := do(newClassProposalEngine(NewClassProposalHandler(store)), http.MethodPost,
		classPath(uuid.New(), "/accept"), nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestContract_AcceptClassProposal_400WhenTheClassIsNotOffered(t *testing.T) {
	store := &stubClassProposalStore{err: services.ErrClassNotInProposal}
	w := do(newClassProposalEngine(NewClassProposalHandler(store)), http.MethodPost,
		classPath(uuid.New(), "/accept"), jsonReader(`{"class_key":"plc"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

// A malformed body is refused rather than ignored. Dropping it would accept the
// PROPOSED class while the reviewer believed they had chosen a different one.
func TestContract_AcceptClassProposal_400OnAMalformedBody(t *testing.T) {
	store := &stubClassProposalStore{one: &services.ClassProposalView{}}
	w := do(newClassProposalEngine(NewClassProposalHandler(store)), http.MethodPost,
		classPath(uuid.New(), "/accept"), jsonReader(`{"class_key":`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", w.Code, w.Body.String())
	}
}

// jsonReader is a body for do(), which takes an io.Reader and sets the content
// type when one is present.
func jsonReader(body string) io.Reader { return strings.NewReader(body) }
