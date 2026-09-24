package handlers

// A HUMAN decision on a proposal writes the same kind of record the MACHINE
// path writes (security review X.5, X5-09).
//
// The merge, relationship and class accept/reject routes carried no explicit
// audit entry. The global LogRequest middleware still recorded method, path,
// status and actor, so nothing was UNAUDITED — but the record said
// "POST /approvals/classes/<uuid>/accept, 200" and not which class was applied
// to which asset, which is the only part anyone reconstructing an approval
// queue afterwards needs.
//
// The asymmetry is what made it worth closing. AssetService.auditAutoAcceptedMerge
// writes a rich record for the auto-accept path — score, model id, candidates,
// reason — precisely because nobody is there to ask. The human path, the one
// with a person who can be asked and therefore the one an auditor actually
// reconstructs, wrote less.
//
// Driven through the REAL routes and a REAL audit middleware, whose batch is
// pointed at an httptest server: the entry is asserted on the wire, in the
// shape audit-service receives. A test that called logAuditActivity directly
// would pass with the call deleted from the handler.
//
// To mutation-test: delete the auditProposalDecision call from any of the three
// handlers and that decision's sub-test times out waiting for its entry.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// auditedEntry is the subset of the activity-log body this test reads. The
// audit-service's own contract is pinned in that service; here the question is
// only whether the handler said which thing was decided.
type auditedEntry struct {
	EventType    string         `json:"event_type"`
	Action       string         `json:"action"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	Metadata     map[string]any `json:"metadata"`
	OldValues    map[string]any `json:"old_values"`
	NewValues    map[string]any `json:"new_values"`
}

// newAuditSpy returns a middleware that puts a REAL audit middleware in the gin
// context — which is how main.go wires it, and what logAuditActivity looks for
// — plus the channel its batch actually posts to.
func newAuditSpy(t *testing.T) (gin.HandlerFunc, <-chan auditedEntry) {
	t.Helper()

	entries := make(chan auditedEntry, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// The batch endpoint takes either one entry or a list, depending on the
		// route; decode whichever arrived rather than assuming.
		var one auditedEntry
		if err := json.Unmarshal(body, &one); err == nil && one.EventType != "" {
			select {
			case entries <- one:
			default:
			}
		}
		var many struct {
			Logs []auditedEntry `json:"logs"`
		}
		if err := json.Unmarshal(body, &many); err == nil {
			for _, e := range many.Logs {
				if e.EventType == "" {
					continue
				}
				select {
				case entries <- e:
				default:
				}
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	cfg := auditmiddleware.DefaultConfig()
	cfg.Enabled = true
	cfg.ServiceName = "inventory-service"
	cfg.AuditServiceURL = srv.URL
	cfg.BatchSize = 1 // flush on the first entry
	cfg.FlushInterval = time.Hour
	mw := auditmiddleware.NewMiddleware(cfg)

	return func(c *gin.Context) {
		c.Set("audit_middleware", mw)
		c.Next()
	}, entries
}

func awaitEntry(t *testing.T, entries <-chan auditedEntry, eventType string) auditedEntry {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case e := <-entries:
			if e.EventType == eventType {
				return e
			}
		case <-deadline:
			t.Fatalf("no audit entry of type %q was written — the decision left no record of WHAT was decided",
				eventType)
			return auditedEntry{}
		}
	}
}

func TestProposalDecisions_WriteAnAuditEntryNamingWhatWasDecided(t *testing.T) {
	t.Run("merge accept", func(t *testing.T) {
		spy, entries := newAuditSpy(t)
		view := sampleMergeProposalView()
		h := NewAssetPhase1Handler(nil, nil, nil, &stubProposalStore{one: &view})

		gin.SetMode(gin.TestMode)
		r := gin.New()
		grp := r.Group("/api/v2")
		grp.Use(spy, func(c *gin.Context) {
			c.Set("tenantID", uuid.New())
			c.Set("userID", uuid.New())
			c.Next()
		})
		grp.POST("/inventory-service/approvals/merge-proposals/:id/accept", h.AcceptMergeProposal)
		grp.POST("/inventory-service/approvals/merge-proposals/:id/keep-separate", h.KeepMergeProposalSeparate)

		survivor := view.Candidates[0].AssetID
		body := `{"survivor_asset_id":"` + survivor.String() + `"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost,
			"/api/v2/inventory-service/approvals/merge-proposals/"+view.ID.String()+"/accept",
			strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", w.Code, w.Body.String())
		}

		e := awaitEntry(t, entries, "asset.merge.accepted")
		if e.ResourceID != view.ID.String() {
			t.Errorf("resource_id = %q, want the proposal %s", e.ResourceID, view.ID)
		}
		if e.Action != "accepted" {
			t.Errorf("action = %q, want accepted", e.Action)
		}
		if got := e.Metadata["survivor_asset_id"]; got != survivor.String() {
			t.Errorf("survivor_asset_id = %v, want %s — the record does not say which asset the merge kept",
				got, survivor)
		}
		if _, ok := e.Metadata["candidates"]; !ok {
			t.Error("the record does not carry the candidates the decision was made between")
		}
	})

	t.Run("class accept", func(t *testing.T) {
		spy, entries := newAuditSpy(t)
		proposal := sampleClassProposal()
		h := NewClassProposalHandler(&stubClassProposalStore{one: &proposal})

		gin.SetMode(gin.TestMode)
		r := gin.New()
		grp := r.Group("/api/v2")
		grp.Use(spy, func(c *gin.Context) {
			c.Set("tenantID", uuid.New())
			c.Set("userID", uuid.New())
			c.Next()
		})
		grp.POST("/inventory-service/approvals/classes/:id/accept", h.AcceptClassProposal)

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost,
			"/api/v2/inventory-service/approvals/classes/"+proposal.ID.String()+"/accept", nil)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", w.Code, w.Body.String())
		}

		e := awaitEntry(t, entries, "asset.class_proposal.accepted")
		if got := e.Metadata["asset_id"]; got != proposal.AssetID.String() {
			t.Errorf("asset_id = %v, want %s — the record does not say WHICH asset was reclassified",
				got, proposal.AssetID)
		}
		if got := e.Metadata["proposed_class_key"]; got != proposal.ProposedClassKey {
			t.Errorf("proposed_class_key = %v, want %q — the record does not say WHICH class was applied",
				got, proposal.ProposedClassKey)
		}
	})

	t.Run("relationship reject", func(t *testing.T) {
		spy, entries := newAuditSpy(t)
		edge := sampleProposal()
		h := NewRelationshipHandler(&stubRelationshipStore{one: &edge})

		gin.SetMode(gin.TestMode)
		r := gin.New()
		grp := r.Group("/api/v2")
		grp.Use(spy, func(c *gin.Context) {
			c.Set("tenantID", uuid.New())
			c.Set("userID", uuid.New())
			c.Next()
		})
		grp.POST("/inventory-service/approvals/relationships/:edgeId/reject", h.RejectRelationshipProposal)

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost,
			"/api/v2/inventory-service/approvals/relationships/"+edge.ID.String()+"/reject", nil)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", w.Code, w.Body.String())
		}

		e := awaitEntry(t, entries, "asset.relationship_proposal.rejected")
		if got := e.Metadata["from_asset_id"]; got != edge.FromAssetID.String() {
			t.Errorf("from_asset_id = %v, want %s — the record does not say which claim about the "+
				"topology was rejected", got, edge.FromAssetID)
		}
		if got := e.Metadata["relationship_type"]; got != edge.Type {
			t.Errorf("relationship_type = %v, want %q", got, edge.Type)
		}
	})
}

func sampleMergeProposalView() services.MergeProposalView {
	obs := uuid.New()
	return services.MergeProposalView{
		ID: uuid.New(), TenantID: uuid.New(), Status: "pending",
		Source: "sensor", SourceKind: "measured", Reason: "same serial",
		ObservationAssetID: &obs,
		Candidates: []services.MergeCandidateView{
			{AssetID: uuid.New(), DisplayName: "web01", Score: 0.91},
			{AssetID: uuid.New(), DisplayName: "web01.example.test", Score: 0.62},
		},
		ModelID: "matcher-rules",
	}
}
