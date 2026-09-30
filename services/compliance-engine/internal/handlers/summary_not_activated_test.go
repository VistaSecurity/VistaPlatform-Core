package handlers

// GET /summary for a published framework the tenant has not activated.
//
// The service returns ErrFrameworkNotLicensed; the handler used to fall through
// to its generic branch and answer 500 "Failed to evaluate framework", which
// sent the MCP compliance-summary tool (and an operator) hunting a server fault
// that did not exist. It is a 403 with a machine-readable reason, beside the
// neighbouring edition/licence refusals.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
)

type summaryErrStore struct {
	stubEvaluationStore
	err error
}

func (s *summaryErrStore) EvaluateFramework(_, _ uuid.UUID, _ string, _ models.ScenarioFilters, _ *uuid.UUID) (*services.SummaryResponse, error) {
	return nil, s.err
}

func summaryEngine(err error) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/compliance-engine")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})
	wh := &WorkspaceHandlers{evaluationService: &summaryErrStore{err: err}}
	grp.GET("/summary", wh.GetSummary)
	return r
}

func TestGetSummary_NotActivatedIs403WithReason(t *testing.T) {
	path := fmt.Sprintf("%s/summary?framework_id=%s", evalBase, uuid.New())
	for name, err := range map[string]error{
		"bare":    services.ErrFrameworkNotLicensed,
		"wrapped": fmt.Errorf("evaluate: %w", services.ErrFrameworkNotLicensed),
	} {
		t.Run(name, func(t *testing.T) {
			w := do(summaryEngine(err), http.MethodGet, path, nil)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
			}
			var body struct {
				Error  string `json:"error"`
				Reason string `json:"reason"`
			}
			if e := json.Unmarshal(w.Body.Bytes(), &body); e != nil {
				t.Fatalf("not JSON: %v (%s)", e, w.Body.String())
			}
			if body.Reason != sharedapi.ReasonFrameworkNotActivated {
				t.Errorf("reason = %q, want %q", body.Reason, sharedapi.ReasonFrameworkNotActivated)
			}
			if body.Error == "" {
				t.Error("no human-readable error")
			}
		})
	}
}

// The other polarity: the typed arm must not swallow the neighbours.
func TestGetSummary_OtherErrorsKeepTheirStatus(t *testing.T) {
	path := fmt.Sprintf("%s/summary?framework_id=%s", evalBase, uuid.New())
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{"unknown framework is 404", fmt.Errorf("%w: x", services.ErrFrameworkNotFound), http.StatusNotFound},
		{"anything else is still a 500", errors.New("db exploded"), http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := do(summaryEngine(tc.err), http.MethodGet, path, nil)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}
