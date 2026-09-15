package handlers

// Shared harness for the remediation-drafting contract tests, in both edition
// polarities. The cases themselves live in remediation_draft_core_contract_test.go
// (`!ee`) and remediation_draft_ee_contract_test.go (`ee`) — they assert
// different things because the edition boundary is a build-tag fact, and a test
// that could only ever see one side of it is a test that cannot fail in the
// direction that matters.

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
)

// --- stubs -----------------------------------------------------------------

type stubFindingResolver struct {
	ref seams.FindingRef
	err error
}

func (s *stubFindingResolver) ResolveFinding(context.Context, uuid.UUID, uuid.UUID) (seams.FindingRef, error) {
	return s.ref, s.err
}

type stubDraftPlanStore struct {
	created   *models.RemediationPlan
	createErr error

	added    *models.RemediationPlanItem
	addErr   error
	addCalls []addDraftedCall
}

type addDraftedCall struct {
	TenantID, PlanID, AddedBy, FindingID uuid.UUID
	Notes, SourceKind, SourceRef         string
}

func (s *stubDraftPlanStore) Create(uuid.UUID, uuid.UUID, models.CreatePlanInput) (*models.RemediationPlan, error) {
	return s.created, s.createErr
}

func (s *stubDraftPlanStore) AddDraftedItem(
	tenantID, planID, addedBy, findingID uuid.UUID, notes, sourceKind, sourceRef string,
) (*models.RemediationPlanItem, error) {
	s.addCalls = append(s.addCalls, addDraftedCall{
		TenantID: tenantID, PlanID: planID, AddedBy: addedBy, FindingID: findingID,
		Notes: notes, SourceKind: sourceKind, SourceRef: sourceRef,
	})
	return s.added, s.addErr
}

// stubRemediator is a seams.Remediator returning a canned answer.
type stubRemediator struct {
	draft seams.PlanDraft
	err   error
	calls int
	last  seams.FindingRef
}

func (s *stubRemediator) Propose(_ context.Context, f seams.FindingRef) (seams.PlanDraft, error) {
	s.calls++
	s.last = f
	return s.draft, s.err
}

// --- engine ----------------------------------------------------------------

// newRemediationDraftEngine drives the REAL handlers on the REAL route paths.
//
// The routes are registered here exactly as cmd/main.go registers them, minus
// the RBAC middleware — which is covered by its own gate test. What this must
// not do is call the handler methods directly: the edition check, the
// tenant-controls read and the JSON binding are all in the handler, and a test
// that skipped the router would still exercise them, but a test that skipped
// the ROUTE would not notice a path typo. Both routes are POSTs on a path with a
// `:id` segment beside the existing `/findings/:id/...` group, which is exactly
// the shape gin conflicts on.
func newRemediationDraftEngine(
	seam seams.Remediator, resolver findingResolver, plans draftPlanStore,
	tenantID, userID uuid.UUID,
) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/compliance-engine")
	grp.Use(func(c *gin.Context) {
		if tenantID != uuid.Nil {
			c.Set("tenantID", tenantID)
		}
		if userID != uuid.Nil {
			c.Set("userID", userID.String())
		}
		c.Next()
	})

	// rawDB nil: these tests do not exercise the tenant kill switch, which needs
	// a real settings row. The handler logs that it is unconsulted and the
	// boundary's second lock is the backstop — and the kill switch's own
	// behaviour is pinned where it can be driven honestly, in
	// shared/ai/ee/remediator's tests.
	h := NewRemediationDraftHandlers(seam, resolver, plans, nil)
	grp.POST("/findings/:id/remediation/draft", h.Draft)
	grp.POST("/findings/:id/remediation/accept", h.Accept)
	return r
}

// --- fixtures --------------------------------------------------------------

const rdFinding = "9f1e6f2a-0000-4000-8000-00000000feed"

func sampleFindingRef() seams.FindingRef {
	return seams.FindingRef{
		FindingID:    rdFinding,
		TenantID:     uuid.New().String(),
		Producer:     "crypto",
		Kind:         "weak_configuration",
		Severity:     "high",
		SubjectType:  "crypto_configuration",
		SubjectLabel: "web01:443",
		Summary:      "Weak cryptographic configuration on web01:443",
		Guidance:     "Reconfigure the service to stop offering the weak component the catalogue flagged.",
		Evidence:     map[string]any{"protocol_version": "TLSv1.0"},
	}
}

func sampleModelDraft() seams.PlanDraft {
	return seams.PlanDraft{
		Proposal: seams.NewProposal("mock-model-1", "remediator:model", 0),
		Source:   seams.PlanSourceModel,
		Summary:  "Retire TLS 1.0 on this interface.",
		Steps: []seams.PlanStep{{
			Order:     1,
			Action:    "Disable TLSv1.0 on the management profile " + seams.EvidenceCiteMarker("protocol_version") + ".",
			Rationale: "The interface is still negotiating it.",
			Citations: []seams.Citation{{Kind: seams.CitationKindEvidence, Ref: "protocol_version"}},
			Manual:    true,
		}},
		Dropped: 1,
	}
}
