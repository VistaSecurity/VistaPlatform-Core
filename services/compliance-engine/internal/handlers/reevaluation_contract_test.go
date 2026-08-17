package handlers

// Contract + behaviour test for the TENANT-facing manual re-evaluation surface
// (Risk & Compliance → Posture): GET /reevaluation and POST /reevaluate.
//
// Drives the REAL gin handlers over httptest with an in-memory cooldown stub (no
// database — the persisted cooldown itself is proven against real Postgres in
// reevaluation_integration_test.go), asserting each body conforms to the schema in
// api/openapi/compliance-engine.openapi.yaml. Shares loadSpec / assertConforms / do
// with framework_contract_test.go.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
)

// --- stubs ------------------------------------------------------------------

type stubCooldown struct {
	state    services.ReevaluationState
	claimed  bool
	claimErr error
	stateErr error

	// what Claim was actually asked about — proves the handler passes the
	// CONTEXT tenant and never a caller-supplied one.
	claimedTenant uuid.UUID
	claimedUser   uuid.UUID
	claimCalls    int
}

func (s *stubCooldown) State(context.Context, uuid.UUID) (services.ReevaluationState, error) {
	return s.state, s.stateErr
}

func (s *stubCooldown) Claim(_ context.Context, tenantID, userID uuid.UUID) (services.ReevaluationState, bool, error) {
	s.claimCalls++
	s.claimedTenant, s.claimedUser = tenantID, userID
	return s.state, s.claimed, s.claimErr
}

type spyEnqueuer struct {
	calls   int
	tenants []uuid.UUID
}

func (s *spyEnqueuer) EnqueueTenant(tenantID uuid.UUID, _ string) {
	s.calls++
	s.tenants = append(s.tenants, tenantID)
}

// newReevaluationEngine mounts the two routes with the same tenant/user injection
// the production middleware performs. Routes mirror cmd/main.go 1:1.
func newReevaluationEngine(cd *stubCooldown, enq reconcileEnqueuer, tenantID, userID uuid.UUID) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &ReevaluationHandler{svc: cd, enqueuer: enq}
	grp := r.Group("/api/v1/compliance-engine")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", tenantID)
		c.Set("userID", userID)
		c.Next()
	})
	grp.GET("/reevaluation", h.GetState)
	grp.POST("/reevaluate", h.Reevaluate)
	return r
}

func allowedState() services.ReevaluationState {
	last := time.Now().Add(-3 * time.Hour)
	return services.ReevaluationState{LastRequestedAt: &last, Allowed: true, Cooldown: time.Hour}
}

func blockedState() services.ReevaluationState {
	last := time.Now().Add(-10 * time.Minute)
	next := last.Add(time.Hour)
	return services.ReevaluationState{LastRequestedAt: &last, NextAllowedAt: &next, Cooldown: time.Hour}
}

// --- tests ------------------------------------------------------------------

func TestContract_GetReevaluationState(t *testing.T) {
	sv := loadSpec(t)

	t.Run("never re-evaluated", func(t *testing.T) {
		cd := &stubCooldown{state: services.ReevaluationState{Allowed: true, Cooldown: time.Hour}}
		e := newReevaluationEngine(cd, &spyEnqueuer{}, uuid.New(), uuid.New())
		w := do(e, http.MethodGet, "/api/v1/compliance-engine/reevaluation", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
		}
		sv.assertConforms(t, "ReevaluationState", w.Body.Bytes())
		// A tenant that has never run one must read as null, not as a zero time —
		// the UI renders "Not re-evaluated yet" off exactly this.
		if got := w.Body.String(); !containsJSONNull(got, "last_requested_at") {
			t.Fatalf("last_requested_at should be null for a tenant that never ran one: %s", got)
		}
	})

	t.Run("in cooldown", func(t *testing.T) {
		cd := &stubCooldown{state: blockedState()}
		e := newReevaluationEngine(cd, &spyEnqueuer{}, uuid.New(), uuid.New())
		w := do(e, http.MethodGet, "/api/v1/compliance-engine/reevaluation", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
		}
		sv.assertConforms(t, "ReevaluationState", w.Body.Bytes())
	})
}

func TestContract_ReevaluateAccepted(t *testing.T) {
	sv := loadSpec(t)
	tenant, user := uuid.New(), uuid.New()
	cd := &stubCooldown{state: allowedState(), claimed: true}
	enq := &spyEnqueuer{}
	e := newReevaluationEngine(cd, enq, tenant, user)

	w := do(e, http.MethodPost, "/api/v1/compliance-engine/reevaluate", nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d: %s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ReevaluationAccepted", w.Body.Bytes())
	if enq.calls != 1 {
		t.Fatalf("want exactly one reconcile enqueued, got %d", enq.calls)
	}
	// The reconcile must be for the CONTEXT tenant. A caller-supplied tenant on a
	// tenant route is a cross-tenant hole; there is no parameter to supply one, and
	// this pins that the handler reads the session.
	if enq.tenants[0] != tenant {
		t.Fatalf("enqueued tenant %s, want the session tenant %s", enq.tenants[0], tenant)
	}
	if cd.claimedTenant != tenant || cd.claimedUser != user {
		t.Fatalf("claim used tenant=%s user=%s, want %s/%s", cd.claimedTenant, cd.claimedUser, tenant, user)
	}
}

func TestContract_ReevaluateBlockedByCooldown(t *testing.T) {
	sv := loadSpec(t)
	cd := &stubCooldown{state: blockedState(), claimed: false}
	enq := &spyEnqueuer{}
	e := newReevaluationEngine(cd, enq, uuid.New(), uuid.New())

	w := do(e, http.MethodPost, "/api/v1/compliance-engine/reevaluate", nil)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d: %s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ReevaluationBlocked", w.Body.Bytes())
	// The whole point: a blocked request must not have run anything.
	if enq.calls != 0 {
		t.Fatalf("blocked request enqueued %d reconciles, want 0", enq.calls)
	}
	if ra := w.Header().Get("Retry-After"); ra == "" || ra == "0" {
		t.Fatalf("Retry-After should be a positive number of seconds, got %q", ra)
	}
}

// A missing enqueuer must answer 503 WITHOUT consuming the cooldown: burning an
// hour on a request that could never have run is the "success while doing nothing"
// shape this endpoint exists to avoid.
func TestContract_ReevaluateWithoutTransportDoesNotConsumeCooldown(t *testing.T) {
	cd := &stubCooldown{state: allowedState(), claimed: true}
	e := newReevaluationEngine(cd, nil, uuid.New(), uuid.New())

	w := do(e, http.MethodPost, "/api/v1/compliance-engine/reevaluate", nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d: %s", w.Code, w.Body.String())
	}
	if cd.claimCalls != 0 {
		t.Fatalf("cooldown was consumed %d times with no transport, want 0", cd.claimCalls)
	}
}

// NewReevaluationHandler must store a nil *ReconcileEnqueuer as a nil INTERFACE.
// A typed nil in an interface is non-nil, which would make the 503 guard above
// silently stop guarding — we would answer 202 and enqueue into nothing.
func TestReevaluationHandler_NilEnqueuerStaysNil(t *testing.T) {
	h := NewReevaluationHandler(nil, nil)
	if h.enqueuer != nil {
		t.Fatalf("nil *ReconcileEnqueuer must be stored as a nil interface, got %#v", h.enqueuer)
	}
}

// The platform-admin route is deliberately NOT rate-limited (owner decision): it is
// the escape hatch after an engine fix or a bulk import. Driving the REAL admin
// handler three times in a row must give three 202s — no 429, ever. Pinned on the
// route itself so "let's rate-limit everything" cannot land quietly.
func TestContract_AdminReevaluateIsNotRateLimited(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	// The admin handler takes the concrete enqueuer; a nil NATS client makes
	// publish a no-op, which is all this needs — what is under test is the
	// ABSENCE of a limiter, not delivery.
	h := NewAdminReconcileHandler(services.NewReconcileEnqueuer(nil, nil))
	r.POST("/api/v1/compliance-engine/admin/tenants/:tenantId/reevaluate", h.ReevaluateTenant)

	tenant := uuid.New().String()
	for i := 1; i <= 3; i++ {
		w := do(r, http.MethodPost, "/api/v1/compliance-engine/admin/tenants/"+tenant+"/reevaluate", nil)
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("admin re-evaluation #%d was rate-limited (429) — the platform-admin exemption is gone", i)
		}
		if w.Code != http.StatusAccepted {
			t.Fatalf("admin re-evaluation #%d: want 202, got %d: %s", i, w.Code, w.Body.String())
		}
	}
}

// containsJSONNull reports whether the body has `"<field>":null` (whitespace-
// insensitive for the one space encoding/json never emits).
func containsJSONNull(body, field string) bool {
	return len(body) > 0 && (indexOf(body, `"`+field+`":null`) >= 0)
}

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
