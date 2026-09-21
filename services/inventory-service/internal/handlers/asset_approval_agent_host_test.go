package handlers

// The INTERNAL agent-host approval route, driven through a real gin engine.
//
// The thing worth pinning is the gate, both polarities: a request that the
// auth middleware did not mark as a verified internal call must be refused
// BEFORE the store is consulted, and one that was marked must reach the store
// with the ids it carried. Delete the IsInternalCall check in the handler and
// the first case goes red; that is the one that matters, because this route
// has no RBAC in front of it.

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

type recordingApprovalStore struct {
	stubApprovalStore
	calls    int
	tenantID uuid.UUID
	assetID  uuid.UUID
	agentID  uuid.UUID
	approved bool
	err      error
}

func (s *recordingApprovalStore) AutoApproveAgentHost(tenantID, assetID, agentID uuid.UUID) (bool, error) {
	s.calls++
	s.tenantID, s.assetID, s.agentID = tenantID, assetID, agentID
	return s.approved, s.err
}

func newAgentHostRouter(store *recordingApprovalStore, tenantID uuid.UUID, internal bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		// What shared/middleware sets for a verified internal call, and for an
		// ordinary tenant user: the tenant either way, the internal flag and
		// the "system" sentinel only for the former.
		c.Set("tenantID", tenantID)
		if internal {
			c.Set(sharedmw.CtxKeyIsInternalCall, true)
			c.Set(sharedmw.CtxKeyUserID, sharedmw.InternalUserIDSentinel)
		} else {
			c.Set("userID", uuid.New())
		}
		c.Next()
	})
	r.POST("/inventory-service/assets/auto-approve/agent-host", NewAssetApprovalHandler(store).AutoApproveAgentHost)
	return r
}

func postAgentHost(r *gin.Engine, body any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/inventory-service/assets/auto-approve/agent-host", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestAutoApproveAgentHost_RefusesNonInternalCalls(t *testing.T) {
	store := &recordingApprovalStore{approved: true}
	r := newAgentHostRouter(store, uuid.New(), false)
	w := postAgentHost(r, map[string]string{"asset_id": uuid.New().String(), "agent_id": uuid.New().String()})
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: a tenant user (even one with every permission) must not reach the agent-host approval", w.Code)
	}
	if store.calls != 0 {
		t.Fatalf("store consulted %d times before the internal-call gate", store.calls)
	}
}

func TestAutoApproveAgentHost_InternalCallReachesTheStore(t *testing.T) {
	tenant, asset, agent := uuid.New(), uuid.New(), uuid.New()
	store := &recordingApprovalStore{approved: true}
	r := newAgentHostRouter(store, tenant, true)
	w := postAgentHost(r, map[string]string{"asset_id": asset.String(), "agent_id": agent.String()})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if store.calls != 1 || store.tenantID != tenant || store.assetID != asset || store.agentID != agent {
		t.Fatalf("store got (%d calls, tenant %s, asset %s, agent %s)", store.calls, store.tenantID, store.assetID, store.agentID)
	}
	var out struct {
		Approved bool   `json:"approved"`
		AssetID  string `json:"asset_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || !out.Approved || out.AssetID != asset.String() {
		t.Fatalf("body = %s (err %v)", w.Body.String(), err)
	}
}

func TestAutoApproveAgentHost_NotApprovedIsAnAnswerNotAFailure(t *testing.T) {
	// The host was denied, or already monitoring: the store says false and the
	// route says 200 + approved:false. An agent reporting on a schedule must
	// not read that as a transport failure worth retrying immediately.
	store := &recordingApprovalStore{approved: false}
	r := newAgentHostRouter(store, uuid.New(), true)
	w := postAgentHost(r, map[string]string{"asset_id": uuid.New().String(), "agent_id": uuid.New().String()})
	if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(`"approved":false`)) {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
}

func TestAutoApproveAgentHost_BadIDsAre400(t *testing.T) {
	store := &recordingApprovalStore{approved: true}
	r := newAgentHostRouter(store, uuid.New(), true)
	for name, body := range map[string]map[string]string{
		"missing agent": {"asset_id": uuid.New().String()},
		"nil asset":     {"asset_id": uuid.Nil.String(), "agent_id": uuid.New().String()},
		"garbage":       {"asset_id": "not-a-uuid", "agent_id": uuid.New().String()},
	} {
		if w := postAgentHost(r, body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, w.Code)
		}
	}
	if store.calls != 0 {
		t.Fatalf("store consulted for malformed input")
	}
}

func TestAutoApproveAgentHost_StoreErrorIs500(t *testing.T) {
	store := &recordingApprovalStore{err: errors.New("db down")}
	r := newAgentHostRouter(store, uuid.New(), true)
	w := postAgentHost(r, map[string]string{"asset_id": uuid.New().String(), "agent_id": uuid.New().String()})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}
