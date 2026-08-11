package api

// Handler tests for the tenant-scoped member mutations (Settings → Users:
// remove member / activate-deactivate member). These cover the request- and
// access-validation paths that return BEFORE any *sql.DB dependency is touched,
// so they run with nil db — the same technique the InviteTenantMember validation
// tests use. (The 200/db paths are exercised by integration tests, not here.)

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// newTenantMutationEngine wires the two mutation routes with nil db. The
// validation paths never reach the db, so nil is safe.
func newTenantMutationEngine(authenticated bool, ctxTenantID string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/auth-service")
	grp.Use(func(c *gin.Context) {
		if authenticated {
			c.Set("tenantID", ctxTenantID)
			c.Set("userID", aUserID)
		}
		c.Next()
	})
	grp.DELETE("/tenant/:tenantId/users/:userId", DeleteTenantMember(nil))
	grp.PUT("/tenant/:tenantId/users/:userId/status", UpdateTenantMemberStatus(nil))
	return r
}

const aTargetUserID = "44444444-4444-4444-4444-444444444444"

// --- DELETE /tenant/{tenantId}/users/{userId} -------------------------------

func TestDeleteTenantMember_400_badTenantID(t *testing.T) {
	eng := newTenantMutationEngine(true, aTenantID)
	w := do(eng, http.MethodDelete, "/api/v1/auth-service/tenant/not-a-uuid/users/"+aTargetUserID, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestDeleteTenantMember_400_badUserID(t *testing.T) {
	eng := newTenantMutationEngine(true, aTenantID)
	w := do(eng, http.MethodDelete, "/api/v1/auth-service/tenant/"+aTenantID+"/users/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestDeleteTenantMember_401(t *testing.T) {
	eng := newTenantMutationEngine(false, aTenantID)
	w := do(eng, http.MethodDelete, "/api/v1/auth-service/tenant/"+aTenantID+"/users/"+aTargetUserID, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
}

// Token tenant != path tenant -> 403 (cross-tenant access denied).
func TestDeleteTenantMember_403(t *testing.T) {
	eng := newTenantMutationEngine(true, aTenantID)
	w := do(eng, http.MethodDelete, "/api/v1/auth-service/tenant/"+bTenantID+"/users/"+aTargetUserID, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// Deleting yourself -> 400 (returns before db).
func TestDeleteTenantMember_400_self(t *testing.T) {
	eng := newTenantMutationEngine(true, aTenantID)
	w := do(eng, http.MethodDelete, "/api/v1/auth-service/tenant/"+aTenantID+"/users/"+aUserID, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

// --- PUT /tenant/{tenantId}/users/{userId}/status ---------------------------

func TestUpdateTenantMemberStatus_400_badTenantID(t *testing.T) {
	eng := newTenantMutationEngine(true, aTenantID)
	body := strings.NewReader(`{"status":"active"}`)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/not-a-uuid/users/"+aTargetUserID+"/status", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestUpdateTenantMemberStatus_401(t *testing.T) {
	eng := newTenantMutationEngine(false, aTenantID)
	body := strings.NewReader(`{"status":"active"}`)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/"+aTenantID+"/users/"+aTargetUserID+"/status", body)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
}

func TestUpdateTenantMemberStatus_403(t *testing.T) {
	eng := newTenantMutationEngine(true, aTenantID)
	body := strings.NewReader(`{"status":"suspended"}`)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/"+bTenantID+"/users/"+aTargetUserID+"/status", body)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

func TestUpdateTenantMemberStatus_400_badBody(t *testing.T) {
	eng := newTenantMutationEngine(true, aTenantID)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/"+aTenantID+"/users/"+aTargetUserID+"/status", strings.NewReader(`{`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

// An unknown status value -> 400 (returns before db).
func TestUpdateTenantMemberStatus_400_invalidStatus(t *testing.T) {
	eng := newTenantMutationEngine(true, aTenantID)
	body := strings.NewReader(`{"status":"emperor"}`)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/"+aTenantID+"/users/"+aTargetUserID+"/status", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

// Deactivating yourself -> 400 (returns before db).
func TestUpdateTenantMemberStatus_400_selfDeactivate(t *testing.T) {
	eng := newTenantMutationEngine(true, aTenantID)
	body := strings.NewReader(`{"status":"suspended"}`)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/"+aTenantID+"/users/"+aUserID+"/status", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

// statusToIsActive maps the allowed set and rejects the rest.
func TestStatusToIsActive(t *testing.T) {
	cases := []struct {
		in        string
		wantAct12 bool
		wantValid bool
	}{
		{"active", true, true},
		{"inactive", false, true},
		{"suspended", false, true},
		{"emperor", false, false},
		{"", false, false},
	}
	for _, tc := range cases {
		gotActive, gotValid := statusToIsActive(tc.in)
		if gotActive != tc.wantAct12 || gotValid != tc.wantValid {
			t.Errorf("statusToIsActive(%q) = (%v,%v), want (%v,%v)", tc.in, gotActive, gotValid, tc.wantAct12, tc.wantValid)
		}
	}
}
