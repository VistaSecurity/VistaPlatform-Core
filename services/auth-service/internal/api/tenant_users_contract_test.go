package api

// Contract test for the tenant-users surface (Settings → Users). Extends the
// auth-service spec-first contract (ADR-0001) and reuses the shared harness
// (loadSpec / assertConforms / do / aTenantID) from cross_cutter_contract_test.go.
//
// ListTenantUsers was refactored to depend on the tenantUsersStore interface
// (via ListTenantUsersWithStore), so it's driven with an in-memory stub — no
// database. InviteTenantMember is heavily auth/email/db-coupled on its 201 path;
// its request-validation paths (400 / 401 / 403) return before any dependency is
// touched, so they're contract-tested by calling it with nil deps.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const bTenantID = "33333333-3333-3333-3333-333333333333"

type stubTenantUsersStore struct {
	users []TenantUser
	err   error
}

func (s *stubTenantUsersStore) ListTenantUsers(_ context.Context, _ uuid.UUID) ([]TenantUser, error) {
	return s.users, s.err
}

func newTenantUsersEngine(store tenantUsersStore, authenticated bool, ctxTenantID string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if store == nil {
		store = &stubTenantUsersStore{}
	}
	grp := r.Group("/api/v1/auth-service")
	grp.Use(func(c *gin.Context) {
		if authenticated {
			c.Set("tenantID", ctxTenantID)
		}
		c.Next()
	})
	grp.GET("/tenant/:tenantId/users", ListTenantUsersWithStore(store))
	// Validation paths only — nil deps are never reached before the 400/401/403 returns.
	grp.POST("/tenant/:tenantId/users/invite", InviteTenantMember(nil, nil, nil, nil))
	return r
}

func sampleTenantUser() TenantUser {
	return TenantUser{
		ID:            uuid.New(),
		TenantID:      uuid.MustParse(aTenantID),
		Email:         "user@example.com",
		FirstName:     "Test",
		LastName:      "User",
		Role:          "viewer",
		Roles:         []string{"viewer"},
		IsActive:      true,
		EmailVerified: true,
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
		AuthMethods:   []string{"password"},
	}
}

// --- GET /tenant/{tenantId}/users -------------------------------------------

func TestContract_ListTenantUsers_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newTenantUsersEngine(&stubTenantUsersStore{users: []TenantUser{sampleTenantUser()}}, true, aTenantID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/"+aTenantID+"/users", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TenantUsersResponse", w.Body.Bytes())
}

// No members -> users serializes as null (nullable array).
func TestContract_ListTenantUsers_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := newTenantUsersEngine(&stubTenantUsersStore{}, true, aTenantID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/"+aTenantID+"/users", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TenantUsersResponse", w.Body.Bytes())
}

func TestContract_ListTenantUsers_400_badPathID(t *testing.T) {
	sv := loadSpec(t)
	eng := newTenantUsersEngine(&stubTenantUsersStore{}, true, aTenantID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/not-a-uuid/users", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_ListTenantUsers_401(t *testing.T) {
	sv := loadSpec(t)
	eng := newTenantUsersEngine(&stubTenantUsersStore{}, false, aTenantID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/"+aTenantID+"/users", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Token tenant != path tenant -> 403.
func TestContract_ListTenantUsers_403(t *testing.T) {
	sv := loadSpec(t)
	eng := newTenantUsersEngine(&stubTenantUsersStore{}, true, aTenantID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/"+bTenantID+"/users", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_ListTenantUsers_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newTenantUsersEngine(&stubTenantUsersStore{err: errors.New("db down")}, true, aTenantID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/"+aTenantID+"/users", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- POST /tenant/{tenantId}/users/invite (validation paths) ----------------

func TestContract_InviteTenantMember_400_badPathID(t *testing.T) {
	sv := loadSpec(t)
	eng := newTenantUsersEngine(&stubTenantUsersStore{}, true, aTenantID)
	body := strings.NewReader(`{"email":"new@example.com","role":"viewer"}`)
	w := do(eng, http.MethodPost, "/api/v1/auth-service/tenant/not-a-uuid/users/invite", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_InviteTenantMember_401(t *testing.T) {
	sv := loadSpec(t)
	eng := newTenantUsersEngine(&stubTenantUsersStore{}, false, aTenantID)
	body := strings.NewReader(`{"email":"new@example.com","role":"viewer"}`)
	w := do(eng, http.MethodPost, "/api/v1/auth-service/tenant/"+aTenantID+"/users/invite", body)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_InviteTenantMember_403(t *testing.T) {
	sv := loadSpec(t)
	eng := newTenantUsersEngine(&stubTenantUsersStore{}, true, aTenantID)
	body := strings.NewReader(`{"email":"new@example.com","role":"viewer"}`)
	w := do(eng, http.MethodPost, "/api/v1/auth-service/tenant/"+bTenantID+"/users/invite", body)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_InviteTenantMember_400_badBody(t *testing.T) {
	sv := loadSpec(t)
	eng := newTenantUsersEngine(&stubTenantUsersStore{}, true, aTenantID)
	w := do(eng, http.MethodPost, "/api/v1/auth-service/tenant/"+aTenantID+"/users/invite", strings.NewReader(`{`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// A well-formed body with an unsupported role -> 400 (returns before auth deps).
func TestContract_InviteTenantMember_400_invalidRole(t *testing.T) {
	sv := loadSpec(t)
	eng := newTenantUsersEngine(&stubTenantUsersStore{}, true, aTenantID)
	body := strings.NewReader(`{"email":"new@example.com","role":"emperor"}`)
	w := do(eng, http.MethodPost, "/api/v1/auth-service/tenant/"+aTenantID+"/users/invite", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
