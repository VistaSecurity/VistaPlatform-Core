package api

// Contract tests for the My Profile sessions + connections surface:
//   GET    /auth/sessions                       (list active sessions)
//   DELETE /auth/sessions/{id}                  (revoke a session)
//   GET    /auth/connections                    (list linked auth methods)
//   PUT    /auth/connections/{id}/primary       (set primary)
//
// loadSpec / assertConforms / do are shared with cross_cutter_contract_test.go
// (same package), as is the stubAuthServiceStore the session/connection
// handlers drive.
//
// DELETE /auth/sso/unlink used to be asserted here too. It moved to
// ee/sso/unlink_contract_test.go with SSOUnlink itself — unlinking a federated
// identity is Enterprise, and Core has no such route to test.

import (
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/models"
)

// newProfileEngine mounts the profile session/connection routes on
// /api/v1/auth-service with the same string-typed userID context the
// RequireAuth middleware sets in production.
func newProfileEngine(as *stubAuthServiceStore, authenticated bool, userID string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if as == nil {
		as = &stubAuthServiceStore{}
	}
	grp := r.Group("/api/v1/auth-service")
	grp.Use(func(c *gin.Context) {
		if authenticated {
			c.Set("userID", userID)
		}
		c.Next()
	})
	authHandlers := &AuthHandlers{authService: as}
	grp.GET("/auth/sessions", authHandlers.ListSessions)
	grp.DELETE("/auth/sessions/:id", authHandlers.RevokeSession)
	grp.GET("/auth/connections", authHandlers.ListConnections)
	grp.PUT("/auth/connections/:id/primary", authHandlers.SetPrimaryAuth)
	return r
}

func sampleSession() models.Session {
	now := time.Now().UTC()
	ip := "203.0.113.7"
	ua := "Mozilla/5.0"
	return models.Session{
		ID:            uuid.New(),
		UserID:        uuid.New(),
		FamilyID:      uuid.New(),
		ExpiresAt:     now.Add(24 * time.Hour),
		LastUsedAt:    now,
		IsRevoked:     false,
		CreatedFromIP: &ip,
		UserAgent:     &ua,
		CreatedAt:     now,
		RevokedAt:     nil,
	}
}

func sampleConnection() models.Connection {
	now := time.Now().UTC()
	pid := uuid.New()
	ext := "ext-123"
	email := "user@example.com"
	return models.Connection{
		ID:             uuid.New(),
		UserID:         uuid.New(),
		AuthType:       "sso",
		SSOProviderID:  &pid,
		ExternalUserID: &ext,
		ExternalEmail:  &email,
		IsPrimary:      true,
		LastUsedAt:     &now,
		Metadata:       map[string]interface{}{"provider": "okta"},
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

const profileUserID = "11111111-1111-1111-1111-111111111111"

// --- GET /auth/sessions -----------------------------------------------------

func TestContract_ListSessions_200(t *testing.T) {
	sv := loadSpec(t)
	s := sampleSession()
	eng := newProfileEngine(&stubAuthServiceStore{sessions: []models.Session{s}}, true, profileUserID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/auth/sessions", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SessionsResponse", w.Body.Bytes())
}

// Empty -> sessions is null (not []), still conforms.
func TestContract_ListSessions_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := newProfileEngine(&stubAuthServiceStore{}, true, profileUserID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/auth/sessions", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SessionsResponse", w.Body.Bytes())
}

func TestContract_ListSessions_401(t *testing.T) {
	sv := loadSpec(t)
	eng := newProfileEngine(&stubAuthServiceStore{}, false, profileUserID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/auth/sessions", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_ListSessions_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newProfileEngine(&stubAuthServiceStore{sessionsErr: auth.ErrUserNotFound}, true, profileUserID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/auth/sessions", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- DELETE /auth/sessions/{id} ---------------------------------------------

func TestContract_RevokeSession_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newProfileEngine(&stubAuthServiceStore{}, true, profileUserID)
	w := do(eng, http.MethodDelete, "/api/v1/auth-service/auth/sessions/"+uuid.New().String(), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_RevokeSession_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newProfileEngine(&stubAuthServiceStore{}, true, profileUserID)
	w := do(eng, http.MethodDelete, "/api/v1/auth-service/auth/sessions/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_RevokeSession_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newProfileEngine(&stubAuthServiceStore{revokeErr: auth.ErrUserNotFound}, true, profileUserID)
	w := do(eng, http.MethodDelete, "/api/v1/auth-service/auth/sessions/"+uuid.New().String(), nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- GET /auth/connections --------------------------------------------------

func TestContract_ListConnections_200(t *testing.T) {
	sv := loadSpec(t)
	c := sampleConnection()
	eng := newProfileEngine(&stubAuthServiceStore{connections: []models.Connection{c}}, true, profileUserID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/auth/connections", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "ConnectionsResponse", w.Body.Bytes())
}

func TestContract_ListConnections_401(t *testing.T) {
	sv := loadSpec(t)
	eng := newProfileEngine(&stubAuthServiceStore{}, false, profileUserID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/auth/connections", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- PUT /auth/connections/{id}/primary -------------------------------------

func TestContract_SetPrimaryConnection_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newProfileEngine(&stubAuthServiceStore{}, true, profileUserID)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/auth/connections/"+uuid.New().String()+"/primary", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_SetPrimaryConnection_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newProfileEngine(&stubAuthServiceStore{}, true, profileUserID)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/auth/connections/not-a-uuid/primary", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_SetPrimaryConnection_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newProfileEngine(&stubAuthServiceStore{setPrimaryErr: auth.ErrUserNotFound}, true, profileUserID)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/auth/connections/"+uuid.New().String()+"/primary", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
