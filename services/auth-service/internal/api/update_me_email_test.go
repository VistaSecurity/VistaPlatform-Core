package api

// SECURITY: PUT /auth/me must not let a bare access token rewrite the account's
// sign-in email. Forgot-password mails a reset link to the address on the row,
// so changing it -- with no current password and no confirmation to the new
// mailbox -- is a one-request account takeover for anyone holding the session
// (an unattended browser, a proxied XSS request, a narrowly-scoped token).
//
// Drives the real handler through gin with the package's stub store, and
// records what reaches UpdateUser so "refused" cannot pass for "ran and the
// stub ignored it".

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/auth-service/internal/models"
)

type recordingUpdateStore struct {
	stubAuthServiceStore
	updates []models.UpdateUserRequest
}

func (s *recordingUpdateStore) UpdateUser(_ uuid.UUID, req *models.UpdateUserRequest) (*models.User, error) {
	s.updates = append(s.updates, *req)
	return s.userResult, nil
}

// updateMeEngine mounts PUT /auth/me the way router.go does, behind a stand-in
// for RequireAuth that sets the caller as the production middleware does.
func updateMeEngine(store authServiceStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &AuthHandlers{authService: store}
	g := r.Group("/api/v1/auth-service")
	g.Use(func(c *gin.Context) {
		c.Set("userID", aUserID)
		c.Set("tenantID", aTenantID)
		c.Next()
	})
	g.PUT("/auth/me", h.UpdateMe)
	return r
}

func TestUpdateMe_RefusesEmailChange(t *testing.T) {
	uid, tid := uuid.MustParse(aUserID), uuid.MustParse(aTenantID)
	store := &recordingUpdateStore{stubAuthServiceStore: stubAuthServiceStore{userResult: sampleUser(uid, tid)}}
	eng := updateMeEngine(store)

	w := do(eng, http.MethodPut, "/api/v1/auth-service/auth/me", strings.NewReader(`{"email":"attacker@evil.example"}`))
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "email_change_not_supported") {
		t.Fatalf("email change = %d %s; want 403 email_change_not_supported", w.Code, w.Body.String())
	}
	if len(store.updates) != 0 {
		t.Fatalf("UpdateUser ran %d time(s) for a refused email change", len(store.updates))
	}

	// A differently-cased DIFFERENT address, bundled with a legitimate name edit, is still a change.
	w = do(eng, http.MethodPut, "/api/v1/auth-service/auth/me", strings.NewReader(`{"first_name":"X","email":"OTHER@Example.com"}`))
	if w.Code != http.StatusForbidden || len(store.updates) != 0 {
		t.Fatalf("email change bundled with a name edit = %d (updates=%d); want 403 and no update", w.Code, len(store.updates))
	}
}

func TestUpdateMe_StillEditsProfileAndAcceptsUnchangedEmail(t *testing.T) {
	uid, tid := uuid.MustParse(aUserID), uuid.MustParse(aTenantID)
	u := sampleUser(uid, tid)
	store := &recordingUpdateStore{stubAuthServiceStore: stubAuthServiceStore{userResult: u}}
	eng := updateMeEngine(store)

	// Name/timezone only: what My Profile -> Personal sends.
	w := do(eng, http.MethodPut, "/api/v1/auth-service/auth/me", strings.NewReader(`{"first_name":"Renamed","timezone":"UTC"}`))
	if w.Code != http.StatusOK || len(store.updates) != 1 {
		t.Fatalf("profile edit = %d %s (updates=%d); want 200 and one update", w.Code, w.Body.String(), len(store.updates))
	}

	// A client echoing the current address back (any case) is not a change.
	w = do(eng, http.MethodPut, "/api/v1/auth-service/auth/me", strings.NewReader(`{"first_name":"Again","email":"USER@example.com"}`))
	if w.Code != http.StatusOK || len(store.updates) != 2 {
		t.Fatalf("echoed email = %d %s (updates=%d); want 200", w.Code, w.Body.String(), len(store.updates))
	}
	if store.updates[1].Email != nil {
		t.Fatalf("unchanged email was forwarded to UpdateUser as %q; it must be dropped", *store.updates[1].Email)
	}
}
