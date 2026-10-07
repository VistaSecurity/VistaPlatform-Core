package handlers

// D8 (pentest-readiness review): platform-admin deactivate, delete and
// admin-initiated set-password revoked none of the user's refresh tokens.
//
// These drive the real handlers (the *WithStore constructors the routes wrap)
// over httptest. The route-to-handler wiring in server.go, and the effect on real
// platform_refresh_tokens rows, are proven through the real router in
// internal/api (TestIntegration_PlatformUserLifecycle_EndsSessions_RealRouter).

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type recordingSessionRevoker struct {
	mu      sync.Mutex
	revoked []uuid.UUID
	err     error
}

func (r *recordingSessionRevoker) RevokeAllUserTokens(id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked = append(r.revoked, id)
	return r.err
}

func (r *recordingSessionRevoker) calls() []uuid.UUID {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]uuid.UUID(nil), r.revoked...)
}

// userOpEngine mounts the three handlers under test over the contract stubs and
// returns the target's id (a user the stub caller outranks).
func userOpEngine(t *testing.T, store *stubPlatformUserStore, rev *recordingSessionRevoker) (*gin.Engine, uuid.UUID) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	target := uuid.New()
	store.user = samplePlatformUser()
	store.userFound = true
	store.roleExists = true
	r := gin.New()
	grp := r.Group("/users")
	grp.Use(func(c *gin.Context) { c.Set("userID", stubCallerID); c.Next() })
	grp.PUT("/:id", updatePlatformUserWithStore(store, rev))
	grp.DELETE("/:id", deletePlatformUserWithStore(store, rev))
	grp.PUT("/:id/set-password", adminSetPasswordWithStore(store, stubPasswordHasher{}, rev))
	return r, target
}

func doUserOp(r *gin.Engine, method, id, suffix, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/users/"+id+suffix, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestPlatformUserDeactivate_EndsTheUsersSessions(t *testing.T) {
	rev := &recordingSessionRevoker{}
	r, target := userOpEngine(t, &stubPlatformUserStore{}, rev)

	// Only an explicit deactivation revokes: an edit that leaves the user active,
	// or reactivates them, must not sign them out.
	for _, body := range []string{`{"first_name":"Renamed"}`, `{"is_active":true}`} {
		if w := doUserOp(r, http.MethodPut, target.String(), "", body); w.Code != http.StatusOK {
			t.Fatalf("%s => %d %s", body, w.Code, w.Body.String())
		}
	}
	if got := rev.calls(); len(got) != 0 {
		t.Fatalf("a non-deactivating edit revoked sessions: %v", got)
	}

	if w := doUserOp(r, http.MethodPut, target.String(), "", `{"is_active":false}`); w.Code != http.StatusOK {
		t.Fatalf("deactivate => %d %s", w.Code, w.Body.String())
	}
	if got := rev.calls(); len(got) != 1 || got[0] != target {
		t.Fatalf("deactivation revoked %v; want exactly the target %s", got, target)
	}
}

func TestPlatformUserDelete_EndsTheUsersSessions(t *testing.T) {
	rev := &recordingSessionRevoker{}
	r, target := userOpEngine(t, &stubPlatformUserStore{}, rev)
	if w := doUserOp(r, http.MethodDelete, target.String(), "", ``); w.Code != http.StatusOK {
		t.Fatalf("delete => %d %s", w.Code, w.Body.String())
	}
	if got := rev.calls(); len(got) != 1 || got[0] != target {
		t.Fatalf("deletion revoked %v; want exactly the target %s", got, target)
	}
}

func TestPlatformUserDelete_RefusedDeleteRevokesNothing(t *testing.T) {
	rev := &recordingSessionRevoker{}
	r, target := userOpEngine(t, &stubPlatformUserStore{deleteErr: errors.New("db down")}, rev)
	if w := doUserOp(r, http.MethodDelete, target.String(), "", ``); w.Code != http.StatusInternalServerError {
		t.Fatalf("failed delete => %d; want 500", w.Code)
	}
	if got := rev.calls(); len(got) != 0 {
		t.Fatalf("a delete that did not happen still revoked sessions: %v", got)
	}
}

func TestAdminSetPassword_EndsTheUsersSessions(t *testing.T) {
	rev := &recordingSessionRevoker{}
	r, target := userOpEngine(t, &stubPlatformUserStore{}, rev)
	w := doUserOp(r, http.MethodPut, target.String(), "/set-password", `{"new_password":"Brand-New-Passw0rd!2026"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("set-password => %d %s", w.Code, w.Body.String())
	}
	if got := rev.calls(); len(got) != 1 || got[0] != target {
		t.Fatalf("set-password revoked %v; want exactly the target %s", got, target)
	}
}

func TestAdminSetPassword_FailureToEndSessionsIsNotSwallowed(t *testing.T) {
	rev := &recordingSessionRevoker{err: errors.New("db down")}
	r, target := userOpEngine(t, &stubPlatformUserStore{}, rev)
	w := doUserOp(r, http.MethodPut, target.String(), "/set-password", `{"new_password":"Brand-New-Passw0rd!2026"}`)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "sessions could not be ended") {
		t.Fatalf("set-password with a failing revoke => %d %s; want a 500 that says the sessions could not be ended", w.Code, w.Body.String())
	}
}

func TestAdminSetPassword_WeakPasswordRevokesNothing(t *testing.T) {
	rev := &recordingSessionRevoker{}
	r, target := userOpEngine(t, &stubPlatformUserStore{}, rev)
	if w := doUserOp(r, http.MethodPut, target.String(), "/set-password", `{"new_password":"short"}`); w.Code == http.StatusOK {
		t.Fatalf("a weak password was accepted: %d", w.Code)
	}
	if got := rev.calls(); len(got) != 0 {
		t.Fatalf("a refused password change revoked sessions: %v", got)
	}
}
