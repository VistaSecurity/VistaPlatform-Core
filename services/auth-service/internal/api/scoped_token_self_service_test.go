package api

// -- routes that carry RequireAuth but no permission string have nothing
// to intersect a PAT's scopes with, so a read-only token could drive them in
// full (change the owner's password, profile, sessions, consents...). Every
// self-service account route refuses scoped tokens, the same refusal
// /api-tokens has; read-only self info stays open (mcp-service needs GET
// /auth/me). These tests drive the REAL SetupRouter, so deleting the gate from
// router.go turns them red.

import (
	"net/http"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// enumUserRows is one active tenant user as GetUserByID scans it.
func enumUserRows(id, tenantID uuid.UUID) *sqlmock.Rows {
	now := time.Now()
	return sqlmock.NewRows(enumUserColumns).AddRow(
		id, tenantID, "pat@example.test", nil, "P", "Q",
		true, true, nil, nil, nil, nil, now, now, nil)
}

const scopedRefusal = "Not available to API tokens"

// selfServiceRoutes is the classification: every RequireAuth-only route that
// changes the caller's own account (or exports their data). Keep in step with
// the rejectScoped uses in router.go.
var selfServiceRoutes = []struct{ method, path string }{
	{http.MethodPost, "/auth/logout"},
	{http.MethodPut, "/auth/me"},
	{http.MethodPost, "/auth/change-password"},
	{http.MethodPut, "/auth/me/preferences/notifications"},
	{http.MethodPost, "/auth/users/me/eula"},
	{http.MethodPost, "/auth/legal/accept"},
	{http.MethodPost, "/auth/select-tier"},
	{http.MethodPost, "/auth/onboarding/progress"},
	{http.MethodDelete, "/auth/sessions/" + "00000000-0000-0000-0000-000000000001"},
	{http.MethodPut, "/auth/connections/00000000-0000-0000-0000-000000000001/primary"},
	{http.MethodPost, "/auth/upload-avatar"},
	{http.MethodGet, "/me/data-export"},
	{http.MethodPost, "/onboarding/steps/x/complete"},
	{http.MethodPost, "/onboarding/steps/x/skip"},
	{http.MethodPost, "/onboarding/dismiss"},
}

// readOnlySelfRoutes stay open to scoped tokens.
var readOnlySelfRoutes = []struct{ method, path string }{
	{http.MethodGet, "/auth/me/preferences/notifications"},
	{http.MethodGet, "/auth/legal/pending"},
	{http.MethodGet, "/auth/onboarding/status"},
	{http.MethodGet, "/auth/sessions"},
	{http.MethodGet, "/auth/connections"},
	{http.MethodGet, "/user/permissions"},
}

func TestScopedTokenRefusedOnSelfServiceAccountRoutes(t *testing.T) {
	userID, tenantID := uuid.New(), uuid.New()
	for _, rt := range selfServiceRoutes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			db, mock := newGatesDB(t)
			expectLiveTenantState(mock, tenantID)
			r := gatesRouter(t, db, nil)
			w := serve(r, bearer(rt.method, gatesBase+rt.path, gatesTenantToken(t, userID, tenantID, []string{"inventory.read"}), `{}`))
			if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), scopedRefusal) {
				t.Fatalf("scoped token => %d %s, want 403 %q", w.Code, w.Body.String(), scopedRefusal)
			}
		})
	}
}

// The other polarity: an ordinary (unscoped) session is NOT refused by the
// gate, so a gate that refused everyone would not pass for a fix.
func TestUnscopedTokenIsNotRefusedBySelfServiceGate(t *testing.T) {
	userID, tenantID := uuid.New(), uuid.New()
	for _, rt := range selfServiceRoutes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			db, mock := newGatesDB(t)
			expectLiveTenantState(mock, tenantID)
			r := gatesRouter(t, db, nil)
			w := serve(r, bearer(rt.method, gatesBase+rt.path, gatesTenantToken(t, userID, tenantID, nil), `{}`))
			if strings.Contains(w.Body.String(), scopedRefusal) {
				t.Fatalf("an unscoped session was refused as an API token: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestScopedTokenCanReadSelf(t *testing.T) {
	userID, tenantID := uuid.New(), uuid.New()

	t.Run("GET /auth/me => 200", func(t *testing.T) {
		db, mock := newGatesDB(t)
		expectLiveTenantState(mock, tenantID)
		mock.ExpectQuery(`FROM users\s+WHERE id = \$1 AND deleted_at IS NULL`).
			WithArgs(userID).
			WillReturnRows(enumUserRows(userID, tenantID))
		r := gatesRouter(t, db, nil)
		w := serve(r, bearer(http.MethodGet, gatesBase+"/auth/me", gatesTenantToken(t, userID, tenantID, []string{"inventory.read"}), ""))
		if w.Code != http.StatusOK {
			t.Fatalf("GET /auth/me with a scoped token => %d %s, want 200 (mcp-service reads it)", w.Code, w.Body.String())
		}
	})

	for _, rt := range readOnlySelfRoutes {
		t.Run(rt.method+" "+rt.path+" is not gated", func(t *testing.T) {
			db, mock := newGatesDB(t)
			expectLiveTenantState(mock, tenantID)
			r := gatesRouter(t, db, nil)
			w := serve(r, bearer(rt.method, gatesBase+rt.path, gatesTenantToken(t, userID, tenantID, []string{"inventory.read"}), ""))
			if strings.Contains(w.Body.String(), scopedRefusal) {
				t.Fatalf("read-only self route refused a scoped token: %d %s", w.Code, w.Body.String())
			}
		})
	}
}
