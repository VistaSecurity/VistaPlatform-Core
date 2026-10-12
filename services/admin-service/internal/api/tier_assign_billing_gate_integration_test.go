package api

// Assigning a plan to a tenant, and previewing a tier migration, are
// tenant-lifecycle/billing actions: they sit behind platform.billing, while
// authoring the catalogue (create / edit / deprecate a tier, entitlements) and
// reading tiers stay behind platform.settings. Drives the REAL router with
// permissions resolved from the database, so moving either route back under the
// settings group fails here.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/models"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const tierAssignGateSigningKey = "tier-assign-billing-gate-integration-not-a-real-key"

func TestIntegration_TierAssignAndImpact_AreBillingGated_RealRouter(t *testing.T) {
	db := testdb.ScratchDatabase(t)
	t.Setenv("AUDIT_LOGGING_ENABLED", "false")
	srv := NewServerWithConnections(&config.Config{Environment: "test", JWTSecret: tierAssignGateSigningKey}, db, db, EditionHooks{})
	router := srv.Router()

	billingOnly := testdb.NewPlatformUser(t, db, testdb.NewPlatformRole(t, db, rbac.PermissionPlatformBilling))
	settingsOnly := testdb.NewPlatformUser(t, db, testdb.NewPlatformRole(t, db, rbac.PermissionPlatformSettings))

	token := func(user uuid.UUID) string {
		signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, models.JWTClaims{
			UserID: user, Email: "gate@example.test", Role: "super_admin", Type: "access", // role claim is free; permissions come from the DB
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
		}).SignedString([]byte(tierAssignGateSigningKey))
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	tierID := uuid.NewString()
	// refused reports whether the permission gate itself answered.
	refused := func(user uuid.UUID, method, path string) (bool, string) {
		req := httptest.NewRequest(method, "/api/v1/admin-service/admin/tiers"+path, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+token(user))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), "Insufficient permissions"), w.Body.String()
	}

	for _, rt := range []struct{ method, path string }{
		{http.MethodPost, "/" + tierID + "/assign"},
		{http.MethodGet, "/" + tierID + "/impact-analysis"},
	} {
		if r, body := refused(billingOnly, rt.method, rt.path); r {
			t.Errorf("%s %s with platform.billing alone was refused by the gate: %s", rt.method, rt.path, body)
		}
		if r, body := refused(settingsOnly, rt.method, rt.path); !r {
			t.Errorf("%s %s with platform.settings alone must be refused (403 Insufficient permissions), got: %s", rt.method, rt.path, body)
		}
	}

	// Catalogue authoring is unchanged: settings holds it, billing does not.
	for _, rt := range []struct{ method, path string }{
		{http.MethodPost, ""},
		{http.MethodPut, "/" + tierID},
		{http.MethodDelete, "/" + tierID},
		{http.MethodGet, ""},
		{http.MethodPut, "/" + tierID + "/entitlements"},
	} {
		if r, body := refused(billingOnly, rt.method, rt.path); !r {
			t.Errorf("%s /tiers%s with platform.billing alone must be refused, got: %s", rt.method, rt.path, body)
		}
		if r, body := refused(settingsOnly, rt.method, rt.path); r {
			t.Errorf("%s /tiers%s with platform.settings was refused by the gate: %s", rt.method, rt.path, body)
		}
	}
}
