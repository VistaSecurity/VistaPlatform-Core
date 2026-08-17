package api

// — POST /auth/select-tier had neither an RBAC gate nor an entitlement
// check: any authenticated tenant user, viewer included, could move the tenant
// onto a higher tier for free.
//
// Two independent guards close it, and both are tested here:
//
//  1. WIRING — the route must carry middleware.RequirePermission(…,
//     "billing.update"). TestSelectTierRoute_* drives the REAL SetupRouter, so
//     deleting the middleware from router.go fails the test; a test that only
//     exercised the middleware in isolation would stay green through exactly
//     that deletion.
//  2. ENTITLEMENT — validateTenantTierSelection must refuse a paid tier the
//     tenant has no active subscription for, and must keep the free trial tier
//     selectable so onboarding is unaffected.

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
)

// selectTierRequest builds the real router over a sqlmock database, mints an
// access token for userID/tenantID, and POSTs a tier selection.
func selectTierRequest(t *testing.T, db *sql.DB, userID, tenantID, tierID uuid.UUID) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{JWTSecret: "test-secret-for-select-tier"}
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}) // never dialed on this path
	defer func() { _ = rdb.Close() }()

	router := SetupRouter(cfg, db, db, rdb, nil, EditionHooks{})

	jwtService := auth.NewJWTService(cfg.JWTSecret, time.Hour, time.Hour)
	access, _, err := jwtService.GenerateTokens(userID, tenantID, "member@example.test", "viewer")
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-service/auth/select-tier",
		strings.NewReader(`{"subscription_tier_id":"`+tierID.String()+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+access)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// expectPermissionCheck mocks RBACService.CheckPermission, which runs inside
// WithTenantTx (BEGIN / set_tenant_context / COUNT / COMMIT).
func expectPermissionCheck(mock sqlmock.Sqlmock, userID, tenantID uuid.UUID, granted bool) {
	mock.ExpectBegin()
	mock.ExpectExec(`set_tenant_context`).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`FROM tenant_permissions`).
		WithArgs(userID, tenantID, "billing.update").
		WillReturnRows(sqlmock.NewRows([]string{"has"}).AddRow(granted))
	mock.ExpectCommit()
}

// TestSelectTierRoute_403WhenCallerLacksBillingUpdate is the wiring proof: the
// request never reaches the handler (no user/tenant lookup is mocked, so the
// handler would error differently), and the refusal names the permission.
func TestSelectTierRoute_403WhenCallerLacksBillingUpdate(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	userID, tenantID, tierID := uuid.New(), uuid.New(), uuid.New()
	expectPermissionCheck(mock, userID, tenantID, false)

	w := selectTierRequest(t, db, userID, tenantID, tierID)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "billing.update") {
		t.Fatalf("403 body does not name the required permission: %s", w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations (the permission check did not run — is the middleware wired?): %v", err)
	}
}

// TestSelectTierRoute_PassesTheGateWhenPermissionHeld pins the other polarity:
// with billing.update held, the request reaches the handler and the handler's
// own queries run. Without this, a gate that refused everyone would look fine.
func TestSelectTierRoute_PassesTheGateWhenPermissionHeld(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	userID, tenantID, tierID := uuid.New(), uuid.New(), uuid.New()
	expectPermissionCheck(mock, userID, tenantID, true)
	// The handler's first query, on the bypass pool (same mock here).
	mock.ExpectQuery(`SELECT tenant_id FROM users WHERE id = \$1`).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))
	expectTierLookup(mock, tierID, "pro", 19900, false)
	expectEntitlementLookup(mock, tenantID, tierID, "pro", false)

	w := selectTierRequest(t, db, userID, tenantID, tierID)
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402 (gate passed, entitlement refused); body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// --- entitlement check ------------------------------------------------------

func expectTierLookup(mock sqlmock.Sqlmock, tierID uuid.UUID, name string, priceCents int64, isTrial bool) {
	mock.ExpectQuery(`SELECT name, COALESCE\(price_cents, 0\), COALESCE\(is_trial, false\)`).
		WithArgs(tierID).
		WillReturnRows(sqlmock.NewRows([]string{"name", "price_cents", "is_trial"}).AddRow(name, priceCents, isTrial))
}

func expectEntitlementLookup(mock sqlmock.Sqlmock, tenantID, tierID uuid.UUID, name string, entitled bool) {
	mock.ExpectBegin()
	mock.ExpectExec(`set_tenant_context`).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 0))
	q := mock.ExpectQuery(`FROM billing_subscriptions`).WithArgs(tenantID, tierID.String(), name)
	if entitled {
		q.WillReturnRows(sqlmock.NewRows([]string{"entitled"}).AddRow(1))
		mock.ExpectCommit()
		return
	}
	q.WillReturnError(sql.ErrNoRows)
}

func TestValidateTenantTierSelection_FreeTrialTierNeedsNoSubscription(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	tenantID, tierID := uuid.New(), uuid.New()
	expectTierLookup(mock, tierID, "free", 0, true)

	if err := validateTenantTierSelection(t.Context(), db, tenantID, tierID); err != nil {
		t.Fatalf("free trial tier must stay selectable (onboarding): %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

func TestValidateTenantTierSelection_PaidTierWithoutSubscriptionIsRefused(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	tenantID, tierID := uuid.New(), uuid.New()
	expectTierLookup(mock, tierID, "pro", 19900, false)
	expectEntitlementLookup(mock, tenantID, tierID, "pro", false)

	err = validateTenantTierSelection(t.Context(), db, tenantID, tierID)
	if err == nil {
		t.Fatal("a paid tier with no active subscription must be refused")
	}
	if !isErrTierNotEntitled(err) {
		t.Fatalf("err = %v, want errTierNotEntitled", err)
	}
}

// TestValidateTenantTierSelection_PaidTierFlaggedTrialStillNeedsSubscription
// pins the residual hole in the previous is_trial-only rule: a PAID tier that a
// platform admin flags is_trial must not become free to select.
func TestValidateTenantTierSelection_PaidTierFlaggedTrialStillNeedsSubscription(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	tenantID, tierID := uuid.New(), uuid.New()
	expectTierLookup(mock, tierID, "pro", 19900, true) // is_trial = true, but paid
	expectEntitlementLookup(mock, tenantID, tierID, "pro", false)

	if err := validateTenantTierSelection(t.Context(), db, tenantID, tierID); !isErrTierNotEntitled(err) {
		t.Fatalf("err = %v, want errTierNotEntitled", err)
	}
}

func TestValidateTenantTierSelection_PaidTierWithActiveSubscriptionIsAllowed(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	tenantID, tierID := uuid.New(), uuid.New()
	expectTierLookup(mock, tierID, "pro", 19900, false)
	expectEntitlementLookup(mock, tenantID, tierID, "pro", true)

	if err := validateTenantTierSelection(t.Context(), db, tenantID, tierID); err != nil {
		t.Fatalf("an entitled tenant must be allowed onto its paid tier: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

func isErrTierNotEntitled(err error) bool {
	return err != nil && strings.Contains(err.Error(), errTierNotEntitled.Error())
}
