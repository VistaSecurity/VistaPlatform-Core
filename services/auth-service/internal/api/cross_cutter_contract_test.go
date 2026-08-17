package api

// Contract test for the auth-service cross-cutter HTTP surface.
//
// Eighth (and final pre-spec) vertical slice for the spec-first API contract
// (ADR-0001), and the first slice for auth-service. It exercises the REAL
// gin handlers over httptest (with in-memory stub stores satisfying
// authServiceStore + rbacStore + limitChecker, no database) and asserts that
// every response body conforms to the schema declared in
// api/openapi/auth-service.openapi.yaml.
//
// OpenAPI 3.1 schemas ARE JSON Schema 2020-12, so we validate response
// bodies directly with santhosh-tekuri/jsonschema/v6 — same approach as
// the scopes / inventory-service / compliance-engine contract tests.
//
// If a handler's response shape drifts from the spec (a renamed field, a
// new required key, a wrong type), the matching test here fails. That is
// the guardrail: the spec cannot silently diverge from what the service
// returns.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/models"
	authrbac "github.com/vistasecurity/vistaplatform/auth-service/internal/rbac"
	"gopkg.in/yaml.v3"
)

const specBaseURI = "https://vistaplatform.local/auth-service.openapi.yaml"

// --- spec loading + response validation -----------------------------------

type specValidator struct{ compiler *jsonschema.Compiler }

func loadSpec(t *testing.T) *specValidator {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	// api -> internal -> auth-service -> services -> repo root.
	specPath := filepath.Join(
		filepath.Dir(thisFile), "..", "..", "..", "..",
		"api", "openapi", "auth-service.openapi.yaml",
	)
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read spec %s: %v", specPath, err)
	}
	// YAML -> generic -> JSON -> canonical form jsonschema expects.
	var asAny any
	if err := yaml.Unmarshal(raw, &asAny); err != nil {
		t.Fatalf("yaml unmarshal spec: %v", err)
	}
	jsonBytes, err := json.Marshal(asAny)
	if err != nil {
		t.Fatalf("re-marshal spec to json: %v", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(jsonBytes))
	if err != nil {
		t.Fatalf("jsonschema unmarshal spec: %v", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(specBaseURI, doc); err != nil {
		t.Fatalf("add spec resource: %v", err)
	}
	return &specValidator{compiler: c}
}

// assertConforms validates that body matches #/components/schemas/<schemaName>.
func (sv *specValidator) assertConforms(t *testing.T, schemaName string, body []byte) {
	t.Helper()
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/" + schemaName)
	if err != nil {
		t.Fatalf("compile schema %s: %v", schemaName, err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("unmarshal response body: %v\nbody: %s", err, string(body))
	}
	if err := sch.Validate(inst); err != nil {
		t.Fatalf("response violates schema %q:\n%v\n--- body ---\n%s", schemaName, err, string(body))
	}
}

// --- in-memory stub stores -------------------------------------------------

// stubAuthServiceStore satisfies authServiceStore. Only the methods exercised
// by this slice (`GetUserByID`, `GetTenantByID` — both called by `GetMe`)
// carry behavior; the rest are present to satisfy the interface and panic if
// ever called. Mirrors the framework_contract_test pattern in
// compliance-engine.
type stubAuthServiceStore struct {
	userResult   *models.User
	userErr      error
	tenantResult *models.Tenant
	tenantErr    error
	notifPrefs   map[string]interface{}
	notifGetErr  error
	notifUpdErr  error

	// Profile sessions/connections slice.
	sessions       []models.Session
	sessionsErr    error
	revokeErr      error
	connections    []models.Connection
	connectionsErr error
	setPrimaryErr  error

	// Access-token denylist calls recorded for.
	revokedJTIs []string

	// Register / reset-password write surface.
	registerResult   *models.User
	registerErr      error
	registerCalls    int
	loginResult      *models.AuthResponse
	loginErr         error
	resetPasswordErr error
	verifyEmailErr   error
	emailUserResult  *models.User
	emailUserErr     error
	db               *sql.DB
	bypassDB         *sql.DB

	bootstrappedTenantIDs []uuid.UUID
}

func (s *stubAuthServiceStore) GetUserByID(_ uuid.UUID) (*models.User, error) {
	return s.userResult, s.userErr
}
func (s *stubAuthServiceStore) GetTenantByID(_ uuid.UUID) (*models.Tenant, error) {
	return s.tenantResult, s.tenantErr
}

// Out-of-scope methods — never called from the cross-cutter contract test;
// return zero values so the file compiles and behaves predictably if a
// future test accidentally invokes one.
func (s *stubAuthServiceStore) GetDB() *sql.DB       { return s.db }
func (s *stubAuthServiceStore) GetBypassDB() *sql.DB { return s.bypassDB }
func (s *stubAuthServiceStore) Register(_ *models.RegisterRequest) (*models.User, error) {
	s.registerCalls++
	return s.registerResult, s.registerErr
}
func (s *stubAuthServiceStore) Login(_ *models.LoginRequest, _, _ string) (*models.AuthResponse, error) {
	return s.loginResult, s.loginErr
}
func (s *stubAuthServiceStore) Logout(_ uuid.UUID) error { return nil }
func (s *stubAuthServiceStore) RefreshToken(_, _, _ string) (*models.AuthResponse, error) {
	return nil, nil
}
func (s *stubAuthServiceStore) GetUserByEmail(_ string) (*models.User, error) {
	return s.emailUserResult, s.emailUserErr
}
func (s *stubAuthServiceStore) BootstrapTrialIfApplicable(tenantID uuid.UUID) error {
	s.bootstrappedTenantIDs = append(s.bootstrappedTenantIDs, tenantID)
	return nil
}
func (s *stubAuthServiceStore) UpdateUser(_ uuid.UUID, _ *models.UpdateUserRequest) (*models.User, error) {
	return nil, nil
}
func (s *stubAuthServiceStore) GetNotificationPreferences(_ uuid.UUID) (map[string]interface{}, error) {
	return s.notifPrefs, s.notifGetErr
}
func (s *stubAuthServiceStore) UpdateNotificationPreferences(_ uuid.UUID, _ map[string]interface{}) error {
	return s.notifUpdErr
}
func (s *stubAuthServiceStore) ChangePassword(_ uuid.UUID, _ *models.ChangePasswordRequest) error {
	return nil
}
func (s *stubAuthServiceStore) ForgotPassword(_ *models.ForgotPasswordRequest) error { return nil }
func (s *stubAuthServiceStore) ResetPassword(_ *models.ResetPasswordRequest) error {
	return s.resetPasswordErr
}
func (s *stubAuthServiceStore) VerifyEmail(_ string) error              { return s.verifyEmailErr }
func (s *stubAuthServiceStore) SendEmailVerification(_ uuid.UUID) error { return nil }
func (s *stubAuthServiceStore) GetUserSessions(_ uuid.UUID) ([]models.Session, error) {
	return s.sessions, s.sessionsErr
}
func (s *stubAuthServiceStore) RevokeRefreshToken(_, _ uuid.UUID) error { return s.revokeErr }
func (s *stubAuthServiceStore) GetUserAuthMethods(_ uuid.UUID) ([]models.Connection, error) {
	return s.connections, s.connectionsErr
}
func (s *stubAuthServiceStore) SetPrimaryAuthMethod(_, _ uuid.UUID) error    { return s.setPrimaryErr }
func (s *stubAuthServiceStore) UpdateUserAvatar(_ uuid.UUID, _ string) error { return nil }
func (s *stubAuthServiceStore) RevokeJTI(_ context.Context, jti string, _ time.Duration) error {
	s.revokedJTIs = append(s.revokedJTIs, jti)
	return nil
}

// stubRBACStore satisfies rbac.rbacStore. Only `GetUserPermissions` (the
// in-scope cross-cutter) carries behavior.
type stubRBACStore struct {
	permissions       []authrbac.Permission
	err               error
	tenantRoles       []authrbac.Role
	tenantPermissions []authrbac.Permission
	userRoles         []authrbac.Role
	matrix            *authrbac.PermissionMatrix
	matrixErr         error
	createdRole       *authrbac.Role
	createErr         error
	deleteResult      *authrbac.DeleteRoleResult
	deleteErr         error
	assignErr         error
	removeErr         error
	updPermsErr       error
}

func (s *stubRBACStore) GetUserPermissions(_, _ uuid.UUID) ([]authrbac.Permission, error) {
	return s.permissions, s.err
}

func (s *stubRBACStore) GetTenantRoles(_ uuid.UUID) ([]authrbac.Role, error) {
	return s.tenantRoles, s.err
}
func (s *stubRBACStore) GetTenantPermissions(_ uuid.UUID) ([]authrbac.Permission, error) {
	return s.tenantPermissions, s.err
}
func (s *stubRBACStore) GetUserRoles(_, _ uuid.UUID) ([]authrbac.Role, error) {
	return s.userRoles, s.err
}
func (s *stubRBACStore) AssignUserRole(_, _, _, _ uuid.UUID) error { return s.assignErr }
func (s *stubRBACStore) RemoveUserRole(_, _, _ uuid.UUID) error    { return s.removeErr }
func (s *stubRBACStore) GetPermissionMatrix(_, _, _ uuid.UUID) (*authrbac.PermissionMatrix, error) {
	return s.matrix, s.matrixErr
}
func (s *stubRBACStore) UpdateRolePermissions(_, _, _ uuid.UUID, _ []uuid.UUID) error {
	return s.updPermsErr
}
func (s *stubRBACStore) CreateTenantRole(_, _ uuid.UUID, _ authrbac.CreateRoleRequest) (*authrbac.Role, error) {
	return s.createdRole, s.createErr
}
func (s *stubRBACStore) DeleteTenantRole(_, _ uuid.UUID, _ *uuid.UUID) (*authrbac.DeleteRoleResult, error) {
	return s.deleteResult, s.deleteErr
}
func (s *stubRBACStore) CheckPermission(_, _ uuid.UUID, _ string) (bool, error) {
	return false, nil
}

// stubLimitChecker satisfies limitChecker — the slice of
// LimitEnforcementService that getTenantFeaturesHandler calls.
type stubLimitChecker struct {
	featureResults map[string]bool
	featureErrs    map[string]error
	usageCurrent   int
	usageLimit     *int
	usageErr       error
}

func (s *stubLimitChecker) CheckFeatureAccess(_ uuid.UUID, feature string) (bool, error) {
	if s.featureErrs != nil {
		if e, ok := s.featureErrs[feature]; ok && e != nil {
			return false, e
		}
	}
	if s.featureResults == nil {
		return false, nil
	}
	return s.featureResults[feature], nil
}

func (s *stubLimitChecker) GetComplianceFrameworkUsage(_ uuid.UUID) (int, *int, error) {
	if s.usageErr != nil {
		return 0, nil, s.usageErr
	}
	return s.usageCurrent, s.usageLimit, nil
}

// --- test harness ----------------------------------------------------------

// newEngine mounts the in-scope routes on /api/v1/auth-service with a
// middleware that injects userID + tenantID as strings (the way
// RequireAuth middleware does in production — handlers parse them via
// uuid.Parse(idStr.(string))).
//
// Pass `nil` for any store the test does not need to drive responses for —
// the corresponding routes will still mount but the stubs return zero
// values.
func newEngine(
	as *stubAuthServiceStore,
	rs *stubRBACStore,
	limits *stubLimitChecker,
	authenticated bool,
	userID, tenantID string,
) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	if as == nil {
		as = &stubAuthServiceStore{}
	}
	if rs == nil {
		rs = &stubRBACStore{}
	}
	if limits == nil {
		limits = &stubLimitChecker{}
	}

	grp := r.Group("/api/v1/auth-service")
	grp.Use(func(c *gin.Context) {
		if authenticated {
			c.Set("userID", userID)
			c.Set("tenantID", tenantID)
		}
		c.Next()
	})

	authHandlers := &AuthHandlers{authService: as}
	rbacHandlers := authrbac.NewRBACHandlersWithStore(rs)

	grp.GET("/auth/me", authHandlers.GetMe)
	grp.GET("/user/permissions", rbacHandlers.GetCurrentUserPermissions)
	grp.GET("/tenant/features", newTenantFeaturesHandler(limits))
	grp.GET("/tenant/:tenantId/roles", rbacHandlers.GetTenantRoles)
	grp.POST("/tenant/:tenantId/roles", rbacHandlers.CreateTenantRole)
	grp.DELETE("/tenant/:tenantId/roles/:roleId", rbacHandlers.DeleteTenantRole)
	grp.GET("/permissions", rbacHandlers.GetTenantPermissions)
	grp.GET("/tenant/:tenantId/users/:userId/roles", rbacHandlers.GetUserRoles)
	grp.GET("/auth/me/preferences/notifications", authHandlers.GetNotificationPreferences)
	grp.PUT("/auth/me/preferences/notifications", authHandlers.UpdateNotificationPreferences)
	grp.GET("/tenant/:tenantId/roles/:roleId/matrix", rbacHandlers.GetPermissionMatrix)
	grp.PUT("/tenant/:tenantId/roles/:roleId/permissions", rbacHandlers.UpdateRolePermissions)
	grp.POST("/tenant/:tenantId/users/:userId/roles", rbacHandlers.AssignRole)
	grp.DELETE("/tenant/:tenantId/users/:userId/roles/:roleId", rbacHandlers.RemoveRole)

	return r
}

func do(engine *gin.Engine, method, path string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, body)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

// --- sample data ----------------------------------------------------------

func sampleUser(userID, tenantID uuid.UUID) *models.User {
	now := time.Now().UTC()
	avatar := "https://example.com/avatar.png"
	tz := "America/New_York"
	return &models.User{
		ID:            userID,
		TenantID:      tenantID,
		Email:         "user@example.com",
		PasswordHash:  "should-be-stripped",
		FirstName:     "Test",
		LastName:      "User",
		Role:          "tenant_admin",
		IsActive:      true,
		EmailVerified: true,
		AvatarURL:     &avatar,
		Timezone:      &tz,
		Preferences:   map[string]interface{}{"theme": "dark"},
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

func sampleTenant(tenantID uuid.UUID) *models.Tenant {
	now := time.Now().UTC()
	domain := "example.com"
	return &models.Tenant{
		ID:                 tenantID,
		Name:               "Example Corp",
		Slug:               "example",
		Domain:             &domain,
		SubscriptionTierID: uuid.New(),
		BillingEmail:       "billing@example.com",
		PaymentStatus:      "active",
		Settings:           map[string]interface{}{"hello": "world"},
		CreatedAt:          now,
		UpdatedAt:          now,
	}
}

const (
	aUserID   = "11111111-1111-1111-1111-111111111111"
	aTenantID = "22222222-2222-2222-2222-222222222222"
)

// --- the contract tests ----------------------------------------------------

// /auth/me

func TestContract_GetMe_200_withTenant(t *testing.T) {
	sv := loadSpec(t)
	uid, tid := uuid.MustParse(aUserID), uuid.MustParse(aTenantID)
	eng := newEngine(
		&stubAuthServiceStore{
			userResult:   sampleUser(uid, tid),
			tenantResult: sampleTenant(tid),
		},
		nil, nil, true, aUserID, aTenantID,
	)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/auth/me", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MeResponse", w.Body.Bytes())
	// password_hash must be stripped.
	if strings.Contains(w.Body.String(), "password_hash") {
		t.Fatalf("password_hash leaked into response body: %s", w.Body.String())
	}
	// Must include tenant on the happy path.
	if !strings.Contains(w.Body.String(), `"tenant"`) {
		t.Fatalf("expected tenant key in response, got: %s", w.Body.String())
	}
}

func TestContract_GetMe_200_tenantOmittedOnTenantLookupFailure(t *testing.T) {
	sv := loadSpec(t)
	uid, tid := uuid.MustParse(aUserID), uuid.MustParse(aTenantID)
	eng := newEngine(
		&stubAuthServiceStore{
			userResult: sampleUser(uid, tid),
			tenantErr:  errors.New("tenant lookup boom"),
		},
		nil, nil, true, aUserID, aTenantID,
	)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/auth/me", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	// MeResponse still validates because `tenant` is optional in the schema.
	sv.assertConforms(t, "MeResponse", w.Body.Bytes())
	// `tenant` must be ABSENT entirely (not present-but-null) — the
	// documented x-quirk.
	if strings.Contains(w.Body.String(), `"tenant"`) {
		t.Fatalf("tenant key should be absent on failure, got: %s", w.Body.String())
	}
}

func TestContract_GetMe_401_notAuthenticated(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(nil, nil, nil, false, "", "")
	w := do(eng, http.MethodGet, "/api/v1/auth-service/auth/me", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetMe_404_userNotFound(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(
		&stubAuthServiceStore{userErr: errUserNotFoundShim()},
		nil, nil, true, aUserID, aTenantID,
	)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/auth/me", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetMe_500_unexpectedError(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(
		&stubAuthServiceStore{userErr: errors.New("db is on fire")},
		nil, nil, true, aUserID, aTenantID,
	)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/auth/me", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// /user/permissions

func TestContract_GetCurrentUserPermissions_200_populated(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(
		nil,
		&stubRBACStore{
			permissions: []authrbac.Permission{
				{ID: uuid.New(), Name: "compliance.manage", Resource: "compliance", Action: "manage"},
				{ID: uuid.New(), Name: "users.read", Resource: "users", Action: "read"},
				{ID: uuid.New(), Name: "settings.read", Resource: "settings", Action: "read"},
			},
		},
		nil, true, aUserID, aTenantID,
	)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/user/permissions", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PermissionsResponse", w.Body.Bytes())
}

func TestContract_GetCurrentUserPermissions_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(
		nil,
		&stubRBACStore{permissions: []authrbac.Permission{}},
		nil, true, aUserID, aTenantID,
	)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/user/permissions", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PermissionsResponse", w.Body.Bytes())
}

func TestContract_GetCurrentUserPermissions_401_noUser(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(nil, nil, nil, false, "", "")
	w := do(eng, http.MethodGet, "/api/v1/auth-service/user/permissions", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetCurrentUserPermissions_500_serviceError(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(
		nil,
		&stubRBACStore{err: errors.New("permissions query failed")},
		nil, true, aUserID, aTenantID,
	)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/user/permissions", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// /tenant/features

func TestContract_GetTenantFeatures_200_allOn(t *testing.T) {
	sv := loadSpec(t)
	cap := 10
	eng := newEngine(
		nil, nil,
		&stubLimitChecker{
			featureResults: map[string]bool{
				"custom_policies":     true,
				"threshold_overrides": true,
				"ot_active_probing":   true,
				"ot_primary_lens":     true,
			},
			usageCurrent: 3,
			usageLimit:   &cap,
		},
		true, aUserID, aTenantID,
	)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/features", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "FeaturesResponse", w.Body.Bytes())
}

func TestContract_GetTenantFeatures_200_unlimitedLimit(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(
		nil, nil,
		&stubLimitChecker{
			featureResults: map[string]bool{
				"custom_policies":     false,
				"threshold_overrides": false,
				"ot_active_probing":   false,
				"ot_primary_lens":     false,
			},
			usageCurrent: 7,
			usageLimit:   nil, // unlimited
		},
		true, aUserID, aTenantID,
	)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/features", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "FeaturesResponse", w.Body.Bytes())
	// limit should serialize as JSON null, not be omitted.
	if !strings.Contains(w.Body.String(), `"limit":null`) {
		t.Fatalf("expected limit:null in unlimited case, got: %s", w.Body.String())
	}
}

func TestContract_GetTenantFeatures_200_usageErrorOmitsKey(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(
		nil, nil,
		&stubLimitChecker{
			featureResults: map[string]bool{
				"custom_policies":     true,
				"threshold_overrides": false,
				"ot_active_probing":   false,
				"ot_primary_lens":     true,
			},
			usageErr: errors.New("usage query failed"),
		},
		true, aUserID, aTenantID,
	)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/features", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "FeaturesResponse", w.Body.Bytes())
	// compliance_frameworks key must be absent (not present-but-null) on
	// usage failure — the documented x-quirk.
	if strings.Contains(w.Body.String(), "compliance_frameworks") {
		t.Fatalf("compliance_frameworks should be absent on usage err, got: %s", w.Body.String())
	}
}

func TestContract_GetTenantFeatures_200_perFeatureErrorIsSilent(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(
		nil, nil,
		&stubLimitChecker{
			featureResults: map[string]bool{
				"custom_policies":     true,
				"threshold_overrides": true,
				"ot_active_probing":   false, // overridden by err below
				"ot_primary_lens":     true,
			},
			featureErrs: map[string]error{
				"ot_active_probing": errors.New("flag lookup boom"),
			},
		},
		true, aUserID, aTenantID,
	)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/features", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "FeaturesResponse", w.Body.Bytes())
	// The errored flag must be present and false (safe default).
	if !strings.Contains(w.Body.String(), `"ot_active_probing":false`) {
		t.Fatalf("expected ot_active_probing:false on err, got: %s", w.Body.String())
	}
}

func TestContract_GetTenantFeatures_401_noTenant(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(nil, nil, nil, false, "", "")
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/features", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetTenantFeatures_400_invalidTenantID(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(nil, nil, nil, true, aUserID, "not-a-uuid")
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/features", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- drift-detection guardrail --------------------------------------------

// TestContract_DriftIsCaught proves the guardrail actually validates: a
// body that drifts from the contract (a MeResponse missing the required
// `user` key) MUST be rejected. If this ever passes, the validator is
// rubber-stamping and the whole contract test is worthless.
func TestContract_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/MeResponse")
	if err != nil {
		t.Fatalf("compile MeResponse: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(`{"surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted MeResponse, but it passed — the guardrail is not actually checking")
	}
}

// errUserNotFoundShim returns the canonical "user not found" sentinel the
// handler branches on. The interface lets us return any error, but the
// handler's check is `err == auth.ErrUserNotFound`, so we surface that exact
// value to trigger the 404 branch.
func errUserNotFoundShim() error {
	return auth.ErrUserNotFound
}

// =====================================================================
// rbac (roles / permissions) — Settings → Roles & Permissions
// =====================================================================

func sampleRole() authrbac.Role {
	now := time.Now().UTC()
	return authrbac.Role{
		ID:          uuid.New(),
		Name:        "tenant_admin",
		Description: "Full tenant administration",
		Permissions: map[string]interface{}{"users.manage": true, "settings.update": true},
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// minimalRole leaves Permissions nil (→ JSON null), proving the required-but-
// nullable handling holds.
func minimalRole() authrbac.Role {
	now := time.Now().UTC()
	return authrbac.Role{
		ID:          uuid.New(),
		Name:        "viewer",
		Description: "Read-only",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

func TestContract_GetTenantRoles_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(
		nil,
		&stubRBACStore{tenantRoles: []authrbac.Role{sampleRole(), minimalRole()}},
		nil, true, aUserID, aTenantID,
	)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/"+aTenantID+"/roles", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RoleListResponse", w.Body.Bytes())
}

func TestContract_GetTenantRoles_400_badTenantID(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(nil, &stubRBACStore{}, nil, true, aUserID, aTenantID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/not-a-uuid/roles", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetTenantPermissions_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(
		nil,
		&stubRBACStore{tenantPermissions: []authrbac.Permission{
			{ID: uuid.New(), Name: "users.manage", Description: "Manage users", Resource: "users", Action: "manage"},
			{ID: uuid.New(), Name: "settings.update", Description: "Update settings", Resource: "settings", Action: "update"},
		}},
		nil, true, aUserID, aTenantID,
	)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/permissions", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PermissionListResponse", w.Body.Bytes())
}

func TestContract_GetUserRoles_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(
		nil,
		&stubRBACStore{userRoles: []authrbac.Role{sampleRole()}},
		nil, true, aUserID, aTenantID,
	)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/"+aTenantID+"/users/"+aUserID+"/roles", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RoleListResponse", w.Body.Bytes())
}

// --- notification preferences -----------------------------------------------

func TestContract_GetNotificationPreferences_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(
		&stubAuthServiceStore{notifPrefs: map[string]interface{}{"email_alerts": true, "digest": "daily"}},
		nil, nil, true, aUserID, aTenantID,
	)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/auth/me/preferences/notifications", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "NotificationPreferencesResponse", w.Body.Bytes())
}

func TestContract_UpdateNotificationPreferences_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAuthServiceStore{}, nil, nil, true, aUserID, aTenantID)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/auth/me/preferences/notifications",
		strings.NewReader(`{"email_alerts":false}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_UpdateNotificationPreferences_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(&stubAuthServiceStore{}, nil, nil, true, aUserID, aTenantID)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/auth/me/preferences/notifications",
		strings.NewReader(`not-json`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- tenant RBAC management -------------------------------------------------

func TestContract_GetPermissionMatrix_200(t *testing.T) {
	sv := loadSpec(t)
	permID := uuid.New()
	eng := newEngine(
		nil,
		&stubRBACStore{matrix: &authrbac.PermissionMatrix{
			RoleID:       uuid.MustParse(aTenantID),
			RoleName:     "auditors",
			DisplayName:  "Auditors",
			Description:  "custom role",
			IsSystemRole: false,
			Editable:     true,
			Permissions: []authrbac.MatrixPermission{{
				ID: permID, Name: "users.read", Description: "Read users",
				Resource: "users", Action: "read", Granted: true, Grantable: true,
			}},
			GrantedPermissionIDs: []uuid.UUID{permID},
		}},
		nil, true, aUserID, aTenantID,
	)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/"+aTenantID+"/roles/"+aTenantID+"/matrix", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PermissionMatrixResponse", w.Body.Bytes())
}

func TestContract_CreateTenantRole_201(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(nil, &stubRBACStore{createdRole: &authrbac.Role{
		ID: uuid.New(), Name: "auditors", DisplayName: "Auditors",
		Description: "custom role", IsSystemRole: false,
		PermissionCount: 1, UserCount: 0,
	}}, nil, true, aUserID, aTenantID)
	w := do(eng, http.MethodPost, "/api/v1/auth-service/tenant/"+aTenantID+"/roles",
		strings.NewReader(`{"display_name":"Auditors"}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CreateTenantRoleResponse", w.Body.Bytes())
}

func TestContract_DeleteTenantRole_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(nil, &stubRBACStore{
		deleteResult: &authrbac.DeleteRoleResult{RoleID: uuid.MustParse(aTenantID)},
	}, nil, true, aUserID, aTenantID)
	w := do(eng, http.MethodDelete, "/api/v1/auth-service/tenant/"+aTenantID+"/roles/"+aTenantID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "DeleteTenantRoleResponse", w.Body.Bytes())
}

// A blocked delete must carry the `role_in_use` code and the holder count — the
// UI branches on it to open a reassignment picker.
func TestContract_DeleteTenantRole_409(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(nil, &stubRBACStore{
		deleteErr: &authrbac.ErrRoleInUse{UserCount: 2},
	}, nil, true, aUserID, aTenantID)
	w := do(eng, http.MethodDelete, "/api/v1/auth-service/tenant/"+aTenantID+"/roles/"+aTenantID, nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RoleErrorResponse", w.Body.Bytes())
}

// System roles are read-only on the permission write — 403 `system_role_immutable`.
func TestContract_UpdateRolePermissions_403SystemRole(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(nil, &stubRBACStore{updPermsErr: authrbac.ErrSystemRoleImmutable},
		nil, true, aUserID, aTenantID)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/"+aTenantID+"/roles/"+aTenantID+"/permissions",
		strings.NewReader(`{"permission_ids":[]}`))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RoleErrorResponse", w.Body.Bytes())
}

func TestContract_UpdateRolePermissions_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(nil, &stubRBACStore{}, nil, true, aUserID, aTenantID)
	w := do(eng, http.MethodPut, "/api/v1/auth-service/tenant/"+aTenantID+"/roles/"+aTenantID+"/permissions",
		strings.NewReader(`{"permission_ids":["`+aTenantID+`"]}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "UpdateRolePermissionsResponse", w.Body.Bytes())
}

func TestContract_AssignRole_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(nil, &stubRBACStore{}, nil, true, aUserID, aTenantID)
	w := do(eng, http.MethodPost, "/api/v1/auth-service/tenant/"+aTenantID+"/users/"+aUserID+"/roles",
		strings.NewReader(`{"role_id":"`+aTenantID+`"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RoleAssignmentResponse", w.Body.Bytes())
}

func TestContract_RemoveRole_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newEngine(nil, &stubRBACStore{}, nil, true, aUserID, aTenantID)
	w := do(eng, http.MethodDelete, "/api/v1/auth-service/tenant/"+aTenantID+"/users/"+aUserID+"/roles/"+aTenantID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RoleAssignmentResponse", w.Body.Bytes())
}

// =====================================================================
// platform config + trial status — the public/branding + trial reads the
// web-ui app shell fetches on load (platform-config-context.tsx,
// useTrialStatus.ts). Both handlers were refactored to depend on a narrow
// store interface (platformSettingsStore / trialStatusStore) so they run here
// with no database; the concrete *sql.DB repositories still satisfy them in
// production, and resolveTrialStatus keeps its DB signature for the
// integration tests in trial_status_test.go.
// =====================================================================

// stubPlatformSettingsStore satisfies platformSettingsStore. Keys present in
// `settings` return their raw JSON value; absent keys return sql.ErrNoRows.
type stubPlatformSettingsStore struct {
	settings map[string][]byte
	err      error
}

func (s *stubPlatformSettingsStore) GetPlatformSetting(key string) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	v, ok := s.settings[key]
	if !ok {
		return nil, sql.ErrNoRows
	}
	return v, nil
}

// stubTrialStatusStore satisfies trialStatusStore with a canned row + error.
type stubTrialStatusStore struct {
	row trialStatusRow
	err error
}

func (s *stubTrialStatusStore) GetTrialStatusRow(_ uuid.UUID) (trialStatusRow, error) {
	return s.row, s.err
}

// newConfigEngine mounts just the platform-config + trial-status routes. A
// dedicated builder keeps these two stores out of the broad newEngine harness
// (and its ~30 call sites). /platform/config is unauthenticated;
// /tenant/trial-status reads tenantID from context the way RequireAuth sets it.
func newConfigEngine(pc platformSettingsStore, ts trialStatusStore, authenticated bool, tenantID string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if pc == nil {
		pc = &stubPlatformSettingsStore{}
	}
	if ts == nil {
		ts = &stubTrialStatusStore{}
	}
	grp := r.Group("/api/v1/auth-service")
	grp.Use(func(c *gin.Context) {
		if authenticated {
			c.Set("tenantID", tenantID)
		}
		c.Next()
	})
	grp.GET("/platform/config", getPublicPlatformConfigWithStore(pc))
	grp.GET("/tenant/trial-status", getTenantTrialStatusHandlerWithStore(ts))
	return r
}

// jsonBytes is a tiny helper to build the raw JSON-encoded setting values the
// platform_settings rows hold (the handler json.Unmarshals each value).
func jsonBytes(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal setting value: %v", err)
	}
	return b
}

func TestContract_GetPlatformConfig_200_defaults(t *testing.T) {
	sv := loadSpec(t)
	// Empty store -> every read misses -> only the built-in platform_name default.
	eng := newConfigEngine(&stubPlatformSettingsStore{}, nil, false, "")
	w := do(eng, http.MethodGet, "/api/v1/auth-service/platform/config", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PlatformConfig", w.Body.Bytes())
	// Logo URLs must be absent (omitempty), not present-but-null.
	if strings.Contains(w.Body.String(), "platform_logo_url") {
		t.Fatalf("logo URL keys should be absent when unset, got: %s", w.Body.String())
	}
}

func TestContract_GetPlatformConfig_200_branded(t *testing.T) {
	sv := loadSpec(t)
	eng := newConfigEngine(&stubPlatformSettingsStore{settings: map[string][]byte{
		"platform_name":           jsonBytes(t, "Acme Crypto"),
		"platform_logo_url":       jsonBytes(t, "https://cdn.example.com/logo.png"),
		"platform_login_logo_url": jsonBytes(t, "https://cdn.example.com/login.png"),
	}}, nil, false, "")
	w := do(eng, http.MethodGet, "/api/v1/auth-service/platform/config", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PlatformConfig", w.Body.Bytes())
	if !strings.Contains(w.Body.String(), `"platform_login_logo_url":"https://cdn.example.com/login.png"`) {
		t.Fatalf("expected login logo URL in branded response, got: %s", w.Body.String())
	}
}

func TestContract_GetTrialStatus_200_none(t *testing.T) {
	sv := loadSpec(t)
	// Zero row (isTrial invalid) -> PhaseNone.
	eng := newConfigEngine(nil, &stubTrialStatusStore{}, true, aTenantID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/trial-status", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TrialStatusResponse", w.Body.Bytes())
	// none-phase omits the trial_* fields.
	if strings.Contains(w.Body.String(), "trial_start") {
		t.Fatalf("trial_start should be absent in none phase, got: %s", w.Body.String())
	}
}

func TestContract_GetTrialStatus_200_fullPhase(t *testing.T) {
	sv := loadSpec(t)
	now := time.Now().UTC()
	start := now.Add(-3 * 24 * time.Hour)
	end := now.Add(25 * 24 * time.Hour)
	// A tenant on a trial tier, day 3 of a 14-day full window -> PhaseFull with
	// the nullable trial_* fields populated.
	eng := newConfigEngine(nil, &stubTrialStatusStore{row: trialStatusRow{
		isTrial:       sql.NullBool{Bool: true, Valid: true},
		trialDaysFull: sql.NullInt64{Int64: 14, Valid: true},
		trialDaysSoft: sql.NullInt64{Int64: 14, Valid: true},
		trialStart:    sql.NullTime{Time: start, Valid: true},
		trialEnd:      sql.NullTime{Time: end, Valid: true},
		converted:     sql.NullBool{Bool: false, Valid: true},
	}}, true, aTenantID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/trial-status", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TrialStatusResponse", w.Body.Bytes())
	if !strings.Contains(w.Body.String(), `"trial_days_full":14`) {
		t.Fatalf("expected trial_days_full:14 in populated response, got: %s", w.Body.String())
	}
}

// A lookup error degrades to phase none, still 200 — pins the documented
// cosmetic-degrade behavior.
func TestContract_GetTrialStatus_200_lookupErrorDegrades(t *testing.T) {
	sv := loadSpec(t)
	eng := newConfigEngine(nil, &stubTrialStatusStore{err: errors.New("db is on fire")}, true, aTenantID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/trial-status", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TrialStatusResponse", w.Body.Bytes())
	if !strings.Contains(w.Body.String(), `"phase":"none"`) {
		t.Fatalf("expected phase none on lookup error, got: %s", w.Body.String())
	}
}

func TestContract_GetTrialStatus_401_noTenant(t *testing.T) {
	sv := loadSpec(t)
	eng := newConfigEngine(nil, &stubTrialStatusStore{}, false, "")
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/trial-status", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetTrialStatus_400_badTenant(t *testing.T) {
	sv := loadSpec(t)
	eng := newConfigEngine(nil, &stubTrialStatusStore{}, true, "not-a-uuid")
	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/trial-status", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
