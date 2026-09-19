package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/identitysettings"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

type identitySettingsStub struct {
	response      identitysettings.Settings
	err           error
	tenant, actor uuid.UUID
	calls         int
}

func (s *identitySettingsStub) Get(_ context.Context, tenant uuid.UUID) (identitysettings.Settings, error) {
	s.tenant = tenant
	s.calls++
	return s.response, s.err
}
func (s *identitySettingsStub) Set(_ context.Context, tenant, actor uuid.UUID, _ identitysettings.Update) (identitysettings.Settings, error) {
	s.tenant = tenant
	s.actor = actor
	s.calls++
	return s.response, s.err
}
func settingsResponse() identitysettings.Settings {
	return identitysettings.Settings{Mode: "disabled", Version: 1, Enrichment: identitysettings.Enrichment{ExcludedCIDRs: []string{}, SensitiveAssetIDs: []uuid.UUID{}}, Limits: identitysettings.Limits{MaxExcludedCIDRs: 128, MaxSensitiveAssetIDs: 256, MaxReasonLength: 2000}}
}

const identitySettingsPayload = `{"mode":"disabled","version":1,"reason":"Review prospective admission","enrichment":{"enabled":false,"excluded_cidrs":[],"sensitive_asset_ids":[]}}`

func TestContract_IdentityDiscoverySettingsPermissionsAndScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		for _, grant := range []bool{false, true} {
			t.Run(method+"/"+map[bool]string{false: "denied", true: "allowed"}[grant], func(t *testing.T) {
				tenant, actor := uuid.New(), uuid.New()
				store := &identitySettingsStub{response: settingsResponse()}
				handler := NewIdentityDiscoverySettingsHandler(store)
				router := gin.New()
				router.Use(func(c *gin.Context) { c.Set("tenantID", tenant); c.Set("userID", actor) })
				permission := rbac.PermissionSettingsRead
				handle := handler.Get
				if method == http.MethodPut {
					permission = rbac.PermissionSettingsUpdate
					handle = handler.Update
				}
				router.Handle(method, "/settings/identity-discovery", sharedrbac.RequireTenantPermission(permissionDB(t, grant), permission), handle)
				w := httptest.NewRecorder()
				router.ServeHTTP(w, httptest.NewRequest(method, "/settings/identity-discovery?tenant_id="+uuid.NewString(), strings.NewReader(identitySettingsPayload)))
				if !grant {
					if w.Code != http.StatusForbidden || store.calls != 0 {
						t.Fatalf("permission bypass: %d calls=%d", w.Code, store.calls)
					}
					return
				}
				if w.Code != http.StatusOK || store.tenant != tenant || (method == http.MethodPut && store.actor != actor) {
					t.Fatalf("request scope: %d tenant=%s actor=%s", w.Code, store.tenant, store.actor)
				}
				loadSpec(t).assertConforms(t, "IdentityDiscoverySettings", w.Body.Bytes())
			})
		}
	}
}
func TestIdentityDiscoverySettingsStrictPayloadAndErrorContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name, body string
		err        error
		actor      bool
		want       int
	}{
		{"no actor", identitySettingsPayload, nil, false, http.StatusUnauthorized},
		{"missing enabled", `{"mode":"disabled","enrichment":{}}`, nil, true, http.StatusBadRequest},
		{"unknown field", strings.TrimSuffix(identitySettingsPayload, "}") + `,"tenant_id":"other"}`, nil, true, http.StatusBadRequest},
		{"multiple objects", identitySettingsPayload + `{}`, nil, true, http.StatusBadRequest},
		{"oversized", `{"reason":"` + strings.Repeat("a", 66000) + `"}`, nil, true, http.StatusBadRequest},
		{"stale", identitySettingsPayload, identitysettings.ErrStaleVersion, true, http.StatusConflict},
		{"capability", identitySettingsPayload, identitysettings.ErrCapability, true, http.StatusConflict},
		{"activated", identitySettingsPayload, identitysettings.ErrActivated, true, http.StatusConflict},
		{"validation", identitySettingsPayload, identitysettings.ErrInvalid, true, http.StatusBadRequest},
		{"storage failure", identitySettingsPayload, errors.New("sensitive database detail"), true, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &identitySettingsStub{response: settingsResponse(), err: tc.err}
			h := NewIdentityDiscoverySettingsHandler(store)
			r := gin.New()
			r.Use(func(c *gin.Context) {
				c.Set("tenantID", uuid.New())
				if tc.actor {
					c.Set("userID", uuid.New())
				}
			})
			r.PUT("/settings/identity-discovery", h.Update)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/settings/identity-discovery", strings.NewReader(tc.body)))
			if w.Code != tc.want {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if tc.err == nil && store.calls != 0 {
				t.Fatal("invalid payload reached settings writer")
			}
			if strings.Contains(w.Body.String(), "sensitive database detail") {
				t.Fatal("database details exposed")
			}
			loadSpec(t).assertConforms(t, "IdentityDiscoverySettingsError", w.Body.Bytes())
		})
	}
}
func TestIdentityDiscoverySettingsProductionRoutesKeepPermissionGates(t *testing.T) {
	raw, err := os.ReadFile("../../cmd/main.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, route := range []struct{ group, path string }{{"api", "/inventory-service"}, {"api", ""}, {"apiv2", "/inventory-service"}} {
		for _, operation := range []struct{ method, permission, handler string }{{"GET", "Read", "Get"}, {"PUT", "Update", "Update"}} {
			expected := route.group + `.` + operation.method + `("` + route.path + `/settings/identity-discovery", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionSettings` + operation.permission + `), identityDiscoverySettingsHandler.` + operation.handler + `)`
			if !strings.Contains(source, expected) {
				t.Errorf("production permission gate missing: %s", expected)
			}
		}
	}
	if !strings.Contains(source, "handlers.NewIdentityDiscoverySettingsHandler(identitysettings.NewStore(db))") {
		t.Fatal("production settings store is not wired")
	}
}
