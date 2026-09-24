package handlers

// Contract tests for the platform identity-provider surface (admin-ui ▸
// Settings ▸ Identity Providers): the list body is asserted against
// PlatformIdentityProviderListResponse in api/openapi/admin-service.openapi.yaml,
// and the input schema is checked to carry allowed_email_domains so the
// generated client can send it. sqlmock stands in for Postgres; the real
// handlers run over httptest.

import (
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func identityProviderEngine(t *testing.T) (*gin.Engine, sqlmock.Sqlmock) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	r := gin.New()
	grp := r.Group(apiBase)
	grp.GET("/admin/identity-providers", ListPlatformIdentityProviders(db))
	return r, mock
}

var identityProviderListColumns = []string{
	"id", "provider_type", "provider_name", "purpose", "client_id", "client_secret_encrypted",
	"auth_url", "token_url", "userinfo_url", "scopes", "is_enabled", "allowed_email_domains",
}

func TestContract_ListPlatformIdentityProviders_200(t *testing.T) {
	sv := loadSpec(t)
	r, mock := identityProviderEngine(t)
	const tenantAuth = "https://login.microsoftonline.com/0b6f3c9e-1d2a-4c5b-9e8f-7a6b5c4d3e2f/oauth2/v2.0/"
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, provider_type, provider_name, purpose, client_id, client_secret_encrypted,")).
		WillReturnRows(sqlmock.NewRows(identityProviderListColumns).
			AddRow(uuid.NewString(), "microsoft", "Microsoft", "admin_login", "staff-app", "enc",
				tenantAuth+"authorize", tenantAuth+"token", "https://graph.microsoft.com/oidc/userinfo",
				"openid email profile", true, "{contoso.example,b.example}").
			// A NULL-free but empty list must still come back as [] (required array).
			AddRow(uuid.NewString(), "google", "Google", "signup", "signup-app", "",
				"https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token",
				"https://openidconnect.googleapis.com/v1/userinfo", "openid email profile", false, "{}"))

	w := doRequest(r, http.MethodGet, apiBase+"/admin/identity-providers", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PlatformIdentityProviderListResponse", w.Body.Bytes())
	body := w.Body.String()
	if !strings.Contains(body, `"allowed_email_domains":["contoso.example","b.example"]`) ||
		!strings.Contains(body, `"allowed_email_domains":[]`) {
		t.Fatalf("allowed_email_domains should serialise as arrays (never null): %s", body)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// The spec must not drop the field the handler reads and returns: a response
// without it violates the (required) schema, and the input schema declares it.
func TestContract_PlatformIdentityProvider_AllowedDomainsInSpec(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/PlatformIdentityProvider")
	if err != nil {
		t.Fatal(err)
	}
	missing := map[string]interface{}{
		"id": uuid.NewString(), "provider_type": "google", "provider_name": "Google", "purpose": "signup",
		"client_id": "x", "has_secret": true, "auth_url": "a", "token_url": "t", "scopes": "s", "is_enabled": true,
	}
	if err := sch.Validate(missing); err == nil {
		t.Fatal("a provider without allowed_email_domains must violate PlatformIdentityProvider")
	}
	in, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/PlatformIdentityProviderInput")
	if err != nil {
		t.Fatal(err)
	}
	bad := map[string]interface{}{"provider_type": "microsoft", "client_id": "x", "allowed_email_domains": "contoso.example"}
	if err := in.Validate(bad); err == nil {
		t.Fatal("allowed_email_domains must be declared as an array on the input schema")
	}
}
