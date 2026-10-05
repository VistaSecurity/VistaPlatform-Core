//go:build !ee

package api

// Settings → AI assistant, the provider half, in a CORE build.
//
// A Core build has no model clients, so there is nothing for a tenant to
// connect to. The two routes that would store or try a provider answer 402 —
// the same answer every other Enterprise capability gives — and they answer it
// before reading anything, so a Core install never stores a credential it has
// no use for. Disconnect is deliberately NOT refused: removing a stored
// credential must always be possible.

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/ai"
)

type emptyProviderStore struct{}

func (emptyProviderStore) Platform(context.Context) (ai.PlatformAISettings, error) {
	return ai.PlatformAISettings{TenantProvidersAllowed: true}, nil
}

func (emptyProviderStore) Tenant(context.Context, uuid.UUID) (*ai.StoredProvider, error) {
	return nil, nil
}

func newCoreProviderEngine(t *testing.T) (*gin.Engine, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	resolver := ai.NewResolverOver(emptyProviderStore{}, ai.NewKeyCipher("k"),
		func(context.Context, uuid.UUID) (bool, error) { return true, nil })
	dep := resolveAIDeployment().withResolver(resolver, nil)

	gin.SetMode(gin.TestMode)
	eng := gin.New()
	grp := eng.Group("/api/v1/auth-service")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", aTenantID)
		c.Set("userID", aiUserID)
		c.Next()
	})
	grp.GET("/tenant/ai", getTenantAIHandler(db, dep))
	grp.PUT("/tenant/ai/provider", putTenantAIProviderHandler(db, dep))
	grp.DELETE("/tenant/ai/provider", deleteTenantAIProviderHandler(db, dep))
	grp.POST("/tenant/ai/provider/test", testTenantAIProviderHandler(db, dep))
	return eng, mock
}

func TestTenantAIProvider_CoreAnswers402AndStoresNothing(t *testing.T) {
	for _, route := range []struct{ method, path string }{
		{http.MethodPut, "/api/v1/auth-service/tenant/ai/provider"},
		{http.MethodPost, "/api/v1/auth-service/tenant/ai/provider/test"},
	} {
		eng, mock := newCoreProviderEngine(t)
		w := do(eng, route.method, route.path,
			strings.NewReader(`{"kind":"anthropic","api_key":"sk-ant-000000000000"}`))
		if w.Code != http.StatusPaymentRequired {
			t.Fatalf("%s %s: status = %d, want 402; body=%s", route.method, route.path, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "Vista Platform Enterprise") {
			t.Fatalf("the 402 does not name the edition: %s", w.Body.String())
		}
		// Nothing was queued, so any statement would have failed the request;
		// this states the property rather than relying on that.
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("a Core build touched the database for a provider it cannot use: %v", err)
		}
	}
}

func TestTenantAIProvider_CoreStatusOffersNothingToConnect(t *testing.T) {
	eng, mock := newCoreProviderEngine(t)
	expectControlsRead(t, mock, nil)

	w := do(eng, http.MethodGet, "/api/v1/auth-service/tenant/ai", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{`"provider_kinds":[]`, `"tenant_provider_allowed":false`, `"provider_source":"none"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("Core status lacks %s: %s", want, body)
		}
	}
	// Core gives no "blocked by" reason: the edition is the whole answer and
	// the page already says so.
	if strings.Contains(body, "tenant_provider_blocked_by") {
		t.Fatalf("Core status blames a plan or the deployment: %s", body)
	}
}

func TestTenantAIProvider_CoreCanStillDisconnect(t *testing.T) {
	eng, mock := newCoreProviderEngine(t)
	tenantID := uuid.MustParse(aTenantID)
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("SELECT set_tenant_context($1)")).WithArgs(tenantID).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`UPDATE tenant_admin_settings`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	expectControlsRead(t, mock, nil)

	w := do(eng, http.MethodDelete, "/api/v1/auth-service/tenant/ai/provider", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the stored provider was not removed: %v", err)
	}
}

// expectAIPlanGate is what resolving a tenant's provider asks about the plan.
// In a Core build that is nothing: there are no model clients, so whether the
// plan lets a tenant connect one decides nothing and is not asked. The
// Enterprise half of this helper queues the entitlement lookup.
func expectAIPlanGate(sqlmock.Sqlmock, uuid.UUID) {}
