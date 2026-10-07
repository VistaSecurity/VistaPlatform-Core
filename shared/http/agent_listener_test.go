package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// guardedEngine builds an engine shaped like the services': the guard first,
// an agent group registered through AgentRoutes, and other routes beside it.
func guardedEngine(t *testing.T) (*gin.Engine, *AgentRoutes) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(AgentListenerGuard)
	ok := func(c *gin.Context) { c.String(http.StatusOK, "handler:"+c.FullPath()) }

	routes := NewAgentRoutes()
	svc := engine.Group("/api/v1/svc")
	agents := svc.Group("/agents/:id")
	routes.POST(agents, "/heartbeat", ok)
	routes.GET(agents, "/jobs", ok)
	routes.POST(svc.Group("/agents"), "/host-inventory", ok)

	svc.POST("/agents/register", ok)
	svc.GET("/agents/:id/config", ok) // tenant route sharing the agent prefix
	svc.POST("/internal/refresh", ok)
	svc.GET("/admin/agents", ok)
	engine.GET("/health", ok)
	return engine, routes
}

func serve(h http.Handler, method, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

func TestAgentListenerHandler_ServesOnlyAgentRoutes(t *testing.T) {
	engine, routes := guardedEngine(t)
	agentHandler, err := AgentListenerHandler(engine, routes)
	if err != nil {
		t.Fatalf("AgentListenerHandler: %v", err)
	}

	cases := []struct {
		method, target string
		served         bool
	}{
		{http.MethodPost, "/api/v1/svc/agents/a1/heartbeat", true},
		{http.MethodGet, "/api/v1/svc/agents/a1/jobs", true},
		{http.MethodPost, "/api/v1/svc/agents/host-inventory", true},
		// Wrong method on an agent path.
		{http.MethodGet, "/api/v1/svc/agents/a1/heartbeat", false},
		{http.MethodPost, "/api/v1/svc/agents/register", false},
		{http.MethodGet, "/api/v1/svc/agents/a1/config", false},
		{http.MethodPost, "/api/v1/svc/internal/refresh", false},
		{http.MethodGet, "/api/v1/svc/admin/agents", false},
		{http.MethodGet, "/health", false},
		{http.MethodGet, "/no/such/route", false},
	}
	for _, tc := range cases {
		rec := serve(agentHandler, tc.method, tc.target)
		if tc.served {
			if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), "handler:") {
				t.Errorf("agent listener %s %s = %d %q, want the handler", tc.method, tc.target, rec.Code, rec.Body.String())
			}
			continue
		}
		if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "handler:") {
			t.Errorf("agent listener %s %s = %d %q, want 404 before the handler", tc.method, tc.target, rec.Code, rec.Body.String())
		}
	}

	// The same engine on any other listener is untouched by the guard.
	for _, tc := range cases {
		if tc.target == "/no/such/route" || (tc.method == http.MethodGet && strings.HasSuffix(tc.target, "/heartbeat")) {
			continue
		}
		if rec := serve(engine, tc.method, tc.target); rec.Code != http.StatusOK {
			t.Errorf("mesh listener %s %s = %d, want the handler (guard must be a no-op off the agent listener)", tc.method, tc.target, rec.Code)
		}
	}
}

func TestAgentListenerGuard_IgnoresAForeignContextValue(t *testing.T) {
	engine, _ := guardedEngine(t)
	// A request carrying some other value under a look-alike key is not on the
	// agent listener; only agentListenerHandler can set the real key.
	type otherKey struct{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/svc/admin/agents", nil)
	req = req.WithContext(context.WithValue(req.Context(), otherKey{}, NewAgentRoutes()))
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
}

func TestAgentListenerHandler_RefusesAnUnconfinedEngine(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ok := func(c *gin.Context) { c.Status(http.StatusOK) }

	t.Run("no guard", func(t *testing.T) {
		engine := gin.New()
		routes := NewAgentRoutes()
		routes.POST(engine.Group("/a"), "/heartbeat", ok)
		if _, err := AgentListenerHandler(engine, routes); err == nil {
			t.Fatal("an engine without AgentListenerGuard was accepted")
		}
		if _, err := NewAgentMTLSServer("unused.crt", "unused.key", engine, routes); err == nil || !strings.Contains(err.Error(), "AgentListenerGuard") {
			t.Fatalf("NewAgentMTLSServer accepted an engine without the guard: %v", err)
		}
	})
	t.Run("no routes", func(t *testing.T) {
		engine := gin.New()
		engine.Use(AgentListenerGuard)
		engine.POST("/a/heartbeat", ok)
		if _, err := AgentListenerHandler(engine, NewAgentRoutes()); err == nil {
			t.Fatal("an empty route surface was accepted")
		}
		if _, err := AgentListenerHandler(engine, nil); err == nil {
			t.Fatal("a nil route surface was accepted")
		}
	})
}

// The recorded path must be exactly what gin reports as FullPath, or the guard
// would 404 a route it was told to serve.
func TestAgentRoutes_RecordsGinFullPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(AgentListenerGuard)
	routes := NewAgentRoutes()
	ok := func(c *gin.Context) { c.Status(http.StatusOK) }
	g := engine.Group("/api/v1/").Group("x/:id")
	routes.POST(g, "/a", ok)
	routes.GET(g, "b/", ok)
	routes.Handle(g, http.MethodPut, "", ok)

	registered := map[AgentRoute]bool{}
	for _, r := range engine.Routes() {
		registered[AgentRoute{Method: r.Method, Path: r.Path}] = true
	}
	got := routes.Routes()
	if len(got) != 3 {
		t.Fatalf("recorded %v, want 3 routes", got)
	}
	for _, r := range got {
		if !registered[r] {
			t.Errorf("recorded %s, which gin did not register (gin has %v)", r, engine.Routes())
		}
	}
}
