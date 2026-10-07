package http

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"reflect"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

// The agent/sensor mTLS passthrough listener (NewAgentMTLSServer) is reached
// by TCP passthrough at the edge, so NOTHING the edge does applies to it: no
// admin-plane or internal-route deny, no rate limit, no body limit. It shares
// the service's gin engine with the mesh listener, so without a route surface
// of its own it would serve every route the service has — the admin plane,
// the HMAC-only /internal/ routes, the tenant UI API — to anyone holding any
// client certificate at all (the handshake requires one but cannot verify it;
// see NewAgentMTLSServer).
//
// AgentRoutes is that surface. A service registers its agent-authenticated
// routes THROUGH an AgentRoutes (so the list cannot drift from what is
// registered), installs AgentListenerGuard as the first middleware of the
// engine, and hands the AgentRoutes to NewAgentMTLSServer. On the agent
// listener a request that does not resolve to one of those routes is answered
// 404, exactly as if the route did not exist, before any other middleware or
// handler runs. On every other listener the guard does nothing.

// AgentRoute is one route the agent listener serves: an HTTP method and the
// gin route pattern (c.FullPath()), e.g. "/api/v1/x/agents/:id/heartbeat".
type AgentRoute struct {
	Method string
	Path   string
}

func (r AgentRoute) String() string { return r.Method + " " + r.Path }

// AgentRoutes records the routes the agent listener may serve.
type AgentRoutes struct {
	allowed map[AgentRoute]struct{}
}

// NewAgentRoutes returns an empty agent route surface.
func NewAgentRoutes() *AgentRoutes {
	return &AgentRoutes{allowed: map[AgentRoute]struct{}{}}
}

// Handle registers the route on group exactly as group.Handle would, and
// records it as served by the agent listener.
func (a *AgentRoutes) Handle(group *gin.RouterGroup, method, relativePath string, handlers ...gin.HandlerFunc) {
	group.Handle(method, relativePath, handlers...)
	a.allowed[AgentRoute{Method: method, Path: joinRoutePaths(group.BasePath(), relativePath)}] = struct{}{}
}

// GET is Handle with http.MethodGet.
func (a *AgentRoutes) GET(group *gin.RouterGroup, relativePath string, handlers ...gin.HandlerFunc) {
	a.Handle(group, http.MethodGet, relativePath, handlers...)
}

// POST is Handle with http.MethodPost.
func (a *AgentRoutes) POST(group *gin.RouterGroup, relativePath string, handlers ...gin.HandlerFunc) {
	a.Handle(group, http.MethodPost, relativePath, handlers...)
}

// Allows reports whether the agent listener serves method on the gin route
// pattern fullPath. An unmatched request has an empty FullPath and is never
// allowed.
func (a *AgentRoutes) Allows(method, fullPath string) bool {
	if a == nil || fullPath == "" {
		return false
	}
	_, ok := a.allowed[AgentRoute{Method: method, Path: fullPath}]
	return ok
}

// Routes returns the recorded routes, sorted.
func (a *AgentRoutes) Routes() []AgentRoute {
	out := make([]AgentRoute, 0, len(a.allowed))
	for r := range a.allowed {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out
}

// joinRoutePaths mirrors gin's (unexported) joinPaths, so a recorded path is
// byte-for-byte the FullPath gin reports for the route.
func joinRoutePaths(absolutePath, relativePath string) string {
	if relativePath == "" {
		return absolutePath
	}
	finalPath := path.Join(absolutePath, relativePath)
	if strings.HasSuffix(relativePath, "/") && !strings.HasSuffix(finalPath, "/") {
		return finalPath + "/"
	}
	return finalPath
}

type agentListenerKey struct{}

// agentListenerHandler marks every request arriving on the agent listener with
// its route surface, for AgentListenerGuard to enforce. A context value cannot
// be set by a client.
func agentListenerHandler(engine http.Handler, routes *AgentRoutes) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		engine.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), agentListenerKey{}, routes)))
	})
}

// AgentListenerGuard confines a request that arrived on the agent mTLS
// listener to that listener's AgentRoutes; any other route answers 404 before
// the rest of the chain runs. Requests from any other listener pass untouched.
//
// Install it with engine.Use BEFORE registering any route: gin copies the
// global middleware into a route's chain when the route is registered, so a
// route registered first would not be guarded. NewAgentMTLSServer refuses an
// engine without it.
func AgentListenerGuard(c *gin.Context) {
	routes, onAgentListener := c.Request.Context().Value(agentListenerKey{}).(*AgentRoutes)
	if !onAgentListener {
		c.Next()
		return
	}
	if !routes.Allows(c.Request.Method, c.FullPath()) {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.Next()
}

// hasAgentListenerGuard reports whether AgentListenerGuard is in the engine's
// global middleware chain.
func hasAgentListenerGuard(engine *gin.Engine) bool {
	guard := reflect.ValueOf(AgentListenerGuard).Pointer()
	for _, h := range engine.Handlers {
		if reflect.ValueOf(h).Pointer() == guard {
			return true
		}
	}
	return false
}

// AgentListenerHandler is the handler NewAgentMTLSServer serves: engine,
// confined to routes. Exported for tests that drive the listener's handler
// without a TLS socket; it applies the same checks as NewAgentMTLSServer.
func AgentListenerHandler(engine *gin.Engine, routes *AgentRoutes) (http.Handler, error) {
	if engine == nil {
		return nil, fmt.Errorf("agent listener: no engine")
	}
	if routes == nil || len(routes.allowed) == 0 {
		return nil, fmt.Errorf("agent listener: no agent routes recorded; refusing to serve the whole router")
	}
	if !hasAgentListenerGuard(engine) {
		return nil, fmt.Errorf("agent listener: engine has no AgentListenerGuard middleware; refusing to serve the whole router")
	}
	return agentListenerHandler(engine, routes), nil
}
