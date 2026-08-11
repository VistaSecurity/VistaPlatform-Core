// Package server assembles the MCP server and its HTTP plumbing.
package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/vistasecurity/vistaplatform/mcp-service/internal/platform"
	"github.com/vistasecurity/vistaplatform/mcp-service/internal/tools"
	"github.com/vistasecurity/vistaplatform/shared/version"

	"github.com/gin-gonic/gin"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sirupsen/logrus"
)

// MCPPath is the streamable-HTTP endpoint, addressed through the API
// gateway as <gateway>/api/v1/mcp-service/mcp.
const MCPPath = "/api/v1/mcp-service/mcp"

// NewMCPServer builds the MCP server with the full VistaPlatform tool catalog.
func NewMCPServer(deps *tools.Deps) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{
		Name:    "vistaplatform",
		Title:   "VistaPlatform Cryptographic Inventory",
		Version: strings.TrimSpace(version.Get().Service),
	}, &mcp.ServerOptions{
		Instructions: "Read-only access to this tenant's VistaPlatform cryptographic asset inventory, " +
			"compliance posture and CBOM artifacts. Start broad (vistaplatform_get_risk_summary, " +
			"vistaplatform_list_compliance_frameworks) and drill down with the query tools. " +
			"All data is scoped to the tenant that owns the API token; identifiers are UUIDs " +
			"returned by the list/query tools.",
	})
	tools.Register(s, deps)
	return s
}

// NewHandler wraps the MCP streamable handler with bearer-token (PAT)
// authentication. Stateless JSON mode: every request is self-contained, no
// session affinity, no SSE — the right shape for a horizontally scaled
// service behind a gateway.
func NewHandler(mcpServer *mcp.Server, ex *platform.Exchanger) http.Handler {
	streamable := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return mcpServer },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true},
	)
	return authMiddleware(ex, streamable)
}

func authMiddleware(ex *platform.Exchanger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			unauthorized(w, "Missing bearer token. Pass a VistaPlatform API token (qvpat_...) in the Authorization header; mint one in Settings → API Tokens.")
			return
		}
		grant, err := ex.Exchange(r.Context(), token)
		if err != nil {
			if err == platform.ErrUnauthorized {
				unauthorized(w, "Invalid, expired or revoked API token.")
				return
			}
			logrus.WithError(err).Error("PAT exchange failed")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "authentication backend unavailable"})
			return
		}
		next.ServeHTTP(w, r.WithContext(platform.WithGrant(r.Context(), grant)))
	})
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(h, "Bearer ")
	token = strings.TrimSpace(token)
	if !ok || !strings.HasPrefix(token, "qvpat_") {
		return "", false
	}
	return token, true
}

func unauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("WWW-Authenticate", `Bearer resource_metadata=""`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// NewRouter builds the Gin router: health endpoints plus the MCP endpoint.
func NewRouter(handler http.Handler) *gin.Engine {
	router := gin.New()
	router.Use(gin.Recovery())

	health := func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "mcp-service",
			"version": version.Get(),
		})
	}
	router.GET("/health", health)
	router.GET("/ready", health)

	// MCP streamable HTTP: POST carries JSON-RPC; GET/DELETE are part of
	// the transport surface (rejected appropriately in stateless mode).
	router.Any(MCPPath, gin.WrapH(handler))

	return router
}
