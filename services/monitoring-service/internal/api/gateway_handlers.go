package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
)

// gatewayProxyClient issues server-side requests to Traefik's dashboard API.
// This avoids browser CORS restrictions — the browser never talks to Traefik directly.
func (s *Server) newGatewayHTTPClient() *http.Client {
	return &http.Client{Timeout: 5 * time.Second}
}

func (s *Server) traefikAPIURL() string {
	// The Traefik dashboard API (/api/overview, /api/http/*) is served on the
	// built-in "traefik" entrypoint (default port 8080), NOT on the routing
	// entrypoint (port 80). Use a dedicated env var so the two aren't confused.
	//
	// Returns "" when unset. There is NO api-gateway pod in the Helm/K8s
	// deployment, and cluster Traefik's dashboard API is not exposed at a stable
	// in-namespace name, so the previous "http://api-gateway:8080" default just
	// produced repeated dial failures. When empty, the gateway-dashboard feature
	// reports itself as not configured rather than dialing a dead host.
	return os.Getenv("TRAEFIK_DASHBOARD_URL")
}

// proxyTraefikJSON fetches a Traefik dashboard API path and writes the JSON response to the gin context.
func (s *Server) proxyTraefikJSON(c *gin.Context, path string) {
	base := s.traefikAPIURL()
	if base == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":  "gateway dashboard not configured",
			"detail": "TRAEFIK_DASHBOARD_URL is not set; the Traefik dashboard API is not reachable in this deployment",
		})
		return
	}
	url := fmt.Sprintf("%s%s", base, path)
	resp, err := s.newGatewayHTTPClient().Get(url) //nolint:noctx
	if err != nil {
		sharedapi.ErrorResponse(c, http.StatusServiceUnavailable, "gateway unavailable", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read gateway response"})
		return
	}

	// Validate it is valid JSON before forwarding (Traefik always returns JSON).
	var raw json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid response from gateway"})
		return
	}

	c.Data(resp.StatusCode, "application/json; charset=utf-8", body)
}

// getGatewayOverview proxies GET /api/overview from Traefik's dashboard API.
// Route: GET /api/v1/monitoring-service/gateway/overview
func (s *Server) getGatewayOverview(c *gin.Context) {
	s.proxyTraefikJSON(c, "/api/overview")
}

// getGatewayRouters proxies GET /api/http/routers from Traefik's dashboard API.
// Route: GET /api/v1/monitoring-service/gateway/routers
func (s *Server) getGatewayRouters(c *gin.Context) {
	s.proxyTraefikJSON(c, "/api/http/routers")
}

// getGatewayServices proxies GET /api/http/services from Traefik's dashboard API.
// Route: GET /api/v1/monitoring-service/gateway/services
func (s *Server) getGatewayServices(c *gin.Context) {
	s.proxyTraefikJSON(c, "/api/http/services")
}

// getGatewayMiddlewares proxies GET /api/http/middlewares from Traefik's dashboard API.
// Route: GET /api/v1/monitoring-service/gateway/middlewares
func (s *Server) getGatewayMiddlewares(c *gin.Context) {
	s.proxyTraefikJSON(c, "/api/http/middlewares")
}
