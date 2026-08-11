package handlers

import (
	"testing"

	"github.com/gin-gonic/gin"
)

// TestCertificateRoutesRegister guards the certificate route wiring (
// added create / upload / update / history / search / by-issuer alongside the
// existing reads). gin panics at registration time on a conflicting route tree
// — notably the new static `search` / `by-issuer` siblings of the `:id` param
// and the new `:id/history` — so registering the exact set cmd/main.go installs
// without panicking is the assertion.
func TestCertificateRoutesRegister(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := NewCertificateHandler(&stubCertificateStore{})
	r := gin.New()
	g := r.Group("/api/v1")
	g.GET("/inventory-service/certificates", h.GetCertificates)
	g.GET("/inventory-service/certificates/expiring", h.GetExpiringCertificates)
	g.GET("/inventory-service/certificates/search", h.SearchCertificates)
	g.GET("/inventory-service/certificates/by-issuer/:issuer", h.GetCertificatesByIssuer)
	g.POST("/inventory-service/certificates", h.CreateCertificate)
	g.POST("/inventory-service/certificates/upload", h.UploadCertificate)
	g.POST("/inventory-service/certificates/rebuild-all-chains", h.RebuildAllCertificateChains)
	g.GET("/inventory-service/certificates/:id", h.GetCertificateByID)
	g.GET("/inventory-service/certificates/:id/chain", h.GetCertificateChain)
	g.GET("/inventory-service/certificates/:id/history", h.GetCertificateHistory)
	g.PUT("/inventory-service/certificates/:id", h.UpdateCertificate)
	g.POST("/inventory-service/certificates/:id/rebuild-chain", h.RebuildCertificateChain)

	if len(r.Routes()) != 12 {
		t.Fatalf("expected 12 certificate routes registered, got %d", len(r.Routes()))
	}
}
