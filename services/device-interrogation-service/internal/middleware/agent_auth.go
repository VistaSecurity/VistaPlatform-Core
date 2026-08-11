package middleware

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/certificates"
)

// AgentAuth authenticates device-agent outbound routes (jobs, results,
// heartbeat). Agents authenticate with the per-tenant mTLS client cert issued
// at registration (Subject CN == agent UUID, signed by the tenant's active
// agent CA).
//
// When requireMTLS is true the middleware FAILS CLOSED: a verified
// client cert is mandatory. The agent identity is taken from the cert CN (not
// the URL path), the tenant is derived from that identity, and the cert chain
// is verified against the tenant's active CA. Any missing/mismatched/unverified
// cert is rejected with 401. The dedicated agent-mTLS listener (see
// shared/http.NewAgentMTLSServer + cmd/main.go) terminates the agent's mTLS so
// the real client cert reaches this middleware via edge TLS passthrough.
//
// When requireMTLS is false the legacy behavior is preserved for
// dev/compose/non-passthrough deployments (the agent is resolved from the path
// id, and a mesh/service peer cert on the hop is not treated as an agent cert).
// This is the insecure path is closing; it is gated off by default and
// enabled via the chart's agentMtls toggle.
//
// These endpoints have no in-cluster service callers (agents are the only
// callers), so there is no trusted-proxy bypass — every caller must present
// its own agent cert when requireMTLS is on.
//
// RLS: this is an ingestion/bootstrap path — the tenant is the OUTPUT of the
// agent-id lookup, so the resolve query and the cert-chain CA lookup run on the
// BYPASSRLS (crypto_bypass) connection (mirrors sensor-manager SensorAuth). Once
// tenantID is resolved it is pinned to the gin context for downstream handlers,
// which set app.tenant_id themselves. Pre-flip bypassDB resolves to the same
// connection as db.
func AgentAuth(db, bypassDB *sql.DB, requireMTLS bool) gin.HandlerFunc {
	certService := certificates.NewCertificateService(db, bypassDB, "")

	return func(c *gin.Context) {
		agentIDStr := c.Param("id")
		if agentIDStr == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Missing agent id parameter"})
			c.Abort()
			return
		}

		agentID, err := uuid.Parse(agentIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid agent id format"})
			c.Abort()
			return
		}

		c.Set("agent_id", agentID)
		c.Set("agent_id_str", agentIDStr)

		hasPeerCert := c.Request.TLS != nil && len(c.Request.TLS.PeerCertificates) > 0

		// Fail closed: no verified mTLS peer cert => reject. This is the core
		// fix — previously a request with no client cert was allowed
		// through with zero agent authentication.
		if requireMTLS && !hasPeerCert {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Client certificate required for agent endpoints"})
			c.Abort()
			return
		}
		if requireMTLS && db == nil {
			// Misconfiguration: cannot verify the cert chain without DB access.
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Agent authentication unavailable"})
			c.Abort()
			return
		}

		// When agent mTLS is required, the client cert IS the agent cert
		// (presented via the dedicated agent passthrough listener), so its CN
		// must match the route param. Gated on requireMTLS: with serviceMtls on
		// but agent mTLS off, the peer cert on this hop is the *mesh* cert
		// (CN = a service identity, already validated by the mesh), NOT an
		// agent cert; validating it as one would 401 every request.
		if requireMTLS && hasPeerCert {
			leaf := c.Request.TLS.PeerCertificates[0]
			if leaf.Subject.CommonName != agentIDStr {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "mTLS certificate CN does not match agent id"})
				c.Abort()
				return
			}
			now := time.Now()
			if now.After(leaf.NotAfter) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "mTLS certificate has expired"})
				c.Abort()
				return
			}
			if now.Before(leaf.NotBefore) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "mTLS certificate is not yet valid"})
				c.Abort()
				return
			}
		}

		// Resolve tenant from the agent identity (== verified CN when a cert is
		// present). Tenant is NOT taken from any client-supplied header.
		var tenantID uuid.UUID
		if db != nil {
			// Bootstrap/ingestion lookup: tenant is the OUTPUT → bypass role.
			err := bypassDB.QueryRow(
				`SELECT tenant_id FROM device_agents WHERE id = $1 AND deleted_at IS NULL`,
				agentID,
			).Scan(&tenantID)
			if err == sql.ErrNoRows {
				c.JSON(http.StatusNotFound, gin.H{"error": "Agent not registered"})
				c.Abort()
				return
			}
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve agent"})
				c.Abort()
				return
			}
			c.Set("tenantID", tenantID)
		}

		// Verify the client cert chains to the tenant's active agent CA only in
		// agent-mTLS mode (see above: outside it the peer cert is the mesh cert,
		// not an agent cert).
		if requireMTLS && hasPeerCert && db != nil {
			leaf := c.Request.TLS.PeerCertificates[0]
			if err := verifyAgentCertChain(db, bypassDB, tenantID, leaf); err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "mTLS certificate chain validation failed"})
				c.Abort()
				return
			}
		}

		if requireMTLS && hasPeerCert && db != nil {
			leaf := c.Request.TLS.PeerCertificates[0]
			cert, err := certService.GetCertificate(agentID)
			if err == sql.ErrNoRows {
				hasHistory, historyErr := certService.HasCertificateHistory(agentID)
				if historyErr != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "mTLS certificate status unavailable"})
					c.Abort()
					return
				}
				if hasHistory {
					c.JSON(http.StatusUnauthorized, gin.H{"error": "mTLS certificate is not active"})
					c.Abort()
					return
				}
				// Legacy agents enrolled before active-cert persistence have a
				// CA-valid leaf cert on disk but no agent_certificates row. Bind
				// that first verified cert once so fail-closed mTLS migrations do
				// not strand them; explicit revocations/supersedes are rejected
				// above because they leave certificate history behind.
				leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
				if err := certService.StoreCertificate(agentID, tenantID, string(leafPEM), leaf.SerialNumber.String(), leaf.NotBefore, leaf.NotAfter); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "mTLS certificate status unavailable"})
					c.Abort()
					return
				}
				c.Next()
				return
			}
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "mTLS certificate status unavailable"})
				c.Abort()
				return
			}
			if cert == nil || cert.SerialNumber != leaf.SerialNumber.String() {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "mTLS certificate is not the active certificate"})
				c.Abort()
				return
			}
		}

		if !requireMTLS && !hasPeerCert {
			log.Printf("AgentAuth: WARNING agent %s authenticated WITHOUT a client certificate (AGENT_MTLS_REQUIRED is off)", agentIDStr)
		}

		c.Next()
	}
}

// verifyAgentCertChain verifies leaf against the tenant's active agent CA with
// clientAuth EKU. Returns an error if the CA cannot be loaded/parsed or the
// chain does not verify.
func verifyAgentCertChain(db, bypassDB *sql.DB, tenantID uuid.UUID, leaf *x509.Certificate) error {
	caManager := certificates.NewCAManager(db, bypassDB)
	ca, err := caManager.GetActiveCA(tenantID)
	if err != nil {
		return err
	}
	caBlock, _ := pem.Decode([]byte(ca.CACertPEM))
	if caBlock == nil {
		return errFailedToDecodeCA
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return err
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err
}

var errFailedToDecodeCA = &agentAuthError{"failed to decode tenant CA PEM"}

type agentAuthError struct{ msg string }

func (e *agentAuthError) Error() string { return e.msg }
