package api

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/certificates"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/config"
)

// rotateAgentCertificateRequest is the device-agent's renewal payload: a CSR for
// a freshly generated keypair (see device-agent/internal/api/certificate_rotation.go).
type rotateAgentCertificateRequest struct {
	CSR string `json:"csr" binding:"required"`
}

// rotateAgentCertificateResponse mirrors the field names the device-agent decodes.
type rotateAgentCertificateResponse struct {
	AgentID              string    `json:"agent_id"`
	ClientCert           string    `json:"client_cert"`
	ServerCACert         string    `json:"server_ca_cert"`
	CertificateExpiresAt time.Time `json:"certificate_expires_at"`
	Message              string    `json:"message"`
}

// resolveAgentOutboundTenant resolves (agent_id, owning tenant) for an
// AgentAuth-authenticated outbound request, WITHOUT a tenant JWT. It is the
// device-interrogation counterpart to sensor-manager's requireSensorOutboundAccess:
//
//   - Under enforced agent mTLS the tenant was already derived from the client
//     cert (CN == agent_id, chain-verified) and pinned to the context by
//     AgentAuth — that value is authoritative and used as-is.
//   - In fail-open mode AgentAuth sets only the agent id, so the tenant is
//     resolved from the agent row on the bypass connection.
//
// The tenant is always derived FROM the agent, so a request can only ever act on
// the tenant that owns that agent id — no cross-tenant vector.
func resolveAgentOutboundTenant(c *gin.Context, bypassDB *sql.DB) (uuid.UUID, uuid.UUID, bool) {
	agentID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid agent id format"})
		return uuid.Nil, uuid.Nil, false
	}
	// mTLS mode: AgentAuth already resolved + verified the tenant from the cert.
	if v, exists := c.Get("tenantID"); exists {
		if tid, ok := v.(uuid.UUID); ok && tid != uuid.Nil {
			return agentID, tid, true
		}
	}
	// Fail-open mode: resolve the owning tenant from the trusted-path agent id.
	if bypassDB == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "agent lookup not supported"})
		return uuid.Nil, uuid.Nil, false
	}
	var tenantID uuid.UUID
	if err := bypassDB.QueryRowContext(c.Request.Context(),
		`SELECT tenant_id FROM device_agents WHERE id = $1 AND deleted_at IS NULL`,
		agentID,
	).Scan(&tenantID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Agent not found"})
		return uuid.Nil, uuid.Nil, false
	}
	return agentID, tenantID, true
}

// rotateAgentCertificateHandler issues a replacement device-agent client
// certificate from a CSR, under AgentAuth (the agent authenticates with its
// current cert / trusted-path agent id). This is the device-agent's autonomous
// pre-expiry renewal — the analog of sensor-manager's RotateSensorCertificate.
//
// Before this endpoint existed the device-agent's renewal loop got a 404 on
// every attempt, so its ~12-month enrollment cert eventually expired with no
// path to renew and the agent went dark. This must exist before
// fail-closed agent mTLS is enabled in production.
//
// CertificateService.IssueCertificate persists the new cert and supersedes the
// prior active row in one transaction, so no separate revoke is needed;
// the old cert stops authenticating as soon as rotation commits, which is why
// the agent persists + reconfigures its transport immediately on the response.
func rotateAgentCertificateHandler(db, bypassDB *sql.DB) gin.HandlerFunc {
	cfg, _ := config.Load()
	var encryptionKey string
	if cfg != nil {
		encryptionKey = cfg.EncryptionMasterKey
	}
	certService := certificates.NewCertificateService(db, bypassDB, encryptionKey)
	caManager := certificates.NewCAManager(db, bypassDB)

	return func(c *gin.Context) {
		agentID, tenantID, ok := resolveAgentOutboundTenant(c, bypassDB)
		if !ok {
			return
		}

		var req rotateAgentCertificateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		// Issue + persist + supersede prior active cert (one tx).
		certPEM, err := certService.IssueCertificate(tenantID, agentID, req.CSR)
		if err != nil {
			log.Printf("rotateAgentCertificate: issue failed for agent %s: %v", agentID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to issue certificate from CSR"})
			return
		}

		// Server trust anchor. The per-tenant CA is the agent's CLIENT-cert
		// issuer. With fail-closed agent mTLS the agent connects to the dedicated
		// passthrough listener whose SERVER cert is the per-service mesh cert
		// (platform-CA-signed, NOT the tenant CA), so hand back the platform CA
		// as the server trust anchor. Falls back to the tenant CA when mTLS is
		// not enforced or the platform CA isn't mounted. Mirrors the registration
		// path — and returning the tenant CA here is exactly the trust-anchor
		// clobber that broke sensor rotation in.
		var serverCACert string
		if ca, caErr := caManager.GetActiveCA(tenantID); caErr == nil {
			serverCACert = ca.CACertPEM
		}
		if cfg != nil && cfg.AgentMTLSRequired {
			if pca, perr := os.ReadFile(cfg.PlatformCACertPath); perr == nil && len(pca) > 0 {
				serverCACert = string(pca)
			} else {
				log.Printf("rotateAgentCertificate: AGENT_MTLS_REQUIRED set but platform CA unreadable at %s: %v", cfg.PlatformCACertPath, perr)
			}
		}

		// Expiry from the freshly stored active row.
		var expiresAt time.Time
		if cert, cerr := certService.GetCertificate(agentID); cerr == nil {
			expiresAt = cert.ExpiresAt
		}

		c.JSON(http.StatusOK, rotateAgentCertificateResponse{
			AgentID:              agentID.String(),
			ClientCert:           certPEM,
			ServerCACert:         serverCACert,
			CertificateExpiresAt: expiresAt,
			Message:              "Certificate rotated successfully",
		})
	}
}
