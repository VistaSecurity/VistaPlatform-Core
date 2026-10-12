package api

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/certificates"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/config"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
)

// rotateAgentCertificateRequest is the device-agent's renewal payload: a CSR for
// a freshly generated keypair (see device-agent/internal/api/certificate_rotation.go).
type rotateAgentCertificateRequest struct {
	CSR string `json:"csr" binding:"required"`
	// SupportsAgentSecret is sent by an agent build that stores the per-agent
	// secret. Without it rotation changes nothing about the agent's
	// credential key: an older build would ignore a new secret the platform then
	// sealed under, and every credentialed job would fail to open.
	SupportsAgentSecret bool `json:"supports_agent_secret,omitempty"`
}

// rotateAgentCertificateResponse mirrors the field names the device-agent decodes.
type rotateAgentCertificateResponse struct {
	AgentID              string    `json:"agent_id"`
	ClientCert           string    `json:"client_cert"`
	ServerCACert         string    `json:"server_ca_cert"`
	CertificateExpiresAt time.Time `json:"certificate_expires_at"`
	Message              string    `json:"message"`
	// AgentSecret is the replacement per-agent secret, present only when
	// the request asked for one. The secret it replaces stays valid ON THE AGENT
	// for agentcreds.PreviousSecretWindow so a job sealed just before the
	// rotation still opens; the platform seals with this one from now on.
	AgentSecret        string `json:"agent_secret,omitempty"`
	AgentSecretVersion int    `json:"agent_secret_version,omitempty"`
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
	agentService := services.NewAgentService(db, bypassDB, nil)

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

		// Identity-change guard (H4). Rotation mints a new, legitimately
		// CA-signed certificate for this agent and supersedes the old one, so it
		// must be at least as strong as the identity it rotates. AgentAuth alone
		// is NOT sufficient: with AGENT_MTLS_REQUIRED off it accepts the path id
		// (or X-Agent-ID header) as the entire authenticator, and neither is a
		// secret. This check is unconditional — it does not consult
		// AGENT_MTLS_REQUIRED — so rotation is refused rather than granted when
		// no proof can be presented. Mirrors sensor-manager's sensor-side guard.
		if err := certService.VerifyPresentedIdentity(tenantID, agentID, c.Request.TLS); err != nil {
			log.Printf("rotateAgentCertificate: refused for agent %s, identity not proven: %v", agentID, err)
			if errors.Is(err, certificates.ErrClientCertificateRequired) {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": "Certificate rotation requires the agent's current client certificate",
					"detail": "This request presented no client certificate, so it cannot prove it already holds the identity it is asking to re-issue. " +
						"The agent must reach device-interrogation-service over the agent mTLS passthrough listener with its current certificate. " +
						"On Kubernetes set agentMtls.enabled=true (with agentMtls.backends.device-interrogation-service.dnsName) in the Helm chart. " +
						"An agent that no longer holds a valid certificate must be re-enrolled with a registration key.",
				})
				return
			}
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":  "Presented certificate is not this agent's current certificate",
				"detail": "Rotation is only granted to the holder of the agent's active certificate. Re-enroll the agent with a registration key if its certificate was revoked, superseded or lost.",
			})
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

		resp := rotateAgentCertificateResponse{
			AgentID:              agentID.String(),
			ClientCert:           certPEM,
			ServerCACert:         serverCACert,
			CertificateExpiresAt: expiresAt,
			Message:              "Certificate rotated successfully",
		}

		// The new per-agent secret rides on the certificate rotation.
		// It is issued AFTER the certificate, and a failure here is not allowed
		// to withhold the certificate: the old one is already superseded, so the
		// agent must receive its replacement. With no secret in the response the
		// agent keeps the one it has, which is still the one the platform seals
		// with, so nothing is left half-switched. The next rotation retries.
		if req.SupportsAgentSecret {
			secret, version, serr := agentService.RotateAgentSecret(c.Request.Context(), agentID)
			if serr != nil {
				log.Printf("rotateAgentCertificate: agent secret NOT rotated for agent %s (certificate was): %v", agentID, serr)
			} else {
				resp.AgentSecret = secret
				resp.AgentSecretVersion = version
			}
		}

		c.JSON(http.StatusOK, resp)
	}
}
