package handlers

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/certificates"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/config"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	sharedmodels "github.com/vistasecurity/vistaplatform/shared/models"
)

// AutoRegisterAgentRequest represents an auto-registration request from a platform service
type AutoRegisterAgentRequest struct {
	AgentID  string `json:"agent_id" binding:"required"`  // Fixed agent ID (e.g., "platform-device-interrogation-agent")
	TenantID string `json:"tenant_id" binding:"required"` // Tenant ID to register for
	CSR      string `json:"csr" binding:"required"`       // Certificate Signing Request (PEM format)
	Platform string `json:"platform,omitempty"`           // Optional: platform (defaults to "platform")
	Version  string `json:"version,omitempty"`            // Optional: version (defaults to "system")
}

// AutoRegisterAgentResponse represents the response to an auto-registration request
type AutoRegisterAgentResponse struct {
	AgentID              string `json:"agent_id"`
	TenantID             string `json:"tenant_id"`
	ClientCert           string `json:"client_cert"`            // Signed certificate
	ServerCACert         string `json:"server_ca_cert"`         // CA certificate for trust
	CertificateExpiresAt string `json:"certificate_expires_at"` // Certificate expiration timestamp
	Message              string `json:"message"`
}

// AutoRegisterAgentHandler handles auto-registration of platform agents using service account authentication
// This endpoint is called by platform services (e.g., device-interrogation-service) to register themselves
// as agents for a specific tenant. It bypasses the normal registration key flow.
func AutoRegisterAgentHandler(db, bypassDB *sql.DB) gin.HandlerFunc {
	cfg, _ := config.Load()
	certService := certificates.NewCertificateService(db, bypassDB, cfg.EncryptionMasterKey)

	return func(c *gin.Context) {
		// Get service account from context (set by middleware)
		serviceAccountVal, exists := c.Get("serviceAccount")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Service account not found in context"})
			return
		}

		serviceAccount, ok := serviceAccountVal.(*sharedmodels.ServiceAccount)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid service account type"})
			return
		}

		// Only allow device-interrogation-service to register agents
		if serviceAccount.ServiceName != "device-interrogation-service" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Service account not authorized for agent registration"})
			return
		}

		var req AutoRegisterAgentRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		// Parse tenant ID
		tenantID, err := uuid.Parse(req.TenantID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant_id format"})
			return
		}

		// Parse agent ID (must be a valid UUID)
		agentID, err := uuid.Parse(req.AgentID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid agent_id format"})
			return
		}

		// Validate CSR
		if req.CSR == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "CSR is required"})
			return
		}

		// Parse and validate CSR
		csrBlock, _ := pem.Decode([]byte(req.CSR))
		if csrBlock == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid CSR format"})
			return
		}

		csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse CSR"})
			return
		}

		// Validate CSR signature
		if err := csr.CheckSignature(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "CSR signature validation failed"})
			return
		}

		// Validate CSR Common Name matches agent ID
		if csr.Subject.CommonName != agentID.String() {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("CSR Common Name '%s' does not match agent_id '%s'", csr.Subject.CommonName, agentID.String()),
			})
			return
		}

		// Set defaults
		platform := req.Platform
		if platform == "" {
			platform = "platform"
		}
		version := req.Version
		if version == "" {
			version = "system"
		}

		// Check if encryption key is configured
		if cfg.EncryptionMasterKey == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption key not configured"})
			return
		}

		// Upsert the agent under the request's tenant scope. tenantID is an INPUT
		// (validated from the request body), so the whole find-or-create runs inside
		// one WithTenantTx (device_agents is RLS-scoped).
		ctx := c.Request.Context()
		now := time.Now()
		query := `
			SELECT id, tenant_id, platform, version, status, last_heartbeat, created_at, updated_at
			FROM device_agents
			WHERE id = $1 AND tenant_id = $2
		`
		updateQuery := `
			UPDATE device_agents
			SET platform = $1, version = $2, status = 'active', last_heartbeat = $3, updated_at = $3
			WHERE id = $4 AND tenant_id = $5
		`
		insertQuery := `
			INSERT INTO device_agents (id, tenant_id, registration_key, platform, version, status, created_at, updated_at, last_heartbeat)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (id) DO UPDATE SET
				platform = EXCLUDED.platform,
				version = EXCLUDED.version,
				status = EXCLUDED.status,
				updated_at = EXCLUDED.updated_at,
				last_heartbeat = EXCLUDED.last_heartbeat
		`
		upsertErr := shareddatabase.WithTenantTx(ctx, db, tenantID, func(tx *sql.Tx) error {
			var existingAgent models.Agent
			selErr := tx.QueryRowContext(ctx, query, agentID, tenantID).Scan(
				&existingAgent.ID,
				&existingAgent.TenantID,
				&existingAgent.Platform,
				&existingAgent.Version,
				&existingAgent.Status,
				&existingAgent.LastHeartbeat,
				&existingAgent.CreatedAt,
				&existingAgent.UpdatedAt,
			)
			if selErr == nil {
				_, e := tx.ExecContext(ctx, updateQuery, platform, version, now, agentID, tenantID)
				return e
			}
			if selErr != sql.ErrNoRows {
				return selErr
			}
			// Use empty registration key for auto-registered agents
			_, e := tx.ExecContext(ctx, insertQuery, agentID, tenantID, "", platform, version, "active", now, now, now)
			return e
		})
		if upsertErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to register agent",
			})
			return
		}

		// Issue certificate from CSR after the agent row exists so the
		// persisted certificate can satisfy the agent_certificates FK.
		certPEM, err := certService.IssueCertificate(tenantID, agentID, req.CSR)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to issue certificate from CSR",
			})
			return
		}

		// Get CA certificate
		caManager := certificates.NewCAManager(db, bypassDB)
		ca, err := caManager.GetOrCreateActiveCA(tenantID, cfg.EncryptionMasterKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to get CA certificate",
			})
			return
		}

		// Parse certificate to get expiration
		certBlock, _ := pem.Decode([]byte(certPEM))
		if certBlock == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode issued certificate"})
			return
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to parse issued certificate",
			})
			return
		}

		// Return response
		response := AutoRegisterAgentResponse{
			AgentID:              agentID.String(),
			TenantID:             tenantID.String(),
			ClientCert:           certPEM,
			ServerCACert:         ca.CACertPEM,
			CertificateExpiresAt: cert.NotAfter.Format(time.RFC3339),
			Message:              "Platform agent registered successfully",
		}

		c.JSON(http.StatusOK, response)
	}
}
