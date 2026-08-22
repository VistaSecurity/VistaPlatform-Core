package handlers

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/certificates"
)

// RevokeCertificateRequest represents a certificate revocation request
type RevokeCertificateRequest struct {
	Reason string `json:"reason" binding:"required"`
}

// RevokeCertificateResponse represents the response to a revocation request
type RevokeCertificateResponse struct {
	SensorID  string    `json:"sensor_id"`
	RevokedAt time.Time `json:"revoked_at"`
	Reason    string    `json:"reason"`
	Message   string    `json:"message"`
}

// RotateCertificateRequest represents a certificate rotation request
type RotateCertificateRequest struct {
	CSR string `json:"csr" binding:"required"` // Certificate Signing Request (PEM format)
}

// RotateCertificateResponse represents the response to a rotation request
type RotateCertificateResponse struct {
	SensorID             string    `json:"sensor_id"`
	ClientCert           string    `json:"client_cert"`
	ServerCACert         string    `json:"server_ca_cert"`
	CertificateExpiresAt time.Time `json:"certificate_expires_at"`
	Message              string    `json:"message"`
}

// RevokeSensorCertificate revokes a sensor's certificate
func (h *Handler) RevokeSensorCertificate(c *gin.Context) {
	sensor, _, ok := h.requireSensorAccess(c)
	if !ok {
		return
	}
	sensorID := sensor.ID
	sensorIDStr := sensorID.String()

	var req RevokeCertificateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Validate reason
	validReasons := []string{"compromised", "expired", "rotated", "manual"}
	valid := false
	for _, r := range validReasons {
		if req.Reason == r {
			valid = true
			break
		}
	}
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid revocation reason. Must be one of: compromised, expired, rotated, manual"})
		return
	}

	// Initialize certificate service
	certService := certificates.NewCertificateService(h.sensorService.GetDB(), h.sensorService.GetBypassDB(), h.encryptionKey)

	// Revoke certificate
	err := certService.RevokeCertificate(sensorID, req.Reason)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke certificate"})
		return
	}

	// Get revoked certificate details
	cert, err := certService.GetCertificate(sensorID)
	if err != nil {
		// Certificate might not exist, but revocation was successful
		response := RevokeCertificateResponse{
			SensorID:  sensorIDStr,
			RevokedAt: time.Now(),
			Reason:    req.Reason,
			Message:   "Certificate revoked successfully",
		}
		c.JSON(http.StatusOK, response)
		return
	}

	response := RevokeCertificateResponse{
		SensorID:  sensorIDStr,
		RevokedAt: *cert.RevokedAt,
		Reason:    req.Reason,
		Message:   "Certificate revoked successfully",
	}

	c.JSON(http.StatusOK, response)
}

// RotateSensorCertificate rotates a sensor's certificate by issuing a new one
// from a CSR. This is the sensor's own autonomous pre-expiry renewal, so it runs
// under SensorAuth (the sensor authenticates with its current cert / trusted-path
// sensor_id) — NOT tenant-JWT+RBAC. It was previously mis-wired under the
// tenant-admin route group, so the certless sensor got a 401 on every renewal and
// its ~12-month enrollment cert eventually expired with no path to renew.
// Admin-initiated reissue remains available via RegenerateSensorCertificates.
func (h *Handler) RotateSensorCertificate(c *gin.Context) {
	sensorID, tenantID, ok := h.requireSensorOutboundAccess(c)
	if !ok {
		return
	}
	sensorIDStr := sensorID.String()

	var req RotateCertificateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Initialize certificate service
	certService := certificates.NewCertificateService(h.sensorService.GetDB(), h.sensorService.GetBypassDB(), h.encryptionKey)

	// Get the client-cert issuer CA before issuing. After IssueCertificate stores
	// the replacement, the sensor's old cert is no longer the active serial.
	// Avoid introducing any fail-fast work after that point.
	caManager := certificates.NewCAManager(h.sensorService.GetDB(), h.sensorService.GetBypassDB())
	ca, err := caManager.GetOrCreateActiveCA(tenantID, h.encryptionKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get CA certificate"})
		return
	}

	// Issue new certificate from CSR
	certPEM, err := certService.IssueCertificate(tenantID, sensorID, req.CSR)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to issue certificate from CSR"})
		return
	}

	certificateExpiresAt := time.Now().AddDate(1, 0, 0)
	serialNumber := ""
	if block, _ := pem.Decode([]byte(certPEM)); block != nil {
		if cert, parseErr := x509.ParseCertificate(block.Bytes); parseErr == nil {
			certificateExpiresAt = cert.NotAfter
			serialNumber = cert.SerialNumber.String()
		}
	}
	if serialNumber != "" {
		if err := certService.RevokeCertificatesExcept(sensorID, serialNumber, "rotated"); err != nil && h.log != nil {
			h.log.WithError(err).WithField("sensor_id", sensorIDStr).Warn("failed to revoke previous sensor certificates after rotation")
		}
	}

	response := RotateCertificateResponse{
		SensorID:             sensorIDStr,
		ClientCert:           certPEM,
		ServerCACert:         advertisedServerCACert(ca.CACertPEM),
		CertificateExpiresAt: certificateExpiresAt,
		Message:              "Certificate rotated successfully",
	}

	c.JSON(http.StatusOK, response)
}

// GetSensorCertificate retrieves the current certificate for a sensor
func (h *Handler) GetSensorCertificate(c *gin.Context) {
	sensor, _, ok := h.requireSensorAccess(c)
	if !ok {
		return
	}
	sensorID := sensor.ID

	// Initialize certificate service
	certService := certificates.NewCertificateService(h.sensorService.GetDB(), h.sensorService.GetBypassDB(), h.encryptionKey)

	// Get certificate
	cert, err := certService.GetCertificate(sensorID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"sensor_id":         cert.SensorID.String(),
		"certificate_pem":   cert.CertificatePEM,
		"serial_number":     cert.SerialNumber,
		"issued_at":         cert.IssuedAt,
		"expires_at":        cert.ExpiresAt,
		"revoked_at":        cert.RevokedAt,
		"revocation_reason": cert.RevocationReason,
		"is_revoked":        cert.RevokedAt != nil,
		"is_expired":        time.Now().After(cert.ExpiresAt),
		"days_until_expiry": int(time.Until(cert.ExpiresAt).Hours() / 24),
	})
}
