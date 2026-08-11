package api

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor/internal/certificates"
)

// RotateCertificate rotates the sensor's certificate by generating a new CSR and requesting a new certificate
func (c *SensorManagerClient) RotateCertificate() error {
	// Parse current sensor ID
	sensorID, err := uuid.Parse(c.config.SensorID)
	if err != nil {
		return fmt.Errorf("invalid sensor ID: %v", err)
	}

	// Load existing private key or generate new one
	var privateKey interface{}
	csrGen := certificates.NewCSRGenerator()

	if c.config.Security.ClientKey != "" {
		// Try to parse existing private key
		key, err := csrGen.ParsePrivateKey(c.config.Security.ClientKey)
		if err != nil {
			// If we can't parse it, generate a new keypair
			newKey, err := csrGen.GenerateKeyPair()
			if err != nil {
				return fmt.Errorf("failed to generate new keypair: %v", err)
			}
			privateKey = newKey
		} else {
			privateKey = key
		}
	} else {
		// No existing key, generate new one
		newKey, err := csrGen.GenerateKeyPair()
		if err != nil {
			return fmt.Errorf("failed to generate keypair: %v", err)
		}
		privateKey = newKey
	}

	// Type assert to *rsa.PrivateKey
	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("invalid private key type")
	}

	// Generate new CSR
	csrPEM, err := csrGen.GenerateCSR(sensorID, rsaKey)
	if err != nil {
		return fmt.Errorf("failed to generate CSR: %v", err)
	}

	// Encode private key for storage
	privateKeyPEM, err := csrGen.EncodePrivateKey(rsaKey)
	if err != nil {
		return fmt.Errorf("failed to encode private key: %v", err)
	}

	// Request certificate rotation
	rotationReq := map[string]interface{}{
		"csr": csrPEM,
	}

	jsonData, err := json.Marshal(rotationReq)
	if err != nil {
		return fmt.Errorf("failed to marshal rotation request: %v", err)
	}

	url := fmt.Sprintf("%s/api/v1/sensor-manager/sensors/%s/certificates/rotate", c.baseURL, c.config.SensorID)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create rotation request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Use existing certificate for authentication during rotation
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send rotation request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("certificate rotation failed with status %d: %s", resp.StatusCode, string(body))
	}

	var rotationResp struct {
		SensorID             string    `json:"sensor_id"`
		ClientCert           string    `json:"client_cert"`
		ServerCACert         string    `json:"server_ca_cert"`
		CertificateExpiresAt time.Time `json:"certificate_expires_at"`
		Message              string    `json:"message"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&rotationResp); err != nil {
		return fmt.Errorf("failed to decode rotation response: %v", err)
	}

	// Update configuration with new certificate
	c.config.Security.ClientCert = rotationResp.ClientCert
	c.config.Security.ClientKey = privateKeyPEM // Store new private key
	if rotationResp.ServerCACert != "" {
		c.config.Security.ServerCACert = rotationResp.ServerCACert
	}

	// Reconfigure HTTP client with new certificate
	if err := c.reconfigureTLS(); err != nil {
		return fmt.Errorf("failed to reconfigure TLS after rotation: %v", err)
	}

	return nil
}

// CheckCertificateExpiration checks if the current certificate is expiring soon
func (c *SensorManagerClient) CheckCertificateExpiration() (time.Time, bool, error) {
	if c.config.Security.ClientCert == "" {
		return time.Time{}, false, fmt.Errorf("no certificate configured")
	}

	// Parse certificate
	block, _ := pem.Decode([]byte(c.config.Security.ClientCert))
	if block == nil {
		return time.Time{}, false, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("failed to parse certificate: %v", err)
	}

	expiresAt := cert.NotAfter
	now := time.Now()
	expiringSoon := expiresAt.Sub(now) < 30*24*time.Hour // Expiring within 30 days

	return expiresAt, expiringSoon, nil
}

// reconfigureTLS reconfigures the HTTP client with updated certificates
func (c *SensorManagerClient) reconfigureTLS() error {
	if !c.config.Security.UseTLS || c.config.Security.ClientCert == "" || c.config.Security.ClientKey == "" {
		return nil // TLS not enabled or certificates not configured
	}

	// Load certificate from PEM strings (not files)
	cert, err := tls.X509KeyPair([]byte(c.config.Security.ClientCert), []byte(c.config.Security.ClientKey))
	if err != nil {
		return fmt.Errorf("failed to load certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Add server CA if provided
	if c.config.Security.ServerCACert != "" {
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM([]byte(c.config.Security.ServerCACert)) {
			return fmt.Errorf("failed to parse server CA certificate")
		}
		tlsConfig.RootCAs = caPool
	}

	c.httpClient.Transport = &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return nil
}
