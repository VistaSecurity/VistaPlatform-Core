package registration

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/certificates"
)

// Certificate represents a stored certificate for a tenant
type Certificate struct {
	ClientCert   string
	ServerCACert string
	PrivateKey   string
	ExpiresAt    time.Time
	TenantID     uuid.UUID
}

// AutoRegisterService handles auto-registration of platform sensors
type AutoRegisterService struct {
	config       *config.Config
	db           *sqlx.DB
	certificates map[uuid.UUID]*Certificate // tenant ID -> certificate
	certMutex    sync.RWMutex
	certDir      string
	sensorID     uuid.UUID
}

// NewAutoRegisterService creates a new auto-registration service
func NewAutoRegisterService(cfg *config.Config, db *sqlx.DB) (*AutoRegisterService, error) {
	// Parse fixed sensor ID
	sensorID, err := uuid.Parse(cfg.PlatformDiscoverySensorID)
	if err != nil {
		return nil, fmt.Errorf("invalid platform discovery sensor ID: %w", err)
	}

	// Create certificate directory
	certDir := "/app/certs"
	if err := os.MkdirAll(certDir, 0700); err != nil {
		// Fallback to /tmp if /app/certs doesn't exist (e.g., in dev)
		certDir = "/tmp/cluster-sensor-certs"
		_ = os.MkdirAll(certDir, 0700)
	}

	service := &AutoRegisterService{
		config:       cfg,
		db:           db,
		certificates: make(map[uuid.UUID]*Certificate),
		certDir:      certDir,
		sensorID:     sensorID,
	}

	// Load existing certificates from file system
	service.loadCertificatesFromDisk()

	return service, nil
}

// RegisterForAllTenants registers the platform sensor for all active tenants
func (s *AutoRegisterService) RegisterForAllTenants() error {
	// RLS: the tenants table is global (no tenant_isolation policy), so this
	// platform-wide enumeration is left unwrapped — crypto_app has a grant and
	// there is no RLS to satisfy. (Phase 4: still reads fine on the app role.)
	// Query all active tenants
	query := `
		SELECT id
		FROM tenants
		WHERE deleted_at IS NULL
		ORDER BY created_at ASC
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return fmt.Errorf("failed to query tenants: %w", err)
	}
	defer rows.Close()

	var tenantIDs []uuid.UUID
	for rows.Next() {
		var tenantID uuid.UUID
		if err := rows.Scan(&tenantID); err != nil {
			continue
		}
		tenantIDs = append(tenantIDs, tenantID)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("failed to scan tenants: %w", err)
	}

	// Register for each tenant
	var errors []error
	for _, tenantID := range tenantIDs {
		if err := s.RegisterForTenant(tenantID); err != nil {
			errors = append(errors, fmt.Errorf("failed to register for tenant %s: %w", tenantID, err))
			// Continue with other tenants even if one fails
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("registration completed with %d errors: %v", len(errors), errors)
	}

	return nil
}

// RegisterForTenant registers the platform sensor for a specific tenant
func (s *AutoRegisterService) RegisterForTenant(tenantID uuid.UUID) error {
	// Check if we already have a valid certificate for this tenant
	s.certMutex.RLock()
	cert, exists := s.certificates[tenantID]
	s.certMutex.RUnlock()

	if exists && cert != nil && time.Now().Before(cert.ExpiresAt.Add(-30*24*time.Hour)) {
		// Certificate exists and is valid (not expiring within 30 days)
		return nil
	}

	// Generate keypair and CSR
	csrGen := certificates.NewCSRGenerator()
	privateKey, err := csrGen.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %w", err)
	}

	csrPEM, err := csrGen.GenerateCSR(s.sensorID, privateKey)
	if err != nil {
		return fmt.Errorf("failed to generate CSR: %w", err)
	}

	// Encode private key
	privateKeyPEM, err := csrGen.EncodePrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	// Call auto-registration endpoint
	reqBody := map[string]interface{}{
		"sensor_id": s.sensorID.String(),
		"tenant_id": tenantID.String(),
		"csr":       csrPEM,
		"name":      "Platform Discovery Sensor",
		"platform":  "platform",
		"version":   platformAgentVersion(),
		"profile":   "discovery",
		"tags":      []string{"system", "discovery", "platform"},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/sensor-manager/sensors/auto-register", s.config.SensorManagerURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Create HTTP client with mTLS using bootstrap certificates
	client, err := s.createMTLSClient()
	if err != nil {
		return fmt.Errorf("failed to create mTLS client: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("auto-registration failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var response struct {
		SensorID             string `json:"sensor_id"`
		TenantID             string `json:"tenant_id"`
		ClientCert           string `json:"client_cert"`
		ServerCACert         string `json:"server_ca_cert"`
		CertificateExpiresAt string `json:"certificate_expires_at"`
		Message              string `json:"message"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	// Parse expiration
	expiresAt, err := time.Parse(time.RFC3339, response.CertificateExpiresAt)
	if err != nil {
		// Default to 1 year from now if parsing fails
		expiresAt = time.Now().AddDate(1, 0, 0)
	}

	// Store certificate
	cert = &Certificate{
		ClientCert:   response.ClientCert,
		ServerCACert: response.ServerCACert,
		PrivateKey:   privateKeyPEM,
		ExpiresAt:    expiresAt,
		TenantID:     tenantID,
	}

	s.certMutex.Lock()
	s.certificates[tenantID] = cert
	s.certMutex.Unlock()

	// Save to disk
	if err := s.saveCertificateToDisk(tenantID, cert); err != nil {
		// Log error but don't fail registration
		fmt.Printf("Warning: Failed to save certificate to disk: %v\n", err)
	}

	return nil
}

// GetCertificate retrieves a certificate for a tenant
func (s *AutoRegisterService) GetCertificate(tenantID uuid.UUID) (*Certificate, error) {
	s.certMutex.RLock()
	defer s.certMutex.RUnlock()

	cert, exists := s.certificates[tenantID]
	if !exists || cert == nil {
		return nil, fmt.Errorf("certificate not found for tenant %s", tenantID)
	}

	return cert, nil
}

// loadCertificatesFromDisk loads certificates from the file system
func (s *AutoRegisterService) loadCertificatesFromDisk() {
	// Try to load certificates from disk
	// File naming: {sensor-id}-{tenant-id}-cert.pem, {sensor-id}-{tenant-id}-key.pem, {sensor-id}-{tenant-id}-ca.pem
	pattern := filepath.Join(s.certDir, fmt.Sprintf("%s-*-cert.pem", s.sensorID.String()))
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return // No certificates found or error
	}

	for _, certFile := range matches {
		// Extract tenant ID from filename
		// Format: {sensor-id}-{tenant-id}-cert.pem
		base := filepath.Base(certFile)
		// Remove {sensor-id}- and -cert.pem
		tenantIDStr := base[len(s.sensorID.String())+1 : len(base)-9] // Remove sensor ID prefix and "-cert.pem" suffix
		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			continue
		}

		// Load certificate files
		certPEM, err := os.ReadFile(certFile) //nolint:gosec // intentional — certFile from filepath.Glob over s.certDir, filename validated as {sensorID}-{tenantUUID}-cert.pem
		if err != nil {
			continue
		}

		keyFile := filepath.Join(s.certDir, fmt.Sprintf("%s-%s-key.pem", s.sensorID.String(), tenantID.String()))
		keyPEM, err := os.ReadFile(keyFile) //nolint:gosec // intentional — keyFile path built from server-validated certDir + sensorID UUID + tenantID UUID
		if err != nil {
			continue
		}

		caFile := filepath.Join(s.certDir, fmt.Sprintf("%s-%s-ca.pem", s.sensorID.String(), tenantID.String()))
		caPEM, err := os.ReadFile(caFile) //nolint:gosec // intentional — caFile path built from server-validated certDir + sensorID UUID + tenantID UUID
		if err != nil {
			continue
		}

		// Parse certificate to get expiration
		block, _ := pem.Decode(certPEM)
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		s.certMutex.Lock()
		s.certificates[tenantID] = &Certificate{
			ClientCert:   string(certPEM),
			ServerCACert: string(caPEM),
			PrivateKey:   string(keyPEM),
			ExpiresAt:    cert.NotAfter,
			TenantID:     tenantID,
		}
		s.certMutex.Unlock()
	}
}

// saveCertificateToDisk saves a certificate to the file system
func (s *AutoRegisterService) saveCertificateToDisk(tenantID uuid.UUID, cert *Certificate) error {
	baseName := fmt.Sprintf("%s-%s", s.sensorID.String(), tenantID.String())

	// Save certificate
	certFile := filepath.Join(s.certDir, fmt.Sprintf("%s-cert.pem", baseName))
	if err := os.WriteFile(certFile, []byte(cert.ClientCert), 0600); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}

	// Save private key
	keyFile := filepath.Join(s.certDir, fmt.Sprintf("%s-key.pem", baseName))
	if err := os.WriteFile(keyFile, []byte(cert.PrivateKey), 0600); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	// Save CA certificate
	caFile := filepath.Join(s.certDir, fmt.Sprintf("%s-ca.pem", baseName))
	if err := os.WriteFile(caFile, []byte(cert.ServerCACert), 0600); err != nil {
		return fmt.Errorf("failed to save CA certificate: %w", err)
	}

	return nil
}

// createMTLSClient creates an HTTP client configured with bootstrap mTLS certificates
func (s *AutoRegisterService) createMTLSClient() (*http.Client, error) {
	// Load bootstrap client certificate and key
	certPEM, err := os.ReadFile(s.config.BootstrapCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read bootstrap certificate: %w", err)
	}

	keyPEM, err := os.ReadFile(s.config.BootstrapKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read bootstrap private key: %w", err)
	}

	// Load certificate and key
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate and key: %w", err)
	}

	// Load CA certificate for server verification
	caCertPEM, err := os.ReadFile(s.config.BootstrapCACertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read bootstrap CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to parse bootstrap CA certificate")
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	// Create HTTP client with mTLS
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	return client, nil
}

// platformAgentVersion is what the in-cluster platform agent reports as its
// version at registration. The chart injects SERVICE_VERSION per pod (aligned
// with the image tag via helm), which is the truth about the running code —
// the old hardcoded "system" placeholder left the version column meaningless.
func platformAgentVersion() string {
	if v := os.Getenv("SERVICE_VERSION"); v != "" {
		// The chart injects the release tag ("v0.6.0"); the platform stores the
		// bare version and the UI renders it as v{version}, so strip the prefix.
		return strings.TrimPrefix(v, "v")
	}
	return "dev"
}
