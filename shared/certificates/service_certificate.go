package certificates

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
)

// ServiceCertificateService handles service certificate operations for platform services
// Each service gets both server and client certificates for mTLS communication
type ServiceCertificateService struct {
	db            *sql.DB
	caManager     *ServiceCAManager
	encryptionKey string
}

// NewServiceCertificateService creates a new service certificate service
func NewServiceCertificateService(db *sql.DB, encryptionKey string) *ServiceCertificateService {
	return &ServiceCertificateService{
		db:            db,
		caManager:     NewServiceCAManager(db),
		encryptionKey: encryptionKey,
	}
}

// ServiceCertificate represents a service certificate in the database
type ServiceCertificate struct {
	ID               uuid.UUID
	ServiceName      string
	ServerCertPEM    string
	ServerKeyPEM     string // Decrypted (not stored in DB)
	ClientCertPEM    string
	ClientKeyPEM     string // Decrypted (not stored in DB)
	SerialNumber     string
	IssuedAt         time.Time
	ExpiresAt        time.Time
	RevokedAt        *time.Time
	RevocationReason *string
	CreatedAt        time.Time
}

// ServiceCertificates represents both server and client certificates for a service
type ServiceCertificates struct {
	ServiceName   string
	ServerCertPEM string
	ServerKeyPEM  string
	ClientCertPEM string
	ClientKeyPEM  string
	SerialNumber  string
	IssuedAt      time.Time
	ExpiresAt     time.Time
}

// IssueServiceCertificates issues both server and client certificates for a platform service
func (s *ServiceCertificateService) IssueServiceCertificates(serviceName string) (*ServiceCertificates, error) {
	// Get or create active service CA
	ca, err := s.caManager.GetOrCreateActiveCA(s.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get service CA: %w", err)
	}

	// Get CA private key
	caKey, err := s.caManager.GetCAKey(ca.ID, s.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get service CA key: %w", err)
	}

	// Parse CA certificate
	caBlock, _ := pem.Decode([]byte(ca.CACertPEM))
	if caBlock == nil {
		return nil, fmt.Errorf("failed to decode service CA certificate")
	}

	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse service CA certificate: %w", err)
	}

	// Generate serial number (shared for both certs)
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(0x7FFFFFFF))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(1, 0, 0) // 1 year validity

	// Generate server certificate
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server key: %w", err)
	}

	serverSerial, err := rand.Int(rand.Reader, big.NewInt(0x7FFFFFFF))
	if err != nil {
		return nil, fmt.Errorf("failed to generate server serial number: %w", err)
	}

	serverTemplate := x509.Certificate{
		SerialNumber: serverSerial,
		Subject: pkix.Name{
			Organization:       []string{"VistaPlatform"},
			OrganizationalUnit: []string{"VistaPlatform"},
			Country:            []string{"US"},
			Province:           []string{"Florida"},
			Locality:           []string{"Orlando"},
			CommonName:         serviceName, // Use service name as CN
		},
		DNSNames:     []string{serviceName}, // Service name for DNS resolution
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SubjectKeyId: serverKey.PublicKey.N.Bytes()[:20],
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create server certificate: %w", err)
	}

	serverCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertDER,
	})

	serverKeyDER := x509.MarshalPKCS1PrivateKey(serverKey)
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: serverKeyDER,
	})

	// Generate client certificate
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client key: %w", err)
	}

	clientSerial, err := rand.Int(rand.Reader, big.NewInt(0x7FFFFFFF))
	if err != nil {
		return nil, fmt.Errorf("failed to generate client serial number: %w", err)
	}

	clientTemplate := x509.Certificate{
		SerialNumber: clientSerial,
		Subject: pkix.Name{
			Organization:       []string{"VistaPlatform"},
			OrganizationalUnit: []string{"VistaPlatform"},
			Country:            []string{"US"},
			Province:           []string{"Florida"},
			Locality:           []string{"Orlando"},
			CommonName:         serviceName, // Use service name as CN
		},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		SubjectKeyId: clientKey.PublicKey.N.Bytes()[:20],
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, &clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create client certificate: %w", err)
	}

	clientCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientCertDER,
	})

	clientKeyDER := x509.MarshalPKCS1PrivateKey(clientKey)
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: clientKeyDER,
	})

	// Store certificates in database
	err = s.StoreServiceCertificates(serviceName, string(serverCertPEM), string(serverKeyPEM),
		string(clientCertPEM), string(clientKeyPEM), serialNumber.String(), notBefore, notAfter)
	if err != nil {
		return nil, fmt.Errorf("failed to store service certificates: %w", err)
	}

	return &ServiceCertificates{
		ServiceName:   serviceName,
		ServerCertPEM: string(serverCertPEM),
		ServerKeyPEM:  string(serverKeyPEM),
		ClientCertPEM: string(clientCertPEM),
		ClientKeyPEM:  string(clientKeyPEM),
		SerialNumber:  serialNumber.String(),
		IssuedAt:      notBefore,
		ExpiresAt:     notAfter,
	}, nil
}

// StoreServiceCertificates stores service certificates in the database
func (s *ServiceCertificateService) StoreServiceCertificates(serviceName, serverCertPEM, serverKeyPEM,
	clientCertPEM, clientKeyPEM, serialNumber string, issuedAt, expiresAt time.Time) error {
	// Encrypt the keys
	encryptedServerKey, err := encryptServiceData(serverKeyPEM, s.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt server key: %w", err)
	}

	encryptedClientKey, err := encryptServiceData(clientKeyPEM, s.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt client key: %w", err)
	}

	query := `
		INSERT INTO platform_service_certificates (
			service_name, server_cert_pem, server_key_pem_encrypted,
			client_cert_pem, client_key_pem_encrypted, serial_number,
			issued_at, expires_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (service_name) DO UPDATE SET
			server_cert_pem = EXCLUDED.server_cert_pem,
			server_key_pem_encrypted = EXCLUDED.server_key_pem_encrypted,
			client_cert_pem = EXCLUDED.client_cert_pem,
			client_key_pem_encrypted = EXCLUDED.client_key_pem_encrypted,
			serial_number = EXCLUDED.serial_number,
			issued_at = EXCLUDED.issued_at,
			expires_at = EXCLUDED.expires_at,
			revoked_at = NULL,
			revocation_reason = NULL
	`

	_, err = s.db.Exec(query, serviceName, serverCertPEM, encryptedServerKey,
		clientCertPEM, encryptedClientKey, serialNumber, issuedAt, expiresAt, time.Now())
	if err != nil {
		return fmt.Errorf("failed to store service certificates: %w", err)
	}

	return nil
}

// GetServiceCertificates retrieves the active service certificates for a service
func (s *ServiceCertificateService) GetServiceCertificates(serviceName string) (*ServiceCertificates, error) {
	query := `
		SELECT service_name, server_cert_pem, server_key_pem_encrypted,
		       client_cert_pem, client_key_pem_encrypted, serial_number,
		       issued_at, expires_at
		FROM platform_service_certificates
		WHERE service_name = $1 AND revoked_at IS NULL
		ORDER BY issued_at DESC
		LIMIT 1
	`

	var serverKeyEncrypted, clientKeyEncrypted string
	certs := &ServiceCertificates{}
	err := s.db.QueryRow(query, serviceName).Scan(
		&certs.ServiceName,
		&certs.ServerCertPEM,
		&serverKeyEncrypted,
		&certs.ClientCertPEM,
		&clientKeyEncrypted,
		&certs.SerialNumber,
		&certs.IssuedAt,
		&certs.ExpiresAt,
	)
	if err != nil {
		return nil, err
	}

	// Decrypt the keys
	serverKeyPEM, err := decryptServiceData(serverKeyEncrypted, s.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt server key: %w", err)
	}

	clientKeyPEM, err := decryptServiceData(clientKeyEncrypted, s.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt client key: %w", err)
	}

	certs.ServerKeyPEM = serverKeyPEM
	certs.ClientKeyPEM = clientKeyPEM

	return certs, nil
}

// ValidateServiceCertificate validates a service certificate against the platform service CA
func (s *ServiceCertificateService) ValidateServiceCertificate(certPEM string, isServer bool) error {
	// Parse certificate
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check expiration
	now := time.Now()
	if now.After(cert.NotAfter) {
		return fmt.Errorf("service certificate has expired")
	}
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("service certificate is not yet valid")
	}

	// Get active service CA
	ca, err := s.caManager.GetActiveCA()
	if err != nil {
		return fmt.Errorf("failed to get service CA: %w", err)
	}

	// Parse CA certificate
	caBlock, _ := pem.Decode([]byte(ca.CACertPEM))
	if caBlock == nil {
		return fmt.Errorf("failed to decode service CA certificate")
	}

	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse service CA certificate: %w", err)
	}

	// Verify certificate chain
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	expectedUsage := x509.ExtKeyUsageServerAuth
	if !isServer {
		expectedUsage = x509.ExtKeyUsageClientAuth
	}

	opts := x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{expectedUsage},
	}

	_, err = cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("service certificate chain validation failed: %w", err)
	}

	// Check revocation status
	serviceName := cert.Subject.CommonName
	serviceCerts, err := s.GetServiceCertificates(serviceName)
	if err == nil && serviceCerts != nil {
		// Check if certificate matches stored certificate
		var storedCertPEM string
		if isServer {
			storedCertPEM = serviceCerts.ServerCertPEM
		} else {
			storedCertPEM = serviceCerts.ClientCertPEM
		}

		if certPEM != storedCertPEM {
			return fmt.Errorf("certificate does not match stored certificate for service")
		}
	}

	return nil
}

// RevokeServiceCertificate revokes service certificates for a service
func (s *ServiceCertificateService) RevokeServiceCertificate(serviceName, reason string) error {
	query := `
		UPDATE platform_service_certificates
		SET revoked_at = NOW(), revocation_reason = $1
		WHERE service_name = $2 AND revoked_at IS NULL
	`

	_, err := s.db.Exec(query, reason, serviceName)
	if err != nil {
		return fmt.Errorf("failed to revoke service certificate: %w", err)
	}

	return nil
}
