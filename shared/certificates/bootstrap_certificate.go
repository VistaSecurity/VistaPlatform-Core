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

// BootstrapCertificateService handles bootstrap certificate operations for platform services
type BootstrapCertificateService struct {
	db            *sql.DB
	caManager     *BootstrapCAManager
	encryptionKey string
}

// NewBootstrapCertificateService creates a new bootstrap certificate service
func NewBootstrapCertificateService(db *sql.DB, encryptionKey string) *BootstrapCertificateService {
	return &BootstrapCertificateService{
		db:            db,
		caManager:     NewBootstrapCAManager(db),
		encryptionKey: encryptionKey,
	}
}

// BootstrapCertificate represents a bootstrap certificate in the database
type BootstrapCertificate struct {
	ID               uuid.UUID
	ServiceName      string
	CertificatePEM   string
	SerialNumber     string
	IssuedAt         time.Time
	ExpiresAt        time.Time
	RevokedAt        *time.Time
	RevocationReason *string
	CreatedAt        time.Time
}

// IssueBootstrapCertificate issues a bootstrap certificate for a platform service
func (s *BootstrapCertificateService) IssueBootstrapCertificate(serviceName string) (string, string, error) {
	// Get or create active bootstrap CA
	ca, err := s.caManager.GetOrCreateActiveCA(s.encryptionKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to get bootstrap CA: %w", err)
	}

	// Get CA private key
	caKey, err := s.caManager.GetCAKey(ca.ID, s.encryptionKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to get bootstrap CA key: %w", err)
	}

	// Parse CA certificate
	caBlock, _ := pem.Decode([]byte(ca.CACertPEM))
	if caBlock == nil {
		return "", "", fmt.Errorf("failed to decode bootstrap CA certificate")
	}

	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse bootstrap CA certificate: %w", err)
	}

	// Generate service private key
	serviceKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate service key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(0x7FFFFFFF))
	if err != nil {
		return "", "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template
	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 3, 0) // 90 days validity (3 months)

	certTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"Vista Platform"},
			OrganizationalUnit: []string{"Vista Platform"},
			Country:            []string{"US"},
			Province:           []string{"Florida"},
			Locality:           []string{"Orlando"},
			CommonName:         serviceName, // Use service name as CN
		},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		SubjectKeyId: serviceKey.PublicKey.N.Bytes()[:20], // Use first 20 bytes of modulus
	}

	// Sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &certTemplate, caCert, &serviceKey.PublicKey, caKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create bootstrap certificate: %w", err)
	}

	// Encode certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key
	keyDER := x509.MarshalPKCS1PrivateKey(serviceKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyDER,
	})

	// Store certificate in database
	err = s.StoreBootstrapCertificate(serviceName, string(certPEM), serialNumber.String(), notBefore, notAfter)
	if err != nil {
		return "", "", fmt.Errorf("failed to store bootstrap certificate: %w", err)
	}

	return string(certPEM), string(keyPEM), nil
}

// StoreBootstrapCertificate stores a bootstrap certificate in the database
func (s *BootstrapCertificateService) StoreBootstrapCertificate(serviceName, certPEM, serialNumber string, issuedAt, expiresAt time.Time) error {
	query := `
		INSERT INTO platform_bootstrap_certificates (
			service_name, certificate_pem, serial_number,
			issued_at, expires_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (service_name) DO UPDATE SET
			certificate_pem = EXCLUDED.certificate_pem,
			serial_number = EXCLUDED.serial_number,
			issued_at = EXCLUDED.issued_at,
			expires_at = EXCLUDED.expires_at,
			revoked_at = NULL,
			revocation_reason = NULL
	`

	_, err := s.db.Exec(query, serviceName, certPEM, serialNumber, issuedAt, expiresAt, time.Now())
	if err != nil {
		return fmt.Errorf("failed to store bootstrap certificate: %w", err)
	}

	return nil
}

// GetBootstrapCertificate retrieves the active bootstrap certificate for a service
func (s *BootstrapCertificateService) GetBootstrapCertificate(serviceName string) (*BootstrapCertificate, error) {
	query := `
		SELECT id, service_name, certificate_pem, serial_number,
		       issued_at, expires_at, revoked_at, revocation_reason, created_at
		FROM platform_bootstrap_certificates
		WHERE service_name = $1 AND revoked_at IS NULL
		ORDER BY issued_at DESC
		LIMIT 1
	`

	cert := &BootstrapCertificate{}
	err := s.db.QueryRow(query, serviceName).Scan(
		&cert.ID,
		&cert.ServiceName,
		&cert.CertificatePEM,
		&cert.SerialNumber,
		&cert.IssuedAt,
		&cert.ExpiresAt,
		&cert.RevokedAt,
		&cert.RevocationReason,
		&cert.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// ValidateBootstrapCertificate validates a bootstrap certificate against the platform CA
func (s *BootstrapCertificateService) ValidateBootstrapCertificate(certPEM string) error {
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
		return fmt.Errorf("bootstrap certificate has expired")
	}
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("bootstrap certificate is not yet valid")
	}

	// Get active bootstrap CA
	ca, err := s.caManager.GetActiveCA()
	if err != nil {
		return fmt.Errorf("failed to get bootstrap CA: %w", err)
	}

	// Parse CA certificate
	caBlock, _ := pem.Decode([]byte(ca.CACertPEM))
	if caBlock == nil {
		return fmt.Errorf("failed to decode bootstrap CA certificate")
	}

	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse bootstrap CA certificate: %w", err)
	}

	// Verify certificate chain
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	opts := x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	_, err = cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("bootstrap certificate chain validation failed: %w", err)
	}

	// Check revocation status
	serviceName := cert.Subject.CommonName
	bootstrapCert, err := s.GetBootstrapCertificate(serviceName)
	if err == nil && bootstrapCert != nil {
		if bootstrapCert.RevokedAt != nil {
			return fmt.Errorf("bootstrap certificate has been revoked")
		}
	}

	return nil
}

// RevokeBootstrapCertificate revokes a bootstrap certificate
func (s *BootstrapCertificateService) RevokeBootstrapCertificate(serviceName, reason string) error {
	query := `
		UPDATE platform_bootstrap_certificates
		SET revoked_at = NOW(), revocation_reason = $1
		WHERE service_name = $2 AND revoked_at IS NULL
	`

	_, err := s.db.Exec(query, reason, serviceName)
	if err != nil {
		return fmt.Errorf("failed to revoke bootstrap certificate: %w", err)
	}

	return nil
}
