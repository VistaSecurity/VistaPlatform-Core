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
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

// BootstrapCAManager handles platform-level bootstrap CA certificate lifecycle
type BootstrapCAManager struct {
	db *sql.DB
}

// NewBootstrapCAManager creates a new bootstrap CA manager
func NewBootstrapCAManager(db *sql.DB) *BootstrapCAManager {
	return &BootstrapCAManager{db: db}
}

// BootstrapCA represents a platform bootstrap CA certificate in the database
type BootstrapCA struct {
	ID                uuid.UUID
	CACertPEM         string
	CAKeyPEMEncrypted string
	SerialNumber      int64
	CreatedAt         time.Time
	ExpiresAt         time.Time
	IsActive          bool
}

// GetOrCreateActiveCA retrieves the active platform bootstrap CA, creating one if it doesn't exist
func (m *BootstrapCAManager) GetOrCreateActiveCA(encryptionKey string) (*BootstrapCA, error) {
	// Try to get existing active CA
	ca, err := m.GetActiveCA()
	if err == nil && ca != nil {
		return ca, nil
	}
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to check for existing bootstrap CA: %w", err)
	}

	// No active CA exists, create a new one
	return m.GenerateBootstrapCA(encryptionKey)
}

// GetActiveCA retrieves the active platform bootstrap CA certificate
func (m *BootstrapCAManager) GetActiveCA() (*BootstrapCA, error) {
	query := `
		SELECT id, ca_cert_pem, ca_key_pem_encrypted, serial_number,
		       created_at, expires_at, is_active
		FROM platform_bootstrap_ca
		WHERE is_active = TRUE
		ORDER BY created_at DESC
		LIMIT 1
	`

	ca := &BootstrapCA{}
	var caKeyEncrypted string
	err := m.db.QueryRow(query).Scan(
		&ca.ID,
		&ca.CACertPEM,
		&caKeyEncrypted,
		&ca.SerialNumber,
		&ca.CreatedAt,
		&ca.ExpiresAt,
		&ca.IsActive,
	)
	if err != nil {
		return nil, err
	}

	ca.CAKeyPEMEncrypted = caKeyEncrypted
	return ca, nil
}

// GenerateBootstrapCA creates a new platform bootstrap CA certificate
func (m *BootstrapCAManager) GenerateBootstrapCA(encryptionKey string) (*BootstrapCA, error) {
	// Generate CA private key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate bootstrap CA key: %w", err)
	}

	// Create CA certificate template
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(0x7FFFFFFF))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(10, 0, 0) // 10 years validity

	caTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"Vista Platform"},
			OrganizationalUnit: []string{"Vista Platform"},
			Country:            []string{"US"},
			Province:           []string{"Florida"},
			Locality:           []string{"Orlando"},
			CommonName:         "Vista Platform Bootstrap CA",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
	}

	// Self-sign the CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create bootstrap CA certificate: %w", err)
	}

	// Encode CA certificate
	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})

	// Encode CA private key
	caKeyDER := x509.MarshalPKCS1PrivateKey(caKey)
	caKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: caKeyDER,
	})

	// Encrypt the private key
	encryptedKey, err := encryptBootstrapData(string(caKeyPEM), encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt bootstrap CA key: %w", err)
	}

	// Store in database
	caID := uuid.New()
	query := `
		INSERT INTO platform_bootstrap_ca (
			id, ca_cert_pem, ca_key_pem_encrypted, serial_number,
			created_at, expires_at, is_active
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, ca_cert_pem, ca_key_pem_encrypted, serial_number,
		          created_at, expires_at, is_active
	`

	ca := &BootstrapCA{}
	err = m.db.QueryRow(query,
		caID,
		string(caCertPEM),
		encryptedKey,
		serialNumber.Int64(),
		notBefore,
		notAfter,
		true,
	).Scan(
		&ca.ID,
		&ca.CACertPEM,
		&ca.CAKeyPEMEncrypted,
		&ca.SerialNumber,
		&ca.CreatedAt,
		&ca.ExpiresAt,
		&ca.IsActive,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to store bootstrap CA certificate: %w", err)
	}

	return ca, nil
}

// GetCAKey retrieves and decrypts the bootstrap CA private key
func (m *BootstrapCAManager) GetCAKey(caID uuid.UUID, encryptionKey string) (*rsa.PrivateKey, error) {
	query := `
		SELECT ca_key_pem_encrypted
		FROM platform_bootstrap_ca
		WHERE id = $1
	`

	var encryptedKey string
	err := m.db.QueryRow(query, caID).Scan(&encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve bootstrap CA key: %w", err)
	}

	// Decrypt the key
	keyPEM, err := decryptBootstrapData(encryptedKey, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt bootstrap CA key: %w", err)
	}

	// Parse the private key
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode bootstrap CA key PEM")
	}

	caKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse bootstrap CA key: %w", err)
	}

	return caKey, nil
}

// RotateCA creates a new bootstrap CA and marks the old one as inactive
func (m *BootstrapCAManager) RotateCA(encryptionKey string) (*BootstrapCA, error) {
	// Mark existing CA as inactive
	updateQuery := `
		UPDATE platform_bootstrap_ca
		SET is_active = FALSE
		WHERE is_active = TRUE
	`
	_, err := m.db.Exec(updateQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to deactivate old bootstrap CA: %w", err)
	}

	// Create new CA
	return m.GenerateBootstrapCA(encryptionKey)
}

// encryptBootstrapData encrypts data using AES-256-GCM with the encryption service
func encryptBootstrapData(data, masterKey string) (string, error) {
	if masterKey == "" {
		return "", fmt.Errorf("encryption master key is required")
	}

	encService, err := encryption.NewService(masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to initialize encryption service: %w", err)
	}

	return encService.Encrypt(data)
}

// decryptBootstrapData decrypts data using AES-256-GCM with the encryption service
func decryptBootstrapData(encryptedData, masterKey string) (string, error) {
	if masterKey == "" {
		return "", fmt.Errorf("encryption master key is required")
	}

	encService, err := encryption.NewService(masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to initialize encryption service: %w", err)
	}

	return encService.Decrypt(encryptedData)
}
