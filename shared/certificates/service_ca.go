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

// ServiceCAManager handles platform-level service CA certificate lifecycle
// This CA is used to issue certificates for all platform services for mTLS communication
type ServiceCAManager struct {
	db *sql.DB
}

// NewServiceCAManager creates a new service CA manager
func NewServiceCAManager(db *sql.DB) *ServiceCAManager {
	return &ServiceCAManager{db: db}
}

// ServiceCA represents a platform service CA certificate in the database
type ServiceCA struct {
	ID                uuid.UUID
	CACertPEM         string
	CAKeyPEMEncrypted string
	SerialNumber      int64
	CreatedAt         time.Time
	ExpiresAt         time.Time
	IsActive          bool
}

// GetOrCreateActiveCA retrieves the active platform service CA, creating one if it doesn't exist
func (m *ServiceCAManager) GetOrCreateActiveCA(encryptionKey string) (*ServiceCA, error) {
	// Try to get existing active CA
	ca, err := m.GetActiveCA()
	if err == nil && ca != nil {
		return ca, nil
	}
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to check for existing service CA: %w", err)
	}

	// No active CA exists, create a new one
	return m.GenerateServiceCA(encryptionKey)
}

// GetActiveCA retrieves the active platform service CA certificate
func (m *ServiceCAManager) GetActiveCA() (*ServiceCA, error) {
	query := `
		SELECT id, ca_cert_pem, ca_key_pem_encrypted, serial_number,
		       created_at, expires_at, is_active
		FROM platform_service_ca
		WHERE is_active = TRUE
		ORDER BY created_at DESC
		LIMIT 1
	`

	ca := &ServiceCA{}
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

// GenerateServiceCA creates a new platform service CA certificate
func (m *ServiceCAManager) GenerateServiceCA(encryptionKey string) (*ServiceCA, error) {
	// Generate CA private key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate service CA key: %w", err)
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
			Organization:       []string{"VistaPlatform"},
			OrganizationalUnit: []string{"VistaPlatform"},
			Country:            []string{"US"},
			Province:           []string{"Florida"},
			Locality:           []string{"Orlando"},
			CommonName:         "VistaPlatform Service CA",
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
		return nil, fmt.Errorf("failed to create service CA certificate: %w", err)
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
	encryptedKey, err := encryptServiceData(string(caKeyPEM), encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt service CA key: %w", err)
	}

	// Store in database
	caID := uuid.New()
	query := `
		INSERT INTO platform_service_ca (
			id, ca_cert_pem, ca_key_pem_encrypted, serial_number,
			created_at, expires_at, is_active
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, ca_cert_pem, ca_key_pem_encrypted, serial_number,
		          created_at, expires_at, is_active
	`

	ca := &ServiceCA{}
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
		return nil, fmt.Errorf("failed to store service CA certificate: %w", err)
	}

	return ca, nil
}

// GetCAKey retrieves and decrypts the service CA private key
func (m *ServiceCAManager) GetCAKey(caID uuid.UUID, encryptionKey string) (*rsa.PrivateKey, error) {
	query := `
		SELECT ca_key_pem_encrypted
		FROM platform_service_ca
		WHERE id = $1
	`

	var encryptedKey string
	err := m.db.QueryRow(query, caID).Scan(&encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve service CA key: %w", err)
	}

	// Decrypt the key
	keyPEM, err := decryptServiceData(encryptedKey, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt service CA key: %w", err)
	}

	// Parse the private key
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode service CA key PEM")
	}

	caKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse service CA key: %w", err)
	}

	return caKey, nil
}

// RotateCA creates a new service CA and marks the old one as inactive
func (m *ServiceCAManager) RotateCA(encryptionKey string) (*ServiceCA, error) {
	// Mark existing CA as inactive
	updateQuery := `
		UPDATE platform_service_ca
		SET is_active = FALSE
		WHERE is_active = TRUE
	`
	_, err := m.db.Exec(updateQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to deactivate old service CA: %w", err)
	}

	// Create new CA
	return m.GenerateServiceCA(encryptionKey)
}

// encryptServiceData encrypts data using AES-256-GCM with the encryption service
func encryptServiceData(data, masterKey string) (string, error) {
	if masterKey == "" {
		return "", fmt.Errorf("encryption master key is required")
	}

	encService, err := encryption.NewService(masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to initialize encryption service: %w", err)
	}

	return encService.Encrypt(data)
}

// decryptServiceData decrypts data using AES-256-GCM with the encryption service
func decryptServiceData(encryptedData, masterKey string) (string, error) {
	if masterKey == "" {
		return "", fmt.Errorf("encryption master key is required")
	}

	encService, err := encryption.NewService(masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to initialize encryption service: %w", err)
	}

	return encService.Decrypt(encryptedData)
}
