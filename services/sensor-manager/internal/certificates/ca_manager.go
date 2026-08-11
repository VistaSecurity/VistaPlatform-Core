package certificates

import (
	"context"
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
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

// CAManager handles persistent CA certificate lifecycle
type CAManager struct {
	db *sql.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) connection used only by the
	// cross-tenant path annotated `// RLS: cross-tenant — runs on the bypass role`
	// (GetCAKey, addressed by CA id with no tenant input). Pre-flip it resolves to
	// the same connection as db.
	bypassDB *sql.DB
}

// NewCAManager creates a new CA manager. db is the RLS-scoped (crypto_app)
// connection; bypassDB is the BYPASSRLS (crypto_bypass) connection used by the
// cross-tenant key lookup. Pre-flip both handles resolve to the same connection.
func NewCAManager(db, bypassDB *sql.DB) *CAManager {
	return &CAManager{db: db, bypassDB: bypassDB}
}

// CACertificate represents a CA certificate in the database
type CACertificate struct {
	ID                uuid.UUID
	TenantID          uuid.UUID
	CACertPEM         string
	CAKeyPEMEncrypted string
	SerialNumber      int64
	CreatedAt         time.Time
	ExpiresAt         time.Time
	IsActive          bool
}

// GetOrCreateActiveCA retrieves the active CA for a tenant, creating one if it doesn't exist
func (m *CAManager) GetOrCreateActiveCA(tenantID uuid.UUID, encryptionKey string) (*CACertificate, error) {
	// Try to get existing active CA
	ca, err := m.GetActiveCA(tenantID)
	if err == nil && ca != nil {
		return ca, nil
	}
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to check for existing CA: %w", err)
	}

	// No active CA exists, create a new one
	return m.CreateCA(tenantID, encryptionKey)
}

// GetActiveCA retrieves the active CA certificate for a tenant
func (m *CAManager) GetActiveCA(tenantID uuid.UUID) (*CACertificate, error) {
	query := `
		SELECT id, tenant_id, ca_cert_pem, ca_key_pem_encrypted, serial_number,
		       created_at, expires_at, is_active
		FROM sensor_ca_certificates
		WHERE tenant_id = $1 AND is_active = TRUE
		ORDER BY created_at DESC
		LIMIT 1
	`

	// RLS-scoped read on `sensor_ca_certificates`: WithTenantTx sets app.tenant_id;
	// the explicit WHERE tenant_id = $1 is kept as the primary control. The
	// sql.ErrNoRows sentinel is returned transparently because GetOrCreateActiveCA
	// branches on it (no active CA → create one). context.Background() because this
	// method has no ctx parameter.
	ctx := context.Background()
	ca := &CACertificate{}
	var caKeyEncrypted string
	err := shareddatabase.WithTenantTx(ctx, m.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, tenantID).Scan(
			&ca.ID,
			&ca.TenantID,
			&ca.CACertPEM,
			&caKeyEncrypted,
			&ca.SerialNumber,
			&ca.CreatedAt,
			&ca.ExpiresAt,
			&ca.IsActive,
		)
	})
	if err != nil {
		return nil, err
	}

	ca.CAKeyPEMEncrypted = caKeyEncrypted
	return ca, nil
}

// CreateCA creates a new CA certificate for a tenant
func (m *CAManager) CreateCA(tenantID uuid.UUID, encryptionKey string) (*CACertificate, error) {
	// Generate CA private key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %w", err)
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
			CommonName:         fmt.Sprintf("VistaPlatform CA - Tenant %s", tenantID.String()[:8]),
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
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
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
	encryptedKey, err := encryptData(string(caKeyPEM), encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt CA key: %w", err)
	}

	// Store in database
	caID := uuid.New()
	query := `
		INSERT INTO sensor_ca_certificates (
			id, tenant_id, ca_cert_pem, ca_key_pem_encrypted, serial_number,
			created_at, expires_at, is_active
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, tenant_id, ca_cert_pem, ca_key_pem_encrypted, serial_number,
		          created_at, expires_at, is_active
	`

	// RLS-scoped write on `sensor_ca_certificates`: WithTenantTx sets app.tenant_id
	// so the INSERT's tenant_id satisfies WITH CHECK. context.Background() because
	// this method has no ctx parameter.
	ctx := context.Background()
	ca := &CACertificate{}
	err = shareddatabase.WithTenantTx(ctx, m.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query,
			caID,
			tenantID,
			string(caCertPEM),
			encryptedKey,
			serialNumber.Int64(),
			notBefore,
			notAfter,
			true,
		).Scan(
			&ca.ID,
			&ca.TenantID,
			&ca.CACertPEM,
			&ca.CAKeyPEMEncrypted,
			&ca.SerialNumber,
			&ca.CreatedAt,
			&ca.ExpiresAt,
			&ca.IsActive,
		)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to store CA certificate: %w", err)
	}

	return ca, nil
}

// GetCAKey retrieves and decrypts the CA private key
//
// RLS: cross-tenant — runs on the bypass role (Phase 4). Addressed by the CA id
// (which the caller obtained from the tenant-scoped GetActiveCA/GetOrCreateActiveCA),
// not by tenant, so there is no tenant input to set app.tenant_id with here. The
// preceding tenant-scoped CA lookup is the isolation boundary.
func (m *CAManager) GetCAKey(caID uuid.UUID, encryptionKey string) (*rsa.PrivateKey, error) {
	query := `
		SELECT ca_key_pem_encrypted
		FROM sensor_ca_certificates
		WHERE id = $1
	`

	// Runs on bypassDB (BYPASSRLS) — direct, no WithTenantTx (addressed by CA id).
	var encryptedKey string
	err := m.bypassDB.QueryRow(query, caID).Scan(&encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve CA key: %w", err)
	}

	// Decrypt the key
	keyPEM, err := decryptData(encryptedKey, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt CA key: %w", err)
	}

	// Parse the private key
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode CA key PEM")
	}

	caKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA key: %w", err)
	}

	return caKey, nil
}

// RotateCA creates a new CA and marks the old one as inactive
func (m *CAManager) RotateCA(tenantID uuid.UUID, encryptionKey string) (*CACertificate, error) {
	// Mark existing CA as inactive.
	// RLS-scoped write on `sensor_ca_certificates`: WithTenantTx sets app.tenant_id;
	// the explicit WHERE tenant_id = $1 is kept as the primary control.
	// context.Background() because this method has no ctx parameter.
	ctx := context.Background()
	updateQuery := `
		UPDATE sensor_ca_certificates
		SET is_active = FALSE
		WHERE tenant_id = $1 AND is_active = TRUE
	`
	err := shareddatabase.WithTenantTx(ctx, m.db, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, updateQuery, tenantID)
		return e
	})
	if err != nil {
		return nil, fmt.Errorf("failed to deactivate old CA: %w", err)
	}

	// Create new CA (CreateCA wraps its own WithTenantTx)
	return m.CreateCA(tenantID, encryptionKey)
}

// encryptData encrypts data using AES-256-GCM with the encryption service
func encryptData(data, masterKey string) (string, error) {
	if masterKey == "" {
		return "", fmt.Errorf("encryption master key is required")
	}

	encService, err := encryption.NewService(masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to initialize encryption service: %w", err)
	}

	return encService.Encrypt(data)
}

// decryptData decrypts data using AES-256-GCM with the encryption service
func decryptData(encryptedData, masterKey string) (string, error) {
	if masterKey == "" {
		return "", fmt.Errorf("encryption master key is required")
	}

	encService, err := encryption.NewService(masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to initialize encryption service: %w", err)
	}

	return encService.Decrypt(encryptedData)
}
