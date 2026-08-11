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

// CertificateService handles certificate operations for device agents
type CertificateService struct {
	db *sql.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) connection used only by the
	// cross-tenant path (CA key lookup by CA id, where the tenant is not an
	// input). Pre-flip it resolves to the same connection as db.
	bypassDB      *sql.DB
	caManager     *CAManager
	encryptionKey string
}

// NewCertificateService creates a new certificate service. db is the RLS-scoped
// (crypto_app) connection; bypassDB is the BYPASSRLS (crypto_bypass) connection
// used by the cross-tenant CA-key lookup. Pre-flip both handles resolve to the
// same connection.
func NewCertificateService(db, bypassDB *sql.DB, encryptionKey string) *CertificateService {
	return &CertificateService{
		db:            db,
		bypassDB:      bypassDB,
		caManager:     NewCAManager(db, bypassDB),
		encryptionKey: encryptionKey,
	}
}

// IssueCertificate issues a certificate for an agent by signing a CSR
func (s *CertificateService) IssueCertificate(tenantID, agentID uuid.UUID, csrPEM string) (string, error) {
	// Parse the CSR
	csrBlock, _ := pem.Decode([]byte(csrPEM))
	if csrBlock == nil {
		return "", fmt.Errorf("failed to decode CSR PEM")
	}

	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse CSR: %w", err)
	}

	// Validate CSR signature
	if err := csr.CheckSignature(); err != nil {
		return "", fmt.Errorf("invalid CSR signature: %w", err)
	}

	// Validate CN matches agent ID
	if csr.Subject.CommonName != agentID.String() {
		return "", fmt.Errorf("CSR CN (%s) does not match agent ID (%s)", csr.Subject.CommonName, agentID.String())
	}

	// Get or create active CA for tenant
	ca, err := s.caManager.GetOrCreateActiveCA(tenantID, s.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to get CA: %w", err)
	}

	// Get CA private key
	caKey, err := s.caManager.GetCAKey(ca.ID, s.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to get CA key: %w", err)
	}

	// Parse CA certificate
	caBlock, _ := pem.Decode([]byte(ca.CACertPEM))
	if caBlock == nil {
		return "", fmt.Errorf("failed to decode CA certificate")
	}

	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(0x7FFFFFFF))
	if err != nil {
		return "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template
	notBefore := time.Now()
	notAfter := notBefore.AddDate(1, 0, 0) // 1 year validity

	certTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"VistaPlatform Device Agent"},
			Country:      []string{"US"},
			CommonName:   agentID.String(), // Use agent ID as CN
		},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		SubjectKeyId: csr.PublicKey.(*rsa.PublicKey).N.Bytes()[:20], // Use first 20 bytes of modulus
	}

	// Sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &certTemplate, caCert, csr.PublicKey, caKey)
	if err != nil {
		return "", fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	if err := s.StoreCertificate(agentID, tenantID, string(certPEM), serialNumber.String(), notBefore, notAfter); err != nil {
		return "", fmt.Errorf("failed to store certificate: %w", err)
	}

	return string(certPEM), nil
}

// StoreCertificate stores a newly issued device-agent client certificate and
// supersedes any previous active certificate for the same agent. AgentAuth uses
// this row as the server-side active-cert binding; a CA-valid old cert should
// stop working immediately after rotation.
func (s *CertificateService) StoreCertificate(agentID, tenantID uuid.UUID, certPEM, serialNumber string, issuedAt, expiresAt time.Time) error {
	ctx := context.Background()
	return shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		// Insert/activate the replacement first, then supersede prior rows.
		// Revoking first would leave the agent with zero active certs if the
		// insert fails (same anti-pattern fixed for sensors in).
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO agent_certificates (
				agent_id, tenant_id, certificate_pem, serial_number,
				issued_at, expires_at, created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
			ON CONFLICT (agent_id, serial_number) DO UPDATE SET
				certificate_pem = EXCLUDED.certificate_pem,
				issued_at = EXCLUDED.issued_at,
				expires_at = EXCLUDED.expires_at,
				revoked_at = NULL,
				revocation_reason = NULL,
				updated_at = NOW()
		`, agentID, tenantID, certPEM, serialNumber, issuedAt, expiresAt); err != nil {
			return fmt.Errorf("insert agent certificate: %w", err)
		}

		if _, err := tx.ExecContext(ctx, `
			UPDATE agent_certificates
			SET revoked_at = NOW(),
			    revocation_reason = 'superseded',
			    updated_at = NOW()
			WHERE agent_id = $1
			  AND tenant_id = $2
			  AND revoked_at IS NULL
			  AND serial_number <> $3
		`, agentID, tenantID, serialNumber); err != nil {
			return fmt.Errorf("supersede previous agent certificates: %w", err)
		}
		return nil
	})
}

// GetCertificate retrieves the current unrevoked certificate for an agent.
//
// RLS: cross-tenant — runs on the bypass role. This is used on the mTLS auth
// path where tenant identity is being established from the agent id/cert pair.
func (s *CertificateService) GetCertificate(agentID uuid.UUID) (*AgentCertificate, error) {
	cert := &AgentCertificate{}
	err := s.bypassDB.QueryRow(`
		SELECT id, agent_id, tenant_id, certificate_pem, serial_number,
		       issued_at, expires_at, revoked_at, revocation_reason, created_at
		FROM agent_certificates
		WHERE agent_id = $1 AND revoked_at IS NULL
		ORDER BY issued_at DESC
		LIMIT 1
	`, agentID).Scan(
		&cert.ID,
		&cert.AgentID,
		&cert.TenantID,
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

// HasCertificateHistory reports whether any certificate row has ever existed
// for this agent, including revoked/superseded rows. AgentAuth uses this to
// distinguish legacy pre-persistence enrollments from intentional revocation.
func (s *CertificateService) HasCertificateHistory(agentID uuid.UUID) (bool, error) {
	var exists bool
	err := s.bypassDB.QueryRow(`
		SELECT EXISTS (
			SELECT 1
			FROM agent_certificates
			WHERE agent_id = $1
		)
	`, agentID).Scan(&exists)
	return exists, err
}

// AgentCertificate represents a persisted device-agent client certificate.
type AgentCertificate struct {
	ID               uuid.UUID
	AgentID          uuid.UUID
	TenantID         uuid.UUID
	CertificatePEM   string
	SerialNumber     string
	IssuedAt         time.Time
	ExpiresAt        time.Time
	RevokedAt        *time.Time
	RevocationReason *string
	CreatedAt        time.Time
}

// CAManager handles persistent CA certificate lifecycle for device agents
type CAManager struct {
	db *sql.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) connection used only by the
	// cross-tenant path (GetCAKey, addressed by CA id with no tenant input).
	// Pre-flip it resolves to the same connection as db.
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
	encService, err := encryption.NewService(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize encryption service: %w", err)
	}
	encryptedKey, err := encService.Encrypt(string(caKeyPEM))
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
	encService, err := encryption.NewService(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize encryption service: %w", err)
	}
	keyPEM, err := encService.Decrypt(encryptedKey)
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
