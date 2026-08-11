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
	"log"
	"math/big"
	"time"

	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// CertificateService handles certificate operations
type CertificateService struct {
	db *sql.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) connection used only by the
	// cross-tenant paths annotated `// RLS: cross-tenant — runs on the bypass role`
	// (GetCertificate / RevokeCertificate, keyed by sensor id with no tenant
	// input). Pre-flip it resolves to the same connection as db.
	bypassDB      *sql.DB
	caManager     *CAManager
	encryptionKey string
}

// NewCertificateService creates a new certificate service. db is the RLS-scoped
// (crypto_app) connection; bypassDB is the BYPASSRLS (crypto_bypass) connection
// used by the cross-tenant cert lookup/revoke paths. Pre-flip both handles
// resolve to the same connection.
func NewCertificateService(db, bypassDB *sql.DB, encryptionKey string) *CertificateService {
	return &CertificateService{
		db:            db,
		bypassDB:      bypassDB,
		caManager:     NewCAManager(db, bypassDB),
		encryptionKey: encryptionKey,
	}
}

// IssueCertificate issues a certificate for a sensor by signing a CSR
func (s *CertificateService) IssueCertificate(tenantID, sensorID uuid.UUID, csrPEM string) (string, error) {
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

	// Validate CN matches sensor ID
	if csr.Subject.CommonName != sensorID.String() {
		return "", fmt.Errorf("CSR CN (%s) does not match sensor ID (%s)", csr.Subject.CommonName, sensorID.String())
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
			Organization: []string{"VistaPlatform Sensor"},
			Country:      []string{"US"},
			CommonName:   sensorID.String(), // Use sensor ID as CN
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

	// Verify sensor exists before storing certificate (handles transaction visibility)
	// This ensures the sensor record is visible to this connection before foreign key constraint check
	// RLS: these `SELECT ... FROM sensors WHERE id = $1` verification probes are
	// by-id existence checks on the registration/auto-register bootstrap path
	// (tenant is the validated request input, not derived here) — they run on the
	// bypass role (Phase 4). The tenant-scoped write below is StoreCertificate.
	log.Printf("DEBUG: CertificateService - Verifying sensor exists: %s", sensorID.String())
	var verifySensorID uuid.UUID
	verifyErr := s.bypassDB.QueryRow("SELECT id FROM sensors WHERE id = $1", sensorID).Scan(&verifySensorID)
	if verifyErr != nil {
		log.Printf("DEBUG: CertificateService - First verification failed: %v, retrying with longer delays...", verifyErr)
		// Retry with longer delays (handles transaction commit visibility delay and connection pooling)
		delays := []time.Duration{200 * time.Millisecond, 500 * time.Millisecond, 1 * time.Second, 2 * time.Second, 3 * time.Second}
		for i, delay := range delays {
			time.Sleep(delay)
			verifyErr = s.bypassDB.QueryRow("SELECT id FROM sensors WHERE id = $1", sensorID).Scan(&verifySensorID)
			if verifyErr == nil {
				log.Printf("DEBUG: CertificateService - Sensor found after retry %d (delay: %v)", i+1, delay)
				break
			}
			log.Printf("DEBUG: CertificateService - Retry %d failed: %v", i+1, verifyErr)
		}
		if verifyErr != nil {
			log.Printf("DEBUG: CertificateService - Sensor verification failed after all retries: %v", verifyErr)
			// Check if sensor exists at all (for debugging)
			var count int
			countErr := s.bypassDB.QueryRow("SELECT COUNT(*) FROM sensors WHERE id = $1", sensorID).Scan(&count)
			if countErr == nil {
				log.Printf("DEBUG: CertificateService - Sensor count check: count=%d for sensor_id=%s", count, sensorID.String())
			}
			return "", fmt.Errorf("sensor record not found (sensor_id=%s): %w", sensorID.String(), verifyErr)
		}
	} else {
		log.Printf("DEBUG: CertificateService - Sensor verified on first attempt")
	}

	// Store certificate in database
	err = s.StoreCertificate(sensorID, tenantID, string(certPEM), serialNumber.String(), notBefore, notAfter)
	if err != nil {
		return "", fmt.Errorf("failed to store certificate: %w", err)
	}

	return string(certPEM), nil
}

// StoreCertificate stores a certificate in the database
func (s *CertificateService) StoreCertificate(sensorID, tenantID uuid.UUID, certPEM, serialNumber string, issuedAt, expiresAt time.Time) error {
	query := `
		INSERT INTO sensor_certificates (
			sensor_id, tenant_id, certificate_pem, serial_number,
			issued_at, expires_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (sensor_id, serial_number) DO UPDATE SET
			certificate_pem = EXCLUDED.certificate_pem,
			issued_at = EXCLUDED.issued_at,
			expires_at = EXCLUDED.expires_at
	`

	// RLS-scoped write on `sensor_certificates`: WithTenantTx sets app.tenant_id so
	// the INSERT's tenant_id satisfies WITH CHECK. context.Background() because this
	// method has no ctx parameter.
	ctx := context.Background()
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query, sensorID, tenantID, certPEM, serialNumber, issuedAt, expiresAt, time.Now())
		return e
	})
	if err != nil {
		log.Printf("DEBUG: StoreCertificate failed - sensor_id=%s, error=%v", sensorID.String(), err)
		// Check if sensor exists (for debugging)
		var sensorExists bool
		checkErr := s.bypassDB.QueryRow("SELECT EXISTS(SELECT 1 FROM sensors WHERE id = $1)", sensorID).Scan(&sensorExists)
		if checkErr == nil {
			log.Printf("DEBUG: StoreCertificate - Sensor exists check: exists=%v for sensor_id=%s", sensorExists, sensorID.String())
		}
		return fmt.Errorf("failed to store certificate: %w", err)
	}

	return nil
}

// StoreCertificateWithTx stores a certificate in the database using the provided transaction
func (s *CertificateService) StoreCertificateWithTx(tx *sql.Tx, sensorID, tenantID uuid.UUID, certPEM, serialNumber string, issuedAt, expiresAt time.Time) error {
	query := `
		INSERT INTO sensor_certificates (
			sensor_id, tenant_id, certificate_pem, serial_number,
			issued_at, expires_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (sensor_id, serial_number) DO UPDATE SET
			certificate_pem = EXCLUDED.certificate_pem,
			issued_at = EXCLUDED.issued_at,
			expires_at = EXCLUDED.expires_at
	`

	_, err := tx.Exec(query, sensorID, tenantID, certPEM, serialNumber, issuedAt, expiresAt, time.Now())
	if err != nil {
		return fmt.Errorf("failed to store certificate: %w", err)
	}

	return nil
}

// GetCertificate retrieves the active certificate for a sensor
//
// RLS: cross-tenant — runs on the bypass role (Phase 4). Keyed by sensor id with
// no tenant input. It runs on the mTLS auth-verification hot path (sensor_auth.go)
// where the tenant is being ESTABLISHED from the cert, and on the cert-management
// path where the caller already authorized the sensor via the tenant-scoped guard.
// Setting app.tenant_id here would require resolving the sensor's tenant first;
// deferred to Phase 4 (move to bypassDB).
func (s *CertificateService) GetCertificate(sensorID uuid.UUID) (*SensorCertificate, error) {
	query := `
		SELECT id, sensor_id, tenant_id, certificate_pem, serial_number,
		       issued_at, expires_at, revoked_at, revocation_reason, created_at
		FROM sensor_certificates
		WHERE sensor_id = $1 AND revoked_at IS NULL
		ORDER BY issued_at DESC
		LIMIT 1
	`

	// Runs on bypassDB (BYPASSRLS) — direct, no WithTenantTx (keyed by sensor id).
	cert := &SensorCertificate{}
	err := s.bypassDB.QueryRow(query, sensorID).Scan(
		&cert.ID,
		&cert.SensorID,
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

// RevokeCertificate revokes a certificate
//
// RLS: cross-tenant — runs on the bypass role (Phase 4). Keyed by sensor id with
// no tenant input (the cert-management caller already authorized the sensor via
// the tenant-scoped guard before invoking this). Setting app.tenant_id here would
// require resolving the sensor's tenant first; deferred to Phase 4.
func (s *CertificateService) RevokeCertificate(sensorID uuid.UUID, reason string) error {
	// Runs on bypassDB (BYPASSRLS) — direct, no WithTenantTx (keyed by sensor id).
	query := `
		UPDATE sensor_certificates
		SET revoked_at = NOW(), revocation_reason = $1
		WHERE sensor_id = $2 AND revoked_at IS NULL
	`

	_, err := s.bypassDB.Exec(query, reason, sensorID)
	if err != nil {
		return fmt.Errorf("failed to revoke certificate: %w", err)
	}

	return nil
}

// RevokeCertificatesExcept revokes every active certificate for a sensor except
// the just-issued replacement. Rotation calls this after issuing the new cert so
// a transient issuance failure cannot strand the sensor with only a revoked cert.
func (s *CertificateService) RevokeCertificatesExcept(sensorID uuid.UUID, keepSerialNumber, reason string) error {
	query := `
		UPDATE sensor_certificates
		SET revoked_at = NOW(), revocation_reason = $1
		WHERE sensor_id = $2
		  AND serial_number <> $3
		  AND revoked_at IS NULL
	`

	_, err := s.bypassDB.Exec(query, reason, sensorID, keepSerialNumber)
	if err != nil {
		return fmt.Errorf("failed to revoke old certificates: %w", err)
	}

	return nil
}

// SensorCertificate represents a sensor certificate in the database
type SensorCertificate struct {
	ID               uuid.UUID
	SensorID         uuid.UUID
	TenantID         uuid.UUID
	CertificatePEM   string
	SerialNumber     string
	IssuedAt         time.Time
	ExpiresAt        time.Time
	RevokedAt        *time.Time
	RevocationReason *string
	CreatedAt        time.Time
}
