package services

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
)

// ExternalConnectionsService manages the external_connections and
// external_connection_history tables. It is the storage layer for
// 3rd party public internet connections observed by sensors.
type ExternalConnectionsService struct {
	db                       *database.DB
	algorithms               *AlgorithmService
	serviceIdentificationSvc *ServiceIdentificationService
}

// NewExternalConnectionsService creates a new service wired to the algorithm service
// for crypto strength assessment.
func NewExternalConnectionsService(db *database.DB, algorithms *AlgorithmService) *ExternalConnectionsService {
	return &ExternalConnectionsService{db: db, algorithms: algorithms}
}

// SetServiceIdentificationService injects the service identification dependency.
func (s *ExternalConnectionsService) SetServiceIdentificationService(svc *ServiceIdentificationService) {
	s.serviceIdentificationSvc = svc
}

// Upsert inserts or updates an external connection observation.
// Crypto strength and PQC resistance are assessed at write time using the algorithms table.
func (s *ExternalConnectionsService) Upsert(tenantID uuid.UUID, input models.ExternalConnectionUpsert) (*models.ExternalConnection, error) {
	if input.SourceIP == "" || input.DestIP == "" || input.DestPort == 0 || input.Protocol == "" {
		return nil, fmt.Errorf("source_ip, dest_ip, dest_port, and protocol are required")
	}

	// --- Crypto assessment ---
	cryptoStrength, isPQC, kexAlgorithm, weakReasons := s.assessCrypto(input)
	if input.KeyExchangeAlgorithm == nil && kexAlgorithm != "" {
		input.KeyExchangeAlgorithm = &kexAlgorithm
	}

	var weakReasonsArr pq.StringArray
	if len(weakReasons) > 0 {
		weakReasonsArr = pq.StringArray(weakReasons)
	}

	// source_asset_id is resolved best-effort inside the tenant tx below (the
	// network_assets lookup, the external_connections upsert, and the history
	// write are all RLS-scoped and run as one unit).
	var sourceAssetID *uuid.UUID

	// --- Certificate expiry flag ---
	certIsExpired := input.CertNotAfter != nil && input.CertNotAfter.Before(time.Now())

	now := time.Now()

	var certSAN pq.StringArray
	if len(input.CertSAN) > 0 {
		certSAN = pq.StringArray(input.CertSAN)
	}

	var supportedTLSVersions pq.StringArray
	if len(input.SupportedTLSVersions) > 0 {
		supportedTLSVersions = pq.StringArray(input.SupportedTLSVersions)
	}

	// --- Upsert into external_connections ---
	// CTE captures the previous state on conflict so we can write history.
	upsertSQL := `
WITH prev AS (
    SELECT id, cipher_suite, protocol_version, crypto_strength, is_pqc_resistant, cert_fingerprint_sha256, cert_not_after
    FROM external_connections
    WHERE tenant_id = $1 AND source_ip = $2::inet AND dest_ip = $3::inet AND dest_port = $4 AND protocol = $5
),
upserted AS (
    INSERT INTO external_connections (
        tenant_id, source_ip, source_hostname, source_asset_id,
        dest_ip, dest_hostname, dest_port, protocol, protocol_version,
        cipher_suite, key_exchange_algorithm, key_size,
        supported_tls_versions,
        crypto_strength, is_pqc_resistant, weak_reasons,
        cert_subject, cert_issuer, cert_san,
        cert_not_before, cert_not_after, cert_fingerprint_sha256,
        cert_public_key_algorithm, cert_public_key_size, cert_signature_algorithm,
        cert_is_expired, cert_validation_status, cert_pem,
        first_seen_at, last_seen_at, observation_count, sensor_id,
        created_at, updated_at
    ) VALUES (
        $1, $2::inet, $6, $7,
        $3::inet, $8, $4, $5, $9,
        $10, $11, $12,
        $29,
        $13, $14, $30,
        $15, $16, $17,
        $18, $19, $20,
        $21, $22, $23,
        $24, $25, $26,
        $27, $27, 1, $28,
        $27, $27
    )
    ON CONFLICT ON CONSTRAINT uq_external_connection DO UPDATE SET
        source_hostname         = COALESCE(EXCLUDED.source_hostname, external_connections.source_hostname),
        source_asset_id         = COALESCE(EXCLUDED.source_asset_id, external_connections.source_asset_id),
        dest_hostname           = COALESCE(EXCLUDED.dest_hostname, external_connections.dest_hostname),
        protocol_version        = COALESCE(EXCLUDED.protocol_version, external_connections.protocol_version),
        cipher_suite            = COALESCE(EXCLUDED.cipher_suite, external_connections.cipher_suite),
        key_exchange_algorithm  = COALESCE(EXCLUDED.key_exchange_algorithm, external_connections.key_exchange_algorithm),
        key_size                = COALESCE(EXCLUDED.key_size, external_connections.key_size),
        supported_tls_versions  = COALESCE(EXCLUDED.supported_tls_versions, external_connections.supported_tls_versions),
        crypto_strength         = CASE
                                      WHEN EXCLUDED.crypto_strength <> 'unknown' THEN EXCLUDED.crypto_strength
                                      ELSE external_connections.crypto_strength
                                  END,
        is_pqc_resistant        = CASE
                                      WHEN EXCLUDED.crypto_strength <> 'unknown' THEN EXCLUDED.is_pqc_resistant
                                      ELSE external_connections.is_pqc_resistant
                                  END,
        weak_reasons            = CASE
                                      WHEN EXCLUDED.crypto_strength <> 'unknown' THEN EXCLUDED.weak_reasons
                                      ELSE external_connections.weak_reasons
                                  END,
        cert_subject            = COALESCE(EXCLUDED.cert_subject, external_connections.cert_subject),
        cert_issuer             = COALESCE(EXCLUDED.cert_issuer, external_connections.cert_issuer),
        cert_san                = COALESCE(EXCLUDED.cert_san, external_connections.cert_san),
        cert_not_before         = COALESCE(EXCLUDED.cert_not_before, external_connections.cert_not_before),
        cert_not_after          = COALESCE(EXCLUDED.cert_not_after, external_connections.cert_not_after),
        cert_fingerprint_sha256 = COALESCE(EXCLUDED.cert_fingerprint_sha256, external_connections.cert_fingerprint_sha256),
        cert_public_key_algorithm = COALESCE(EXCLUDED.cert_public_key_algorithm, external_connections.cert_public_key_algorithm),
        cert_public_key_size    = COALESCE(EXCLUDED.cert_public_key_size, external_connections.cert_public_key_size),
        cert_signature_algorithm = COALESCE(EXCLUDED.cert_signature_algorithm, external_connections.cert_signature_algorithm),
        cert_is_expired         = EXCLUDED.cert_is_expired,
        cert_validation_status  = COALESCE(EXCLUDED.cert_validation_status, external_connections.cert_validation_status),
        cert_pem                = COALESCE(EXCLUDED.cert_pem, external_connections.cert_pem),
        last_seen_at            = EXCLUDED.last_seen_at,
        observation_count       = external_connections.observation_count + 1,
        sensor_id               = COALESCE(EXCLUDED.sensor_id, external_connections.sensor_id),
        updated_at              = EXCLUDED.updated_at
    RETURNING *
)
SELECT
    u.id, u.tenant_id,
    u.source_ip::text, u.source_hostname, u.source_asset_id,
    u.dest_ip::text, u.dest_hostname, u.dest_port,
    u.protocol, u.protocol_version, u.cipher_suite, u.key_exchange_algorithm, u.key_size,
    u.supported_tls_versions,
    u.crypto_strength, u.is_pqc_resistant, u.weak_reasons,
    u.cert_subject, u.cert_issuer, u.cert_san,
    u.cert_not_before, u.cert_not_after, u.cert_fingerprint_sha256,
    u.cert_public_key_algorithm, u.cert_public_key_size, u.cert_signature_algorithm,
    u.cert_is_expired, u.cert_validation_status, u.cert_pem,
    u.first_seen_at, u.last_seen_at, u.observation_count, u.sensor_id,
    u.created_at, u.updated_at,
    (prev.id IS NULL) AS is_new,
    prev.cipher_suite AS prev_cipher_suite,
    prev.protocol_version AS prev_protocol_version,
    prev.crypto_strength AS prev_crypto_strength,
    prev.is_pqc_resistant AS prev_is_pqc_resistant,
    prev.cert_fingerprint_sha256 AS prev_cert_fingerprint,
    prev.cert_not_after AS prev_cert_not_after
FROM upserted u
LEFT JOIN prev ON true
`

	var conn models.ExternalConnection
	var isNew bool
	var prevCipherSuite, prevProtocolVersion, prevCryptoStrength, prevCertFingerprint sql.NullString
	var prevIsPQC sql.NullBool
	var prevCertNotAfter sql.NullTime
	var scanCertSAN pq.StringArray
	var scanSupportedTLSVersions pq.StringArray
	var scanWeakReasons pq.StringArray

	// RLS-scoped unit: resolve source_asset_id (network_assets), upsert the row
	// (external_connections), and write the history row (external_connection_history)
	// all inside one WithTenantTx so app.tenant_id is set for every statement and
	// the upsert + its history land atomically.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		// --- Resolve source_asset_id best-effort ---
		{
			var id uuid.UUID
			q := `SELECT id FROM network_assets WHERE tenant_id = $1 AND ip_address::text = $2 AND deleted_at IS NULL LIMIT 1`
			if e := tx.QueryRow(q, tenantID, input.SourceIP).Scan(&id); e == nil {
				sourceAssetID = &id
			}
		}

		if e := tx.QueryRow(upsertSQL,
			// $1-$5: unique key
			tenantID, input.SourceIP, input.DestIP, input.DestPort, input.Protocol,
			// $6-$28: columns
			input.SourceHostname, sourceAssetID,
			input.DestHostname, input.ProtocolVersion,
			input.CipherSuite, input.KeyExchangeAlgorithm, input.KeySize,
			cryptoStrength, isPQC,
			input.CertSubject, input.CertIssuer, certSAN,
			input.CertNotBefore, input.CertNotAfter, input.CertFingerprintSHA256,
			input.CertPublicKeyAlgorithm, input.CertPublicKeySize, input.CertSignatureAlgorithm,
			certIsExpired, input.CertValidationStatus, input.CertPEM,
			now, input.SensorID,
			// $29: supported_tls_versions
			supportedTLSVersions,
			// $30: weak_reasons
			weakReasonsArr,
		).Scan(
			&conn.ID, &conn.TenantID,
			&conn.SourceIP, &conn.SourceHostname, &conn.SourceAssetID,
			&conn.DestIP, &conn.DestHostname, &conn.DestPort,
			&conn.Protocol, &conn.ProtocolVersion, &conn.CipherSuite, &conn.KeyExchangeAlgorithm, &conn.KeySize,
			&scanSupportedTLSVersions,
			&conn.CryptoStrength, &conn.IsPQCResistant, &scanWeakReasons,
			&conn.CertSubject, &conn.CertIssuer, &scanCertSAN,
			&conn.CertNotBefore, &conn.CertNotAfter, &conn.CertFingerprintSHA256,
			&conn.CertPublicKeyAlgorithm, &conn.CertPublicKeySize, &conn.CertSignatureAlgorithm,
			&conn.CertIsExpired, &conn.CertValidationStatus, &conn.CertPEM,
			&conn.FirstSeenAt, &conn.LastSeenAt, &conn.ObservationCount, &conn.SensorID,
			&conn.CreatedAt, &conn.UpdatedAt,
			&isNew,
			&prevCipherSuite, &prevProtocolVersion, &prevCryptoStrength, &prevIsPQC,
			&prevCertFingerprint, &prevCertNotAfter,
		); e != nil {
			return fmt.Errorf("upsert external connection: %w", e)
		}
		if len(scanWeakReasons) > 0 {
			conn.WeakReasons = []string(scanWeakReasons)
		}
		if len(scanCertSAN) > 0 {
			conn.CertSAN = []string(scanCertSAN)
		}
		if len(scanSupportedTLSVersions) > 0 {
			conn.SupportedTLSVersions = []string(scanSupportedTLSVersions)
		}

		// --- Write history row ---
		changeType, shouldRecord := s.determineChangeType(isNew,
			prevCipherSuite.String, prevProtocolVersion.String,
			prevCryptoStrength.String, prevIsPQC.Bool,
			prevCertFingerprint.String, prevCertNotAfter,
			&conn,
		)
		if shouldRecord {
			var prevPQC *bool
			if prevIsPQC.Valid {
				b := prevIsPQC.Bool
				prevPQC = &b
			}
			var prevCA *time.Time
			if prevCertNotAfter.Valid {
				t := prevCertNotAfter.Time
				prevCA = &t
			}

			var histPrevCipher, histPrevProto, histPrevStrength, histPrevFP *string
			if prevCipherSuite.Valid {
				histPrevCipher = &prevCipherSuite.String
			}
			if prevProtocolVersion.Valid {
				histPrevProto = &prevProtocolVersion.String
			}
			if prevCryptoStrength.Valid {
				histPrevStrength = &prevCryptoStrength.String
			}
			if prevCertFingerprint.Valid {
				histPrevFP = &prevCertFingerprint.String
			}

			newCS := conn.CryptoStrength
			_, _ = tx.Exec(`
				INSERT INTO external_connection_history (
					id, external_connection_id, tenant_id, change_type,
					previous_protocol_version, previous_cipher_suite, previous_crypto_strength,
					previous_is_pqc_resistant, previous_cert_fingerprint_sha256, previous_cert_not_after,
					new_protocol_version, new_cipher_suite, new_crypto_strength,
					new_is_pqc_resistant, new_cert_fingerprint_sha256, new_cert_not_after,
					created_at
				) VALUES (
					gen_random_uuid(), $1, $2, $3,
					$4, $5, $6, $7, $8, $9,
					$10, $11, $12, $13, $14, $15,
					NOW()
				)`,
				conn.ID, tenantID, changeType,
				histPrevProto, histPrevCipher, histPrevStrength, prevPQC, histPrevFP, prevCA,
				conn.ProtocolVersion, conn.CipherSuite, &newCS, &conn.IsPQCResistant,
				conn.CertFingerprintSHA256, conn.CertNotAfter,
			)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// --- Service identification ---
	// IdentifyService runs on the ServiceIdentificationService's own db handle
	// against the non-RLS service_identification_rules table, so it stays outside
	// the tenant tx; only the resulting external_connections UPDATE is RLS-scoped.
	if s.serviceIdentificationSvc != nil {
		hints := s.serviceIdentificationSvc.IdentifyService(tenantID, input.DestPort, input.Protocol, nil)
		if hints != nil {
			ver := hints.ServiceVersion
			_ = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
				_, _ = tx.Exec(`
					UPDATE external_connections SET service_name = $1, service_version = NULLIF($2, ''),
						service_confidence = $3, service_identification_method = $4, updated_at = NOW()
					WHERE id = $5 AND tenant_id = $6`,
					hints.ServiceName, ver, hints.Confidence, hints.IdentificationMethod, conn.ID, tenantID)
				return nil
			})
			conn.ServiceName = &hints.ServiceName
			if ver != "" {
				conn.ServiceVersion = &ver
			}
			conn.ServiceConfidence = &hints.Confidence
			conn.ServiceIdentificationMethod = &hints.IdentificationMethod
		}
	}

	// freshness guard: if this connection has been elevated to a managed
	// asset, keep that asset's last_seen current on every re-observation so
	// continuous vendor monitoring doesn't let the promoted asset go stale. The
	// join is a no-op for the (vast majority) non-elevated connections. This is
	// the passive-path counterpart to the in-place refresh in IngestFindings;
	// both the manual route and the sensor BatchProcessor reach external_connections
	// through this Upsert, so the freshness logic lives here once.
	// (Re-materializing a rotated cert into the managed asset is a follow-up — it
	// needs idempotent crypto handling to avoid duplicate crypto_implementations.)
	// RLS-scoped write over network_assets (and reads external_connections).
	_ = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, _ = tx.Exec(`
			UPDATE network_assets na
			SET last_seen_at = NOW(), updated_at = NOW()
			FROM external_connections ec
			WHERE ec.id = $1 AND ec.tenant_id = $2
			  AND ec.elevated_asset_id = na.id AND na.tenant_id = $2`,
			conn.ID, tenantID)
		return nil
	})

	return &conn, nil
}

// normalizeCipherComponent strips operating-mode suffixes from a cipher component
// name, then removes formatting hyphens and spaces so the result matches the
// algorithms.code format (e.g. "AES-256-GCM" → "AES256", "CHACHA20-POLY1305" →
// "CHACHA20", "TLS 1.2" → "TLS1.2"). For codes that already match (key exchange,
// hash), this is a no-op.
//
// The rules live in shared/cryptoparse alongside the parser that produces the
// values being normalized; this wrapper keeps the call sites short.
func normalizeCipherComponent(parsed string) string {
	return cryptoparse.NormalizeComponentCode(parsed)
}

// resolveAlgorithmForComponent looks up a cipher component (key exchange, symmetric,
// hash, signature) in the algorithms table using DB-driven matching only — no
// strength values are hardcoded here.
//
// Lookup order:
//  1. Case-insensitive exact code match (handles ECDHE, SHA384, etc.)
//  2. Normalize the component (strip mode suffix, remove hyphens) and retry
//     (handles AES-256-GCM → AES256, CHACHA20-POLY1305 → ChaCha20, etc.)
//
// Returns nil without error if no matching row exists; that component is simply
// not counted in the assessment rather than causing a failure.
func (s *ExternalConnectionsService) resolveAlgorithmForComponent(parsed string) (*Algorithm, error) {
	if strings.TrimSpace(parsed) == "" {
		return nil, nil
	}

	alg, err := s.algorithms.GetAlgorithmByCodeCI(parsed)
	if err != nil {
		return nil, err
	}
	if alg != nil {
		return alg, nil
	}

	normalized := normalizeCipherComponent(parsed)
	if normalized == parsed {
		return nil, nil
	}
	return s.algorithms.GetAlgorithmByCodeCI(normalized)
}

// assessCrypto evaluates the cipher suite and protocol against the algorithms table
// and returns (cryptoStrength, isPQCResistant, parsedKEX, weakReasons).
func (s *ExternalConnectionsService) assessCrypto(input models.ExternalConnectionUpsert) (strength string, isPQC bool, kex string, weakReasons []string) {
	strength = "unknown"
	isPQC = false
	kex = ""

	var components *CipherSuiteComponents
	if input.CipherSuite != nil && strings.TrimSpace(*input.CipherSuite) != "" {
		if c, err := s.algorithms.ParseCipherSuite(*input.CipherSuite); err == nil && c != nil {
			components = c
			kex = c.KeyExchange
		}
	}

	// Weak protocol versions are an immediate indicator of weakness.
	// Check both the negotiated version and the enumerated supported versions.
	if isWeakProtocol(input.Protocol, input.ProtocolVersion) {
		v := ""
		if input.ProtocolVersion != nil {
			v = " " + *input.ProtocolVersion
		}
		weakReasons = append(weakReasons, fmt.Sprintf("Weak protocol: %s%s", input.Protocol, v))
	}
	if hasWeakTLSVersion(input.SupportedTLSVersions) {
		legacy := legacyTLSVersions(input.SupportedTLSVersions)
		weakReasons = append(weakReasons, fmt.Sprintf("Server accepts legacy TLS: %s", strings.Join(legacy, ", ")))
	}

	// --- DH/RSA key size gate ---
	// When key_exchange is DHE/DH and a key_size is reported, check thresholds
	// regardless of what the algorithms table says about the generic "DHE" code.
	weakReasons = append(weakReasons, s.assessKeyExchangeSize(input)...)

	// --- Certificate public key size gate ---
	weakReasons = append(weakReasons, assessCertPublicKeySize(input)...)

	// --- Certificate signature algorithm check ---
	weakReasons = append(weakReasons, assessCertSignatureAlgorithm(input)...)

	// --- Certificate validation status check ---
	weakReasons = append(weakReasons, assessCertValidationStatus(input)...)

	// --- Sensor-level certificate quality flags ---
	weakReasons = append(weakReasons, assessSensorCertFlags(input)...)

	// If we already found weak reasons from protocol or key size, mark weak
	// but continue checking for additional reasons to give a complete report.
	hasWeakFlag := len(weakReasons) > 0

	// Whole cipher suite as a single algorithms.code (seed includes many IANA names).
	// Prefer this path because the full suite row carries the authoritative assessment
	// without needing to compose component-level verdicts.
	if input.CipherSuite != nil {
		raw := strings.TrimSpace(*input.CipherSuite)
		if raw != "" {
			if suiteAlg, err := s.algorithms.GetAlgorithmByCodeCI(raw); err == nil && suiteAlg != nil {
				if isWeakAlgorithm(suiteAlg) {
					weakReasons = append(weakReasons, fmt.Sprintf("Weak cipher suite: %s", raw))
					return "weak", suiteAlg.IsPQC && suiteAlg.PQCStandardizationStatus == "standardized", kex, weakReasons
				}
				if hasWeakFlag {
					return "weak", false, kex, weakReasons
				}
				if suiteAlg.IsPQC && suiteAlg.PQCStandardizationStatus == "standardized" {
					isPQC = true
				}
				return "good", isPQC, kex, weakReasons
			}
		}
	}

	if components == nil {
		if hasWeakFlag {
			return "weak", false, kex, weakReasons
		}
		return strength, isPQC, kex, weakReasons
	}

	goodCount := 0
	totalChecked := 0

	for _, code := range []string{components.KeyExchange, components.Signature, components.Symmetric, components.Hash} {
		if code == "" {
			continue
		}
		alg, err := s.resolveAlgorithmForComponent(code)
		if err != nil || alg == nil {
			// No matching row — skip rather than treating as weak/good
			continue
		}
		totalChecked++
		if isWeakAlgorithm(alg) {
			weakReasons = append(weakReasons, fmt.Sprintf("Weak %s: %s (%s, %s)", alg.Category, code, alg.Strength, alg.DeprecationStatus))
			hasWeakFlag = true
			continue // keep checking for more reasons
		}
		if alg.IsPQC && alg.PQCStandardizationStatus == "standardized" {
			isPQC = true
		}
		goodCount++
	}

	if hasWeakFlag {
		return "weak", false, kex, weakReasons
	}
	if totalChecked > 0 && goodCount == totalChecked {
		strength = "good"
	}
	return strength, isPQC, kex, weakReasons
}

// assessKeyExchangeSize checks the key exchange key size against NIST thresholds.
// Returns weak reasons for sub-standard key sizes on DH and RSA key exchanges.
func (s *ExternalConnectionsService) assessKeyExchangeSize(input models.ExternalConnectionUpsert) []string {
	if input.KeySize == nil || *input.KeySize == 0 {
		return nil
	}
	keySize := *input.KeySize

	// Determine the key exchange type from explicit field or parsed cipher suite
	kexType := ""
	if input.KeyExchangeAlgorithm != nil {
		kexType = strings.ToUpper(strings.TrimSpace(*input.KeyExchangeAlgorithm))
	}

	var reasons []string

	switch {
	case strings.HasPrefix(kexType, "DH") && !strings.HasPrefix(kexType, "ECDHE"):
		// DH, DHE, DH-*, etc. (not ECDHE)
		reasons = s.checkDHKeySize(kexType, keySize)
	case strings.HasPrefix(kexType, "RSA"):
		reasons = s.checkRSAKeySize(kexType, keySize)
	case kexType == "STATIC-RSA":
		reasons = append(reasons, "No forward secrecy: static RSA key exchange")
		reasons = append(reasons, s.checkRSAKeySize(kexType, keySize)...)
	}

	return reasons
}

// checkDHKeySize evaluates Diffie-Hellman key exchange key sizes.
func (s *ExternalConnectionsService) checkDHKeySize(kexType string, keySize int) []string {
	var reasons []string

	if keySize < 1024 {
		reasons = append(reasons, fmt.Sprintf("Critical: %s key exchange with %d-bit modulus (trivially factorable, Logjam CVE-2015-4000)", kexType, keySize))
	} else if keySize < 2048 {
		reasons = append(reasons, fmt.Sprintf("Weak: %s key exchange with %d-bit modulus (below NIST SP 800-131A minimum of 2048 bits)", kexType, keySize))
	}

	return reasons
}

// checkRSAKeySize evaluates RSA key exchange key sizes.
func (s *ExternalConnectionsService) checkRSAKeySize(kexType string, keySize int) []string {
	var reasons []string

	if keySize < 1024 {
		reasons = append(reasons, fmt.Sprintf("Critical: %s key exchange with %d-bit key (trivially factorable)", kexType, keySize))
	} else if keySize < 2048 {
		reasons = append(reasons, fmt.Sprintf("Weak: %s key exchange with %d-bit key (below NIST SP 800-131A minimum of 2048 bits)", kexType, keySize))
	}

	return reasons
}

// legacyTLSVersions extracts the weak versions from a supported versions list.
func legacyTLSVersions(versions []string) []string {
	var legacy []string
	for _, v := range versions {
		upper := strings.ToUpper(strings.TrimSpace(v))
		if strings.Contains(upper, "SSL") || upper == "TLS 1.0" || upper == "TLS 1.1" {
			legacy = append(legacy, v)
		}
	}
	return legacy
}

// assessCertPublicKeySize checks the certificate's public key size against NIST thresholds.
func assessCertPublicKeySize(input models.ExternalConnectionUpsert) []string {
	if input.CertPublicKeySize == nil || *input.CertPublicKeySize == 0 {
		return nil
	}
	keySize := *input.CertPublicKeySize
	alg := ""
	if input.CertPublicKeyAlgorithm != nil {
		alg = strings.ToUpper(strings.TrimSpace(*input.CertPublicKeyAlgorithm))
	}

	var reasons []string
	switch {
	case strings.Contains(alg, "RSA"):
		if keySize < 1024 {
			reasons = append(reasons, fmt.Sprintf("Critical: certificate RSA public key is %d bits (trivially factorable)", keySize))
		} else if keySize < 2048 {
			reasons = append(reasons, fmt.Sprintf("Weak: certificate RSA public key is %d bits (below NIST minimum of 2048)", keySize))
		}
	case strings.Contains(alg, "EC") || strings.Contains(alg, "ECDSA"):
		if keySize < 224 {
			reasons = append(reasons, fmt.Sprintf("Weak: certificate ECDSA public key is %d bits (below NIST minimum of 224)", keySize))
		}
	}
	return reasons
}

// assessCertSignatureAlgorithm checks for weak certificate signature algorithms.
func assessCertSignatureAlgorithm(input models.ExternalConnectionUpsert) []string {
	if input.CertSignatureAlgorithm == nil {
		return nil
	}
	sig := strings.ToUpper(strings.TrimSpace(*input.CertSignatureAlgorithm))
	if sig == "" {
		return nil
	}

	var reasons []string
	switch {
	case strings.Contains(sig, "MD5"):
		reasons = append(reasons, "Critical: certificate signed with MD5 (collision attacks demonstrated)")
	case strings.Contains(sig, "MD2"):
		reasons = append(reasons, "Critical: certificate signed with MD2 (cryptographically broken)")
	case strings.Contains(sig, "SHA1") || strings.Contains(sig, "SHA-1"):
		reasons = append(reasons, "Weak: certificate signed with SHA-1 (deprecated, collision attacks demonstrated)")
	}
	return reasons
}

// assessCertValidationStatus adds weak reasons for certificate trust issues.
func assessCertValidationStatus(input models.ExternalConnectionUpsert) []string {
	if input.CertValidationStatus == nil {
		return nil
	}
	status := strings.ToLower(strings.TrimSpace(*input.CertValidationStatus))
	if status == "" || status == "valid" {
		return nil
	}

	var reasons []string
	switch status {
	case "self_signed":
		reasons = append(reasons, "Certificate is self-signed (not issued by a trusted CA)")
	case "expired":
		reasons = append(reasons, "Certificate has expired or is not yet valid")
	case "hostname_mismatch":
		reasons = append(reasons, "Certificate hostname does not match the server")
	case "untrusted_ca":
		reasons = append(reasons, "Certificate signed by an untrusted certificate authority")
	case "incomplete_chain":
		reasons = append(reasons, "Incomplete certificate chain (missing intermediate certificates)")
	case "revoked":
		reasons = append(reasons, "Certificate has been revoked")
	default:
		reasons = append(reasons, fmt.Sprintf("Certificate validation issue: %s", status))
	}
	return reasons
}

// assessSensorCertFlags checks sensor-level certificate quality flags and produces
// weak_reasons for issues that the structured field checks above can't detect.
func assessSensorCertFlags(input models.ExternalConnectionUpsert) []string {
	var reasons []string

	if input.CertKnownBadCA != nil && *input.CertKnownBadCA != "" {
		reasons = append(reasons, fmt.Sprintf("Critical: certificate chain includes known-bad CA: %s", *input.CertKnownBadCA))
	}

	if input.CertHasSCT != nil && !*input.CertHasSCT {
		reasons = append(reasons, "Certificate missing Signed Certificate Timestamps (SCTs) — not logged in Certificate Transparency")
	}

	if input.CertNoSubject {
		reasons = append(reasons, "Certificate has no Subject DN")
	} else if input.CertNoCommonName {
		reasons = append(reasons, "Certificate has no Common Name in Subject DN")
	}

	if input.OCSPStatus != nil && *input.OCSPStatus == "revoked" {
		vs := ""
		if input.CertValidationStatus != nil {
			vs = strings.ToLower(strings.TrimSpace(*input.CertValidationStatus))
		}
		if vs != "revoked" {
			reasons = append(reasons, "Certificate has been revoked (OCSP)")
		}
	}

	return reasons
}

// isWeakProtocol returns true if the protocol version is known-weak (SSLv2/3, TLS 1.0/1.1).
// IKE is handled as a protocol name (not "IPsec/IKE") — no SSL check needed.
func isWeakProtocol(protocol string, version *string) bool {
	p := strings.ToUpper(strings.TrimSpace(protocol))
	if strings.Contains(p, "SSL") {
		return true
	}
	if p == "TLS" && version != nil {
		v := strings.TrimSpace(*version)
		if v == "1.0" || v == "1.1" || v == "1" {
			return true
		}
	}
	return false
}

// hasWeakTLSVersion returns true if the enumerated supported TLS versions list
// contains any weak version (TLS 1.0, TLS 1.1, or any SSL variant). This catches
// servers that negotiate TLS 1.2+ but still accept legacy versions.
func hasWeakTLSVersion(versions []string) bool {
	for _, v := range versions {
		upper := strings.ToUpper(strings.TrimSpace(v))
		if strings.Contains(upper, "SSL") {
			return true
		}
		// "TLS 1.0", "TLS 1.1" from the enumerator
		if upper == "TLS 1.0" || upper == "TLS 1.1" {
			return true
		}
	}
	return false
}

// isWeakAlgorithm returns true if the algorithm should be considered weak.
func isWeakAlgorithm(alg *Algorithm) bool {
	if alg.Strength == "weak" {
		return true
	}
	switch alg.DeprecationStatus {
	case "deprecated", "obsolete":
		return true
	}
	return false
}

// determineChangeType figures out what kind of history row to write.
// Returns (changeType, shouldRecord).
func (s *ExternalConnectionsService) determineChangeType(
	isNew bool,
	prevCipher, prevProto, prevStrength string, prevIsPQC bool,
	prevFingerprint string, prevCertNotAfter sql.NullTime,
	conn *models.ExternalConnection,
) (string, bool) {
	if isNew {
		return "first_seen", true
	}

	// Cert rotation: fingerprint changed and we have a new one
	newFP := ""
	if conn.CertFingerprintSHA256 != nil {
		newFP = *conn.CertFingerprintSHA256
	}
	if newFP != "" && prevFingerprint != "" && newFP != prevFingerprint {
		return "cert_rotated", true
	}

	// Cipher suite changed
	newCS := ""
	if conn.CipherSuite != nil {
		newCS = *conn.CipherSuite
	}
	if newCS != "" && prevCipher != "" && newCS != prevCipher {
		return "cipher_changed", true
	}

	// Protocol version changed
	newPV := ""
	if conn.ProtocolVersion != nil {
		newPV = *conn.ProtocolVersion
	}
	if newPV != "" && prevProto != "" && newPV != prevProto {
		if isVersionUpgrade(prevProto, newPV) {
			return "protocol_upgraded", true
		}
		return "protocol_downgraded", true
	}

	// Crypto strength changed
	if prevStrength != "" && conn.CryptoStrength != prevStrength {
		return "crypto_strength_changed", true
	}

	return "", false
}

// isVersionUpgrade returns true if newVersion is numerically higher than prevVersion.
func isVersionUpgrade(prev, next string) bool {
	parseTLSVer := func(v string) float64 {
		v = strings.TrimPrefix(strings.ToUpper(v), "TLS")
		v = strings.TrimSpace(v)
		var f float64
		_, _ = fmt.Sscanf(v, "%f", &f)
		return f
	}
	return parseTLSVer(next) > parseTLSVer(prev)
}

// List returns paginated external connections for the tenant.
func (s *ExternalConnectionsService) List(tenantID uuid.UUID, f models.ExternalConnectionFilters) ([]models.ExternalConnection, int, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 {
		f.PageSize = 20
	}
	if f.PageSize > 100 {
		f.PageSize = 100
	}
	if f.SortOrder != "asc" && f.SortOrder != "desc" {
		f.SortOrder = "desc"
	}
	sortCol := "last_seen_at"
	switch f.SortBy {
	case "last_seen_at", "dest_hostname", "dest_ip", "source_ip", "protocol", "crypto_strength", "observation_count":
		sortCol = f.SortBy
	}
	sortOrder := "DESC"
	if strings.ToUpper(f.SortOrder) == "ASC" {
		sortOrder = "ASC"
	}

	args := []interface{}{tenantID}
	argIdx := 2
	where := []string{"tenant_id = $1"}

	if f.Search != "" {
		where = append(where, fmt.Sprintf("(dest_hostname ILIKE $%d OR dest_ip::text ILIKE $%d)", argIdx, argIdx))
		args = append(args, "%"+f.Search+"%")
		argIdx++
	}
	if f.CryptoStrength != "" {
		where = append(where, fmt.Sprintf("crypto_strength = $%d", argIdx))
		args = append(args, f.CryptoStrength)
		argIdx++
	}
	if f.IsPQCResistant != nil {
		where = append(where, fmt.Sprintf("is_pqc_resistant = $%d", argIdx))
		args = append(args, *f.IsPQCResistant)
		argIdx++
	}
	if f.CertExpired != nil {
		where = append(where, fmt.Sprintf("cert_is_expired = $%d", argIdx))
		args = append(args, *f.CertExpired)
		argIdx++
	}
	if f.CertTrustIssue != nil && *f.CertTrustIssue {
		where = append(where, "(cert_validation_status IS NOT NULL AND LOWER(TRIM(cert_validation_status)) <> 'valid')")
	}
	if f.HasLegacyTLS != nil && *f.HasLegacyTLS {
		where = append(where, "supported_tls_versions && ARRAY['TLS 1.0','TLS 1.1']::text[]")
	}
	if f.SourceAssetID != nil {
		where = append(where, fmt.Sprintf("source_asset_id = $%d", argIdx))
		args = append(args, *f.SourceAssetID)
		argIdx++
	}

	whereSQL := strings.Join(where, " AND ")
	offset := (f.Page - 1) * f.PageSize

	// Snapshot the count args before pagination params are appended; the count
	// and the page run together inside one tenant tx below.
	countArgs := append([]interface{}{}, args...)

	args = append(args, f.PageSize, offset)
	listSQL := fmt.Sprintf(`
		SELECT
			id, tenant_id,
			source_ip::text, source_hostname, source_asset_id,
			dest_ip::text, dest_hostname, dest_port,
			protocol, protocol_version, cipher_suite, key_exchange_algorithm, key_size,
			supported_tls_versions,
			crypto_strength, is_pqc_resistant, weak_reasons,
			cert_subject, cert_issuer, cert_san,
			cert_not_before, cert_not_after, cert_fingerprint_sha256,
			cert_public_key_algorithm, cert_public_key_size, cert_signature_algorithm,
			cert_is_expired, cert_validation_status, cert_pem,
			first_seen_at, last_seen_at, observation_count, sensor_id,
			created_at, updated_at, elevated_asset_id
		FROM external_connections
		WHERE %s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d`,
		whereSQL, sortCol, sortOrder, argIdx, argIdx+1)

	// RLS-scoped reads over external_connections — count + page in one tenant tx.
	var total int
	var list []models.ExternalConnection
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		if e := tx.QueryRow("SELECT COUNT(*) FROM external_connections WHERE "+whereSQL, countArgs...).Scan(&total); e != nil {
			return fmt.Errorf("count external connections: %w", e)
		}

		rows, e := tx.Query(listSQL, args...)
		if e != nil {
			return fmt.Errorf("list external connections: %w", e)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var conn models.ExternalConnection
			var certSAN pq.StringArray
			var scanSTV pq.StringArray
			var scanWR pq.StringArray
			if e := rows.Scan(
				&conn.ID, &conn.TenantID,
				&conn.SourceIP, &conn.SourceHostname, &conn.SourceAssetID,
				&conn.DestIP, &conn.DestHostname, &conn.DestPort,
				&conn.Protocol, &conn.ProtocolVersion, &conn.CipherSuite, &conn.KeyExchangeAlgorithm, &conn.KeySize,
				&scanSTV,
				&conn.CryptoStrength, &conn.IsPQCResistant, &scanWR,
				&conn.CertSubject, &conn.CertIssuer, &certSAN,
				&conn.CertNotBefore, &conn.CertNotAfter, &conn.CertFingerprintSHA256,
				&conn.CertPublicKeyAlgorithm, &conn.CertPublicKeySize, &conn.CertSignatureAlgorithm,
				&conn.CertIsExpired, &conn.CertValidationStatus, &conn.CertPEM,
				&conn.FirstSeenAt, &conn.LastSeenAt, &conn.ObservationCount, &conn.SensorID,
				&conn.CreatedAt, &conn.UpdatedAt, &conn.ElevatedAssetID,
			); e != nil {
				return fmt.Errorf("scan external connection: %w", e)
			}
			if len(certSAN) > 0 {
				conn.CertSAN = []string(certSAN)
			}
			if len(scanSTV) > 0 {
				conn.SupportedTLSVersions = []string(scanSTV)
			}
			if len(scanWR) > 0 {
				conn.WeakReasons = []string(scanWR)
			}
			list = append(list, conn)
		}
		if e := rows.Err(); e != nil {
			return fmt.Errorf("rows error: %w", e)
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return list, total, nil
}

// GetByID retrieves a single external connection.
func (s *ExternalConnectionsService) GetByID(tenantID, id uuid.UUID) (*models.ExternalConnection, error) {
	var conn models.ExternalConnection
	var certSAN pq.StringArray
	var scanSTV pq.StringArray
	var scanWR pq.StringArray
	// RLS-scoped read over external_connections — WithTenantTx returns fn's error
	// verbatim, so the sql.ErrNoRows check below still works.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`
			SELECT
				id, tenant_id,
				source_ip::text, source_hostname, source_asset_id,
				dest_ip::text, dest_hostname, dest_port,
				protocol, protocol_version, cipher_suite, key_exchange_algorithm, key_size,
				supported_tls_versions,
				crypto_strength, is_pqc_resistant, weak_reasons,
				cert_subject, cert_issuer, cert_san,
				cert_not_before, cert_not_after, cert_fingerprint_sha256,
				cert_public_key_algorithm, cert_public_key_size, cert_signature_algorithm,
				cert_is_expired, cert_validation_status, cert_pem,
				first_seen_at, last_seen_at, observation_count, sensor_id,
				created_at, updated_at, elevated_asset_id
			FROM external_connections
			WHERE id = $1 AND tenant_id = $2`,
			id, tenantID,
		).Scan(
			&conn.ID, &conn.TenantID,
			&conn.SourceIP, &conn.SourceHostname, &conn.SourceAssetID,
			&conn.DestIP, &conn.DestHostname, &conn.DestPort,
			&conn.Protocol, &conn.ProtocolVersion, &conn.CipherSuite, &conn.KeyExchangeAlgorithm, &conn.KeySize,
			&scanSTV,
			&conn.CryptoStrength, &conn.IsPQCResistant, &scanWR,
			&conn.CertSubject, &conn.CertIssuer, &certSAN,
			&conn.CertNotBefore, &conn.CertNotAfter, &conn.CertFingerprintSHA256,
			&conn.CertPublicKeyAlgorithm, &conn.CertPublicKeySize, &conn.CertSignatureAlgorithm,
			&conn.CertIsExpired, &conn.CertValidationStatus, &conn.CertPEM,
			&conn.FirstSeenAt, &conn.LastSeenAt, &conn.ObservationCount, &conn.SensorID,
			&conn.CreatedAt, &conn.UpdatedAt, &conn.ElevatedAssetID,
		)
	})
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get external connection by id: %w", err)
	}
	if len(certSAN) > 0 {
		conn.CertSAN = []string(certSAN)
	}
	if len(scanSTV) > 0 {
		conn.SupportedTLSVersions = []string(scanSTV)
	}
	if len(scanWR) > 0 {
		conn.WeakReasons = []string(scanWR)
	}
	return &conn, nil
}

// MarkElevated links a 3rd-party connection to the managed asset a tenant
// elevated it into. Tenant-scoped; returns an error if no row matched.
func (s *ExternalConnectionsService) MarkElevated(tenantID, connID, assetID uuid.UUID) error {
	// RLS-scoped write over external_connections.
	var rowsAffected int64
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		res, e := tx.Exec(
			`UPDATE external_connections SET elevated_asset_id = $1, updated_at = NOW()
			 WHERE id = $2 AND tenant_id = $3`,
			assetID, connID, tenantID)
		if e != nil {
			return e
		}
		rowsAffected, _ = res.RowsAffected()
		return nil
	})
	if err != nil {
		return fmt.Errorf("mark connection elevated: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("external connection %s not found", connID)
	}
	return nil
}

// GetHistory returns paginated history for a single external connection.
func (s *ExternalConnectionsService) GetHistory(tenantID, connectionID uuid.UUID, page, pageSize int) ([]models.ExternalConnectionHistory, int, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}

	offset := (page - 1) * pageSize

	// RLS-scoped reads over external_connection_history — count + page in one tenant tx.
	var total int
	var history []models.ExternalConnectionHistory
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		if e := tx.QueryRow(
			`SELECT COUNT(*) FROM external_connection_history WHERE external_connection_id = $1 AND tenant_id = $2`,
			connectionID, tenantID,
		).Scan(&total); e != nil {
			return fmt.Errorf("count history: %w", e)
		}

		rows, e := tx.Query(`
			SELECT
				id, external_connection_id, tenant_id, change_type,
				previous_protocol_version, previous_cipher_suite, previous_crypto_strength,
				previous_is_pqc_resistant, previous_cert_fingerprint_sha256, previous_cert_not_after,
				new_protocol_version, new_cipher_suite, new_crypto_strength,
				new_is_pqc_resistant, new_cert_fingerprint_sha256, new_cert_not_after,
				created_at
			FROM external_connection_history
			WHERE external_connection_id = $1 AND tenant_id = $2
			ORDER BY created_at DESC
			LIMIT $3 OFFSET $4`,
			connectionID, tenantID, pageSize, offset,
		)
		if e != nil {
			return fmt.Errorf("list history: %w", e)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var h models.ExternalConnectionHistory
			if e := rows.Scan(
				&h.ID, &h.ExternalConnectionID, &h.TenantID, &h.ChangeType,
				&h.PreviousProtocolVersion, &h.PreviousCipherSuite, &h.PreviousCryptoStrength,
				&h.PreviousIsPQCResistant, &h.PreviousCertFingerprintSHA256, &h.PreviousCertNotAfter,
				&h.NewProtocolVersion, &h.NewCipherSuite, &h.NewCryptoStrength,
				&h.NewIsPQCResistant, &h.NewCertFingerprintSHA256, &h.NewCertNotAfter,
				&h.CreatedAt,
			); e != nil {
				return fmt.Errorf("scan history: %w", e)
			}
			history = append(history, h)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, err
	}
	return history, total, nil
}

// GetSummary returns aggregate counts for the summary card row.
func (s *ExternalConnectionsService) GetSummary(tenantID uuid.UUID) (*models.ExternalConnectionsSummary, error) {
	var summary models.ExternalConnectionsSummary
	// RLS-scoped read over external_connections.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`
			SELECT
				COUNT(*) AS total,
				COUNT(*) FILTER (WHERE crypto_strength = 'weak') AS weak_crypto,
				COUNT(*) FILTER (WHERE is_pqc_resistant = true) AS pqc_resistant,
				COUNT(*) FILTER (WHERE cert_is_expired = true) AS expired_certs,
				COUNT(*) FILTER (WHERE supported_tls_versions && ARRAY['TLS 1.0','TLS 1.1']::text[]) AS legacy_tls,
				COUNT(DISTINCT source_ip) AS source_hosts
			FROM external_connections
			WHERE tenant_id = $1`,
			tenantID,
		).Scan(&summary.Total, &summary.WeakCrypto, &summary.PQCResistant, &summary.ExpiredCerts, &summary.LegacyTLS, &summary.SourceHosts)
	})
	if err != nil {
		return nil, fmt.Errorf("get external connections summary: %w", err)
	}
	return &summary, nil
}

// Delete hard-deletes an external connection (history cascades via FK).
func (s *ExternalConnectionsService) Delete(tenantID, id uuid.UUID) error {
	// RLS-scoped delete over external_connections (history cascades via FK).
	var rowsAffected int64
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		result, e := tx.Exec(
			`DELETE FROM external_connections WHERE id = $1 AND tenant_id = $2`,
			id, tenantID,
		)
		if e != nil {
			return e
		}
		rowsAffected, _ = result.RowsAffected()
		return nil
	})
	if err != nil {
		return fmt.Errorf("delete external connection: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("external connection not found")
	}
	return nil
}
