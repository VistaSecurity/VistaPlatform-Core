package services

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// MeasurementExtractor extracts measurements from inventory for compliance evaluation.
//
// # Deleted inventory is not in scope, and forgetting that resurrects findings
//
// Asset deletion is a SOFT delete: inventory-service's DeleteAsset only stamps
// network_assets.deleted_at, and deliberately leaves the asset's
// crypto_implementations rows alone. FindingsService.OnAssetDeleted then flips
// that asset's findings to INACTIVE.
//
// Every crypto_implementations query below therefore has to carry BOTH
// `na.deleted_at IS NULL` and `ci.deleted_at IS NULL`. Without them a whole-tenant
// reconcile re-extracts the deleted asset, recomputes the same violation, and
// upsertFindings flips the INACTIVE rows straight back to ACTIVE — with
// workflow_status reset to NEW and resurfaced_at stamped, so the tenant loses
// triage state and their score drops again for an asset that no longer exists.
// The two predicates are independent: an asset delete sets only na.deleted_at,
// while a crypto-implementation delete sets only ci.deleted_at.
//
// The `certificates` queries need no equivalent — that table has no deleted_at
// column; a certificate is either present or gone.
type MeasurementExtractor struct {
	db *sqlx.DB
}

// NewMeasurementExtractor creates a new measurement extractor
func NewMeasurementExtractor(db *sqlx.DB) *MeasurementExtractor {
	return &MeasurementExtractor{db: db}
}

// MeasurementValue represents a measurement value with metadata
type MeasurementValue struct {
	Value      interface{}            `json:"value"`
	AssetID    uuid.UUID              `json:"asset_id"`
	AssetType  string                 `json:"asset_type"` // network_asset, certificate, crypto_implementation
	TenantID   uuid.UUID              `json:"tenant_id"`
	MeasuredAt time.Time              `json:"measured_at"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// ExtractMeasurementsForAsset returns the measurement values for a single asset
// (ADR-0015 per-asset reconcile: a change folds controls over one asset's values and
// reconciles only that asset's findings). The asset filter is pushed into each
// extractor's SQL, so a per-asset reconcile reads only that asset's rows.
func (s *MeasurementExtractor) ExtractMeasurementsForAsset(tenantID, assetID uuid.UUID, measurementTypeCode string) ([]MeasurementValue, error) {
	return s.extract(tenantID, assetID, measurementTypeCode)
}

// ExtractMeasurements extracts measurements for a given measurement type and tenant
// (all assets).
func (s *MeasurementExtractor) ExtractMeasurements(tenantID uuid.UUID, measurementTypeCode string) ([]MeasurementValue, error) {
	return s.extract(tenantID, uuid.Nil, measurementTypeCode)
}

// extract dispatches to the per-type extractor. assetID == uuid.Nil means "all
// assets for the tenant"; a concrete assetID scopes extraction to that one asset
// (each extractor filters by `($2::uuid IS NULL OR <id> = $2)`).
func (s *MeasurementExtractor) extract(tenantID, assetID uuid.UUID, measurementTypeCode string) ([]MeasurementValue, error) {
	switch measurementTypeCode {
	case "cert_expiration_days":
		return s.GetCertificateExpirationDays(tenantID, assetID)
	case "tls_version":
		return s.GetTLSVersion(tenantID, assetID)
	case "key_size":
		return s.GetKeySize(tenantID, assetID)
	case "key_size_ec":
		return s.GetECKeySize(tenantID, assetID)
	case "cert_algorithm":
		return s.GetCertificateAlgorithm(tenantID, assetID)
	case "cert_pqc_status":
		return s.GetCertificatePQCStatus(tenantID, assetID)
	case "cert_sig_pqc_status":
		return s.GetCertificateSignaturePQCStatus(tenantID, assetID)
	case "config_kex_pqc_status":
		return s.GetConfigKeyExchangePQCStatus(tenantID, assetID)
	case "config_sig_pqc_status":
		return s.GetConfigSignaturePQCStatus(tenantID, assetID)
	case "config_sym_strength":
		return s.GetConfigSymmetricStrength(tenantID, assetID)
	case "cert_validity_days":
		return s.GetCertificateValidityDays(tenantID, assetID)
	case "key_exchange_algorithm":
		return s.GetKeyExchangeAlgorithm(tenantID, assetID)
	case "symmetric_encryption":
		return s.GetSymmetricEncryption(tenantID, assetID)
	case "hash_algorithm":
		return s.GetHashAlgorithm(tenantID, assetID)
	case "cipher_suite_name":
		return s.GetCipherSuiteName(tenantID, assetID)
	case "pfs_support":
		return s.GetPFSSupport(tenantID, assetID)
	case "tls_compression_enabled":
		return s.GetTLSCompressionEnabled(tenantID, assetID)
	case "certificate_chain_valid":
		return s.GetCertificateChainValid(tenantID, assetID)
	case "ot_protocol_encryption":
		return s.GetOTProtocolEncryption(tenantID, assetID)
	default:
		return nil, fmt.Errorf("unsupported measurement type: %s", measurementTypeCode)
	}
}

// assetArg maps a uuid.Nil "all assets" sentinel to a SQL NULL and a concrete asset
// id to itself, for the `($2::uuid IS NULL OR <id> = $2)` filter every extractor uses.
func assetArg(assetID uuid.UUID) interface{} {
	if assetID == uuid.Nil {
		return nil
	}
	return assetID
}

// classifyPQCAlgorithm maps a certificate public-key algorithm to its post-quantum
// readiness: "quantum_safe" for a NIST PQC family (ML-KEM/Kyber, ML-DSA/Dilithium,
// SLH-DSA/SPHINCS+, FN-DSA/Falcon), else "quantum_vulnerable". Classical RSA/ECDSA/
// EdDSA/DSA/DH and any unrecognized algorithm are treated as vulnerable — if we can't
// prove a key is post-quantum, it must be assumed at risk. Pure (no DB).
func classifyPQCAlgorithm(algorithm string) string {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	pqc := []string{"ML-KEM", "MLKEM", "KYBER", "ML-DSA", "MLDSA", "DILITHIUM", "SLH-DSA", "SLHDSA", "SPHINCS", "FALCON", "FN-DSA", "FNDSA"}
	for _, p := range pqc {
		if strings.Contains(a, p) {
			return "quantum_safe"
		}
	}
	return "quantum_vulnerable"
}

// classifySymmetricQuantumMargin maps a symmetric cipher to its post-quantum margin:
// "quantum_safe" for AES-192/256 or ChaCha20 (>=128-bit security retained under Grover's
// quadratic speedup), else "quantum_marginal" (AES-128 and weaker — below the CNSA 2.0 /
// post-quantum margin). Advisory: symmetric crypto is weakened, not broken, by quantum.
// Pure (no DB). Unknown/empty is treated as marginal (assume-at-risk, like the PQC
// classifier).
func classifySymmetricQuantumMargin(algorithm string) string {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	safe := []string{"AES-256", "AES256", "AES_256", "AES-192", "AES192", "AES_192", "CHACHA20"}
	for _, s := range safe {
		if strings.Contains(a, s) {
			return "quantum_safe"
		}
	}
	return "quantum_marginal"
}

// GetCertificatePQCStatus classifies each leaf certificate's public-key algorithm as
// quantum_vulnerable or quantum_safe (ADR-0015 /). A pattern rule
// {"pattern":"^quantum_vulnerable$","match_means_violation":true} flags vulnerable
// certs for the opt-in PQC Readiness framework. Per-asset scoped via assetArg.
func (s *MeasurementExtractor) GetCertificatePQCStatus(tenantID, assetID uuid.UUID) ([]MeasurementValue, error) {
	query := `
		SELECT
			c.id as asset_id,
			c.tenant_id,
			c.public_key_algorithm,
			c.updated_at as measured_at,
			c.common_name
		FROM certificates c
		WHERE c.tenant_id = $1
			AND ($2::uuid IS NULL OR c.id = $2)
			AND c.is_ca_certificate = false
		ORDER BY c.updated_at DESC
	`
	// RLS-scoped read of certificates (tenant_isolation policy). WithTenantTx sets
	// app.tenant_id; the explicit WHERE c.tenant_id = $1 stays as the primary control.
	var measurements []MeasurementValue
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qerr := tx.QueryContext(context.Background(), query, tenantID, assetArg(assetID))
		if qerr != nil {
			return fmt.Errorf("failed to query certificate PQC status: %w", qerr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var rowAssetID, rowTenantID uuid.UUID
			var algorithm, commonName sql.NullString
			var measuredAt time.Time
			if err := rows.Scan(&rowAssetID, &rowTenantID, &algorithm, &measuredAt, &commonName); err != nil {
				return fmt.Errorf("failed to scan certificate PQC status: %w", err)
			}
			metadata := make(map[string]interface{})
			if commonName.Valid {
				metadata["common_name"] = commonName.String
			}
			if algorithm.Valid {
				metadata["algorithm"] = algorithm.String
			}
			measurements = append(measurements, MeasurementValue{
				Value:      classifyPQCAlgorithm(algorithm.String),
				AssetID:    rowAssetID,
				AssetType:  "certificate",
				TenantID:   rowTenantID,
				MeasuredAt: measuredAt,
				Metadata:   metadata,
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return measurements, nil
}

// GetCertificateSignaturePQCStatus classifies each leaf certificate's SIGNATURE
// algorithm (the algorithm its CA signed it with) as quantum_vulnerable or quantum_safe
// ( PQC-002). Distinct from cert_pqc_status, which classifies the cert's own public
// key. A pattern rule {"pattern":"^quantum_vulnerable$","match_means_violation":true}
// flags vulnerable signatures. Per-asset scoped via assetArg.
func (s *MeasurementExtractor) GetCertificateSignaturePQCStatus(tenantID, assetID uuid.UUID) ([]MeasurementValue, error) {
	query := `
		SELECT
			c.id as asset_id,
			c.tenant_id,
			c.signature_algorithm,
			c.updated_at as measured_at,
			c.common_name
		FROM certificates c
		WHERE c.tenant_id = $1
			AND ($2::uuid IS NULL OR c.id = $2)
			AND c.is_ca_certificate = false
			AND c.signature_algorithm IS NOT NULL
		ORDER BY c.updated_at DESC
	`
	// RLS-scoped read of certificates (tenant_isolation policy).
	var measurements []MeasurementValue
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qerr := tx.QueryContext(context.Background(), query, tenantID, assetArg(assetID))
		if qerr != nil {
			return fmt.Errorf("failed to query certificate signature PQC status: %w", qerr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var rowAssetID, rowTenantID uuid.UUID
			var algorithm, commonName sql.NullString
			var measuredAt time.Time
			if err := rows.Scan(&rowAssetID, &rowTenantID, &algorithm, &measuredAt, &commonName); err != nil {
				return fmt.Errorf("failed to scan certificate signature PQC status: %w", err)
			}
			if !algorithm.Valid {
				continue
			}
			metadata := map[string]interface{}{"signature_algorithm": algorithm.String}
			if commonName.Valid {
				metadata["common_name"] = commonName.String
			}
			measurements = append(measurements, MeasurementValue{
				Value:      classifyPQCAlgorithm(algorithm.String),
				AssetID:    rowAssetID,
				AssetType:  "certificate",
				TenantID:   rowTenantID,
				MeasuredAt: measuredAt,
				Metadata:   metadata,
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return measurements, nil
}

// GetConfigKeyExchangePQCStatus classifies each crypto-config's key-exchange algorithm
// as quantum_vulnerable or quantum_safe ( PQC-003 — the highest-priority PQC control,
// harvest-now-decrypt-later). classifyPQCAlgorithm's substring match already treats a
// hybrid KEX (e.g. X25519MLKEM768 → contains MLKEM) as quantum_safe. Per-asset scoped.
func (s *MeasurementExtractor) GetConfigKeyExchangePQCStatus(tenantID, assetID uuid.UUID) ([]MeasurementValue, error) {
	return s.classifyConfigAlgorithmPQC(tenantID, assetID, "key_exchange_algorithm", "key exchange PQC status")
}

// GetConfigSignaturePQCStatus classifies each crypto-config's signature/authentication
// algorithm as quantum_vulnerable or quantum_safe ( PQC-004). Per-asset scoped.
func (s *MeasurementExtractor) GetConfigSignaturePQCStatus(tenantID, assetID uuid.UUID) ([]MeasurementValue, error) {
	return s.classifyConfigAlgorithmPQC(tenantID, assetID, "signature_algorithm", "signature PQC status")
}

// classifyConfigAlgorithmPQC is the shared body for the per-config asymmetric-algorithm
// PQC measurements (key-exchange and signature): it reads one crypto_implementations
// algorithm column, classifies it with classifyPQCAlgorithm, and emits one
// crypto_implementation MeasurementValue per config that has the column set. column MUST
// be a fixed identifier from this file (never user input) — it is interpolated into SQL.
func (s *MeasurementExtractor) classifyConfigAlgorithmPQC(tenantID, assetID uuid.UUID, column, label string) ([]MeasurementValue, error) {
	query := fmt.Sprintf(`
		SELECT
			na.id as asset_id,
			ci.tenant_id,
			ci.%s,
			ci.last_verified_at as measured_at,
			na.hostname,
			na.ip_address,
			na.port,
			ci.cipher_suite
		FROM crypto_implementations ci
		JOIN network_assets na ON ci.asset_id = na.id
		WHERE ci.tenant_id = $1
			AND na.deleted_at IS NULL
			AND ci.deleted_at IS NULL
			AND ($2::uuid IS NULL OR na.id = $2)
			AND ci.%s IS NOT NULL
		ORDER BY ci.last_verified_at DESC
	`, column, column)

	// RLS-scoped read (tenant_isolation policy). WithTenantTx sets app.tenant_id;
	// the explicit WHERE … tenant_id = $1 stays as the primary control.
	var measurements []MeasurementValue
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qerr := tx.QueryContext(context.Background(), query, tenantID, assetArg(assetID))
		if qerr != nil {
			return fmt.Errorf("failed to query config %s: %w", label, qerr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var rowAssetID, rowTenantID uuid.UUID
			var algorithm sql.NullString
			var measuredAt time.Time
			var hostname, ipAddress, cipherSuite sql.NullString
			var port sql.NullInt64
			if err := rows.Scan(&rowAssetID, &rowTenantID, &algorithm, &measuredAt, &hostname, &ipAddress, &port, &cipherSuite); err != nil {
				return fmt.Errorf("failed to scan config %s: %w", label, err)
			}
			if !algorithm.Valid {
				continue
			}
			metadata := map[string]interface{}{"algorithm": algorithm.String}
			if hostname.Valid {
				metadata["hostname"] = hostname.String
			}
			if ipAddress.Valid {
				metadata["ip_address"] = ipAddress.String
			}
			if port.Valid {
				metadata["port"] = port.Int64
			}
			if cipherSuite.Valid {
				metadata["cipher_suite"] = cipherSuite.String
			}
			measurements = append(measurements, MeasurementValue{
				Value:      classifyPQCAlgorithm(algorithm.String),
				AssetID:    rowAssetID,
				AssetType:  "crypto_implementation",
				TenantID:   rowTenantID,
				MeasuredAt: measuredAt,
				Metadata:   metadata,
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return measurements, nil
}

// GetConfigSymmetricStrength classifies each crypto-config's symmetric cipher quantum
// margin as quantum_safe or quantum_marginal ( PQC-005, advisory). A pattern rule
// {"pattern":"^quantum_marginal$","match_means_violation":true} flags sub-AES-256 ciphers.
// Per-asset scoped via assetArg.
func (s *MeasurementExtractor) GetConfigSymmetricStrength(tenantID, assetID uuid.UUID) ([]MeasurementValue, error) {
	query := `
		SELECT
			na.id as asset_id,
			ci.tenant_id,
			ci.symmetric_encryption,
			ci.last_verified_at as measured_at,
			na.hostname,
			na.ip_address,
			na.port,
			ci.cipher_suite
		FROM crypto_implementations ci
		JOIN network_assets na ON ci.asset_id = na.id
		WHERE ci.tenant_id = $1
			AND na.deleted_at IS NULL
			AND ci.deleted_at IS NULL
			AND ($2::uuid IS NULL OR na.id = $2)
			AND ci.symmetric_encryption IS NOT NULL
		ORDER BY ci.last_verified_at DESC
	`
	// RLS-scoped read (tenant_isolation policy). WithTenantTx sets app.tenant_id;
	// the explicit WHERE … tenant_id = $1 stays as the primary control.
	var measurements []MeasurementValue
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qerr := tx.QueryContext(context.Background(), query, tenantID, assetArg(assetID))
		if qerr != nil {
			return fmt.Errorf("failed to query config symmetric strength: %w", qerr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var rowAssetID, rowTenantID uuid.UUID
			var algorithm sql.NullString
			var measuredAt time.Time
			var hostname, ipAddress, cipherSuite sql.NullString
			var port sql.NullInt64
			if err := rows.Scan(&rowAssetID, &rowTenantID, &algorithm, &measuredAt, &hostname, &ipAddress, &port, &cipherSuite); err != nil {
				return fmt.Errorf("failed to scan config symmetric strength: %w", err)
			}
			if !algorithm.Valid {
				continue
			}
			metadata := map[string]interface{}{"symmetric_encryption": algorithm.String}
			if hostname.Valid {
				metadata["hostname"] = hostname.String
			}
			if ipAddress.Valid {
				metadata["ip_address"] = ipAddress.String
			}
			if port.Valid {
				metadata["port"] = port.Int64
			}
			if cipherSuite.Valid {
				metadata["cipher_suite"] = cipherSuite.String
			}
			measurements = append(measurements, MeasurementValue{
				Value:      classifySymmetricQuantumMargin(algorithm.String),
				AssetID:    rowAssetID,
				AssetType:  "crypto_implementation",
				TenantID:   rowTenantID,
				MeasuredAt: measuredAt,
				Metadata:   metadata,
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return measurements, nil
}

// GetCertificateValidityDays emits each leaf certificate's validity PERIOD in days
// (not_after - not_before) — distinct from cert_expiration_days (days remaining). A
// threshold rule {"operator":"<=","value":398} flags over-long certificate lifetimes
// (the CA/Browser Forum is driving TLS max validity down toward 47 days). Per-asset
// scoped via assetArg.
func (s *MeasurementExtractor) GetCertificateValidityDays(tenantID, assetID uuid.UUID) ([]MeasurementValue, error) {
	query := `
		SELECT
			c.id as asset_id,
			c.tenant_id,
			EXTRACT(EPOCH FROM (c.not_after - c.not_before)) / 86400.0 as validity_days,
			c.updated_at as measured_at,
			c.common_name
		FROM certificates c
		WHERE c.tenant_id = $1
			AND ($2::uuid IS NULL OR c.id = $2)
			AND c.not_after IS NOT NULL
			AND c.not_before IS NOT NULL
			AND c.is_ca_certificate = false
		ORDER BY c.updated_at DESC
	`
	// RLS-scoped read (tenant_isolation policy). WithTenantTx sets app.tenant_id;
	// the explicit WHERE … tenant_id = $1 stays as the primary control.
	var measurements []MeasurementValue
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qerr := tx.QueryContext(context.Background(), query, tenantID, assetArg(assetID))
		if qerr != nil {
			return fmt.Errorf("failed to query certificate validity days: %w", qerr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var rowAssetID, rowTenantID uuid.UUID
			var validityDays float64
			var measuredAt time.Time
			var commonName sql.NullString
			if err := rows.Scan(&rowAssetID, &rowTenantID, &validityDays, &measuredAt, &commonName); err != nil {
				return fmt.Errorf("failed to scan certificate validity days: %w", err)
			}
			metadata := make(map[string]interface{})
			if commonName.Valid {
				metadata["common_name"] = commonName.String
			}
			measurements = append(measurements, MeasurementValue{
				Value:      int(validityDays),
				AssetID:    rowAssetID,
				AssetType:  "certificate",
				TenantID:   rowTenantID,
				MeasuredAt: measuredAt,
				Metadata:   metadata,
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return measurements, nil
}

// GetOTProtocolEncryption emits one MeasurementValue per OT protocol session,
// with Value="absent" when no cryptographic protection is observed and
// Value="present" otherwise. The compliance-engine pattern rule
// {"pattern":"^absent$","match_means_violation":true} fails per "absent"
// row, producing a finding for each unencrypted OT asset.
//
// "Encrypted" here means the crypto_implementations row carries either a
// cipher_suite or a non-empty symmetric_encryption — anything the sensor
// would record only when actual crypto was negotiated. Plaintext OT (Modbus
// without TLS, plaintext DNP3, plaintext S7, plaintext HART-IP, etc.)
// leaves both fields empty. BACnet/SC always carries a TLS handshake so it
// reads as "present" via cipher_suite.
//
// The IN-clause must stay in sync with the OT entries of the protocol_type
// enum (see scripts/database/schema.sql) and with resolveProtocol() in
// services/inventory-service/internal/services/asset_service.go.
func (s *MeasurementExtractor) GetOTProtocolEncryption(tenantID, assetID uuid.UUID) ([]MeasurementValue, error) {
	query := `
		SELECT
			na.id as asset_id,
			ci.tenant_id,
			ci.protocol,
			COALESCE(NULLIF(ci.cipher_suite, ''), '')           AS cipher_suite,
			COALESCE(NULLIF(ci.symmetric_encryption, ''), '')   AS symmetric_encryption,
			ci.last_verified_at as measured_at,
			na.hostname,
			na.ip_address,
			na.port
		FROM crypto_implementations ci
		JOIN network_assets na ON ci.asset_id = na.id
		WHERE ci.tenant_id = $1
			AND na.deleted_at IS NULL
			AND ci.deleted_at IS NULL
			AND ($2::uuid IS NULL OR na.id = $2)
			AND ci.protocol IN ('Modbus','DNP3','MMS','ICCP','BACnet','BACnet_SC','EtherNet_IP','OPC_UA','HART_IP','S7')
		ORDER BY ci.last_verified_at DESC
	`

	// RLS-scoped read (tenant_isolation policy). WithTenantTx sets app.tenant_id;
	// the explicit WHERE … tenant_id = $1 stays as the primary control.
	var measurements []MeasurementValue
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qerr := tx.QueryContext(context.Background(), query, tenantID, assetArg(assetID))
		if qerr != nil {
			return fmt.Errorf("failed to query OT protocol encryption: %w", qerr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var assetID uuid.UUID
			var rowTenantID uuid.UUID
			var protocol string
			var cipherSuite string
			var symmetricEncryption string
			var measuredAt time.Time
			var hostname sql.NullString
			var ipAddress sql.NullString
			var port sql.NullInt64

			if err := rows.Scan(&assetID, &rowTenantID, &protocol, &cipherSuite, &symmetricEncryption, &measuredAt, &hostname, &ipAddress, &port); err != nil {
				return fmt.Errorf("failed to scan OT protocol encryption: %w", err)
			}

			encryptionState := "absent"
			if cipherSuite != "" || symmetricEncryption != "" {
				encryptionState = "present"
			}

			metadata := map[string]interface{}{
				"protocol": protocol,
			}
			if hostname.Valid {
				metadata["hostname"] = hostname.String
			}
			if ipAddress.Valid {
				metadata["ip_address"] = ipAddress.String
			}
			if port.Valid {
				metadata["port"] = port.Int64
			}
			if cipherSuite != "" {
				metadata["cipher_suite"] = cipherSuite
			}

			measurements = append(measurements, MeasurementValue{
				Value:      encryptionState,
				AssetID:    assetID,
				AssetType:  "crypto_implementation",
				TenantID:   rowTenantID,
				MeasuredAt: measuredAt,
				Metadata:   metadata,
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return measurements, nil
}

// GetCertificateExpirationDays calculates days until certificate expiration
func (s *MeasurementExtractor) GetCertificateExpirationDays(tenantID, assetID uuid.UUID) ([]MeasurementValue, error) {
	query := `
		SELECT
			c.id as asset_id,
			c.tenant_id,
			EXTRACT(EPOCH FROM (c.not_after - NOW())) / 86400.0 as expiration_days,
			c.not_after,
			c.common_name,
			c.public_key_algorithm,
			c.public_key_size
		FROM certificates c
		WHERE c.tenant_id = $1
			AND ($2::uuid IS NULL OR c.id = $2)
			AND c.not_after IS NOT NULL
			AND c.is_ca_certificate = false
		ORDER BY c.not_after ASC
	`

	// RLS-scoped read (tenant_isolation policy). WithTenantTx sets app.tenant_id;
	// the explicit WHERE … tenant_id = $1 stays as the primary control.
	var measurements []MeasurementValue
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qerr := tx.QueryContext(context.Background(), query, tenantID, assetArg(assetID))
		if qerr != nil {
			return fmt.Errorf("failed to query certificate expiration: %w", qerr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var assetID uuid.UUID
			var tenantID uuid.UUID
			var expirationDays float64
			var notAfter time.Time
			var commonName sql.NullString
			var algorithm sql.NullString
			var keySize sql.NullInt64

			if err := rows.Scan(&assetID, &tenantID, &expirationDays, &notAfter, &commonName, &algorithm, &keySize); err != nil {
				return fmt.Errorf("failed to scan certificate expiration: %w", err)
			}

			metadata := make(map[string]interface{})
			if commonName.Valid {
				metadata["common_name"] = commonName.String
			}
			if algorithm.Valid {
				metadata["algorithm"] = algorithm.String
			}
			if keySize.Valid {
				metadata["key_size"] = keySize.Int64
			}

			metadata["not_after"] = notAfter

			// Floor, deliberately: a partial day is not a whole day of
			// remaining validity, and for an ALREADY-expired certificate
			// (negative value) floor keeps counting down instead of rounding
			// back toward zero the way Go's int() truncation does — -0.5 days
			// expired reads as -1, not 0 ("expires today").
			measurements = append(measurements, MeasurementValue{
				Value:   int(math.Floor(expirationDays)),
				AssetID: assetID,
				// MeasuredAt is when the measurement was TAKEN, not the
				// certificate's not_after. Using not_after (CMP-10) stamped
				// every finding's first_seen/last_seen with a future date, so
				// "newest finding" ordering and any age-based reporting were
				// wrong by the certificate's remaining lifetime. not_after
				// travels in the evidence metadata instead.
				AssetType:  "certificate",
				TenantID:   tenantID,
				MeasuredAt: time.Now(),
				Metadata:   metadata,
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return measurements, nil
}

// GetTLSVersion gets TLS protocol versions from crypto configurations
func (s *MeasurementExtractor) GetTLSVersion(tenantID, assetID uuid.UUID) ([]MeasurementValue, error) {
	query := `
		SELECT
			na.id as asset_id,
			ci.tenant_id,
			ci.protocol_version,
			ci.last_verified_at as measured_at,
			na.hostname,
			na.ip_address,
			na.port
		FROM crypto_implementations ci
		JOIN network_assets na ON ci.asset_id = na.id
		WHERE ci.tenant_id = $1
			AND na.deleted_at IS NULL
			AND ci.deleted_at IS NULL
			AND ($2::uuid IS NULL OR na.id = $2)
			AND ci.protocol = 'TLS'
			AND ci.protocol_version IS NOT NULL
		ORDER BY ci.last_verified_at DESC
	`

	// RLS-scoped read (tenant_isolation policy). WithTenantTx sets app.tenant_id;
	// the explicit WHERE … tenant_id = $1 stays as the primary control.
	var measurements []MeasurementValue
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qerr := tx.QueryContext(context.Background(), query, tenantID, assetArg(assetID))
		if qerr != nil {
			return fmt.Errorf("failed to query TLS version: %w", qerr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var assetID uuid.UUID
			var tenantID uuid.UUID
			var protocolVersion sql.NullString
			var measuredAt time.Time
			var hostname sql.NullString
			var ipAddress sql.NullString
			var port sql.NullInt64

			if err := rows.Scan(&assetID, &tenantID, &protocolVersion, &measuredAt, &hostname, &ipAddress, &port); err != nil {
				return fmt.Errorf("failed to scan TLS version: %w", err)
			}

			if !protocolVersion.Valid {
				continue
			}

			metadata := make(map[string]interface{})
			if hostname.Valid {
				metadata["hostname"] = hostname.String
			}
			if ipAddress.Valid {
				metadata["ip_address"] = ipAddress.String
			}
			if port.Valid {
				metadata["port"] = port.Int64
			}

			measurements = append(measurements, MeasurementValue{
				Value:      protocolVersion.String,
				AssetID:    assetID,
				AssetType:  "crypto_implementation",
				TenantID:   tenantID,
				MeasuredAt: measuredAt,
				Metadata:   metadata,
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return measurements, nil
}

// GetKeyExchangeAlgorithm gets key exchange algorithms from crypto configurations
func (s *MeasurementExtractor) GetKeyExchangeAlgorithm(tenantID, assetID uuid.UUID) ([]MeasurementValue, error) {
	query := `
		SELECT
			na.id as asset_id,
			ci.tenant_id,
			ci.key_exchange_algorithm,
			ci.last_verified_at as measured_at,
			na.hostname,
			na.ip_address,
			na.port,
			ci.cipher_suite
		FROM crypto_implementations ci
		JOIN network_assets na ON ci.asset_id = na.id
		WHERE ci.tenant_id = $1
			AND na.deleted_at IS NULL
			AND ci.deleted_at IS NULL
			AND ($2::uuid IS NULL OR na.id = $2)
			AND ci.key_exchange_algorithm IS NOT NULL
		ORDER BY ci.last_verified_at DESC
	`

	// RLS-scoped read (tenant_isolation policy). WithTenantTx sets app.tenant_id;
	// the explicit WHERE … tenant_id = $1 stays as the primary control.
	var measurements []MeasurementValue
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qerr := tx.QueryContext(context.Background(), query, tenantID, assetArg(assetID))
		if qerr != nil {
			return fmt.Errorf("failed to query key exchange algorithm: %w", qerr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var assetID uuid.UUID
			var tenantID uuid.UUID
			var keyExchange sql.NullString
			var measuredAt time.Time
			var hostname sql.NullString
			var ipAddress sql.NullString
			var port sql.NullInt64
			var cipherSuite sql.NullString

			if err := rows.Scan(&assetID, &tenantID, &keyExchange, &measuredAt, &hostname, &ipAddress, &port, &cipherSuite); err != nil {
				return fmt.Errorf("failed to scan key exchange algorithm: %w", err)
			}

			if !keyExchange.Valid {
				continue
			}

			metadata := make(map[string]interface{})
			if hostname.Valid {
				metadata["hostname"] = hostname.String
			}
			if ipAddress.Valid {
				metadata["ip_address"] = ipAddress.String
			}
			if port.Valid {
				metadata["port"] = port.Int64
			}
			if cipherSuite.Valid {
				metadata["cipher_suite"] = cipherSuite.String
			}

			measurements = append(measurements, MeasurementValue{
				Value:      keyExchange.String,
				AssetID:    assetID,
				AssetType:  "crypto_implementation",
				TenantID:   tenantID,
				MeasuredAt: measuredAt,
				Metadata:   metadata,
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return measurements, nil
}

// GetSymmetricEncryption gets symmetric encryption algorithms from crypto configurations
func (s *MeasurementExtractor) GetSymmetricEncryption(tenantID, assetID uuid.UUID) ([]MeasurementValue, error) {
	query := `
		SELECT
			na.id as asset_id,
			ci.tenant_id,
			ci.symmetric_encryption,
			ci.last_verified_at as measured_at,
			na.hostname,
			na.ip_address,
			na.port,
			ci.cipher_suite
		FROM crypto_implementations ci
		JOIN network_assets na ON ci.asset_id = na.id
		WHERE ci.tenant_id = $1
			AND na.deleted_at IS NULL
			AND ci.deleted_at IS NULL
			AND ($2::uuid IS NULL OR na.id = $2)
			AND ci.symmetric_encryption IS NOT NULL
		ORDER BY ci.last_verified_at DESC
	`

	// RLS-scoped read (tenant_isolation policy). WithTenantTx sets app.tenant_id;
	// the explicit WHERE … tenant_id = $1 stays as the primary control.
	var measurements []MeasurementValue
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qerr := tx.QueryContext(context.Background(), query, tenantID, assetArg(assetID))
		if qerr != nil {
			return fmt.Errorf("failed to query symmetric encryption: %w", qerr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var assetID uuid.UUID
			var tenantID uuid.UUID
			var symmetricEncryption sql.NullString
			var measuredAt time.Time
			var hostname sql.NullString
			var ipAddress sql.NullString
			var port sql.NullInt64
			var cipherSuite sql.NullString

			if err := rows.Scan(&assetID, &tenantID, &symmetricEncryption, &measuredAt, &hostname, &ipAddress, &port, &cipherSuite); err != nil {
				return fmt.Errorf("failed to scan symmetric encryption: %w", err)
			}

			if !symmetricEncryption.Valid {
				continue
			}

			metadata := make(map[string]interface{})
			if hostname.Valid {
				metadata["hostname"] = hostname.String
			}
			if ipAddress.Valid {
				metadata["ip_address"] = ipAddress.String
			}
			if port.Valid {
				metadata["port"] = port.Int64
			}
			if cipherSuite.Valid {
				metadata["cipher_suite"] = cipherSuite.String
			}

			measurements = append(measurements, MeasurementValue{
				Value:      symmetricEncryption.String,
				AssetID:    assetID,
				AssetType:  "crypto_implementation",
				TenantID:   tenantID,
				MeasuredAt: measuredAt,
				Metadata:   metadata,
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return measurements, nil
}

// GetHashAlgorithm gets hash algorithms from crypto configurations
func (s *MeasurementExtractor) GetHashAlgorithm(tenantID, assetID uuid.UUID) ([]MeasurementValue, error) {
	query := `
		SELECT
			na.id as asset_id,
			ci.tenant_id,
			ci.hash_algorithm,
			ci.last_verified_at as measured_at,
			na.hostname,
			na.ip_address,
			na.port,
			ci.cipher_suite
		FROM crypto_implementations ci
		JOIN network_assets na ON ci.asset_id = na.id
		WHERE ci.tenant_id = $1
			AND na.deleted_at IS NULL
			AND ci.deleted_at IS NULL
			AND ($2::uuid IS NULL OR na.id = $2)
			AND ci.hash_algorithm IS NOT NULL
		ORDER BY ci.last_verified_at DESC
	`

	// RLS-scoped read (tenant_isolation policy). WithTenantTx sets app.tenant_id;
	// the explicit WHERE … tenant_id = $1 stays as the primary control.
	var measurements []MeasurementValue
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qerr := tx.QueryContext(context.Background(), query, tenantID, assetArg(assetID))
		if qerr != nil {
			return fmt.Errorf("failed to query hash algorithm: %w", qerr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var assetID uuid.UUID
			var tenantID uuid.UUID
			var hashAlgorithm sql.NullString
			var measuredAt time.Time
			var hostname sql.NullString
			var ipAddress sql.NullString
			var port sql.NullInt64
			var cipherSuite sql.NullString

			if err := rows.Scan(&assetID, &tenantID, &hashAlgorithm, &measuredAt, &hostname, &ipAddress, &port, &cipherSuite); err != nil {
				return fmt.Errorf("failed to scan hash algorithm: %w", err)
			}

			if !hashAlgorithm.Valid {
				continue
			}

			metadata := make(map[string]interface{})
			if hostname.Valid {
				metadata["hostname"] = hostname.String
			}
			if ipAddress.Valid {
				metadata["ip_address"] = ipAddress.String
			}
			if port.Valid {
				metadata["port"] = port.Int64
			}
			if cipherSuite.Valid {
				metadata["cipher_suite"] = cipherSuite.String
			}

			measurements = append(measurements, MeasurementValue{
				Value:      hashAlgorithm.String,
				AssetID:    assetID,
				AssetType:  "crypto_implementation",
				TenantID:   tenantID,
				MeasuredAt: measuredAt,
				Metadata:   metadata,
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return measurements, nil
}

// GetCipherSuiteName gets full cipher suite names from crypto configurations
func (s *MeasurementExtractor) GetCipherSuiteName(tenantID, assetID uuid.UUID) ([]MeasurementValue, error) {
	query := `
		SELECT
			na.id as asset_id,
			ci.tenant_id,
			ci.cipher_suite,
			ci.last_verified_at as measured_at,
			na.hostname,
			na.ip_address,
			na.port
		FROM crypto_implementations ci
		JOIN network_assets na ON ci.asset_id = na.id
		WHERE ci.tenant_id = $1
			AND na.deleted_at IS NULL
			AND ci.deleted_at IS NULL
			AND ($2::uuid IS NULL OR na.id = $2)
			AND ci.cipher_suite IS NOT NULL
		ORDER BY ci.last_verified_at DESC
	`

	// RLS-scoped read (tenant_isolation policy). WithTenantTx sets app.tenant_id;
	// the explicit WHERE … tenant_id = $1 stays as the primary control.
	var measurements []MeasurementValue
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qerr := tx.QueryContext(context.Background(), query, tenantID, assetArg(assetID))
		if qerr != nil {
			return fmt.Errorf("failed to query cipher suite name: %w", qerr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var assetID uuid.UUID
			var tenantID uuid.UUID
			var cipherSuite sql.NullString
			var measuredAt time.Time
			var hostname sql.NullString
			var ipAddress sql.NullString
			var port sql.NullInt64

			if err := rows.Scan(&assetID, &tenantID, &cipherSuite, &measuredAt, &hostname, &ipAddress, &port); err != nil {
				return fmt.Errorf("failed to scan cipher suite name: %w", err)
			}

			if !cipherSuite.Valid {
				continue
			}

			metadata := make(map[string]interface{})
			if hostname.Valid {
				metadata["hostname"] = hostname.String
			}
			if ipAddress.Valid {
				metadata["ip_address"] = ipAddress.String
			}
			if port.Valid {
				metadata["port"] = port.Int64
			}

			measurements = append(measurements, MeasurementValue{
				Value:      cipherSuite.String,
				AssetID:    assetID,
				AssetType:  "crypto_implementation",
				TenantID:   tenantID,
				MeasuredAt: measuredAt,
				Metadata:   metadata,
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return measurements, nil
}

// GetPFSSupport calculates Perfect Forward Secrecy support from key exchange algorithm
func (s *MeasurementExtractor) GetPFSSupport(tenantID, assetID uuid.UUID) ([]MeasurementValue, error) {
	query := `
		SELECT
			na.id as asset_id,
			ci.tenant_id,
			ci.key_exchange_algorithm,
			ci.last_verified_at as measured_at,
			na.hostname,
			na.ip_address,
			na.port
		FROM crypto_implementations ci
		JOIN network_assets na ON ci.asset_id = na.id
		WHERE ci.tenant_id = $1
			AND na.deleted_at IS NULL
			AND ci.deleted_at IS NULL
			AND ($2::uuid IS NULL OR na.id = $2)
			AND ci.key_exchange_algorithm IS NOT NULL
		ORDER BY ci.last_verified_at DESC
	`

	// RLS-scoped read (tenant_isolation policy). WithTenantTx sets app.tenant_id;
	// the explicit WHERE … tenant_id = $1 stays as the primary control.
	var measurements []MeasurementValue
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qerr := tx.QueryContext(context.Background(), query, tenantID, assetArg(assetID))
		if qerr != nil {
			return fmt.Errorf("failed to query PFS support: %w", qerr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var assetID uuid.UUID
			var tenantID uuid.UUID
			var keyExchange sql.NullString
			var measuredAt time.Time
			var hostname sql.NullString
			var ipAddress sql.NullString
			var port sql.NullInt64

			if err := rows.Scan(&assetID, &tenantID, &keyExchange, &measuredAt, &hostname, &ipAddress, &port); err != nil {
				return fmt.Errorf("failed to scan PFS support: %w", err)
			}

			if !keyExchange.Valid {
				continue
			}

			// PFS is supported if key exchange is ECDHE or DHE
			pfsSupported := strings.Contains(strings.ToUpper(keyExchange.String), "ECDHE") ||
				strings.Contains(strings.ToUpper(keyExchange.String), "DHE")

			metadata := make(map[string]interface{})
			metadata["key_exchange_algorithm"] = keyExchange.String
			if hostname.Valid {
				metadata["hostname"] = hostname.String
			}
			if ipAddress.Valid {
				metadata["ip_address"] = ipAddress.String
			}
			if port.Valid {
				metadata["port"] = port.Int64
			}

			measurements = append(measurements, MeasurementValue{
				Value:      pfsSupported,
				AssetID:    assetID,
				AssetType:  "crypto_implementation",
				TenantID:   tenantID,
				MeasuredAt: measuredAt,
				Metadata:   metadata,
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return measurements, nil
}

// GetTLSCompressionEnabled checks if TLS compression is enabled
// Note: This may need to be extracted from raw_data or metadata if available
func (s *MeasurementExtractor) GetTLSCompressionEnabled(tenantID, assetID uuid.UUID) ([]MeasurementValue, error) {
	query := `
		SELECT
			na.id as asset_id,
			ci.tenant_id,
			ci.raw_data,
			ci.last_verified_at as measured_at,
			na.hostname,
			na.ip_address,
			na.port
		FROM crypto_implementations ci
		JOIN network_assets na ON ci.asset_id = na.id
		WHERE ci.tenant_id = $1
			AND na.deleted_at IS NULL
			AND ci.deleted_at IS NULL
			AND ($2::uuid IS NULL OR na.id = $2)
			AND ci.protocol = 'TLS'
		ORDER BY ci.last_verified_at DESC
	`

	// RLS-scoped read (tenant_isolation policy). WithTenantTx sets app.tenant_id;
	// the explicit WHERE … tenant_id = $1 stays as the primary control.
	var measurements []MeasurementValue
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qerr := tx.QueryContext(context.Background(), query, tenantID, assetArg(assetID))
		if qerr != nil {
			return fmt.Errorf("failed to query TLS compression: %w", qerr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var assetID uuid.UUID
			var tenantID uuid.UUID
			var rawData sql.NullString
			var measuredAt time.Time
			var hostname sql.NullString
			var ipAddress sql.NullString
			var port sql.NullInt64

			if err := rows.Scan(&assetID, &tenantID, &rawData, &measuredAt, &hostname, &ipAddress, &port); err != nil {
				return fmt.Errorf("failed to scan TLS compression: %w", err)
			}

			// Default to false (compression disabled) if not found in raw_data
			// In practice, this would be extracted from raw_data JSON if available
			compressionEnabled := false
			if rawData.Valid && strings.Contains(strings.ToUpper(rawData.String), "COMPRESSION") {
				// Check if compression is enabled in raw_data
				// This is a simplified check - actual implementation would parse JSON
				compressionEnabled = strings.Contains(strings.ToUpper(rawData.String), `"compression":true`)
			}

			metadata := make(map[string]interface{})
			if hostname.Valid {
				metadata["hostname"] = hostname.String
			}
			if ipAddress.Valid {
				metadata["ip_address"] = ipAddress.String
			}
			if port.Valid {
				metadata["port"] = port.Int64
			}

			measurements = append(measurements, MeasurementValue{
				Value:      compressionEnabled,
				AssetID:    assetID,
				AssetType:  "crypto_implementation",
				TenantID:   tenantID,
				MeasuredAt: measuredAt,
				Metadata:   metadata,
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return measurements, nil
}

// GetCertificateChainValid checks if certificate chain is valid
// Note: This would typically come from certificate validation status
func (s *MeasurementExtractor) GetCertificateChainValid(tenantID, assetID uuid.UUID) ([]MeasurementValue, error) {
	query := `
		SELECT
			c.id as asset_id,
			c.tenant_id,
			c.is_self_signed,
			c.updated_at as measured_at,
			c.common_name,
			c.issuer_dn
		FROM certificates c
		WHERE c.tenant_id = $1
			AND ($2::uuid IS NULL OR c.id = $2)
			AND c.is_ca_certificate = false
		ORDER BY c.updated_at DESC
	`

	// RLS-scoped read (tenant_isolation policy). WithTenantTx sets app.tenant_id;
	// the explicit WHERE … tenant_id = $1 stays as the primary control.
	var measurements []MeasurementValue
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qerr := tx.QueryContext(context.Background(), query, tenantID, assetArg(assetID))
		if qerr != nil {
			return fmt.Errorf("failed to query certificate chain validity: %w", qerr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var assetID uuid.UUID
			var tenantID uuid.UUID
			var isSelfSigned sql.NullBool
			var measuredAt time.Time
			var commonName sql.NullString
			var issuerDN sql.NullString

			if err := rows.Scan(&assetID, &tenantID, &isSelfSigned, &measuredAt, &commonName, &issuerDN); err != nil {
				return fmt.Errorf("failed to scan certificate chain validity: %w", err)
			}

			// Chain is valid if not self-signed (simplified - actual validation would check full chain)
			chainValid := true
			if isSelfSigned.Valid && isSelfSigned.Bool {
				chainValid = false
			}

			metadata := make(map[string]interface{})
			if commonName.Valid {
				metadata["common_name"] = commonName.String
			}
			if issuerDN.Valid {
				metadata["issuer_dn"] = issuerDN.String
			}

			measurements = append(measurements, MeasurementValue{
				Value:      chainValid,
				AssetID:    assetID,
				AssetType:  "certificate",
				TenantID:   tenantID,
				MeasuredAt: measuredAt,
				Metadata:   metadata,
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return measurements, nil
}

// Key-size algorithm families. A key size is only meaningful against the floor
// for its own family: 2048 bits is the SP 800-131A minimum for the
// integer-factorisation / finite-field family (RSA, DSA, Diffie-Hellman), while
// an elliptic-curve key of 256 bits carries MORE security than RSA-2048
// (SP 800-57 comparable strength: 128-bit vs 112-bit).
//
// Applying one `key_size >= 2048` rule to both families — which BP-005 and
// CH-001 did until CMP-4 — flags every P-256 and Ed25519 certificate in the
// inventory as a weak key. That is not a threshold that is slightly off; it is
// the wrong question asked of the wrong algorithm.
const (
	keyFamilyFiniteField   = "finite_field"   // RSA / DSA / DH — floor 2048
	keyFamilyEllipticCurve = "elliptic_curve" // EC / EdDSA / X25519 — floor 256
	keyFamilyUnknown       = ""               // not classifiable — NOT ASSESSED
)

// keySizeFamily maps a certificate public-key algorithm to the family whose
// minimum-size rule applies. An unrecognised (or absent) algorithm returns
// keyFamilyUnknown and the certificate is skipped entirely rather than judged
// against a floor that may not apply — the same "score 0 means NOT ASSESSED"
// honesty the risk catalogue keeps.
//
// Elliptic-curve forms are tested FIRST: "ECDSA" contains the substring "DSA",
// so a finite-field-first order silently classifies every ECDSA certificate as
// RSA-family and re-creates the bug this function exists to fix.
func keySizeFamily(algorithm string) string {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	if a == "" {
		return keyFamilyUnknown
	}

	// A post-quantum key has no classical size floor at all: ML-DSA-65's key is
	// thousands of bits of lattice, and comparing it to 2048 measures nothing.
	// Checked first because "ML-DSA" contains "DSA" — the same substring trap
	// that ECDSA springs below.
	if classifyPQCAlgorithm(a) == "quantum_safe" {
		return keyFamilyUnknown
	}

	ecMarkers := []string{
		"ECDSA", "ECDH", "EDDSA", "ED25519", "ED448", "X25519", "X448",
		"ECPUBLICKEY", "PRIME256V1", "SECP", "BRAINPOOL", "CURVE25519", "P-256", "P-384", "P-521",
	}
	for _, m := range ecMarkers {
		if strings.Contains(a, m) {
			return keyFamilyEllipticCurve
		}
	}
	if a == "EC" || strings.HasPrefix(a, "EC-") || strings.HasPrefix(a, "EC ") {
		return keyFamilyEllipticCurve
	}

	ffMarkers := []string{"RSA", "DSA", "DIFFIE", "ELGAMAL"}
	for _, m := range ffMarkers {
		if strings.Contains(a, m) {
			return keyFamilyFiniteField
		}
	}
	if a == "DH" || strings.HasPrefix(a, "DH-") {
		return keyFamilyFiniteField
	}

	return keyFamilyUnknown
}

// GetKeySize gets key sizes from certificates whose public key is in the
// finite-field family (RSA / DSA / DH). Elliptic-curve certificates are served
// by GetECKeySize under the `key_size_ec` measurement type; certificates whose
// algorithm cannot be classified are emitted by neither, so they are reported
// as not assessed instead of judged against the wrong floor (CMP-4).
func (s *MeasurementExtractor) GetKeySize(tenantID, assetID uuid.UUID) ([]MeasurementValue, error) {
	return s.keySizesForFamily(tenantID, assetID, keyFamilyFiniteField)
}

// GetECKeySize is GetKeySize for the elliptic-curve family (EC / EdDSA).
func (s *MeasurementExtractor) GetECKeySize(tenantID, assetID uuid.UUID) ([]MeasurementValue, error) {
	return s.keySizesForFamily(tenantID, assetID, keyFamilyEllipticCurve)
}

func (s *MeasurementExtractor) keySizesForFamily(tenantID, assetID uuid.UUID, family string) ([]MeasurementValue, error) {
	query := `
		SELECT
			c.id as asset_id,
			c.tenant_id,
			c.public_key_size,
			c.updated_at as measured_at,
			c.common_name,
			c.public_key_algorithm
		FROM certificates c
		WHERE c.tenant_id = $1
			AND ($2::uuid IS NULL OR c.id = $2)
			AND c.public_key_size IS NOT NULL
			AND c.is_ca_certificate = false
		ORDER BY c.updated_at DESC
	`

	// RLS-scoped read (tenant_isolation policy). WithTenantTx sets app.tenant_id;
	// the explicit WHERE … tenant_id = $1 stays as the primary control.
	var measurements []MeasurementValue
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qerr := tx.QueryContext(context.Background(), query, tenantID, assetArg(assetID))
		if qerr != nil {
			return fmt.Errorf("failed to query key size: %w", qerr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var assetID uuid.UUID
			var tenantID uuid.UUID
			var keySize sql.NullInt64
			var measuredAt time.Time
			var commonName sql.NullString
			var algorithm sql.NullString

			if err := rows.Scan(&assetID, &tenantID, &keySize, &measuredAt, &commonName, &algorithm); err != nil {
				return fmt.Errorf("failed to scan key size: %w", err)
			}

			if !keySize.Valid {
				continue
			}
			if keySizeFamily(algorithm.String) != family {
				continue
			}

			metadata := make(map[string]interface{})
			if commonName.Valid {
				metadata["common_name"] = commonName.String
			}
			if algorithm.Valid {
				metadata["algorithm"] = algorithm.String
			}
			metadata["key_family"] = family

			measurements = append(measurements, MeasurementValue{
				Value:      int(keySize.Int64),
				AssetID:    assetID,
				AssetType:  "certificate",
				TenantID:   tenantID,
				MeasuredAt: measuredAt,
				Metadata:   metadata,
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return measurements, nil
}

// GetCertificateAlgorithm gets certificate algorithms
func (s *MeasurementExtractor) GetCertificateAlgorithm(tenantID, assetID uuid.UUID) ([]MeasurementValue, error) {
	query := `
		SELECT
			c.id as asset_id,
			c.tenant_id,
			c.public_key_algorithm,
			c.updated_at as measured_at,
			c.common_name,
			c.public_key_size
		FROM certificates c
		WHERE c.tenant_id = $1
			AND ($2::uuid IS NULL OR c.id = $2)
			AND c.public_key_algorithm IS NOT NULL
			AND c.is_ca_certificate = false
		ORDER BY c.updated_at DESC
	`

	// RLS-scoped read (tenant_isolation policy). WithTenantTx sets app.tenant_id;
	// the explicit WHERE … tenant_id = $1 stays as the primary control.
	var measurements []MeasurementValue
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qerr := tx.QueryContext(context.Background(), query, tenantID, assetArg(assetID))
		if qerr != nil {
			return fmt.Errorf("failed to query certificate algorithm: %w", qerr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var assetID uuid.UUID
			var tenantID uuid.UUID
			var algorithm sql.NullString
			var measuredAt time.Time
			var commonName sql.NullString
			var keySize sql.NullInt64

			if err := rows.Scan(&assetID, &tenantID, &algorithm, &measuredAt, &commonName, &keySize); err != nil {
				return fmt.Errorf("failed to scan certificate algorithm: %w", err)
			}

			if !algorithm.Valid {
				continue
			}

			metadata := make(map[string]interface{})
			if commonName.Valid {
				metadata["common_name"] = commonName.String
			}
			if keySize.Valid {
				metadata["key_size"] = keySize.Int64
			}

			measurements = append(measurements, MeasurementValue{
				Value:      algorithm.String,
				AssetID:    assetID,
				AssetType:  "certificate",
				TenantID:   tenantID,
				MeasuredAt: measuredAt,
				Metadata:   metadata,
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return measurements, nil
}
