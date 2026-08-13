package services

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

type CertificateService struct {
	db             *database.DB
	eventPublisher *EventPublisherService
}

func NewCertificateService(db *database.DB, eventPublisher *EventPublisherService) *CertificateService {
	return &CertificateService{
		db:             db,
		eventPublisher: eventPublisher,
	}
}

// certificateColumns is the canonical column list for all certificate queries.
// Every method that reads certificates should use this constant to prevent column
// drift (the class of bug where list vs. detail queries return different fields).
const certificateColumns = `
	id, tenant_id, serial_number, subject_dn, issuer_dn, common_name,
	subject_alternative_names, signature_algorithm, public_key_algorithm,
	public_key_size, not_before, not_after, fingerprint_sha1, fingerprint_sha256,
	certificate_pem, is_self_signed, is_ca_certificate, key_usage, extended_key_usage,
	issuer_certificate_id, superseded_by_certificate_id, certificate_state, certificate_state_reason,
	revoked_at, revocation_discovered_at,
	certificate_format, activation_date, deactivation_date, destruction_date,
	signature_algorithm_oid, public_key_algorithm_oid,
	data_completeness, data_source, last_data_update,
	created_at, updated_at,
	known_bad_ca, cert_ownership`

// effectiveOwnershipExpr resolves the SAME "which ownership bucket does this
// certificate belong to" answer for both the `?ownership=` filter and the
// list response's `ownership` field (#H-6). Precedence: the ownership of an
// asset the cert is actually deployed on (crypto_implementations link) wins
// when present, else the declared cert_ownership (manual uploads), else
// "unknown" — never NULL, so every certificate lands in exactly one of
// internal / third_party / unknown and the buckets always sum to the total.
const effectiveOwnershipExpr = `COALESCE(
	(SELECT na.asset_ownership
	   FROM crypto_implementations ci
	   JOIN network_assets na ON na.id = ci.asset_id
	  WHERE ci.certificate_id = certificates.id
	    AND ci.tenant_id = certificates.tenant_id
	    AND ci.deleted_at IS NULL
	    AND na.deleted_at IS NULL
	  LIMIT 1),
	cert_ownership,
	'unknown'
)`

// scanCertificateRow scans a single row into a Certificate model. The scanner
// must return columns in the order defined by certificateColumns.
func scanCertificateRow(scanner interface {
	Scan(dest ...interface{}) error
}) (models.Certificate, error) {
	return scanCertificateRowWithOptions(scanner, false)
}

func scanCertificateRowWithOptions(scanner interface {
	Scan(dest ...interface{}) error
}, withDeploymentCount bool) (models.Certificate, error) {
	return scanCertificateRowFull(scanner, withDeploymentCount, false)
}

// scanCertificateRowWithCountAndOwnership scans a certificate row that
// includes both the deployment_count and effective-ownership trailing
// columns (in that order). Used by GetCertificates so the list response can
// expose the SAME "which ownership bucket does this cert belong to" answer
// the `?ownership=` filter uses (see effectiveOwnershipExpr) — see #H-6.
func scanCertificateRowWithCountAndOwnership(scanner interface {
	Scan(dest ...interface{}) error
}) (models.Certificate, error) {
	return scanCertificateRowFull(scanner, true, true)
}

func scanCertificateRowFull(scanner interface {
	Scan(dest ...interface{}) error
}, withDeploymentCount bool, withOwnership bool) (models.Certificate, error) {
	var cert models.Certificate
	var serialNumber, commonName, sigAlg, pubKeyAlg, certPEM, fpSHA1, dataSource sql.NullString
	var certStateReason, sigAlgOID, pubKeyAlgOID sql.NullString
	var knownBadCA, certOwnership sql.NullString
	var pubKeySize sql.NullInt64
	var notBefore, notAfter, revokedAt, revocationDiscoveredAt, lastDataUpdate sql.NullTime
	var activationDate, deactivationDate, destructionDate sql.NullTime
	var issuerCertID, supersededByCertID sql.NullString
	var sanArray pq.StringArray
	var deploymentCount sql.NullInt64
	var effectiveOwnership sql.NullString

	dest := []interface{}{
		&cert.ID, &cert.TenantID, &serialNumber, &cert.SubjectDN, &cert.IssuerDN, &commonName,
		&sanArray, &sigAlg, &pubKeyAlg, &pubKeySize, &notBefore, &notAfter,
		&fpSHA1, &cert.FingerprintSHA256, &certPEM, &cert.IsSelfSigned, &cert.IsCACertificate,
		pq.Array(&cert.KeyUsage), pq.Array(&cert.ExtendedKeyUsage),
		&issuerCertID, &supersededByCertID, &cert.CertificateState, &certStateReason,
		&revokedAt, &revocationDiscoveredAt,
		&cert.CertificateFormat, &activationDate, &deactivationDate, &destructionDate,
		&sigAlgOID, &pubKeyAlgOID,
		&cert.DataCompleteness, &dataSource, &lastDataUpdate,
		&cert.CreatedAt, &cert.UpdatedAt,
		&knownBadCA, &certOwnership,
	}
	if withDeploymentCount {
		dest = append(dest, &deploymentCount)
	}
	if withOwnership {
		dest = append(dest, &effectiveOwnership)
	}

	err := scanner.Scan(dest...)
	if err != nil {
		return cert, err
	}

	if withDeploymentCount && deploymentCount.Valid {
		count := int(deploymentCount.Int64)
		cert.DeploymentCount = &count
	}
	if withOwnership {
		if effectiveOwnership.Valid && effectiveOwnership.String != "" {
			cert.Ownership = effectiveOwnership.String
		} else {
			cert.Ownership = "unknown"
		}
	}

	if knownBadCA.Valid && knownBadCA.String != "" {
		v := knownBadCA.String
		cert.KnownBadCA = &v
	}
	if certOwnership.Valid && certOwnership.String != "" {
		v := certOwnership.String
		cert.CertOwnership = &v
	}

	if serialNumber.Valid {
		cert.SerialNumber = &serialNumber.String
	}
	if commonName.Valid {
		cert.CommonName = &commonName.String
	}
	if sigAlg.Valid {
		cert.SignatureAlgorithm = &sigAlg.String
	}
	if pubKeyAlg.Valid {
		cert.PublicKeyAlgorithm = &pubKeyAlg.String
	}
	if pubKeySize.Valid {
		size := int(pubKeySize.Int64)
		cert.PublicKeySize = &size
	}
	if notBefore.Valid {
		cert.NotBefore = &notBefore.Time
	}
	if notAfter.Valid {
		cert.NotAfter = &notAfter.Time
	}
	if fpSHA1.Valid {
		cert.FingerprintSHA1 = &fpSHA1.String
	}
	if certPEM.Valid {
		cert.CertificatePEM = &certPEM.String
	}
	if issuerCertID.Valid {
		if id, err := uuid.Parse(issuerCertID.String); err == nil {
			cert.IssuerCertificateID = &id
		}
	}
	if supersededByCertID.Valid {
		if id, err := uuid.Parse(supersededByCertID.String); err == nil {
			cert.SupersededByCertificateID = &id
		}
	}
	if certStateReason.Valid {
		cert.CertificateStateReason = &certStateReason.String
	}
	if revokedAt.Valid {
		cert.RevokedAt = &revokedAt.Time
	}
	if revocationDiscoveredAt.Valid {
		cert.RevocationDiscoveredAt = &revocationDiscoveredAt.Time
	}
	if activationDate.Valid {
		cert.ActivationDate = &activationDate.Time
	}
	if deactivationDate.Valid {
		cert.DeactivationDate = &deactivationDate.Time
	}
	if destructionDate.Valid {
		cert.DestructionDate = &destructionDate.Time
	}
	if sigAlgOID.Valid {
		cert.SignatureAlgorithmOID = &sigAlgOID.String
	}
	if pubKeyAlgOID.Valid {
		cert.PublicKeyAlgorithmOID = &pubKeyAlgOID.String
	}
	if dataSource.Valid {
		cert.DataSource = &dataSource.String
	}
	if lastDataUpdate.Valid {
		cert.LastDataUpdate = &lastDataUpdate.Time
	}
	cert.SubjectAlternativeNames = []string(sanArray)

	return cert, nil
}

// GetCertificates retrieves certificates with optional filters
func (s *CertificateService) GetCertificates(tenantID uuid.UUID, filters models.CertificateFilters) ([]models.Certificate, int, error) {
	if filters.Page == 0 {
		filters.Page = 1
	}
	if filters.PageSize == 0 {
		filters.PageSize = 20
	}
	if filters.SortBy == "" {
		filters.SortBy = "not_after"
	}
	if filters.SortOrder == "" {
		filters.SortOrder = "asc"
	}

	// deploymentCountSubquery returns, per-certificate, the number of distinct
	// non-deleted network assets that use this certificate — either directly
	// (a crypto_implementation's certificate_id points at it, the leaf-cert
	// case) OR as an ancestor of a directly-deployed cert via the issuer
	// chain (certificates.issuer_certificate_id). Without the chain walk, a
	// CA/intermediate cert that is never itself a config's leaf certificate_id
	// always shows deployment_count 0 → "Unassigned", even though the SAME
	// asset's crypto_implementation carries a key extracted from that exact CA
	// cert (implementation_keys → keys, see keyDeploymentCountSubquery) and so
	// the Keys lens correctly shows it as "used by N assets". That
	// cert-vs-key contradiction is #M-7. WITH RECURSIVE walks from every
	// directly-deployed leaf cert up through issuer_certificate_id so an
	// intermediate/root CA cert is credited with the deployments of every leaf
	// it issued (directly or transitively), matching what the key badge shows.
	const deploymentCountSubquery = `
		(WITH RECURSIVE deployed_chain AS (
			SELECT ci.asset_id, ci.certificate_id AS cert_id
			  FROM crypto_implementations ci
			  JOIN network_assets na ON na.id = ci.asset_id
			 WHERE ci.tenant_id = certificates.tenant_id
			   AND ci.deleted_at IS NULL
			   AND na.deleted_at IS NULL
			   AND ci.certificate_id IS NOT NULL
			UNION
			SELECT dc.asset_id, c.issuer_certificate_id
			  FROM deployed_chain dc
			  JOIN certificates c ON c.id = dc.cert_id
			 WHERE c.issuer_certificate_id IS NOT NULL
		)
		SELECT COUNT(DISTINCT asset_id) FROM deployed_chain WHERE cert_id = certificates.id) AS deployment_count`

	selectClause := `SELECT` + certificateColumns + `, ` + deploymentCountSubquery + `, ` + effectiveOwnershipExpr + ` AS effective_ownership`

	baseFrom := ` FROM certificates WHERE tenant_id = $1`

	args := []interface{}{tenantID}
	argCount := 1
	whereConditions := []string{}

	if filters.CertificateID != nil {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`id = $%d`, argCount))
		args = append(args, *filters.CertificateID)
	}

	// Apply filters
	if filters.ExpiringDays != nil {
		// Note: Using string interpolation for INTERVAL (PostgreSQL requirement), so don't increment argCount
		// This ensures LIMIT/OFFSET parameter numbers are correct
		whereConditions = append(whereConditions, fmt.Sprintf(`not_after BETWEEN NOW() AND NOW() + INTERVAL '%d days'`, *filters.ExpiringDays))
	}

	if filters.KeySizeMin != nil {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`public_key_size >= $%d`, argCount))
		args = append(args, *filters.KeySizeMin)
	}

	if filters.Algorithm != nil {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`public_key_algorithm = $%d`, argCount))
		args = append(args, *filters.Algorithm)
	}

	if filters.Issuer != nil {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`issuer_dn ILIKE $%d`, argCount))
		args = append(args, "%"+*filters.Issuer+"%")
	}

	if filters.SelfSigned != nil {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`is_self_signed = $%d`, argCount))
		args = append(args, *filters.SelfSigned)
	}

	// Ownership filter: partitions the WHOLE set into internal / third_party /
	// unknown using the same effectiveOwnershipExpr the list SELECT exposes as
	// `ownership` (#H-6). Previously this matched only
	// `na.asset_ownership = $N OR cert_ownership = $N`, which let a cert with
	// NO asset link and a NULL cert_ownership fall through every bucket
	// (unknown != NULL, so equality against the literal 'unknown' never
	// matched it) — filtered counts summed to less than the unfiltered total.
	// effectiveOwnershipExpr's COALESCE(...,'unknown') guarantees every
	// certificate matches exactly one of the three values.
	if filters.Ownership != nil {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`(%s) = $%d`, effectiveOwnershipExpr, argCount))
		args = append(args, *filters.Ownership)
	}

	// Full-text-ish search across common_name, subject_dn, issuer_dn, and SANs.
	// SANs are a TEXT[] column so we compare the array rendered as text; this
	// stays pagination-correct because it runs at the DB layer.
	if filters.Search != nil {
		trimmed := strings.TrimSpace(*filters.Search)
		if trimmed != "" {
			argCount++
			whereConditions = append(whereConditions, fmt.Sprintf(
				`(common_name ILIKE $%d OR subject_dn ILIKE $%d OR issuer_dn ILIKE $%d OR array_to_string(subject_alternative_names, ',') ILIKE $%d)`,
				argCount, argCount, argCount, argCount,
			))
			args = append(args, "%"+trimmed+"%")
		}
	}

	// Build WHERE clause
	whereClause := ""
	if len(whereConditions) > 0 {
		whereClause = " AND " + strings.Join(whereConditions, " AND ")
	}
	query := selectClause + baseFrom + whereClause

	// Get total count - build count query separately
	countQuery := `
		SELECT COUNT(*)
		FROM certificates
		WHERE tenant_id = $1
	` + whereClause

	// Add ordering
	orderBy := "ORDER BY "
	switch filters.SortBy {
	case "not_after", "expiration":
		orderBy += "not_after"
	case "common_name", "cn":
		orderBy += "common_name"
	case "issuer", "issuer_dn":
		orderBy += "issuer_dn"
	case "key_size", "public_key_size":
		orderBy += "public_key_size"
	case "created_at":
		orderBy += "created_at"
	case "deployment_count":
		orderBy += "deployment_count"
	case "data_source":
		orderBy += "data_source"
	default:
		orderBy += "not_after"
	}

	if filters.SortOrder == "desc" {
		orderBy += " DESC NULLS LAST"
	} else {
		orderBy += " ASC NULLS LAST"
	}
	query += " " + orderBy

	// Add pagination
	offset := (filters.Page - 1) * filters.PageSize
	// Use direct integer interpolation for LIMIT/OFFSET (safe - these are integers from our code, not user input)
	// This avoids PostgreSQL type inference issues with parameterized LIMIT/OFFSET
	query += fmt.Sprintf(" LIMIT %d OFFSET %d", filters.PageSize, offset)

	// RLS-scoped reads over certificates — count + page run in one tenant tx
	// (sets app.tenant_id). The explicit WHERE tenant_id = $1 is kept as the
	// primary control.
	var total int
	var certificates []models.Certificate
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		if e := tx.QueryRow(countQuery, args...).Scan(&total); e != nil {
			return fmt.Errorf("failed to count certificates: %w", e)
		}
		rows, e := tx.Query(query, args...)
		if e != nil {
			return fmt.Errorf("failed to query certificates: %w", e)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			cert, e := scanCertificateRowWithCountAndOwnership(rows)
			if e != nil {
				return fmt.Errorf("failed to scan certificate: %w", e)
			}
			certificates = append(certificates, cert)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, err
	}

	return certificates, total, nil
}

// GetCertificateByID retrieves a single certificate with its relationships
func (s *CertificateService) GetCertificateByID(tenantID, certID uuid.UUID) (*models.Certificate, error) {
	query := `SELECT` + certificateColumns + `
		FROM certificates
		WHERE id = $1 AND tenant_id = $2
	`

	// RLS-scoped read over certificates.
	var cert models.Certificate
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		var e error
		cert, e = scanCertificateRow(tx.QueryRow(query, certID, tenantID))
		return e
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	// Load related assets
	assets, err := s.getRelatedAssets(tenantID, certID)
	if err == nil {
		cert.RelatedAssets = assets
	}

	return &cert, nil
}

// GetExpiringCertificates retrieves certificates expiring within specified days,
// including recently expired certs within lookbackDays (0 = no lookback).
func (s *CertificateService) GetExpiringCertificates(tenantID uuid.UUID, days int, limit int, lookbackDays ...int) ([]models.Certificate, error) {
	lookback := 0
	if len(lookbackDays) > 0 && lookbackDays[0] > 0 {
		lookback = lookbackDays[0]
	}

	query := `SELECT` + certificateColumns + `
		FROM certificates
		WHERE tenant_id = $1
		AND not_after BETWEEN NOW() - INTERVAL '%d days' AND NOW() + INTERVAL '%d days'
		ORDER BY not_after ASC
		LIMIT $2
	`

	// RLS-scoped read over certificates.
	var certificates []models.Certificate
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, e := tx.Query(fmt.Sprintf(query, lookback, days), tenantID, limit)
		if e != nil {
			return fmt.Errorf("failed to query expiring certificates: %w", e)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			cert, e := scanCertificateRow(rows)
			if e != nil {
				return fmt.Errorf("failed to scan certificate: %w", e)
			}
			certificates = append(certificates, cert)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	// Load related assets (each in its own tenant tx)
	for i := range certificates {
		assets, e := s.getRelatedAssets(tenantID, certificates[i].ID)
		if e == nil {
			certificates[i].RelatedAssets = assets
		}
	}

	return certificates, nil
}

// getRelatedAssets retrieves assets that use this certificate — directly (a
// crypto_implementation's certificate_id points at it) or as an ancestor CA
// in the issuer chain of a directly-deployed leaf cert. Mirrors
// deploymentCountSubquery (#M-7) so the drawer's related-asset list agrees
// with the list row's deployment_count badge for CA/intermediate certs.
func (s *CertificateService) getRelatedAssets(tenantID, certID uuid.UUID) ([]models.Asset, error) {
	query := `
		WITH RECURSIVE deployed_chain AS (
			SELECT ci.asset_id, ci.certificate_id AS cert_id
			  FROM crypto_implementations ci
			  JOIN network_assets na ON na.id = ci.asset_id
			 WHERE ci.tenant_id = $2
			   AND ci.deleted_at IS NULL
			   AND na.deleted_at IS NULL
			   AND ci.certificate_id IS NOT NULL
			UNION
			SELECT dc.asset_id, c.issuer_certificate_id
			  FROM deployed_chain dc
			  JOIN certificates c ON c.id = dc.cert_id
			 WHERE c.issuer_certificate_id IS NOT NULL
		)
		SELECT DISTINCT
			a.id, a.tenant_id, a.hostname, a.ip_address, a.port, a.asset_type,
			a.operating_system, a.environment, a.business_unit, a.owner_email,
			a.description, a.tags::text, a.metadata::text, a.asset_ownership, a.asset_status,
			a.first_discovered_at, a.last_seen_at,
			a.created_at, a.updated_at, a.deleted_at
		FROM network_assets a
		JOIN deployed_chain dc ON dc.asset_id = a.id
		WHERE dc.cert_id = $1
		AND a.tenant_id = $2
		AND a.deleted_at IS NULL
		LIMIT 10
	`

	// RLS-scoped read over network_assets / crypto_implementations.
	var assets []models.Asset
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, e := tx.Query(query, certID, tenantID)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var asset models.Asset
			var tagsText, metadataText sql.NullString

			if e := rows.Scan(
				&asset.ID, &asset.TenantID, &asset.Hostname, &asset.IPAddress, &asset.Port,
				&asset.AssetType, &asset.OperatingSystem, &asset.Environment, &asset.BusinessUnit,
				&asset.OwnerEmail, &asset.Description, &tagsText, &metadataText, &asset.AssetOwnership, &asset.AssetStatus,
				&asset.FirstDiscoveredAt, &asset.LastSeenAt, &asset.CreatedAt, &asset.UpdatedAt,
				&asset.DeletedAt,
			); e != nil {
				continue
			}

			if tagsText.Valid {
				_ = json.Unmarshal([]byte(tagsText.String), &asset.Tags)
			}
			if metadataText.Valid {
				_ = json.Unmarshal([]byte(metadataText.String), &asset.Metadata)
			}

			assets = append(assets, asset)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	return assets, nil
}

// GetCertificatesByAssetID returns the full certificate records linked to a
// single asset. Linkage is sourced from crypto_implementations — the same
// asset→certificate join the asset-certificate-links endpoint and
// getRelatedAssets use — so this stays consistent with how the rest of the
// service models the asset/cert relationship. Results are DISTINCT because a
// cert can be bound to an asset via multiple configurations (e.g. two
// protocols sharing one cert). Tenant scoping is enforced on both the
// certificate and the crypto_implementation rows.
func (s *CertificateService) GetCertificatesByAssetID(tenantID, assetID uuid.UUID) ([]models.Certificate, error) {
	query := `
		SELECT DISTINCT ON (certificates.id)` + certificateColumns + `
		FROM certificates
		JOIN crypto_implementations ci ON ci.certificate_id = certificates.id
		WHERE ci.asset_id = $1
		  AND certificates.tenant_id = $2
		  AND ci.tenant_id = $2
		  AND ci.deleted_at IS NULL
		ORDER BY certificates.id`

	// RLS-scoped read over certificates / crypto_implementations.
	certificates := make([]models.Certificate, 0)
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, e := tx.Query(query, assetID, tenantID)
		if e != nil {
			return fmt.Errorf("failed to query certificates by asset: %w", e)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			cert, e := scanCertificateRow(rows)
			if e != nil {
				return fmt.Errorf("failed to scan certificate: %w", e)
			}
			certificates = append(certificates, cert)
		}
		if e := rows.Err(); e != nil {
			return fmt.Errorf("error iterating certificates by asset: %w", e)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return certificates, nil
}

// CalculateFingerprint calculates SHA256 fingerprint from PEM or metadata
func (s *CertificateService) CalculateFingerprint(certData models.CertificateData) (string, error) {
	// If PEM is available, calculate from PEM
	if certData.CertificatePEM != "" {
		return s.calculateFingerprintFromPEM(certData.CertificatePEM)
	}

	// If fingerprint is already provided, use it
	if certData.FingerprintSHA256 != "" {
		return certData.FingerprintSHA256, nil
	}

	// If we have serial + issuer, we can create a composite key but not a true fingerprint
	// Return empty string to indicate fingerprint needs to be calculated later
	if certData.SerialNumber != "" && certData.IssuerDN != "" {
		return "", fmt.Errorf("fingerprint cannot be calculated without PEM or existing fingerprint")
	}

	return "", fmt.Errorf("insufficient data to calculate fingerprint")
}

// updateCertQualityFlags persists certificate quality flags (SCT, known-bad CA,
// OCSP, EV) if any are present in the CertificateData.
func (s *CertificateService) updateCertQualityFlags(tenantID, certID uuid.UUID, certData models.CertificateData) {
	hasFlags := certData.HasSCT != nil || certData.KnownBadCA != "" || certData.IsEV || certData.OCSPStatus != ""
	if !hasFlags {
		return
	}
	// RLS-scoped write over certificates — wrapped in WithTenantTx.
	_ = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, _ = tx.Exec(`
			UPDATE certificates SET
				has_sct = COALESCE($2, has_sct),
				known_bad_ca = COALESCE(NULLIF($3, ''), known_bad_ca),
				is_ev = COALESCE($4, is_ev),
				ocsp_status = COALESCE(NULLIF($5, ''), ocsp_status),
				ocsp_detail = COALESCE(NULLIF($6, ''), ocsp_detail),
				updated_at = NOW()
			WHERE id = $1`,
			certID, certData.HasSCT, certData.KnownBadCA, certData.IsEV, certData.OCSPStatus, certData.OCSPDetail,
		)
		return nil
	})
}

// calculateFingerprintFromPEM calculates SHA256 fingerprint from certificate PEM
func (s *CertificateService) calculateFingerprintFromPEM(pemData string) (string, error) {
	// Parse PEM and calculate SHA256 fingerprint
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM data")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Calculate SHA256 fingerprint
	fingerprint := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(fingerprint[:]), nil
}

// FindByCompositeKey finds certificate by composite key (SHA256 + serial + issuer)
func (s *CertificateService) FindByCompositeKey(
	tenantID uuid.UUID,
	fingerprintSHA256 string,
	serialNumber string,
	issuerDN string,
) (*models.Certificate, error) {
	query := `
		SELECT
			id, tenant_id, serial_number, subject_dn, issuer_dn, common_name,
			subject_alternative_names, signature_algorithm, public_key_algorithm,
			public_key_size, not_before, not_after, fingerprint_sha1, fingerprint_sha256,
			certificate_pem, is_self_signed, is_ca_certificate, key_usage, extended_key_usage,
			issuer_certificate_id, superseded_by_certificate_id, certificate_state,
			revoked_at, revocation_discovered_at, data_completeness, data_source,
			last_data_update, created_at, updated_at
		FROM certificates
		WHERE tenant_id = $1
		AND fingerprint_sha256 = $2
		AND serial_number = $3
		AND issuer_dn = $4
		LIMIT 1
	`

	var cert models.Certificate
	var serialNumberVal, commonName, sigAlg, pubKeyAlg, certPEM, fpSHA1, dataSource sql.NullString
	var pubKeySize sql.NullInt64
	var notBefore, notAfter, revokedAt, revocationDiscoveredAt, lastDataUpdate sql.NullTime
	var issuerCertID, supersededByCertID sql.NullString
	var sanArray pq.StringArray

	// RLS-scoped read over certificates.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(query, tenantID, fingerprintSHA256, serialNumber, issuerDN).Scan(
			&cert.ID, &cert.TenantID, &serialNumberVal, &cert.SubjectDN, &cert.IssuerDN, &commonName,
			&sanArray, &sigAlg, &pubKeyAlg, &pubKeySize, &notBefore, &notAfter,
			&fpSHA1, &cert.FingerprintSHA256, &certPEM, &cert.IsSelfSigned, &cert.IsCACertificate,
			pq.Array(&cert.KeyUsage), pq.Array(&cert.ExtendedKeyUsage),
			&issuerCertID, &supersededByCertID, &cert.CertificateState,
			&revokedAt, &revocationDiscoveredAt, &cert.DataCompleteness, &dataSource,
			&lastDataUpdate, &cert.CreatedAt, &cert.UpdatedAt,
		)
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Not found, not an error
		}
		return nil, fmt.Errorf("failed to find certificate: %w", err)
	}

	// Handle nullable fields
	if serialNumberVal.Valid {
		cert.SerialNumber = &serialNumberVal.String
	}
	if commonName.Valid {
		cert.CommonName = &commonName.String
	}
	if sigAlg.Valid {
		cert.SignatureAlgorithm = &sigAlg.String
	}
	if pubKeyAlg.Valid {
		cert.PublicKeyAlgorithm = &pubKeyAlg.String
	}
	if pubKeySize.Valid {
		size := int(pubKeySize.Int64)
		cert.PublicKeySize = &size
	}
	if notBefore.Valid {
		cert.NotBefore = &notBefore.Time
	}
	if notAfter.Valid {
		cert.NotAfter = &notAfter.Time
	}
	if fpSHA1.Valid {
		cert.FingerprintSHA1 = &fpSHA1.String
	}
	if certPEM.Valid {
		cert.CertificatePEM = &certPEM.String
	}
	if issuerCertID.Valid {
		if id, err := uuid.Parse(issuerCertID.String); err == nil {
			cert.IssuerCertificateID = &id
		}
	}
	if supersededByCertID.Valid {
		if id, err := uuid.Parse(supersededByCertID.String); err == nil {
			cert.SupersededByCertificateID = &id
		}
	}
	if revokedAt.Valid {
		cert.RevokedAt = &revokedAt.Time
	}
	if revocationDiscoveredAt.Valid {
		cert.RevocationDiscoveredAt = &revocationDiscoveredAt.Time
	}
	if dataSource.Valid {
		cert.DataSource = &dataSource.String
	}
	if lastDataUpdate.Valid {
		cert.LastDataUpdate = &lastDataUpdate.Time
	}
	cert.SubjectAlternativeNames = []string(sanArray)

	return &cert, nil
}

// FindOrCreateCertificate finds existing certificate by fingerprint or creates new one
func (s *CertificateService) FindOrCreateCertificate(
	tenantID uuid.UUID,
	certData models.CertificateData,
) (*models.Certificate, error) {
	// Try to calculate fingerprint if not provided
	fingerprintSHA256 := certData.FingerprintSHA256
	if fingerprintSHA256 == "" {
		// If PEM is available, calculate from PEM
		if certData.CertificatePEM != "" {
			calculated, err := s.calculateFingerprintFromPEM(certData.CertificatePEM)
			if err == nil {
				fingerprintSHA256 = calculated
				certData.FingerprintSHA256 = calculated
			}
		} else {
			// Try to calculate from other metadata
			calculated, err := s.CalculateFingerprint(certData)
			if err == nil {
				fingerprintSHA256 = calculated
			}
		}
	}

	// Try to find by fingerprint first
	if fingerprintSHA256 != "" {
		query := `
			SELECT id FROM certificates
			WHERE tenant_id = $1 AND fingerprint_sha256 = $2
			LIMIT 1
		`
		var existingID uuid.UUID
		// RLS-scoped read over certificates.
		err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
			return tx.QueryRow(query, tenantID, fingerprintSHA256).Scan(&existingID)
		})
		if err == nil {
			// Found existing certificate, update it with new data if needed
			return s.UpdateCertificate(tenantID, existingID, certData)
		}
	}

	// Try composite key lookup if we have serial + issuer
	if certData.SerialNumber != "" && certData.IssuerDN != "" && fingerprintSHA256 != "" {
		existing, err := s.FindByCompositeKey(tenantID, fingerprintSHA256, certData.SerialNumber, certData.IssuerDN)
		if err == nil && existing != nil {
			// Found existing, update it
			return s.UpdateCertificate(tenantID, existing.ID, certData)
		}
	}

	// Check for certificate renewal (same CN but different serial)
	var oldCertID *uuid.UUID
	if certData.CommonName != "" && certData.SerialNumber != "" {
		renewalCert, err := s.detectCertificateRenewal(tenantID, certData)
		if err == nil && renewalCert != nil {
			oldCertID = &renewalCert.ID
		}
	}

	// Create new certificate
	newCert, err := s.CreateCertificate(tenantID, certData)
	if err != nil {
		return nil, err
	}

	// If we detected a renewal, link the old certificate to the new one
	if oldCertID != nil && newCert != nil {
		// Mark old certificate as superseded by new one.
		// RLS-scoped write over certificates.
		_ = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
			updateQuery := `UPDATE certificates SET superseded_by_certificate_id = $1 WHERE id = $2`
			_, _ = tx.Exec(updateQuery, newCert.ID, *oldCertID)
			return nil
		})

		// Record renewal events
		_ = s.RecordCertificateHistory(tenantID, *oldCertID, "renewed", map[string]interface{}{
			"previous_certificate_id": oldCertID.String(),
			"new_certificate_id":      newCert.ID.String(),
			"new_serial_number":       certData.SerialNumber,
		})
		_ = s.RecordCertificateHistory(tenantID, newCert.ID, "created", map[string]interface{}{
			"renewal_of": oldCertID.String(),
		})
	}

	return newCert, nil
}

// detectCertificateRenewal detects if a certificate is a renewal of an existing certificate
func (s *CertificateService) detectCertificateRenewal(tenantID uuid.UUID, certData models.CertificateData) (*models.Certificate, error) {
	if certData.CommonName == "" || certData.SerialNumber == "" {
		return nil, nil
	}

	// Look for existing certificate with same CN but different serial
	query := `
		SELECT id FROM certificates
		WHERE tenant_id = $1
		  AND common_name = $2
		  AND serial_number != $3
		  AND (superseded_by_certificate_id IS NULL)
		ORDER BY not_after DESC
		LIMIT 1
	`

	var existingID uuid.UUID
	// RLS-scoped read over certificates.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(query, tenantID, certData.CommonName, certData.SerialNumber).Scan(&existingID)
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No renewal detected
		}
		return nil, err
	}

	// Get the existing certificate
	return s.GetCertificateByID(tenantID, existingID)
}

// CreateCertificate creates a new certificate record
func (s *CertificateService) CreateCertificate(
	tenantID uuid.UUID,
	certData models.CertificateData,
) (*models.Certificate, error) {
	// Calculate fingerprint if not provided
	fingerprintSHA256 := certData.FingerprintSHA256
	if fingerprintSHA256 == "" {
		calculated, err := s.CalculateFingerprint(certData)
		if err == nil {
			fingerprintSHA256 = calculated
		} else {
			// If we can't calculate, we still create with placeholder
			// Generate a placeholder fingerprint based on serial + issuer
			if certData.SerialNumber != "" && certData.IssuerDN != "" {
				// Use a hash of serial + issuer as placeholder
				hash := sha256.Sum256([]byte(certData.SerialNumber + certData.IssuerDN))
				fingerprintSHA256 = hex.EncodeToString(hash[:])
			} else {
				return nil, fmt.Errorf("cannot create certificate without fingerprint or serial+issuer")
			}
		}
	}

	// Determine data completeness
	dataCompleteness := "complete"
	if certData.CertificatePEM == "" {
		dataCompleteness = "partial"
	}
	if fingerprintSHA256 == "" || certData.SubjectDN == "" || certData.IssuerDN == "" {
		dataCompleteness = "placeholder"
	}

	// Determine data source
	dataSource := "unknown"
	if certData.DataSource != "" {
		dataSource = certData.DataSource
	} else if certData.CertificatePEM != "" {
		dataSource = "discovery"
	}

	// Determine certificate state based on not_after
	certificateState := "active"
	if certData.NotAfter.Before(time.Now()) {
		certificateState = "expired"
	}

	insertQuery := `
		INSERT INTO certificates (
			tenant_id, serial_number, subject_dn, issuer_dn, common_name,
			subject_alternative_names, signature_algorithm, public_key_algorithm,
			public_key_size, not_before, not_after, fingerprint_sha1, fingerprint_sha256,
			certificate_pem, is_self_signed, is_ca_certificate, key_usage, extended_key_usage,
			issuer_certificate_id, certificate_state, data_completeness, data_source, cert_ownership
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23
		) RETURNING id, created_at, updated_at
	`

	var certID uuid.UUID
	var createdAt, updatedAt time.Time

	var fingerprintSHA1 *string
	if certData.FingerprintSHA1 != "" {
		fingerprintSHA1 = &certData.FingerprintSHA1
	}

	var certPEM *string
	if certData.CertificatePEM != "" {
		certPEM = &certData.CertificatePEM
	}

	var serialNum *string
	if certData.SerialNumber != "" {
		serialNum = &certData.SerialNumber
	}

	var commonName *string
	if certData.CommonName != "" {
		commonName = &certData.CommonName
	}

	var sigAlg *string
	if certData.SignatureAlgorithm != "" {
		sigAlg = &certData.SignatureAlgorithm
	}

	var pubKeyAlg *string
	if certData.PublicKeyAlgorithm != "" {
		pubKeyAlg = &certData.PublicKeyAlgorithm
	}

	var pubKeySize *int
	if certData.PublicKeySize > 0 {
		pubKeySize = &certData.PublicKeySize
	}

	var certOwnershipVal sql.NullString
	if certData.CertOwnership != "" {
		certOwnershipVal = sql.NullString{String: certData.CertOwnership, Valid: true}
	}

	// RLS-scoped write over certificates — WithTenantTx sets app.tenant_id so the
	// INSERT's tenant_id satisfies the policy WITH CHECK.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(
			insertQuery,
			tenantID, serialNum, certData.SubjectDN, certData.IssuerDN, commonName,
			pq.Array(certData.SubjectAlternativeNames), sigAlg, pubKeyAlg,
			pubKeySize, certData.NotBefore, certData.NotAfter, fingerprintSHA1, fingerprintSHA256,
			certPEM, certData.IsSelfSigned, certData.IsCACertificate,
			pq.Array(certData.KeyUsage), pq.Array(certData.ExtendedKeyUsage),
			certData.IssuerCertificateID, certificateState, dataCompleteness, dataSource,
			certOwnershipVal,
		).Scan(&certID, &createdAt, &updatedAt)
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Persist certificate quality flags if present
	s.updateCertQualityFlags(tenantID, certID, certData)

	// Record certificate creation history
	_ = s.RecordCertificateHistory(tenantID, certID, "created", map[string]interface{}{
		"source":            dataSource,
		"data_completeness": dataCompleteness,
	})

	// Build and return certificate
	cert := &models.Certificate{
		ID:                      certID,
		TenantID:                tenantID,
		SerialNumber:            serialNum,
		SubjectDN:               certData.SubjectDN,
		IssuerDN:                certData.IssuerDN,
		CommonName:              commonName,
		SubjectAlternativeNames: certData.SubjectAlternativeNames,
		SignatureAlgorithm:      sigAlg,
		PublicKeyAlgorithm:      pubKeyAlg,
		PublicKeySize:           pubKeySize,
		NotBefore:               &certData.NotBefore,
		NotAfter:                &certData.NotAfter,
		FingerprintSHA1:         fingerprintSHA1,
		FingerprintSHA256:       fingerprintSHA256,
		CertificatePEM:          certPEM,
		IsSelfSigned:            certData.IsSelfSigned,
		IsCACertificate:         certData.IsCACertificate,
		KeyUsage:                certData.KeyUsage,
		ExtendedKeyUsage:        certData.ExtendedKeyUsage,
		IssuerCertificateID:     certData.IssuerCertificateID,
		CertificateState:        certificateState,
		DataCompleteness:        dataCompleteness,
		DataSource:              &dataSource,
		CreatedAt:               createdAt,
		UpdatedAt:               updatedAt,
	}

	// Publish certificate created event
	if s.eventPublisher != nil {
		ctx := context.Background()
		source := "discovery"
		if err := s.eventPublisher.PublishCertificateChanged(ctx, tenantID, cert.ID, events.ChangeTypeCreated, source); err != nil {
			log.Printf("[CertificateService] Warning: Failed to publish certificate created event: %v", err)
		}
	}

	return cert, nil
}

// UpdateCertificate updates an existing certificate with new data
func (s *CertificateService) UpdateCertificate(
	tenantID, certID uuid.UUID,
	certData models.CertificateData,
) (*models.Certificate, error) {
	updateQuery, args := s.buildCertificateUpdateQuery(tenantID, certID, certData)

	var updatedID uuid.UUID
	var updatedAt time.Time
	// RLS-scoped write over certificates.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(updateQuery, args...).Scan(&updatedID, &updatedAt)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update certificate: %w", err)
	}

	// Record update history (args carries the trailing certID + tenantID)
	_ = s.RecordCertificateHistory(tenantID, certID, "data_enriched", map[string]interface{}{
		"fields_updated": len(args) - 2,
	})

	// Publish certificate updated event
	if s.eventPublisher != nil {
		ctx := context.Background()
		source := "discovery"
		if err := s.eventPublisher.PublishCertificateChanged(ctx, tenantID, certID, events.ChangeTypeUpdated, source); err != nil {
			log.Printf("[CertificateService] Warning: Failed to publish certificate updated event: %v", err)
		}
	}

	return s.GetCertificateByID(tenantID, certID)
}

// buildCertificateUpdateQuery assembles the dynamic enrichment UPDATE for a
// certificate: a SET clause per non-empty field, the parameter-less
// completeness/timestamp clauses, and the WHERE on (id, tenant_id). Pure so
// the placeholder arithmetic is unit-testable — the numbering drifted once
// and silently broke every enrichment update ("could not determine data type
// of parameter $N").
func (s *CertificateService) buildCertificateUpdateQuery(
	tenantID, certID uuid.UUID,
	certData models.CertificateData,
) (string, []interface{}) {
	// Build update query with only non-empty fields
	updates := []string{}
	args := []interface{}{}
	argCount := 0

	if certData.SubjectDN != "" {
		argCount++
		updates = append(updates, fmt.Sprintf("subject_dn = $%d", argCount))
		args = append(args, certData.SubjectDN)
	}
	if certData.IssuerDN != "" {
		argCount++
		updates = append(updates, fmt.Sprintf("issuer_dn = $%d", argCount))
		args = append(args, certData.IssuerDN)
	}
	if certData.SerialNumber != "" {
		argCount++
		updates = append(updates, fmt.Sprintf("serial_number = $%d", argCount))
		args = append(args, certData.SerialNumber)
	}
	if certData.CommonName != "" {
		argCount++
		updates = append(updates, fmt.Sprintf("common_name = $%d", argCount))
		args = append(args, certData.CommonName)
	}
	if len(certData.SubjectAlternativeNames) > 0 {
		argCount++
		updates = append(updates, fmt.Sprintf("subject_alternative_names = $%d", argCount))
		args = append(args, pq.Array(certData.SubjectAlternativeNames))
	}
	if certData.CertificatePEM != "" {
		argCount++
		updates = append(updates, fmt.Sprintf("certificate_pem = $%d", argCount))
		args = append(args, certData.CertificatePEM)
		// Recalculate fingerprint if PEM is being updated
		if certData.FingerprintSHA256 == "" {
			calculated, err := s.CalculateFingerprint(certData)
			if err == nil {
				argCount++
				updates = append(updates, fmt.Sprintf("fingerprint_sha256 = $%d", argCount))
				args = append(args, calculated)
			}
		}
	}
	if certData.PublicKeyAlgorithm != "" {
		argCount++
		updates = append(updates, fmt.Sprintf("public_key_algorithm = $%d", argCount))
		args = append(args, certData.PublicKeyAlgorithm)
	}
	if certData.PublicKeySize > 0 {
		argCount++
		updates = append(updates, fmt.Sprintf("public_key_size = $%d", argCount))
		args = append(args, certData.PublicKeySize)
	}
	if certData.SignatureAlgorithm != "" {
		argCount++
		updates = append(updates, fmt.Sprintf("signature_algorithm = $%d", argCount))
		args = append(args, certData.SignatureAlgorithm)
	}
	if certData.IssuerCertificateID != nil {
		argCount++
		updates = append(updates, fmt.Sprintf("issuer_certificate_id = $%d", argCount))
		args = append(args, certData.IssuerCertificateID)
	}

	// These SET clauses take no bind parameters — argCount must NOT advance for
	// them, or the WHERE placeholders below drift past the bound args and the
	// whole UPDATE fails with "could not determine data type of parameter $N".
	updates = append(updates, "data_completeness = CASE WHEN certificate_pem IS NOT NULL THEN 'complete' ELSE 'partial' END")
	updates = append(updates, "last_data_update = NOW()")
	updates = append(updates, "updated_at = NOW()")

	idArg, tenantArg := argCount+1, argCount+2
	args = append(args, certID, tenantID)

	updateQuery := fmt.Sprintf(`
		UPDATE certificates
		SET %s
		WHERE id = $%d AND tenant_id = $%d
		RETURNING id, updated_at
	`, strings.Join(updates, ", "), idArg, tenantArg)

	return updateQuery, args
}

// LinkCertificateIssuer links a certificate to its issuer certificate
func (s *CertificateService) LinkCertificateIssuer(tenantID, certID, issuerCertID uuid.UUID) error {
	// RLS-scoped write over certificates.
	return database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		query := `UPDATE certificates SET issuer_certificate_id = $1 WHERE id = $2`
		_, err := tx.Exec(query, issuerCertID, certID)
		if err != nil {
			return fmt.Errorf("failed to link certificate issuer: %w", err)
		}
		return nil
	})
}

// LinkCertificateToImplementation links a certificate to a crypto configuration
func (s *CertificateService) LinkCertificateToImplementation(
	tenantID, implID, certID uuid.UUID,
	role string,
) error {
	order := 0
	switch role {
	case "intermediate":
		order = 1
	case "root":
		order = 2
	}

	// RLS-scoped: crypto_implementations is RLS-policied (security_invoker view
	// over the partitioned table); crypto_implementation_certificates is a junction
	// table (no policy) but is written in the same tenant tx for consistency.
	return database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		// First, check if primary certificate_id should be set
		if role == "leaf" || role == "primary" {
			updateQuery := `UPDATE crypto_implementations SET certificate_id = $1 WHERE id = $2`
			if _, err := tx.Exec(updateQuery, certID, implID); err != nil {
				return fmt.Errorf("failed to update crypto configuration certificate_id: %w", err)
			}
		}

		// Also add to junction table for multiple certificates support
		insertQuery := `
			INSERT INTO crypto_implementation_certificates (
				crypto_implementation_id, certificate_id, certificate_role, certificate_order
			) VALUES ($1, $2, $3, $4)
			ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING
		`
		if _, err := tx.Exec(insertQuery, implID, certID, role, order); err != nil {
			return fmt.Errorf("failed to link certificate to implementation: %w", err)
		}
		return nil
	})
}

// GetCertificateChain retrieves the full certificate chain for a certificate
func (s *CertificateService) GetCertificateChain(
	tenantID, certID uuid.UUID,
) ([]models.Certificate, error) {
	chain := []models.Certificate{}

	// Start with the leaf certificate
	currentCert, err := s.GetCertificateByID(tenantID, certID)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}
	if currentCert == nil {
		return nil, fmt.Errorf("certificate not found")
	}

	chain = append(chain, *currentCert)

	// Follow issuer chain
	currentIssuerID := currentCert.IssuerCertificateID
	for currentIssuerID != nil {
		issuerCert, err := s.GetCertificateByID(tenantID, *currentIssuerID)
		if err != nil || issuerCert == nil {
			break // End of chain
		}
		chain = append(chain, *issuerCert)
		currentIssuerID = issuerCert.IssuerCertificateID
	}

	return chain, nil
}

// RecordCertificateHistory records a certificate lifecycle event.
//
// tenantID is now passed in by every caller. Previously this method derived it
// via `SELECT tenant_id FROM certificates WHERE id = $1`, which under enforced
// RLS would itself need a tenant context (chicken-and-egg). Threading the
// already-known tenantID removes that bootstrap lookup and lets the write run
// inside one tenant tx.
func (s *CertificateService) RecordCertificateHistory(
	tenantID, certID uuid.UUID,
	eventType string,
	eventData map[string]interface{},
) error {
	eventDataJSON, _ := json.Marshal(eventData)

	insertQuery := `
		INSERT INTO certificate_history (
			certificate_id, tenant_id, event_type, event_data, discovered_at, created_at
		) VALUES ($1, $2, $3, $4, NOW(), NOW())
	`

	// RLS-scoped write over certificate_history.
	return database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		if _, err := tx.Exec(insertQuery, certID, tenantID, eventType, eventDataJSON); err != nil {
			return fmt.Errorf("failed to record certificate history: %w", err)
		}
		return nil
	})
}

// GetCertificateHistory retrieves certificate history events
func (s *CertificateService) GetCertificateHistory(
	tenantID, certID uuid.UUID,
) ([]models.CertificateHistory, error) {
	query := `
		SELECT
			id, certificate_id, tenant_id, event_type, event_data,
			previous_certificate_id, discovered_at, created_at, created_by
		FROM certificate_history
		WHERE certificate_id = $1 AND tenant_id = $2
		ORDER BY created_at DESC
	`

	// RLS-scoped read over certificate_history.
	var history []models.CertificateHistory
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, e := tx.Query(query, certID, tenantID)
		if e != nil {
			return fmt.Errorf("failed to query certificate history: %w", e)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var h models.CertificateHistory
			var eventDataJSON sql.NullString
			var prevCertID, createdBy sql.NullString
			var discoveredAt sql.NullTime

			if e := rows.Scan(
				&h.ID, &h.CertificateID, &h.TenantID, &h.EventType, &eventDataJSON,
				&prevCertID, &discoveredAt, &h.CreatedAt, &createdBy,
			); e != nil {
				continue
			}

			if eventDataJSON.Valid {
				_ = json.Unmarshal([]byte(eventDataJSON.String), &h.EventData)
			}
			if prevCertID.Valid {
				if id, e := uuid.Parse(prevCertID.String); e == nil {
					h.PreviousCertificateID = &id
				}
			}
			if discoveredAt.Valid {
				h.DiscoveredAt = &discoveredAt.Time
			}
			if createdBy.Valid {
				if id, e := uuid.Parse(createdBy.String); e == nil {
					h.CreatedBy = &id
				}
			}

			history = append(history, h)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	return history, nil
}

// RebuildCertificateChain attempts to rebuild the certificate chain by matching issuer DNs
// This is useful when certificates are discovered separately and need to be linked
func (s *CertificateService) RebuildCertificateChain(tenantID uuid.UUID, certID uuid.UUID) (*RebuildChainResult, error) {
	result := &RebuildChainResult{
		CertificateID: certID,
		LinksCreated:  0,
		ChainComplete: false,
	}

	// Get the starting certificate
	cert, err := s.GetCertificateByID(tenantID, certID)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}
	if cert == nil {
		return nil, fmt.Errorf("certificate not found")
	}

	// If already has an issuer link or is self-signed, start chain building
	if cert.IsSelfSigned {
		result.ChainComplete = true
		result.ChainLength = 1
		return result, nil
	}

	// Build chain from this certificate up to the root
	currentCert := cert
	chainLength := 1
	maxDepth := 10 // Prevent infinite loops

	for i := 0; i < maxDepth; i++ {
		// Skip if we've reached a self-signed certificate (root)
		if currentCert.IsSelfSigned || currentCert.SubjectDN == currentCert.IssuerDN {
			result.ChainComplete = true
			break
		}

		// Skip if we already have an issuer link
		if currentCert.IssuerCertificateID != nil {
			// Follow the existing link
			nextCert, err := s.GetCertificateByID(tenantID, *currentCert.IssuerCertificateID)
			if err != nil || nextCert == nil {
				break
			}
			currentCert = nextCert
			chainLength++
			continue
		}

		// Try to find the issuer certificate by matching subject DN
		issuerCert, err := s.findCertificateBySubjectDN(tenantID, currentCert.IssuerDN)
		if err != nil || issuerCert == nil {
			// No issuer found, chain is incomplete
			break
		}

		// Verify the issuer can sign this certificate using x509
		if currentCert.CertificatePEM != nil && issuerCert.CertificatePEM != nil {
			if !s.verifyCertificateSignature(*currentCert.CertificatePEM, *issuerCert.CertificatePEM) {
				// Signature verification failed, this is not the right issuer
				break
			}
		}

		// Link the certificates
		if err := s.LinkCertificateIssuer(tenantID, currentCert.ID, issuerCert.ID); err != nil {
			log.Printf("Warning: failed to link certificate %s to issuer %s: %v", currentCert.ID, issuerCert.ID, err)
			break
		}

		result.LinksCreated++
		chainLength++
		currentCert = issuerCert

		// Check if we've reached a root
		if issuerCert.IsSelfSigned || issuerCert.SubjectDN == issuerCert.IssuerDN {
			result.ChainComplete = true
			break
		}
	}

	result.ChainLength = chainLength
	return result, nil
}

// RebuildChainResult contains the results of a certificate chain rebuild operation
type RebuildChainResult struct {
	CertificateID uuid.UUID `json:"certificate_id"`
	LinksCreated  int       `json:"links_created"`
	ChainLength   int       `json:"chain_length"`
	ChainComplete bool      `json:"chain_complete"`
}

// findCertificateBySubjectDN finds a certificate by its subject DN
func (s *CertificateService) findCertificateBySubjectDN(tenantID uuid.UUID, subjectDN string) (*models.Certificate, error) {
	query := `
		SELECT
			id, tenant_id, serial_number, subject_dn, issuer_dn, common_name,
			not_before, not_after, signature_algorithm, public_key_algorithm, public_key_size,
			fingerprint_sha256, fingerprint_sha1, subject_alternative_names,
			certificate_pem, is_self_signed, is_ca_certificate, key_usage, extended_key_usage,
			issuer_certificate_id, superseded_by_certificate_id, certificate_state,
			revoked_at, revocation_discovered_at, data_completeness, data_source,
			last_data_update, created_at, updated_at
		FROM certificates
		WHERE tenant_id = $1 AND subject_dn = $2 AND deleted_at IS NULL
		ORDER BY not_after DESC
		LIMIT 1
	`

	var cert models.Certificate
	var serialNumber, signatureAlg, pubKeyAlg sql.NullString
	var commonName, fingerprintSHA1, certPEM, dataSource sql.NullString
	var notBefore, notAfter sql.NullTime
	var pubKeySize sql.NullInt32
	var fingerprintSHA256 string
	var sans, keyUsage, extKeyUsage pq.StringArray
	var issuerCertID, supersededByID sql.NullString
	var revStatus sql.NullString
	var revokedAt, revDiscoveredAt, lastDataUpdate sql.NullTime
	var dataCompleteness sql.NullString

	// RLS-scoped read over certificates.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(query, tenantID, subjectDN).Scan(
			&cert.ID, &cert.TenantID, &serialNumber, &cert.SubjectDN, &cert.IssuerDN, &commonName,
			&notBefore, &notAfter, &signatureAlg, &pubKeyAlg, &pubKeySize,
			&fingerprintSHA256, &fingerprintSHA1, &sans,
			&certPEM, &cert.IsSelfSigned, &cert.IsCACertificate, &keyUsage, &extKeyUsage,
			&issuerCertID, &supersededByID, &revStatus,
			&revokedAt, &revDiscoveredAt, &dataCompleteness, &dataSource,
			&lastDataUpdate, &cert.CreatedAt, &cert.UpdatedAt,
		)
	})
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query certificate: %w", err)
	}

	// Map nullable fields
	if serialNumber.Valid {
		cert.SerialNumber = &serialNumber.String
	}
	if commonName.Valid {
		cert.CommonName = &commonName.String
	}
	if notBefore.Valid {
		cert.NotBefore = &notBefore.Time
	}
	if notAfter.Valid {
		cert.NotAfter = &notAfter.Time
	}
	if signatureAlg.Valid {
		cert.SignatureAlgorithm = &signatureAlg.String
	}
	if pubKeyAlg.Valid {
		cert.PublicKeyAlgorithm = &pubKeyAlg.String
	}
	if pubKeySize.Valid {
		size := int(pubKeySize.Int32)
		cert.PublicKeySize = &size
	}
	cert.FingerprintSHA256 = fingerprintSHA256
	if fingerprintSHA1.Valid {
		cert.FingerprintSHA1 = &fingerprintSHA1.String
	}
	cert.SubjectAlternativeNames = []string(sans)
	if certPEM.Valid {
		cert.CertificatePEM = &certPEM.String
	}
	cert.KeyUsage = []string(keyUsage)
	cert.ExtendedKeyUsage = []string(extKeyUsage)
	if issuerCertID.Valid {
		if id, err := uuid.Parse(issuerCertID.String); err == nil {
			cert.IssuerCertificateID = &id
		}
	}
	if supersededByID.Valid {
		if id, err := uuid.Parse(supersededByID.String); err == nil {
			cert.SupersededByCertificateID = &id
		}
	}
	if revStatus.Valid {
		cert.CertificateState = revStatus.String
	}
	if revokedAt.Valid {
		cert.RevokedAt = &revokedAt.Time
	}
	if revDiscoveredAt.Valid {
		cert.RevocationDiscoveredAt = &revDiscoveredAt.Time
	}
	if dataCompleteness.Valid {
		cert.DataCompleteness = dataCompleteness.String
	}
	if dataSource.Valid {
		cert.DataSource = &dataSource.String
	}
	if lastDataUpdate.Valid {
		cert.LastDataUpdate = &lastDataUpdate.Time
	}

	return &cert, nil
}

// verifyCertificateSignature verifies that the certificate was signed by the issuer
func (s *CertificateService) verifyCertificateSignature(certPEM, issuerPEM string) bool {
	// Parse the certificate
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}

	// Parse the issuer certificate
	issuerBlock, _ := pem.Decode([]byte(issuerPEM))
	if issuerBlock == nil {
		return false
	}
	issuer, err := x509.ParseCertificate(issuerBlock.Bytes)
	if err != nil {
		return false
	}

	// Verify the signature
	err = cert.CheckSignatureFrom(issuer)
	return err == nil
}

// RebuildAllCertificateChains rebuilds chains for all certificates in a tenant
func (s *CertificateService) RebuildAllCertificateChains(ctx context.Context, tenantID uuid.UUID) (*RebuildAllChainsResult, error) {
	result := &RebuildAllChainsResult{
		TotalCertificates: 0,
		ChainsRebuilt:     0,
		LinksCreated:      0,
		CompletedChains:   0,
		Errors:            []string{},
	}

	// Get all certificates that don't have an issuer link and are not self-signed
	query := `
		SELECT id FROM certificates
		WHERE tenant_id = $1
		AND deleted_at IS NULL
		AND is_self_signed = false
		AND issuer_certificate_id IS NULL
		ORDER BY created_at
	`

	// RLS-scoped read over certificates.
	var certIDs []uuid.UUID
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, e := tx.QueryContext(ctx, query, tenantID)
		if e != nil {
			return fmt.Errorf("failed to query certificates: %w", e)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var id uuid.UUID
			if e := rows.Scan(&id); e != nil {
				continue
			}
			certIDs = append(certIDs, id)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	result.TotalCertificates = len(certIDs)

	// Rebuild chain for each certificate
	for _, certID := range certIDs {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		chainResult, err := s.RebuildCertificateChain(tenantID, certID)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("cert %s: %v", certID, err))
			continue
		}

		if chainResult.LinksCreated > 0 {
			result.ChainsRebuilt++
			result.LinksCreated += chainResult.LinksCreated
		}
		if chainResult.ChainComplete {
			result.CompletedChains++
		}
	}

	return result, nil
}

// RebuildAllChainsResult contains the results of rebuilding all certificate chains
type RebuildAllChainsResult struct {
	TotalCertificates int      `json:"total_certificates"`
	ChainsRebuilt     int      `json:"chains_rebuilt"`
	LinksCreated      int      `json:"links_created"`
	CompletedChains   int      `json:"completed_chains"`
	Errors            []string `json:"errors,omitempty"`
}
