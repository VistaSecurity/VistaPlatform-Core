package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

type CryptoImplementationService struct {
	db *database.DB
}

func NewCryptoImplementationService(db *database.DB) *CryptoImplementationService {
	return &CryptoImplementationService{
		db: db,
	}
}

// GetCryptoImplementations retrieves crypto configurations with optional filters
func (s *CryptoImplementationService) GetCryptoImplementations(tenantID uuid.UUID, filters models.CryptoImplementationFilters) ([]models.CryptoImplementation, int, error) {
	// Set defaults
	if filters.Page == 0 {
		filters.Page = 1
	}
	if filters.PageSize == 0 {
		filters.PageSize = 20
	}
	if filters.SortBy == "" {
		filters.SortBy = "last_verified_at"
	}
	if filters.SortOrder == "" {
		filters.SortOrder = "desc"
	}

	// Base query with JOIN to network_assets for asset information
	// Also LEFT JOIN to certificates for additional context
	query := `
		SELECT
			ci.id, ci.tenant_id, ci.asset_id, ci.protocol, ci.protocol_version, ci.cipher_suite,
			ci.key_exchange_algorithm, ci.signature_algorithm, ci.symmetric_encryption,
			ci.hash_algorithm, ci.key_size, ci.certificate_id, ci.discovery_method,
			ci.confidence_score, ci.source_sensor_id, ci.raw_data, ci.risk_score,
			ci.compliance_status, ci.first_discovered_at, ci.last_verified_at,
			ci.created_at, ci.updated_at, ci.deleted_at,
			-- Asset information
			a.hostname as asset_hostname, a.ip_address as asset_ip_address, a.asset_type, a.environment as asset_environment, a.business_unit as asset_business_unit,
			-- Certificate information (if present)
			c.common_name as cert_common_name, c.issuer_dn as cert_issuer_dn
		FROM crypto_implementations ci
		INNER JOIN network_assets a ON ci.asset_id = a.id
		LEFT JOIN certificates c ON ci.certificate_id = c.id
		WHERE ci.tenant_id = $1 AND ci.deleted_at IS NULL AND a.deleted_at IS NULL
	`

	args := []interface{}{tenantID}
	argCount := 1
	whereConditions := []string{}

	// Apply filters
	if len(filters.Protocol) > 0 {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`ci.protocol = ANY($%d)`, argCount))
		args = append(args, pq.Array(filters.Protocol))
	}

	if len(filters.ProtocolVersion) > 0 {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`ci.protocol_version = ANY($%d)`, argCount))
		args = append(args, pq.Array(filters.ProtocolVersion))
	}

	if len(filters.CipherSuite) > 0 {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`ci.cipher_suite = ANY($%d)`, argCount))
		args = append(args, pq.Array(filters.CipherSuite))
	}

	if len(filters.HashAlgorithm) > 0 {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`ci.hash_algorithm = ANY($%d)`, argCount))
		args = append(args, pq.Array(filters.HashAlgorithm))
	}

	if filters.KeySizeMin != nil {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`ci.key_size >= $%d`, argCount))
		args = append(args, *filters.KeySizeMin)
	}

	if filters.CertificateID != nil {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`ci.certificate_id = $%d`, argCount))
		args = append(args, *filters.CertificateID)
	}

	if filters.AssetID != nil {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`ci.asset_id = $%d`, argCount))
		args = append(args, *filters.AssetID)
	}

	if len(filters.DiscoveryMethod) > 0 {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`ci.discovery_method = ANY($%d)`, argCount))
		args = append(args, pq.Array(filters.DiscoveryMethod))
	}

	if filters.UsesDeprecatedAlgorithms != nil && *filters.UsesDeprecatedAlgorithms {
		// Filter for deprecated algorithms: old protocol versions, weak hash algorithms, or small key sizes
		whereConditions = append(whereConditions, `(
			ci.protocol_version IN ('TLSv1.0', 'TLSv1.1', 'SSLv2', 'SSLv3')
			OR ci.hash_algorithm IN ('SHA1', 'MD5')
			OR (ci.key_size IS NOT NULL AND ci.key_size < 2048)
		)`)
	}

	if filters.Search != "" {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`(
			ci.protocol ILIKE $%d
			OR ci.protocol_version ILIKE $%d
			OR ci.cipher_suite ILIKE $%d
			OR a.hostname ILIKE $%d
			OR a.ip_address ILIKE $%d
		)`, argCount, argCount, argCount, argCount, argCount))
		searchPattern := "%" + filters.Search + "%"
		args = append(args, searchPattern)
	}

	// Build WHERE clause
	whereClause := ""
	if len(whereConditions) > 0 {
		whereClause = " AND " + strings.Join(whereConditions, " AND ")
	}
	query += whereClause

	// Get total count
	countQuery := `
		SELECT COUNT(*)
		FROM crypto_implementations ci
		INNER JOIN network_assets a ON ci.asset_id = a.id
		LEFT JOIN certificates c ON ci.certificate_id = c.id
		WHERE ci.tenant_id = $1 AND ci.deleted_at IS NULL AND a.deleted_at IS NULL
	` + whereClause

	var total int

	// Apply risk level filter (must be done after we have risk_score)
	// We'll filter in application code after calculating risk_level
	var riskLevelFilter []string
	if len(filters.RiskLevel) > 0 {
		riskLevelFilter = filters.RiskLevel
	}

	// Add ordering
	orderBy := "ORDER BY "
	switch filters.SortBy {
	case "last_verified_at", "last_verified":
		orderBy += "ci.last_verified_at"
	case "first_discovered_at", "discovered":
		orderBy += "ci.first_discovered_at"
	case "risk_score", "risk":
		orderBy += "ci.risk_score"
	case "protocol":
		orderBy += "ci.protocol"
	case "protocol_version":
		orderBy += "ci.protocol_version"
	case "created_at":
		orderBy += "ci.created_at"
	default:
		orderBy += "ci.last_verified_at"
	}

	if filters.SortOrder == "desc" {
		orderBy += " DESC"
	} else {
		orderBy += " ASC"
	}
	query += " " + orderBy

	// Add pagination
	offset := (filters.Page - 1) * filters.PageSize
	query += fmt.Sprintf(" LIMIT %d OFFSET %d", filters.PageSize, offset)

	// RLS-scoped reads over crypto_implementations (JOIN network_assets / certificates)
	// — count + page run in one tenant tx so app.tenant_id is set for both.
	var implementations []models.CryptoImplementation
	txErr := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		if e := tx.QueryRow(countQuery, args...).Scan(&total); e != nil {
			return fmt.Errorf("failed to count crypto implementations: %w", e)
		}

		// Execute query
		rows, err := tx.Queryx(query, args...)
		if err != nil {
			return fmt.Errorf("failed to query crypto implementations: %w", err)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var impl models.CryptoImplementation
			var protocolVersion, cipherSuite, keyExchangeAlg, sigAlg, symEnc, hashAlg sql.NullString
			var keySize sql.NullInt64
			var certID, sourceSensorID sql.NullString
			var confidenceScore sql.NullFloat64
			var riskScore sql.NullInt64
			var rawDataJSON, complianceStatusJSON sql.NullString
			var deletedAt sql.NullTime
			// Asset fields
			var assetHostname, assetIPAddress, assetType, assetEnvironment, assetBusinessUnit sql.NullString
			// Certificate fields
			var certCommonName, certIssuerDN sql.NullString

			err := rows.Scan(
				&impl.ID, &impl.TenantID, &impl.AssetID, &impl.Protocol, &protocolVersion, &cipherSuite,
				&keyExchangeAlg, &sigAlg, &symEnc, &hashAlg, &keySize, &certID, &impl.DiscoveryMethod,
				&confidenceScore, &sourceSensorID, &rawDataJSON, &riskScore,
				&complianceStatusJSON, &impl.FirstDiscoveredAt, &impl.LastVerifiedAt,
				&impl.CreatedAt, &impl.UpdatedAt, &deletedAt,
				&assetHostname, &assetIPAddress, &assetType, &assetEnvironment, &assetBusinessUnit,
				&certCommonName, &certIssuerDN,
			)
			if err != nil {
				return fmt.Errorf("failed to scan crypto implementation: %w", err)
			}

			// Handle nullable fields
			if protocolVersion.Valid {
				impl.ProtocolVersion = &protocolVersion.String
			}
			if cipherSuite.Valid {
				impl.CipherSuite = &cipherSuite.String
			}
			if keyExchangeAlg.Valid {
				impl.KeyExchangeAlgorithm = &keyExchangeAlg.String
			}
			if sigAlg.Valid {
				impl.SignatureAlgorithm = &sigAlg.String
			}
			if symEnc.Valid {
				impl.SymmetricEncryption = &symEnc.String
			}
			if hashAlg.Valid {
				impl.HashAlgorithm = &hashAlg.String
			}
			if keySize.Valid {
				size := int(keySize.Int64)
				impl.KeySize = &size
			}
			if certID.Valid {
				if id, err := uuid.Parse(certID.String); err == nil {
					impl.CertificateID = &id
				}
			}
			if sourceSensorID.Valid {
				if id, err := uuid.Parse(sourceSensorID.String); err == nil {
					impl.SourceSensorID = &id
				}
			}
			if confidenceScore.Valid {
				impl.ConfidenceScore = &confidenceScore.Float64
			}
			if riskScore.Valid {
				score := int(riskScore.Int64)
				impl.RiskScore = &score
			}
			if deletedAt.Valid {
				impl.DeletedAt = &deletedAt.Time
			}

			// Map asset fields
			if assetHostname.Valid {
				impl.AssetHostname = &assetHostname.String
			}
			if assetIPAddress.Valid {
				impl.AssetIPAddress = &assetIPAddress.String
			}
			if assetType.Valid {
				impl.AssetType = &assetType.String
			}
			if assetEnvironment.Valid {
				impl.AssetEnvironment = &assetEnvironment.String
			}
			if assetBusinessUnit.Valid {
				impl.AssetBusinessUnit = &assetBusinessUnit.String
			}

			// Parse JSONB fields
			if rawDataJSON.Valid && rawDataJSON.String != "" {
				var rawData models.JSONB
				if err := json.Unmarshal([]byte(rawDataJSON.String), &rawData); err == nil {
					impl.RawData = rawData
				} else {
					impl.RawData = make(models.JSONB)
				}
			} else {
				impl.RawData = make(models.JSONB)
			}

			if complianceStatusJSON.Valid && complianceStatusJSON.String != "" {
				var complianceStatus models.JSONB
				if err := json.Unmarshal([]byte(complianceStatusJSON.String), &complianceStatus); err == nil {
					impl.ComplianceStatus = complianceStatus
				} else {
					impl.ComplianceStatus = make(models.JSONB)
				}
			} else {
				impl.ComplianceStatus = make(models.JSONB)
			}

			// Calculate risk level from risk score
			score := 0
			if impl.RiskScore != nil {
				score = *impl.RiskScore
			}
			impl.RiskLevel = models.GetRiskLevel(score)

			// Filter by risk level if specified (after calculating it)
			if len(riskLevelFilter) > 0 {
				riskLevelMatch := false
				for _, level := range riskLevelFilter {
					if strings.EqualFold(impl.RiskLevel, level) {
						riskLevelMatch = true
						break
					}
				}
				if !riskLevelMatch {
					continue // Skip this implementation
				}
			}

			implementations = append(implementations, impl)
		}
		return rows.Err()
	})
	if txErr != nil {
		return nil, 0, txErr
	}

	// If we filtered by risk level, we need to adjust the total count
	// For now, we'll return the filtered count (which may be less than total)
	// In a production system, you might want to calculate this more efficiently
	if len(riskLevelFilter) > 0 {
		total = len(implementations)
	}

	if err := enrichCryptoImplementationsWithRelations(s.db, tenantID, implementations); err != nil {
		return nil, 0, err
	}

	return implementations, total, nil
}

// GetCryptoImplementationByID retrieves a single crypto configuration with full details
func (s *CryptoImplementationService) GetCryptoImplementationByID(tenantID, id uuid.UUID) (*models.CryptoImplementation, error) {
	query := `
		SELECT
			ci.id, ci.tenant_id, ci.asset_id, ci.protocol, ci.protocol_version, ci.cipher_suite,
			ci.key_exchange_algorithm, ci.signature_algorithm, ci.symmetric_encryption,
			ci.hash_algorithm, ci.key_size, ci.certificate_id, ci.discovery_method,
			ci.confidence_score, ci.source_sensor_id, ci.raw_data, ci.risk_score,
			ci.compliance_status, ci.first_discovered_at, ci.last_verified_at,
			ci.created_at, ci.updated_at, ci.deleted_at,
			-- Asset information
			a.hostname as asset_hostname, a.ip_address as asset_ip_address, a.asset_type, a.environment as asset_environment, a.business_unit as asset_business_unit
		FROM crypto_implementations ci
		INNER JOIN network_assets a ON ci.asset_id = a.id
		WHERE ci.id = $1 AND ci.tenant_id = $2 AND ci.deleted_at IS NULL AND a.deleted_at IS NULL
	`

	var impl models.CryptoImplementation
	var protocolVersion, cipherSuite, keyExchangeAlg, sigAlg, symEnc, hashAlg sql.NullString
	var keySize sql.NullInt64
	var certID, sourceSensorID sql.NullString
	var confidenceScore sql.NullFloat64
	var riskScore sql.NullInt64
	var rawDataJSON, complianceStatusJSON sql.NullString
	var deletedAt sql.NullTime
	// Asset fields
	var assetHostname, assetIPAddress, assetType, assetEnvironment, assetBusinessUnit sql.NullString

	// RLS-scoped read over crypto_implementations (JOIN network_assets).
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(query, id, tenantID).Scan(
			&impl.ID, &impl.TenantID, &impl.AssetID, &impl.Protocol, &protocolVersion, &cipherSuite,
			&keyExchangeAlg, &sigAlg, &symEnc, &hashAlg, &keySize, &certID, &impl.DiscoveryMethod,
			&confidenceScore, &sourceSensorID, &rawDataJSON, &riskScore,
			&complianceStatusJSON, &impl.FirstDiscoveredAt, &impl.LastVerifiedAt,
			&impl.CreatedAt, &impl.UpdatedAt, &deletedAt,
			&assetHostname, &assetIPAddress, &assetType, &assetEnvironment, &assetBusinessUnit,
		)
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("crypto implementation not found")
		}
		return nil, fmt.Errorf("failed to get crypto implementation: %w", err)
	}

	// Handle nullable fields
	if protocolVersion.Valid {
		impl.ProtocolVersion = &protocolVersion.String
	}
	if cipherSuite.Valid {
		impl.CipherSuite = &cipherSuite.String
	}
	if keyExchangeAlg.Valid {
		impl.KeyExchangeAlgorithm = &keyExchangeAlg.String
	}
	if sigAlg.Valid {
		impl.SignatureAlgorithm = &sigAlg.String
	}
	if symEnc.Valid {
		impl.SymmetricEncryption = &symEnc.String
	}
	if hashAlg.Valid {
		impl.HashAlgorithm = &hashAlg.String
	}
	if keySize.Valid {
		size := int(keySize.Int64)
		impl.KeySize = &size
	}
	if certID.Valid {
		if id, err := uuid.Parse(certID.String); err == nil {
			impl.CertificateID = &id
		}
	}
	if sourceSensorID.Valid {
		if id, err := uuid.Parse(sourceSensorID.String); err == nil {
			impl.SourceSensorID = &id
		}
	}
	if confidenceScore.Valid {
		impl.ConfidenceScore = &confidenceScore.Float64
	}
	if riskScore.Valid {
		score := int(riskScore.Int64)
		impl.RiskScore = &score
	}
	if deletedAt.Valid {
		impl.DeletedAt = &deletedAt.Time
	}

	// Map asset fields
	if assetHostname.Valid {
		impl.AssetHostname = &assetHostname.String
	}
	if assetIPAddress.Valid {
		impl.AssetIPAddress = &assetIPAddress.String
	}
	if assetType.Valid {
		impl.AssetType = &assetType.String
	}
	if assetEnvironment.Valid {
		impl.AssetEnvironment = &assetEnvironment.String
	}
	if assetBusinessUnit.Valid {
		impl.AssetBusinessUnit = &assetBusinessUnit.String
	}

	// Parse JSONB fields
	if rawDataJSON.Valid && rawDataJSON.String != "" {
		var rawData models.JSONB
		if err := json.Unmarshal([]byte(rawDataJSON.String), &rawData); err == nil {
			impl.RawData = rawData
		} else {
			impl.RawData = make(models.JSONB)
		}
	} else {
		impl.RawData = make(models.JSONB)
	}

	if complianceStatusJSON.Valid && complianceStatusJSON.String != "" {
		var complianceStatus models.JSONB
		if err := json.Unmarshal([]byte(complianceStatusJSON.String), &complianceStatus); err == nil {
			impl.ComplianceStatus = complianceStatus
		} else {
			impl.ComplianceStatus = make(models.JSONB)
		}
	} else {
		impl.ComplianceStatus = make(models.JSONB)
	}

	// Calculate risk level
	score := 0
	if impl.RiskScore != nil {
		score = *impl.RiskScore
	}
	impl.RiskLevel = models.GetRiskLevel(score)

	implementations := []models.CryptoImplementation{impl}
	if err := enrichCryptoImplementationsWithRelations(s.db, tenantID, implementations); err != nil {
		return nil, err
	}
	impl = implementations[0]

	return &impl, nil
}

// GetAssetCertificateLinks returns asset→certificate edges for the tenant,
// optionally scoped by asset IDs and/or certificate IDs. Each row is one
// crypto_implementation that pins a cert to an asset; an asset/cert pair can
// appear more than once if the cert is bound via multiple configurations
// (e.g. two protocols using the same cert).
//
// At least one of assetIDs or certIDs must be non-empty — the endpoint is
// intended to scope to "the edges relevant to what's currently on screen,"
// not to dump the full graph. Both can be supplied together to intersect.
func (s *CryptoImplementationService) GetAssetCertificateLinks(
	tenantID uuid.UUID,
	assetIDs []uuid.UUID,
	certIDs []uuid.UUID,
) ([]models.AssetCertificateLink, error) {
	if len(assetIDs) == 0 && len(certIDs) == 0 {
		return nil, fmt.Errorf("at least one of asset_ids or certificate_ids must be provided")
	}

	query := `
		SELECT
			ci.asset_id,
			ci.certificate_id,
			ci.id AS crypto_implementation_id,
			ci.protocol,
			ci.risk_score
		FROM crypto_implementations ci
		WHERE ci.tenant_id = $1
		  AND ci.deleted_at IS NULL
		  AND ci.certificate_id IS NOT NULL`

	args := []interface{}{tenantID}
	if len(assetIDs) > 0 {
		args = append(args, pq.Array(assetIDs))
		query += fmt.Sprintf(" AND ci.asset_id = ANY($%d)", len(args))
	}
	if len(certIDs) > 0 {
		args = append(args, pq.Array(certIDs))
		query += fmt.Sprintf(" AND ci.certificate_id = ANY($%d)", len(args))
	}

	links := make([]models.AssetCertificateLink, 0)
	// RLS-scoped read over crypto_implementations.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.Queryx(query, args...)
		if err != nil {
			return fmt.Errorf("failed to query asset-certificate links: %w", err)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var link models.AssetCertificateLink
			var certID sql.NullString
			if err := rows.Scan(
				&link.AssetID,
				&certID,
				&link.CryptoImplementationID,
				&link.Protocol,
				&link.RiskScore,
			); err != nil {
				return fmt.Errorf("failed to scan asset-certificate link: %w", err)
			}
			// certificate_id IS NOT NULL is in the WHERE, but scan needs sql.NullString
			// because the column is nullable. Re-parse defensively.
			if !certID.Valid {
				continue
			}
			parsed, err := uuid.Parse(certID.String)
			if err != nil {
				continue
			}
			link.CertificateID = parsed
			links = append(links, link)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("error iterating asset-certificate links: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return links, nil
}
