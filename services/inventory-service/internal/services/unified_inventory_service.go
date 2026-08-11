package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

type UnifiedInventoryService struct {
	db *database.DB
}

func NewUnifiedInventoryService(db *database.DB) *UnifiedInventoryService {
	return &UnifiedInventoryService{
		db: db,
	}
}

// GetUnifiedInventory retrieves a unified view of assets, certificates, and crypto implementations
func (s *UnifiedInventoryService) GetUnifiedInventory(
	tenantID uuid.UUID,
	filters models.UnifiedInventoryFilters,
) ([]models.UnifiedEntity, int, *models.UnifiedInventorySummary, error) {
	// Set defaults
	if filters.Page == 0 {
		filters.Page = 1
	}
	if filters.PageSize == 0 {
		filters.PageSize = 20
	}
	if filters.EntityType == "" {
		filters.EntityType = "both"
	}
	if filters.ViewMode == "" {
		filters.ViewMode = "unified"
	}

	// Build the unified query
	entities, queryTotal, err := s.buildUnifiedQuery(tenantID, filters)
	if err != nil {
		return nil, 0, nil, err
	}

	// Calculate total count separately for accuracy
	total := queryTotal
	if total == 0 {
		// Fallback: count entities if query count failed
		total = len(entities)
	}

	// Calculate summary
	summary, err := s.calculateSummary(tenantID, filters)
	if err != nil {
		// Don't fail on summary calculation error, just log it
		summary = &models.UnifiedInventorySummary{}
	}

	return entities, total, summary, nil
}

func (s *UnifiedInventoryService) buildUnifiedQuery(
	tenantID uuid.UUID,
	filters models.UnifiedInventoryFilters,
) ([]models.UnifiedEntity, int, error) {
	var entities []models.UnifiedEntity
	var queries []string
	// Start with tenantID as $1 - both queries will reference this
	args := []interface{}{tenantID}
	argCount := 2 // Next argument number after tenantID

	// Build shared filter arguments first (filters that apply to both asset and certificate queries)
	// This ensures UNION ALL queries use the same argument positions for common filters
	sharedArgPositions := make(map[string]int) // Map filter key to argument position

	// Environment filter - shared between asset and certificate queries
	if len(filters.Environment) > 0 {
		sharedArgPositions["environment"] = argCount
		args = append(args, pq.Array(filters.Environment))
		argCount++
	}

	// Build asset query if needed
	if filters.EntityType == "assets" || filters.EntityType == "both" {
		assetQuery, assetArgs, assetArgCount := s.buildAssetQuery(filters, argCount, sharedArgPositions)
		// Adjust placeholder numbers in the query to match combined args array positions
		// The query was built with placeholders starting from argCount, but we need them
		// relative to the combined args array. The assetArgs will be appended at position len(args),
		// so the first asset arg will be at position len(args) + 1 (1-indexed).
		// The key insight: if we add N args, and they start at argCount in the query,
		// but at len(args)+1 in combined args, then placeholders >= argCount need to be
		// adjusted by offset = (len(args)+1) - argCount.
		// However, if argCount == len(args)+1, then offset=0 and no adjustment is needed.
		// But if the query uses placeholders > argCount (e.g., argCount+1 for the first arg),
		// we still need to adjust them. The issue is we don't know the exact placeholder numbers.
		// Solution: adjust all placeholders >= argCount by the offset, which will correctly
		// map them to their positions in the combined args array.
		if len(assetArgs) > 0 {
			newBase := len(args) + 1
			// The first placeholder in the query is likely argCount (if no filters before it)
			// or argCount+1, argCount+2, etc. (depending on how many filters were added).
			// Since we don't know the exact placeholder numbers, we adjust all placeholders
			// >= argCount. However, if the first placeholder is actually argCount+1 and
			// it should be at newBase, then offset = newBase - (argCount+1).
			// But we're using oldBase=argCount, so offset = newBase - argCount.
			// This works if the first placeholder is argCount, but fails if it's argCount+1.
			// Solution: use argCount+1 as oldBase if we have args, since the first arg
			// is likely at argCount+1 (after incrementing argCount for the filter).
			oldBase := argCount
			if len(assetArgs) > 0 {
				// The first arg is likely at argCount+1 (after incrementing for the filter)
				// So adjust placeholders >= argCount+1 to start from newBase
				oldBase = argCount + 1
			}
			if newBase != oldBase {
				assetQuery = s.adjustPlaceholderNumbers(assetQuery, oldBase, newBase)
			}
		}
		queries = append(queries, assetQuery)
		args = append(args, assetArgs...)
		argCount = assetArgCount
	}

	// Build certificate query if needed
	if filters.EntityType == "certificates" || filters.EntityType == "both" {
		certQuery, certArgs, _ := s.buildCertificateQuery(filters, argCount, sharedArgPositions)
		// Adjust placeholder numbers in the query to match combined args array positions
		// Same logic as asset query: use argCount+1 as oldBase since first placeholder
		// is likely at argCount+1 (after incrementing for the filter)
		if len(certArgs) > 0 {
			oldBase := argCount + 1  // First placeholder is likely here
			newBase := len(args) + 1 // Where certArgs will start in combined args (1-indexed)
			if newBase != oldBase {
				certQuery = s.adjustPlaceholderNumbers(certQuery, oldBase, newBase)
			}
		}
		queries = append(queries, certQuery)
		args = append(args, certArgs...)
	}

	if len(queries) == 0 {
		return []models.UnifiedEntity{}, 0, nil
	}

	// Combine queries with UNION ALL
	combinedQuery := strings.Join(queries, " UNION ALL ")

	// Add ordering
	orderBy := "ORDER BY "
	if filters.SortBy != "" {
		switch filters.SortBy {
		case "risk_score", "risk_level":
			orderBy += "risk_score"
		case "created_at":
			orderBy += "created_at"
		case "expiration", "not_after":
			orderBy += "not_after"
		default:
			orderBy += "created_at"
		}
	} else {
		orderBy += "created_at"
	}

	if filters.SortOrder == "desc" {
		orderBy += " DESC"
	} else {
		orderBy += " ASC"
	}

	combinedQuery += " " + orderBy

	// Add pagination
	offset := (filters.Page - 1) * filters.PageSize
	// Use len(args) + 1 to ensure correct argument positioning
	// IMPORTANT: Calculate LIMIT/OFFSET positions BEFORE appending them to args
	limitArgNum := len(args) + 1
	offsetArgNum := len(args) + 2
	combinedQuery += fmt.Sprintf(" LIMIT $%d OFFSET $%d", limitArgNum, offsetArgNum)
	// Now append LIMIT/OFFSET args - these will be at positions limitArgNum and offsetArgNum
	args = append(args, filters.PageSize, offset)

	// Get total count by wrapping the combined query
	// Remove ORDER BY, LIMIT, and OFFSET from count query
	countQuery := combinedQuery
	// Find and remove ORDER BY clause
	if idx := strings.Index(countQuery, "ORDER BY"); idx != -1 {
		countQuery = countQuery[:idx]
	}
	// Remove LIMIT and OFFSET (they use placeholders)
	countQuery = strings.TrimSpace(countQuery)
	countArgs := args[:len(args)-2] // Remove LIMIT and OFFSET args

	// RLS-scoped reads over network_assets / certificates / crypto_implementations
	// (every UNION branch filters on tenant_id = $1) — page rows, per-row hydration,
	// and the wrapped count all run in one tenant tx (sets app.tenant_id).
	var total int
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, e := tx.Query(combinedQuery, args...)
		if e != nil {
			return fmt.Errorf("failed to execute unified query: %w", e)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var entity models.UnifiedEntity
			var entityType string
			var entityID sql.NullString
			var riskScore sql.NullInt64
			var riskLevel sql.NullString
			var certCount, assetCount, implCount sql.NullInt64
			var daysUntilExp sql.NullInt64
			var createdAt sql.NullTime
			var notAfter sql.NullTime

			if e := rows.Scan(
				&entityType,
				&entityID,
				&riskScore,
				&riskLevel,
				&certCount,
				&assetCount,
				&implCount,
				&daysUntilExp,
				&createdAt,
				&notAfter,
			); e != nil {
				return fmt.Errorf("failed to scan unified entity: %w", e)
			}

			entity.EntityType = entityType
			if riskScore.Valid {
				entity.RiskScore = int(riskScore.Int64)
			}
			if riskLevel.Valid {
				entity.RiskLevel = riskLevel.String
			}
			if certCount.Valid {
				count := int(certCount.Int64)
				entity.CertificateCount = &count
			}
			if assetCount.Valid {
				count := int(assetCount.Int64)
				entity.AssetCount = &count
			}
			if implCount.Valid {
				count := int(implCount.Int64)
				entity.CryptoImplementationCount = &count
			}
			if daysUntilExp.Valid {
				days := int(daysUntilExp.Int64)
				entity.DaysUntilExpiration = &days
			}

			// Load full entity data based on type (same tenant tx → RLS already set).
			if entityID.Valid {
				entityUUID, perr := uuid.Parse(entityID.String)
				if perr == nil {
					entity.ID = entityUUID
					switch entityType {
					case "asset":
						if asset, lerr := s.loadAssetTx(tx, tenantID, entityUUID); lerr == nil {
							entity.Asset = asset
						}
					case "certificate":
						if cert, lerr := s.loadCertificateTx(tx, tenantID, entityUUID); lerr == nil {
							entity.Certificate = cert
						}
					}
				}
			}

			entities = append(entities, entity)
		}
		if e := rows.Err(); e != nil {
			return fmt.Errorf("error iterating unified entities: %w", e)
		}

		// Count all results within the same tenant tx.
		if e := tx.QueryRow("SELECT COUNT(*) FROM ("+countQuery+") as subq", countArgs...).Scan(&total); e != nil {
			// Fallback: use entities length (may be inaccurate with pagination)
			total = len(entities)
		}
		return nil
	}); err != nil {
		return nil, 0, err
	}

	return entities, total, nil
}

func (s *UnifiedInventoryService) buildAssetQuery(
	filters models.UnifiedInventoryFilters,
	startArgCount int,
	sharedArgPositions map[string]int,
) (string, []interface{}, int) {
	argCount := startArgCount
	args := []interface{}{}
	// tenantID is $1 in the combined query
	whereConditions := []string{"a.tenant_id = $1", "a.deleted_at IS NULL"}

	// Apply asset filters
	if len(filters.AssetType) > 0 {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`a.asset_type = ANY($%d)`, argCount))
		args = append(args, pq.Array(filters.AssetType))
	}

	// Use shared argument position if environment filter is shared, otherwise create new one
	if len(filters.Environment) > 0 {
		if pos, shared := sharedArgPositions["environment"]; shared {
			whereConditions = append(whereConditions, fmt.Sprintf(`a.environment = ANY($%d)`, pos))
			// Don't add to args - it's already in the shared args
		} else {
			argCount++
			whereConditions = append(whereConditions, fmt.Sprintf(`a.environment = ANY($%d)`, argCount))
			args = append(args, pq.Array(filters.Environment))
		}
	}

	if len(filters.AssetStatus) > 0 {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`a.asset_status = ANY($%d)`, argCount))
		args = append(args, pq.Array(filters.AssetStatus))
	} else {
		whereConditions = append(whereConditions, `a.asset_status = 'monitoring'`)
	}

	// Certificate-based filters
	if filters.HasCertificates != nil && *filters.HasCertificates {
		whereConditions = append(whereConditions, `EXISTS (SELECT 1 FROM crypto_implementations ci WHERE ci.asset_id = a.id AND ci.certificate_id IS NOT NULL AND ci.deleted_at IS NULL)`)
	}

	if filters.CertExpiringWithin != nil {
		argCount++
		days := *filters.CertExpiringWithin
		whereConditions = append(whereConditions, fmt.Sprintf(`EXISTS (
			SELECT 1 FROM crypto_implementations ci
			JOIN certificates c ON ci.certificate_id = c.id
			WHERE ci.asset_id = a.id
			AND c.not_after BETWEEN NOW() AND NOW() + INTERVAL '%d days'
			AND ci.deleted_at IS NULL
		)`, days))
	}

	// Deprecated algorithms filter
	if filters.UsesDeprecatedAlgorithms != nil && *filters.UsesDeprecatedAlgorithms {
		whereConditions = append(whereConditions, `EXISTS (
			SELECT 1 FROM crypto_implementations ci
			WHERE ci.asset_id = a.id
			AND ci.deleted_at IS NULL
			AND (
				ci.protocol_version IN ('TLSv1.0', 'TLSv1.1', 'SSLv2', 'SSLv3')
				OR ci.hash_algorithm IN ('SHA1', 'MD5')
				OR (ci.key_size IS NOT NULL AND ci.key_size < 2048)
			)
		)`)
	}

	// Crypto implementation filters
	if len(filters.ProtocolVersion) > 0 {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`EXISTS (
			SELECT 1 FROM crypto_implementations ci
			WHERE ci.asset_id = a.id
			AND ci.protocol_version = ANY($%d)
			AND ci.deleted_at IS NULL
		)`, argCount))
		args = append(args, pq.Array(filters.ProtocolVersion))
	}

	if len(filters.HashAlgorithm) > 0 {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`EXISTS (
			SELECT 1 FROM crypto_implementations ci
			WHERE ci.asset_id = a.id
			AND ci.hash_algorithm = ANY($%d)
			AND ci.deleted_at IS NULL
		)`, argCount))
		args = append(args, pq.Array(filters.HashAlgorithm))
	}

	if filters.KeySizeMin != nil {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`EXISTS (
			SELECT 1 FROM crypto_implementations ci
			WHERE ci.asset_id = a.id
			AND ci.key_size >= $%d
			AND ci.deleted_at IS NULL
		)`, argCount))
		args = append(args, *filters.KeySizeMin)
	}

	// Risk level filter - must use HAVING since it uses aggregate functions
	havingConditions := []string{}
	if len(filters.RiskLevel) > 0 {
		riskConditions := []string{}
		for _, level := range filters.RiskLevel {
			// Exact-band predicates from the canonical ladder, so the filter can
			// never select a different range than the badge displays.
			if cond, ok := models.RiskBandSQL("COALESCE(MAX(ci.risk_score), 0)", level); ok {
				riskConditions = append(riskConditions, cond)
			}
		}
		if len(riskConditions) > 0 {
			havingConditions = append(havingConditions, "("+strings.Join(riskConditions, " OR ")+")")
		}
	}

	query := fmt.Sprintf(`
		SELECT
			'asset' as entity_type,
			a.id::text as entity_id,
			COALESCE(MAX(ci.risk_score), 0) as risk_score,
			`+models.RiskLevelCaseSQL("COALESCE(MAX(ci.risk_score), 0)")+` as risk_level,
			COUNT(DISTINCT c.id) as certificate_count,
			NULL::bigint as asset_count,
			COUNT(DISTINCT ci.id) as crypto_implementation_count,
			NULL::bigint as days_until_expiration,
			a.created_at as created_at,
			NULL::timestamp as not_after
		FROM network_assets a
		LEFT JOIN crypto_implementations ci ON a.id = ci.asset_id AND ci.deleted_at IS NULL
		LEFT JOIN certificates c ON ci.certificate_id = c.id
		WHERE %s
		GROUP BY a.id, a.created_at
	`, strings.Join(whereConditions, " AND "))

	// Add HAVING clause if we have risk level filters
	if len(havingConditions) > 0 {
		query += " HAVING " + strings.Join(havingConditions, " AND ")
	}

	return query, args, argCount
}

func (s *UnifiedInventoryService) buildCertificateQuery(
	filters models.UnifiedInventoryFilters,
	startArgCount int,
	sharedArgPositions map[string]int,
) (string, []interface{}, int) {
	argCount := startArgCount
	args := []interface{}{}
	// tenantID is $1 in the combined query
	whereConditions := []string{"c.tenant_id = $1"}

	// Certificate-specific filters
	if filters.CertExpiringWithin != nil {
		argCount++
		days := *filters.CertExpiringWithin
		whereConditions = append(whereConditions, fmt.Sprintf(`c.not_after BETWEEN NOW() AND NOW() + INTERVAL '%d days'`, days))
	}

	if filters.CertExpiringDays != nil {
		argCount++
		days := *filters.CertExpiringDays
		whereConditions = append(whereConditions, fmt.Sprintf(`c.not_after BETWEEN NOW() AND NOW() + INTERVAL '%d days'`, days))
	}

	if filters.CertKeySizeMin != nil {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`c.public_key_size >= $%d`, argCount))
		args = append(args, *filters.CertKeySizeMin)
	}

	if filters.CertAlgorithm != nil {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`c.public_key_algorithm = $%d`, argCount))
		args = append(args, *filters.CertAlgorithm)
	}

	if filters.CertIssuer != nil {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`c.issuer_dn ILIKE $%d`, argCount))
		args = append(args, "%"+*filters.CertIssuer+"%")
	}

	// Environment filter (through related assets) - use shared argument position if available
	if len(filters.Environment) > 0 {
		if pos, shared := sharedArgPositions["environment"]; shared {
			whereConditions = append(whereConditions, fmt.Sprintf(`EXISTS (
				SELECT 1 FROM crypto_implementations ci
				JOIN network_assets a ON ci.asset_id = a.id
				WHERE ci.certificate_id = c.id
				AND a.environment = ANY($%d)
				AND a.deleted_at IS NULL
				AND ci.deleted_at IS NULL
			)`, pos))
			// Don't add to args - it's already in the shared args
		} else {
			argCount++
			whereConditions = append(whereConditions, fmt.Sprintf(`EXISTS (
				SELECT 1 FROM crypto_implementations ci
				JOIN network_assets a ON ci.asset_id = a.id
				WHERE ci.certificate_id = c.id
				AND a.environment = ANY($%d)
				AND a.deleted_at IS NULL
				AND ci.deleted_at IS NULL
			)`, argCount))
			args = append(args, pq.Array(filters.Environment))
		}
	}

	// Risk level filter - must use HAVING since it uses aggregate functions
	havingConditions := []string{}
	if len(filters.RiskLevel) > 0 {
		riskConditions := []string{}
		for _, level := range filters.RiskLevel {
			// Exact-band predicates from the canonical ladder, so the filter can
			// never select a different range than the badge displays.
			if cond, ok := models.RiskBandSQL("COALESCE(MAX(ci.risk_score), 0)", level); ok {
				riskConditions = append(riskConditions, cond)
			}
		}
		if len(riskConditions) > 0 {
			havingConditions = append(havingConditions, "("+strings.Join(riskConditions, " OR ")+")")
		}
	}

	query := fmt.Sprintf(`
		SELECT
			'certificate' as entity_type,
			c.id::text as entity_id,
			COALESCE(MAX(ci.risk_score), 0) as risk_score,
			`+models.RiskLevelCaseSQL("COALESCE(MAX(ci.risk_score), 0)")+` as risk_level,
			NULL::bigint as certificate_count,
			COUNT(DISTINCT a.id) as asset_count,
			COUNT(DISTINCT ci.id) as crypto_implementation_count,
			EXTRACT(DAY FROM (c.not_after - NOW()))::int as days_until_expiration,
			c.created_at as created_at,
			c.not_after as not_after
		FROM certificates c
		LEFT JOIN crypto_implementations ci ON c.id = ci.certificate_id AND ci.deleted_at IS NULL
		LEFT JOIN network_assets a ON ci.asset_id = a.id AND a.deleted_at IS NULL
		WHERE %s
		GROUP BY c.id, c.created_at, c.not_after
	`, strings.Join(whereConditions, " AND "))

	// Add HAVING clause if we have risk level filters
	if len(havingConditions) > 0 {
		query += " HAVING " + strings.Join(havingConditions, " AND ")
	}

	return query, args, argCount
}

// loadAssetTx hydrates a single asset inside an existing tenant tx (RLS already
// set by the caller's WithTenantTx). network_assets is RLS-scoped.
func (s *UnifiedInventoryService) loadAssetTx(tx *sqlx.Tx, tenantID, assetID uuid.UUID) (*models.Asset, error) {
	query := `
		SELECT
			id, tenant_id, hostname, ip_address, port, asset_type,
			operating_system, environment, business_unit, owner_email,
			description, tags::text, metadata::text, asset_ownership, asset_status,
			first_discovered_at, last_seen_at,
			created_at, updated_at, deleted_at
		FROM network_assets
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
	`

	var asset models.Asset
	var tagsText, metadataText sql.NullString

	err := tx.QueryRow(query, assetID, tenantID).Scan(
		&asset.ID, &asset.TenantID, &asset.Hostname, &asset.IPAddress, &asset.Port,
		&asset.AssetType, &asset.OperatingSystem, &asset.Environment, &asset.BusinessUnit,
		&asset.OwnerEmail, &asset.Description, &tagsText, &metadataText, &asset.AssetOwnership, &asset.AssetStatus,
		&asset.FirstDiscoveredAt, &asset.LastSeenAt, &asset.CreatedAt, &asset.UpdatedAt,
		&asset.DeletedAt,
	)
	if err != nil {
		return nil, err
	}

	// Parse JSON fields
	if tagsText.Valid {
		_ = json.Unmarshal([]byte(tagsText.String), &asset.Tags)
	}
	if metadataText.Valid {
		_ = json.Unmarshal([]byte(metadataText.String), &asset.Metadata)
	}

	return &asset, nil
}

// loadCertificateTx hydrates a single certificate inside an existing tenant tx
// (RLS already set by the caller's WithTenantTx). certificates is RLS-scoped.
func (s *UnifiedInventoryService) loadCertificateTx(tx *sqlx.Tx, tenantID, certID uuid.UUID) (*models.Certificate, error) {
	query := `
		SELECT
			id, tenant_id, serial_number, subject_dn, issuer_dn, common_name,
			subject_alternative_names, signature_algorithm, public_key_algorithm,
			public_key_size, not_before, not_after, fingerprint_sha1, fingerprint_sha256,
			certificate_pem, is_self_signed, is_ca_certificate, key_usage, extended_key_usage,
			created_at, updated_at
		FROM certificates
		WHERE id = $1 AND tenant_id = $2
	`

	var cert models.Certificate
	var serialNumber, commonName, sigAlg, pubKeyAlg, certPEM, fpSHA1 sql.NullString
	var pubKeySize sql.NullInt64
	var notBefore, notAfter sql.NullTime
	var sanArray pq.StringArray

	err := tx.QueryRow(query, certID, tenantID).Scan(
		&cert.ID, &cert.TenantID, &serialNumber, &cert.SubjectDN, &cert.IssuerDN, &commonName,
		&sanArray, &sigAlg, &pubKeyAlg, &pubKeySize, &notBefore, &notAfter,
		&fpSHA1, &cert.FingerprintSHA256, &certPEM, &cert.IsSelfSigned, &cert.IsCACertificate,
		pq.Array(&cert.KeyUsage), pq.Array(&cert.ExtendedKeyUsage),
		&cert.CreatedAt, &cert.UpdatedAt,
	)
	if err != nil {
		return nil, err
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
	cert.SubjectAlternativeNames = []string(sanArray)

	return &cert, nil
}

func (s *UnifiedInventoryService) calculateSummary(
	tenantID uuid.UUID,
	filters models.UnifiedInventoryFilters,
) (*models.UnifiedInventorySummary, error) {
	summary := &models.UnifiedInventorySummary{}

	// RLS-scoped reads over network_assets / certificates / crypto_implementations —
	// all summary counts run in one tenant tx (sets app.tenant_id). Per-query errors
	// are tolerated (best-effort summary), matching the prior behavior.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		// Total assets
		var totalAssets int
		if e := tx.QueryRow("SELECT COUNT(*) FROM network_assets WHERE tenant_id = $1 AND deleted_at IS NULL AND asset_status = 'monitoring'", tenantID).Scan(&totalAssets); e == nil {
			summary.TotalAssets = totalAssets
		}

		// Total certificates
		var totalCerts int
		if e := tx.QueryRow("SELECT COUNT(*) FROM certificates WHERE tenant_id = $1", tenantID).Scan(&totalCerts); e == nil {
			summary.TotalCertificates = totalCerts
		}

		// Total crypto implementations
		var totalImpls int
		if e := tx.QueryRow(`
			SELECT COUNT(*) FROM crypto_implementations ci
			JOIN network_assets a ON ci.asset_id = a.id
			WHERE a.tenant_id = $1 AND ci.deleted_at IS NULL AND a.deleted_at IS NULL
		`, tenantID).Scan(&totalImpls); e == nil {
			summary.TotalCryptoImplementations = totalImpls
		}

		// Expiring certificates (within 30 days)
		var expiringCerts int
		if e := tx.QueryRow(`
			SELECT COUNT(*) FROM certificates
			WHERE tenant_id = $1
			AND not_after BETWEEN NOW() AND NOW() + INTERVAL '30 days'
		`, tenantID).Scan(&expiringCerts); e == nil {
			summary.ExpiringCertificates = expiringCerts
		}

		// Deprecated algorithms
		var deprecatedAlgs int
		if e := tx.QueryRow(`
			SELECT COUNT(DISTINCT ci.id) FROM crypto_implementations ci
			JOIN network_assets a ON ci.asset_id = a.id
			WHERE a.tenant_id = $1
			AND ci.deleted_at IS NULL
			AND a.deleted_at IS NULL
			AND (
				ci.protocol_version IN ('TLSv1.0', 'TLSv1.1', 'SSLv2', 'SSLv3')
				OR ci.hash_algorithm IN ('SHA1', 'MD5')
				OR (ci.key_size IS NOT NULL AND ci.key_size < 2048)
			)
		`, tenantID).Scan(&deprecatedAlgs); e == nil {
			summary.DeprecatedAlgorithms = deprecatedAlgs
		}

		// Assets with certificates
		var assetsWithCerts int
		if e := tx.QueryRow(`
			SELECT COUNT(DISTINCT a.id) FROM network_assets a
			JOIN crypto_implementations ci ON a.id = ci.asset_id
			WHERE a.tenant_id = $1
			AND a.deleted_at IS NULL
			AND ci.deleted_at IS NULL
			AND ci.certificate_id IS NOT NULL
		`, tenantID).Scan(&assetsWithCerts); e == nil {
			summary.AssetsWithCertificates = assetsWithCerts
		}

		// High risk entities
		var highRisk int
		if e := tx.QueryRow(`
			SELECT COUNT(*) FROM (
				SELECT a.id FROM network_assets a
				LEFT JOIN crypto_implementations ci ON a.id = ci.asset_id AND ci.deleted_at IS NULL
				WHERE a.tenant_id = $1 AND a.deleted_at IS NULL
				GROUP BY a.id
				HAVING `+models.MustRiskAtLeastSQL("COALESCE(MAX(ci.risk_score), 0)", "High")+`
			) as high_risk_assets
		`, tenantID).Scan(&highRisk); e == nil {
			summary.HighRiskEntities = highRisk
		}
		return nil
	}); err != nil {
		return summary, err
	}

	return summary, nil
}

// adjustPlaceholderNumbers adjusts placeholder numbers in a query string to match new base position
// oldBase: the base argument number used when building the query (e.g., startArgCount)
// newBase: the new base argument number in the combined args array
// This adjusts all placeholders >= oldBase by the offset (newBase - oldBase)
func (s *UnifiedInventoryService) adjustPlaceholderNumbers(query string, oldBase int, newBase int) string {
	if oldBase == newBase {
		return query // No adjustment needed
	}

	offset := newBase - oldBase
	// Match $N patterns where N is a number, but only adjust placeholders >= oldBase
	re := regexp.MustCompile(`\$(\d+)`)

	return re.ReplaceAllStringFunc(query, func(match string) string {
		numStr := match[1:] // Remove the $
		num, err := strconv.Atoi(numStr)
		if err != nil {
			return match // If not a number, return as-is
		}

		// Only adjust placeholders that are >= oldBase (these are the ones we added in this query)
		// Placeholders < oldBase (like $1 for tenantID) should remain unchanged
		if num >= oldBase {
			newNum := num + offset
			// Ensure we don't create invalid placeholder numbers
			if newNum < 1 {
				return match // Don't adjust if result would be invalid
			}
			return fmt.Sprintf("$%d", newNum)
		}
		return match
	})
}
