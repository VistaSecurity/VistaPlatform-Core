package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
)

// CryptoRisksSummary represents aggregated crypto risk statistics
type CryptoRisksSummary struct {
	Critical          int `json:"critical"`
	High              int `json:"high"`
	Medium            int `json:"medium"`
	Informational     int `json:"informational"`
	TotalAffected     int `json:"total_assets_affected"`
	ProtocolIssues    int `json:"protocol_issues"`
	AlgorithmIssues   int `json:"algorithm_issues"`
	CertificateIssues int `json:"certificate_issues"`
	KeySizeIssues     int `json:"key_size_issues"`
}

// CryptoRisk represents a detected cryptographic risk
type CryptoRisk struct {
	ID                     uuid.UUID `json:"id" db:"id"`
	TenantID               uuid.UUID `json:"tenant_id" db:"tenant_id"`
	AssetID                uuid.UUID `json:"asset_id" db:"asset_id"`
	CryptoImplementationID uuid.UUID `json:"crypto_implementation_id" db:"crypto_implementation_id"`
	Severity               string    `json:"severity"`
	Category               string    `json:"category"`
	IssueType              string    `json:"issue_type"`
	CurrentValue           string    `json:"current_value"`
	Description            string    `json:"description"`
	Recommendation         string    `json:"recommendation"`
	DetectedAt             time.Time `json:"detected_at"`
	// Asset info
	AssetHostname  *string `json:"asset_hostname,omitempty" db:"hostname"`
	AssetIPAddress *string `json:"asset_ip_address,omitempty" db:"ip_address"`
	AssetPort      *int    `json:"asset_port,omitempty" db:"port"`
	AssetType      string  `json:"asset_type,omitempty" db:"asset_type"`
	// Crypto implementation info
	Protocol        string  `json:"protocol,omitempty" db:"protocol"`
	ProtocolVersion *string `json:"protocol_version,omitempty" db:"protocol_version"`
	CipherSuite     *string `json:"cipher_suite,omitempty" db:"cipher_suite"`
}

// CryptoRiskFilters defines filters for crypto risk queries
type CryptoRiskFilters struct {
	Severity  []string `json:"severity" form:"severity"` // critical, high, medium, info
	Category  []string `json:"category" form:"category"` // protocol, algorithm, certificate, key_size
	Search    string   `json:"search" form:"search"`
	Page      int      `json:"page" form:"page"`
	PageSize  int      `json:"page_size" form:"page_size"`
	SortBy    string   `json:"sort_by" form:"sort_by"`
	SortOrder string   `json:"sort_order" form:"sort_order"`
}

// CryptoRisksResponse represents the paginated response for crypto risks
// MaxCryptoRiskPageSize is the largest page a single ListRisks call will
// return. List endpoints clamp to it; the CSV export pages through in chunks
// of this size to stream the full result set.
const MaxCryptoRiskPageSize = 100

type CryptoRisksResponse struct {
	Risks      []CryptoRisk `json:"risks"`
	Total      int          `json:"total"`
	Page       int          `json:"page"`
	PageSize   int          `json:"page_size"`
	TotalPages int          `json:"total_pages"`
}

// CryptoRisksService handles crypto risk queries and analysis
type CryptoRisksService struct {
	db *database.DB
}

// NewCryptoRisksService creates a new crypto risks service
func NewCryptoRisksService(db *database.DB) *CryptoRisksService {
	return &CryptoRisksService{db: db}
}

// GetSummary returns aggregated crypto risk statistics for a tenant
func (s *CryptoRisksService) GetSummary(tenantID uuid.UUID) (*CryptoRisksSummary, error) {
	summary := &CryptoRisksSummary{}

	// RLS-scoped reads over crypto_implementations / certificates (JOIN network_assets)
	// — all aggregate counts run in one tenant tx so app.tenant_id is set throughout.
	txErr := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		// Critical: TLS 1.0, SSL, RC4, MD5, DES, weak keys < 1024
		// Handle various protocol version formats: '1.0', 'TLSv1.0', 'TLSV1.0', 'TLS 1.0', 'TLS1.0'
		criticalQuery := `
		SELECT COUNT(DISTINCT ci.asset_id)
		-- key-size and DES predicates are generated (weak_crypto_detector.go) so
		-- the summary counters, the list filters and the Go classifier cannot
		-- disagree about what counts as weak.
		FROM crypto_implementations ci
		JOIN network_assets na ON ci.asset_id = na.id AND na.deleted_at IS NULL
		WHERE ci.tenant_id = $1
		  AND ci.deleted_at IS NULL
		  AND (
			UPPER(ci.protocol_version) IN ('SSLV2', 'SSLV3', 'SSL2', 'SSL3')
			OR UPPER(ci.protocol_version) LIKE '%TLS%1.0%'
			OR UPPER(ci.protocol_version) LIKE '%TLS%1%0%'
			OR (ci.protocol_version IS NOT NULL AND (
				ci.protocol_version = '1.0'
				OR ci.protocol_version LIKE '1.0%'
				OR ci.protocol_version LIKE '%1.0'
			))
			OR UPPER(ci.cipher_suite) LIKE '%RC4%'
			OR ` + singleDESSQL("ci.cipher_suite") + `
			OR UPPER(ci.cipher_suite) LIKE '%NULL%'
			OR UPPER(ci.cipher_suite) LIKE '%EXPORT%'
			OR UPPER(ci.hash_algorithm) LIKE '%MD5%'
			OR UPPER(ci.hash_algorithm) LIKE '%MD4%'
			OR ` + criticallyWeakKeySizeSQL("ci.key_size", "ci.key_exchange_algorithm") + `
		  )
	`
		if err := tx.Get(&summary.Critical, criticalQuery, tenantID); err != nil {
			return fmt.Errorf("failed to count critical risks: %w", err)
		}

		// High: TLS 1.1, SHA1, 3DES, RSA < 2048
		// Handle various protocol version formats: '1.1', 'TLSv1.1', 'TLSV1.1', 'TLS 1.1', 'TLS1.1'
		highQuery := `
		SELECT COUNT(DISTINCT ci.asset_id)
		FROM crypto_implementations ci
		JOIN network_assets na ON ci.asset_id = na.id AND na.deleted_at IS NULL
		WHERE ci.tenant_id = $1
		  AND ci.deleted_at IS NULL
		  AND (
			UPPER(ci.protocol_version) LIKE '%TLS%1.1%'
			OR UPPER(ci.protocol_version) LIKE '%TLS%1%1%'
			OR (ci.protocol_version IS NOT NULL AND (
				ci.protocol_version = '1.1'
				OR ci.protocol_version LIKE '1.1%'
				OR ci.protocol_version LIKE '%1.1'
			))
			OR ` + tripleDESSQL("ci.cipher_suite") + `
			OR UPPER(ci.hash_algorithm) LIKE '%SHA1%' OR UPPER(ci.hash_algorithm) LIKE '%SHA-1%'
			OR ` + highRiskKeySizeSQL("ci.key_size", "ci.key_exchange_algorithm") + `
		  )
		  AND NOT (
			UPPER(ci.protocol_version) IN ('SSLV2', 'SSLV3', 'SSL2', 'SSL3')
			OR UPPER(ci.protocol_version) LIKE '%TLS%1.0%'
			OR UPPER(ci.protocol_version) LIKE '%TLS%1%0%'
			OR (ci.protocol_version IS NOT NULL AND (
				ci.protocol_version = '1.0'
				OR ci.protocol_version LIKE '1.0%'
				OR ci.protocol_version LIKE '%1.0'
			))
			OR UPPER(ci.cipher_suite) LIKE '%RC4%'
			OR ` + singleDESSQL("ci.cipher_suite") + `
			OR UPPER(ci.cipher_suite) LIKE '%NULL%'
			OR UPPER(ci.hash_algorithm) LIKE '%MD5%'
			OR ` + criticallyWeakKeySizeSQL("ci.key_size", "ci.key_exchange_algorithm") + `
		  )
	`
		if err := tx.Get(&summary.High, highQuery, tenantID); err != nil {
			return fmt.Errorf("failed to count high risks: %w", err)
		}

		// Medium: Certificates expiring within 30 days
		mediumQuery := `
		SELECT COUNT(DISTINCT ci.asset_id)
		FROM crypto_implementations ci
		JOIN network_assets na ON ci.asset_id = na.id AND na.deleted_at IS NULL
		JOIN crypto_implementation_certificates cic ON ci.id = cic.crypto_implementation_id
		JOIN certificates c ON cic.certificate_id = c.id
		WHERE ci.tenant_id = $1
		  AND ci.deleted_at IS NULL
		  AND c.not_after IS NOT NULL
		  AND c.not_after BETWEEN NOW() AND NOW() + INTERVAL '30 days'
	`
		if err := tx.Get(&summary.Medium, mediumQuery, tenantID); err != nil {
			return fmt.Errorf("failed to count medium risks: %w", err)
		}

		// Informational: any implementation with a positive risk_score that
		// doesn't match one of the Critical/High protocol/cipher/hash/key-size
		// signatures or the Medium cert-expiry window. This predicate must stay
		// IDENTICAL to ListRisks' `severity=informational` filter (L-9a): before
		// this fix, Informational was never assigned (always the Go zero value),
		// so /crypto-risks/summary reported all-zero severity buckets tenant-wide
		// while /crypto-risks (list, unfiltered) returned non-zero rows —
		// classifyRisk defaults unmatched-but-risk_score>0 rows to
		// "informational", which the summary had no query for at all.
		informationalQuery := `
		SELECT COUNT(DISTINCT ci.asset_id)
		FROM crypto_implementations ci
		JOIN network_assets na ON ci.asset_id = na.id AND na.deleted_at IS NULL
		WHERE ci.tenant_id = $1
		  AND ci.deleted_at IS NULL
		  AND ci.risk_score IS NOT NULL AND ci.risk_score > 0
		  AND NOT (
			UPPER(ci.protocol_version) IN ('SSLV2', 'SSLV3', 'SSL2', 'SSL3')
			OR UPPER(ci.protocol_version) LIKE '%TLS%1.0%'
			OR UPPER(ci.protocol_version) LIKE '%TLS%1%0%'
			OR UPPER(ci.protocol_version) LIKE '%TLS%1.1%'
			OR UPPER(ci.protocol_version) LIKE '%TLS%1%1%'
			OR (ci.protocol_version IS NOT NULL AND (
				ci.protocol_version = '1.0'
				OR ci.protocol_version = '1.1'
				OR ci.protocol_version LIKE '1.0%'
				OR ci.protocol_version LIKE '1.1%'
				OR ci.protocol_version LIKE '%1.0'
				OR ci.protocol_version LIKE '%1.1'
			))
			OR UPPER(ci.cipher_suite) LIKE '%RC4%'
			OR UPPER(ci.cipher_suite) LIKE '%DES%'
			OR UPPER(ci.cipher_suite) LIKE '%NULL%'
			OR UPPER(ci.cipher_suite) LIKE '%EXPORT%'
			OR UPPER(ci.hash_algorithm) LIKE '%MD5%'
			OR UPPER(ci.hash_algorithm) LIKE '%MD4%'
			OR UPPER(ci.hash_algorithm) LIKE '%SHA1%'
			OR UPPER(ci.hash_algorithm) LIKE '%SHA-1%'
			OR ` + anyWeakKeySizeSQL("ci.key_size", "ci.key_exchange_algorithm") + `
			OR EXISTS (
				SELECT 1 FROM crypto_implementation_certificates cic
				JOIN certificates c ON cic.certificate_id = c.id
				WHERE cic.crypto_implementation_id = ci.id
				  AND c.not_after IS NOT NULL
				  AND c.not_after BETWEEN NOW() AND NOW() + INTERVAL '30 days'
			)
		  )
	`
		if err := tx.Get(&summary.Informational, informationalQuery, tenantID); err != nil {
			return fmt.Errorf("failed to count informational risks: %w", err)
		}

		// Total affected assets (any risk)
		totalQuery := `
		SELECT COUNT(DISTINCT ci.asset_id)
		FROM crypto_implementations ci
		JOIN network_assets na ON ci.asset_id = na.id AND na.deleted_at IS NULL
		WHERE ci.tenant_id = $1
		  AND ci.deleted_at IS NULL
		  AND (
			ci.risk_score IS NOT NULL AND ci.risk_score > 0
		  )
	`
		if err := tx.Get(&summary.TotalAffected, totalQuery, tenantID); err != nil {
			return fmt.Errorf("failed to count total affected: %w", err)
		}

		// Protocol issues
		// Handle various protocol version formats
		protocolQuery := `
		SELECT COUNT(*)
		FROM crypto_implementations ci
		JOIN network_assets na ON ci.asset_id = na.id AND na.deleted_at IS NULL
		WHERE ci.tenant_id = $1
		  AND ci.deleted_at IS NULL
		  AND (
			UPPER(ci.protocol_version) IN ('SSLV2', 'SSLV3', 'SSL2', 'SSL3')
			OR UPPER(ci.protocol_version) LIKE '%TLS%1.0%'
			OR UPPER(ci.protocol_version) LIKE '%TLS%1%0%'
			OR UPPER(ci.protocol_version) LIKE '%TLS%1.1%'
			OR UPPER(ci.protocol_version) LIKE '%TLS%1%1%'
			OR (ci.protocol_version IS NOT NULL AND (
				ci.protocol_version = '1.0'
				OR ci.protocol_version = '1.1'
				OR ci.protocol_version LIKE '1.0%'
				OR ci.protocol_version LIKE '1.1%'
				OR ci.protocol_version LIKE '%1.0'
				OR ci.protocol_version LIKE '%1.1'
			))
		  )
	`
		if err := tx.Get(&summary.ProtocolIssues, protocolQuery, tenantID); err != nil {
			return fmt.Errorf("failed to count protocol issues: %w", err)
		}

		// Algorithm issues
		algorithmQuery := `
		SELECT COUNT(*)
		FROM crypto_implementations ci
		JOIN network_assets na ON ci.asset_id = na.id AND na.deleted_at IS NULL
		WHERE ci.tenant_id = $1
		  AND ci.deleted_at IS NULL
		  AND (
			UPPER(ci.cipher_suite) LIKE '%RC4%'
			OR UPPER(ci.cipher_suite) LIKE '%DES%'
			OR UPPER(ci.cipher_suite) LIKE '%3DES%'
			OR UPPER(ci.cipher_suite) LIKE '%NULL%'
			OR UPPER(ci.cipher_suite) LIKE '%EXPORT%'
			OR UPPER(ci.hash_algorithm) LIKE '%MD5%'
			OR UPPER(ci.hash_algorithm) LIKE '%SHA1%'
			OR UPPER(ci.hash_algorithm) LIKE '%SHA-1%'
		  )
	`
		if err := tx.Get(&summary.AlgorithmIssues, algorithmQuery, tenantID); err != nil {
			return fmt.Errorf("failed to count algorithm issues: %w", err)
		}

		// Certificate issues (expiring within 90 days or weak key)
		certQuery := `
		SELECT COUNT(*)
		FROM certificates c
		WHERE c.tenant_id = $1
		  AND (
			(c.not_after IS NOT NULL AND c.not_after BETWEEN NOW() AND NOW() + INTERVAL '90 days')
			OR (c.public_key_size IS NOT NULL AND c.public_key_size < 2048)
		  )
	`
		if err := tx.Get(&summary.CertificateIssues, certQuery, tenantID); err != nil {
			return fmt.Errorf("failed to count certificate issues: %w", err)
		}

		// Key size issues
		keySizeQuery := `
		SELECT COUNT(*)
		FROM crypto_implementations ci
		JOIN network_assets na ON ci.asset_id = na.id AND na.deleted_at IS NULL
		WHERE ci.tenant_id = $1
		  AND ci.deleted_at IS NULL
		  AND ` + anyWeakKeySizeSQL("ci.key_size", "ci.key_exchange_algorithm") + `
	`
		if err := tx.Get(&summary.KeySizeIssues, keySizeQuery, tenantID); err != nil {
			return fmt.Errorf("failed to count key size issues: %w", err)
		}
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}

	return summary, nil
}

// ListRisks returns a paginated list of crypto risks for a tenant
func (s *CryptoRisksService) ListRisks(tenantID uuid.UUID, filters CryptoRiskFilters) (*CryptoRisksResponse, error) {
	// Set defaults
	if filters.Page < 1 {
		filters.Page = 1
	}
	if filters.PageSize < 1 {
		filters.PageSize = 20
	} else if filters.PageSize > MaxCryptoRiskPageSize {
		// Clamp oversized page requests to the max instead of silently
		// snapping back to the default — the export path pages through at
		// MaxCryptoRiskPageSize and would otherwise be truncated to 20.
		filters.PageSize = MaxCryptoRiskPageSize
	}
	offset := (filters.Page - 1) * filters.PageSize

	// Build the query to identify risky crypto implementations
	var conditions []string
	args := []interface{}{tenantID}
	argPos := 2

	// Base condition for risks
	riskConditions := []string{}

	// Severity filter
	if len(filters.Severity) > 0 {
		severityConditions := []string{}
		for _, sev := range filters.Severity {
			switch strings.ToLower(sev) {
			case "critical":
				severityConditions = append(severityConditions, `(
					UPPER(ci.protocol_version) IN ('SSLV2', 'SSLV3', 'SSL2', 'SSL3')
					OR UPPER(ci.protocol_version) LIKE '%TLS%1.0%'
					OR UPPER(ci.protocol_version) LIKE '%TLS%1%0%'
					OR (ci.protocol_version IS NOT NULL AND (
						ci.protocol_version = '1.0'
						OR ci.protocol_version LIKE '1.0%'
						OR ci.protocol_version LIKE '%1.0'
					))
					OR UPPER(ci.cipher_suite) LIKE '%RC4%'
					OR `+singleDESSQL("ci.cipher_suite")+`
					OR UPPER(ci.cipher_suite) LIKE '%NULL%'
					OR UPPER(ci.cipher_suite) LIKE '%EXPORT%'
					OR UPPER(ci.hash_algorithm) LIKE '%MD5%'
					OR UPPER(ci.hash_algorithm) LIKE '%MD4%'
					OR `+criticallyWeakKeySizeSQL("ci.key_size", "ci.key_exchange_algorithm")+`
				)`)
			case "high":
				severityConditions = append(severityConditions, `(
					UPPER(ci.protocol_version) LIKE '%TLS%1.1%'
					OR UPPER(ci.protocol_version) LIKE '%TLS%1%1%'
					OR (ci.protocol_version IS NOT NULL AND (
						ci.protocol_version = '1.1'
						OR ci.protocol_version LIKE '1.1%'
						OR ci.protocol_version LIKE '%1.1'
					))
					OR `+tripleDESSQL("ci.cipher_suite")+`
					OR UPPER(ci.hash_algorithm) LIKE '%SHA1%'
					OR UPPER(ci.hash_algorithm) LIKE '%SHA-1%'
					OR `+highRiskKeySizeSQL("ci.key_size", "ci.key_exchange_algorithm")+`
				)`)
			case "medium":
				// Medium: expiring certificates (within 30 days)
				severityConditions = append(severityConditions, `(
					EXISTS (
						SELECT 1 FROM crypto_implementation_certificates cic
						JOIN certificates c ON cic.certificate_id = c.id
						WHERE cic.crypto_implementation_id = ci.id
						  AND c.not_after IS NOT NULL
						  AND c.not_after BETWEEN NOW() AND NOW() + INTERVAL '30 days'
					)
				)`)
			case "informational":
				// Informational: any other risks not classified as critical/high/medium
				// This will be handled by classifyRisk function
				severityConditions = append(severityConditions, `(
					ci.risk_score IS NOT NULL AND ci.risk_score > 0
					AND NOT (
						UPPER(ci.protocol_version) IN ('SSLV2', 'SSLV3', 'SSL2', 'SSL3')
						OR UPPER(ci.protocol_version) LIKE '%TLS%1.0%'
						OR UPPER(ci.protocol_version) LIKE '%TLS%1%0%'
						OR UPPER(ci.protocol_version) LIKE '%TLS%1.1%'
						OR UPPER(ci.protocol_version) LIKE '%TLS%1%1%'
						OR (ci.protocol_version IS NOT NULL AND (
							ci.protocol_version = '1.0'
							OR ci.protocol_version = '1.1'
							OR ci.protocol_version LIKE '1.0%'
							OR ci.protocol_version LIKE '1.1%'
							OR ci.protocol_version LIKE '%1.0'
							OR ci.protocol_version LIKE '%1.1'
						))
						OR UPPER(ci.cipher_suite) LIKE '%RC4%'
						OR UPPER(ci.cipher_suite) LIKE '%DES%'
						OR UPPER(ci.cipher_suite) LIKE '%NULL%'
						OR UPPER(ci.cipher_suite) LIKE '%EXPORT%'
						OR UPPER(ci.hash_algorithm) LIKE '%MD5%'
						OR UPPER(ci.hash_algorithm) LIKE '%MD4%'
						OR UPPER(ci.hash_algorithm) LIKE '%SHA1%'
						OR UPPER(ci.hash_algorithm) LIKE '%SHA-1%'
						OR `+anyWeakKeySizeSQL("ci.key_size", "ci.key_exchange_algorithm")+`
						OR EXISTS (
							SELECT 1 FROM crypto_implementation_certificates cic
							JOIN certificates c ON cic.certificate_id = c.id
							WHERE cic.crypto_implementation_id = ci.id
							  AND c.not_after IS NOT NULL
							  AND c.not_after BETWEEN NOW() AND NOW() + INTERVAL '30 days'
						)
					)
				)`)
			}
		}
		if len(severityConditions) > 0 {
			riskConditions = append(riskConditions, "("+strings.Join(severityConditions, " OR ")+")")
		}
	} else {
		// Default: show all risks (critical, high, medium, informational)
		// Return all crypto implementations that match ANY risk pattern
		// Don't require risk_score > 0 as many risks may not have score set yet
		riskConditions = append(riskConditions, `(
			UPPER(ci.protocol_version) IN ('SSLV2', 'SSLV3', 'SSL2', 'SSL3')
			OR UPPER(ci.protocol_version) LIKE '%TLS%1.0%'
			OR UPPER(ci.protocol_version) LIKE '%TLS%1%0%'
			OR UPPER(ci.protocol_version) LIKE '%TLS%1.1%'
			OR UPPER(ci.protocol_version) LIKE '%TLS%1%1%'
			OR (ci.protocol_version IS NOT NULL AND (
				ci.protocol_version = '1.0'
				OR ci.protocol_version = '1.1'
				OR ci.protocol_version LIKE '1.0%'
				OR ci.protocol_version LIKE '1.1%'
				OR ci.protocol_version LIKE '%1.0'
				OR ci.protocol_version LIKE '%1.1'
			))
			OR UPPER(ci.cipher_suite) LIKE '%RC4%'
			OR UPPER(ci.cipher_suite) LIKE '%DES%'
			OR UPPER(ci.cipher_suite) LIKE '%NULL%'
			OR UPPER(ci.cipher_suite) LIKE '%EXPORT%'
			OR UPPER(ci.hash_algorithm) LIKE '%MD5%'
			OR UPPER(ci.hash_algorithm) LIKE '%MD4%'
			OR UPPER(ci.hash_algorithm) LIKE '%SHA1%'
			OR UPPER(ci.hash_algorithm) LIKE '%SHA-1%'
			OR `+anyWeakKeySizeSQL("ci.key_size", "ci.key_exchange_algorithm")+`
			OR EXISTS (
				SELECT 1 FROM crypto_implementation_certificates cic
				JOIN certificates c ON cic.certificate_id = c.id
				WHERE cic.crypto_implementation_id = ci.id
				  AND c.not_after IS NOT NULL
				  AND c.not_after BETWEEN NOW() AND NOW() + INTERVAL '90 days'
			)
			OR (ci.risk_score IS NOT NULL AND ci.risk_score > 0)
		)`)
	}

	// Category filter
	if len(filters.Category) > 0 {
		categoryConditions := []string{}
		for _, cat := range filters.Category {
			switch strings.ToLower(cat) {
			case "protocol":
				categoryConditions = append(categoryConditions, `(
					UPPER(ci.protocol_version) IN ('SSLV2', 'SSLV3', 'SSL2', 'SSL3')
					OR UPPER(ci.protocol_version) LIKE '%TLS%1.0%'
					OR UPPER(ci.protocol_version) LIKE '%TLS%1%0%'
					OR UPPER(ci.protocol_version) LIKE '%TLS%1.1%'
					OR UPPER(ci.protocol_version) LIKE '%TLS%1%1%'
					OR (ci.protocol_version IS NOT NULL AND (
						ci.protocol_version = '1.0'
						OR ci.protocol_version = '1.1'
						OR ci.protocol_version LIKE '1.0%'
						OR ci.protocol_version LIKE '1.1%'
						OR ci.protocol_version LIKE '%1.0'
						OR ci.protocol_version LIKE '%1.1'
					))
				)`)
			case "algorithm":
				categoryConditions = append(categoryConditions, `(
					UPPER(ci.cipher_suite) LIKE '%RC4%'
					OR UPPER(ci.cipher_suite) LIKE '%DES%'
					OR UPPER(ci.cipher_suite) LIKE '%NULL%'
					OR UPPER(ci.cipher_suite) LIKE '%EXPORT%'
					OR UPPER(ci.hash_algorithm) LIKE '%MD5%'
					OR UPPER(ci.hash_algorithm) LIKE '%SHA1%'
				)`)
			case "key_size":
				categoryConditions = append(categoryConditions,
					anyWeakKeySizeSQL("ci.key_size", "ci.key_exchange_algorithm"))
			}
		}
		if len(categoryConditions) > 0 {
			conditions = append(conditions, "("+strings.Join(categoryConditions, " OR ")+")")
		}
	}

	if len(riskConditions) > 0 {
		conditions = append(conditions, "("+strings.Join(riskConditions, " OR ")+")")
	}

	// Search filter
	if filters.Search != "" {
		conditions = append(conditions, fmt.Sprintf(`(
			na.hostname ILIKE $%d
			OR na.ip_address ILIKE $%d
			OR ci.protocol ILIKE $%d
			OR ci.cipher_suite ILIKE $%d
		)`, argPos, argPos, argPos, argPos))
		args = append(args, "%"+filters.Search+"%")
		argPos++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "AND " + strings.Join(conditions, " AND ")
	}

	// Count total
	// Use same structure as main query to ensure consistent counting
	countQuery := fmt.Sprintf(`
		SELECT COUNT(DISTINCT ci.id)
		FROM crypto_implementations ci
		JOIN network_assets na ON ci.asset_id = na.id AND na.deleted_at IS NULL
		LEFT JOIN crypto_implementation_certificates cic ON cic.crypto_implementation_id = ci.id
		LEFT JOIN certificates c ON cic.certificate_id = c.id
		WHERE ci.tenant_id = $1
		  AND ci.deleted_at IS NULL
		  %s
	`, whereClause)

	var total int

	// Build sort clause
	sortClause := "ORDER BY ci.risk_score DESC NULLS LAST, ci.created_at DESC"
	if filters.SortBy != "" {
		validSorts := map[string]string{
			"severity":    "ci.risk_score",
			"detected_at": "ci.created_at",
			"hostname":    "na.hostname",
			"protocol":    "ci.protocol",
		}
		if col, ok := validSorts[filters.SortBy]; ok {
			order := "ASC"
			if strings.ToUpper(filters.SortOrder) == "DESC" {
				order = "DESC"
			}
			sortClause = fmt.Sprintf("ORDER BY %s %s NULLS LAST", col, order)
		}
	}

	// Fetch risks
	// Include certificate expiration info for medium risk classification
	query := fmt.Sprintf(`
		SELECT ci.id, ci.tenant_id, ci.asset_id, ci.id as crypto_implementation_id,
		       ci.protocol, ci.protocol_version, ci.cipher_suite, ci.hash_algorithm,
		       ci.key_exchange_algorithm, ci.key_size,
		       ci.risk_score, ci.created_at,
		       na.hostname, na.ip_address, na.port, na.asset_type,
		       MIN(c.not_after) as earliest_cert_expiry
		FROM crypto_implementations ci
		JOIN network_assets na ON ci.asset_id = na.id AND na.deleted_at IS NULL
		LEFT JOIN crypto_implementation_certificates cic ON cic.crypto_implementation_id = ci.id
		LEFT JOIN certificates c ON cic.certificate_id = c.id
		WHERE ci.tenant_id = $1
		  AND ci.deleted_at IS NULL
		  %s
		GROUP BY ci.id, ci.tenant_id, ci.asset_id, ci.protocol, ci.protocol_version,
		         ci.cipher_suite, ci.hash_algorithm, ci.key_exchange_algorithm, ci.key_size, ci.risk_score,
		         ci.created_at, na.hostname, na.ip_address, na.port, na.asset_type
		%s
		LIMIT $%d OFFSET $%d
	`, whereClause, sortClause, argPos, argPos+1)

	countArgs := append([]interface{}{}, args...)
	args = append(args, filters.PageSize, offset)

	// RLS-scoped reads over crypto_implementations / certificates (JOIN network_assets)
	// — count + page run in one tenant tx so app.tenant_id is set for both.
	risks := []CryptoRisk{}
	txErr := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		if e := tx.Get(&total, countQuery, countArgs...); e != nil {
			return fmt.Errorf("failed to count risks: %w", e)
		}

		rows, err := tx.Queryx(query, args...)
		if err != nil {
			return fmt.Errorf("failed to query risks: %w", err)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var row struct {
				ID                     uuid.UUID  `db:"id"`
				TenantID               uuid.UUID  `db:"tenant_id"`
				AssetID                uuid.UUID  `db:"asset_id"`
				CryptoImplementationID uuid.UUID  `db:"crypto_implementation_id"`
				Protocol               string     `db:"protocol"`
				ProtocolVersion        *string    `db:"protocol_version"`
				CipherSuite            *string    `db:"cipher_suite"`
				HashAlgorithm          *string    `db:"hash_algorithm"`
				KeyExchangeAlgorithm   *string    `db:"key_exchange_algorithm"`
				KeySize                *int       `db:"key_size"`
				RiskScore              *int       `db:"risk_score"`
				CreatedAt              time.Time  `db:"created_at"`
				Hostname               *string    `db:"hostname"`
				IPAddress              *string    `db:"ip_address"`
				Port                   *int       `db:"port"`
				AssetType              string     `db:"asset_type"`
				EarliestCertExpiry     *time.Time `db:"earliest_cert_expiry"`
			}

			if err := rows.StructScan(&row); err != nil {
				return fmt.Errorf("failed to scan risk row: %w", err)
			}

			// Determine severity and category based on values
			risk := CryptoRisk{
				ID:                     row.ID,
				TenantID:               row.TenantID,
				AssetID:                row.AssetID,
				CryptoImplementationID: row.CryptoImplementationID,
				Protocol:               row.Protocol,
				ProtocolVersion:        row.ProtocolVersion,
				CipherSuite:            row.CipherSuite,
				DetectedAt:             row.CreatedAt,
				AssetHostname:          row.Hostname,
				AssetIPAddress:         row.IPAddress,
				AssetPort:              row.Port,
				AssetType:              row.AssetType,
			}

			// Classify the risk (include certificate expiration for medium risk detection)
			s.classifyRisk(&risk, row.ProtocolVersion, row.CipherSuite, row.HashAlgorithm, row.KeyExchangeAlgorithm, row.KeySize, row.EarliestCertExpiry)

			risks = append(risks, risk)
		}
		return rows.Err()
	})
	if txErr != nil {
		return nil, txErr
	}

	totalPages := (total + filters.PageSize - 1) / filters.PageSize

	return &CryptoRisksResponse{
		Risks:      risks,
		Total:      total,
		Page:       filters.Page,
		PageSize:   filters.PageSize,
		TotalPages: totalPages,
	}, nil
}

// classifyRisk determines severity, category, and description for a risk
func (s *CryptoRisksService) classifyRisk(risk *CryptoRisk, protocolVersion, cipherSuite, hashAlgorithm, keyExchange *string, keySize *int, certExpiry *time.Time) {
	// Check for critical protocol issues
	// Handle various protocol version formats: '1.0', 'TLSv1.0', 'TLSV1.0', 'TLS 1.0', 'TLS1.0'
	if protocolVersion != nil {
		pv := strings.ToUpper(*protocolVersion)
		// Check for SSL or TLS 1.0 (various formats)
		if strings.Contains(pv, "SSL") ||
			strings.Contains(pv, "TLS1.0") ||
			strings.Contains(pv, "TLSV1.0") ||
			strings.Contains(pv, "TLS 1.0") ||
			strings.Contains(pv, "TLSV1") && strings.Contains(pv, "0") ||
			*protocolVersion == "1.0" ||
			strings.HasPrefix(*protocolVersion, "1.0") ||
			strings.HasSuffix(*protocolVersion, "1.0") {
			risk.Severity = "critical"
			risk.Category = "protocol"
			risk.IssueType = "weak_protocol"
			risk.CurrentValue = *protocolVersion
			risk.Description = "Using a critically vulnerable protocol version"
			risk.Recommendation = "Upgrade to TLS 1.2 or TLS 1.3 immediately"
			return
		}
		// TLS 1.1 only — do not use a broad "TLSV1" + "1" heuristic: TLSv1.2 / TLSv1.3
		// also contain TLSV1 and a digit "1" but no "0", which wrongly matched here before.
		if strings.Contains(pv, "TLSV1.1") ||
			strings.Contains(pv, "TLS1.1") ||
			strings.Contains(pv, "TLS 1.1") ||
			strings.Contains(pv, "TLS_1_1") ||
			*protocolVersion == "1.1" ||
			strings.HasPrefix(*protocolVersion, "1.1") ||
			strings.HasSuffix(*protocolVersion, "1.1") {
			risk.Severity = "high"
			risk.Category = "protocol"
			risk.IssueType = "deprecated_protocol"
			risk.CurrentValue = *protocolVersion
			risk.Description = "Using a deprecated protocol version"
			risk.Recommendation = "Upgrade to TLS 1.2 or TLS 1.3"
			return
		}
	}

	// Check for critical algorithm issues
	if cipherSuite != nil {
		cs := strings.ToUpper(*cipherSuite)
		if strings.Contains(cs, "RC4") || strings.Contains(cs, "NULL") || strings.Contains(cs, "EXPORT") {
			risk.Severity = "critical"
			risk.Category = "algorithm"
			risk.IssueType = "weak_cipher"
			risk.CurrentValue = *cipherSuite
			risk.Description = "Using a weak or broken cipher algorithm"
			risk.Recommendation = "Use AES-GCM or ChaCha20-Poly1305 cipher suites"
			return
		}
		if isSingleDES(cs) {
			risk.Severity = "critical"
			risk.Category = "algorithm"
			risk.IssueType = "weak_cipher"
			risk.CurrentValue = *cipherSuite
			risk.Description = "Using the deprecated DES cipher"
			risk.Recommendation = "Use AES-GCM or ChaCha20-Poly1305 cipher suites"
			return
		}
		if strings.Contains(cs, "3DES") || strings.Contains(cs, "CBC3") || strings.Contains(cs, "DES_EDE") {
			risk.Severity = "high"
			risk.Category = "algorithm"
			risk.IssueType = "deprecated_cipher"
			risk.CurrentValue = *cipherSuite
			risk.Description = "Using the deprecated 3DES cipher"
			risk.Recommendation = "Use AES-GCM or ChaCha20-Poly1305 cipher suites"
			return
		}
	}

	// Check for hash algorithm issues
	if hashAlgorithm != nil {
		ha := strings.ToUpper(*hashAlgorithm)
		if strings.Contains(ha, "MD5") || strings.Contains(ha, "MD4") {
			risk.Severity = "critical"
			risk.Category = "algorithm"
			risk.IssueType = "weak_hash"
			risk.CurrentValue = *hashAlgorithm
			risk.Description = "Using a cryptographically broken hash algorithm"
			risk.Recommendation = "Use SHA-256 or SHA-384 for hashing"
			return
		}
		if strings.Contains(ha, "SHA1") || strings.Contains(ha, "SHA-1") {
			risk.Severity = "high"
			risk.Category = "algorithm"
			risk.IssueType = "deprecated_hash"
			risk.CurrentValue = *hashAlgorithm
			risk.Description = "Using a deprecated hash algorithm (SHA-1)"
			risk.Recommendation = "Use SHA-256 or SHA-384 for hashing"
			return
		}
	}

	// Check for key size issues.
	//
	// A bit-length floor only means something for the algorithm family it was
	// derived for. This branch used to flag ANY key below 2048 bits as a weak
	// RSA key, so every P-256 / X25519 / Ed25519 endpoint — a 256-bit key, and a
	// healthy one — was reported as "RSA key size is critically weak", the
	// modern configurations the product should be rewarding. keyExchangeFamily
	// (weak_crypto_detector.go) is the single classifier for this; it is reused
	// here rather than re-derived so the two cannot drift.
	if keySize != nil && *keySize > 0 {
		switch keyExchangeFamily(keyExchange) {
		case kexFamilyEllipticCurve:
			if *keySize < minECCKeySizeBits {
				risk.Severity = "high"
				risk.Category = "key_size"
				risk.IssueType = "weak_key_size"
				risk.CurrentValue = fmt.Sprintf("%d bits", *keySize)
				risk.Description = "ECC key size is below recommended minimum (256 bits)"
				risk.Recommendation = "Use at least 256-bit ECC keys"
				return
			}
		case kexFamilyFiniteField:
			if *keySize < 1024 {
				risk.Severity = "critical"
				risk.Category = "key_size"
				risk.IssueType = "critically_weak_key_size"
				risk.CurrentValue = fmt.Sprintf("%d bits", *keySize)
				risk.Description = "RSA key size is critically weak (below 1024 bits)"
				risk.Recommendation = "Use at least 2048-bit RSA keys"
				return
			}
			if *keySize < minRSAKeySizeBits {
				risk.Severity = "high"
				risk.Category = "key_size"
				risk.IssueType = "weak_key_size"
				risk.CurrentValue = fmt.Sprintf("%d bits", *keySize)
				risk.Description = "RSA key size is below recommended minimum (2048 bits)"
				risk.Recommendation = "Use at least 2048-bit RSA keys, preferably 3072 or 4096 bits"
				return
			}
		case kexFamilyUnknown, kexFamilyPostQuantum:
			// Unknown: a bare 256 could be an EC key (healthy) or an RSA modulus
			// (catastrophic), and guessing wrong in either direction is worse
			// than staying quiet. Post-quantum key sizes are not comparable to
			// either floor.
		}
	}

	// Check for medium risks: expiring certificates (within 30 days)
	if certExpiry != nil {
		daysUntilExpiry := int(time.Until(*certExpiry).Hours() / 24)
		if daysUntilExpiry > 0 && daysUntilExpiry <= 30 {
			risk.Severity = "medium"
			risk.Category = "certificate"
			risk.IssueType = "expiring_certificate"
			risk.CurrentValue = fmt.Sprintf("Expires in %d days", daysUntilExpiry)
			risk.Description = fmt.Sprintf("Certificate expiring within %d days", daysUntilExpiry)
			risk.Recommendation = "Renew certificate before expiration to avoid service disruption"
			return
		}
	}

	// Default classification
	risk.Severity = "informational"
	risk.Category = "unknown"
	risk.IssueType = "other"
	risk.Description = "Crypto implementation flagged for review"
	risk.Recommendation = "Review and verify cryptographic configuration"
}

// GetRiskByID returns a specific crypto risk by ID
func (s *CryptoRisksService) GetRiskByID(tenantID, riskID uuid.UUID) (*CryptoRisk, error) {
	query := `
		SELECT ci.id, ci.tenant_id, ci.asset_id, ci.id as crypto_implementation_id,
		       ci.protocol, ci.protocol_version, ci.cipher_suite, ci.hash_algorithm,
		       ci.key_exchange_algorithm, ci.key_size,
		       ci.risk_score, ci.created_at,
		       na.hostname, na.ip_address, na.port, na.asset_type,
		       MIN(c.not_after) as earliest_cert_expiry
		FROM crypto_implementations ci
		JOIN network_assets na ON ci.asset_id = na.id AND na.deleted_at IS NULL
		LEFT JOIN crypto_implementation_certificates cic ON cic.crypto_implementation_id = ci.id
		LEFT JOIN certificates c ON cic.certificate_id = c.id
		WHERE ci.tenant_id = $1
		  AND ci.id = $2
		  AND ci.deleted_at IS NULL
		GROUP BY ci.id, ci.tenant_id, ci.asset_id, ci.protocol, ci.protocol_version,
		         ci.cipher_suite, ci.hash_algorithm, ci.key_exchange_algorithm, ci.key_size, ci.risk_score,
		         ci.created_at, na.hostname, na.ip_address, na.port, na.asset_type
	`

	var row struct {
		ID                     uuid.UUID  `db:"id"`
		TenantID               uuid.UUID  `db:"tenant_id"`
		AssetID                uuid.UUID  `db:"asset_id"`
		CryptoImplementationID uuid.UUID  `db:"crypto_implementation_id"`
		Protocol               string     `db:"protocol"`
		ProtocolVersion        *string    `db:"protocol_version"`
		CipherSuite            *string    `db:"cipher_suite"`
		HashAlgorithm          *string    `db:"hash_algorithm"`
		KeyExchangeAlgorithm   *string    `db:"key_exchange_algorithm"`
		KeySize                *int       `db:"key_size"`
		RiskScore              *int       `db:"risk_score"`
		CreatedAt              time.Time  `db:"created_at"`
		Hostname               *string    `db:"hostname"`
		IPAddress              *string    `db:"ip_address"`
		Port                   *int       `db:"port"`
		AssetType              string     `db:"asset_type"`
		EarliestCertExpiry     *time.Time `db:"earliest_cert_expiry"`
	}

	// RLS-scoped read over crypto_implementations / certificates (JOIN network_assets).
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.Get(&row, query, tenantID, riskID)
	}); err != nil {
		return nil, fmt.Errorf("failed to get risk: %w", err)
	}

	risk := &CryptoRisk{
		ID:                     row.ID,
		TenantID:               row.TenantID,
		AssetID:                row.AssetID,
		CryptoImplementationID: row.CryptoImplementationID,
		Protocol:               row.Protocol,
		ProtocolVersion:        row.ProtocolVersion,
		CipherSuite:            row.CipherSuite,
		DetectedAt:             row.CreatedAt,
		AssetHostname:          row.Hostname,
		AssetIPAddress:         row.IPAddress,
		AssetPort:              row.Port,
		AssetType:              row.AssetType,
	}

	s.classifyRisk(risk, row.ProtocolVersion, row.CipherSuite, row.HashAlgorithm, row.KeyExchangeAlgorithm, row.KeySize, row.EarliestCertExpiry)

	return risk, nil
}
