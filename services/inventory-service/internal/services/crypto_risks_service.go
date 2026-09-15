package services

// A crypto risk is measured on an ENDPOINT, and the row says so.
//
// `ci.endpoint_id` names the exact socket a configuration was observed on, so
// the address and port a risk row carries are that endpoint's, never the host's
// primary address COALESCEd in. The JSON field names stay `asset_ip_address` /
// `asset_port` for the consumers that already read them, with `endpoint_id` and
// `endpoint_address` alongside: an asset with two TLS endpoints has two rows
// here and they are different sockets, which the old flattening could not say.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
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
	AssetHostname *string `json:"asset_hostname,omitempty" db:"hostname"`
	// AssetIPAddress is the ASSET's primary address — the one to show when
	// there is room for one. It is NOT the endpoint's; the two differ on a
	// multi-homed host, and COALESCEing one onto the other (which this row used
	// to do) reported an address nobody measured this configuration on.
	AssetIPAddress *string `json:"asset_ip_address,omitempty" db:"ip_address"`
	// EndpointID, EndpointAddress and EndpointPort are the socket the
	// configuration was actually measured on. All three are nil for a
	// configuration with no endpoint — an at-rest resource, which is a real
	// answer and is what retired the "AT-REST" port sentinel.
	EndpointID      *uuid.UUID `json:"endpoint_id,omitempty" db:"endpoint_id"`
	EndpointAddress *string    `json:"endpoint_address,omitempty" db:"endpoint_address"`
	EndpointPort    *int       `json:"endpoint_port,omitempty" db:"endpoint_port"`
	// AssetPort is EndpointPort under its pre-endpoint name, kept for consumers
	// that already read it.
	AssetPort *int `json:"asset_port,omitempty" db:"port"`
	// AssetClassKey is the owning asset's class (ADR-0002 D2). Renamed with
	// the value: an asset the old enum called "appliance" is now `hardware`,
	// `switch` or `firewall`.
	AssetClassKey string `json:"asset_class_key,omitempty" db:"class_key"`
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

// GetSummary returns aggregated crypto risk statistics for a tenant.
//
// # Roll up per asset first, then band once
//
// The four severity counters count ASSETS, and every asset lands in exactly
// one. Each was previously its own `COUNT(DISTINCT ci.asset_id)` with the band
// decided per CONFIGURATION, so a host with one TLS 1.0 endpoint and one TLS
// 1.1 endpoint was counted in Critical and in High — the buckets overlapped,
// summed past the number of affected assets, and made the distribution bar
// exceed 100%. That is the bug CLAUDE.md names: band per implementation, count
// distinct assets, and one asset appears in several buckets.
//
// The fix is the rule stated there: take the WORST severity per asset, then
// band that once. `cryptoSeverityCaseSQL` ranks a configuration 4..1 so the
// rollup is a plain MAX, and the four counters are `FILTER`s over the ranked
// per-asset row.
//
// The issue counters below (protocol / algorithm / certificate / key size) are
// deliberately a different unit — they count CONFIGURATIONS, because "how many
// weak protocol configurations" is the question they answer — and they are
// labelled as such in the response.
//
// A dead `LEFT JOIN asset_endpoints e` sat in eight of these queries after the
// endpoint split, joined and then never referenced. It is gone: a join nothing
// reads is a cost with no meaning, and it invited the reader to think the
// counter was per endpoint.
func (s *CryptoRisksService) GetSummary(tenantID uuid.UUID) (*CryptoRisksSummary, error) {
	summary := &CryptoRisksSummary{}

	// RLS-scoped reads over crypto_implementations / certificates (JOIN assets)
	// — all aggregate counts run in one tenant tx so app.tenant_id is set throughout.
	txErr := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		// One pass: rank every live configuration, keep the worst per asset,
		// then count assets per band. Five numbers from one statement, which is
		// also what makes them consistent with each other.
		bandQuery := `
		WITH ranked AS (
			SELECT ci.asset_id, ` + cryptoSeverityCaseSQL() + ` AS severity
			FROM crypto_implementations ci
			JOIN assets na ON na.tenant_id = ci.tenant_id AND na.id = ci.asset_id
			                  AND na.deleted_at IS NULL
			WHERE ci.tenant_id = $1 AND ci.deleted_at IS NULL
		),
		per_asset AS (
			SELECT asset_id, MAX(severity) AS severity
			FROM ranked
			GROUP BY asset_id
		)
		SELECT
			COUNT(*) FILTER (WHERE severity = 4) AS critical,
			COUNT(*) FILTER (WHERE severity = 3) AS high,
			COUNT(*) FILTER (WHERE severity = 2) AS medium,
			COUNT(*) FILTER (WHERE severity = 1) AS informational,
			COUNT(*) FILTER (WHERE severity > 0) AS total_affected
		FROM per_asset
	`
		if err := tx.QueryRow(bandQuery, tenantID).Scan(
			&summary.Critical, &summary.High, &summary.Medium,
			&summary.Informational, &summary.TotalAffected,
		); err != nil {
			return fmt.Errorf("failed to count risk bands: %w", err)
		}

		// The issue counters: configurations, not assets.
		issueQuery := `
		SELECT
			COUNT(*) FILTER (WHERE
				UPPER(COALESCE(ci.protocol_version, '')) IN ('SSLV2', 'SSLV3', 'SSL2', 'SSL3')
				OR UPPER(COALESCE(ci.protocol_version, '')) LIKE '%TLS%1.0%'
				OR UPPER(COALESCE(ci.protocol_version, '')) LIKE '%TLS%1%0%'
				OR UPPER(COALESCE(ci.protocol_version, '')) LIKE '%TLS%1.1%'
				OR UPPER(COALESCE(ci.protocol_version, '')) LIKE '%TLS%1%1%'
				OR COALESCE(ci.protocol_version, '') IN ('1.0', '1.1')
				OR COALESCE(ci.protocol_version, '') LIKE '1.0%'
				OR COALESCE(ci.protocol_version, '') LIKE '1.1%'
				OR COALESCE(ci.protocol_version, '') LIKE '%1.0'
				OR COALESCE(ci.protocol_version, '') LIKE '%1.1'
			) AS protocol_issues,
			COUNT(*) FILTER (WHERE
				UPPER(COALESCE(ci.cipher_suite, '')) LIKE '%RC4%'
				OR UPPER(COALESCE(ci.cipher_suite, '')) LIKE '%DES%'
				OR UPPER(COALESCE(ci.cipher_suite, '')) LIKE '%NULL%'
				OR UPPER(COALESCE(ci.cipher_suite, '')) LIKE '%EXPORT%'
				OR UPPER(COALESCE(ci.hash_algorithm, '')) LIKE '%MD5%'
				OR UPPER(COALESCE(ci.hash_algorithm, '')) LIKE '%SHA1%'
				OR UPPER(COALESCE(ci.hash_algorithm, '')) LIKE '%SHA-1%'
			) AS algorithm_issues,
			COUNT(*) FILTER (WHERE ` + anyWeakKeySizeSQL("ci.key_size", "ci.key_exchange_algorithm") + `) AS key_size_issues
		FROM crypto_implementations ci
		JOIN assets na ON na.tenant_id = ci.tenant_id AND na.id = ci.asset_id
		                  AND na.deleted_at IS NULL
		WHERE ci.tenant_id = $1 AND ci.deleted_at IS NULL
	`
		if err := tx.QueryRow(issueQuery, tenantID).Scan(
			&summary.ProtocolIssues, &summary.AlgorithmIssues, &summary.KeySizeIssues,
		); err != nil {
			return fmt.Errorf("failed to count issues: %w", err)
		}

		// Certificate issues (expiring within 90 days or weak key).
		//
		// The weak-key half used to be a bare `public_key_size < 2048`, which is
		// the RSA/finite-field floor applied to every family: a healthy 256-bit
		// EC certificate counted as an issue here while the `crypto` finding
		// producer (shared/cryptoparse.WeakKeySizeSeverity) raised nothing for
		// it — two opinions about the same certificate. anyWeakKeySizeSQL is the
		// SQL twin of that same classifier, family-aware via public_key_algorithm
		// ("RSA" / "ECDSA" / "Ed25519", as Go's x509 PublicKeyAlgorithm.String()
		// spells them).
		certQuery := `
		SELECT COUNT(*)
		FROM certificates c
		WHERE c.tenant_id = $1
		  AND (
			(c.not_after IS NOT NULL AND c.not_after BETWEEN NOW() AND NOW() + INTERVAL '90 days')
			OR ` + anyWeakKeySizeSQL("c.public_key_size", "c.public_key_algorithm") + `
		  )
	`
		if err := tx.Get(&summary.CertificateIssues, certQuery, tenantID); err != nil {
			return fmt.Errorf("failed to count certificate issues: %w", err)
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
				severityConditions = append(severityConditions, cryptoCriticalSQL())
			case "high":
				severityConditions = append(severityConditions, cryptoHighSQL())
			case "medium":
				// Medium: expiring certificates (within 30 days)
				severityConditions = append(severityConditions, cryptoMediumSQL())
			case "informational":
				// Informational: scored, but matching none of the three named
				// bands. Defined as the negation of the others so the four bands
				// partition the scored configurations.
				severityConditions = append(severityConditions, cryptoInformationalSQL())
			}
		}
		if len(severityConditions) > 0 {
			riskConditions = append(riskConditions, "("+strings.Join(severityConditions, " OR ")+")")
		}
	} else {
		// Default: show all risks (critical, high, medium, informational)
		// Return all crypto implementations that match ANY risk pattern
		// Don't require risk_score > 0 as many risks may not have score set yet
		riskConditions = append(riskConditions, cryptoAnyRiskSQL())
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
		// host(...) is INET and ci.protocol is the protocol_type ENUM; neither has
		// an ILIKE (~~*) operator, so both need an explicit ::text cast or the
		// statement fails at plan time. Same defect/fix as the Configuration-lens
		// search in crypto_implementation_service.go.
		//
		// Both addresses are searched, rather than a COALESCE of them: typing the
		// endpoint's address should find the row, and so should typing the host's.
		// COALESCE searched only whichever one happened to be non-NULL.
		conditions = append(conditions, fmt.Sprintf(`(
			na.hostname ILIKE $%d
			OR host(na.primary_address)::text ILIKE $%d
			OR host(e.address)::text ILIKE $%d
			OR ci.protocol::text ILIKE $%d
			OR ci.cipher_suite ILIKE $%d
		)`, argPos, argPos, argPos, argPos, argPos))
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
		JOIN assets na ON na.tenant_id = ci.tenant_id AND na.id = ci.asset_id AND na.deleted_at IS NULL
		LEFT JOIN asset_endpoints e ON e.tenant_id = ci.tenant_id AND e.id = ci.endpoint_id
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
		       na.hostname, host(na.primary_address) AS ip_address,
		       e.id AS endpoint_id, host(e.address) AS endpoint_address, e.port, na.class_key AS asset_type,
		       MIN(c.not_after) as earliest_cert_expiry
		FROM crypto_implementations ci
		JOIN assets na ON na.tenant_id = ci.tenant_id AND na.id = ci.asset_id AND na.deleted_at IS NULL
		LEFT JOIN asset_endpoints e ON e.tenant_id = ci.tenant_id AND e.id = ci.endpoint_id
		LEFT JOIN crypto_implementation_certificates cic ON cic.crypto_implementation_id = ci.id
		LEFT JOIN certificates c ON cic.certificate_id = c.id
		WHERE ci.tenant_id = $1
		  AND ci.deleted_at IS NULL
		  %s
		GROUP BY ci.id, ci.tenant_id, ci.asset_id, ci.protocol, ci.protocol_version,
		         ci.cipher_suite, ci.hash_algorithm, ci.key_exchange_algorithm, ci.key_size, ci.risk_score,
		         ci.created_at, na.hostname, na.primary_address, e.id, e.address, e.port, na.class_key
		%s
		LIMIT $%d OFFSET $%d
	`, whereClause, sortClause, argPos, argPos+1)

	countArgs := append([]interface{}{}, args...)
	args = append(args, filters.PageSize, offset)

	// RLS-scoped reads over crypto_implementations / certificates (JOIN assets)
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
				EndpointID             *uuid.UUID `db:"endpoint_id"`
				EndpointAddress        *string    `db:"endpoint_address"`
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
				EndpointID:             row.EndpointID,
				EndpointAddress:        row.EndpointAddress,
				EndpointPort:           row.Port,
				AssetPort:              row.Port,
				AssetClassKey:          row.AssetType,
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
			if *keySize < cryptoparse.MinECCKeySizeBits {
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
			if *keySize < cryptoparse.MinRSAKeySizeBits {
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
		       na.hostname, host(na.primary_address) AS ip_address,
		       e.id AS endpoint_id, host(e.address) AS endpoint_address, e.port, na.class_key AS asset_type,
		       MIN(c.not_after) as earliest_cert_expiry
		FROM crypto_implementations ci
		JOIN assets na ON na.tenant_id = ci.tenant_id AND na.id = ci.asset_id AND na.deleted_at IS NULL
		LEFT JOIN asset_endpoints e ON e.tenant_id = ci.tenant_id AND e.id = ci.endpoint_id
		LEFT JOIN crypto_implementation_certificates cic ON cic.crypto_implementation_id = ci.id
		LEFT JOIN certificates c ON cic.certificate_id = c.id
		WHERE ci.tenant_id = $1
		  AND ci.id = $2
		  AND ci.deleted_at IS NULL
		GROUP BY ci.id, ci.tenant_id, ci.asset_id, ci.protocol, ci.protocol_version,
		         ci.cipher_suite, ci.hash_algorithm, ci.key_exchange_algorithm, ci.key_size, ci.risk_score,
		         ci.created_at, na.hostname, na.primary_address, e.id, e.address, e.port, na.class_key
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
		EndpointID             *uuid.UUID `db:"endpoint_id"`
		EndpointAddress        *string    `db:"endpoint_address"`
		Port                   *int       `db:"port"`
		AssetType              string     `db:"asset_type"`
		EarliestCertExpiry     *time.Time `db:"earliest_cert_expiry"`
	}

	// RLS-scoped read over crypto_implementations / certificates (JOIN assets).
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
		EndpointID:             row.EndpointID,
		EndpointAddress:        row.EndpointAddress,
		EndpointPort:           row.Port,
		AssetPort:              row.Port,
		AssetClassKey:          row.AssetType,
	}

	s.classifyRisk(risk, row.ProtocolVersion, row.CipherSuite, row.HashAlgorithm, row.KeyExchangeAlgorithm, row.KeySize, row.EarliestCertExpiry)

	return risk, nil
}
