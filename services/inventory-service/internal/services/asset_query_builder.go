// Package services: asset list query builder (WHERE/HAVING from filters).
package services

import (
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// SearchTerm represents a parsed search term (field, value, exact, operator).
type SearchTerm struct {
	Field    string // empty for general search, or specific field like "hostname", "ip", etc.
	Value    string
	Exact    bool   // true if wrapped in quotes
	Operator string // "AND" or "OR" - only used when multiple terms
}

// parseSearchQuery parses a search query string into structured search terms.
// Supports exact phrases, field-specific (hostname:, ip:, etc.), and AND/OR.
func parseSearchQuery(query string) []SearchTerm {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil
	}
	var terms []SearchTerm
	var currentTerm strings.Builder
	var inQuotes bool
	var currentField string
	var operator string
	i := 0
	for i < len(query) {
		char := query[i]
		switch char {
		case '"':
			if inQuotes {
				if currentTerm.Len() > 0 {
					terms = append(terms, SearchTerm{Field: currentField, Value: currentTerm.String(), Exact: true, Operator: operator})
					currentTerm.Reset()
					currentField = ""
					operator = ""
				}
				inQuotes = false
			} else {
				if currentTerm.Len() > 0 {
					terms = append(terms, SearchTerm{Field: currentField, Value: currentTerm.String(), Exact: false, Operator: operator})
					currentTerm.Reset()
					currentField = ""
					operator = ""
				}
				inQuotes = true
			}
		case ' ':
			if inQuotes {
				currentTerm.WriteRune(rune(char))
			} else {
				remaining := strings.ToUpper(strings.TrimSpace(query[i:]))
				if strings.HasPrefix(remaining, "AND ") {
					if currentTerm.Len() > 0 {
						terms = append(terms, SearchTerm{Field: currentField, Value: currentTerm.String(), Exact: false, Operator: operator})
						currentTerm.Reset()
						currentField = ""
					}
					operator = "AND"
					i += 3
					continue
				} else if strings.HasPrefix(remaining, "OR ") {
					if currentTerm.Len() > 0 {
						terms = append(terms, SearchTerm{Field: currentField, Value: currentTerm.String(), Exact: false, Operator: operator})
						currentTerm.Reset()
						currentField = ""
					}
					operator = "OR"
					i += 2
					continue
				} else {
					if currentTerm.Len() > 0 {
						terms = append(terms, SearchTerm{Field: currentField, Value: currentTerm.String(), Exact: false, Operator: operator})
						currentTerm.Reset()
						currentField = ""
						operator = ""
					}
				}
			}
		case ':':
			if !inQuotes && currentTerm.Len() > 0 {
				fieldCandidate := currentTerm.String()
				remaining := query[i+1:]
				if len(remaining) > 0 && remaining[0] != ' ' {
					currentField = strings.ToLower(fieldCandidate)
					currentTerm.Reset()
					i++
					continue
				}
			}
			currentTerm.WriteRune(rune(char))
		default:
			currentTerm.WriteRune(rune(char))
		}
		i++
	}
	if currentTerm.Len() > 0 {
		terms = append(terms, SearchTerm{Field: currentField, Value: currentTerm.String(), Exact: inQuotes, Operator: operator})
	}
	return terms
}

// validateAssetFilters validates asset filter parameters and returns helpful error messages.
func validateAssetFilters(filters models.AssetFilters) error {
	validAssetTypes := map[string]bool{
		"server": true, "endpoint": true, "service": true, "appliance": true,
	}
	for _, assetType := range filters.AssetType {
		if !validAssetTypes[assetType] {
			if assetType == "certificate" || assetType == "certificates" {
				return fmt.Errorf(
					"invalid asset_type '%s': certificates are not asset types. Use 'has_certificates=true' filter to find assets with certificates, or use the /certificates endpoint to view certificates directly",
					assetType,
				)
			}
			return fmt.Errorf("invalid asset_type '%s'. Valid types: server, endpoint, service, appliance", assetType)
		}
	}
	if filters.LastSeenBefore != "" {
		if _, err := time.Parse(time.RFC3339, filters.LastSeenBefore); err != nil {
			return fmt.Errorf("invalid last_seen_before '%s': must be an RFC3339 timestamp (e.g. 2026-05-29T00:00:00Z)", filters.LastSeenBefore)
		}
	}
	return nil
}

// buildAssetListWhereAndHaving builds WHERE and HAVING conditions and args for GetAssets.
// argStart is the first placeholder index (e.g. 2 when $1 is tenant_id). Returns only the args for placeholders $argStart and beyond (caller prepends tenantID).
func buildAssetListWhereAndHaving(filters models.AssetFilters, argStart int) (whereConditions, havingConditions []string, args []interface{}) {
	argCount := argStart - 1
	whereConditions = []string{}

	if len(filters.AssetStatus) > 0 {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`a.asset_status = ANY($%d)`, argCount))
		args = append(args, pq.Array(filters.AssetStatus))
	} else {
		whereConditions = append(whereConditions, `a.asset_status = 'monitoring'`)
	}

	if len(filters.DiscoverySource) > 0 {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`a.metadata->>'discovery_source' = ANY($%d)`, argCount))
		args = append(args, pq.Array(filters.DiscoverySource))
	}

	// UnscannedOnly: never actively scanned (Active Scan coverage cut).
	if filters.UnscannedOnly != nil && *filters.UnscannedOnly {
		whereConditions = append(whereConditions, `a.last_scanned_at IS NULL`)
	}

	if filters.LastSeenBefore != "" {
		// Validated as RFC3339 in validateAssetFilters; parameterized as a
		// timestamp. NULL last_seen_at intentionally never matches.
		if cutoff, err := time.Parse(time.RFC3339, filters.LastSeenBefore); err == nil {
			argCount++
			whereConditions = append(whereConditions, fmt.Sprintf(`a.last_seen_at < $%d`, argCount))
			args = append(args, cutoff)
		}
	}

	if filters.Search != "" {
		terms := parseSearchQuery(filters.Search)
		if len(terms) > 0 {
			var searchConditions []string
			for i, term := range terms {
				pattern := term.Value
				if !term.Exact {
					pattern = "%" + term.Value + "%"
				}
				argCount++
				var condition string
				switch term.Field {
				case "hostname":
					condition = fmt.Sprintf(`a.hostname ILIKE $%d`, argCount)
				case "ip", "ip_address":
					condition = fmt.Sprintf(`a.ip_address::text ILIKE $%d`, argCount)
				case "owner", "owner_email", "email":
					condition = fmt.Sprintf(`a.owner_email ILIKE $%d`, argCount)
				case "os", "operating_system", "operating system":
					condition = fmt.Sprintf(`a.operating_system ILIKE $%d`, argCount)
				case "description", "desc":
					condition = fmt.Sprintf(`a.description ILIKE $%d`, argCount)
				case "business_unit", "business unit", "bu":
					condition = fmt.Sprintf(`a.business_unit ILIKE $%d`, argCount)
				case "tags", "tag":
					condition = fmt.Sprintf(`a.tags::text ILIKE $%d`, argCount)
				case "metadata", "meta":
					condition = fmt.Sprintf(`a.metadata::text ILIKE $%d`, argCount)
				default:
					condition = fmt.Sprintf(`(
						a.hostname ILIKE $%d OR a.ip_address::text ILIKE $%d OR a.description ILIKE $%d OR
						a.business_unit ILIKE $%d OR a.owner_email ILIKE $%d OR a.operating_system ILIKE $%d OR
						a.tags::text ILIKE $%d OR a.metadata::text ILIKE $%d
					)`, argCount, argCount, argCount, argCount, argCount, argCount, argCount, argCount)
				}
				if i > 0 && term.Operator != "" {
					condition = term.Operator + " " + condition
				}
				searchConditions = append(searchConditions, condition)
				args = append(args, pattern)
			}
			if len(searchConditions) > 0 {
				whereConditions = append(whereConditions, "("+strings.Join(searchConditions, " ")+")")
			}
		}
	}

	if len(filters.AssetType) > 0 {
		typePlaceholders := []string{}
		for _, assetType := range filters.AssetType {
			argCount++
			typePlaceholders = append(typePlaceholders, fmt.Sprintf(`$%d::asset_type`, argCount))
			args = append(args, assetType)
		}
		whereConditions = append(whereConditions, fmt.Sprintf(`a.asset_type IN (%s)`, strings.Join(typePlaceholders, ", ")))
	}
	if len(filters.Environment) > 0 {
		envPlaceholders := []string{}
		for _, env := range filters.Environment {
			argCount++
			envPlaceholders = append(envPlaceholders, fmt.Sprintf(`$%d::environment_type`, argCount))
			args = append(args, env)
		}
		whereConditions = append(whereConditions, fmt.Sprintf(`a.environment IN (%s)`, strings.Join(envPlaceholders, ", ")))
	}
	if len(filters.Protocol) > 0 {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`ci.protocol = ANY($%d)`, argCount))
		args = append(args, pq.Array(filters.Protocol))
	}
	if len(filters.BusinessUnit) > 0 {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`a.business_unit = ANY($%d)`, argCount))
		args = append(args, pq.Array(filters.BusinessUnit))
	}
	if len(filters.LocationRegion) > 0 {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`COALESCE(a.tags->'location'->>'region', a.tags->>'region') = ANY($%d)`, argCount))
		args = append(args, pq.Array(filters.LocationRegion))
	}
	if len(filters.LocationSite) > 0 {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`COALESCE(a.tags->'location'->>'site', a.tags->>'site') = ANY($%d)`, argCount))
		args = append(args, pq.Array(filters.LocationSite))
	}
	if len(filters.LocationBuilding) > 0 {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`COALESCE(a.tags->'location'->>'building', a.tags->>'building') = ANY($%d)`, argCount))
		args = append(args, pq.Array(filters.LocationBuilding))
	}
	if len(filters.LocationZone) > 0 {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`COALESCE(a.tags->'location'->>'zone', a.tags->>'zone') = ANY($%d)`, argCount))
		args = append(args, pq.Array(filters.LocationZone))
	}
	if len(filters.LocationID) > 0 {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`a.location_id::text = ANY($%d)`, argCount))
		args = append(args, pq.Array(filters.LocationID))
	}
	if len(filters.NetworkSegmentID) > 0 {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`a.network_segment_id::text = ANY($%d)`, argCount))
		args = append(args, pq.Array(filters.NetworkSegmentID))
	}
	if len(filters.OperatingSystem) > 0 {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`a.operating_system = ANY($%d)`, argCount))
		args = append(args, pq.Array(filters.OperatingSystem))
	}
	if len(filters.OwnerEmail) > 0 {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`a.owner_email = ANY($%d)`, argCount))
		args = append(args, pq.Array(filters.OwnerEmail))
	}
	if len(filters.AssetOwnership) > 0 {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`a.asset_ownership = ANY($%d)`, argCount))
		args = append(args, pq.Array(filters.AssetOwnership))
	}
	if filters.HasCertificates != nil && *filters.HasCertificates {
		whereConditions = append(whereConditions, `EXISTS (
			SELECT 1 FROM crypto_implementations ci
			WHERE ci.asset_id = a.id AND ci.certificate_id IS NOT NULL AND ci.deleted_at IS NULL
		)`)
	}
	if filters.CertExpiringWithin != nil {
		days := *filters.CertExpiringWithin
		whereConditions = append(whereConditions, fmt.Sprintf(`EXISTS (
			SELECT 1 FROM crypto_implementations ci
			JOIN certificates c ON ci.certificate_id = c.id
			WHERE ci.asset_id = a.id AND c.not_after BETWEEN NOW() AND NOW() + INTERVAL '%d days' AND ci.deleted_at IS NULL
		)`, days))
	}
	if filters.CertKeySizeMin != nil {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`EXISTS (
			SELECT 1 FROM crypto_implementations ci JOIN certificates c ON ci.certificate_id = c.id
			WHERE ci.asset_id = a.id AND c.public_key_size >= $%d AND ci.deleted_at IS NULL
		)`, argCount))
		args = append(args, *filters.CertKeySizeMin)
	}
	if filters.CertAlgorithm != nil {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`EXISTS (
			SELECT 1 FROM crypto_implementations ci JOIN certificates c ON ci.certificate_id = c.id
			WHERE ci.asset_id = a.id AND c.public_key_algorithm = $%d AND ci.deleted_at IS NULL
		)`, argCount))
		args = append(args, *filters.CertAlgorithm)
	}
	if len(filters.ProtocolVersion) > 0 {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`EXISTS (
			SELECT 1 FROM crypto_implementations ci WHERE ci.asset_id = a.id AND ci.protocol_version = ANY($%d) AND ci.deleted_at IS NULL
		)`, argCount))
		args = append(args, pq.Array(filters.ProtocolVersion))
	}
	if len(filters.HashAlgorithm) > 0 {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`EXISTS (
			SELECT 1 FROM crypto_implementations ci WHERE ci.asset_id = a.id AND ci.hash_algorithm = ANY($%d) AND ci.deleted_at IS NULL
		)`, argCount))
		args = append(args, pq.Array(filters.HashAlgorithm))
	}
	if filters.KeySizeMin != nil {
		argCount++
		whereConditions = append(whereConditions, fmt.Sprintf(`EXISTS (
			SELECT 1 FROM crypto_implementations ci WHERE ci.asset_id = a.id AND ci.key_size >= $%d AND ci.deleted_at IS NULL
		)`, argCount))
		args = append(args, *filters.KeySizeMin)
	}
	if filters.UsesDeprecatedAlgorithms != nil && *filters.UsesDeprecatedAlgorithms {
		whereConditions = append(whereConditions, `EXISTS (
			SELECT 1 FROM crypto_implementations ci WHERE ci.asset_id = a.id AND ci.deleted_at IS NULL AND `+
			deprecatedAlgorithmsSQL("ci.")+`
		)`)
	}
	if len(filters.RiskLevel) > 0 {
		riskLevelConditions := []string{}
		for _, rl := range filters.RiskLevel {
			if cond, ok := models.RiskBandSQL("COALESCE(MAX(ci.risk_score), 0)", rl); ok {
				riskLevelConditions = append(riskLevelConditions, "("+cond+")")
			}
		}
		if len(riskLevelConditions) > 0 {
			havingConditions = append(havingConditions, "("+strings.Join(riskLevelConditions, " OR ")+")")
		}
	}
	return whereConditions, havingConditions, args
}
