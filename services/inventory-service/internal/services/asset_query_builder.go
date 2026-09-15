// Package services: asset list query builder (WHERE/HAVING from filters).
package services

// The pre-query-language search box, and the validation the API still owes its
// callers.
//
// `buildAssetListWhereAndHaving` — a second, hand-written WHERE-builder that ran
// beside the facet query's own copy of the same predicates — is GONE. Every
// filter parameter is now translated into a query string by
// LegacyFiltersToQuery and compiled once, so the list and the facet rail cannot
// describe different populations. parseSearchQuery survives because the old
// `search=` box has a grammar of its own (field aliases, AND/OR) that has to be
// read before it can be rewritten as query-language terms.

import (
	"fmt"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
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
					i = skipKeyword(query, i, len("AND"))
					continue
				} else if strings.HasPrefix(remaining, "OR ") {
					if currentTerm.Len() > 0 {
						terms = append(terms, SearchTerm{Field: currentField, Value: currentTerm.String(), Exact: false, Operator: operator})
						currentTerm.Reset()
						currentField = ""
					}
					operator = "OR"
					i = skipKeyword(query, i, len("OR"))
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

// skipKeyword advances past " AND " / " OR " starting at the space i points at.
//
// It used to be `i += 3` for AND and `i += 2` for OR, which is one short in both
// cases and left the final letter behind as a term of its own: `web AND owner:x`
// parsed as THREE terms — "web", "D", and owner:x, so the list silently searched
// for a free-text "D". The keyword's real offset is found rather than assumed,
// which also handles a run of spaces before it.
func skipKeyword(query string, i, keywordLen int) int {
	j := i
	for j < len(query) && query[j] == ' ' {
		j++
	}
	return j + keywordLen
}

// validateAssetFilters validates asset filter parameters and returns helpful error messages.
//
// `asset_type` carries CLASS KEYS now, so it is validated against the class
// registry rather than against the four values of the enum phase 1 dropped. The
// old whitelist rejected every key the class facet writes — `hypervisor`,
// `cloud_resource`, `switch` — while accepting three values no column can hold.
func validateAssetFilters(filters models.AssetFilters) error {
	for _, assetType := range filters.AssetType {
		if _, ok := assetclass.Get(assetType); !ok {
			if assetType == "certificate" || assetType == "certificates" {
				return fmt.Errorf(
					"invalid asset_type '%s': certificates are not asset types. Use 'has_certificates=true' filter to find assets with certificates, or use the /certificates endpoint to view certificates directly",
					assetType,
				)
			}
			return fmt.Errorf("invalid asset_type '%s': it is not a class key. "+
				"Browse the taxonomy at GET /asset-classes, or use query=class:<key> for a whole branch", assetType)
		}
	}
	if filters.LastSeenBefore != "" {
		if _, err := time.Parse(time.RFC3339, filters.LastSeenBefore); err != nil {
			return fmt.Errorf("invalid last_seen_before '%s': must be an RFC3339 timestamp (e.g. 2026-05-29T00:00:00Z)", filters.LastSeenBefore)
		}
	}
	return nil
}
