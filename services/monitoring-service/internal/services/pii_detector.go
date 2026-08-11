package services

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// PIIDetector handles PII detection and scrubbing based on rules from the database
type PIIDetector struct {
	db    *sql.DB
	rules []PIIRule
}

// PIIRule represents a PII detection rule from the database
type PIIRule struct {
	ID               string
	Name             string
	PIIType          string
	PatternType      string
	Pattern          string
	RedactionMethod  string
	ReplacementValue string
	Priority         int
	IsActive         bool
}

// PIIDetectionResult represents the result of PII detection and scrubbing
type PIIDetectionResult struct {
	Detected      bool
	PIITypes      []string
	ScrubbedText  string
	RedactionMask []string
}

// NewPIIDetector creates a new PII detector and loads rules from the database
func NewPIIDetector(db *sql.DB) (*PIIDetector, error) {
	detector := &PIIDetector{
		db:    db,
		rules: []PIIRule{},
	}

	// Load rules from database
	if err := detector.loadRules(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to load PII rules: %w", err)
	}

	return detector, nil
}

// loadRules loads PII detection rules from the database
func (d *PIIDetector) loadRules(ctx context.Context) error {
	query := `
		SELECT id, rule_name, pii_type, pattern_type, pattern, redaction_method, 
		       replacement_value, priority, is_active
		FROM platform_log_pii_rules
		WHERE is_active = true
		ORDER BY priority DESC, rule_name ASC
	`

	rows, err := d.db.QueryContext(ctx, query)
	if err != nil {
		// If table doesn't exist yet, return empty rules (will be created by migration)
		return nil
	}
	defer rows.Close()

	d.rules = []PIIRule{}
	for rows.Next() {
		var rule PIIRule
		err := rows.Scan(
			&rule.ID, &rule.Name, &rule.PIIType, &rule.PatternType,
			&rule.Pattern, &rule.RedactionMethod, &rule.ReplacementValue,
			&rule.Priority, &rule.IsActive,
		)
		if err != nil {
			continue
		}
		d.rules = append(d.rules, rule)
	}

	return nil
}

// ReloadRules reloads PII rules from the database (useful after rule updates)
func (d *PIIDetector) ReloadRules(ctx context.Context) error {
	return d.loadRules(ctx)
}

// DetectAndScrub detects PII in text and scrubs it according to rules
func (d *PIIDetector) DetectAndScrub(ctx context.Context, text string) *PIIDetectionResult {
	result := &PIIDetectionResult{
		Detected:      false,
		PIITypes:      []string{},
		ScrubbedText:  text,
		RedactionMask: []string{},
	}

	// Reload rules to ensure we have the latest
	d.ReloadRules(ctx)

	scrubbedText := text
	detectedTypes := make(map[string]bool)
	redactedFields := make(map[string]bool)

	// Apply each rule in priority order
	for _, rule := range d.rules {
		if !rule.IsActive {
			continue
		}

		matches, found := d.applyRule(scrubbedText, rule)
		if found {
			detectedTypes[rule.PIIType] = true
			redactedFields[rule.PIIType] = true
			scrubbedText = d.scrubMatches(scrubbedText, matches, rule)
		}
	}

	// Build result
	if len(detectedTypes) > 0 {
		result.Detected = true
		for piiType := range detectedTypes {
			result.PIITypes = append(result.PIITypes, piiType)
		}
		for field := range redactedFields {
			result.RedactionMask = append(result.RedactionMask, field)
		}
		result.ScrubbedText = scrubbedText
	}

	return result
}

// applyRule applies a single PII detection rule to text
func (d *PIIDetector) applyRule(text string, rule PIIRule) ([]string, bool) {
	switch rule.PatternType {
	case "regex":
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, false
		}
		matches := re.FindAllString(text, -1)
		return matches, len(matches) > 0

	case "keyword":
		// Simple case-insensitive keyword search
		lowerText := strings.ToLower(text)
		lowerKeyword := strings.ToLower(rule.Pattern)
		if strings.Contains(lowerText, lowerKeyword) {
			return []string{rule.Pattern}, true
		}
		return nil, false

	case "format":
		// Format-based detection (e.g., phone numbers, SSNs)
		// For now, treat format patterns as regex
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, false
		}
		matches := re.FindAllString(text, -1)
		return matches, len(matches) > 0

	default:
		return nil, false
	}
}

// scrubMatches scrubs detected PII matches from text according to redaction method
func (d *PIIDetector) scrubMatches(text string, matches []string, rule PIIRule) string {
	scrubbed := text

	for _, match := range matches {
		var replacement string
		switch rule.RedactionMethod {
		case "hash":
			// Hash the match using SHA-256
			hash := sha256.Sum256([]byte(match))
			replacement = fmt.Sprintf("[%s_HASHED_%s]", rule.PIIType, hex.EncodeToString(hash[:])[:8])
		case "mask":
			// Mask the match (e.g., "123-45-6789" -> "***-**-****")
			if len(match) > 4 {
				replacement = match[:2] + strings.Repeat("*", len(match)-4) + match[len(match)-2:]
			} else {
				replacement = strings.Repeat("*", len(match))
			}
		case "remove":
			// Remove the match entirely
			replacement = fmt.Sprintf("[%s_REDACTED]", rule.PIIType)
		case "replace":
			// Replace with specified value
			if rule.ReplacementValue != "" {
				replacement = rule.ReplacementValue
			} else {
				replacement = fmt.Sprintf("[%s_REDACTED]", rule.PIIType)
			}
		default:
			// Default to masking
			if len(match) > 4 {
				replacement = match[:2] + strings.Repeat("*", len(match)-4) + match[len(match)-2:]
			} else {
				replacement = strings.Repeat("*", len(match))
			}
		}

		// Replace all occurrences of the match
		scrubbed = strings.ReplaceAll(scrubbed, match, replacement)
	}

	return scrubbed
}

// GetRedactionMaskJSON returns the redaction mask as a JSON array string
func (result *PIIDetectionResult) GetRedactionMaskJSON() string {
	if len(result.RedactionMask) == 0 {
		return "[]"
	}

	jsonBytes, err := json.Marshal(result.RedactionMask)
	if err != nil {
		return "[]"
	}

	return string(jsonBytes)
}
