package services

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
)

// RemediationService provides remediation guidance lookup and aggregation
type RemediationService struct {
	db               *database.DB
	algorithmService *AlgorithmService
}

// NewRemediationService creates a new RemediationService
func NewRemediationService(db *database.DB, algorithmService *AlgorithmService) *RemediationService {
	return &RemediationService{
		db:               db,
		algorithmService: algorithmService,
	}
}

// RemediationSummary aggregates remediation information for a crypto configuration
type RemediationSummary struct {
	CryptoImplementationID  uuid.UUID          `json:"crypto_implementation_id"`
	RiskScore               int                `json:"risk_score"`
	Issues                  []RemediationIssue `json:"issues"`
	PriorityActions         []string           `json:"priority_actions"`
	OverallTimeline         string             `json:"overall_timeline"`
	RecommendedAlternatives []string           `json:"recommended_alternatives"`
	ComplianceImpact        map[string]string  `json:"compliance_impact"`
	Resources               []string           `json:"resources"`
}

// RemediationIssue represents a single issue requiring remediation
type RemediationIssue struct {
	Type         string   `json:"type"` // protocol, cipher, hash, key_size
	Code         string   `json:"code"` // Algorithm/protocol code
	Name         string   `json:"name"`
	Severity     string   `json:"severity"`
	Summary      string   `json:"summary"`
	Impact       string   `json:"impact"`
	Steps        []string `json:"steps"`
	Timeline     string   `json:"timeline"`
	Alternatives []string `json:"alternatives"`
	Resources    []string `json:"resources"`
}

// GetRemediationForCryptoImplementation returns detailed remediation guidance for a crypto configuration
func (s *RemediationService) GetRemediationForCryptoImplementation(ctx context.Context, tenantID uuid.UUID, implID uuid.UUID) (*RemediationSummary, error) {
	// Query the crypto configuration
	query := `
		SELECT
			id, protocol, protocol_version, cipher_suite, hash_algorithm, key_size,
			risk_score, compliance_status
		FROM crypto_implementations
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
	`

	var id uuid.UUID
	var protocol, protocolVersion, cipherSuite, hashAlgorithm sql.NullString
	var keySize sql.NullInt32
	var riskScore sql.NullInt32
	var complianceStatusJSON []byte

	// RLS-scoped read over crypto_implementations — run inside WithTenantTx so
	// app.tenant_id is set for the policy.
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(query, implID, tenantID).Scan(
			&id, &protocol, &protocolVersion, &cipherSuite, &hashAlgorithm, &keySize,
			&riskScore, &complianceStatusJSON,
		)
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("crypto implementation not found")
		}
		return nil, fmt.Errorf("failed to query crypto implementation: %w", err)
	}

	summary := &RemediationSummary{
		CryptoImplementationID:  id,
		RiskScore:               int(riskScore.Int32),
		Issues:                  []RemediationIssue{},
		PriorityActions:         []string{},
		RecommendedAlternatives: []string{},
		ComplianceImpact:        make(map[string]string),
		Resources:               []string{},
	}

	// Analyze protocol version
	if protocolVersion.Valid && protocolVersion.String != "" {
		issue := s.getProtocolRemediation(protocolVersion.String)
		if issue != nil {
			summary.Issues = append(summary.Issues, *issue)
			summary.RecommendedAlternatives = append(summary.RecommendedAlternatives, issue.Alternatives...)
			summary.Resources = appendUnique(summary.Resources, issue.Resources...)
		}
	}

	// Analyze cipher suite
	if cipherSuite.Valid && cipherSuite.String != "" {
		issues := s.getCipherSuiteRemediation(cipherSuite.String)
		for _, issue := range issues {
			summary.Issues = append(summary.Issues, issue)
			summary.RecommendedAlternatives = append(summary.RecommendedAlternatives, issue.Alternatives...)
			summary.Resources = appendUnique(summary.Resources, issue.Resources...)
		}
	}

	// Analyze hash algorithm
	if hashAlgorithm.Valid && hashAlgorithm.String != "" {
		issue := s.getHashRemediation(hashAlgorithm.String)
		if issue != nil {
			summary.Issues = append(summary.Issues, *issue)
			summary.RecommendedAlternatives = append(summary.RecommendedAlternatives, issue.Alternatives...)
			summary.Resources = appendUnique(summary.Resources, issue.Resources...)
		}
	}

	// Analyze key size
	if keySize.Valid && keySize.Int32 > 0 && keySize.Int32 < 2048 {
		issue := s.getKeySizeRemediation(int(keySize.Int32))
		if issue != nil {
			summary.Issues = append(summary.Issues, *issue)
			summary.Resources = appendUnique(summary.Resources, issue.Resources...)
		}
	}

	// Calculate overall timeline and priority actions
	s.calculateOverallRemediationPlan(summary)

	// Extract compliance impact from issues
	for _, issue := range summary.Issues {
		alg, _ := s.algorithmService.GetAlgorithmByCode(issue.Code)
		if alg != nil && alg.ComplianceMappings != nil {
			for framework, status := range alg.ComplianceMappings {
				if statusStr, ok := status.(string); ok {
					if existing, exists := summary.ComplianceImpact[framework]; exists {
						// Keep the worse status
						if isWorseComplianceStatus(statusStr, existing) {
							summary.ComplianceImpact[framework] = statusStr
						}
					} else {
						summary.ComplianceImpact[framework] = statusStr
					}
				}
			}
		}
	}

	return summary, nil
}

// getProtocolRemediation returns remediation guidance for a protocol version
func (s *RemediationService) getProtocolRemediation(version string) *RemediationIssue {
	normalizedVersion := strings.ToUpper(strings.TrimSpace(version))

	// Check if this is a weak protocol
	weakProtocols := map[string]bool{
		"SSLV2":   true,
		"SSLV3":   true,
		"TLSV1.0": true,
		"TLSV1.1": true,
	}

	if !weakProtocols[normalizedVersion] {
		return nil // Not a weak protocol
	}

	// Look up from algorithm taxonomy
	alg, err := s.algorithmService.GetAlgorithmByCode(normalizedVersion)
	if err != nil || alg == nil {
		// Return generic guidance
		return &RemediationIssue{
			Type:         "protocol",
			Code:         normalizedVersion,
			Name:         version,
			Severity:     "High",
			Summary:      fmt.Sprintf("%s is an outdated protocol version", version),
			Impact:       "Outdated protocol versions may have known vulnerabilities",
			Steps:        []string{"Upgrade to TLS 1.2 or TLS 1.3"},
			Timeline:     "Within 30 days",
			Alternatives: []string{"TLSv1.2", "TLSv1.3"},
		}
	}

	issue := &RemediationIssue{
		Type:         "protocol",
		Code:         alg.Code,
		Name:         alg.Name,
		Severity:     mapStrengthToSeverity(alg.Strength),
		Alternatives: alg.RecommendedAlternatives,
	}

	// Extract from remediation guidance if available
	if alg.RemediationGuidance != nil {
		if summary, ok := alg.RemediationGuidance["summary"].(string); ok {
			issue.Summary = summary
		}
		if impact, ok := alg.RemediationGuidance["impact"].(string); ok {
			issue.Impact = impact
		}
		if steps, ok := alg.RemediationGuidance["steps"].([]interface{}); ok {
			for _, step := range steps {
				if s, ok := step.(string); ok {
					issue.Steps = append(issue.Steps, s)
				}
			}
		}
		if timeline, ok := alg.RemediationGuidance["timeline"].(string); ok {
			issue.Timeline = timeline
		}
		if resources, ok := alg.RemediationGuidance["resources"].([]interface{}); ok {
			for _, res := range resources {
				if r, ok := res.(string); ok {
					issue.Resources = append(issue.Resources, r)
				}
			}
		}
	} else if alg.MigrationGuidance != nil {
		issue.Summary = *alg.MigrationGuidance
		issue.Steps = []string{*alg.MigrationGuidance}
	}

	return issue
}

// getCipherSuiteRemediation returns remediation guidance for weak cipher suite components
func (s *RemediationService) getCipherSuiteRemediation(cipherSuite string) []RemediationIssue {
	var issues []RemediationIssue
	upperCipherSuite := strings.ToUpper(cipherSuite)

	// Check for weak ciphers
	weakCiphers := map[string]string{
		"RC4":    "RC4",
		"DES":    "DES",
		"3DES":   "3DES",
		"EXPORT": "EXPORT",
		"NULL":   "NULL",
	}

	for weakCipher, code := range weakCiphers {
		if strings.Contains(upperCipherSuite, weakCipher) {
			alg, _ := s.algorithmService.GetAlgorithmByCode(code)
			issue := RemediationIssue{
				Type:     "cipher",
				Code:     code,
				Name:     weakCipher,
				Severity: "Critical",
			}

			if alg != nil {
				issue.Name = alg.Name
				issue.Alternatives = alg.RecommendedAlternatives
				if alg.RemediationGuidance != nil {
					if summary, ok := alg.RemediationGuidance["summary"].(string); ok {
						issue.Summary = summary
					}
					if impact, ok := alg.RemediationGuidance["impact"].(string); ok {
						issue.Impact = impact
					}
					if steps, ok := alg.RemediationGuidance["steps"].([]interface{}); ok {
						for _, step := range steps {
							if s, ok := step.(string); ok {
								issue.Steps = append(issue.Steps, s)
							}
						}
					}
					if timeline, ok := alg.RemediationGuidance["timeline"].(string); ok {
						issue.Timeline = timeline
					}
					if resources, ok := alg.RemediationGuidance["resources"].([]interface{}); ok {
						for _, res := range resources {
							if r, ok := res.(string); ok {
								issue.Resources = append(issue.Resources, r)
							}
						}
					}
				}
			} else {
				issue.Summary = fmt.Sprintf("%s is a weak cipher and should not be used", weakCipher)
				issue.Impact = "Weak ciphers can be broken, compromising data confidentiality"
				issue.Steps = []string{"Replace with AES-GCM or ChaCha20-Poly1305"}
				issue.Timeline = "Immediate - within 7 days"
				issue.Alternatives = []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20_POLY1305"}
			}

			issues = append(issues, issue)
		}
	}

	return issues
}

// getHashRemediation returns remediation guidance for weak hash algorithms
func (s *RemediationService) getHashRemediation(hashAlgorithm string) *RemediationIssue {
	upperHash := strings.ToUpper(strings.TrimSpace(hashAlgorithm))

	weakHashes := map[string]bool{
		"MD5":   true,
		"SHA1":  true,
		"SHA-1": true,
	}

	// Normalize SHA-1 to SHA1
	if upperHash == "SHA-1" {
		upperHash = "SHA1"
	}

	if !weakHashes[upperHash] {
		return nil
	}

	alg, _ := s.algorithmService.GetAlgorithmByCode(upperHash)
	issue := &RemediationIssue{
		Type:     "hash",
		Code:     upperHash,
		Name:     hashAlgorithm,
		Severity: "High",
	}

	if alg != nil {
		issue.Name = alg.Name
		issue.Alternatives = alg.RecommendedAlternatives
		issue.Severity = mapStrengthToSeverity(alg.Strength)
		if alg.RemediationGuidance != nil {
			if summary, ok := alg.RemediationGuidance["summary"].(string); ok {
				issue.Summary = summary
			}
			if impact, ok := alg.RemediationGuidance["impact"].(string); ok {
				issue.Impact = impact
			}
			if steps, ok := alg.RemediationGuidance["steps"].([]interface{}); ok {
				for _, step := range steps {
					if s, ok := step.(string); ok {
						issue.Steps = append(issue.Steps, s)
					}
				}
			}
			if timeline, ok := alg.RemediationGuidance["timeline"].(string); ok {
				issue.Timeline = timeline
			}
			if resources, ok := alg.RemediationGuidance["resources"].([]interface{}); ok {
				for _, res := range resources {
					if r, ok := res.(string); ok {
						issue.Resources = append(issue.Resources, r)
					}
				}
			}
		}
	} else {
		issue.Summary = fmt.Sprintf("%s is a weak hash algorithm", hashAlgorithm)
		issue.Impact = "Weak hash algorithms are vulnerable to collision attacks"
		issue.Steps = []string{"Replace with SHA-256 or SHA-512"}
		issue.Timeline = "High priority - within 30 days"
		issue.Alternatives = []string{"SHA256", "SHA512"}
	}

	return issue
}

// getKeySizeRemediation returns remediation guidance for weak key sizes
func (s *RemediationService) getKeySizeRemediation(keySize int) *RemediationIssue {
	var severity, timeline string
	if keySize <= 512 {
		severity = "Critical"
		timeline = "Immediate - within 7 days"
	} else if keySize <= 1024 {
		severity = "High"
		timeline = "High priority - within 30 days"
	} else {
		severity = "Medium"
		timeline = "Medium priority - within 90 days"
	}

	return &RemediationIssue{
		Type:     "key_size",
		Code:     fmt.Sprintf("RSA-%d", keySize),
		Name:     fmt.Sprintf("%d-bit key", keySize),
		Severity: severity,
		Summary:  fmt.Sprintf("%d-bit key size is insufficient for modern security requirements", keySize),
		Impact:   "Small key sizes can be factored or brute-forced with sufficient resources",
		Steps: []string{
			"Generate new key pair with at least 2048-bit RSA or 256-bit ECDSA",
			"Request new certificate with the new key",
			"Deploy the new certificate to all servers",
			"Revoke the old certificate",
		},
		Timeline:     timeline,
		Alternatives: []string{"RSA-2048", "RSA-4096", "ECDSA-P256", "ECDSA-P384"},
		Resources: []string{
			"https://www.keylength.com/",
			"https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final",
		},
	}
}

// calculateOverallRemediationPlan calculates priority actions and timeline
func (s *RemediationService) calculateOverallRemediationPlan(summary *RemediationSummary) {
	var criticalCount, highCount int
	priorityMap := make(map[string]bool)

	for _, issue := range summary.Issues {
		switch issue.Severity {
		case "Critical":
			criticalCount++
			if len(issue.Steps) > 0 {
				priorityMap[issue.Steps[0]] = true
			}
		case "High":
			highCount++
		}
	}

	// Build priority actions list
	for action := range priorityMap {
		summary.PriorityActions = append(summary.PriorityActions, action)
	}

	// Calculate overall timeline
	if criticalCount > 0 {
		summary.OverallTimeline = "Immediate action required - within 7-14 days"
	} else if highCount > 0 {
		summary.OverallTimeline = "High priority - within 30 days"
	} else if len(summary.Issues) > 0 {
		summary.OverallTimeline = "Medium priority - within 90 days"
	} else {
		summary.OverallTimeline = "No urgent remediation needed"
	}
}

// GetRemediationGuidanceByAlgorithm returns remediation guidance for a specific algorithm code
func (s *RemediationService) GetRemediationGuidanceByAlgorithm(ctx context.Context, algorithmCode string) (*RemediationIssue, error) {
	alg, err := s.algorithmService.GetAlgorithmByCode(algorithmCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get algorithm: %w", err)
	}
	if alg == nil {
		return nil, fmt.Errorf("algorithm not found: %s", algorithmCode)
	}

	issue := &RemediationIssue{
		Type:         alg.Category,
		Code:         alg.Code,
		Name:         alg.Name,
		Severity:     mapStrengthToSeverity(alg.Strength),
		Alternatives: alg.RecommendedAlternatives,
	}

	if alg.RemediationGuidance != nil {
		if summary, ok := alg.RemediationGuidance["summary"].(string); ok {
			issue.Summary = summary
		}
		if impact, ok := alg.RemediationGuidance["impact"].(string); ok {
			issue.Impact = impact
		}
		if steps, ok := alg.RemediationGuidance["steps"].([]interface{}); ok {
			for _, step := range steps {
				if s, ok := step.(string); ok {
					issue.Steps = append(issue.Steps, s)
				}
			}
		}
		if timeline, ok := alg.RemediationGuidance["timeline"].(string); ok {
			issue.Timeline = timeline
		}
		if resources, ok := alg.RemediationGuidance["resources"].([]interface{}); ok {
			for _, res := range resources {
				if r, ok := res.(string); ok {
					issue.Resources = append(issue.Resources, r)
				}
			}
		}
	} else if alg.MigrationGuidance != nil {
		issue.Summary = *alg.MigrationGuidance
		issue.Steps = []string{*alg.MigrationGuidance}
	}

	return issue, nil
}

// Helper functions

func mapStrengthToSeverity(strength string) string {
	switch strength {
	case "weak":
		return "Critical"
	case "deprecated":
		return "High"
	case "acceptable":
		return "Medium"
	default:
		return "Low"
	}
}

func isWorseComplianceStatus(newStatus, existingStatus string) bool {
	statusOrder := map[string]int{
		"non-compliant": 0,
		"deprecated":    1,
		"acceptable":    2,
		"compliant":     3,
		"approved":      4,
	}

	newOrder, newOk := statusOrder[strings.ToLower(newStatus)]
	existingOrder, existingOk := statusOrder[strings.ToLower(existingStatus)]

	if !newOk {
		return false
	}
	if !existingOk {
		return true
	}
	return newOrder < existingOrder
}

func appendUnique(slice []string, items ...string) []string {
	seen := make(map[string]bool)
	for _, item := range slice {
		seen[item] = true
	}
	for _, item := range items {
		if !seen[item] {
			slice = append(slice, item)
			seen[item] = true
		}
	}
	return slice
}
