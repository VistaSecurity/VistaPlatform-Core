package codescan

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// Scanner scans source code repositories for weak cryptographic patterns
type Scanner struct {
	db    *sql.DB
	rules []Rule
}

// NewScanner creates a new code scanner with the default rule set
func NewScanner(db *sql.DB) *Scanner {
	return &Scanner{
		db:    db,
		rules: DefaultRules(),
	}
}

// Finding represents a single code scan finding
type Finding struct {
	RuleID         string
	Description    string
	FindingType    string
	Severity       string
	Language       string
	Algorithm      string
	FilePath       string
	LineNumber     int
	LineContent    string
	MatchedPattern string
	RiskScore      int
	Confidence     float64
}

// ScanResult contains the results of scanning a repository
type ScanResult struct {
	RepositoryURL  string
	RepositoryName string
	Branch         string
	CommitSHA      string
	Findings       []Finding
	FilesScanned   int
	Duration       time.Duration
}

// ScanGitHubRepository scans a GitHub repository using the GitHub API.
// It fetches the repository tree and scans relevant files.
func (s *Scanner) ScanGitHubRepository(
	ctx context.Context,
	accessToken string,
	owner string,
	repo string,
	branch string,
) (*ScanResult, error) {
	start := time.Now()

	result := &ScanResult{
		RepositoryURL:  fmt.Sprintf("https://github.com/%s/%s", owner, repo),
		RepositoryName: fmt.Sprintf("%s/%s", owner, repo),
		Branch:         branch,
	}

	// Get the repository tree via GitHub API
	treeURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/git/trees/%s?recursive=1", owner, repo, branch)
	req, err := http.NewRequestWithContext(ctx, "GET", treeURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create tree request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch tree: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var tree struct {
		SHA  string `json:"sha"`
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
			Size int    `json:"size"`
		} `json:"tree"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tree); err != nil {
		return nil, fmt.Errorf("failed to decode tree: %w", err)
	}

	result.CommitSHA = tree.SHA

	// Filter to scannable files
	for _, entry := range tree.Tree {
		if entry.Type != "blob" {
			continue
		}

		// Skip binary files, vendor dirs, and very large files
		if shouldSkipFile(entry.Path, entry.Size) {
			continue
		}

		// Check if any rules match this file type
		applicableRules := s.rulesForFile(entry.Path)
		if len(applicableRules) == 0 {
			continue
		}

		// Fetch and scan the file
		findings, err := s.scanGitHubFile(ctx, client, accessToken, owner, repo, branch, entry.Path, applicableRules)
		if err != nil {
			log.Printf("Warning: failed to scan %s: %v", entry.Path, err)
			continue
		}

		result.Findings = append(result.Findings, findings...)
		result.FilesScanned++
	}

	result.Duration = time.Since(start)
	return result, nil
}

// scanGitHubFile fetches a single file from GitHub and scans it
func (s *Scanner) scanGitHubFile(
	ctx context.Context,
	client *http.Client,
	accessToken string,
	owner, repo, branch, filePath string,
	rules []Rule,
) ([]Finding, error) {
	fileURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", owner, repo, branch, filePath)
	req, err := http.NewRequestWithContext(ctx, "GET", fileURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	return s.scanReader(resp.Body, filePath, rules)
}

// ScanContent scans source code content (as a string) against all applicable rules
func (s *Scanner) ScanContent(content string, filePath string) ([]Finding, error) {
	applicableRules := s.rulesForFile(filePath)
	if len(applicableRules) == 0 {
		return nil, nil
	}
	return s.scanReader(strings.NewReader(content), filePath, applicableRules)
}

// scanReader scans an io.Reader line by line against the given rules
func (s *Scanner) scanReader(r io.Reader, filePath string, rules []Rule) ([]Finding, error) {
	var findings []Finding

	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, rule := range rules {
			if rule.Pattern.MatchString(line) {
				match := rule.Pattern.FindString(line)
				findings = append(findings, Finding{
					RuleID:         rule.ID,
					Description:    rule.Description,
					FindingType:    rule.FindingType,
					Severity:       rule.Severity,
					Language:       rule.Language,
					Algorithm:      rule.Algorithm,
					FilePath:       filePath,
					LineNumber:     lineNum,
					LineContent:    truncateLine(line, 500),
					MatchedPattern: match,
					RiskScore:      severityToRiskScore(rule.Severity),
					Confidence:     0.85,
				})
			}
		}
	}

	return findings, scanner.Err()
}

// rulesForFile returns rules applicable to a given file path
func (s *Scanner) rulesForFile(filePath string) []Rule {
	ext := filepath.Ext(filePath)
	var applicable []Rule

	for _, rule := range s.rules {
		if matchesFileGlob(filePath, ext, rule.FileGlob) {
			applicable = append(applicable, rule)
		}
	}

	return applicable
}

// StoreScanResults stores scan findings into the crypto_code_findings table
func (s *Scanner) StoreScanResults(
	ctx context.Context,
	tenantID uuid.UUID,
	integrationID uuid.UUID,
	result *ScanResult,
) error {
	query := `
		INSERT INTO crypto_code_findings (
			tenant_id, integration_id,
			repository_url, repository_name, branch, commit_sha,
			file_path, line_number, line_content,
			finding_type, severity, language,
			rule_id, rule_description, matched_pattern,
			risk_score, confidence_score,
			status, first_detected_at, last_detected_at
		) VALUES (
			$1, $2,
			$3, $4, $5, $6,
			$7, $8, $9,
			$10, $11, $12,
			$13, $14, $15,
			$16, $17,
			'open', NOW(), NOW()
		)
	`

	for _, f := range result.Findings {
		// RLS-scoped write on `crypto_code_findings`: tenantID is an input → WithTenantTx.
		err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
			_, e := tx.ExecContext(ctx, query,
				tenantID, integrationID,
				result.RepositoryURL, result.RepositoryName, result.Branch, result.CommitSHA,
				f.FilePath, f.LineNumber, f.LineContent,
				f.FindingType, f.Severity, f.Language,
				f.RuleID, f.Description, f.MatchedPattern,
				f.RiskScore, f.Confidence,
			)
			return e
		})
		if err != nil {
			log.Printf("Warning: failed to store code finding %s in %s:%d: %v",
				f.RuleID, f.FilePath, f.LineNumber, err)
		}
	}

	return nil
}

// --- Helpers ---

// shouldSkipFile returns true for files that shouldn't be scanned
func shouldSkipFile(path string, size int) bool {
	// Skip very large files (> 1MB)
	if size > 1_000_000 {
		return true
	}

	// Skip vendor/dependency directories
	skipDirs := []string{
		"vendor/", "node_modules/", ".git/", "dist/", "build/",
		"__pycache__/", ".tox/", ".venv/", "venv/",
		"target/", "bin/", "obj/", ".gradle/",
	}
	for _, dir := range skipDirs {
		if strings.Contains(path, dir) {
			return true
		}
	}

	// Skip binary/non-code extensions
	skipExts := []string{
		".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
		".woff", ".woff2", ".ttf", ".eot",
		".zip", ".tar", ".gz", ".bz2",
		".exe", ".dll", ".so", ".dylib",
		".pdf", ".doc", ".docx",
		".min.js", ".min.css",
		".lock",
	}
	lower := strings.ToLower(path)
	for _, ext := range skipExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}

	return false
}

// matchesFileGlob checks if a file path matches a rule's file glob
func matchesFileGlob(filePath, ext string, glob string) bool {
	if glob == "*" {
		return true
	}

	// Handle brace expansion: *.{js,ts,mjs,cjs}
	if strings.Contains(glob, "{") {
		prefix := glob[:strings.Index(glob, "{")]
		inner := glob[strings.Index(glob, "{")+1 : strings.Index(glob, "}")]
		exts := strings.Split(inner, ",")
		for _, e := range exts {
			if matched, _ := filepath.Match(prefix+e, filepath.Base(filePath)); matched {
				return true
			}
		}
		return false
	}

	matched, _ := filepath.Match(glob, filepath.Base(filePath))
	return matched
}

// severityToRiskScore converts a severity string to a numeric risk score
func severityToRiskScore(severity string) int {
	switch severity {
	case "critical":
		return 90
	case "high":
		return 75
	case "medium":
		return 50
	case "low":
		return 25
	case "info":
		return 10
	default:
		return 50
	}
}

// truncateLine truncates a line to maxLen characters
func truncateLine(line string, maxLen int) string {
	line = strings.TrimSpace(line)
	if len(line) > maxLen {
		return line[:maxLen] + "..."
	}
	return line
}
