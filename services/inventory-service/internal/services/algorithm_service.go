package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
)

// catalogueCacheTTL bounds how stale the in-memory algorithm catalogue may be.
// The catalogue is curated reference data (a few hundred rows) that changes only
// when a platform admin edits it, while ingest resolves 15-25 components per
// finding against it — one query each before this cache existed. Writes through
// this service invalidate immediately; the TTL only bounds staleness caused by
// another replica's write.
const catalogueCacheTTL = 5 * time.Minute

type AlgorithmService struct {
	db *database.DB

	// Cached whole-table snapshot used by the ingest classification path.
	// Deliberately NOT used by GetAlgorithmByCode/GetAlgorithmByCodeCI: the
	// admin catalogue API must always read through to the database.
	cacheMu   sync.RWMutex
	cache     *algorithmCatalogue
	cacheTTL  time.Duration
	cacheOnly bool // test seam: serve the injected snapshot, never load from DB
}

func NewAlgorithmService(db *database.DB) *AlgorithmService {
	return &AlgorithmService{
		db:       db,
		cacheTTL: catalogueCacheTTL,
	}
}

// algorithmCatalogue is an immutable snapshot of the algorithms table, indexed
// for the two lookups classification needs: case-insensitive exact code match,
// and an unambiguous substring match within a category.
type algorithmCatalogue struct {
	byCode   map[string]*Algorithm // key: lower(code)
	ordered  []*Algorithm          // stable order, for deterministic substring matching
	loadedAt time.Time
}

func newAlgorithmCatalogue(algs []Algorithm) *algorithmCatalogue {
	c := &algorithmCatalogue{
		byCode:   make(map[string]*Algorithm, len(algs)),
		ordered:  make([]*Algorithm, 0, len(algs)),
		loadedAt: time.Now(),
	}
	for i := range algs {
		a := algs[i]
		c.byCode[strings.ToLower(a.Code)] = &a
		c.ordered = append(c.ordered, &a)
	}
	return c
}

// lookup returns the row whose code equals the given string, ignoring case.
func (c *algorithmCatalogue) lookup(code string) *Algorithm {
	return c.byCode[strings.ToLower(strings.TrimSpace(code))]
}

// lookupInCategory is lookup, restricted to one category.
//
// The restriction matters because a code can be a family name in one category
// and a component name in another: "RSA" is a key-exchange row (static RSA key
// transport, no forward secrecy) AND the authentication half of every
// TLS_ECDHE_RSA_* suite. Resolving the signature component against the
// key-exchange row would attach a no-forward-secrecy verdict to a suite that
// has forward secrecy.
func (c *algorithmCatalogue) lookupInCategory(code, category string) *Algorithm {
	alg := c.lookup(code)
	if alg == nil || alg.Category != category {
		return nil
	}
	return alg
}

// substringMatches returns every row in a category whose CODE contains the
// needle. Codes only — names are prose, and matching them once recorded an SSH
// server reporting protocol version "2.0" as running SSLv2.
func (c *algorithmCatalogue) substringMatches(needle, category string) []*Algorithm {
	n := strings.ToLower(strings.TrimSpace(needle))
	if n == "" {
		return nil
	}
	var out []*Algorithm
	for _, a := range c.ordered {
		if a.Category == category && strings.Contains(strings.ToLower(a.Code), n) {
			out = append(out, a)
		}
	}
	return out
}

// catalogue returns a cached snapshot of the algorithms table, reloading it
// when the TTL has elapsed.
func (s *AlgorithmService) catalogue() (*algorithmCatalogue, error) {
	ttl := s.cacheTTL
	if ttl <= 0 {
		ttl = catalogueCacheTTL
	}

	s.cacheMu.RLock()
	cached := s.cache
	only := s.cacheOnly
	s.cacheMu.RUnlock()
	if cached != nil && (only || time.Since(cached.loadedAt) < ttl) {
		return cached, nil
	}
	if only {
		return newAlgorithmCatalogue(nil), nil
	}

	algs, err := s.GetAllAlgorithms()
	if err != nil {
		return nil, err
	}
	fresh := newAlgorithmCatalogue(algs)

	s.cacheMu.Lock()
	s.cache = fresh
	s.cacheMu.Unlock()
	return fresh, nil
}

// invalidateCatalogue drops the cached snapshot. Called by every write path in
// this service so an admin edit is visible to classification immediately.
func (s *AlgorithmService) invalidateCatalogue() {
	s.cacheMu.Lock()
	s.cache = nil
	s.cacheMu.Unlock()
}

// setCatalogueForTest installs a fixed catalogue snapshot and stops the service
// from ever touching the database for classification. Test-only.
func (s *AlgorithmService) setCatalogueForTest(algs []Algorithm) {
	s.cacheMu.Lock()
	s.cache = newAlgorithmCatalogue(algs)
	s.cacheOnly = true
	s.cacheMu.Unlock()
}

// DB returns the underlying database connection for direct queries
func (s *AlgorithmService) DB() *database.DB {
	return s.db
}

// Algorithm represents an algorithm in the taxonomy.
// Enhanced with CycloneDX algorithmProperties identity fields.
type Algorithm struct {
	ID                       uuid.UUID              `json:"id" db:"id"`
	Code                     string                 `json:"code" db:"code"`
	Category                 string                 `json:"category" db:"category"`
	Subcategory              *string                `json:"subcategory,omitempty" db:"subcategory"`
	Name                     string                 `json:"name" db:"name"`
	Description              *string                `json:"description,omitempty" db:"description"`
	Strength                 string                 `json:"strength" db:"strength"`
	DeprecationStatus        string                 `json:"deprecation_status" db:"deprecation_status"`
	DeprecationDate          *string                `json:"deprecation_date,omitempty" db:"deprecation_date"`
	RiskScore                int                    `json:"risk_score" db:"risk_score"`
	RecommendedAlternatives  []string               `json:"recommended_alternatives,omitempty" db:"recommended_alternatives"`
	MigrationGuidance        *string                `json:"migration_guidance,omitempty" db:"migration_guidance"`
	RemediationGuidance      map[string]interface{} `json:"remediation_guidance,omitempty" db:"remediation_guidance"`
	ComplianceMappings       map[string]interface{} `json:"compliance_mappings" db:"compliance_mappings"`
	Metadata                 map[string]interface{} `json:"metadata" db:"metadata"`
	IsStandard               bool                   `json:"is_standard" db:"is_standard"`
	IsPQC                    bool                   `json:"is_pqc" db:"is_pqc"`
	PQCStandardizationStatus string                 `json:"pqc_standardization_status" db:"pqc_standardization_status"`
	CreatedAt                string                 `json:"created_at" db:"created_at"`
	UpdatedAt                string                 `json:"updated_at" db:"updated_at"`

	// CycloneDX algorithmProperties identity fields
	AlgorithmFamily          *string  `json:"algorithm_family,omitempty" db:"algorithm_family"`
	Primitive                *string  `json:"primitive,omitempty" db:"primitive"`
	Mode                     *string  `json:"mode,omitempty" db:"mode"`
	Padding                  *string  `json:"padding,omitempty" db:"padding"`
	OID                      *string  `json:"oid,omitempty" db:"oid"`
	CryptoFunctions          []string `json:"crypto_functions,omitempty" db:"crypto_functions"`
	ClassicalSecurityLevel   *int     `json:"classical_security_level,omitempty" db:"classical_security_level"`
	NistQuantumSecurityLevel *int     `json:"nist_quantum_security_level,omitempty" db:"nist_quantum_security_level"`
	ParameterSetIdentifier   *string  `json:"parameter_set_identifier,omitempty" db:"parameter_set_identifier"`
	Curve                    *string  `json:"curve,omitempty" db:"curve"`
}

// RemediationGuidance provides structured remediation information
type RemediationGuidance struct {
	Summary   string   `json:"summary"`
	Impact    string   `json:"impact"`
	Steps     []string `json:"steps"`
	Timeline  string   `json:"timeline"`
	Resources []string `json:"resources"`
}

// algorithmColumns is the canonical SELECT column list for the algorithms table.
// All queries returning Algorithm structs should use this to stay in sync.
const algorithmColumns = `id, code, category, subcategory, name, description,
	strength, deprecation_status, deprecation_date, risk_score,
	recommended_alternatives, migration_guidance, remediation_guidance,
	compliance_mappings, metadata, is_standard, is_pqc, pqc_standardization_status,
	created_at, updated_at,
	algorithm_family, primitive, mode, padding, oid, crypto_functions,
	classical_security_level, nist_quantum_security_level, parameter_set_identifier,
	curve`

// prefixColumns adds a table alias to each column in a comma-separated column list.
func prefixColumns(alias, columns string) string {
	parts := strings.Split(columns, ",")
	for i, p := range parts {
		parts[i] = alias + "." + strings.TrimSpace(p)
	}
	return strings.Join(parts, ", ")
}

// scanner is implemented by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...interface{}) error
}

// scanAlgorithmRow scans a single algorithm row from the canonical column list.
func scanAlgorithmRow(s scanner) (*Algorithm, error) {
	var alg Algorithm
	var subcategory, description, deprecationDate, migrationGuidance sql.NullString
	var complianceMappingsJSON, metadataJSON, remediationGuidanceJSON sql.NullString
	var recommendedAlternatives, cryptoFunctions pq.StringArray
	var algorithmFamily, primitive, mode, padding, oid, parameterSetIdentifier, curve sql.NullString
	var classicalSecurityLevel, nistQuantumSecurityLevel sql.NullInt64

	err := s.Scan(
		&alg.ID, &alg.Code, &alg.Category, &subcategory, &alg.Name, &description,
		&alg.Strength, &alg.DeprecationStatus, &deprecationDate, &alg.RiskScore,
		&recommendedAlternatives, &migrationGuidance, &remediationGuidanceJSON,
		&complianceMappingsJSON, &metadataJSON, &alg.IsStandard, &alg.IsPQC, &alg.PQCStandardizationStatus,
		&alg.CreatedAt, &alg.UpdatedAt,
		&algorithmFamily, &primitive, &mode, &padding, &oid, &cryptoFunctions,
		&classicalSecurityLevel, &nistQuantumSecurityLevel, &parameterSetIdentifier,
		&curve,
	)
	if err != nil {
		return nil, err
	}

	if subcategory.Valid {
		alg.Subcategory = &subcategory.String
	}
	if description.Valid {
		alg.Description = &description.String
	}
	if deprecationDate.Valid {
		alg.DeprecationDate = &deprecationDate.String
	}
	if migrationGuidance.Valid {
		alg.MigrationGuidance = &migrationGuidance.String
	}
	if remediationGuidanceJSON.Valid {
		_ = json.Unmarshal([]byte(remediationGuidanceJSON.String), &alg.RemediationGuidance)
	}
	if complianceMappingsJSON.Valid {
		_ = json.Unmarshal([]byte(complianceMappingsJSON.String), &alg.ComplianceMappings)
	}
	if metadataJSON.Valid {
		_ = json.Unmarshal([]byte(metadataJSON.String), &alg.Metadata)
	}
	alg.RecommendedAlternatives = []string(recommendedAlternatives)
	alg.CryptoFunctions = []string(cryptoFunctions)

	if algorithmFamily.Valid {
		alg.AlgorithmFamily = &algorithmFamily.String
	}
	if primitive.Valid {
		alg.Primitive = &primitive.String
	}
	if mode.Valid {
		alg.Mode = &mode.String
	}
	if padding.Valid {
		alg.Padding = &padding.String
	}
	if oid.Valid {
		alg.OID = &oid.String
	}
	if parameterSetIdentifier.Valid {
		alg.ParameterSetIdentifier = &parameterSetIdentifier.String
	}
	if curve.Valid {
		alg.Curve = &curve.String
	}
	if classicalSecurityLevel.Valid {
		v := int(classicalSecurityLevel.Int64)
		alg.ClassicalSecurityLevel = &v
	}
	if nistQuantumSecurityLevel.Valid {
		v := int(nistQuantumSecurityLevel.Int64)
		alg.NistQuantumSecurityLevel = &v
	}

	return &alg, nil
}

// GetAlgorithmByCode retrieves an algorithm by its code
func (s *AlgorithmService) GetAlgorithmByCode(code string) (*Algorithm, error) {
	return s.getAlgorithmByCodeQuery(`WHERE code = $1`, code)
}

// GetAlgorithmByCodeCI finds an algorithm by code with case-insensitive matching.
// Use this when the caller may not know the exact casing stored in the taxonomy
// (e.g. parser output "CHACHA20" vs stored code "ChaCha20").
func (s *AlgorithmService) GetAlgorithmByCodeCI(code string) (*Algorithm, error) {
	return s.getAlgorithmByCodeQuery(`WHERE UPPER(code) = UPPER($1)`, code)
}

func (s *AlgorithmService) getAlgorithmByCodeQuery(whereClause, code string) (*Algorithm, error) {
	query := fmt.Sprintf(`SELECT %s FROM algorithms %s LIMIT 1`, algorithmColumns, whereClause)

	alg, err := scanAlgorithmRow(s.db.QueryRow(query, code))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get algorithm: %w", err)
	}

	return alg, nil
}

// GetBatchRecommendations retrieves recommendations for multiple algorithms.
// Returns a map of the REQUESTED algorithm code to its recommendation data, and
// a list of codes that resolved to nothing.
//
// One query. The previous implementation spawned an unbounded goroutine (and a
// database round trip) per requested code, so a caller could open as many
// concurrent connections as it had strings in the request body.
func (s *AlgorithmService) GetBatchRecommendations(algorithmCodes []string) (map[string]*Algorithm, []string, error) {
	recommendations := make(map[string]*Algorithm)
	failed := []string{}
	if len(algorithmCodes) == 0 {
		return recommendations, failed, nil
	}

	upper := make([]string, 0, len(algorithmCodes))
	for _, c := range algorithmCodes {
		upper = append(upper, strings.ToUpper(strings.TrimSpace(c)))
	}

	algs, err := s.queryAlgorithms(
		fmt.Sprintf(`SELECT %s FROM algorithms WHERE UPPER(code) = ANY($1)`, algorithmColumns),
		pq.Array(upper),
	)
	if err != nil {
		return nil, nil, err
	}

	byUpperCode := make(map[string]*Algorithm, len(algs))
	for i := range algs {
		byUpperCode[strings.ToUpper(algs[i].Code)] = &algs[i]
	}

	for i, code := range algorithmCodes {
		alg, ok := byUpperCode[upper[i]]
		if !ok {
			failed = append(failed, code)
			continue
		}
		// Only include algorithms that have recommendations
		if len(alg.RecommendedAlternatives) > 0 {
			recommendations[code] = alg
		}
	}

	return recommendations, failed, nil
}

// AlgorithmAssessmentUpdate carries the editable assessment fields for the
// platform-admin rating-catalog update endpoint (ADR-0003 Phase 1). Only these
// fields may be changed; identity/CycloneDX fields (code, primitive, oid, …)
// are immutable through this path. All fields are optional pointers — a nil
// field is left unchanged.
type AlgorithmAssessmentUpdate struct {
	Strength                 *string                `json:"strength,omitempty"`
	RiskScore                *int                   `json:"risk_score,omitempty"`
	DeprecationStatus        *string                `json:"deprecation_status,omitempty"`
	DeprecationDate          *string                `json:"deprecation_date,omitempty"`
	IsPQC                    *bool                  `json:"is_pqc,omitempty"`
	PQCStandardizationStatus *string                `json:"pqc_standardization_status,omitempty"`
	MigrationGuidance        *string                `json:"migration_guidance,omitempty"`
	RecommendedAlternatives  []string               `json:"recommended_alternatives,omitempty"`
	RemediationGuidance      map[string]interface{} `json:"remediation_guidance,omitempty"`
	ComplianceMappings       map[string]interface{} `json:"compliance_mappings,omitempty"`
}

// UpdateAlgorithmAssessment updates ONLY the assessment fields of an algorithm
// identified by code. It returns the updated Algorithm. If no algorithm with the
// given code exists, it returns (nil, nil) so the handler can emit a 404.
//
// Identity/CycloneDX fields are never touched. updated_at is always refreshed.
// COALESCE keeps any field the caller didn't supply (nil pointer) unchanged;
// recommended_alternatives is replaced wholesale when supplied (non-nil slice).
func (s *AlgorithmService) UpdateAlgorithmAssessment(code string, upd AlgorithmAssessmentUpdate) (*Algorithm, error) {
	// recommended_alternatives: nil => leave unchanged; non-nil => replace.
	var recAlts interface{}
	if upd.RecommendedAlternatives != nil {
		recAlts = pq.StringArray(upd.RecommendedAlternatives)
	}

	// jsonb fields: nil map => leave unchanged; non-nil => replace wholesale.
	var remediationJSON, complianceJSON interface{}
	if upd.RemediationGuidance != nil {
		b, err := json.Marshal(upd.RemediationGuidance)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal remediation_guidance: %w", err)
		}
		remediationJSON = string(b)
	}
	if upd.ComplianceMappings != nil {
		b, err := json.Marshal(upd.ComplianceMappings)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal compliance_mappings: %w", err)
		}
		complianceJSON = string(b)
	}

	// deprecation_date: nil pointer => leave unchanged; empty string => clear (NULL);
	// non-empty => set. Use a sql.NullString so an explicit "" clears the column.
	var depDate interface{}
	if upd.DeprecationDate != nil {
		if *upd.DeprecationDate == "" {
			depDate = sql.NullString{} // NULL
		} else {
			depDate = *upd.DeprecationDate
		}
	}

	query := `
		UPDATE algorithms SET
			strength = COALESCE($2, strength),
			risk_score = COALESCE($3, risk_score),
			deprecation_status = COALESCE($4, deprecation_status),
			migration_guidance = COALESCE($5, migration_guidance),
			recommended_alternatives = COALESCE($6, recommended_alternatives),
			is_pqc = COALESCE($7, is_pqc),
			pqc_standardization_status = COALESCE($8, pqc_standardization_status),
			remediation_guidance = COALESCE($9::jsonb, remediation_guidance),
			compliance_mappings = COALESCE($10::jsonb, compliance_mappings),
			deprecation_date = CASE WHEN $11::boolean THEN $12::date ELSE deprecation_date END,
			updated_at = NOW()
		WHERE code = $1
	`

	res, err := s.db.Exec(query, code,
		upd.Strength, upd.RiskScore, upd.DeprecationStatus, upd.MigrationGuidance, recAlts,
		upd.IsPQC, upd.PQCStandardizationStatus, remediationJSON, complianceJSON,
		upd.DeprecationDate != nil, depDate,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to update algorithm assessment: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("failed to read update result: %w", err)
	}
	if rows == 0 {
		return nil, nil // not found
	}
	s.invalidateCatalogue()

	return s.GetAlgorithmByCode(code)
}

// AlgorithmCreate carries all fields for creating a new algorithm row through the
// platform-admin editor. code/name/category are required; everything else is
// optional and falls back to the table's column defaults when nil/empty.
type AlgorithmCreate struct {
	// Identity / classification
	Code                     string   `json:"code"`
	Name                     string   `json:"name"`
	Category                 string   `json:"category"`
	Subcategory              *string  `json:"subcategory,omitempty"`
	Description              *string  `json:"description,omitempty"`
	AlgorithmFamily          *string  `json:"algorithm_family,omitempty"`
	Primitive                *string  `json:"primitive,omitempty"`
	Mode                     *string  `json:"mode,omitempty"`
	Padding                  *string  `json:"padding,omitempty"`
	OID                      *string  `json:"oid,omitempty"`
	CryptoFunctions          []string `json:"crypto_functions,omitempty"`
	ClassicalSecurityLevel   *int     `json:"classical_security_level,omitempty"`
	NistQuantumSecurityLevel *int     `json:"nist_quantum_security_level,omitempty"`
	ParameterSetIdentifier   *string  `json:"parameter_set_identifier,omitempty"`
	Curve                    *string  `json:"curve,omitempty"`
	IsStandard               *bool    `json:"is_standard,omitempty"`
	// Assessment
	Strength                 *string                `json:"strength,omitempty"`
	RiskScore                *int                   `json:"risk_score,omitempty"`
	DeprecationStatus        *string                `json:"deprecation_status,omitempty"`
	DeprecationDate          *string                `json:"deprecation_date,omitempty"`
	IsPQC                    *bool                  `json:"is_pqc,omitempty"`
	PQCStandardizationStatus *string                `json:"pqc_standardization_status,omitempty"`
	MigrationGuidance        *string                `json:"migration_guidance,omitempty"`
	RecommendedAlternatives  []string               `json:"recommended_alternatives,omitempty"`
	RemediationGuidance      map[string]interface{} `json:"remediation_guidance,omitempty"`
	ComplianceMappings       map[string]interface{} `json:"compliance_mappings,omitempty"`
}

// ErrAlgorithmExists is returned by CreateAlgorithm when an algorithm with the
// requested code already exists (the handler maps it to 409).
var ErrAlgorithmExists = fmt.Errorf("algorithm already exists")

// CreateAlgorithm inserts a brand-new algorithm row. Returns ErrAlgorithmExists
// if the code is already taken. Optional fields fall back to the column defaults
// when nil. The created Algorithm is returned fully hydrated.
func (s *AlgorithmService) CreateAlgorithm(in AlgorithmCreate) (*Algorithm, error) {
	// Guard duplicate code up-front (the unique index would also reject it, but
	// this gives a clean ErrAlgorithmExists instead of a raw pq error).
	existing, err := s.GetAlgorithmByCode(in.Code)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrAlgorithmExists
	}

	var recAlts interface{}
	if in.RecommendedAlternatives != nil {
		recAlts = pq.StringArray(in.RecommendedAlternatives)
	}
	var cryptoFns interface{}
	if in.CryptoFunctions != nil {
		cryptoFns = pq.StringArray(in.CryptoFunctions)
	}
	var remediationJSON, complianceJSON interface{}
	if in.RemediationGuidance != nil {
		b, err := json.Marshal(in.RemediationGuidance)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal remediation_guidance: %w", err)
		}
		remediationJSON = string(b)
	}
	if in.ComplianceMappings != nil {
		b, err := json.Marshal(in.ComplianceMappings)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal compliance_mappings: %w", err)
		}
		complianceJSON = string(b)
	}
	var depDate interface{}
	if in.DeprecationDate != nil && *in.DeprecationDate != "" {
		depDate = *in.DeprecationDate
	}

	// COALESCE($n, <default>) lets every optional column fall back to its schema
	// default when the caller omits it.
	insertQuery := `
		INSERT INTO algorithms (
			code, name, category, subcategory, description,
			strength, risk_score, deprecation_status, deprecation_date,
			is_pqc, pqc_standardization_status, migration_guidance,
			recommended_alternatives, remediation_guidance, compliance_mappings,
			is_standard, algorithm_family, primitive, mode, padding, oid,
			crypto_functions, classical_security_level, nist_quantum_security_level,
			parameter_set_identifier, curve
		) VALUES (
			$1, $2, $3, $4, $5,
			COALESCE($6, 'acceptable'), COALESCE($7, 50), COALESCE($8, 'current'), $9::date,
			COALESCE($10, false), COALESCE($11, 'none'), $12,
			COALESCE($13, ARRAY[]::text[]), COALESCE($14::jsonb, '{}'::jsonb), COALESCE($15::jsonb, '{}'::jsonb),
			COALESCE($16, true), $17, $18, $19, $20, $21,
			COALESCE($22, ARRAY[]::text[]), $23, $24,
			$25, $26
		) RETURNING id
	`

	var algID uuid.UUID
	err = s.db.QueryRow(insertQuery,
		in.Code, in.Name, in.Category, in.Subcategory, in.Description,
		in.Strength, in.RiskScore, in.DeprecationStatus, depDate,
		in.IsPQC, in.PQCStandardizationStatus, in.MigrationGuidance,
		recAlts, remediationJSON, complianceJSON,
		in.IsStandard, in.AlgorithmFamily, in.Primitive, in.Mode, in.Padding, in.OID,
		cryptoFns, in.ClassicalSecurityLevel, in.NistQuantumSecurityLevel,
		in.ParameterSetIdentifier, in.Curve,
	).Scan(&algID)
	if err != nil {
		return nil, fmt.Errorf("failed to create algorithm: %w", err)
	}
	s.invalidateCatalogue()

	return s.GetAlgorithmByCode(in.Code)
}

// ClassifyAlgorithm resolves an observed algorithm string against the catalogue.
//
// Resolution order (all against the cached catalogue snapshot, so a finding
// costs zero queries once warm):
//
//  1. Case-insensitive exact code match. Case-SENSITIVE matching was the bug
//     here: the parsers emit "CHACHA20" while the catalogue stores "ChaCha20",
//     so the only correct row was skipped and the fuzzy fallback ran instead.
//  2. The same match after stripping cipher-mode suffixes and formatting
//     hyphens (shared with the external-connections path), so a legacy caller
//     passing "AES-256-GCM" still lands on AES256.
//  3. A substring match on the CODE within the category — but ONLY when it is
//     unambiguous.
//
// A bare family name like "RSA" in the signature category matches many
// catalogue rows, and any tie-break among them is a guess. An earlier unordered
// `LIMIT 1` picked one arbitrarily; in practice "RSA" resolved to **RSA-MD5**,
// so every RSA-authenticated TLS endpoint was recorded as using MD5 signatures
// and scored 90 — critical — off a guess.
//
// Matching is against the CODE only. Names are prose, and matching them meant
// an SSH server reporting protocol version "2.0" matched the name "SSL 2.0" and
// was recorded as running SSLv2 — critical, and wrong.
//
// When nothing resolves, the component is left UNLINKED and (nil, nil) is
// returned. It used to be inserted into the catalogue as a fresh row rated
// "acceptable" with risk 50 — a fabricated Medium verdict on an algorithm
// nobody had ever assessed, indistinguishable in the UI from a curated one.
// Unlinked means the implementation keeps risk 0, which the product already
// defines as "not assessed" rather than "assessed as safe".
func (s *AlgorithmService) ClassifyAlgorithm(algorithmString string, category string) (*Algorithm, error) {
	if strings.TrimSpace(algorithmString) == "" {
		return nil, nil
	}

	cat, err := s.catalogue()
	if err != nil {
		return nil, err
	}

	normalized := strings.ToUpper(strings.TrimSpace(algorithmString))

	if alg := cat.lookupInCategory(normalized, category); alg != nil {
		return alg, nil
	}
	if stripped := normalizeCipherComponent(normalized); stripped != normalized {
		if alg := cat.lookupInCategory(stripped, category); alg != nil {
			return alg, nil
		}
	}

	// Protocol versions get one more chance, because the spelling producers emit
	// and the spelling the catalogue codes are not related by separator removal
	// alone: pcap-processor reports SSLv3 as "SSL 3.0". (The spaced TLS forms —
	// "TLS 1.2" from the sensor's TLS enricher and the F5 interrogator — are
	// already handled a few lines up, by the space removal in
	// normalizeCipherComponent.) Without this, a protocol-version component
	// resolved to nothing and the RFC 8996 deprecation ladder never fired.
	if category == "protocol_version" {
		if alias := cryptoparse.NormalizeProtocolVersion(normalized); alias != "" {
			if alg := cat.lookupInCategory(alias, category); alg != nil {
				return alg, nil
			}
		}
	}

	matches := cat.substringMatches(normalized, category)
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		codes := make([]string, 0, len(matches))
		for _, m := range matches {
			codes = append(codes, m.Code)
		}
		log.Printf("[AlgorithmService] %q is ambiguous in category %q (matches %v) — leaving it unclassified rather than guessing",
			algorithmString, category, codes)
		return nil, nil
	}

	log.Printf("[AlgorithmService] %q is not in the algorithm catalogue (category %q) — leaving it unassessed",
		algorithmString, category)
	return nil, nil
}

// LinkAlgorithmToImplementation links an algorithm to a crypto implementation
func (s *AlgorithmService) LinkAlgorithmToImplementation(
	implID uuid.UUID,
	algorithmID uuid.UUID,
	algorithmType string,
	isInferred bool,
) error {
	insertQuery := `
		INSERT INTO crypto_implementation_algorithms (
			crypto_implementation_id, algorithm_id, algorithm_type, is_inferred
		) VALUES ($1, $2, $3, $4)
		ON CONFLICT (crypto_implementation_id, algorithm_id, algorithm_type) DO NOTHING
	`

	_, err := s.db.Exec(insertQuery, implID, algorithmID, algorithmType, isInferred)
	if err != nil {
		return fmt.Errorf("failed to link algorithm to implementation: %w", err)
	}

	return nil
}

// GetAlgorithmsByImplementation retrieves all algorithms linked to a crypto implementation
func (s *AlgorithmService) GetAlgorithmsByImplementation(implID uuid.UUID) ([]Algorithm, error) {
	return s.queryAlgorithms(
		fmt.Sprintf(`SELECT %s
			FROM algorithms a
			JOIN crypto_implementation_algorithms cia ON a.id = cia.algorithm_id
			WHERE cia.crypto_implementation_id = $1
			ORDER BY cia.algorithm_type, a.risk_score DESC`,
			prefixColumns("a", algorithmColumns)),
		implID,
	)
}

// GetAlgorithmsByCategory retrieves all algorithms in a category
func (s *AlgorithmService) GetAlgorithmsByCategory(category string) ([]Algorithm, error) {
	return s.queryAlgorithms(
		fmt.Sprintf(`SELECT %s FROM algorithms WHERE category = $1 ORDER BY risk_score DESC, code`, algorithmColumns),
		category,
	)
}

// queryAlgorithms executes a query and scans all rows into Algorithm structs.
func (s *AlgorithmService) queryAlgorithms(query string, args ...interface{}) ([]Algorithm, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query algorithms: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var algorithms []Algorithm
	for rows.Next() {
		alg, err := scanAlgorithmRow(rows)
		if err != nil {
			continue
		}
		algorithms = append(algorithms, *alg)
	}
	return algorithms, nil
}

// GetAllAlgorithms retrieves all algorithms with optional filters
func (s *AlgorithmService) GetAllAlgorithms() ([]Algorithm, error) {
	return s.queryAlgorithms(
		fmt.Sprintf(`SELECT %s FROM algorithms ORDER BY category, risk_score DESC, code`, algorithmColumns),
	)
}

// GetPQCAlgorithms retrieves all PQC algorithms
func (s *AlgorithmService) GetPQCAlgorithms() ([]Algorithm, error) {
	return s.queryAlgorithms(
		fmt.Sprintf(`SELECT %s FROM algorithms WHERE is_pqc = true ORDER BY pqc_standardization_status, category, risk_score DESC, code`, algorithmColumns),
	)
}

// GetNonPQCAlgorithms retrieves all non-PQC algorithms
func (s *AlgorithmService) GetNonPQCAlgorithms() ([]Algorithm, error) {
	return s.queryAlgorithms(
		fmt.Sprintf(`SELECT %s FROM algorithms WHERE is_pqc = false ORDER BY category, risk_score DESC, code`, algorithmColumns),
	)
}

// GetStandardizedPQCAlgorithms retrieves all NIST standardized PQC algorithms
func (s *AlgorithmService) GetStandardizedPQCAlgorithms() ([]Algorithm, error) {
	return s.queryAlgorithms(
		fmt.Sprintf(`SELECT %s FROM algorithms WHERE is_pqc = true AND pqc_standardization_status = 'standardized' ORDER BY category, risk_score DESC, code`, algorithmColumns),
	)
}

// CipherSuiteComponents is the canonical parsed shape of a cipher-suite name.
//
// The parser itself lives in shared/cryptoparse so that cbom-service (and, in
// time, the standalone sensor) resolve the same wire string to the same
// catalogue vocabulary. It used to be duplicated by hand into cbom-service and
// the copy drifted — see the package doc there. This alias keeps the many
// in-package references reading naturally.
type CipherSuiteComponents = cryptoparse.CipherSuiteComponents

// ParseCipherSuite parses a cipher suite name and extracts its components.
//
// It is a method for historical reasons only: the parse is pure string work and
// touches no service state. Catalogue RESOLUTION of the parsed components — the
// part that needs the database — stays here, in ClassifyAlgorithm.
func (s *AlgorithmService) ParseCipherSuite(cipherSuite string) (*CipherSuiteComponents, error) {
	return cryptoparse.ParseCipherSuite(cipherSuite)
}

// pqcMigrationTargets maps classical algorithm families to their PQC replacements
var pqcMigrationTargets = map[string]string{
	"RSA":   "ML-KEM",
	"ECDSA": "ML-DSA",
	"ECDH":  "ML-KEM",
	"DH":    "ML-KEM",
	"DSA":   "ML-DSA",
	"EdDSA": "ML-DSA",
}

// quantumSafeFamilyPrimitives marks the primitives that make an algorithm
// FAMILY quantum-safe, for the per-family breakdown only. The headline
// per-implementation classification does NOT use an allowlist — see
// quantumVulnerablePrimitives in pqc_readiness.go for why. Kept in sync with
// that denylist by TestPQC_FamilyAndImplementationViewsAgree.
var quantumSafeFamilyPrimitives = map[string]bool{
	"ae": true, "hash": true, "mac": true,
	"block-cipher": true, "stream-cipher": true, "xof": true,
}

// GetPQCProgress returns quantum-readiness across a tenant's crypto
// implementations.
//
// Two views, deliberately separated because they count different things:
//
//   - The headline counters (PQCReady / SymmetricSafe / NonPQC / Unclassified)
//     classify each IMPLEMENTATION exactly once, via the shared classifier that
//     /pqc/summary also uses. They partition the population, so PQCPercentage
//     is bounded by 100.
//
//   - ByFamily counts ALGORITHM FAMILIES and is a migration worklist ("RSA: 42
//     -> ML-KEM"). One implementation appears under several families, so these
//     counts intentionally sum past the implementation total.
//
// Mixing those units is what made the old percentage exceed 100%: it summed
// per-family counts over a per-implementation denominator.
func (s *AlgorithmService) GetPQCProgress(tenantID uuid.UUID) (*models.PQCProgress, error) {
	counts, err := classifyTenantImplementationsPQC(s.db, tenantID)
	if err != nil {
		return nil, err
	}

	progress := &models.PQCProgress{
		TotalImplementations: counts.Total,
		PQCReady:             counts.PQCReady,
		SymmetricSafe:        counts.SymmetricSafe,
		NonPQC:               counts.NeedsMigration,
		Unclassified:         counts.Unclassified,
		PQCPercentage:        counts.ReadyPercent(),
		ByFamily:             []models.PQCFamilyStats{},
	}

	// Per-family worklist. Restricted to real component roles for the same
	// reason the classifier is: protocol-version and cipher-suite container rows
	// are not algorithm families anyone migrates.
	const familyQuery = `
		SELECT COALESCE(NULLIF(a.algorithm_family, ''), 'Unknown') AS family,
		       a.is_pqc,
		       COALESCE(a.primitive, '') AS primitive,
		       COUNT(DISTINCT cia.crypto_implementation_id) AS impl_count
		  FROM crypto_implementation_algorithms cia
		  JOIN algorithms a ON a.id = cia.algorithm_id
		  JOIN crypto_implementations ci ON ci.id = cia.crypto_implementation_id
		 WHERE ci.tenant_id = $1 AND ci.deleted_at IS NULL
		   AND cia.algorithm_type = ANY($2)
		 GROUP BY family, a.is_pqc, a.primitive
		 ORDER BY impl_count DESC, family
	`

	// RLS-scoped read; the tenant boundary is crypto_implementations.
	err = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, e := tx.Query(familyQuery, tenantID, pq.Array(pqcComponentRoles))
		if e != nil {
			return fmt.Errorf("failed to query PQC family breakdown: %w", e)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var st models.PQCFamilyStats
			var primitive string
			if e := rows.Scan(&st.Family, &st.IsPQC, &primitive, &st.Count); e != nil {
				return fmt.Errorf("failed to scan PQC family row: %w", e)
			}
			st.QuantumSafe = st.IsPQC || quantumSafeFamilyPrimitives[primitive]
			if !st.QuantumSafe {
				if target, ok := pqcMigrationTargets[st.Family]; ok {
					st.MigrateTo = target
				}
			}
			progress.ByFamily = append(progress.ByFamily, st)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	return progress, nil
}
