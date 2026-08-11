package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// algorithmReader is the slice of *services.AlgorithmService the algorithm
// handlers depend on. Declaring it as an interface (the concrete service still
// satisfies it) lets the contract test drive the real handlers with an
// in-memory stub — no database — per the spec-first contract recipe (ADR-0001).
//
// Note: DB() leaks the raw *database.DB because GetAlgorithmRecommendations /
// GetAlgorithmUsage run inline SQL rather than going through a service method.
// It is here only so those (un-specced) handlers still compile against the
// interface; the contract-tested read handlers don't touch it.
type algorithmReader interface {
	GetAllAlgorithms() ([]services.Algorithm, error)
	GetAlgorithmsByCategory(category string) ([]services.Algorithm, error)
	GetPQCAlgorithms() ([]services.Algorithm, error)
	GetNonPQCAlgorithms() ([]services.Algorithm, error)
	GetStandardizedPQCAlgorithms() ([]services.Algorithm, error)
	GetAlgorithmByCode(code string) (*services.Algorithm, error)
	GetBatchRecommendations(algorithmCodes []string) (map[string]*services.Algorithm, []string, error)
	GetPQCProgress(tenantID uuid.UUID) (*models.PQCProgress, error)
	UpdateAlgorithmAssessment(code string, upd services.AlgorithmAssessmentUpdate) (*services.Algorithm, error)
	CreateAlgorithm(in services.AlgorithmCreate) (*services.Algorithm, error)
	DB() *database.DB
}

// validStrengths and validDeprecationStatuses mirror the schema CHECK
// constraints on the algorithms table (valid_strength / valid_deprecation_status).
var validStrengths = map[string]bool{
	"weak": true, "acceptable": true, "strong": true, "recommended": true,
}

var validDeprecationStatuses = map[string]bool{
	"current": true, "deprecated": true, "obsolete": true,
}

// validPQCStatuses / validCategories mirror the valid_pqc_status and
// valid_category schema CHECK constraints on the algorithms table.
var validPQCStatuses = map[string]bool{
	"none": true, "standardized": true, "candidate": true, "alternative": true,
}

var validCategories = map[string]bool{
	"hash": true, "symmetric": true, "key_exchange": true,
	"signature": true, "protocol_version": true, "cipher_suite": true,
}

type AlgorithmHandler struct {
	algorithmService algorithmReader
}

func NewAlgorithmHandler(algorithmService *services.AlgorithmService) *AlgorithmHandler {
	return &AlgorithmHandler{
		algorithmService: algorithmService,
	}
}

// ListAlgorithms handles GET /api/v1/inventory-service/algorithms
// Returns a list of algorithms with optional filters
func (h *AlgorithmHandler) ListAlgorithms(c *gin.Context) {
	// Parse query parameters
	category := c.Query("category")
	strength := c.Query("strength")
	deprecationStatus := c.Query("deprecation_status")
	pqc := c.Query("pqc")              // "true", "false", or empty for all
	pqcStatus := c.Query("pqc_status") // "standardized", "candidate", "alternative", "none"
	search := c.Query("search")

	// Get algorithms based on PQC filter
	var algorithms []services.Algorithm
	var err error

	// PQC-specific queries take priority
	if pqc == "true" {
		if pqcStatus == "standardized" {
			algorithms, err = h.algorithmService.GetStandardizedPQCAlgorithms()
		} else {
			algorithms, err = h.algorithmService.GetPQCAlgorithms()
		}
	} else if pqc == "false" {
		algorithms, err = h.algorithmService.GetNonPQCAlgorithms()
	} else if category != "" {
		algorithms, err = h.algorithmService.GetAlgorithmsByCategory(category)
	} else {
		algorithms, err = h.algorithmService.GetAllAlgorithms()
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve algorithms"})
		return
	}

	// Apply additional filters
	filtered := make([]services.Algorithm, 0)
	for _, alg := range algorithms {
		// Filter by strength
		if strength != "" && alg.Strength != strength {
			continue
		}

		// Filter by deprecation status
		if deprecationStatus != "" && alg.DeprecationStatus != deprecationStatus {
			continue
		}

		// Filter by PQC standardization status (if not already filtered)
		if pqcStatus != "" && alg.PQCStandardizationStatus != pqcStatus {
			continue
		}

		// Filter by search term (name or code)
		if search != "" {
			searchLower := strings.ToLower(search)
			nameLower := strings.ToLower(alg.Name)
			codeLower := strings.ToLower(alg.Code)
			if !strings.Contains(nameLower, searchLower) && !strings.Contains(codeLower, searchLower) {
				continue
			}
		}

		filtered = append(filtered, alg)
	}

	c.JSON(http.StatusOK, gin.H{
		"algorithms": filtered,
		"total":      len(filtered),
	})
}

// GetAlgorithmByCode handles GET /api/v1/inventory-service/algorithms/:code
// Returns a single algorithm by its code
func (h *AlgorithmHandler) GetAlgorithmByCode(c *gin.Context) {
	code := c.Param("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Algorithm code is required"})
		return
	}

	algorithm, err := h.algorithmService.GetAlgorithmByCode(code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve algorithm"})
		return
	}

	if algorithm == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Algorithm not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"algorithm": algorithm})
}

// GetAlgorithmRecommendations handles GET /api/v1/inventory-service/algorithms/:code/recommendations
// Returns recommendations for an algorithm
func (h *AlgorithmHandler) GetAlgorithmRecommendations(c *gin.Context) {
	code := c.Param("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Algorithm code is required"})
		return
	}

	algorithm, err := h.algorithmService.GetAlgorithmByCode(code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve algorithm"})
		return
	}

	if algorithm == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Algorithm not found"})
		return
	}

	// Build recommendations response
	recommendations := gin.H{
		"algorithm": algorithm,
		"recommendations": gin.H{
			"alternatives":       algorithm.RecommendedAlternatives,
			"migration_guidance": algorithm.MigrationGuidance,
			"risk_score":         algorithm.RiskScore,
			"strength":           algorithm.Strength,
			"deprecation_status": algorithm.DeprecationStatus,
		},
	}

	c.JSON(http.StatusOK, recommendations)
}

// GetBatchRecommendations handles POST /api/v1/inventory-service/algorithms/recommendations/batch
// Returns recommendations for multiple algorithms in a single request
func (h *AlgorithmHandler) GetBatchRecommendations(c *gin.Context) {
	var req struct {
		AlgorithmCodes []string `json:"algorithm_codes" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if len(req.AlgorithmCodes) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "algorithm_codes array cannot be empty"})
		return
	}

	// Limit batch size to prevent abuse
	if len(req.AlgorithmCodes) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Maximum 100 algorithm codes allowed per batch request"})
		return
	}

	recommendations, failed, err := h.algorithmService.GetBatchRecommendations(req.AlgorithmCodes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get batch recommendations"})
		return
	}

	// Format response to match individual recommendation format
	// Fetch full algorithm details for recommended alternatives
	recommendationsList := make([]gin.H, 0, len(recommendations))
	for code, alg := range recommendations {
		// Fetch recommended alternative algorithms
		alternatives := make([]*services.Algorithm, 0)
		for _, altCode := range alg.RecommendedAlternatives {
			if altAlg, err := h.algorithmService.GetAlgorithmByCode(altCode); err == nil && altAlg != nil {
				alternatives = append(alternatives, altAlg)
			}
		}

		// Determine priority
		priority := "low"
		if alg.RiskScore >= 80 {
			priority = "high"
		} else if alg.RiskScore >= 60 {
			priority = "high"
		} else if alg.RiskScore >= 40 {
			priority = "medium"
		}

		recommendationsList = append(recommendationsList, gin.H{
			"algorithm_code":           code,
			"current_algorithm":        alg,
			"recommended_alternatives": alternatives,
			"migration_guidance":       alg.MigrationGuidance,
			"risk_score":               alg.RiskScore,
			"strength":                 alg.Strength,
			"deprecation_status":       alg.DeprecationStatus,
			"priority":                 priority,
			"reason":                   fmt.Sprintf("Risk score: %d, Strength: %s", alg.RiskScore, alg.Strength),
		})
	}

	response := gin.H{
		"recommendations": recommendationsList,
	}

	// Include failed codes if any
	if len(failed) > 0 {
		response["failed"] = failed
	}

	c.JSON(http.StatusOK, response)
}

// GetAlgorithmUsage handles GET /api/v1/inventory-service/algorithms/:code/usage
// Returns usage statistics for an algorithm
func (h *AlgorithmHandler) GetAlgorithmUsage(c *gin.Context) {
	code := c.Param("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Algorithm code is required"})
		return
	}

	// Get algorithm
	algorithm, err := h.algorithmService.GetAlgorithmByCode(code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve algorithm"})
		return
	}

	if algorithm == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Algorithm not found"})
		return
	}

	// Query actual usage from crypto_implementations by matching the algorithm code
	// against cipher suite, key exchange, signature, symmetric encryption, and hash columns
	tenantID := c.GetString("tenant_id")

	var inUseCount, configuredCount int
	countQuery := `
		SELECT
			COUNT(DISTINCT ci.asset_id) as in_use_count,
			COUNT(ci.id) as configured_count
		FROM crypto_implementations ci
		WHERE ci.tenant_id = $1::uuid
		  AND ci.deleted_at IS NULL
		  AND (
			ci.cipher_suite ILIKE '%' || $2 || '%'
			OR ci.key_exchange_algorithm ILIKE '%' || $2 || '%'
			OR ci.signature_algorithm ILIKE '%' || $2 || '%'
			OR ci.symmetric_encryption ILIKE '%' || $2 || '%'
			OR ci.hash_algorithm ILIKE '%' || $2 || '%'
		  )
	`
	err = h.algorithmService.DB().QueryRow(countQuery, tenantID, algorithm.Code).Scan(&inUseCount, &configuredCount)
	if err != nil {
		inUseCount = 0
		configuredCount = 0
	}

	// Get the assets using this algorithm
	type assetUsage struct {
		AssetID  string  `json:"asset_id" db:"asset_id"`
		Hostname *string `json:"hostname" db:"hostname"`
		IP       *string `json:"ip_address" db:"ip_address"`
		Port     *int    `json:"port" db:"port"`
	}
	var assets []assetUsage
	assetsQuery := `
		SELECT DISTINCT na.id as asset_id, na.hostname, na.ip_address, na.port
		FROM crypto_implementations ci
		JOIN network_assets na ON ci.asset_id = na.id
		WHERE ci.tenant_id = $1::uuid
		  AND ci.deleted_at IS NULL
		  AND (
			ci.cipher_suite ILIKE '%' || $2 || '%'
			OR ci.key_exchange_algorithm ILIKE '%' || $2 || '%'
			OR ci.signature_algorithm ILIKE '%' || $2 || '%'
			OR ci.symmetric_encryption ILIKE '%' || $2 || '%'
			OR ci.hash_algorithm ILIKE '%' || $2 || '%'
		  )
		LIMIT 100
	`
	rows, err := h.algorithmService.DB().Queryx(assetsQuery, tenantID, algorithm.Code)
	if err == nil {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var a assetUsage
			if err := rows.StructScan(&a); err == nil {
				assets = append(assets, a)
			}
		}
	}
	if assets == nil {
		assets = []assetUsage{}
	}

	usage := gin.H{
		"algorithm": algorithm,
		"usage": gin.H{
			"in_use_count":     inUseCount,
			"configured_count": configuredCount,
			"assets":           assets,
		},
	}

	c.JSON(http.StatusOK, usage)
}

// GetPQCAlgorithms handles GET /api/v1/inventory-service/algorithms/pqc
// Returns all PQC algorithms
func (h *AlgorithmHandler) GetPQCAlgorithms(c *gin.Context) {
	algorithms, err := h.algorithmService.GetPQCAlgorithms()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve PQC algorithms"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"algorithms": algorithms,
		"total":      len(algorithms),
	})
}

// GetNonPQCAlgorithms handles GET /api/v1/inventory-service/algorithms/non-pqc
// Returns all non-PQC algorithms
func (h *AlgorithmHandler) GetNonPQCAlgorithms(c *gin.Context) {
	algorithms, err := h.algorithmService.GetNonPQCAlgorithms()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve non-PQC algorithms"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"algorithms": algorithms,
		"total":      len(algorithms),
	})
}

// GetStandardizedPQCAlgorithms handles GET /api/v1/inventory-service/algorithms/pqc/standardized
// Returns all NIST standardized PQC algorithms
func (h *AlgorithmHandler) GetStandardizedPQCAlgorithms(c *gin.Context) {
	algorithms, err := h.algorithmService.GetStandardizedPQCAlgorithms()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve standardized PQC algorithms"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"algorithms": algorithms,
		"total":      len(algorithms),
	})
}

// GetPQCProgress handles GET /api/v1/inventory-service/pqc/progress
// Returns quantum-readiness metrics across crypto implementations
func (h *AlgorithmHandler) GetPQCProgress(c *gin.Context) {
	tenantID, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantUUID, ok := tenantID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	progress, err := h.algorithmService.GetPQCProgress(tenantUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get PQC progress"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"progress": progress})
}

// updateAlgorithmRequest is the request body for UpdateAlgorithm. Only the
// editable assessment fields are accepted; identity/CycloneDX fields cannot be
// changed through this endpoint. All fields are optional — a field that is
// omitted (nil pointer) is left unchanged. recommended_alternatives, when
// supplied, replaces the existing list wholesale.
type updateAlgorithmRequest struct {
	Strength                 *string                `json:"strength"`
	RiskScore                *int                   `json:"risk_score"`
	DeprecationStatus        *string                `json:"deprecation_status"`
	DeprecationDate          *string                `json:"deprecation_date"`
	IsPQC                    *bool                  `json:"is_pqc"`
	PQCStandardizationStatus *string                `json:"pqc_standardization_status"`
	MigrationGuidance        *string                `json:"migration_guidance"`
	RecommendedAlternatives  []string               `json:"recommended_alternatives"`
	RemediationGuidance      map[string]interface{} `json:"remediation_guidance"`
	ComplianceMappings       map[string]interface{} `json:"compliance_mappings"`
}

// UpdateAlgorithm handles PUT /api/v{1,2}/inventory-service/algorithms/:code
// (operationId: updateAlgorithm).
//
// Gated on the algorithms.manage platform permission (RequirePlatformPermission)
// and audited: it edits the global crypto rating catalog (the algorithms table),
// the platform-wide crypto source of truth (ADR-0003 Phase 1). Only the
// assessment fields may change;
// identity/CycloneDX fields are immutable here. The before/after state is
// emitted to the audit log (resource_type "algorithm", resource_id = the
// algorithm's UUID, old_values/new_values).
func (h *AlgorithmHandler) UpdateAlgorithm(c *gin.Context) {
	code := c.Param("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Algorithm code is required"})
		return
	}

	var req updateAlgorithmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Validate against the schema CHECK constraints before touching the DB.
	if req.Strength != nil && !validStrengths[*req.Strength] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "strength must be one of: weak, acceptable, strong, recommended"})
		return
	}
	if req.DeprecationStatus != nil && !validDeprecationStatuses[*req.DeprecationStatus] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "deprecation_status must be one of: current, deprecated, obsolete"})
		return
	}
	if req.RiskScore != nil && (*req.RiskScore < 0 || *req.RiskScore > 100) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "risk_score must be between 0 and 100"})
		return
	}
	if req.PQCStandardizationStatus != nil && !validPQCStatuses[*req.PQCStandardizationStatus] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "pqc_standardization_status must be one of: none, standardized, candidate, alternative"})
		return
	}

	// Load current state for the audit before-image and to 404 unknown codes.
	before, err := h.algorithmService.GetAlgorithmByCode(code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve algorithm"})
		return
	}
	if before == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Algorithm not found"})
		return
	}

	updated, err := h.algorithmService.UpdateAlgorithmAssessment(code, services.AlgorithmAssessmentUpdate{
		Strength:                 req.Strength,
		RiskScore:                req.RiskScore,
		DeprecationStatus:        req.DeprecationStatus,
		DeprecationDate:          req.DeprecationDate,
		IsPQC:                    req.IsPQC,
		PQCStandardizationStatus: req.PQCStandardizationStatus,
		MigrationGuidance:        req.MigrationGuidance,
		RecommendedAlternatives:  req.RecommendedAlternatives,
		RemediationGuidance:      req.RemediationGuidance,
		ComplianceMappings:       req.ComplianceMappings,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update algorithm"})
		return
	}
	if updated == nil {
		// Raced with a delete between the read and the write.
		c.JSON(http.StatusNotFound, gin.H{"error": "Algorithm not found"})
		return
	}

	// Emit an audit entry capturing who changed what (before → after) on the
	// global crypto rating catalog. Only the editable assessment fields are
	// recorded; the algorithm's UUID is the resource_id and the code is carried
	// in metadata for human-readable correlation.
	resourceType := "algorithm"
	resourceID := updated.ID
	oldValues := map[string]interface{}{
		"strength":                   before.Strength,
		"risk_score":                 before.RiskScore,
		"deprecation_status":         before.DeprecationStatus,
		"deprecation_date":           before.DeprecationDate,
		"is_pqc":                     before.IsPQC,
		"pqc_standardization_status": before.PQCStandardizationStatus,
		"migration_guidance":         before.MigrationGuidance,
		"recommended_alternatives":   before.RecommendedAlternatives,
	}
	newValues := map[string]interface{}{
		"strength":                   updated.Strength,
		"risk_score":                 updated.RiskScore,
		"deprecation_status":         updated.DeprecationStatus,
		"deprecation_date":           updated.DeprecationDate,
		"is_pqc":                     updated.IsPQC,
		"pqc_standardization_status": updated.PQCStandardizationStatus,
		"migration_guidance":         updated.MigrationGuidance,
		"recommended_alternatives":   updated.RecommendedAlternatives,
	}
	changedFields := make([]string, 0, len(oldValues))
	for field := range oldValues {
		if fmt.Sprintf("%v", oldValues[field]) != fmt.Sprintf("%v", newValues[field]) {
			changedFields = append(changedFields, field)
		}
	}
	logAuditActivity(c,
		"configuration.algorithm.updated",
		"configuration",
		"update",
		&resourceType,
		&resourceID,
		oldValues,
		newValues,
		changedFields,
		map[string]interface{}{"algorithm_code": updated.Code},
	)

	c.JSON(http.StatusOK, gin.H{"algorithm": updated})
}

// createAlgorithmRequest is the request body for CreateAlgorithm. code, name and
// category are required; all other fields are optional and fall back to the
// algorithms-table column defaults.
type createAlgorithmRequest struct {
	// Identity / classification
	Code                     string   `json:"code"`
	Name                     string   `json:"name"`
	Category                 string   `json:"category"`
	Subcategory              *string  `json:"subcategory"`
	Description              *string  `json:"description"`
	AlgorithmFamily          *string  `json:"algorithm_family"`
	Primitive                *string  `json:"primitive"`
	Mode                     *string  `json:"mode"`
	Padding                  *string  `json:"padding"`
	OID                      *string  `json:"oid"`
	CryptoFunctions          []string `json:"crypto_functions"`
	ClassicalSecurityLevel   *int     `json:"classical_security_level"`
	NistQuantumSecurityLevel *int     `json:"nist_quantum_security_level"`
	ParameterSetIdentifier   *string  `json:"parameter_set_identifier"`
	Curve                    *string  `json:"curve"`
	IsStandard               *bool    `json:"is_standard"`
	// Assessment
	Strength                 *string                `json:"strength"`
	RiskScore                *int                   `json:"risk_score"`
	DeprecationStatus        *string                `json:"deprecation_status"`
	DeprecationDate          *string                `json:"deprecation_date"`
	IsPQC                    *bool                  `json:"is_pqc"`
	PQCStandardizationStatus *string                `json:"pqc_standardization_status"`
	MigrationGuidance        *string                `json:"migration_guidance"`
	RecommendedAlternatives  []string               `json:"recommended_alternatives"`
	RemediationGuidance      map[string]interface{} `json:"remediation_guidance"`
	ComplianceMappings       map[string]interface{} `json:"compliance_mappings"`
}

// CreateAlgorithm handles POST /api/v{1,2}/inventory-service/algorithms
// (operationId: createAlgorithm).
//
// Gated on the algorithms.manage platform permission and audited. Creates a new
// row in the global crypto rating catalog (the algorithms table). code/name/
// category are required; a duplicate code returns 409. The same enum validation
// as UpdateAlgorithm applies to the assessment fields, plus category and
// pqc_standardization_status validation against their schema CHECK constraints.
func (h *AlgorithmHandler) CreateAlgorithm(c *gin.Context) {
	var req createAlgorithmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	req.Code = strings.TrimSpace(req.Code)
	req.Name = strings.TrimSpace(req.Name)
	req.Category = strings.TrimSpace(req.Category)

	if req.Code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code is required"})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if req.Category == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "category is required"})
		return
	}
	if !validCategories[req.Category] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "category must be one of: hash, symmetric, key_exchange, signature, protocol_version, cipher_suite"})
		return
	}

	// Assessment enum validation (same constraints as UpdateAlgorithm).
	if req.Strength != nil && !validStrengths[*req.Strength] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "strength must be one of: weak, acceptable, strong, recommended"})
		return
	}
	if req.DeprecationStatus != nil && !validDeprecationStatuses[*req.DeprecationStatus] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "deprecation_status must be one of: current, deprecated, obsolete"})
		return
	}
	if req.RiskScore != nil && (*req.RiskScore < 0 || *req.RiskScore > 100) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "risk_score must be between 0 and 100"})
		return
	}
	if req.PQCStandardizationStatus != nil && !validPQCStatuses[*req.PQCStandardizationStatus] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "pqc_standardization_status must be one of: none, standardized, candidate, alternative"})
		return
	}

	created, err := h.algorithmService.CreateAlgorithm(services.AlgorithmCreate{
		Code:                     req.Code,
		Name:                     req.Name,
		Category:                 req.Category,
		Subcategory:              req.Subcategory,
		Description:              req.Description,
		AlgorithmFamily:          req.AlgorithmFamily,
		Primitive:                req.Primitive,
		Mode:                     req.Mode,
		Padding:                  req.Padding,
		OID:                      req.OID,
		CryptoFunctions:          req.CryptoFunctions,
		ClassicalSecurityLevel:   req.ClassicalSecurityLevel,
		NistQuantumSecurityLevel: req.NistQuantumSecurityLevel,
		ParameterSetIdentifier:   req.ParameterSetIdentifier,
		Curve:                    req.Curve,
		IsStandard:               req.IsStandard,
		Strength:                 req.Strength,
		RiskScore:                req.RiskScore,
		DeprecationStatus:        req.DeprecationStatus,
		DeprecationDate:          req.DeprecationDate,
		IsPQC:                    req.IsPQC,
		PQCStandardizationStatus: req.PQCStandardizationStatus,
		MigrationGuidance:        req.MigrationGuidance,
		RecommendedAlternatives:  req.RecommendedAlternatives,
		RemediationGuidance:      req.RemediationGuidance,
		ComplianceMappings:       req.ComplianceMappings,
	})
	if err == services.ErrAlgorithmExists {
		c.JSON(http.StatusConflict, gin.H{"error": "An algorithm with this code already exists"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create algorithm"})
		return
	}

	// Audit: record the new algorithm's identity + assessment.
	resourceType := "algorithm"
	resourceID := created.ID
	newValues := map[string]interface{}{
		"code":                       created.Code,
		"name":                       created.Name,
		"category":                   created.Category,
		"strength":                   created.Strength,
		"risk_score":                 created.RiskScore,
		"deprecation_status":         created.DeprecationStatus,
		"is_pqc":                     created.IsPQC,
		"pqc_standardization_status": created.PQCStandardizationStatus,
	}
	logAuditActivity(c,
		"configuration.algorithm.created",
		"configuration",
		"create",
		&resourceType,
		&resourceID,
		map[string]interface{}{},
		newValues,
		[]string{"code", "name", "category"},
		map[string]interface{}{"algorithm_code": created.Code},
	)

	c.JSON(http.StatusCreated, gin.H{"algorithm": created})
}
