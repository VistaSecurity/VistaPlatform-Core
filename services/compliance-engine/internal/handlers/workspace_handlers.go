package handlers

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// findingsStore is the slice of *services.FindingsService the finding handlers
// depend on. Declaring it as an interface (the concrete service still satisfies
// it) lets the contract test drive the real handlers with an in-memory stub —
// no database — per the spec-first contract recipe (ADR-0001). It is the union
// of every findingsService method the workspace handlers call.
type findingsStore interface {
	ListFindings(tenantID uuid.UUID, filters services.FindingListFilters, page, pageSize int) ([]models.ComplianceFinding, int, error)
	AssignFindingOwner(tenantID, findingID, assignedTo, assignedBy uuid.UUID, notes *string) error
	UnassignFindingOwner(tenantID, findingID uuid.UUID) error
	GetFinding(tenantID, findingID uuid.UUID) (*models.ComplianceFinding, error)
	GetFindingsByAsset(tenantID, assetID uuid.UUID) ([]models.ComplianceFinding, error)
	GetFindingStatistics(tenantID uuid.UUID) (*services.FindingStatistics, error)
	GetFindingsByControl(tenantID uuid.UUID, limit int) ([]services.FindingsByControlGroup, error)
	GetEvidenceID(tenantID, findingID uuid.UUID) (string, string, error)
	UpdateWorkflowStatus(tenantID, findingID, changedBy uuid.UUID, workflowStatus string, suppressionReason *string, suppressedUntil *time.Time) error
	GetFindingHistory(tenantID, findingID uuid.UUID) ([]models.ComplianceFindingHistory, error)
}

// scenarioStore / overrideStore are the slices of *services.ScenarioService /
// *services.OverrideService the workspace handlers depend on — same
// interface-for-testability pattern as findingsStore (ADR-0001). Each is the
// union of every method its handlers call; the concrete services satisfy them.
type scenarioStore interface {
	CreateScenario(tenantID, userID uuid.UUID, name string, frameworkID uuid.UUID, frameworkVersion string, filters models.ScenarioFilters) (*models.Scenario, error)
	UpdateScenario(tenantID, scenarioID, userID uuid.UUID, name string, filters models.ScenarioFilters) (*models.Scenario, error)
	GetScenario(tenantID, scenarioID uuid.UUID) (*models.Scenario, error)
	ListScenarios(tenantID uuid.UUID) ([]models.Scenario, error)
	DeleteScenario(tenantID, scenarioID uuid.UUID) error
	CheckScenarioNameExists(tenantID uuid.UUID, name string, excludeID *uuid.UUID) (bool, error)
}

type overrideStore interface {
	CreateOverride(tenantID, userID uuid.UUID, scenarioID *uuid.UUID, controlID uuid.UUID, overrideType models.OverrideType, severityFrom, severityTo *string, rationale, frameworkType string) (*models.Override, error)
	ListOverrides(tenantID uuid.UUID, scenarioID *uuid.UUID) ([]models.Override, error)
	DeleteOverride(tenantID, overrideID uuid.UUID) error
}

// evaluationStore is the slice of *services.EvaluationService the workspace
// handlers depend on — same interface-for-testability pattern as the stores
// above (ADR-0001). It is the union of every evaluationService method the
// workspace handlers call; the concrete *services.EvaluationService satisfies
// it, so production wiring is untouched. Declaring it lets the contract test
// drive the score / status / multi-framework-evaluate handlers with an
// in-memory stub — no database.
type evaluationStore interface {
	EvaluateFramework(tenantID, frameworkID uuid.UUID, version string, filters models.ScenarioFilters, scenarioID *uuid.UUID) (*services.SummaryResponse, error)
	EvaluateMultipleFrameworks(tenantID uuid.UUID, frameworkIDs []uuid.UUID, frameworkVersions map[string]string, filters models.ScenarioFilters, entityType string) ([]services.MultiFrameworkEvaluationResult, error)
	GetComplianceScore(tenantID uuid.UUID, frameworkID *uuid.UUID) (*services.ComplianceScoreResponse, error)
	GetControlDetails(tenantID, controlID uuid.UUID, scenarioID *uuid.UUID, filters models.ScenarioFilters, page, pageSize int) (*services.ControlDetailsResponse, error)
	GetControlDetailsTotalCount(tenantID, controlID uuid.UUID, filters models.ScenarioFilters) (int, error)
	GetFrameworkStatus(tenantID uuid.UUID) (*services.FrameworkStatusResponse, error)
	ResolveControlID(controlIDStr, frameworkIDStr string) (uuid.UUID, error)
}

// WorkspaceHandlers contains workspace-related handlers
type WorkspaceHandlers struct {
	evaluationService evaluationStore
	scenarioService   scenarioStore
	overrideService   overrideStore
	findingsService   findingsStore
}

// NewWorkspaceHandlers creates a new instance of workspace handlers
func NewWorkspaceHandlers(evaluationService *services.EvaluationService, scenarioService *services.ScenarioService, overrideService *services.OverrideService, findingsService *services.FindingsService) *WorkspaceHandlers {
	return &WorkspaceHandlers{
		evaluationService: evaluationService,
		scenarioService:   scenarioService,
		overrideService:   overrideService,
		findingsService:   findingsService,
	}
}

// GetSummary returns compliance summary for a framework with filters and overrides
func (h *WorkspaceHandlers) GetSummary(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	// Parse query parameters
	frameworkIDStr := c.Query("framework_id")
	if frameworkIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "framework_id is required"})
		return
	}

	frameworkID, err := uuid.Parse(frameworkIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid framework_id"})
		return
	}

	frameworkVersion := c.Query("framework_version")
	scenarioIDStr := c.Query("scenario_id")

	// Parse filters
	filters := models.ScenarioFilters{
		Environment:    c.Query("environment"),
		Severity:       c.Query("severity"),
		EncryptionOnly: c.Query("encryption_only") == "true",
		Owner:          c.Query("owner"),
	}

	// Parse tags
	if tagsStr := c.Query("tags"); tagsStr != "" {
		// Simple comma-separated tags for now
		filters.Tags = []string{tagsStr} // TODO: Parse comma-separated values
	}

	// Parse scenario ID if provided
	var scenarioID *uuid.UUID
	if scenarioIDStr != "" {
		parsedScenarioID, err := uuid.Parse(scenarioIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scenario_id"})
			return
		}
		scenarioID = &parsedScenarioID
	}

	// Get summary from evaluation service
	summary, err := h.evaluationService.EvaluateFramework(tenantUUID, frameworkID, frameworkVersion, filters, scenarioID)
	if err != nil {
		// An unknown framework_id is a client problem (commonly a stale
		// reference cached in the browser from a prior seed run), not a
		// server fault — return 404 so the UI can recover gracefully
		// instead of surfacing a 500.
		if errors.Is(err, services.ErrFrameworkNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Framework not found"})
			return
		}
		// Log genuine evaluation failures for debugging.
		fmt.Printf("ERROR: Failed to evaluate framework %s for tenant %s: %v\n", frameworkID, tenantUUID, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to evaluate framework",
		})
		return
	}

	c.JSON(http.StatusOK, summary)
}

// GetControlDetails returns detailed information for a specific control
func (h *WorkspaceHandlers) GetControlDetails(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	controlIDStr := c.Param("id")
	frameworkIDStr := c.Query("framework_id")
	controlID, err := uuid.Parse(controlIDStr)
	if err != nil {
		// Not a UUID — try resolving string control_id (e.g., "BP-002") to UUID
		resolvedID, resolveErr := h.evaluationService.ResolveControlID(controlIDStr, frameworkIDStr)
		if resolveErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid control ID"})
			return
		}
		controlID = resolvedID
	}

	// Parse query parameters
	scenarioIDStr := c.Query("scenario_id")
	var scenarioID *uuid.UUID
	if scenarioIDStr != "" {
		if id, err := uuid.Parse(scenarioIDStr); err == nil {
			scenarioID = &id
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scenario_id"})
			return
		}
	}

	// Parse filters
	filters := models.ScenarioFilters{
		Environment:    c.Query("environment"),
		Severity:       c.Query("severity"),
		EncryptionOnly: c.Query("encryption_only") == "true",
		Owner:          c.Query("owner"),
	}

	// Parse pagination
	page := 1
	pageSize := 25
	if pageStr := c.Query("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}
	if pageSizeStr := c.Query("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	// Get control details from evaluation service
	details, err := h.evaluationService.GetControlDetails(tenantUUID, controlID, scenarioID, filters, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get control details",
		})
		return
	}

	// Get total findings count for pagination
	totalFindings, err := h.evaluationService.GetControlDetailsTotalCount(tenantUUID, controlID, filters)
	if err != nil {
		// Fallback to estimated count
		totalFindings = len(details.Findings) + (page-1)*pageSize
	}

	c.JSON(http.StatusOK, gin.H{
		"control":          details.Control,
		"rationale":        details.Rationale,
		"evidence_summary": details.EvidenceSummary,
		"findings":         details.Findings,
		"overrides":        details.Overrides,
		"pagination": gin.H{
			"page":      page,
			"page_size": pageSize,
			"total":     totalFindings,
		},
	})
}

// CreateScenario creates a new compliance scenario
func (h *WorkspaceHandlers) CreateScenario(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	userUUID, ok := sharedmw.GetUserIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return
	}

	// Parse request body
	var input struct {
		Name             string                 `json:"name" binding:"required"`
		FrameworkID      string                 `json:"framework_id" binding:"required"`
		FrameworkVersion string                 `json:"framework_version" binding:"required"`
		Filters          models.ScenarioFilters `json:"filters"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	// Parse framework ID
	frameworkID, err := uuid.Parse(input.FrameworkID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid framework_id"})
		return
	}

	// Check if scenario name already exists
	nameTaken, err := h.scenarioService.CheckScenarioNameExists(tenantUUID, input.Name, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to check scenario name",
		})
		return
	}

	if nameTaken {
		c.JSON(http.StatusConflict, gin.H{"error": "Scenario name already exists"})
		return
	}

	// Create scenario
	scenario, err := h.scenarioService.CreateScenario(tenantUUID, userUUID, input.Name, frameworkID, input.FrameworkVersion, input.Filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create scenario",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":  "Scenario created successfully",
		"scenario": scenario,
	})
}

// UpdateScenario updates an existing scenario
func (h *WorkspaceHandlers) UpdateScenario(c *gin.Context) {
	userUUID, ok := sharedmw.GetUserIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return
	}

	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	// Parse scenario ID
	scenarioIDStr := c.Param("id")
	scenarioID, err := uuid.Parse(scenarioIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scenario ID"})
		return
	}

	// Parse request body
	var input struct {
		Name    string                 `json:"name" binding:"required"`
		Filters models.ScenarioFilters `json:"filters"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	// Update scenario
	scenario, err := h.scenarioService.UpdateScenario(tenantUUID, scenarioID, userUUID, input.Name, input.Filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update scenario",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "Scenario updated successfully",
		"scenario": scenario,
	})
}

// GetScenario retrieves a specific scenario
func (h *WorkspaceHandlers) GetScenario(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	// Parse scenario ID
	scenarioIDStr := c.Param("id")
	scenarioID, err := uuid.Parse(scenarioIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scenario ID"})
		return
	}

	// Get scenario
	scenario, err := h.scenarioService.GetScenario(tenantUUID, scenarioID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Scenario not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"scenario": scenario})
}

// ListScenarios retrieves all scenarios for a tenant
func (h *WorkspaceHandlers) ListScenarios(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	// Get scenarios
	scenarios, err := h.scenarioService.ListScenarios(tenantUUID)
	if err != nil {
		// Log error for debugging but return empty array instead of 500
		// This allows the UI to load even if database is temporarily unavailable
		log.Printf("⚠️  Error listing scenarios for tenant %s: %v", tenantUUID, err)
		c.JSON(http.StatusOK, gin.H{"scenarios": []interface{}{}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"scenarios": scenarios})
}

// DeleteScenario deletes a scenario
func (h *WorkspaceHandlers) DeleteScenario(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	// Parse scenario ID
	scenarioIDStr := c.Param("id")
	scenarioID, err := uuid.Parse(scenarioIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scenario ID"})
		return
	}

	// Delete scenario
	err = h.scenarioService.DeleteScenario(tenantUUID, scenarioID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete scenario",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Scenario deleted successfully"})
}

// CreateOverride creates a new compliance override
func (h *WorkspaceHandlers) CreateOverride(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	userUUID, ok := sharedmw.GetUserIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return
	}

	// Parse request body
	var input struct {
		ScenarioID    *string `json:"scenario_id"`
		ControlID     string  `json:"control_id" binding:"required"`
		OverrideType  string  `json:"override_type" binding:"required"`
		SeverityFrom  *string `json:"severity_from"`
		SeverityTo    *string `json:"severity_to"`
		Rationale     string  `json:"rationale" binding:"required"`
		FrameworkType string  `json:"framework_type"` // "platform" or "tenant" (defaults to "platform")
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	// Parse control ID
	controlID, err := uuid.Parse(input.ControlID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid control_id"})
		return
	}

	// Parse scenario ID if provided
	var scenarioID *uuid.UUID
	if input.ScenarioID != nil {
		parsedScenarioID, err := uuid.Parse(*input.ScenarioID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scenario_id"})
			return
		}
		scenarioID = &parsedScenarioID
	}

	// Parse override type
	overrideType := models.OverrideType(input.OverrideType)
	if !overrideType.IsValid() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid override_type"})
		return
	}

	// Default framework_type to "platform" for new overrides
	frameworkType := input.FrameworkType
	if frameworkType == "" {
		frameworkType = "platform"
	}

	// Create override
	override, err := h.overrideService.CreateOverride(tenantUUID, userUUID, scenarioID, controlID, overrideType, input.SeverityFrom, input.SeverityTo, input.Rationale, frameworkType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create override",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":  "Override created successfully",
		"override": override,
	})
}

// ListOverrides retrieves overrides for a tenant
func (h *WorkspaceHandlers) ListOverrides(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	// Parse scenario ID if provided
	scenarioIDStr := c.Query("scenario_id")
	var scenarioID *uuid.UUID
	if scenarioIDStr != "" {
		parsedScenarioID, err := uuid.Parse(scenarioIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scenario_id"})
			return
		}
		scenarioID = &parsedScenarioID
	}

	// Get overrides
	overrides, err := h.overrideService.ListOverrides(tenantUUID, scenarioID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to list overrides",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"overrides": overrides})
}

// DeleteOverride deletes an override
func (h *WorkspaceHandlers) DeleteOverride(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	// Parse override ID
	overrideIDStr := c.Param("id")
	overrideID, err := uuid.Parse(overrideIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid override ID"})
		return
	}

	// Delete override
	err = h.overrideService.DeleteOverride(tenantUUID, overrideID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete override",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Override deleted successfully"})
}

// GetComplianceScore returns the overall compliance score across all frameworks
// Optional query parameter: framework_id - if provided, calculates score for that specific framework
// Otherwise uses tenant's default framework
func (h *WorkspaceHandlers) GetComplianceScore(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	// Parse optional framework_id query parameter
	var frameworkID *uuid.UUID
	if frameworkIDStr := c.Query("framework_id"); frameworkIDStr != "" {
		parsedID, err := uuid.Parse(frameworkIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid framework_id format"})
			return
		}
		frameworkID = &parsedID
	}

	score, err := h.evaluationService.GetComplianceScore(tenantUUID, frameworkID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to calculate compliance score",
		})
		return
	}

	c.JSON(http.StatusOK, score)
}

// EvaluateMultipleFrameworks evaluates multiple frameworks simultaneously
func (h *WorkspaceHandlers) EvaluateMultipleFrameworks(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	// Parse request body
	var input struct {
		FrameworkIDs      []string               `json:"framework_ids" binding:"required"`
		FrameworkVersions map[string]string      `json:"framework_versions"`
		Filters           models.ScenarioFilters `json:"filters"`
		EntityType        string                 `json:"entity_type"` // certificates, algorithms, systems, network
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	if len(input.FrameworkIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one framework_id is required"})
		return
	}

	// Parse framework IDs
	frameworkUUIDs := make([]uuid.UUID, 0, len(input.FrameworkIDs))
	for _, idStr := range input.FrameworkIDs {
		id, err := uuid.Parse(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid framework_id",
				"details": fmt.Sprintf("Invalid UUID: %s", idStr),
			})
			return
		}
		frameworkUUIDs = append(frameworkUUIDs, id)
	}

	// Evaluate multiple frameworks
	results, err := h.evaluationService.EvaluateMultipleFrameworks(tenantUUID, frameworkUUIDs, input.FrameworkVersions, input.Filters, input.EntityType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to evaluate frameworks",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"results": results,
		"count":   len(results),
	})
}

// GetFrameworkStatus returns compliance status for all active frameworks
func (h *WorkspaceHandlers) GetFrameworkStatus(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	status, err := h.evaluationService.GetFrameworkStatus(tenantUUID)
	if err != nil {
		log.Printf("⚠️ GetFrameworkStatus: Service error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get framework status",
		})
		return
	}

	c.JSON(http.StatusOK, status)
}

// AssignFindingOwner assigns a user to a finding
func (h *WorkspaceHandlers) AssignFindingOwner(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	userUUID, ok := sharedmw.GetUserIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return
	}

	// Parse finding ID
	findingIDStr := c.Param("id")
	findingID, err := uuid.Parse(findingIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid finding ID"})
		return
	}

	// Parse request body
	var input struct {
		AssignedTo string  `json:"assigned_to" binding:"required"`
		Notes      *string `json:"notes"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	assignedToUUID, err := uuid.Parse(input.AssignedTo)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid assigned_to UUID"})
		return
	}

	// Assign finding
	err = h.findingsService.AssignFindingOwner(tenantUUID, findingID, assignedToUUID, userUUID, input.Notes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to assign finding owner",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Finding assigned successfully"})
}

// UnassignFindingOwner removes assignment from a finding
func (h *WorkspaceHandlers) UnassignFindingOwner(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	// Parse finding ID
	findingIDStr := c.Param("id")
	findingID, err := uuid.Parse(findingIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid finding ID"})
		return
	}

	// Unassign finding
	err = h.findingsService.UnassignFindingOwner(tenantUUID, findingID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to unassign finding owner",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Finding unassigned successfully"})
}

// GetEvidenceId returns a copyable evidence ID for a finding
func (h *WorkspaceHandlers) GetEvidenceId(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	// Parse finding ID
	findingIDStr := c.Param("id")
	findingID, err := uuid.Parse(findingIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid finding ID"})
		return
	}

	// Get finding to verify it exists and belongs to tenant
	_, err = h.findingsService.GetFinding(tenantUUID, findingID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Finding not found",
		})
		return
	}

	// Get evidence ID using service method
	evidenceID, evidenceRef, err := h.findingsService.GetEvidenceID(tenantUUID, findingID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get evidence ID",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"evidence_id":  evidenceID,
		"evidence_ref": evidenceRef,
		"copyable":     true,
	})
}

// UpdateFindingWorkflowStatus updates the workflow status of a finding
func (h *WorkspaceHandlers) UpdateFindingWorkflowStatus(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	// Get user ID from context
	userIDStr, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Parse finding ID
	findingIDStr := c.Param("id")
	findingID, err := uuid.Parse(findingIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid finding ID"})
		return
	}

	// Parse request body
	var req struct {
		WorkflowStatus    string  `json:"workflow_status" binding:"required"`
		SuppressionReason *string `json:"suppression_reason,omitempty"`
		SuppressedUntil   *string `json:"suppressed_until,omitempty"` // ISO 8601 timestamp
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Parse suppressed_until if provided
	var suppressedUntil *time.Time
	if req.SuppressedUntil != nil {
		parsed, err := time.Parse(time.RFC3339, *req.SuppressedUntil)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid suppressed_until format (use ISO 8601)"})
			return
		}
		suppressedUntil = &parsed
	}

	// Update workflow status
	err = h.findingsService.UpdateWorkflowStatus(tenantUUID, findingID, userID, req.WorkflowStatus, req.SuppressionReason, suppressedUntil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update workflow status",
		})
		return
	}

	// Get updated finding
	finding, err := h.findingsService.GetFinding(tenantUUID, findingID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get updated finding",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"finding": finding})
}

// GetFindingHistory retrieves the history of a finding
func (h *WorkspaceHandlers) GetFindingHistory(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	// Parse finding ID
	findingIDStr := c.Param("id")
	findingID, err := uuid.Parse(findingIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid finding ID"})
		return
	}

	// Get history
	history, err := h.findingsService.GetFindingHistory(tenantUUID, findingID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get finding history",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"history": history})
}

// ListFindings returns a paginated, filterable tenant-wide findings list
// (). Filters: workflow_status, severity, assigned_to, unassigned,
// control_id, framework_id. Joined asset detail rides on each finding so the
// caller can render rows without per-asset fetches.
func (h *WorkspaceHandlers) ListFindings(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))

	filters := services.FindingListFilters{
		WorkflowStatus: c.Query("workflow_status"),
		Severity:       c.Query("severity"),
		Unassigned:     c.Query("unassigned") == "true",
	}
	if v := c.Query("assigned_to"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid assigned_to"})
			return
		}
		filters.AssignedTo = &id
	}
	if v := c.Query("control_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid control_id"})
			return
		}
		filters.ControlID = &id
	}
	if v := c.Query("framework_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid framework_id"})
			return
		}
		filters.FrameworkID = &id
	}

	findings, total, err := h.findingsService.ListFindings(tenantUUID, filters, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list findings"})
		return
	}

	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 50
	}
	if pageSize > 200 {
		pageSize = 200
	}
	c.JSON(http.StatusOK, gin.H{"findings": findings, "total": total, "page": page, "page_size": pageSize})
}

// GetFindingsByAsset retrieves all findings for a specific asset
func (h *WorkspaceHandlers) GetFindingsByAsset(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	// Parse asset ID
	assetIDStr := c.Param("assetId")
	assetID, err := uuid.Parse(assetIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset ID"})
		return
	}

	// Get findings
	findings, err := h.findingsService.GetFindingsByAsset(tenantUUID, assetID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get findings",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"findings": findings})
}

// GetFindingStatistics returns aggregated statistics for findings
func (h *WorkspaceHandlers) GetFindingStatistics(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	// Get statistics
	stats, err := h.findingsService.GetFindingStatistics(tenantUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get finding statistics",
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// GetFindingsByControl returns active findings grouped by framework control,
// ranked worst-severity → count → affected-assets (ADR-0007 item 4). Backs the
// Posture "top exposures" list. `?limit=` defaults to 5 (capped at 50).
func (h *WorkspaceHandlers) GetFindingsByControl(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	limit := 5
	if v, err := strconv.Atoi(c.DefaultQuery("limit", "5")); err == nil && v > 0 {
		limit = v
	}

	groups, err := h.findingsService.GetFindingsByControl(tenantUUID, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get findings by control"})
		return
	}
	if groups == nil {
		groups = []services.FindingsByControlGroup{} // serialize [] not null (schema: required array)
	}

	c.JSON(http.StatusOK, gin.H{"groups": groups})
}
