package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// OnboardingStep represents a step in the onboarding workflow
type OnboardingStep struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Order       int        `json:"order"`
	Required    bool       `json:"required"`
	Status      string     `json:"status"` // "pending", "completed", "skipped"
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	SkippedAt   *time.Time `json:"skipped_at,omitempty"`
}

// OnboardingWorkflow represents the full onboarding workflow
type OnboardingWorkflow struct {
	ID    string           `json:"id"`
	Name  string           `json:"name"`
	Steps []OnboardingStep `json:"steps"`
}

// OnboardingProgress represents user's onboarding progress
type OnboardingProgress struct {
	UserID                string           `json:"user_id"`
	TenantID              string           `json:"tenant_id"`
	OnboardingCompleted   bool             `json:"onboarding_completed"`
	OnboardingCompletedAt *time.Time       `json:"onboarding_completed_at,omitempty"`
	Progress              ProgressInfo     `json:"progress"`
	Steps                 []OnboardingStep `json:"steps"`
}

// ProgressInfo represents progress statistics
type ProgressInfo struct {
	CompletedSteps    int     `json:"completed_steps"`
	TotalSteps        int     `json:"total_steps"`
	RequiredCompleted int     `json:"required_completed"`
	RequiredTotal     int     `json:"required_total"`
	Percentage        float64 `json:"percentage"`
}

// CompleteStepRequest represents a request to complete a step
type CompleteStepRequest struct {
	Data map[string]interface{} `json:"data,omitempty"`
}

// StepResponse represents a step completion/skip response
type StepResponse struct {
	Message   string         `json:"message"`
	Step      OnboardingStep `json:"step"`
	Progress  ProgressInfo   `json:"progress"`
	Completed bool           `json:"onboarding_complete"`
}

// GetOnboardingWorkflow handles GET /onboarding/workflow - Get onboarding workflow
func GetOnboardingWorkflow(db *sql.DB, bypassDB *sql.DB) gin.HandlerFunc {
	return GetOnboardingWorkflowWithStore(newOnboardingRepo(db, bypassDB))
}

// GetOnboardingWorkflowWithStore is the store-backed implementation of
// GetOnboardingWorkflow, exercised directly by the contract test.
func GetOnboardingWorkflowWithStore(store onboardingStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from context
		tenantIDStr := c.GetString("tenantID")
		if tenantIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
			return
		}

		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		// Get user ID from context
		userIDStr := c.GetString("userID")
		if userIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
			return
		}

		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}

		// Get workflow (tenant-specific or default)
		workflowID, workflowName, stepsJSON, err := store.GetOnboardingWorkflowConfig(c.Request.Context(), tenantID)

		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Onboarding workflow not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch workflow"})
			return
		}

		// Parse steps
		var rawSteps []map[string]interface{}
		if err := json.Unmarshal(stepsJSON, &rawSteps); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse workflow steps"})
			return
		}

		// Get user's progress
		completedStepsJSON, skippedStepsJSON, err := store.GetUserWorkflowProgress(c.Request.Context(), userID, workflowID)

		completedSteps := make(map[string]bool)
		skippedSteps := make(map[string]bool)

		if err == nil {
			var completed []string
			var skipped []string
			_ = json.Unmarshal(completedStepsJSON, &completed)
			_ = json.Unmarshal(skippedStepsJSON, &skipped)

			for _, stepID := range completed {
				completedSteps[stepID] = true
			}
			for _, stepID := range skipped {
				skippedSteps[stepID] = true
			}
		}

		// Auto-complete steps the tenant has evidence for before rendering.
		reconcileAutoSteps(c.Request.Context(), store, userID, tenantID, workflowID, rawSteps, completedSteps, skippedSteps)

		// Build steps with status
		steps := make([]OnboardingStep, 0, len(rawSteps))
		for i, rawStep := range rawSteps {
			stepID, _ := rawStep["id"].(string)
			title, _ := rawStep["title"].(string)
			description, _ := rawStep["description"].(string)
			required, _ := rawStep["required"].(bool)

			status := "pending"
			if completedSteps[stepID] {
				status = "completed"
			} else if skippedSteps[stepID] {
				status = "skipped"
			}

			step := OnboardingStep{
				ID:          stepID,
				Title:       title,
				Description: description,
				Order:       i + 1,
				Required:    required,
				Status:      status,
			}

			// Get completion/skip timestamps if available
			if status == "completed" || status == "skipped" {
				timestamp, _, _ := store.GetStepTimestamp(c.Request.Context(), userID, workflowID, stepID)

				if timestamp.Valid {
					if status == "completed" {
						step.CompletedAt = &timestamp.Time
					} else {
						step.SkippedAt = &timestamp.Time
					}
				}
			}

			steps = append(steps, step)
		}

		workflow := OnboardingWorkflow{
			ID:    workflowID.String(),
			Name:  workflowName,
			Steps: steps,
		}

		c.JSON(http.StatusOK, gin.H{"workflow": workflow})
	}
}

// CompleteOnboardingStep handles POST /onboarding/steps/:id/complete - Complete an onboarding step
func CompleteOnboardingStep(db *sql.DB, bypassDB *sql.DB) gin.HandlerFunc {
	return CompleteOnboardingStepWithStore(newOnboardingRepo(db, bypassDB))
}

// CompleteOnboardingStepWithStore is the store-backed implementation, exercised
// directly by the contract test.
func CompleteOnboardingStepWithStore(store onboardingStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get step ID from URL
		stepID := c.Param("id")
		if stepID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Step ID is required"})
			return
		}

		// Get tenant ID from context
		tenantIDStr := c.GetString("tenantID")
		if tenantIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
			return
		}

		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		// Get user ID from context
		userIDStr := c.GetString("userID")
		if userIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
			return
		}

		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}

		// Parse request body (optional)
		var req CompleteStepRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			// Request body is optional
			req = CompleteStepRequest{Data: make(map[string]interface{})}
		}

		// Get workflow
		workflowID, _, stepsJSON, err := store.GetOnboardingWorkflowConfig(c.Request.Context(), tenantID)

		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Onboarding workflow not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch workflow"})
			return
		}

		// Verify step exists in workflow
		var rawSteps []map[string]interface{}
		if err := json.Unmarshal(stepsJSON, &rawSteps); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse workflow steps"})
			return
		}

		var stepFound bool
		var stepRequired bool
		for _, rawStep := range rawSteps {
			if rawStep["id"] == stepID {
				stepFound = true
				stepRequired, _ = rawStep["required"].(bool)
				break
			}
		}

		if !stepFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Step not found in workflow"})
			return
		}

		// Check if step is already completed
		existingCompletedJSON, _, progErr := store.GetUserWorkflowProgress(c.Request.Context(), userID, workflowID)

		var existingCompleted []string
		if progErr == nil {
			_ = json.Unmarshal(existingCompletedJSON, &existingCompleted)
		}

		alreadyCompleted := false
		if progErr == nil {
			for _, completedID := range existingCompleted {
				if completedID == stepID {
					alreadyCompleted = true
					break
				}
			}
		}

		if alreadyCompleted {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Step already completed"})
			return
		}

		// Update or insert progress
		stepDataJSON, _ := json.Marshal(req.Data)
		if err := store.UpsertCompletedStep(c.Request.Context(), userID, workflowID, stepID, stepDataJSON); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update progress"})
			return
		}

		// Check if all required steps are completed
		progress, allRequiredComplete := calculateProgress(c.Request.Context(), store, userID, workflowID, rawSteps)

		// If all required steps complete, mark onboarding as complete
		if allRequiredComplete {
			if err := store.MarkOnboardingComplete(c.Request.Context(), userID); err != nil {
				// Log but don't fail
				fmt.Printf("[ONBOARDING] WARNING: Failed to mark onboarding complete: %v\n", err)
			}
		}

		step := OnboardingStep{
			ID:          stepID,
			Required:    stepRequired,
			Status:      "completed",
			CompletedAt: func() *time.Time { t := time.Now(); return &t }(),
		}

		response := StepResponse{
			Message:   "Step completed successfully",
			Step:      step,
			Progress:  progress,
			Completed: allRequiredComplete,
		}

		c.JSON(http.StatusOK, response)
	}
}

// GetOnboardingProgress handles GET /onboarding/progress - Get onboarding progress
func GetOnboardingProgress(db *sql.DB, bypassDB *sql.DB) gin.HandlerFunc {
	return GetOnboardingProgressWithStore(newOnboardingRepo(db, bypassDB))
}

// GetOnboardingProgressWithStore is the store-backed implementation of
// GetOnboardingProgress, exercised directly by the contract test.
func GetOnboardingProgressWithStore(store onboardingStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from context
		tenantIDStr := c.GetString("tenantID")
		if tenantIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
			return
		}

		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		// Get user ID from context
		userIDStr := c.GetString("userID")
		if userIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
			return
		}

		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}

		// Get user's onboarding completion status
		onboardingCompletedAt, err := store.GetUserOnboardingCompletedAt(c.Request.Context(), userID)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
			return
		}

		onboardingCompleted := onboardingCompletedAt.Valid

		// Get workflow
		workflowID, _, stepsJSON, err := store.GetOnboardingWorkflowConfig(c.Request.Context(), tenantID)

		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Onboarding workflow not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch workflow"})
			return
		}

		// Parse steps
		var rawSteps []map[string]interface{}
		if err := json.Unmarshal(stepsJSON, &rawSteps); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse workflow steps"})
			return
		}

		// Get step statuses
		completedStepsJSON, skippedStepsJSON, err := store.GetUserWorkflowProgress(c.Request.Context(), userID, workflowID)

		completedSteps := make(map[string]bool)
		skippedSteps := make(map[string]bool)

		if err == nil {
			var completed []string
			var skipped []string
			_ = json.Unmarshal(completedStepsJSON, &completed)
			_ = json.Unmarshal(skippedStepsJSON, &skipped)

			for _, stepID := range completed {
				completedSteps[stepID] = true
			}
			for _, stepID := range skipped {
				skippedSteps[stepID] = true
			}
		}

		// Auto-complete steps the tenant has evidence for, THEN compute progress
		// (calculateProgress re-reads the store, so it sees what was persisted).
		reconcileAutoSteps(c.Request.Context(), store, userID, tenantID, workflowID, rawSteps, completedSteps, skippedSteps)

		progress, allRequiredComplete := calculateProgress(c.Request.Context(), store, userID, workflowID, rawSteps)
		if allRequiredComplete && !onboardingCompleted {
			// reconcileAutoSteps just finished the last required step(s); reflect
			// it in this response instead of waiting for the next read.
			onboardingCompleted = true
			now := time.Now()
			onboardingCompletedAt = sql.NullTime{Time: now, Valid: true}
		}

		// Build steps with status
		steps := make([]OnboardingStep, 0, len(rawSteps))
		for i, rawStep := range rawSteps {
			stepID, _ := rawStep["id"].(string)
			title, _ := rawStep["title"].(string)
			description, _ := rawStep["description"].(string)
			required, _ := rawStep["required"].(bool)

			status := "pending"
			if completedSteps[stepID] {
				status = "completed"
			} else if skippedSteps[stepID] {
				status = "skipped"
			}

			step := OnboardingStep{
				ID:          stepID,
				Title:       title,
				Description: description,
				Order:       i + 1,
				Required:    required,
				Status:      status,
			}

			// Get timestamps if available
			if status == "completed" || status == "skipped" {
				timestamp, _, _ := store.GetStepTimestamp(c.Request.Context(), userID, workflowID, stepID)

				if timestamp.Valid {
					if status == "completed" {
						step.CompletedAt = &timestamp.Time
					} else {
						step.SkippedAt = &timestamp.Time
					}
				}
			}

			steps = append(steps, step)
		}

		response := OnboardingProgress{
			UserID:              userID.String(),
			TenantID:            tenantID.String(),
			OnboardingCompleted: onboardingCompleted,
			Progress:            progress,
			Steps:               steps,
		}

		if onboardingCompletedAt.Valid {
			response.OnboardingCompletedAt = &onboardingCompletedAt.Time
		}

		c.JSON(http.StatusOK, response)
	}
}

// SkipOnboardingStep handles POST /onboarding/steps/:id/skip - Skip an onboarding step
func SkipOnboardingStep(db *sql.DB, bypassDB *sql.DB) gin.HandlerFunc {
	return SkipOnboardingStepWithStore(newOnboardingRepo(db, bypassDB))
}

// SkipOnboardingStepWithStore is the store-backed implementation, exercised
// directly by the contract test.
func SkipOnboardingStepWithStore(store onboardingStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get step ID from URL
		stepID := c.Param("id")
		if stepID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Step ID is required"})
			return
		}

		// Get tenant ID from context
		tenantIDStr := c.GetString("tenantID")
		if tenantIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
			return
		}

		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		// Get user ID from context
		userIDStr := c.GetString("userID")
		if userIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
			return
		}

		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}

		// Get workflow
		workflowID, _, stepsJSON, err := store.GetOnboardingWorkflowConfig(c.Request.Context(), tenantID)

		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Onboarding workflow not found"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch workflow"})
			return
		}

		// Verify step exists and is not required
		var rawSteps []map[string]interface{}
		if err := json.Unmarshal(stepsJSON, &rawSteps); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse workflow steps"})
			return
		}

		var stepFound bool
		var stepRequired bool
		for _, rawStep := range rawSteps {
			if rawStep["id"] == stepID {
				stepFound = true
				stepRequired, _ = rawStep["required"].(bool)
				break
			}
		}

		if !stepFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Step not found in workflow"})
			return
		}

		if stepRequired {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot skip required step"})
			return
		}

		// Check if step is already completed or skipped
		existingCompletedJSON, existingSkippedJSON, progErr := store.GetUserWorkflowProgress(c.Request.Context(), userID, workflowID)

		var existingCompleted []string
		var existingSkipped []string
		if progErr == nil {
			_ = json.Unmarshal(existingCompletedJSON, &existingCompleted)
			_ = json.Unmarshal(existingSkippedJSON, &existingSkipped)
		}

		alreadyCompleted := false
		alreadySkipped := false
		if progErr == nil {
			for _, completedID := range existingCompleted {
				if completedID == stepID {
					alreadyCompleted = true
					break
				}
			}
			for _, skippedID := range existingSkipped {
				if skippedID == stepID {
					alreadySkipped = true
					break
				}
			}
		}

		if alreadyCompleted {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Step already completed"})
			return
		}

		if alreadySkipped {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Step already skipped"})
			return
		}

		// Update or insert progress
		if err := store.UpsertSkippedStep(c.Request.Context(), userID, workflowID, stepID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update progress"})
			return
		}

		step := OnboardingStep{
			ID:        stepID,
			Required:  stepRequired,
			Status:    "skipped",
			SkippedAt: func() *time.Time { t := time.Now(); return &t }(),
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Step skipped successfully",
			"step":    step,
		})
	}
}

// OnboardingStatusResponse represents the onboarding status response
type OnboardingStatusResponse struct {
	Required   bool `json:"required"`
	Completed  bool `json:"completed"`
	Dismissed  bool `json:"dismissed"`
	ShowBanner bool `json:"show_banner"`
}

// OnboardingSettingsRequest is the body for PUT /onboarding/settings — the
// tenant-level (org-wide) onboarding toggle. enabled=false disables the wizard
// for every user in the tenant.
type OnboardingSettingsRequest struct {
	Enabled bool `json:"enabled"`
}

// OnboardingSettingsResponse echoes the resolved tenant setting.
type OnboardingSettingsResponse struct {
	Enabled bool `json:"enabled"`
}

// GetOnboardingStatus handles GET /onboarding/status - Get onboarding status
func GetOnboardingStatus(db *sql.DB, bypassDB *sql.DB) gin.HandlerFunc {
	return GetOnboardingStatusWithStore(newOnboardingRepo(db, bypassDB))
}

// GetOnboardingStatusWithStore is the store-backed implementation of
// GetOnboardingStatus, exercised directly by the contract test.
func GetOnboardingStatusWithStore(store onboardingStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from context
		tenantIDStr := c.GetString("tenantID")
		if tenantIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
			return
		}

		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		// Get user ID from context
		userIDStr := c.GetString("userID")
		if userIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
			return
		}

		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}

		// Check if user has completed onboarding
		onboardingCompletedAt, err := store.GetUserOnboardingCompletedAt(c.Request.Context(), userID)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
			return
		}

		completed := onboardingCompletedAt.Valid

		// Per-user dismissal — a user who knows what they're doing has hidden the
		// wizard. Treated as non-fatal: a read error just leaves dismissed=false.
		dismissedAt, dismissErr := store.GetUserOnboardingDismissedAt(c.Request.Context(), userID)
		dismissed := dismissErr == nil && dismissedAt.Valid

		// Not completed? Auto-complete any steps the tenant has evidence for
		// before deciding whether to nudge — a tenant that already set up
		// segments/locations/agents shouldn't keep seeing the checklist just
		// because nobody clicked "Mark as done". Best-effort: any error falls
		// back to the stored state.
		if !completed && !dismissed {
			if workflowID, _, stepsJSON, werr := store.GetOnboardingWorkflowConfig(c.Request.Context(), tenantID); werr == nil {
				var rawSteps []map[string]interface{}
				if json.Unmarshal(stepsJSON, &rawSteps) == nil {
					completedSteps := make(map[string]bool)
					skippedSteps := make(map[string]bool)
					if completedJSON, skippedJSON, perr := store.GetUserWorkflowProgress(c.Request.Context(), userID, workflowID); perr == nil {
						var completedIDs, skippedIDs []string
						_ = json.Unmarshal(completedJSON, &completedIDs)
						_ = json.Unmarshal(skippedJSON, &skippedIDs)
						for _, id := range completedIDs {
							completedSteps[id] = true
						}
						for _, id := range skippedIDs {
							skippedSteps[id] = true
						}
					}
					reconcileAutoSteps(c.Request.Context(), store, userID, tenantID, workflowID, rawSteps, completedSteps, skippedSteps)
					if t, rerr := store.GetUserOnboardingCompletedAt(c.Request.Context(), userID); rerr == nil {
						completed = t.Valid
					}
				}
			}
		}

		// Check tenant settings for onboarding requirement
		configJSON, err := store.GetTenantAdminSettingsConfig(c.Request.Context(), tenantID)

		// Default to true if not set (backward compatible)
		required := true
		if err == nil && len(configJSON) > 0 {
			var config map[string]interface{}
			if err := json.Unmarshal(configJSON, &config); err == nil {
				if onboardingRequired, ok := config["onboarding_required"].(bool); ok {
					required = onboardingRequired
				}
			}
		}

		// Show banner if onboarding is required for the tenant, not completed, and
		// not dismissed by this user.
		showBanner := required && !completed && !dismissed

		response := OnboardingStatusResponse{
			Required:   required,
			Completed:  completed,
			Dismissed:  dismissed,
			ShowBanner: showBanner,
		}

		c.JSON(http.StatusOK, response)
	}
}

// DismissOnboarding handles POST /onboarding/dismiss - permanently dismiss the
// wizard for the current user (per-user, persisted server-side).
func DismissOnboarding(db *sql.DB, bypassDB *sql.DB) gin.HandlerFunc {
	return DismissOnboardingWithStore(newOnboardingRepo(db, bypassDB))
}

// DismissOnboardingWithStore is the store-backed implementation, exercised
// directly by the contract test.
func DismissOnboardingWithStore(store onboardingStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDStr := c.GetString("userID")
		if userIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
			return
		}
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}

		if err := store.DismissOnboardingForUser(c.Request.Context(), userID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to dismiss onboarding"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Onboarding dismissed", "dismissed": true})
	}
}

// UpdateOnboardingSettings handles PUT /onboarding/settings - set the tenant-level
// onboarding_required flag (org-wide enable/disable). Gated to settings.update at
// the router.
func UpdateOnboardingSettings(db *sql.DB, bypassDB *sql.DB) gin.HandlerFunc {
	return UpdateOnboardingSettingsWithStore(newOnboardingRepo(db, bypassDB))
}

// UpdateOnboardingSettingsWithStore is the store-backed implementation, exercised
// directly by the contract test.
func UpdateOnboardingSettingsWithStore(store onboardingStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantIDStr := c.GetString("tenantID")
		if tenantIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
			return
		}
		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		userIDStr := c.GetString("userID")
		if userIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
			return
		}
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}

		var req OnboardingSettingsRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}

		if err := store.SetTenantOnboardingRequired(c.Request.Context(), tenantID, userID, req.Enabled); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update onboarding settings"})
			return
		}

		c.JSON(http.StatusOK, OnboardingSettingsResponse(req))
	}
}

// autoStepEvidence maps a seeded step id to its evidence flag from
// TenantOnboardingEvidence. Steps without a detector (custom workflows) stay
// manual-only.
func autoStepEvidence(stepID string, segments, locations, agents bool) (detected, known bool) {
	switch stepID {
	case "define_networks":
		return segments, true
	case "add_locations":
		return locations, true
	case "deploy_agent":
		return agents, true
	}
	return false, false
}

// reconcileAutoSteps auto-completes checklist steps the tenant has actually
// done ( follow-up): a step whose evidence exists (a segment, a location,
// an agent) is persisted as completed for this user — nobody should have to
// click "Mark as done" for work the platform can see. Evidence is tenant-level,
// so the checklist converges for every member once anyone does the setup; when
// all required steps end up complete, the user's onboarding is marked complete
// so the login nudge stops. Mutates completedSteps in place. Best-effort:
// detection or persistence errors leave the manual state untouched.
func reconcileAutoSteps(ctx context.Context, store onboardingStore, userID, tenantID, workflowID uuid.UUID, rawSteps []map[string]interface{}, completedSteps, skippedSteps map[string]bool) {
	// Anything still pending with a detector?
	pending := false
	for _, rawStep := range rawSteps {
		stepID, _ := rawStep["id"].(string)
		if completedSteps[stepID] || skippedSteps[stepID] {
			continue
		}
		if _, known := autoStepEvidence(stepID, false, false, false); known {
			pending = true
			break
		}
	}
	if !pending {
		return
	}

	segments, locations, agents, err := store.TenantOnboardingEvidence(ctx, tenantID)
	if err != nil {
		return
	}

	autoData := []byte(`{"auto_detected": true}`)
	for _, rawStep := range rawSteps {
		stepID, _ := rawStep["id"].(string)
		if completedSteps[stepID] || skippedSteps[stepID] {
			continue
		}
		detected, known := autoStepEvidence(stepID, segments, locations, agents)
		if !known || !detected {
			continue
		}
		if err := store.UpsertCompletedStep(ctx, userID, workflowID, stepID, autoData); err != nil {
			continue
		}
		completedSteps[stepID] = true
	}

	// If every required step is now complete, finish onboarding for this user.
	allRequiredComplete := true
	anyRequired := false
	for _, rawStep := range rawSteps {
		if required, _ := rawStep["required"].(bool); required {
			anyRequired = true
			stepID, _ := rawStep["id"].(string)
			if !completedSteps[stepID] {
				allRequiredComplete = false
				break
			}
		}
	}
	if anyRequired && allRequiredComplete {
		_ = store.MarkOnboardingComplete(ctx, userID)
	}
}

// calculateProgress calculates progress statistics
func calculateProgress(ctx context.Context, store onboardingStore, userID, workflowID uuid.UUID, rawSteps []map[string]interface{}) (ProgressInfo, bool) {
	// Get completed and skipped steps
	completedStepsJSON, skippedStepsJSON, err := store.GetUserWorkflowProgress(ctx, userID, workflowID)

	completedSteps := make(map[string]bool)
	skippedSteps := make(map[string]bool)

	if err == nil {
		var completed []string
		var skipped []string
		_ = json.Unmarshal(completedStepsJSON, &completed)
		_ = json.Unmarshal(skippedStepsJSON, &skipped)

		for _, stepID := range completed {
			completedSteps[stepID] = true
		}
		for _, stepID := range skipped {
			skippedSteps[stepID] = true
		}
	}

	// Calculate statistics
	totalSteps := len(rawSteps)
	completedCount := 0
	requiredTotal := 0
	requiredCompleted := 0

	for _, rawStep := range rawSteps {
		stepID, _ := rawStep["id"].(string)
		required, _ := rawStep["required"].(bool)

		if required {
			requiredTotal++
		}

		if completedSteps[stepID] {
			completedCount++
			if required {
				requiredCompleted++
			}
		}
	}

	percentage := 0.0
	if totalSteps > 0 {
		percentage = (float64(completedCount) / float64(totalSteps)) * 100
	}

	allRequiredComplete := requiredTotal > 0 && requiredCompleted >= requiredTotal

	return ProgressInfo{
		CompletedSteps:    completedCount,
		TotalSteps:        totalSteps,
		RequiredCompleted: requiredCompleted,
		RequiredTotal:     requiredTotal,
		Percentage:        percentage,
	}, allRequiredComplete
}
