package handlers

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/api"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// FrameworkLicenseHandlers contains all framework license handlers.
//
// The `frameworkLicenseService` field is typed as a small interface
// (`frameworkLicenseStore`, defined in framework_stores.go) rather than the
// concrete `*services.FrameworkLicenseService`. This is what makes the
// tenant-facing subscription HTTP surface exercisable from
// `framework_contract_test.go` with an in-memory stub — no DB, no real service
// dependency tree. `*services.FrameworkLicenseService` satisfies the
// interface implicitly, so production wiring through `cmd/main.go` is
// untouched. The interface declares every method any handler in this file
// calls, so out-of-scope handlers (Admin*, user-preference, Select/Unlock)
// keep compiling against the interface — the contract-test stub fills in
// no-op returns for the methods this slice does not exercise.
type FrameworkLicenseHandlers struct {
	frameworkLicenseService frameworkLicenseStore
}

// NewFrameworkLicenseHandlers creates a new instance of framework license handlers.
// Production callers pass the concrete *services.FrameworkLicenseService; tests
// pass an in-memory stub that satisfies frameworkLicenseStore.
func NewFrameworkLicenseHandlers(frameworkLicenseService *services.FrameworkLicenseService) *FrameworkLicenseHandlers {
	return &FrameworkLicenseHandlers{
		frameworkLicenseService: frameworkLicenseService,
	}
}

// ListLicensedFrameworks lists all licensed frameworks for the current tenant
func (h *FrameworkLicenseHandlers) ListLicensedFrameworks(c *gin.Context) {
	tenantID, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantUUID, ok := tenantID.(uuid.UUID)
	if !ok {
		// Try to parse as string if it's not a UUID
		if tenantIDStr, okStr := tenantID.(string); okStr {
			var err error
			tenantUUID, err = uuid.Parse(tenantIDStr)
			if err != nil {
				log.Printf("ERROR: Invalid tenant ID format: %v (type: %T)\n", tenantID, tenantID)
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID format"})
				return
			}
		} else {
			log.Printf("ERROR: Invalid tenant ID type: %T, value: %v\n", tenantID, tenantID)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID type"})
			return
		}
	}

	// Check if tenantID is nil/empty
	if tenantUUID == uuid.Nil {
		log.Printf("ERROR: Tenant ID is nil/empty\n")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID is required"})
		return
	}

	licenses, err := h.frameworkLicenseService.ListLicensedFrameworks(tenantUUID)
	if err != nil {
		log.Printf("ERROR: Failed to list licensed frameworks for tenant %s: %v\n", tenantUUID, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to list licensed frameworks",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"licenses": licenses,
		"count":    len(licenses),
	})
}

// GetAvailableFrameworks returns available frameworks for selection (published + not yet licensed)
func (h *FrameworkLicenseHandlers) GetAvailableFrameworks(c *gin.Context) {
	tenantID, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantUUID, ok := tenantID.(uuid.UUID)
	if !ok {
		// Try to parse as string if it's not a UUID
		if tenantIDStr, okStr := tenantID.(string); okStr {
			var err error
			tenantUUID, err = uuid.Parse(tenantIDStr)
			if err != nil {
				log.Printf("ERROR: Invalid tenant ID format: %v (type: %T)\n", tenantID, tenantID)
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID format"})
				return
			}
		} else {
			log.Printf("ERROR: Invalid tenant ID type: %T, value: %v\n", tenantID, tenantID)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID type"})
			return
		}
	}

	// Check if tenantID is nil/empty
	if tenantUUID == uuid.Nil {
		log.Printf("ERROR: Tenant ID is nil/empty\n")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID is required"})
		return
	}

	available, err := h.frameworkLicenseService.GetAvailableFrameworks(tenantUUID)
	if err != nil {
		log.Printf("ERROR: Failed to get available frameworks for tenant %s: %v\n", tenantUUID, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get available frameworks",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"frameworks": available,
		"count":      len(available),
	})
}

// GetDefaultFramework returns the tenant's default framework (licensed or platform default)
func (h *FrameworkLicenseHandlers) GetDefaultFramework(c *gin.Context) {
	tenantID, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantUUID, ok := tenantID.(uuid.UUID)
	if !ok {
		// Try to parse as string if it's not a UUID
		if tenantIDStr, okStr := tenantID.(string); okStr {
			var err error
			tenantUUID, err = uuid.Parse(tenantIDStr)
			if err != nil {
				log.Printf("ERROR: Invalid tenant ID format: %v (type: %T)\n", tenantID, tenantID)
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID format"})
				return
			}
		} else {
			log.Printf("ERROR: Invalid tenant ID type: %T, value: %v\n", tenantID, tenantID)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID type"})
			return
		}
	}

	// Check if tenantID is nil/empty
	if tenantUUID == uuid.Nil {
		log.Printf("ERROR: Tenant ID is nil/empty\n")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID is required"})
		return
	}

	defaultFramework, err := h.frameworkLicenseService.GetDefaultFramework(tenantUUID)
	if err != nil {
		log.Printf("ERROR: Failed to get default framework for tenant %s: %v\n", tenantUUID, err)
		// Return 404 if tenant doesn't exist, 500 for other errors
		if strings.Contains(err.Error(), "tenant not found") {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "Tenant not found",
				"details": "The tenant associated with your account does not exist. Please log out and log back in.",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get default framework",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"default_framework": defaultFramework,
	})
}

// SelectFrameworks selects and locks frameworks for the tenant (tenant admin operation)
func (h *FrameworkLicenseHandlers) SelectFrameworks(c *gin.Context) {
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

	// Read request body for debugging (before binding consumes it)
	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err == nil {
		// Restore body for binding
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	var input models.FrameworkLicenseInput
	if err := c.ShouldBindJSON(&input); err != nil {
		log.Printf("ERROR: JSON binding failed: %v\n", err)
		if len(bodyBytes) > 0 {
			log.Printf("ERROR: Request body: %s\n", string(bodyBytes))
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	log.Printf("DEBUG: Received SelectFrameworks request - FrameworkIDs: %v (len=%d), DefaultFrameworkID: %q\n", input.FrameworkIDs, len(input.FrameworkIDs), input.DefaultFrameworkID)

	if len(input.FrameworkIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one framework must be selected"})
		return
	}

	// Parse framework IDs from strings to UUIDs
	frameworkUUIDs := make([]uuid.UUID, 0, len(input.FrameworkIDs))
	for _, idStr := range input.FrameworkIDs {
		id, err := uuid.Parse(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid framework_id format",
				"details": fmt.Sprintf("Invalid UUID: %s", idStr),
			})
			return
		}
		frameworkUUIDs = append(frameworkUUIDs, id)
	}

	// Parse default framework ID from string to UUID
	defaultFrameworkUUID, err := uuid.Parse(input.DefaultFrameworkID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid default_framework_id format",
			"details": fmt.Sprintf("Invalid UUID: %s", input.DefaultFrameworkID),
		})
		return
	}

	err = h.frameworkLicenseService.SelectFrameworks(tenantUUID, frameworkUUIDs, defaultFrameworkUUID, userUUID)
	if err != nil {
		log.Printf("ERROR: Failed to select frameworks for tenant %s: %v\n", tenantUUID, err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to select frameworks",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Frameworks selected and locked successfully",
	})
}

// UnlockFrameworks unlocks frameworks for a tenant (platform admin operation)
func (h *FrameworkLicenseHandlers) UnlockFrameworks(c *gin.Context) {
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

	err := h.frameworkLicenseService.UnlockFrameworks(tenantUUID, userUUID)
	if err != nil {
		log.Printf("ERROR: Failed to unlock frameworks for tenant %s: %v\n", tenantUUID, err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to unlock frameworks",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Frameworks unlocked successfully",
	})
}

// SubscribeFramework subscribes the tenant to a platform framework (self-service)
func (h *FrameworkLicenseHandlers) SubscribeFramework(c *gin.Context) {
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

	var input models.ProvisionFrameworkInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	input.ProvisionedBy = "self_service"
	input.ExpiresAt = nil

	err := h.frameworkLicenseService.SubscribeFramework(tenantUUID, input, userUUID)
	if err != nil {
		log.Printf("ERROR: Failed to subscribe to framework for tenant %s: %v\n", tenantUUID, err)
		api.BadRequest(c, "failed to subscribe to framework")
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Framework subscription created successfully"})
}

// CancelSubscription cancels a framework subscription
func (h *FrameworkLicenseHandlers) CancelSubscription(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	frameworkIDStr := c.Param("frameworkId")
	frameworkID, err := uuid.Parse(frameworkIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid framework ID"})
		return
	}

	err = h.frameworkLicenseService.CancelSubscription(tenantUUID, frameworkID)
	if err != nil {
		log.Printf("ERROR: Failed to cancel subscription for tenant %s framework %s: %v\n", tenantUUID, frameworkID, err)
		api.BadRequest(c, "failed to cancel subscription")
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Framework subscription cancelled successfully"})
}

// SetDefaultFramework sets a licensed framework as the tenant's default
func (h *FrameworkLicenseHandlers) SetDefaultFramework(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	var input struct {
		FrameworkID string `json:"framework_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	frameworkID, err := uuid.Parse(input.FrameworkID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid framework_id format"})
		return
	}

	err = h.frameworkLicenseService.SetDefaultFramework(tenantUUID, frameworkID)
	if err != nil {
		api.ErrorResponse(c, http.StatusBadRequest, "failed to set default framework", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Default framework updated successfully"})
}

// GetUserFrameworkPreference returns the user's framework preference
func (h *FrameworkLicenseHandlers) GetUserFrameworkPreference(c *gin.Context) {
	// Get tenant ID from context
	tenantID, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantUUID, ok := tenantID.(uuid.UUID)
	if !ok {
		if tenantIDStr, okStr := tenantID.(string); okStr {
			var err error
			tenantUUID, err = uuid.Parse(tenantIDStr)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID format"})
				return
			}
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID type"})
			return
		}
	}

	// Get user ID from context
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return
	}

	userUUID, ok := userID.(uuid.UUID)
	if !ok {
		if userIDStr, okStr := userID.(string); okStr {
			var err error
			userUUID, err = uuid.Parse(userIDStr)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
				return
			}
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID type"})
			return
		}
	}

	frameworkID, err := h.frameworkLicenseService.GetUserFrameworkPreference(userUUID, tenantUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get user framework preference",
		})
		return
	}

	if frameworkID == nil {
		c.JSON(http.StatusOK, gin.H{"framework_id": nil})
		return
	}

	c.JSON(http.StatusOK, gin.H{"framework_id": frameworkID.String()})
}

// SetUserFrameworkPreference sets the user's framework preference
func (h *FrameworkLicenseHandlers) SetUserFrameworkPreference(c *gin.Context) {
	// Get tenant ID from context
	tenantID, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantUUID, ok := tenantID.(uuid.UUID)
	if !ok {
		if tenantIDStr, okStr := tenantID.(string); okStr {
			var err error
			tenantUUID, err = uuid.Parse(tenantIDStr)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID format"})
				return
			}
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID type"})
			return
		}
	}

	// Get user ID from context
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return
	}

	userUUID, ok := userID.(uuid.UUID)
	if !ok {
		if userIDStr, okStr := userID.(string); okStr {
			var err error
			userUUID, err = uuid.Parse(userIDStr)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
				return
			}
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID type"})
			return
		}
	}

	// Parse request body
	var input struct {
		FrameworkID string `json:"framework_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	frameworkUUID, err := uuid.Parse(input.FrameworkID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid framework_id format"})
		return
	}

	err = h.frameworkLicenseService.SetUserFrameworkPreference(userUUID, tenantUUID, frameworkUUID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to set user framework preference",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User framework preference set successfully"})
}

// ClearUserFrameworkPreference clears the user's framework preference
func (h *FrameworkLicenseHandlers) ClearUserFrameworkPreference(c *gin.Context) {
	// Get tenant ID from context
	tenantID, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantUUID, ok := tenantID.(uuid.UUID)
	if !ok {
		if tenantIDStr, okStr := tenantID.(string); okStr {
			var err error
			tenantUUID, err = uuid.Parse(tenantIDStr)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID format"})
				return
			}
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID type"})
			return
		}
	}

	// Get user ID from context
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return
	}

	userUUID, ok := userID.(uuid.UUID)
	if !ok {
		if userIDStr, okStr := userID.(string); okStr {
			var err error
			userUUID, err = uuid.Parse(userIDStr)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
				return
			}
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID type"})
			return
		}
	}

	err := h.frameworkLicenseService.ClearUserFrameworkPreference(userUUID, tenantUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to clear user framework preference",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User framework preference cleared successfully"})
}

// =================================================================
// Admin Provisioning Endpoints (platform admin only)
// =================================================================

// AdminProvisionFramework provisions a framework subscription for a tenant
func (h *FrameworkLicenseHandlers) AdminProvisionFramework(c *gin.Context) {
	var input struct {
		TenantID     string  `json:"tenant_id" binding:"required"`
		FrameworkID  string  `json:"framework_id" binding:"required"`
		SetAsDefault bool    `json:"set_as_default"`
		ExpiresAt    *string `json:"expires_at,omitempty"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	tenantID, err := uuid.Parse(input.TenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant_id"})
		return
	}

	userUUID, _ := sharedmw.GetUserIDFromContext(c)

	provisionInput := models.ProvisionFrameworkInput{
		FrameworkID:   input.FrameworkID,
		ProvisionedBy: "admin",
		ExpiresAt:     input.ExpiresAt,
		SetAsDefault:  input.SetAsDefault,
	}

	err = h.frameworkLicenseService.SubscribeFramework(tenantID, provisionInput, userUUID)
	if err != nil {
		log.Printf("ERROR: Admin provision framework failed: %v\n", err)
		api.BadRequest(c, "failed to provision framework")
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Framework provisioned for tenant successfully"})
}

// AdminListTenantSubscriptions lists framework subscriptions for a tenant
func (h *FrameworkLicenseHandlers) AdminListTenantSubscriptions(c *gin.Context) {
	tenantIDStr := c.Param("tenantId")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	licenses, err := h.frameworkLicenseService.ListAllTenantSubscriptionsForAdmin(tenantID)
	if err != nil {
		log.Printf("ERROR: Admin list tenant subscriptions failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list subscriptions"})
		return
	}

	// Convert to admin-friendly format
	type subscriptionView struct {
		ID                  string  `json:"id"`
		TenantID            string  `json:"tenant_id"`
		PlatformFrameworkID string  `json:"platform_framework_id"`
		SubscriptionStatus  string  `json:"subscription_status"`
		SubscriptionStarted *string `json:"subscription_started_at,omitempty"`
		SubscriptionExpires *string `json:"subscription_expires_at,omitempty"`
		ProvisionedBy       string  `json:"provisioned_by"`
		IsDefault           bool    `json:"is_default"`
		FrameworkName       string  `json:"framework_name,omitempty"`
		FrameworkCode       string  `json:"framework_code,omitempty"`
	}

	subs := make([]subscriptionView, 0, len(licenses))
	for _, l := range licenses {
		sub := subscriptionView{
			ID:                  l.ID,
			TenantID:            l.TenantID,
			PlatformFrameworkID: l.PlatformFrameworkID,
			SubscriptionStatus:  l.SubscriptionStatus,
			SubscriptionStarted: l.SubscriptionStartedAt,
			SubscriptionExpires: l.SubscriptionExpiresAt,
			ProvisionedBy:       l.ProvisionedBy,
			IsDefault:           l.IsDefault,
		}
		if l.PlatformFramework != nil {
			sub.FrameworkName = l.PlatformFramework.Name
			sub.FrameworkCode = l.PlatformFramework.Code
		}
		subs = append(subs, sub)
	}

	c.JSON(http.StatusOK, gin.H{
		"subscriptions": subs,
		"count":         len(subs),
	})
}

// AdminCancelTenantSubscription cancels a framework subscription for a tenant
func (h *FrameworkLicenseHandlers) AdminCancelTenantSubscription(c *gin.Context) {
	tenantIDStr := c.Param("tenantId")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	frameworkIDStr := c.Param("frameworkId")
	frameworkID, err := uuid.Parse(frameworkIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid framework ID"})
		return
	}

	err = h.frameworkLicenseService.CancelSubscription(tenantID, frameworkID)
	if err != nil {
		log.Printf("ERROR: Admin cancel subscription failed: %v\n", err)
		api.BadRequest(c, "failed to cancel subscription")
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Framework subscription cancelled for tenant"})
}
