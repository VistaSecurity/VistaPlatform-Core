package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
)

// scheduleStore is the slice of *services.SchedulerService the schedule handlers
// depend on. Declaring it as an interface (the concrete service still satisfies
// it) lets the contract test drive the real handlers with an in-memory stub —
// no database — per the spec-first contract recipe (ADR-0001).
type scheduleStore interface {
	CreateSchedule(ctx context.Context, tenantID uuid.UUID, req services.CreateScheduleRequest) (*services.InterrogationSchedule, error)
	GetSchedule(ctx context.Context, tenantID, scheduleID uuid.UUID) (*services.InterrogationSchedule, error)
	ListSchedules(ctx context.Context, tenantID uuid.UUID) ([]*services.InterrogationSchedule, error)
	UpdateSchedule(ctx context.Context, tenantID, scheduleID uuid.UUID, req services.UpdateScheduleRequest) (*services.InterrogationSchedule, error)
	DeleteSchedule(ctx context.Context, tenantID, scheduleID uuid.UUID) error
	TriggerSchedule(ctx context.Context, tenantID, scheduleID uuid.UUID) (*models.DeviceJob, error)
	GetScheduleHistory(ctx context.Context, tenantID, scheduleID uuid.UUID, limit int) ([]*services.ScheduleHistory, error)
}

// ScheduleHandlers handles schedule-related HTTP requests
type ScheduleHandlers struct {
	schedulerService scheduleStore
}

// NewScheduleHandlers creates a new schedule handlers instance
func NewScheduleHandlers(schedulerService *services.SchedulerService) *ScheduleHandlers {
	return &ScheduleHandlers{
		schedulerService: schedulerService,
	}
}

// CreateSchedule handles POST /schedules
func (h *ScheduleHandlers) CreateSchedule(c *gin.Context) {
	// Get tenant ID from context
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	var req services.CreateScheduleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	schedule, err := h.schedulerService.CreateSchedule(c.Request.Context(), tenantID, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusCreated, schedule)
}

// ListSchedules handles GET /schedules
func (h *ScheduleHandlers) ListSchedules(c *gin.Context) {
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	schedules, err := h.schedulerService.ListSchedules(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"schedules": schedules})
}

// GetSchedule handles GET /schedules/:id
func (h *ScheduleHandlers) GetSchedule(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid schedule ID"})
		return
	}

	// Get tenant ID for isolation check
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	schedule, err := h.schedulerService.GetSchedule(c.Request.Context(), tenantID, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Schedule not found"})
		return
	}

	// Enforce tenant isolation
	if schedule.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Schedule not found"})
		return
	}

	c.JSON(http.StatusOK, schedule)
}

// UpdateSchedule handles PUT /schedules/:id
func (h *ScheduleHandlers) UpdateSchedule(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid schedule ID"})
		return
	}

	// Get tenant ID for isolation check
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	// Verify ownership first
	existingSchedule, err := h.schedulerService.GetSchedule(c.Request.Context(), tenantID, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Schedule not found"})
		return
	}

	if existingSchedule.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Schedule not found"})
		return
	}

	var req services.UpdateScheduleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	schedule, err := h.schedulerService.UpdateSchedule(c.Request.Context(), tenantID, id, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, schedule)
}

// DeleteSchedule handles DELETE /schedules/:id
func (h *ScheduleHandlers) DeleteSchedule(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid schedule ID"})
		return
	}

	// Get tenant ID for isolation check
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	// Verify ownership first
	existingSchedule, err := h.schedulerService.GetSchedule(c.Request.Context(), tenantID, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Schedule not found"})
		return
	}

	if existingSchedule.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Schedule not found"})
		return
	}

	err = h.schedulerService.DeleteSchedule(c.Request.Context(), tenantID, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Schedule deleted successfully"})
}

// TriggerSchedule handles POST /schedules/:id/trigger
func (h *ScheduleHandlers) TriggerSchedule(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid schedule ID"})
		return
	}

	// Get tenant ID for isolation check
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	// Verify ownership first
	existingSchedule, err := h.schedulerService.GetSchedule(c.Request.Context(), tenantID, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Schedule not found"})
		return
	}

	if existingSchedule.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Schedule not found"})
		return
	}

	job, err := h.schedulerService.TriggerSchedule(c.Request.Context(), tenantID, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"message": "Schedule triggered successfully",
		"job_id":  job.ID.String(),
	})
}

// GetScheduleHistory handles GET /schedules/:id/history
func (h *ScheduleHandlers) GetScheduleHistory(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid schedule ID"})
		return
	}

	// Get tenant ID for isolation check
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	// Verify ownership first
	existingSchedule, err := h.schedulerService.GetSchedule(c.Request.Context(), tenantID, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Schedule not found"})
		return
	}

	if existingSchedule.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Schedule not found"})
		return
	}

	history, err := h.schedulerService.GetScheduleHistory(c.Request.Context(), tenantID, id, 50)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"history": history})
}

// EnableSchedule handles POST /schedules/:id/enable
func (h *ScheduleHandlers) EnableSchedule(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid schedule ID"})
		return
	}

	// Get tenant ID for isolation check
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	// Verify ownership first
	existingSchedule, err := h.schedulerService.GetSchedule(c.Request.Context(), tenantID, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Schedule not found"})
		return
	}

	if existingSchedule.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Schedule not found"})
		return
	}

	enabled := true
	schedule, err := h.schedulerService.UpdateSchedule(c.Request.Context(), tenantID, id, services.UpdateScheduleRequest{
		IsEnabled: &enabled,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, schedule)
}

// DisableSchedule handles POST /schedules/:id/disable
func (h *ScheduleHandlers) DisableSchedule(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid schedule ID"})
		return
	}

	// Get tenant ID for isolation check
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	// Verify ownership first
	existingSchedule, err := h.schedulerService.GetSchedule(c.Request.Context(), tenantID, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Schedule not found"})
		return
	}

	if existingSchedule.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Schedule not found"})
		return
	}

	disabled := false
	schedule, err := h.schedulerService.UpdateSchedule(c.Request.Context(), tenantID, id, services.UpdateScheduleRequest{
		IsEnabled: &disabled,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, schedule)
}
