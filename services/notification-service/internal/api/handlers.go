package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/middleware"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
)

// tenantIDFromContext resolves the tenant UUID regardless of whether an
// upstream middleware stored it as uuid.UUID or string — StringifyUserID()
// rewrites the context value to a string, so the bare uuid.UUID type
// assertion this replaces panicked on every tenant request ().
// Absence writes a 403 (mirrors RequireTenant) and returns ok=false.
func tenantIDFromContext(c *gin.Context) (uuid.UUID, bool) {
	id, ok := middleware.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusForbidden, gin.H{"error": "Tenant ID required"})
	}
	return id, ok
}

// Internal API handlers

// sendNotification handles internal service-to-service notification sending
func (s *Server) sendNotification(c *gin.Context) {
	var req models.SendNotificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if err := s.notificationService.SendNotification(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "sent"})
}

// Tenant channel handlers

func (s *Server) listTenantChannels(c *gin.Context) {
	tenantID, ok := tenantIDFromContext(c)
	if !ok {
		return
	}
	channels, err := s.channelManager.GetTenantChannels(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, channels)
}

func (s *Server) getTenantChannel(c *gin.Context) {
	tenantID, ok := tenantIDFromContext(c)
	if !ok {
		return
	}
	channelID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid channel ID"})
		return
	}

	channel, err := s.channelManager.GetTenantChannelByID(c.Request.Context(), tenantID, channelID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Resource not found"})
		return
	}
	c.JSON(http.StatusOK, channel)
}

func (s *Server) createTenantChannel(c *gin.Context) {
	tenantID, ok := tenantIDFromContext(c)
	if !ok {
		return
	}
	userIDStr, _ := c.Get("userID")
	var createdBy *uuid.UUID
	if userIDStr != nil {
		if id, err := uuid.Parse(userIDStr.(string)); err == nil {
			createdBy = &id
		}
	}

	var req models.CreateChannelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	channel, err := s.channelManager.CreateTenantChannel(c.Request.Context(), tenantID, &req, createdBy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusCreated, channel)
}

func (s *Server) updateTenantChannel(c *gin.Context) {
	tenantID, ok := tenantIDFromContext(c)
	if !ok {
		return
	}
	channelID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid channel ID"})
		return
	}

	var req models.UpdateChannelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	channel, err := s.channelManager.UpdateTenantChannel(c.Request.Context(), tenantID, channelID, &req, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, channel)
}

func (s *Server) deleteTenantChannel(c *gin.Context) {
	tenantID, ok := tenantIDFromContext(c)
	if !ok {
		return
	}
	channelID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid channel ID"})
		return
	}

	if err := s.channelManager.DeleteTenantChannel(c.Request.Context(), tenantID, channelID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

func (s *Server) testTenantChannel(c *gin.Context) {
	tenantID, ok := tenantIDFromContext(c)
	if !ok {
		return
	}
	channelID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid channel ID"})
		return
	}

	if err := s.channelManager.TestTenantChannel(c.Request.Context(), tenantID, channelID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "test_sent"})
}

// Tenant rule handlers

func (s *Server) listTenantRules(c *gin.Context) {
	tenantID, ok := tenantIDFromContext(c)
	if !ok {
		return
	}
	rules, err := s.ruleEngine.GetTenantRules(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, rules)
}

func (s *Server) getTenantRule(c *gin.Context) {
	tenantID, ok := tenantIDFromContext(c)
	if !ok {
		return
	}
	ruleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule ID"})
		return
	}

	rules, err := s.ruleEngine.GetTenantRules(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	var rule *models.TenantNotificationRule
	for i := range rules {
		if rules[i].ID == ruleID {
			rule = &rules[i]
			break
		}
	}

	if rule == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}
	c.JSON(http.StatusOK, rule)
}

func (s *Server) createTenantRule(c *gin.Context) {
	tenantID, ok := tenantIDFromContext(c)
	if !ok {
		return
	}
	var req models.CreateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	rule, err := s.ruleEngine.CreateTenantRule(c.Request.Context(), tenantID, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusCreated, rule)
}

func (s *Server) updateTenantRule(c *gin.Context) {
	tenantID, ok := tenantIDFromContext(c)
	if !ok {
		return
	}
	ruleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule ID"})
		return
	}

	var req models.UpdateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	rule, err := s.ruleEngine.UpdateTenantRule(c.Request.Context(), tenantID, ruleID, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, rule)
}

func (s *Server) deleteTenantRule(c *gin.Context) {
	tenantID, ok := tenantIDFromContext(c)
	if !ok {
		return
	}
	ruleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule ID"})
		return
	}

	if err := s.ruleEngine.DeleteTenantRule(c.Request.Context(), tenantID, ruleID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// Tenant history handler

func (s *Server) getTenantHistory(c *gin.Context) {
	tenantID, ok := tenantIDFromContext(c)
	if !ok {
		return
	}
	limit := 50
	if limitStr := c.Query("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	history, err := s.readStore.ListHistory(c.Request.Context(), tenantID, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, history)
}

// Tenant in-app notifications handler

func (s *Server) getTenantInAppNotifications(c *gin.Context) {
	tenantID, ok := tenantIDFromContext(c)
	if !ok {
		return
	}
	notifications, err := s.readStore.ListInAppNotifications(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"notifications": notifications})
}

// markTenantNotificationRead stamps read_at on one in-app notification.
func (s *Server) markTenantNotificationRead(c *gin.Context) {
	tenantID, ok := tenantIDFromContext(c)
	if !ok {
		return
	}
	notificationID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid notification ID"})
		return
	}
	if err := s.readStore.MarkInAppRead(c.Request.Context(), tenantID, notificationID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "read"})
}

// markAllTenantNotificationsRead stamps read_at on all unread in-app notifications.
func (s *Server) markAllTenantNotificationsRead(c *gin.Context) {
	tenantID, ok := tenantIDFromContext(c)
	if !ok {
		return
	}
	if err := s.readStore.MarkAllInAppRead(c.Request.Context(), tenantID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "read"})
}

// Platform in-app inbox handlers (admin-ui bell)

func (s *Server) getPlatformInAppNotifications(c *gin.Context) {
	notifications, err := s.readStore.ListPlatformInAppNotifications(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"notifications": notifications})
}

func (s *Server) markPlatformNotificationRead(c *gin.Context) {
	notificationID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid notification ID"})
		return
	}
	if err := s.readStore.MarkPlatformInAppRead(c.Request.Context(), notificationID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "read"})
}

func (s *Server) markAllPlatformNotificationsRead(c *gin.Context) {
	if err := s.readStore.MarkAllPlatformInAppRead(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "read"})
}

// Platform channel handlers

func (s *Server) listPlatformChannels(c *gin.Context) {
	channels, err := s.channelManager.GetPlatformChannels()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, channels)
}

func (s *Server) getPlatformChannel(c *gin.Context) {
	channelID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid channel ID"})
		return
	}

	channel, err := s.channelManager.GetPlatformChannelByID(channelID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Resource not found"})
		return
	}
	c.JSON(http.StatusOK, channel)
}

func (s *Server) createPlatformChannel(c *gin.Context) {
	userIDStr, _ := c.Get("userID")
	var createdBy *uuid.UUID
	if userIDStr != nil {
		if id, err := uuid.Parse(userIDStr.(string)); err == nil {
			createdBy = &id
		}
	}

	var req models.CreateChannelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	channel, err := s.channelManager.CreatePlatformChannel(&req, createdBy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusCreated, channel)
}

func (s *Server) updatePlatformChannel(c *gin.Context) {
	channelID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid channel ID"})
		return
	}

	userIDStr, _ := c.Get("userID")
	var updatedBy *uuid.UUID
	if userIDStr != nil {
		if id, err := uuid.Parse(userIDStr.(string)); err == nil {
			updatedBy = &id
		}
	}

	var req models.UpdateChannelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	channel, err := s.channelManager.UpdatePlatformChannel(channelID, &req, updatedBy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, channel)
}

func (s *Server) deletePlatformChannel(c *gin.Context) {
	channelID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid channel ID"})
		return
	}

	if err := s.channelManager.DeletePlatformChannel(channelID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

func (s *Server) testPlatformChannel(c *gin.Context) {
	channelID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid channel ID"})
		return
	}

	if err := s.channelManager.TestPlatformChannel(c.Request.Context(), channelID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "test_sent"})
}

// Platform rule handlers

func (s *Server) listPlatformRules(c *gin.Context) {
	rules, err := s.ruleEngine.GetPlatformRules()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, rules)
}

func (s *Server) getPlatformRule(c *gin.Context) {
	ruleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule ID"})
		return
	}

	rules, err := s.ruleEngine.GetPlatformRules()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	var rule *models.PlatformNotificationRule
	for i := range rules {
		if rules[i].ID == ruleID {
			rule = &rules[i]
			break
		}
	}

	if rule == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}
	c.JSON(http.StatusOK, rule)
}

func (s *Server) createPlatformRule(c *gin.Context) {
	var req models.CreateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	rule, err := s.ruleEngine.CreatePlatformRule(&req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusCreated, rule)
}

func (s *Server) updatePlatformRule(c *gin.Context) {
	ruleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule ID"})
		return
	}

	var req models.UpdateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	rule, err := s.ruleEngine.UpdatePlatformRule(ruleID, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, rule)
}

func (s *Server) deletePlatformRule(c *gin.Context) {
	ruleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule ID"})
		return
	}

	if err := s.ruleEngine.DeletePlatformRule(ruleID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// Platform history handler

func (s *Server) getPlatformHistory(c *gin.Context) {
	limit := 50
	if limitStr := c.Query("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	history, err := s.readStore.ListPlatformHistory(c.Request.Context(), limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, history)
}

// --- Platform maintenance windows (storm control §10.3) ---

func (s *Server) listMaintenanceWindows(c *gin.Context) {
	windows, err := s.maintenance.ListMaintenanceWindows(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"windows": windows})
}

type createMaintenanceWindowRequest struct {
	StartsAt time.Time `json:"starts_at" binding:"required"`
	EndsAt   time.Time `json:"ends_at" binding:"required"`
	Reason   string    `json:"reason"`
}

func (s *Server) createMaintenanceWindow(c *gin.Context) {
	userIDStr, _ := c.Get("userID")
	var createdBy *uuid.UUID
	if userIDStr != nil {
		if id, err := uuid.Parse(userIDStr.(string)); err == nil {
			createdBy = &id
		}
	}
	var req createMaintenanceWindowRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	if !req.EndsAt.After(req.StartsAt) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ends_at must be after starts_at"})
		return
	}
	w, err := s.maintenance.CreateMaintenanceWindow(c.Request.Context(), req.StartsAt, req.EndsAt, req.Reason, createdBy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusCreated, w)
}

func (s *Server) deleteMaintenanceWindow(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	found, err := s.maintenance.DeleteMaintenanceWindow(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "maintenance window not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}
