package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/middleware"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/services"
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

// maskedChannel returns a copy of ch that is safe to put on the wire: every
// credential in its config is masked (see services/channel_secrets.go). Every
// tenant channel response goes through it — the manager hands back decrypted
// configs because delivery needs them, so the HTTP boundary is where they stop.
func maskedChannel(ch models.TenantNotificationChannel) models.TenantNotificationChannel {
	ch.Config = services.MaskChannelConfig(ch.Config)
	return ch
}

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
	out := make([]models.TenantNotificationChannel, len(channels))
	for i := range channels {
		out[i] = maskedChannel(channels[i])
	}
	c.JSON(http.StatusOK, out)
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
	c.JSON(http.StatusOK, maskedChannel(*channel))
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

	// A generic webhook is signed. Give a new one a signing secret unless the
	// caller supplied their own; the generated value is returned ONCE, in this
	// response, and is write-only afterwards (masked like every credential).
	generatedSecret := ""
	if req.ChannelType == "webhook" {
		if existing, _ := req.Config["webhook_secret"].(string); strings.TrimSpace(existing) == "" {
			generatedSecret = services.GenerateSigningSecret()
			req.Config["webhook_secret"] = generatedSecret
		}
	}

	channel, err := s.channelManager.CreateTenantChannel(c.Request.Context(), tenantID, &req, createdBy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusCreated, createdChannelResponse{
		TenantNotificationChannel: maskedChannel(*channel),
		SigningSecret:             generatedSecret,
	})
}

// createdChannelResponse is the create response: the (masked) channel, plus the
// signing secret when the server generated one. It is the only place a signing
// secret is ever returned in the clear.
type createdChannelResponse struct {
	models.TenantNotificationChannel
	SigningSecret string `json:"signing_secret,omitempty"`
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
	c.JSON(http.StatusOK, maskedChannel(*channel))
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

	writeChannelTestResult(c, s.channelManager.TestTenantChannel(c.Request.Context(), tenantID, channelID))
}

// writeChannelTestResult answers a channel Test.
//
// A channel that did not deliver is NOT an internal error: it is the answer the
// caller asked for. It gets a 422 with the sanitized reason (services.SafeFailureReason
// — a fixed vocabulary that never carries the URL, query string, headers or
// tokens; see failure_reasons.go), so the UI can say WHY instead of "Test
// failed". `error` stays populated for clients that only read the legacy field.
func writeChannelTestResult(c *gin.Context, err error) {
	if err == nil {
		c.JSON(http.StatusOK, gin.H{"status": "test_sent"})
		return
	}
	var failed *services.ChannelTestError
	switch {
	case errors.As(err, &failed):
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"status":    "test_failed",
			"error":     "Test failed",
			"reason":    failed.Reason,
			"permanent": failed.Permanent,
		})
	case errors.Is(err, services.ErrChannelNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "Resource not found"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
	}
}

// getTenantDeliveryStatus reports whether the platform can deliver each channel
// transport that depends on operator configuration. Today that is email only:
// with no SMTP host configured (platform email settings or SMTP_HOST) every
// email channel is inert, and the tenant deserves to be told on the card rather
// than discover it from a failed Test.
func (s *Server) getTenantDeliveryStatus(c *gin.Context) {
	tenantID, ok := tenantIDFromContext(c)
	if !ok {
		return
	}
	configured, err := s.emailStatus.EmailDeliveryConfigured(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"email": gin.H{"configured": configured}})
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

// maskedPlatformChannel is maskedChannel for platform channels. The platform
// endpoints used to return the DECRYPTED config to any platform admin holding
// platform.notifications.manage — the same credential exposure the tenant
// endpoints had before they were masked. Same policy, same masking.
func maskedPlatformChannel(ch models.PlatformNotificationChannel) models.PlatformNotificationChannel {
	ch.Config = services.MaskChannelConfig(ch.Config)
	return ch
}

func (s *Server) listPlatformChannels(c *gin.Context) {
	channels, err := s.channelManager.GetPlatformChannels()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	var out []models.PlatformNotificationChannel // stays nil (JSON null) when there are none
	if channels != nil {
		out = make([]models.PlatformNotificationChannel, len(channels))
		for i := range channels {
			out[i] = maskedPlatformChannel(channels[i])
		}
	}
	c.JSON(http.StatusOK, out)
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
	c.JSON(http.StatusOK, maskedPlatformChannel(*channel))
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
	c.JSON(http.StatusCreated, maskedPlatformChannel(*channel))
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
	c.JSON(http.StatusOK, maskedPlatformChannel(*channel))
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

	writeChannelTestResult(c, s.channelManager.TestPlatformChannel(c.Request.Context(), channelID))
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
