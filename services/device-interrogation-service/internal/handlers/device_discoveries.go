package handlers

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
)

// Agent-routed Add device ( slice B): the identification runs on the
// device agent the operator named, because only that agent can reach the
// device. See services/device_discovery_jobs.go for the executor rule.
//
//	POST   /devices/discoveries            queue one (discovery.create)  → 202
//	GET    /devices/discoveries            the rows the Devices page shows (discovery.read)
//	POST   /devices/discoveries/:id/retry  re-queue a failed one (discovery.create)
//	DELETE /devices/discoveries/:id        dismiss it (discovery.create)
//
// Retry and dismiss are discovery.create, not update/manage: they act only on
// an add the same permission started, and a discovery is not a device yet.

// deviceDiscoveryQueue is the slice of *services.DeviceDiscoveryJobs these
// handlers use — an interface so the contract test drives the real handlers
// without a database.
type deviceDiscoveryQueue interface {
	Enqueue(ctx context.Context, req services.EnqueueDeviceDiscoveryRequest) (*services.DeviceDiscovery, error)
	List(ctx context.Context, tenantID uuid.UUID) ([]services.DeviceDiscovery, error)
	Retry(ctx context.Context, tenantID, id uuid.UUID) (*services.DeviceDiscovery, error)
	Dismiss(ctx context.Context, tenantID, id uuid.UUID) error
}

// DeviceDiscoveryHandlers serves the routes above.
type DeviceDiscoveryHandlers struct {
	queue deviceDiscoveryQueue
	// probes is the device handlers' limiter: a queued discovery is a device
	// login like a synchronous one and spends the same per-tenant budget.
	probes *probeLimiter
	// audit records each queued discovery as a probe. Nil in tests that do
	// not assert it.
	audit func(c *gin.Context, p probeAudit)
}

// NewDeviceDiscoveryHandlers builds the handlers over the device handlers'
// probe limiter and audit, so Add device has one budget and one audit trail
// whichever way it reaches the device.
func NewDeviceDiscoveryHandlers(queue *services.DeviceDiscoveryJobs, devices *DeviceHandlers) *DeviceDiscoveryHandlers {
	devices.initProbes()
	return &DeviceDiscoveryHandlers{queue: queue, probes: devices.probes, audit: devices.auditProbe}
}

// auditEventQueuedProbe is a device login queued on an agent.
const auditEventQueuedProbe = "discovery.device_probe_queued"

func tenantFrom(c *gin.Context) (uuid.UUID, bool) {
	v, ok := c.Get("tenantID")
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
		return uuid.Nil, false
	}
	id, ok := v.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return uuid.Nil, false
	}
	return id, true
}

// writeDiscoveryRequestError answers a typed refusal, or 500 for anything else.
func writeDiscoveryRequestError(c *gin.Context, err error) string {
	var typed *services.DeviceDiscoveryRequestError
	if errors.As(err, &typed) {
		status := http.StatusUnprocessableEntity
		if typed.Code == services.CodeAgentUnavailable {
			status = http.StatusConflict
		}
		c.JSON(status, gin.H{"error": typed.Code, "message": typed.Message})
		return typed.Code
	}
	switch {
	case errors.Is(err, services.ErrDeviceDiscoveryNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found", "message": "Discovery not found"})
		return "not_found"
	case errors.Is(err, services.ErrDeviceDiscoveryNotRetryable):
		c.JSON(http.StatusConflict, gin.H{"error": "not_retryable", "message": err.Error()})
		return "not_retryable"
	}
	log.Printf("device discovery: %v", err)
	c.JSON(http.StatusInternalServerError, gin.H{"error": "discovery_failed", "message": "Device discovery could not be queued."})
	return "discovery_failed"
}

// Create handles POST /devices/discoveries.
func (h *DeviceDiscoveryHandlers) Create(c *gin.Context) {
	tenantID, ok := tenantFrom(c)
	if !ok {
		return
	}
	var req struct {
		DeviceType            string    `json:"device_type" binding:"required"`
		ManagementURL         string    `json:"management_url" binding:"required"`
		Username              string    `json:"username" binding:"required"`
		Password              string    `json:"password" binding:"required"`
		TLSInsecureSkipVerify bool      `json:"tls_insecure_skip_verify"`
		AgentID               uuid.UUID `json:"agent_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.AgentID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	audit := probeAudit{event: auditEventQueuedProbe, deviceType: req.DeviceType, target: strings.TrimSpace(req.ManagementURL)}
	if ok, wait := h.probes.allowTenant(tenantID); !ok {
		audit.outcome = codeRateLimited
		h.record(c, audit)
		writeProbeLimited(c, codeRateLimited, wait)
		return
	}
	d, err := h.queue.Enqueue(c.Request.Context(), services.EnqueueDeviceDiscoveryRequest{
		TenantID: tenantID, AgentID: req.AgentID, DeviceType: req.DeviceType,
		ManagementURL: req.ManagementURL, Username: req.Username, Password: req.Password,
		TLSInsecureSkipVerify: req.TLSInsecureSkipVerify,
	})
	if err != nil {
		audit.outcome = writeDiscoveryRequestError(c, err)
		h.record(c, audit)
		return
	}
	audit.outcome = outcomeOK
	h.record(c, audit)
	c.JSON(http.StatusAccepted, d)
}

func (h *DeviceDiscoveryHandlers) record(c *gin.Context, p probeAudit) {
	if h.audit != nil {
		h.audit(c, p)
	}
}

// List handles GET /devices/discoveries.
func (h *DeviceDiscoveryHandlers) List(c *gin.Context) {
	tenantID, ok := tenantFrom(c)
	if !ok {
		return
	}
	list, err := h.queue.List(c.Request.Context(), tenantID)
	if err != nil {
		log.Printf("device discovery: list: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list discoveries"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"discoveries": list})
}

// Retry handles POST /devices/discoveries/:id/retry.
func (h *DeviceDiscoveryHandlers) Retry(c *gin.Context) {
	tenantID, ok := tenantFrom(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid discovery ID"})
		return
	}
	if ok, wait := h.probes.allowTenant(tenantID); !ok {
		writeProbeLimited(c, codeRateLimited, wait)
		return
	}
	d, err := h.queue.Retry(c.Request.Context(), tenantID, id)
	if err != nil {
		writeDiscoveryRequestError(c, err)
		return
	}
	c.JSON(http.StatusAccepted, d)
}

// Dismiss handles DELETE /devices/discoveries/:id.
func (h *DeviceDiscoveryHandlers) Dismiss(c *gin.Context) {
	tenantID, ok := tenantFrom(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid discovery ID"})
		return
	}
	if err := h.queue.Dismiss(c.Request.Context(), tenantID, id); err != nil {
		writeDiscoveryRequestError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Discovery dismissed"})
}
