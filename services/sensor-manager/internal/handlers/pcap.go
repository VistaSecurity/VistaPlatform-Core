package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// pcapMagicBytes defines recognized file signatures for PCAP formats
var pcapMagicBytes = [][]byte{
	{0xA1, 0xB2, 0xC3, 0xD4}, // pcap big-endian
	{0xD4, 0xC3, 0xB2, 0xA1}, // pcap little-endian
	{0x0A, 0x0D, 0x0D, 0x0A}, // pcapng
}

// UploadPcap handles POST /api/v1/sensor-manager/pcap/upload
func (h *Handler) UploadPcap(c *gin.Context) {
	// Extract tenant ID
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

	// Extract user ID
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return
	}
	userUUID, ok := userID.(uuid.UUID)
	if !ok {
		// userID may be stored as string in some auth flows
		userStr, ok2 := userID.(string)
		if !ok2 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}
		parsed, err := uuid.Parse(userStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
			return
		}
		userUUID = parsed
	}

	if h.pcapService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "PCAP service unavailable"})
		return
	}

	// Get the uploaded file
	fileHeader, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file provided in 'file' field"})
		return
	}

	// Check file size against platform setting
	maxSizeMB, _ := h.pcapService.GetMaxUploadSize()
	maxSizeBytes := int64(maxSizeMB) * 1024 * 1024
	if fileHeader.Size > maxSizeBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{
			"error": fmt.Sprintf("File size exceeds maximum allowed size of %d MB", maxSizeMB),
		})
		return
	}

	// Validate file extension
	ext := strings.ToLower(filepath.Ext(fileHeader.Filename))
	if ext != ".pcap" && ext != ".pcapng" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File must have .pcap or .pcapng extension"})
		return
	}

	// Open uploaded file for magic byte validation
	src, err := fileHeader.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read uploaded file"})
		return
	}
	defer func() { _ = src.Close() }()

	// Read first 4 bytes for magic byte validation
	magic := make([]byte, 4)
	n, err := io.ReadFull(src, magic)
	if err != nil || n < 4 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File too small or unreadable"})
		return
	}

	if !isValidPcapMagic(magic) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file format: not a valid PCAP or PCAPNG file"})
		return
	}

	// Reset reader to beginning
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process uploaded file"})
		return
	}

	// Create tenant subdirectory with UUID filename
	fileUUID := uuid.New().String()
	tenantDir := filepath.Join("/tmp/pcap-uploads", tenantUUID.String())
	if err := os.MkdirAll(tenantDir, 0750); err != nil {
		h.log.WithError(err).Error("Failed to create pcap upload directory")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare upload directory"})
		return
	}

	destPath := filepath.Join(tenantDir, fileUUID+ext)
	dst, err := os.Create(destPath) //nolint:gosec // intentional — fileUUID is server-generated UUID, ext is whitelisted to .pcap/.pcapng (line 86), tenantDir is fixed tenant-scoped path
	if err != nil {
		h.log.WithError(err).Error("Failed to create destination file")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save uploaded file"})
		return
	}
	// Safety net for the early-return paths below; the success path closes
	// explicitly so the close error can be acted on.
	dstClosed := false
	defer func() {
		if !dstClosed {
			_ = dst.Close()
		}
	}()

	if _, err := io.Copy(dst, src); err != nil {
		h.log.WithError(err).Error("Failed to write uploaded file")
		// Clean up partial file
		_ = os.Remove(destPath)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save uploaded file"})
		return
	}

	// Close explicitly rather than relying on the deferred close: this file is
	// being WRITTEN, and a failed Close can mean buffered data never reached
	// disk. Discarding it would let the job record below point at a truncated
	// capture that pcap-processor would then parse as if it were complete.
	dstClosed = true
	if err := dst.Close(); err != nil {
		h.log.WithError(err).Error("Failed to finalize uploaded file")
		_ = os.Remove(destPath)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save uploaded file"})
		return
	}

	// Create job record
	job, err := h.pcapService.CreateJob(tenantUUID, userUUID, fileHeader.Filename, fileHeader.Size, destPath)
	if err != nil {
		h.log.WithError(err).Error("Failed to create pcap upload job record")
		_ = os.Remove(destPath)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create upload job"})
		return
	}

	// Publish NATS event
	if h.natsClient != nil {
		evt := events.NewPcapJobEvent(tenantUUID, job.ID, destPath, fileHeader.Filename, fileHeader.Size)
		data, err := json.Marshal(evt)
		if err == nil {
			pubErr := h.natsClient.Publish(events.SubjectPcapJobsProcess, data, evt.EventID.String())
			if pubErr != nil {
				h.log.WithError(pubErr).WithFields(logrus.Fields{
					"job_id":    job.ID,
					"tenant_id": tenantUUID,
				}).Error("Failed to publish PCAP job event to NATS")
				// Don't fail the request - the job record exists and can be retried
			}
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"job_id": job.ID,
		"status": "pending",
	})
}

// ListPcapJobs handles GET /api/v1/sensor-manager/pcap/jobs
func (h *Handler) ListPcapJobs(c *gin.Context) {
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

	if h.pcapService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "PCAP service unavailable"})
		return
	}

	// Parse query parameters
	page := 1
	if p := c.Query("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	limit := 20
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	status := c.Query("status")

	jobs, total, err := h.pcapService.ListJobs(tenantUUID, page, limit, status)
	if err != nil {
		h.log.WithError(err).Error("Failed to list pcap upload jobs")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list pcap upload jobs"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"jobs":  jobs,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

// GetPcapJob handles GET /api/v1/sensor-manager/pcap/jobs/:id
func (h *Handler) GetPcapJob(c *gin.Context) {
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

	if h.pcapService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "PCAP service unavailable"})
		return
	}

	jobIDStr := c.Param("id")
	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid job ID"})
		return
	}

	job, err := h.pcapService.GetJob(tenantUUID, jobID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "PCAP upload job not found"})
			return
		}
		h.log.WithError(err).Error("Failed to get pcap upload job")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get pcap upload job"})
		return
	}

	c.JSON(http.StatusOK, job)
}

// DeletePcapJob handles DELETE /api/v1/sensor-manager/pcap/jobs/:id
func (h *Handler) DeletePcapJob(c *gin.Context) {
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

	if h.pcapService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "PCAP service unavailable"})
		return
	}

	jobIDStr := c.Param("id")
	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid job ID"})
		return
	}

	err = h.pcapService.DeleteJob(tenantUUID, jobID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "PCAP upload job not found"})
			return
		}
		h.log.WithError(err).Error("Failed to delete pcap upload job")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete pcap upload job"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "PCAP upload job deleted"})
}

// UpdatePcapJobResults handles POST /api/v1/sensor-manager/internal/pcap/jobs/:id/results
// This is an internal endpoint called by the pcap-processor service via HMAC auth.
func (h *Handler) UpdatePcapJobResults(c *gin.Context) {
	if h.pcapService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "PCAP service unavailable"})
		return
	}

	jobIDStr := c.Param("id")
	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid job ID"})
		return
	}

	var input struct {
		Status           string                 `json:"status" binding:"required"`
		DiscoveryCount   *int                   `json:"discovery_count,omitempty"`
		PacketCount      *int64                 `json:"packet_count,omitempty"`
		ProtocolsFound   map[string]int         `json:"protocols_found,omitempty"`
		CaptureTimeRange map[string]interface{} `json:"capture_time_range,omitempty"`
		ErrorMessage     *string                `json:"error_message,omitempty"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Validate status
	validStatuses := map[string]bool{
		"processing": true, "completed": true, "failed": true, "cancelled": true,
	}
	if !validStatuses[input.Status] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid status value"})
		return
	}

	updates := make(map[string]interface{})
	if input.DiscoveryCount != nil {
		updates["discovery_count"] = *input.DiscoveryCount
	}
	if input.PacketCount != nil {
		updates["packet_count"] = *input.PacketCount
	}
	if input.ProtocolsFound != nil {
		updates["protocols_found"] = input.ProtocolsFound
	}
	if input.CaptureTimeRange != nil {
		updates["capture_time_range"] = input.CaptureTimeRange
	}
	if input.ErrorMessage != nil {
		updates["error_message"] = *input.ErrorMessage
	}

	err = h.pcapService.UpdateJobStatus(jobID, input.Status, updates)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "PCAP upload job not found"})
			return
		}
		h.log.WithError(err).Error("Failed to update pcap upload job results")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update job results"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Job results updated"})
}

// isValidPcapMagic checks if the first 4 bytes match a known PCAP/PCAPNG signature
func isValidPcapMagic(magic []byte) bool {
	if len(magic) < 4 {
		return false
	}
	for _, valid := range pcapMagicBytes {
		match := true
		for i := 0; i < 4; i++ {
			if magic[i] != valid[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
