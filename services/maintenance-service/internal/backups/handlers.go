package backups

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/runs"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	"github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// AuditEvent is one explicit activity-trail entry for a write verb, on top of
// the request-level record the audit middleware writes for every request.
type AuditEvent struct {
	EventType     string // maintenance.backup.created | downloaded | deleted
	EventCategory string // an audit.EventCategory* constant
	Action        string
	ResourceID    string
	Success       bool
	Metadata      map[string]any
}

// Auditor records AuditEvents. cmd/ provides the shared-audit implementation.
type Auditor interface {
	Record(c *gin.Context, ev AuditEvent)
}

type nopAuditor struct{}

func (nopAuditor) Record(*gin.Context, AuditEvent) {}

// The audit event types. Spec §2: downloading a backup is a data export and
// must be in the activity trail.
const (
	EventBackupCreated    = "maintenance.backup.created"
	EventBackupDownloaded = "maintenance.backup.downloaded"
	EventBackupDeleted    = "maintenance.backup.deleted"
)

// Handlers serves the backup routes.
type Handlers struct {
	svc     *Service
	auditor Auditor
	log     logrus.FieldLogger
	// downloadIdle is how long one write of a download may stall before the
	// connection is dropped. The server's WriteTimeout (15s) bounds the WHOLE
	// response, which would cut every multi-GB download short, so the handler
	// replaces it with a per-chunk deadline.
	downloadIdle time.Duration
}

// NewHandlers builds the handlers. auditor may be nil (tests).
func NewHandlers(svc *Service, auditor Auditor, log logrus.FieldLogger) *Handlers {
	if auditor == nil {
		auditor = nopAuditor{}
	}
	if log == nil {
		log = logrus.StandardLogger()
	}
	return &Handlers{svc: svc, auditor: auditor, log: log, downloadIdle: 60 * time.Second}
}

func apiError(c *gin.Context, status int, code, message string) {
	c.AbortWithStatusJSON(status, gin.H{"error": code, "message": message})
}

// CreateRequest is the body of POST /admin/maintenance/backups.
type CreateRequest struct {
	IncludeSecrets bool   `json:"include_secrets"`
	Passphrase     string `json:"passphrase"`
}

// CreateResponse is the 202 body.
type CreateResponse struct {
	Backup Backup   `json:"backup"`
	Run    runs.Run `json:"run"`
}

// ListResponse is the body of GET /admin/maintenance/backups.
type ListResponse struct {
	Backups   []Backup `json:"backups"`
	Available bool     `json:"available"`
	Retention int      `json:"retention"`
}

// List serves GET /backups.
func (h *Handlers) List(c *gin.Context) {
	list, err := h.svc.List(c.Request.Context())
	if err != nil {
		h.log.WithError(err).Error("backups: list")
		apiError(c, http.StatusInternalServerError, "internal_error", "could not list backups")
		return
	}
	c.JSON(http.StatusOK, ListResponse{Backups: list, Available: h.svc.Available(), Retention: h.svc.cfg.Retention})
}

// Create serves POST /backups.
func (h *Handlers) Create(c *gin.Context) {
	var req CreateRequest
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4<<10)
	if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
		apiError(c, http.StatusBadRequest, "invalid_request", "the body must be JSON: {include_secrets, passphrase}")
		return
	}
	var startedBy *uuid.UUID
	if id, ok := sharedmw.GetUserIDFromContext(c); ok && id != uuid.Nil {
		startedBy = &id
	}
	b, run, err := h.svc.Create(c.Request.Context(), startedBy, CreateOptions(req))
	switch {
	case errors.Is(err, ErrPassphraseRequired):
		apiError(c, http.StatusBadRequest, "passphrase_required", err.Error())
		return
	case errors.Is(err, ErrPassphraseTooShort):
		apiError(c, http.StatusBadRequest, "passphrase_too_short", err.Error())
		return
	case errors.Is(err, ErrPassphraseWithoutSecrets):
		apiError(c, http.StatusBadRequest, "passphrase_without_secrets", err.Error())
		return
	case errors.Is(err, ErrUnavailable):
		apiError(c, http.StatusServiceUnavailable, "backups_unavailable", "backups are not available in this deployment")
		return
	case errors.Is(err, runs.ErrRunInProgress):
		apiError(c, http.StatusConflict, "run_in_progress", "another maintenance run is in progress; wait for it to finish")
		return
	case err != nil:
		h.log.WithError(err).Error("backups: create")
		h.auditor.Record(c, AuditEvent{EventType: EventBackupCreated, EventCategory: audit.EventCategorySystem, Action: "create", Success: false,
			Metadata: map[string]any{"include_secrets": req.IncludeSecrets}})
		apiError(c, http.StatusInternalServerError, "internal_error", "could not start the backup")
		return
	}
	h.auditor.Record(c, AuditEvent{EventType: EventBackupCreated, EventCategory: audit.EventCategorySystem, Action: "create",
		ResourceID: b.ID.String(), Success: true,
		Metadata: map[string]any{"include_secrets": req.IncludeSecrets, "run_id": run.ID.String(), "encrypted": b.Encrypted}})
	c.JSON(http.StatusAccepted, CreateResponse{Backup: b, Run: run})
}

func parseID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		apiError(c, http.StatusNotFound, "not_found", "no such backup")
		return uuid.Nil, false
	}
	return id, true
}

// Download serves GET /backups/:id/download: the bundle, streamed from the
// volume with its length, never buffered.
func (h *Handlers) Download(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	d, err := h.svc.Open(c.Request.Context(), id)
	switch {
	case errors.Is(err, ErrNotFound):
		apiError(c, http.StatusNotFound, "not_found", "no such backup")
		return
	case errors.Is(err, ErrNotReady):
		apiError(c, http.StatusConflict, "not_ready", "the backup is not ready to download")
		return
	case err != nil:
		h.log.WithError(err).WithField("backup_id", id).Error("backups: open for download")
		apiError(c, http.StatusInternalServerError, "internal_error", "could not open the backup")
		return
	}
	defer func() { _ = d.File.Close() }()

	contentType := "application/x-tar"
	if d.Backup.Encrypted {
		contentType = "application/octet-stream"
	}
	c.Header("Content-Type", contentType)
	c.Header("Content-Length", fmt.Sprint(d.Size))
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, d.Filename))
	c.Header("Cache-Control", "no-store")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Status(http.StatusOK)

	rc := http.NewResponseController(c.Writer)
	buf := make([]byte, 1<<20)
	var sent int64
	var copyErr error
	for {
		n, rerr := d.File.Read(buf)
		if n > 0 {
			_ = rc.SetWriteDeadline(time.Now().Add(h.downloadIdle))
			w, werr := c.Writer.Write(buf[:n])
			sent += int64(w)
			if werr != nil {
				copyErr = werr
				break
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			copyErr = rerr
			break
		}
	}
	complete := copyErr == nil && sent == d.Size
	h.auditor.Record(c, AuditEvent{EventType: EventBackupDownloaded, EventCategory: audit.EventCategoryData, Action: "export",
		ResourceID: id.String(), Success: complete,
		Metadata: map[string]any{"operation_type": "export", "bytes": sent, "size_bytes": d.Size, "encrypted": d.Backup.Encrypted, "includes_secrets": d.Backup.Contents.Secrets}})
	if copyErr != nil {
		h.log.WithError(copyErr).WithField("backup_id", id).Warn("backups: download interrupted")
	}
}

// Delete serves DELETE /backups/:id.
func (h *Handlers) Delete(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	_, err := h.svc.Delete(c.Request.Context(), id)
	switch {
	case errors.Is(err, ErrNotFound):
		apiError(c, http.StatusNotFound, "not_found", "no such backup")
		return
	case errors.Is(err, ErrBackupRunning):
		apiError(c, http.StatusConflict, "backup_running", "a running backup cannot be deleted")
		return
	case err != nil:
		h.log.WithError(err).WithField("backup_id", id).Error("backups: delete")
		h.auditor.Record(c, AuditEvent{EventType: EventBackupDeleted, EventCategory: audit.EventCategorySystem, Action: "delete", ResourceID: id.String(), Success: false})
		apiError(c, http.StatusInternalServerError, "internal_error", "could not delete the backup")
		return
	}
	h.auditor.Record(c, AuditEvent{EventType: EventBackupDeleted, EventCategory: audit.EventCategorySystem, Action: "delete", ResourceID: id.String(), Success: true})
	c.Status(http.StatusNoContent)
}
