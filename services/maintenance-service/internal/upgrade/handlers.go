package upgrade

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/runs"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// Handlers serves the update, rollback and release-history routes.
type Handlers struct {
	svc *Service
	log logrus.FieldLogger
}

// NewHandlers builds the handlers. svc may be nil (no cluster): every route
// then answers its unavailable state.
func NewHandlers(svc *Service, log logrus.FieldLogger) *Handlers {
	if log == nil {
		log = logrus.StandardLogger()
	}
	return &Handlers{svc: svc, log: log}
}

func apiError(c *gin.Context, status int, code, message string) {
	c.AbortWithStatusJSON(status, gin.H{"error": code, "message": message})
}

// preflightTimeout bounds POST /updates/preflight: the tag listing, a 60s
// cosign verify and a handful of reads.
const preflightTimeout = 90 * time.Second

// PreflightRequest is the body of POST /updates/preflight.
type PreflightRequest struct {
	Version string `json:"version"`
}

// UpdateRequest is the body of POST /updates.
type UpdateRequest struct {
	Version    string `json:"version"`
	SkipBackup bool   `json:"skip_backup"`
}

// RollbackRequest is the body of POST /rollbacks.
type RollbackRequest struct {
	Revision int `json:"revision"`
}

// StartResponse is the 202 body of POST /updates and POST /rollbacks.
type StartResponse struct {
	Run       runs.Run `json:"run"`
	Preflight *Result  `json:"preflight,omitempty"`
}

// PreflightFailedResponse is the 422 body when pre-flight has a failure.
type PreflightFailedResponse struct {
	Error     string `json:"error"`
	Message   string `json:"message"`
	Preflight Result `json:"preflight"`
}

// ReleasesResponse is the body of GET /releases.
type ReleasesResponse struct {
	Releases []Release `json:"releases"`
	// RollbackCandidate is the revision "Roll back to <previous>" offers.
	RollbackCandidate *Release `json:"rollback_candidate"`
}

func bind(c *gin.Context, into any) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4<<10)
	if err := c.ShouldBindJSON(into); err != nil && !errors.Is(err, io.EOF) {
		apiError(c, http.StatusBadRequest, "invalid_request", "the body must be JSON")
		return false
	}
	return true
}

func startedBy(c *gin.Context) *uuid.UUID {
	if id, ok := sharedmw.GetUserIDFromContext(c); ok && id != uuid.Nil {
		return &id
	}
	return nil
}

// Preflight serves POST /updates/preflight.
func (h *Handlers) Preflight(c *gin.Context) {
	var req PreflightRequest
	if !bind(c, &req) {
		return
	}
	if strings.TrimSpace(req.Version) == "" {
		apiError(c, http.StatusBadRequest, "version_required", "version is required")
		return
	}
	if h.svc == nil || h.svc.preflight == nil {
		apiError(c, http.StatusServiceUnavailable, "updates_unavailable", "updates are not available in this deployment")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), preflightTimeout)
	defer cancel()
	c.JSON(http.StatusOK, h.svc.Preflight(ctx, req.Version))
}

// StartUpdate serves POST /updates.
func (h *Handlers) StartUpdate(c *gin.Context) {
	var req UpdateRequest
	if !bind(c, &req) {
		return
	}
	if strings.TrimSpace(req.Version) == "" {
		apiError(c, http.StatusBadRequest, "version_required", "version is required")
		return
	}
	if h.svc == nil {
		apiError(c, http.StatusServiceUnavailable, "updates_unavailable", "updates are not available in this deployment")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), preflightTimeout)
	defer cancel()
	run, res, err := h.svc.StartUpdate(ctx, startedBy(c), req.Version, req.SkipBackup)
	var pf *PreflightFailedError
	switch {
	case errors.Is(err, ErrUnavailable):
		apiError(c, http.StatusServiceUnavailable, "updates_unavailable", "updates are not available in this deployment")
	case errors.Is(err, runs.ErrRunInProgress):
		apiError(c, http.StatusConflict, "run_in_progress", "another maintenance run is in progress; wait for it to finish")
	case errors.As(err, &pf):
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, PreflightFailedResponse{
			Error: "preflight_failed", Message: "pre-flight failed: " + strings.Join(pf.Result.Failed(), ", "), Preflight: pf.Result})
	case errors.Is(err, ErrBackupUnavailable):
		apiError(c, http.StatusUnprocessableEntity, "backup_unavailable", err.Error())
	case err != nil:
		h.log.WithError(err).Error("upgrade: start update")
		apiError(c, http.StatusInternalServerError, "internal_error", "could not start the update")
	default:
		c.JSON(http.StatusAccepted, StartResponse{Run: run, Preflight: &res})
	}
}

// StartRollback serves POST /rollbacks.
func (h *Handlers) StartRollback(c *gin.Context) {
	var req RollbackRequest
	if !bind(c, &req) {
		return
	}
	if req.Revision <= 0 {
		apiError(c, http.StatusBadRequest, "revision_required", "revision must be a positive Helm revision number")
		return
	}
	if h.svc == nil {
		apiError(c, http.StatusServiceUnavailable, "updates_unavailable", "updates are not available in this deployment")
		return
	}
	run, err := h.svc.StartRollback(c.Request.Context(), startedBy(c), req.Revision)
	switch {
	case errors.Is(err, ErrUnavailable):
		apiError(c, http.StatusServiceUnavailable, "updates_unavailable", "updates are not available in this deployment")
	case errors.Is(err, runs.ErrRunInProgress):
		apiError(c, http.StatusConflict, "run_in_progress", "another maintenance run is in progress; wait for it to finish")
	case errors.Is(err, ErrInvalidRevision):
		apiError(c, http.StatusUnprocessableEntity, "invalid_revision", strings.TrimPrefix(err.Error(), "upgrade: "))
	case errors.Is(err, ErrNotUpdatable):
		apiError(c, http.StatusUnprocessableEntity, "not_updatable", strings.TrimPrefix(err.Error(), "upgrade: "))
	case err != nil:
		h.log.WithError(err).Error("upgrade: start rollback")
		apiError(c, http.StatusInternalServerError, "internal_error", "could not start the rollback")
	default:
		c.JSON(http.StatusAccepted, StartResponse{Run: run})
	}
}

// Releases serves GET /releases: the Helm history, newest first.
func (h *Handlers) Releases(c *gin.Context) {
	if h.svc == nil {
		c.JSON(http.StatusOK, ReleasesResponse{Releases: []Release{}})
		return
	}
	history, err := h.svc.History(c.Request.Context())
	switch {
	case errors.Is(err, ErrNoRelease):
		c.JSON(http.StatusOK, ReleasesResponse{Releases: []Release{}})
	case err != nil:
		h.log.WithError(err).Error("upgrade: read the release history")
		apiError(c, http.StatusInternalServerError, "internal_error", "could not read the release history")
	default:
		c.JSON(http.StatusOK, ReleasesResponse{Releases: history, RollbackCandidate: RollbackCandidate(history)})
	}
}
