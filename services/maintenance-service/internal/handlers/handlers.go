// Package handlers holds maintenance-service's HTTP handlers.
//
// maintenance-service is the one Core service that holds a Kubernetes
// credential (spec platform-maintenance.md D1): it backs the platform up,
// tells the operator when a newer release exists, and runs the update. WP1
// shipped the skeleton — the status route the admin console's Maintenance
// section reads; the update check (WP2), backups (WP3) and the update and
// rollback runs (WP4) live in their own packages.
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/capabilities"
	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/versions"
	"github.com/vistasecurity/vistaplatform/shared/version"
)

// ServiceName is the registry key, route prefix, audit ServiceName and
// certificate CN of this service. One constant so they cannot drift apart.
const ServiceName = "maintenance-service"

// Pinger reports whether a dependency is reachable. *sql.DB satisfies it.
type Pinger interface {
	PingContext(ctx context.Context) error
}

// ConnectionState reports whether the NATS connection is up. The shared
// *events.NATSClient satisfies it.
type ConnectionState interface {
	IsConnected() bool
}

// Config is the per-install context the chart renders into the pod.
type Config struct {
	Release capabilities.Release
	// SingleNode is maintenance.singleNode (MAINTENANCE_SINGLE_NODE). The
	// service cannot count nodes itself: nodes are cluster-scoped and the
	// chart grants it no ClusterRole.
	SingleNode bool
}

// Handlers serves /health, /ready and the maintenance API.
type Handlers struct {
	db       Pinger
	nats     ConnectionState
	detector capabilities.Detector
	versions versions.Source
	updates  UpdatesService
	cfg      Config
	log      logrus.FieldLogger
}

// New builds the handlers. nats and versions may be nil: NATS carries only
// the completion event (a later phase), and a nil version source reports the
// versions card's error state instead of failing the whole status call.
func New(db Pinger, nats ConnectionState, detector capabilities.Detector, src versions.Source, cfg Config, log logrus.FieldLogger) *Handlers {
	if log == nil {
		log = logrus.StandardLogger()
	}
	if detector == nil {
		detector = capabilities.NotKubernetes{}
	}
	return &Handlers{db: db, nats: nats, detector: detector, versions: src, cfg: cfg, log: log}
}

// Health is the liveness probe: the process is up and serving. It checks no
// dependency, so a database blip does not get the pod restarted. It carries
// version info like every backend's /health, which is what monitoring-service's
// version aggregator reads.
func (h *Handlers) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": ServiceName,
		"version": version.Get(),
	})
}

// readyTimeout bounds the dependency checks behind /ready.
const readyTimeout = 2 * time.Second

// Ready reports whether the service can do its job: the database must answer
// (every route's permission check reads it). NATS is reported, not required.
func (h *Handlers) Ready(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), readyTimeout)
	defer cancel()

	natsState := "disconnected"
	if h.nats != nil && h.nats.IsConnected() {
		natsState = "connected"
	}
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not_ready", "database": "unconfigured", "nats": natsState})
		return
	}
	if err := h.db.PingContext(ctx); err != nil {
		h.log.WithError(err).Warn("readiness: database ping failed")
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not_ready", "database": "unreachable", "nats": natsState})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ready", "database": "ok", "nats": natsState})
}

// StatusResponse is the body of GET /api/v1/maintenance-service/admin/maintenance/status.
type StatusResponse struct {
	Service      string                    `json:"service"`
	Capabilities capabilities.Capabilities `json:"capabilities"`
	Release      capabilities.Release      `json:"release"`
	SingleNode   bool                      `json:"single_node"`
	// Versions is monitoring-service's GET /version body, verbatim. null when
	// it could not be read; VersionsError then says why.
	Versions      json.RawMessage `json:"versions"`
	VersionsError string          `json:"versions_error,omitempty"`
}

// statusTimeout bounds the whole status call: capability detection plus the
// proxied version read.
const statusTimeout = 10 * time.Second

// Status answers what this install can do and what it runs.
func (h *Handlers) Status(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), statusTimeout)
	defer cancel()

	resp := StatusResponse{
		Service:      ServiceName,
		Capabilities: h.detector.Detect(ctx),
		Release:      h.cfg.Release,
		SingleNode:   h.cfg.SingleNode,
		Versions:     json.RawMessage("null"),
	}
	if h.versions == nil {
		resp.VersionsError = "version source not configured"
	} else if body, err := h.versions.Versions(ctx); err != nil {
		h.log.WithError(err).Warn("status: could not read running versions")
		resp.VersionsError = "could not read running versions from monitoring-service"
	} else {
		resp.Versions = body
	}
	c.JSON(http.StatusOK, resp)
}
