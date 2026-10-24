package handlers

// Log export for discovery agents — the console's Logs tab for an agent.
//
// The agent has no command queue, so a log request rides the heartbeat answer
// the way a restart request does; see shared/agentlogs for the whole round
// trip. Everything here lives in Redis with an expiry rather than in Postgres:
// a request is good for an hour and an export for a day, and log lines are
// diagnostic material the platform has no business keeping.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/vistasecurity/vistaplatform/shared/agentlogs"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// AgentLogStore holds one pending request, one export and one capability flag
// per agent. Tenant is part of every key, so an id from another tenant names a
// key nobody's agent ever reads.
type AgentLogStore interface {
	PutRequest(ctx context.Context, tenantID, agentID uuid.UUID, r agentlogs.Request) error
	GetRequest(ctx context.Context, tenantID, agentID uuid.UUID) (*agentlogs.Request, error)
	DeleteRequest(ctx context.Context, tenantID, agentID uuid.UUID) error
	PutExport(ctx context.Context, tenantID, agentID uuid.UUID, e agentlogs.Export) error
	GetExport(ctx context.Context, tenantID, agentID uuid.UUID) (*agentlogs.Export, error)
	MarkCapable(ctx context.Context, tenantID, agentID uuid.UUID) error
	Capable(ctx context.Context, tenantID, agentID uuid.UUID) (bool, error)
}

// ---- Redis store -----------------------------------------------------------

type redisAgentLogStore struct{ rdb *redis.Client }

// NewRedisAgentLogStore is the production store.
func NewRedisAgentLogStore(rdb *redis.Client) AgentLogStore { return &redisAgentLogStore{rdb: rdb} }

func agentLogKey(tenantID, agentID uuid.UUID, part string) string {
	return "agentlogs:" + tenantID.String() + ":" + agentID.String() + ":" + part
}

func (s *redisAgentLogStore) putJSON(ctx context.Context, key string, v any, ttl time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, key, b, ttl).Err()
}

// getJSON returns false, nil when the key does not exist (or has expired).
func (s *redisAgentLogStore) getJSON(ctx context.Context, key string, v any) (bool, error) {
	b, err := s.rdb.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(b, v)
}

func (s *redisAgentLogStore) PutRequest(ctx context.Context, t, a uuid.UUID, r agentlogs.Request) error {
	return s.putJSON(ctx, agentLogKey(t, a, "request"), r, agentlogs.RequestTTL)
}

func (s *redisAgentLogStore) GetRequest(ctx context.Context, t, a uuid.UUID) (*agentlogs.Request, error) {
	var r agentlogs.Request
	ok, err := s.getJSON(ctx, agentLogKey(t, a, "request"), &r)
	if !ok || err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *redisAgentLogStore) DeleteRequest(ctx context.Context, t, a uuid.UUID) error {
	return s.rdb.Del(ctx, agentLogKey(t, a, "request")).Err()
}

func (s *redisAgentLogStore) PutExport(ctx context.Context, t, a uuid.UUID, e agentlogs.Export) error {
	return s.putJSON(ctx, agentLogKey(t, a, "export"), e, agentlogs.ExportTTL)
}

func (s *redisAgentLogStore) GetExport(ctx context.Context, t, a uuid.UUID) (*agentlogs.Export, error) {
	var e agentlogs.Export
	ok, err := s.getJSON(ctx, agentLogKey(t, a, "export"), &e)
	if !ok || err != nil {
		return nil, err
	}
	return &e, nil
}

func (s *redisAgentLogStore) MarkCapable(ctx context.Context, t, a uuid.UUID) error {
	return s.rdb.Set(ctx, agentLogKey(t, a, "capable"), "1", agentlogs.CapabilityTTL).Err()
}

func (s *redisAgentLogStore) Capable(ctx context.Context, t, a uuid.UUID) (bool, error) {
	n, err := s.rdb.Exists(ctx, agentLogKey(t, a, "capable")).Result()
	return n > 0, err
}

// ---- Handler ---------------------------------------------------------------

// AgentLogsHandler serves the tenant and agent halves of log export.
type AgentLogsHandler struct {
	store AgentLogStore
	// agentExists reports whether the agent belongs to the tenant. A function
	// so the handler can be tested without a database.
	agentExists func(ctx context.Context, tenantID, agentID uuid.UUID) (bool, error)
	now         func() time.Time
}

// NewAgentLogsHandler is the production handler: Redis for the logs, the
// RLS-scoped connection for the tenant's agent check.
func NewAgentLogsHandler(db *sql.DB, rdb *redis.Client) *AgentLogsHandler {
	return &AgentLogsHandler{
		store: NewRedisAgentLogStore(rdb),
		agentExists: func(ctx context.Context, tenantID, agentID uuid.UUID) (bool, error) {
			var exists bool
			err := shareddatabase.WithTenantTx(ctx, db, tenantID, func(tx *sql.Tx) error {
				return tx.QueryRowContext(ctx,
					`SELECT EXISTS (SELECT 1 FROM device_agents WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL)`,
					agentID, tenantID).Scan(&exists)
			})
			return exists, err
		},
		now: time.Now,
	}
}

// AgentLogsView is GET /agents/{id}/logs.
type AgentLogsView struct {
	// Supported is whether this agent's build can send its logs: its last
	// heartbeat said so within agentlogs.CapabilityTTL. False for an older
	// build AND for an agent that has not checked in lately — the console
	// words both, since either way a request would not be collected now.
	Supported bool               `json:"supported"`
	Request   *agentlogs.Request `json:"request,omitempty"`
	Export    *agentlogs.Export  `json:"export,omitempty"`
}

func (h *AgentLogsHandler) tenantAgent(c *gin.Context) (uuid.UUID, uuid.UUID, bool) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return uuid.Nil, uuid.Nil, false
	}
	agentID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent id"})
		return uuid.Nil, uuid.Nil, false
	}
	exists, err := h.agentExists(c.Request.Context(), tenantID, agentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to look up agent"})
		return uuid.Nil, uuid.Nil, false
	}
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return uuid.Nil, uuid.Nil, false
	}
	return tenantID, agentID, true
}

// GetLogs is GET /agents/{id}/logs (tenant, sensors.read).
func (h *AgentLogsHandler) GetLogs(c *gin.Context) {
	tenantID, agentID, ok := h.tenantAgent(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	var view AgentLogsView
	var err error
	if view.Supported, err = h.store.Capable(ctx, tenantID, agentID); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "log export is unavailable"})
		return
	}
	if view.Request, err = h.store.GetRequest(ctx, tenantID, agentID); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "log export is unavailable"})
		return
	}
	if view.Export, err = h.store.GetExport(ctx, tenantID, agentID); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "log export is unavailable"})
		return
	}
	c.JSON(http.StatusOK, view)
}

// RequestLogs is POST /agents/{id}/logs/request (tenant, sensors.update).
// Asking again replaces a pending request: the newest ask is the one an
// operator is waiting on.
func (h *AgentLogsHandler) RequestLogs(c *gin.Context) {
	tenantID, agentID, ok := h.tenantAgent(c)
	if !ok {
		return
	}
	var body struct {
		Lines int `json:"lines"`
	}
	// Optional body: no body asks for the default.
	if c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
	}
	req := agentlogs.Request{
		ID:          uuid.NewString(),
		Lines:       agentlogs.ClampLines(body.Lines),
		RequestedAt: h.now().UTC(),
	}
	if err := h.store.PutRequest(c.Request.Context(), tenantID, agentID, req); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "log export is unavailable"})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"request": req})
}

// maxLogUploadBytes bounds an agent's upload: MaxLines × MaxLineBytes, plus
// room for JSON escaping. Anything bigger is not an honest export.
const maxLogUploadBytes = agentlogs.MaxLines*agentlogs.MaxLineBytes*2 + 64<<10

// Upload is POST /agents/{id}/logs (agent-authenticated outbound route).
//
// Accepted only in reply to the request pending for THIS agent: an upload for
// a request that was replaced or never made is refused, so an agent cannot fill
// the console with lines nobody asked for.
func (h *AgentLogsHandler) Upload(c *gin.Context) {
	tenantVal, hasTenant := c.Get("tenantID")
	tenantID, okT := tenantVal.(uuid.UUID)
	agentVal, _ := c.Get("agent_id")
	agentID, okA := agentVal.(uuid.UUID)
	if !hasTenant || !okT || !okA {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "agent not authenticated"})
		return
	}

	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxLogUploadBytes)
	var up agentlogs.Upload
	if err := c.ShouldBindJSON(&up); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid log upload"})
		return
	}

	ctx := c.Request.Context()
	pending, err := h.store.GetRequest(ctx, tenantID, agentID)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "log export is unavailable"})
		return
	}
	if pending == nil || pending.ID != up.RequestID {
		c.JSON(http.StatusConflict, gin.H{"error": "no pending log request with this id"})
		return
	}

	// Cleaned again here: the agent cleans before sending, and this is the
	// backstop for a build that predates a redaction rule.
	lines := agentlogs.Clean(up.Lines, pending.Lines)
	export := agentlogs.Export{
		RequestID:  pending.ID,
		Lines:      lines,
		LineCount:  len(lines),
		ReceivedAt: h.now().UTC(),
	}
	if err := h.store.PutExport(ctx, tenantID, agentID, export); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "log export is unavailable"})
		return
	}
	if err := h.store.DeleteRequest(ctx, tenantID, agentID); err != nil {
		// The export is stored; a request left behind expires on its own, and
		// the agent will not send it twice (it remembers the last id it sent).
		log.Printf("agent logs: could not clear the request for agent %s: %v", agentID, err)
	}
	c.JSON(http.StatusOK, gin.H{"line_count": export.LineCount})
}

// OnHeartbeat records that the agent can export logs (when its heartbeat says
// so) and returns the request pending for it, if any. Failures are logged and
// read as "nothing pending": log export must never cost an agent its
// heartbeat.
func (h *AgentLogsHandler) OnHeartbeat(ctx context.Context, tenantID, agentID uuid.UUID, capable bool) *agentlogs.Request {
	if !capable {
		// An agent that cannot send logs is not handed a request it would
		// ignore; the console shows the request as waiting on an older build.
		return nil
	}
	if err := h.store.MarkCapable(ctx, tenantID, agentID); err != nil {
		log.Printf("agent logs: could not record capability for agent %s: %v", agentID, err)
	}
	req, err := h.store.GetRequest(ctx, tenantID, agentID)
	if err != nil {
		log.Printf("agent logs: could not read the pending request for agent %s: %v", agentID, err)
		return nil
	}
	return req
}
