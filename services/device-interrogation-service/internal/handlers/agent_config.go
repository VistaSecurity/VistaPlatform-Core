package handlers

// Desired-state endpoints for discovery agents (feature).
//
// The HTTP behaviour lives in shared/agentconfig/confighttp, which sensor-manager
// serves too: confirmation decided server-side, floors raised and reported, a
// save answering with what actually changed. Those are product decisions, not
// per-service ones, and writing them twice is how the sensor and agent halves
// of this product drifted apart before.
//
// What stays here is what genuinely differs: this service owns agents, resolves
// one from the request, and decides what a foreign id is answered with.

import (
	"context"
	"database/sql"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig/confighttp"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig/store"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// AgentConfigHandler serves the desired-state surface for discovery agents.
type AgentConfigHandler struct {
	inner *confighttp.Handler
	store *store.Store
	db    *sql.DB
}

func NewAgentConfigHandler(db *sql.DB) *AgentConfigHandler {
	s := store.New(db)
	h := &AgentConfigHandler{store: s, db: db}
	h.inner = confighttp.New(confighttp.Deps{
		Runtime:       agentconfig.RuntimeAgent,
		Store:         s,
		OwnerFrom:     h.ownerFrom,
		DeviceVersion: h.deviceVersion,
	})
	return h
}

// GetAgentConfig returns one agent's effective settings and convergence state.
func (h *AgentConfigHandler) GetAgentConfig(c *gin.Context) { h.inner.GetDevice(c) }

// PutAgentConfig replaces one agent's override.
func (h *AgentConfigHandler) PutAgentConfig(c *gin.Context) { h.inner.PutDevice(c) }

// GetAgentFleetDefaults returns the tenant-wide agent defaults.
func (h *AgentConfigHandler) GetAgentFleetDefaults(c *gin.Context) { h.inner.GetDefaults(c) }

// PutAgentFleetDefaults replaces the tenant-wide agent defaults.
func (h *AgentConfigHandler) PutAgentFleetDefaults(c *gin.Context) { h.inner.PutDefaults(c) }

// RequestAgentRestart asks one agent to restart at its next check-in.
func (h *AgentConfigHandler) RequestAgentRestart(c *gin.Context) { h.inner.RequestRestart(c) }

// GetAgentConfigHistory answers with who changed this agent's configuration,
// when, and what moved — the reader the audit table did not have.
func (h *AgentConfigHandler) GetAgentConfigHistory(c *gin.Context) { h.inner.GetHistory(c) }

// AgentReport and AgentConfigPayload keep their names for the router and the
// agent-facing contract.
type AgentReport = confighttp.ExchangeReport

// AgentConfigPayload is what the platform sends an agent on its heartbeat.
type AgentConfigPayload = confighttp.ExchangePayload

// Exchange records an agent's report and returns what it should be running.
func (h *AgentConfigHandler) Exchange(ctx context.Context, tenantID, agentID uuid.UUID, rep AgentReport) (*AgentConfigPayload, error) {
	return confighttp.ExchangeCtx(ctx, h.store, tenantID, store.AgentOwner(agentID), rep)
}

// ownerFrom resolves the agent this request addresses, refusing one that is not
// this tenant's.
//
// It MUST run inside WithTenantTx. `device_agents` is an RLS table and the
// service connects as a non-owner role wherever serviceRls is enabled — the
// default — so a query on the plain pool has no `app.tenant_id` set, the policy
// evaluates against NULL, and the row is invisible. The result is not a leak
// but a total outage: every endpoint answers 404 for the tenant's OWN agents.
// That shipped once and passed a full integration suite, because the test
// harness connects as the table owner and bypasses policies; the regression
// test for it connects as the app role deliberately.
//
// A foreign id is answered 404, identically to an unknown one: RLS keeps the
// settings isolated either way, but a different answer would still tell one
// tenant that another's agent exists.
func (h *AgentConfigHandler) ownerFrom(c *gin.Context, tenantID uuid.UUID) (store.Owner, bool) {
	agentID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid agent ID"})
		return store.Owner{}, false
	}

	var found bool
	err = shareddatabase.WithTenantTx(c.Request.Context(), h.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(c.Request.Context(),
			`SELECT EXISTS (SELECT 1 FROM device_agents WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL)`,
			agentID, tenantID).Scan(&found)
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return store.Owner{}, false
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Agent not found"})
		return store.Owner{}, false
	}
	return store.AgentOwner(agentID), true
}

// deviceVersion reports what this agent last told us it was running.
//
// Empty on any failure rather than an error: a version display that cannot be
// built is a missing badge, not a reason to fail the whole configuration read.
// Empty renders as "unknown", which is the truth.
func (h *AgentConfigHandler) deviceVersion(c *gin.Context, tenantID uuid.UUID, owner store.Owner) string {
	var version sql.NullString
	err := shareddatabase.WithTenantTx(c.Request.Context(), h.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(c.Request.Context(),
			`SELECT version FROM device_agents WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`,
			owner.AgentID, tenantID).Scan(&version)
	})
	if err != nil {
		// Empty rather than an error: a version display that cannot be built is
		// a missing badge, not a reason to fail the configuration read. But it
		// is logged, because "this device has not reported a version" and "the
		// query failed" render identically and only one of them is the device's
		// fault — review pointed out the silent version was undiagnosable.
		log.Printf("agent config: could not read version for agent %s: %v", owner.AgentID, err)
		return ""
	}
	return version.String
}
