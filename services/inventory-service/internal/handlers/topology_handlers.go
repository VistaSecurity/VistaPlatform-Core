// Package handlers: the tenant-wide topology (ADR-0006 D4 second half,
// workstream 3.8).
package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// topologyStore is the one method this handler calls — narrow so the contract
// test can drive the real handler with an in-memory stub and no database.
type topologyStore interface {
	GetTopology(ctx context.Context, tenantID uuid.UUID) (*services.Topology, error)
}

// TopologyHandler serves GET /infrastructure-assets/topology.
type TopologyHandler struct {
	assets topologyStore
}

// NewTopologyHandler wires the handler.
func NewTopologyHandler(assets topologyStore) *TopologyHandler {
	return &TopologyHandler{assets: assets}
}

// GetTopology handles GET /infrastructure-assets/topology.
//
// No parameters. The whole tree is one answer — it is a grouping, not a list,
// and paging a hierarchy is how a client comes to render half a tree without
// knowing it. The caps are reported IN the response instead (`truncated`,
// `total_nodes`, `total_edges`), so a tenant past them is told rather than
// silently shown less.
func (h *TopologyHandler) GetTopology(c *gin.Context) {
	tenantID, ok := c.Get("tenantID")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}
	tenantUUID, ok := tenantID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	topology, err := h.assets.GetTopology(c.Request.Context(), tenantUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to build the topology",
			"message": err.Error(),
		})
		return
	}
	// An EMPTY estate answers 200 with empty arrays and zero totals, not 404
	// and not an error. "This tenant has no assets yet" is the state every
	// tenant starts in, and the view says so itself rather than being handed a
	// failure to interpret.
	c.JSON(http.StatusOK, gin.H{"topology": topology})
}
