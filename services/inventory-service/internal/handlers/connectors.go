package handlers

// The connector catalogue — Core, and registry-driven.
//
// Settings → Integrations used to be a hand-kept list beside the page: the CMDB
// platform names lived in a `PLATFORM_LABEL` object in a modal file, and four
// connector keys sat in a database CHECK constraint claiming to be shipped with
// no collector behind any of them. Nothing could see either drift.
//
// This endpoint answers from standards/connectors.yaml instead, so what the
// page offers and what the platform can actually do are the same list by
// construction. It carries three things a UI needs and cannot work out for
// itself:
//
//	status    live / registered / planned — whether anything DISPATCHES on the
//	          key, which is not the same question as whether the database
//	          accepts it (see shared/connectors/implementations.go).
//	feature   the entitlement gating it, empty for Core connectors.
//	entitled  whether THIS tenant has that entitlement right now.
//
// `addable` is the conjunction, computed here rather than in the client, so a
// page cannot check one half and forget the other — which is how a paid
// connector comes to be offered on a Core install.

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/connectors"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	sharedservices "github.com/vistasecurity/vistaplatform/shared/services"
)

// ConnectorCatalogueEntry is one connector as the Integrations page sees it.
type ConnectorCatalogueEntry struct {
	Key             string   `json:"key"`
	Label           string   `json:"label"`
	Kind            string   `json:"kind"`
	Direction       string   `json:"direction"`
	Status          string   `json:"status"`
	ProducesClasses []string `json:"produces_classes,omitempty"`
	Description     string   `json:"description"`
	// Feature is the entitlement key, empty for a Core connector.
	Feature string `json:"feature,omitempty"`
	// Edition is the MINIMUM edition that may grant this connector:
	// core / enterprise / msp. Derived from shared/entitlements rather than
	// restated in the registry, so the two cannot disagree.
	Edition string `json:"edition"`
	// Entitled is whether this tenant holds the entitlement. Always true for a
	// Core connector.
	Entitled bool `json:"entitled"`
	// Addable is `status == live && entitled`. The single question the "Add"
	// button asks.
	Addable bool `json:"addable"`
	// UnavailableReason says WHY, when Addable is false: "upgrade" (your plan
	// or edition does not include it) or "unavailable" (nobody can use it yet,
	// we have not built it). Different sentences — offering an upgrade for
	// something that cannot be bought is the worse of the two mistakes.
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// ConnectorCatalogueGroup is one kind's worth of connectors.
type ConnectorCatalogueGroup struct {
	Kind       string                    `json:"kind"`
	Connectors []ConnectorCatalogueEntry `json:"connectors"`
}

// featureResolver is the slice of LimitEnforcementService this handler needs,
// declared as an interface so the contract test can drive the real router with
// a stub instead of a database.
type featureResolver interface {
	CheckFeatureAccess(tenantID uuid.UUID, feature string) (bool, error)
}

// ConnectorCatalogueHandler serves GET /connectors.
type ConnectorCatalogueHandler struct {
	limits featureResolver
}

// NewConnectorCatalogueHandler builds the handler.
func NewConnectorCatalogueHandler(db *sql.DB) *ConnectorCatalogueHandler {
	return &ConnectorCatalogueHandler{limits: sharedservices.NewLimitEnforcementService(db)}
}

// newConnectorCatalogueHandlerWith is the injectable form the tests use.
func newConnectorCatalogueHandlerWith(limits featureResolver) *ConnectorCatalogueHandler {
	return &ConnectorCatalogueHandler{limits: limits}
}

// List returns the whole registry, grouped by kind, in registry order.
//
// Every connector is returned, including the ones this tenant cannot use. A
// catalogue that hid them would answer "what can I connect to?" with "what you
// have already paid for", and the page's job is to show the shape of the
// product.
func (h *ConnectorCatalogueHandler) List(c *gin.Context) {
	tenantID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	// One lookup per distinct feature key, not one per connector: four CMDB
	// connectors share cmdb_sync, and asking four times is three round trips
	// for an answer we already have.
	entitled := map[string]bool{}
	for _, conn := range connectors.All {
		if conn.Feature == "" {
			continue
		}
		if _, seen := entitled[conn.Feature]; seen {
			continue
		}
		allowed, err := h.limits.CheckFeatureAccess(tenantID, conn.Feature)
		if err != nil {
			// Fail CLOSED, matching RequireFeature: this decides what a paid
			// surface offers, and a lookup failure that rendered every
			// connector addable would put a tenant in front of a form whose
			// save 402s.
			allowed = false
		}
		entitled[conn.Feature] = allowed
	}

	groups := make([]ConnectorCatalogueGroup, 0, len(connectors.Kinds))
	for _, kind := range connectors.Kinds {
		members := connectors.ByKind(kind)
		if len(members) == 0 {
			continue
		}
		group := ConnectorCatalogueGroup{Kind: kind, Connectors: make([]ConnectorCatalogueEntry, 0, len(members))}
		for _, conn := range members {
			group.Connectors = append(group.Connectors, catalogueEntry(conn, entitled))
		}
		groups = append(groups, group)
	}
	c.JSON(http.StatusOK, gin.H{"kinds": connectors.Kinds, "groups": groups})
}

// catalogueEntry projects one registry row. Pure, so the addable/reason rules
// are unit-tested without a database or a router.
func catalogueEntry(conn connectors.Connector, entitled map[string]bool) ConnectorCatalogueEntry {
	e := ConnectorCatalogueEntry{
		Key:             conn.Key,
		Label:           conn.Label,
		Kind:            conn.Kind,
		Direction:       conn.Direction,
		Status:          conn.Status,
		ProducesClasses: conn.ProducesClasses,
		Description:     conn.Description,
		Feature:         conn.Feature,
		Edition:         string(entitlements.EditionFor(conn.Feature)),
	}
	e.Entitled = conn.Feature == "" || entitled[conn.Feature]

	switch {
	case conn.Status != connectors.StatusLive:
		// Not built. Say so; do not offer an upgrade for something nobody can
		// buy yet.
		e.UnavailableReason = "unavailable"
	case !e.Entitled:
		e.UnavailableReason = "upgrade"
	default:
		e.Addable = true
	}
	return e
}
