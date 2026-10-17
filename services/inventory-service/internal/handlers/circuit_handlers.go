package handlers

// HTTP surface of circuits (DCIM BUILD_PLAN row 4.1), under
// /api/v2/inventory-service/circuits:
//
//	GET    /{object}         circuits.read    list (filters, q, limit, offset)
//	POST   /{object}         circuits.manage  create
//	GET    /{object}/{id}    circuits.read
//	PATCH  /{object}/{id}    circuits.manage  a platform circuit type answers 403 read_only
//	DELETE /{object}/{id}    circuits.manage
//
// {object} is providers, provider-accounts, provider-networks, circuit-types,
// circuits, circuit-terminations, circuit-groups, circuit-group-assignments.
// Envelope and error codes are IPAM's (ipam_handlers.go), and so are the
// handler bodies: CircuitHandler serves them over a CRUD-only store. Gates are
// mounted with the routes (cmd/circuit_routes.go).

import (
	"context"
	"encoding/json"
	"net/netip"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// CircuitStore is what the handlers need; services.CircuitService implements
// it.
type CircuitStore interface {
	List(ctx context.Context, tenant uuid.UUID, route string, p services.IPAMListParams) ([]json.RawMessage, int, error)
	Get(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) (json.RawMessage, error)
	Create(ctx context.Context, tenant uuid.UUID, route string, body []byte) (json.RawMessage, error)
	Update(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID, body []byte) (json.RawMessage, error)
	Delete(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) error
}

// CircuitHandler serves the circuit routes.
type CircuitHandler struct {
	h *IPAMHandler
}

// NewCircuitHandler returns the handler over store.
func NewCircuitHandler(store CircuitStore) *CircuitHandler {
	return &CircuitHandler{h: NewIPAMHandler(crudOnlyStore{store})}
}

// List returns the list handler for one circuit object.
func (c *CircuitHandler) List(route string) gin.HandlerFunc { return c.h.List(route) }

// Get returns the single-object handler for one circuit object.
func (c *CircuitHandler) Get(route string) gin.HandlerFunc { return c.h.Get(route) }

// Create returns the create handler for one circuit object.
func (c *CircuitHandler) Create(route string) gin.HandlerFunc { return c.h.Create(route) }

// Update returns the PATCH handler for one circuit object.
func (c *CircuitHandler) Update(route string) gin.HandlerFunc { return c.h.Update(route) }

// Delete returns the delete handler for one circuit object.
func (c *CircuitHandler) Delete(route string) gin.HandlerFunc { return c.h.Delete(route) }

// crudOnlyStore adapts a CircuitStore to IPAMStore: the IPAM-only reads
// (prefix detail, tree, find) are never routed to it.
type crudOnlyStore struct{ CircuitStore }

func (crudOnlyStore) PrefixDetail(context.Context, uuid.UUID, uuid.UUID, services.PrefixDetailParams) (*services.PrefixDetail, error) {
	return nil, services.ErrIPAMNotFound
}

func (crudOnlyStore) PrefixTree(context.Context, uuid.UUID, *uuid.UUID) ([]*services.PrefixTreeNode, int, error) {
	return nil, 0, services.ErrIPAMNotFound
}

func (crudOnlyStore) FindAddress(context.Context, uuid.UUID, netip.Addr, *uuid.UUID, bool) ([]services.FindResult, error) {
	return nil, services.ErrIPAMNotFound
}
