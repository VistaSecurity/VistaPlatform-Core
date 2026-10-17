package handlers

// HTTP surface of custom fields (DCIM BUILD_PLAN row 5.1), under
// /api/v2/inventory-service/dcim:
//
//	GET    /custom-fields                    dcim.read            list (type, name, object_kind, choice_set_id, q)
//	POST   /custom-fields                    custom_fields.manage
//	GET    /custom-fields/{id}               dcim.read
//	PATCH  /custom-fields/{id}               custom_fields.manage
//	DELETE /custom-fields/{id}               custom_fields.manage
//	… the same five for /custom-field-choice-sets (a set in use answers 409 in_use)
//
// Envelope, error codes and handler bodies are IPAM's (ipam_handlers.go) over
// a CRUD-only store. Gates are mounted with the routes
// (cmd/custom_field_routes.go).

import "github.com/gin-gonic/gin"

// CustomFieldHandler serves the custom-field routes.
type CustomFieldHandler struct {
	h *IPAMHandler
}

// NewCustomFieldHandler returns the handler over store
// (services.CustomFieldService).
func NewCustomFieldHandler(store CircuitStore) *CustomFieldHandler {
	return &CustomFieldHandler{h: NewIPAMHandler(crudOnlyStore{store})}
}

// List returns the list handler for one object.
func (c *CustomFieldHandler) List(route string) gin.HandlerFunc { return c.h.List(route) }

// Get returns the single-object handler for one object.
func (c *CustomFieldHandler) Get(route string) gin.HandlerFunc { return c.h.Get(route) }

// Create returns the create handler for one object.
func (c *CustomFieldHandler) Create(route string) gin.HandlerFunc { return c.h.Create(route) }

// Update returns the PATCH handler for one object.
func (c *CustomFieldHandler) Update(route string) gin.HandlerFunc { return c.h.Update(route) }

// Delete returns the delete handler for one object.
func (c *CustomFieldHandler) Delete(route string) gin.HandlerFunc { return c.h.Delete(route) }
