package services

// ContactService owns contacts, contact roles and contact assignments (DCIM
// BUILD_PLAN row 2.8; DATA_MODEL §1). CRUD runs on the IPAM object engine over
// contactSpecs(): one tenant-scoped transaction per call, RLS in force, every
// write recorded in object_changes, platform contact roles (tenant_id NULL)
// readable and refused with ErrIPAMReadOnly on any write.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// ContactService is the contact store.
type ContactService struct {
	db  *sql.DB
	eng *IPAMService
}

// NewContactService returns the store over db (the raw pool; RLS is set per
// transaction).
func NewContactService(db *sql.DB) *ContactService {
	return &ContactService{db: db, eng: newObjectEngine(db, contactSpecs())}
}

func isContactRoute(route string) bool {
	for _, r := range ContactRoutes() {
		if r == route {
			return true
		}
	}
	return false
}

func unknownContactRoute(route string) error {
	return fmt.Errorf("%w: unknown contact object %q", ErrIPAMNotFound, route)
}

// List returns one page of a contact route.
func (s *ContactService) List(ctx context.Context, tenant uuid.UUID, route string, p IPAMListParams) ([]json.RawMessage, int, error) {
	if !isContactRoute(route) {
		return nil, 0, unknownContactRoute(route)
	}
	return s.eng.List(ctx, tenant, route, p)
}

// Get returns one object.
func (s *ContactService) Get(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) (json.RawMessage, error) {
	if !isContactRoute(route) {
		return nil, unknownContactRoute(route)
	}
	return s.eng.Get(ctx, tenant, route, id)
}

// Create creates an object.
func (s *ContactService) Create(ctx context.Context, tenant uuid.UUID, route string, body []byte) (json.RawMessage, error) {
	if !isContactRoute(route) {
		return nil, unknownContactRoute(route)
	}
	return s.eng.Create(ctx, tenant, route, body)
}

// Update patches an object.
func (s *ContactService) Update(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID, body []byte) (json.RawMessage, error) {
	if !isContactRoute(route) {
		return nil, unknownContactRoute(route)
	}
	return s.eng.Update(ctx, tenant, route, id, body)
}

// Delete removes an object. A role still assigned answers ErrIPAMInUse.
func (s *ContactService) Delete(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) error {
	if !isContactRoute(route) {
		return unknownContactRoute(route)
	}
	return s.eng.Delete(ctx, tenant, route, id)
}

// objectGuard answers ErrIPAMNotFound unless kind/id is an object of the
// tenant — the same resolver the assignment itself is validated with.
func (s *ContactService) objectGuard(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID) error {
	return s.eng.tx(ctx, tenant, func(tx *sql.Tx) error {
		if err := objectExists(ctx, tx, tenant, kind, id); err != nil {
			if err == ErrDcimObjectNotFound {
				return ErrIPAMNotFound
			}
			return err
		}
		return nil
	})
}

// ListForObject lists the contact assignments on one object (with the contact
// and role inlined). An object the tenant cannot see is ErrIPAMNotFound.
func (s *ContactService) ListForObject(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID, p IPAMListParams) ([]json.RawMessage, int, error) {
	if err := s.objectGuard(ctx, tenant, kind, id); err != nil {
		return nil, 0, err
	}
	if p.Filters == nil {
		p.Filters = map[string]string{}
	}
	p.Filters["object_kind"] = string(kind)
	p.Filters["object_id"] = id.String()
	return s.eng.List(ctx, tenant, RouteContactAssignments, p)
}

// AssignToObject assigns a contact in a role to one object. The body names
// contact_id, role_id and optionally priority; the object comes from the path.
func (s *ContactService) AssignToObject(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID, body []byte) (json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil || m == nil {
		return nil, ipamInvalid("body must be a JSON object")
	}
	for _, k := range []string{"object_kind", "object_id"} {
		if _, ok := m[k]; ok {
			return nil, ipamInvalid("%s is set by the path, not the body", k)
		}
	}
	m["object_kind"], _ = json.Marshal(string(kind))
	m["object_id"], _ = json.Marshal(id.String())
	merged, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return s.eng.Create(ctx, tenant, RouteContactAssignments, merged)
}

// ContactObjects lists the contact objects the engine serves, for the contract tests.
func ContactObjects() []IPAMObjectInfo {
	var out []IPAMObjectInfo
	for _, sp := range contactSpecs() {
		info := IPAMObjectInfo{Route: sp.Route, Table: sp.Table, Kind: string(sp.Kind)}
		for _, c := range sp.Cols {
			if c.Computed {
				continue
			}
			info.Writable = append(info.Writable, c.Name)
			if c.Required {
				info.Required = append(info.Required, c.Name)
			}
		}
		out = append(out, info)
	}
	return out
}
