package services

// Contacts, contact roles and contact assignments as engine specs (DCIM
// BUILD_PLAN row 2.8; DATA_MODEL §1). Column names are the API property names
// and the OpenAPI schema properties (contact_contract_test.go).
//
// An assignment hangs a (contact, role) on any object by (object_kind,
// object_id). The object is resolved through objectExists — the vocabulary's
// table for the kind, scoped to the tenant — so an object that does not exist,
// belongs to another tenant, or is of a kind whose table has not shipped is a
// 404, never a dangling row.

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// Route segments under /dcim.
const (
	RouteContacts           = "contacts"
	RouteContactRoles       = "contact-roles"
	RouteContactAssignments = "contact-assignments"
)

// ContactRoutes are the contact object routes, in order.
func ContactRoutes() []string {
	return []string{RouteContacts, RouteContactRoles, RouteContactAssignments}
}

var contactPriorities = []string{"primary", "secondary", "tertiary", "inactive"}

func prepareContact(ctx context.Context, tx *sql.Tx, _, id uuid.UUID, row map[string]any) error {
	if s, ok := row["name"].(string); ok {
		row["name"] = strings.TrimSpace(s)
	}
	if e, ok := row["email"].(string); ok && strings.TrimSpace(e) != "" {
		e = strings.TrimSpace(e)
		at := strings.Index(e, "@")
		if at < 1 || at == len(e)-1 || strings.ContainsAny(e, " \t\r\n") {
			return ipamInvalid("email %q is not an address", e)
		}
		row["email"] = e
	}
	if isEmpty(row["group_id"]) {
		row["group_id"] = nil
		return nil
	}
	if err := visible(ctx, tx, "contacts", row["group_id"]); err != nil {
		return err
	}
	if id == uuid.Nil {
		return nil
	}
	// A contact group is a parent contact: refuse a cycle.
	cur := row["group_id"]
	for i := 0; i < 32 && cur != nil; i++ {
		if cur == id.String() {
			return ipamInvalid("group_id would make the contact its own ancestor")
		}
		var next sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT group_id::text FROM public.contacts WHERE id = $1::uuid`, cur).Scan(&next); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		if !next.Valid {
			return nil
		}
		cur = next.String
	}
	return nil
}

func prepareContactAssignment(ctx context.Context, tx *sql.Tx, tenant, _ uuid.UUID, row map[string]any) error {
	ks, _ := row["object_kind"].(string)
	kind, ok := dcim.ParseObjectKind(ks)
	if !ok {
		return ipamInvalid("object_kind %q is not an object kind", ks)
	}
	oid, err := uuid.Parse(strings.TrimSpace(stringOf(row["object_id"])))
	if err != nil {
		return ipamInvalid("object_id must be a UUID")
	}
	if err := objectExists(ctx, tx, tenant, kind, oid); err != nil {
		if errors.Is(err, ErrDcimObjectNotFound) {
			return ErrIPAMNotFound
		}
		return err
	}
	if err := visible(ctx, tx, "contacts", row["contact_id"]); err != nil {
		return err
	}
	if err := visible(ctx, tx, "contact_roles", row["role_id"]); err != nil {
		return err
	}
	return oneOf(row, "priority", contactPriorities)
}

func stringOf(v any) string {
	s, _ := v.(string)
	return s
}

// assignmentListSelect carries the contact and role next to the assignment so
// a panel renders without a second round trip.
const assignmentListSelect = `to_jsonb(t) || jsonb_build_object(
	'contact', jsonb_build_object('id', c.id, 'name', c.name, 'title', c.title, 'phone', c.phone, 'email', c.email),
	'role', jsonb_build_object('id', r.id, 'name', r.name, 'slug', r.slug))`

const assignmentJoin = `JOIN public.contacts c ON c.id = t.contact_id JOIN public.contact_roles r ON r.id = t.role_id`

func contactSpecs() []*ipamSpec {
	return []*ipamSpec{
		{
			Kind: dcim.ObjectKindContact, Table: "contacts", Route: RouteContacts,
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "title", Type: colText},
				ipamCol{Name: "phone", Type: colText},
				ipamCol{Name: "email", Type: colText},
				ipamCol{Name: "address", Type: colText},
				ipamCol{Name: "link", Type: colText},
				ipamCol{Name: "group_id", Type: colUUID},
				externalIDsCol,
			),
			Filters: []ipamFilter{{Param: "group_id", Column: "group_id", Type: colUUID}, {Param: "email", Column: "email", Type: colText}},
			Search:  []string{"name", "title", "email", "phone", "description"},
			Order:   "lower(t.name), t.id",
			Prepare: prepareContact,
		},
		{
			Kind: dcim.ObjectKindContactRole, Table: "contact_roles", Route: RouteContactRoles, Catalogue: true,
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "slug", Type: colText},
			),
			Filters: []ipamFilter{{Param: "slug", Column: "slug", Type: colText}},
			Search:  []string{"name", "slug", "description"},
			Order:   "lower(t.name), t.id",
			Prepare: prepareSlug,
		},
		{
			Kind: dcim.ObjectKindContactAssignment, Table: "contact_assignments", Route: RouteContactAssignments,
			Cols: withSubstrate(
				ipamCol{Name: "object_kind", Type: colText, Required: true},
				ipamCol{Name: "object_id", Type: colUUID, Required: true},
				ipamCol{Name: "contact_id", Type: colUUID, Required: true},
				ipamCol{Name: "role_id", Type: colUUID, Required: true},
				ipamCol{Name: "priority", Type: colText},
			),
			Filters: []ipamFilter{
				{Param: "object_kind", Column: "object_kind", Type: colText},
				{Param: "object_id", Column: "object_id", Type: colUUID},
				{Param: "contact_id", Column: "contact_id", Type: colUUID},
				{Param: "role_id", Column: "role_id", Type: colUUID},
				{Param: "priority", Column: "priority", Type: colText},
			},
			Order:      `CASE t.priority WHEN 'primary' THEN 0 WHEN 'secondary' THEN 1 WHEN 'tertiary' THEN 2 WHEN 'inactive' THEN 4 ELSE 3 END, lower(c.name), t.id`,
			ListSelect: assignmentListSelect, Join: assignmentJoin,
			Prepare: prepareContactAssignment,
		},
	}
}
