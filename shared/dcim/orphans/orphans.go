// Package orphans cleans up polymorphic references that point at an object
// which no longer exists.
//
// A DCIM table that names another object by (kind, id) pair — a tag on a
// device, a journal entry on a prefix, an address assigned to an interface —
// cannot carry a foreign key, because the id may live in any of several
// tables. Deleting the object therefore leaves the reference behind unless the
// delete path remembers to clean it, and there are many delete paths, some of
// them cascades no service sees.
//
// This package is the backstop. Registry classifies EVERY such pair in the
// schema: removed with its object (Delete), cleared to NULL (Null), swept by a
// dedicated path (Elsewhere) or kept on purpose (Retained). Sweep applies the
// first two. orphans_test.go reads schema.sql and fails when a table gains a
// (kind, id) pair that Registry does not name, so a new polymorphic reference
// cannot ship unswept.
package orphans

import (
	"context"
	"database/sql"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// Action is what happens to a reference whose object is gone.
type Action int

const (
	// Delete removes the referencing row: it only has meaning on its object
	// (a tag, a journal entry, a contact assignment).
	Delete Action = iota + 1
	// Null clears the (kind, id) pair on a row that stands on its own and
	// merely pointed at the object (an address's assignment, a prefix's scope).
	Null
	// Elsewhere marks a pair a dedicated path already sweeps.
	Elsewhere
	// Retained marks a pair kept after its object is gone on purpose.
	Retained
)

// Ref is one (kind, id) pair in the schema.
type Ref struct {
	Table   string
	KindCol string
	IDCol   string
	Action  Action
	// Note says why an Elsewhere or Retained pair is not swept here.
	Note string
}

// Key is "table.kind_column", the name the schema test reports.
func (r Ref) Key() string { return r.Table + "." + r.KindCol }

// Registry classifies every polymorphic reference in schema.sql.
var Registry = []Ref{
	{Table: "object_tags", KindCol: "object_kind", IDCol: "object_id", Action: Delete},
	{Table: "journal_entries", KindCol: "object_kind", IDCol: "object_id", Action: Delete},
	{Table: "image_attachments", KindCol: "object_kind", IDCol: "object_id", Action: Delete},
	{Table: "contact_assignments", KindCol: "object_kind", IDCol: "object_id", Action: Delete},
	{Table: "l2vpn_terminations", KindCol: "assigned_kind", IDCol: "assigned_id", Action: Delete},
	{Table: "tunnel_terminations", KindCol: "termination_kind", IDCol: "termination_id", Action: Delete},
	{Table: "unresolved_terminations", KindCol: "origin_kind", IDCol: "origin_id", Action: Delete},

	{Table: "ip_addresses", KindCol: "assigned_kind", IDCol: "assigned_id", Action: Null},
	{Table: "inventory_items", KindCol: "component_kind", IDCol: "component_id", Action: Null},
	{Table: "circuit_terminations", KindCol: "termination_kind", IDCol: "termination_id", Action: Null},
	{Table: "prefixes", KindCol: "scope_kind", IDCol: "scope_id", Action: Null},
	{Table: "vlan_groups", KindCol: "scope_kind", IDCol: "scope_id", Action: Null},
	{Table: "clusters", KindCol: "scope_kind", IDCol: "scope_id", Action: Null},

	{Table: "cable_terminations", KindCol: "termination_kind", IDCol: "termination_id", Action: Elsewhere,
		Note: "inventory-service sweepOrphanTerminations detaches the end and recomputes the paths in the delete's transaction"},
	{Table: "cable_paths", KindCol: "origin_kind", IDCol: "origin_id", Action: Elsewhere,
		Note: "shared/dcim/cablepath recomputes a path when a cable, port mapping or termination on it changes"},
	{Table: "cable_paths", KindCol: "destination_kind", IDCol: "destination_id", Action: Elsewhere,
		Note: "recomputed with the origin's path"},

	{Table: "object_changes", KindCol: "object_kind", IDCol: "object_id", Action: Retained,
		Note: "the change log outlives its object: it holds the post-image of the delete"},
	{Table: "object_changes", KindCol: "related_kind", IDCol: "related_id", Action: Retained,
		Note: "same: the parent a change belonged to may be gone"},
	{Table: "sync_conflicts", KindCol: "object_kind", IDCol: "object_id", Action: Retained,
		Note: "a conflict is a record of what the peer and Vista disagreed on, resolved by a person"},
}

// DBTX is the slice of *sql.Tx (or *sql.DB) Sweep needs.
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Report is what one Sweep found (DryRun) or fixed.
type Report struct {
	// Rows counts affected rows by Ref.Key().
	Rows map[string]int
	// ImageRefs are the storage refs of image_attachments rows that were
	// deleted: their bytes are the caller's to remove (this package cannot
	// reach object storage).
	ImageRefs []string
}

// Total is the number of rows affected.
func (r Report) Total() int {
	n := 0
	for _, c := range r.Rows {
		n += c
	}
	return n
}

// Keys returns the Ref keys that had affected rows, sorted.
func (r Report) Keys() []string {
	var out []string
	for k, c := range r.Rows {
		if c > 0 {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Sweep removes or clears the tenant's references to objects that no longer
// exist. With dryRun it only counts them. Run it in the tenant's RLS session.
// A kind the schema has no table for yet is skipped, not an error.
func Sweep(ctx context.Context, tx DBTX, tenant uuid.UUID, dryRun bool) (Report, error) {
	rep := Report{Rows: map[string]int{}}
	for _, ref := range Registry {
		if ref.Action != Delete && ref.Action != Null {
			continue
		}
		kinds, err := presentKinds(ctx, tx, tenant, ref)
		if err != nil {
			return rep, fmt.Errorf("orphans: %s: %w", ref.Key(), err)
		}
		for _, kind := range kinds {
			target := dcim.ObjectKind(kind).Table()
			if target == "" {
				continue
			}
			exists, err := tableExists(ctx, tx, target)
			if err != nil {
				return rep, fmt.Errorf("orphans: %s: %w", ref.Key(), err)
			}
			if !exists {
				continue
			}
			n, refs, err := sweepOne(ctx, tx, tenant, ref, kind, target, dryRun)
			if err != nil {
				return rep, fmt.Errorf("orphans: %s kind %s: %w", ref.Key(), kind, err)
			}
			rep.Rows[ref.Key()] += n
			rep.ImageRefs = append(rep.ImageRefs, refs...)
		}
	}
	return rep, nil
}

func presentKinds(ctx context.Context, tx DBTX, tenant uuid.UUID, ref Ref) ([]string, error) {
	rows, err := tx.QueryContext(ctx, fmt.Sprintf(`SELECT DISTINCT %[2]s FROM public.%[1]s WHERE tenant_id = $1 AND %[2]s IS NOT NULL`,
		pq.QuoteIdentifier(ref.Table), pq.QuoteIdentifier(ref.KindCol)), tenant)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func tableExists(ctx context.Context, tx DBTX, table string) (bool, error) {
	var ok bool
	err := tx.QueryRowContext(ctx, `SELECT to_regclass('public.' || quote_ident($1)) IS NOT NULL`, table).Scan(&ok)
	return ok, err
}

func sweepOne(ctx context.Context, tx DBTX, tenant uuid.UUID, ref Ref, kind, target string, dryRun bool) (int, []string, error) {
	tbl, kc, ic, tgt := pq.QuoteIdentifier(ref.Table), pq.QuoteIdentifier(ref.KindCol), pq.QuoteIdentifier(ref.IDCol), pq.QuoteIdentifier(target)
	gone := fmt.Sprintf(`r.tenant_id = $1 AND r.%s = $2 AND NOT EXISTS (SELECT 1 FROM public.%s x WHERE x.id = r.%s)`, kc, tgt, ic)

	if dryRun {
		var n int
		err := tx.QueryRowContext(ctx, fmt.Sprintf(`SELECT count(*) FROM public.%s r WHERE %s`, tbl, gone), tenant, kind).Scan(&n)
		return n, nil, err
	}

	switch ref.Action {
	case Null:
		res, err := tx.ExecContext(ctx, fmt.Sprintf(`UPDATE public.%[1]s r SET %[2]s = NULL, %[3]s = NULL WHERE %[4]s`, tbl, kc, ic, gone), tenant, kind)
		if err != nil {
			return 0, nil, err
		}
		n, err := res.RowsAffected()
		return int(n), nil, err
	case Delete:
		if ref.Table == "image_attachments" {
			rows, err := tx.QueryContext(ctx, fmt.Sprintf(`DELETE FROM public.%s r WHERE %s RETURNING r.storage_ref`, tbl, gone), tenant, kind)
			if err != nil {
				return 0, nil, err
			}
			defer func() { _ = rows.Close() }()
			var refs []string
			n := 0
			for rows.Next() {
				var s sql.NullString
				if err := rows.Scan(&s); err != nil {
					return 0, nil, err
				}
				n++
				if s.Valid && s.String != "" {
					refs = append(refs, s.String)
				}
			}
			if err := rows.Err(); err != nil {
				return 0, nil, err
			}
			return n, refs, nil
		}
		res, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM public.%s r WHERE %s`, tbl, gone), tenant, kind)
		if err != nil {
			return 0, nil, err
		}
		n, err := res.RowsAffected()
		return int(n), nil, err
	}
	return 0, nil, nil
}
