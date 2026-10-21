package postgres

// DCIM gap 1, part 2: the virtual device contexts of an observation — a
// Fortinet VDOM, a Palo Alto vsys, an F5 route domain, a Cisco Nexus VDC —
// recorded on the engine's own transaction by the networkWriter, after the
// interfaces, so each interface that names its context can be added to it.
//
// The rules, in SYNC_MODEL's authority terms (collectors are held to them as
// a sync is):
//
//   - A context is matched by (asset, name) over rows that are not rejected —
//     the table's identity. A context no row holds is created with the
//     observation's source kind (`measured` from a collector), its status
//     following its asset (`pending` on an asset waiting in Approvals,
//     `active` on an approved one; a pending context is promoted by the next
//     observation once the asset is approved, as an interface is), and the
//     device's identifier where the platform numbers its contexts.
//   - A MEASURED context gets its identifier refreshed (when the device states
//     one no other context of the asset holds), its status brought back from
//     stale, its description set to the operator's display name when the
//     device states one (an empty one never clears what is stored), and its
//     last_seen_at / observation_count moved.
//   - A DECLARED or IMPORTED context of the same name — a person's, or
//     NetBox's — is matched and never overwritten: only last_seen_at and
//     observation_count move. Its name, identifier, status, business unit,
//     primary addresses and description stay what was said.
//   - An interface naming a context is added to it. Its memberships of OTHER
//     measured contexts of the asset are removed (the device says which one
//     owns the interface); a membership of a declared or imported context is
//     never removed by a collector.
//   - A measured context the device has stopped reporting is marked `stale`
//     once its last_seen_at is older than the tenant's stale window
//     (asset_lifecycle_policies.stale_warning_days, else 30 days), and only
//     by an observation that reports contexts at all — a collector that
//     cannot see contexts says nothing about them. A collector never deletes
//     a context.
//
// Every row it creates or visibly changes is recorded in `object_changes`.

import (
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// defaultContextStaleDays is the asset lifecycle default
// (asset_lifecycle_policies.stale_warning_days' column default), used when
// the tenant has no policy row — the window interfaces go stale by.
const defaultContextStaleDays = 30

// storedContext is the slice of a virtual_device_contexts row this writer
// reads.
type storedContext struct {
	id         uuid.UUID
	identifier sql.NullInt64
	// description is the stored description; "" when NULL.
	description string
	sourceKind  string
	status      string
	lastSeen    time.Time
}

func (w *networkWriter) loadContexts() (map[string]*storedContext, error) {
	rows, err := w.tx.QueryContext(w.ctx, `
		SELECT id, name, identifier, COALESCE(description, ''), source_kind, status, last_seen_at
		  FROM public.virtual_device_contexts
		 WHERE tenant_id = $1 AND asset_id = $2 AND status <> 'rejected'`, w.tenant, w.asset)
	if err != nil {
		return nil, fmt.Errorf("identity/postgres: read virtual device contexts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]*storedContext{}
	for rows.Next() {
		var (
			c    storedContext
			name string
		)
		if err := rows.Scan(&c.id, &name, &c.identifier, &c.description, &c.sourceKind, &c.status, &c.lastSeen); err != nil {
			return nil, fmt.Errorf("identity/postgres: scan virtual device context: %w", err)
		}
		out[name] = &c
	}
	return out, rows.Err()
}

// identifierFree reports whether no other context of the asset (rejected ones
// aside) holds identifier — the virtual_device_contexts_identifier_uniq rule,
// asked first so a collision is a skip, not a failed transaction.
func identifierFree(all map[string]*storedContext, identifier int, self uuid.UUID) bool {
	for _, c := range all {
		if c.id != self && c.identifier.Valid && c.identifier.Int64 == int64(identifier) {
			return false
		}
	}
	return true
}

// virtualDeviceContexts records the observation's contexts and the
// interfaces' memberships, then marks the measured contexts it no longer
// reports stale past the window.
func (w *networkWriter) virtualDeviceContexts(n identity.ObservedNetwork) error {
	if len(n.VirtualDeviceContexts) == 0 {
		return nil
	}
	all, err := w.loadContexts()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, c := range n.VirtualDeviceContexts {
		if seen[c.Name] {
			continue
		}
		seen[c.Name] = true
		if cur, ok := all[c.Name]; ok {
			if err := w.refreshContext(c, cur, all); err != nil {
				return err
			}
			continue
		}
		row, err := w.createContext(c, all)
		if err != nil {
			return err
		}
		all[c.Name] = row
	}
	if err := w.contextMemberships(n.Interfaces, all); err != nil {
		return err
	}
	return w.staleContexts(all, seen)
}

func (w *networkWriter) createContext(c identity.ObservedVirtualDeviceContext, all map[string]*storedContext) (*storedContext, error) {
	id := uuid.New()
	kind := sourceKindOr(w.src.Kind)
	var identifier sql.NullInt64
	if c.Identifier != nil {
		if identifierFree(all, *c.Identifier, id) {
			identifier = sql.NullInt64{Int64: int64(*c.Identifier), Valid: true}
		} else {
			w.skip("virtual device context %q: identifier %d is another context's on the asset; recorded without it", c.Name, *c.Identifier)
		}
	}
	if _, err := w.tx.ExecContext(w.ctx, `
		INSERT INTO public.virtual_device_contexts (id, tenant_id, asset_id, name, identifier, description, source_kind, source_ref,
		                                            status, first_seen_at, last_seen_at, observation_count)
		VALUES ($1, $2, $3, $4, $5, NULLIF($10, ''), $6, NULLIF($7, ''), $8, $9, $9, 1)`,
		id, w.tenant, w.asset, c.Name, identifier, kind, w.src.Ref, w.status, w.at, c.Description); err != nil {
		return nil, fmt.Errorf("identity/postgres: create virtual device context %q: %w", c.Name, err)
	}
	w.res.ContextsCreated++
	post := map[string]any{"name": c.Name, "asset_id": w.asset.String(), "source_kind": kind, "status": w.status}
	if identifier.Valid {
		post["identifier"] = identifier.Int64
	}
	if c.Description != "" {
		post["description"] = c.Description
	}
	if err := w.record(dcim.ObjectKindVirtualDeviceContext, id, changes.ActionCreate, nil, post); err != nil {
		return nil, err
	}
	return &storedContext{id: id, identifier: identifier, description: c.Description, sourceKind: kind, status: w.status, lastSeen: w.at}, nil
}

// refreshContext moves an existing context's sighting counters and, for a
// measured one only, its identifier and status.
func (w *networkWriter) refreshContext(c identity.ObservedVirtualDeviceContext, cur *storedContext, all map[string]*storedContext) error {
	status, identifier, description := cur.status, cur.identifier, cur.description
	// A person's (or NetBox's) context is matched, never overwritten: the
	// collector moves only when it was last seen.
	if cur.sourceKind == string(identity.SourceMeasured) {
		if status == "stale" || (status == "pending" && w.status == "active") {
			status = w.status
		}
		if c.Identifier != nil && (!identifier.Valid || identifier.Int64 != int64(*c.Identifier)) {
			if identifierFree(all, *c.Identifier, cur.id) {
				identifier = sql.NullInt64{Int64: int64(*c.Identifier), Valid: true}
			} else {
				w.skip("virtual device context %q: identifier %d is another context's on the asset; left as it was", c.Name, *c.Identifier)
			}
		}
		// The operator's display name follows the device; an empty one is no
		// answer and leaves the stored one.
		if c.Description != "" {
			description = c.Description
		}
	}
	if _, err := w.tx.ExecContext(w.ctx, `
		UPDATE public.virtual_device_contexts
		   SET status = $3, identifier = $4, description = CASE WHEN $7::bool THEN NULLIF($6, '') ELSE description END,
		       observation_count = observation_count + CASE WHEN last_seen_at >= $5 THEN 0 ELSE 1 END,
		       last_seen_at = GREATEST(last_seen_at, $5), updated_at = now()
		 WHERE tenant_id = $1 AND id = $2`,
		w.tenant, cur.id, status, identifier, w.at, description, description != cur.description); err != nil {
		return fmt.Errorf("identity/postgres: refresh virtual device context %q: %w", c.Name, err)
	}
	w.res.ContextsUpdated++
	pre, post := map[string]any{}, map[string]any{}
	if status != cur.status {
		pre["status"], post["status"] = cur.status, status
	}
	if identifier != cur.identifier {
		pre["identifier"], post["identifier"] = nullInt(cur.identifier), nullInt(identifier)
	}
	if description != cur.description {
		pre["description"], post["description"] = nullString(cur.description), description
	}
	cur.status, cur.identifier, cur.description = status, identifier, description
	if w.at.After(cur.lastSeen) {
		cur.lastSeen = w.at
	}
	if len(post) == 0 {
		return nil
	}
	return w.record(dcim.ObjectKindVirtualDeviceContext, cur.id, changes.ActionUpdate, pre, post)
}

// nullString is a stored description as a change-record value: nil for none.
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// contextMemberships adds each interface to the context it names, and takes
// it out of the asset's other MEASURED contexts.
func (w *networkWriter) contextMemberships(obs []identity.ObservedInterface, all map[string]*storedContext) error {
	measured := map[uuid.UUID]bool{}
	for _, c := range all {
		if c.sourceKind == string(identity.SourceMeasured) {
			measured[c.id] = true
		}
	}
	for _, o := range obs {
		ctx, ok := all[o.VirtualDeviceContext]
		if o.VirtualDeviceContext == "" || !ok {
			continue
		}
		var ifID uuid.UUID
		err := w.tx.QueryRowContext(w.ctx, `
			SELECT id FROM public.interfaces WHERE tenant_id = $1 AND asset_id = $2 AND name = $3 AND status <> 'rejected'`,
			w.tenant, w.asset, o.Name).Scan(&ifID)
		if errors.Is(err, sql.ErrNoRows) {
			w.skip("virtual device context %q: no interface %q on the observed asset", o.VirtualDeviceContext, o.Name)
			continue
		}
		if err != nil {
			return fmt.Errorf("identity/postgres: read interface %q: %w", o.Name, err)
		}
		var cur []string
		if err := w.tx.QueryRowContext(w.ctx, `
			SELECT ARRAY(SELECT virtual_device_context_id::text FROM public.interface_virtual_device_contexts
			              WHERE tenant_id = $1 AND interface_id = $2 ORDER BY virtual_device_context_id)`,
			w.tenant, ifID).Scan(pq.Array(&cur)); err != nil {
			return fmt.Errorf("identity/postgres: read memberships of %q: %w", o.Name, err)
		}
		next := []string{ctx.id.String()}
		var drop []string
		for _, id := range cur {
			u, err := uuid.Parse(id)
			switch {
			case err != nil, u == ctx.id:
			case measured[u]:
				drop = append(drop, id)
				continue
			default:
				next = append(next, id)
			}
		}
		slices.Sort(next)
		next = slices.Compact(next)
		if slices.Equal(cur, next) {
			continue
		}
		if len(drop) > 0 {
			if _, err := w.tx.ExecContext(w.ctx, `
				DELETE FROM public.interface_virtual_device_contexts
				 WHERE tenant_id = $1 AND interface_id = $2 AND virtual_device_context_id = ANY($3::uuid[])`,
				w.tenant, ifID, pq.Array(drop)); err != nil {
				return fmt.Errorf("identity/postgres: leave virtual device contexts on %q: %w", o.Name, err)
			}
		}
		if _, err := w.tx.ExecContext(w.ctx, `
			INSERT INTO public.interface_virtual_device_contexts (tenant_id, interface_id, virtual_device_context_id)
			VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, w.tenant, ifID, ctx.id); err != nil {
			return fmt.Errorf("identity/postgres: join virtual device context %q on %q: %w", o.VirtualDeviceContext, o.Name, err)
		}
		if err := w.record(dcim.ObjectKindInterface, ifID, changes.ActionUpdate,
			map[string]any{"virtual_device_context_ids": cur}, map[string]any{"virtual_device_context_ids": next}); err != nil {
			return err
		}
	}
	return nil
}

// staleContexts marks the asset's measured contexts this observation did not
// report stale once they have gone unseen past the tenant's window.
func (w *networkWriter) staleContexts(all map[string]*storedContext, seen map[string]bool) error {
	days := defaultContextStaleDays
	var policyDays sql.NullInt64
	err := w.tx.QueryRowContext(w.ctx,
		`SELECT stale_warning_days FROM public.asset_lifecycle_policies WHERE tenant_id = $1`, w.tenant).Scan(&policyDays)
	switch {
	case err == nil && policyDays.Valid && policyDays.Int64 > 0:
		days = int(policyDays.Int64)
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("identity/postgres: read the stale window: %w", err)
	}
	cutoff := w.at.AddDate(0, 0, -days)
	for name, c := range all {
		if seen[name] || c.sourceKind != string(identity.SourceMeasured) || (c.status != "active" && c.status != "pending") {
			continue
		}
		if !c.lastSeen.Before(cutoff) {
			continue
		}
		if _, err := w.tx.ExecContext(w.ctx, `
			UPDATE public.virtual_device_contexts SET status = 'stale', updated_at = now()
			 WHERE tenant_id = $1 AND id = $2`, w.tenant, c.id); err != nil {
			return fmt.Errorf("identity/postgres: mark virtual device context %q stale: %w", name, err)
		}
		w.res.ContextsMarkedStale++
		if err := w.record(dcim.ObjectKindVirtualDeviceContext, c.id, changes.ActionUpdate,
			map[string]any{"status": c.status}, map[string]any{"status": "stale"}); err != nil {
			return err
		}
		c.status = "stale"
	}
	return nil
}
