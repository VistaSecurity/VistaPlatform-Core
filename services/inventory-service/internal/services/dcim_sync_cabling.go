package services

// The inventory side of the sync for ports and cables (DCIM BUILD_PLAN row
// 3.5; SYNC_MODEL §3). dcim_sync.go owns the protocol; this file answers it for
// cables and for the parked cable a sync resolves:
//
//   - the six port kinds (console, console server, rear, front, power port,
//     power outlet) are plain object-engine kinds (dcimSyncSpecs takes their
//     specs from component_specs.go), so a sync write runs the same Prepare
//     rules — the asset, the front port's rear position, the outlet's power
//     port on the same asset — as a person's;
//   - a cable is listed WITH its ends (a_terminations / b_terminations, the
//     sync's identity) and written through CableService: its termination
//     rules, the compatibility matrix and the path recompute run exactly as
//     for a person's cable. The sync never re-terminates a cable (its ends are
//     identity): an update writes the cable's own columns;
//   - a NetBox cable whose far end is not here is parked on an end we have
//     (one unresolved row per missing termination, each carrying the whole
//     cable); syncApplier.ApplyCable creates it once every termination
//     resolves, stamped external_ids.<peer> — never against an invented port.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/dcim/unresolved"
)

// syncPortKinds are the row 3.5 component kinds the sync writes through the
// object engine (device bays are not synced).
var syncPortKinds = map[dcim.ObjectKind]bool{
	dcim.ObjectKindConsolePort: true, dcim.ObjectKindConsoleServerPort: true, dcim.ObjectKindRearPort: true,
	dcim.ObjectKindFrontPort: true, dcim.ObjectKindPowerPort: true, dcim.ObjectKindPowerOutlet: true,
}

// syncCableEndSQL is one end of a cable as the sync reads it.
func syncCableEndSQL(end string) string {
	return `COALESCE((SELECT jsonb_agg(jsonb_build_object('termination_kind', ct.termination_kind, 'termination_id', ct.termination_id)
		ORDER BY ct.termination_kind, ct.termination_id)
		FROM public.cable_terminations ct WHERE ct.cable_id = t.id AND ct.cable_end = '` + end + `'), '[]'::jsonb)`
}

// listCables pages through the tenant's cables that are not rejected, each with
// its ends. A pending proposal is listed (it holds its ports, and the
// connector must know it to never push it).
func (s *DCIMSyncService) listCables(ctx context.Context, tenant, after uuid.UUID, limit int) ([]SyncObject, bool, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	sp := cableSpec()
	var out []SyncObject
	err := shareddb.WithTenantTx(ctx, s.raw, tenant, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT to_jsonb(t) || jsonb_build_object('a_terminations', `+syncCableEndSQL("A")+
			`, 'b_terminations', `+syncCableEndSQL("B")+`)
			  FROM public.cables t WHERE t.id > $1 AND t.tenant_id = $3 AND t.status <> 'rejected' ORDER BY t.id LIMIT $2`,
			after, limit+1, tenant)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			obj, err := syncObjectOf(sp, dcim.ObjectKindCable, raw)
			if err != nil {
				return err
			}
			out = append(out, obj)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, false, err
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, nil
}

// syncCableBody is a sync write as a cable API body: its columns, its ends
// (create only) and the substrate the sync stamps.
func syncCableBody(values map[string]any, extra map[string]any) ([]byte, error) {
	body := map[string]any{}
	for k, v := range values {
		body[k] = v
	}
	for k, v := range extra {
		body[k] = v
	}
	return json.Marshal(body)
}

// createCable creates a cable pulled from the peer with both ends, through
// CableService (termination rules, compatibility, paths). The peer is the
// customer's declared wiring: the cable is imported and live.
func (o *dcimSyncObjects) createCable(ctx context.Context, tenant uuid.UUID, peer string, it SyncWrite) (uuid.UUID, error) {
	if o.cables == nil {
		return uuid.Nil, fmt.Errorf("%w: cable has no writer", ErrSyncInvalid)
	}
	for _, end := range []string{"a_terminations", "b_terminations"} {
		if err := checkSyncEnd(it.Values[end], end); err != nil {
			return uuid.Nil, err
		}
	}
	body, err := syncCableBody(it.Values, map[string]any{
		"external_ids": externalIDsWith(nil, peer, it.PeerID), "source_kind": "imported",
		"source_ref": peer + ":" + it.PeerID, "status": "active",
	})
	if err != nil {
		return uuid.Nil, err
	}
	raw, err := o.cables.Create(ctx, tenant, body)
	if err != nil {
		return uuid.Nil, mapIPAMError(err, false)
	}
	var got struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		return uuid.Nil, err
	}
	return got.ID, nil
}

// checkSyncEnd refuses a cable end that still names a termination by the
// peer's id: only the resolver writes a parked cable, once every end is here.
func checkSyncEnd(v any, end string) error {
	list, _ := v.([]any)
	if len(list) == 0 {
		return fmt.Errorf("%w: a cable needs %s", ErrSyncInvalid, end)
	}
	for _, e := range list {
		m, _ := e.(map[string]any)
		if _, err := uuid.Parse(fmt.Sprint(m["termination_id"])); err != nil {
			return fmt.Errorf("%w: %s names a termination that is not here (%v)", ErrSyncInvalid, end, e)
		}
	}
	return nil
}

// updateCable writes a cable's synced columns and (un)links the peer id,
// through CableService.Update (a status change moves the paths over it).
func (o *dcimSyncObjects) updateCable(ctx context.Context, tenant uuid.UUID, peer string, it SyncWrite) error {
	if o.cables == nil {
		return fmt.Errorf("%w: cable has no writer", ErrSyncInvalid)
	}
	for _, end := range []string{"a_terminations", "b_terminations"} {
		if _, ok := it.Values[end]; ok {
			return fmt.Errorf("%w: the sync never re-terminates a cable (%s)", ErrSyncInvalid, end)
		}
	}
	extra := map[string]any{}
	if it.PeerID != "" || it.Unlink {
		var cur []byte
		if err := shareddb.WithTenantTx(ctx, o.raw, tenant, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, `SELECT external_ids FROM public.cables WHERE tenant_id = $1 AND id = $2`, tenant, it.ID).Scan(&cur)
		}); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrSyncNotFound
			}
			return err
		}
		var existing map[string]any
		_ = json.Unmarshal(cur, &existing)
		switch {
		case it.Unlink:
			extra["external_ids"] = externalIDsWithout(existing, peer)
		case fmt.Sprint(existing[peer]) != it.PeerID:
			extra["external_ids"] = externalIDsWith(existing, peer, it.PeerID)
		}
	}
	if len(it.Values) == 0 && len(extra) == 0 {
		return nil
	}
	body, err := syncCableBody(it.Values, extra)
	if err != nil {
		return err
	}
	_, err = o.cables.Update(ctx, tenant, it.ID, body)
	return mapIPAMError(err, false)
}

// parkCable checks a cable parked on one of its ends: the origin is a
// termination kind and the values are a cable create's.
func parkCable(p SyncPark) error {
	if _, ok := terminationTables[p.OriginKind]; !ok {
		return fmt.Errorf("%w: a cable cannot be parked on a %s", ErrSyncInvalid, p.OriginKind)
	}
	if p.Intent != unresolved.IntentCable {
		return fmt.Errorf("%w: a parked cable's intent is %q", ErrSyncInvalid, unresolved.IntentCable)
	}
	if strings.TrimSpace(p.PeerID) == "" {
		return fmt.Errorf("%w: a parked cable needs the peer's id", ErrSyncInvalid)
	}
	return checkWriteColumns(mustSyncSpec(dcim.ObjectKindCable), SyncWrite{Op: "create", Values: p.Values})
}

// applyParkedCable creates a cable a sync parked, once every termination it
// names resolves. A termination still missing leaves it to that termination's
// own parked row (each carries the whole cable); a cable the sync already
// created (it pulled the far end and the cable in one run) is satisfied. A
// cable the inventory refuses (a port meanwhile on another cable) is dropped:
// the next sync reports the disagreement in its plan.
func (a syncApplier) applyParkedCable(ctx context.Context, tenant uuid.UUID, p unresolved.Parked) error {
	peerID, _ := p.Attributes["peer_id"].(string)
	m := syncKeyMatcher{raw: a.s.raw}
	if peerID != "" {
		if _, found, err := m.MatchBySyncKey(ctx, tenant, SyncKey(p.Producer, dcim.ObjectKindCable), peerID); err != nil || found {
			return err
		}
	}
	values := map[string]any{}
	if v, ok := p.Attributes["values"].(map[string]any); ok {
		for k, x := range v {
			values[k] = x
		}
	}
	for _, end := range []string{"a_terminations", "b_terminations"} {
		list, _ := values[end].([]any)
		out := make([]any, 0, len(list))
		for _, e := range list {
			t, _ := e.(map[string]any)
			kind := dcim.ObjectKind(fmt.Sprint(t["termination_kind"]))
			if id, ok := t["termination_id"]; ok && id != nil {
				out = append(out, map[string]any{"termination_kind": string(kind), "termination_id": fmt.Sprint(id)})
				continue
			}
			got, found, err := m.MatchBySyncKey(ctx, tenant, SyncKey(p.Producer, kind), fmt.Sprint(t["peer_id"]))
			if err != nil {
				return err
			}
			if !found {
				return nil // still missing: its own parked row creates the cable
			}
			out = append(out, map[string]any{"termination_kind": string(kind), "termination_id": got.ID.String()})
		}
		values[end] = out
	}
	ctx = changes.WithSource(ctx, changes.SyncSource(p.Producer))
	_, err := a.s.create(ctx, tenant, p.Producer, dcim.ObjectKindCable, SyncWrite{Op: "create", Values: values, PeerID: peerID})
	if errors.Is(err, ErrIPAMInvalid) || errors.Is(err, ErrIPAMConflict) || errors.Is(err, ErrSyncInvalid) {
		return nil
	}
	return err
}
