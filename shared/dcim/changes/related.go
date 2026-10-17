package changes

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// DeriveRelated finds the object a change belongs to from the change's own
// images, so every recorder call site gets a parent without being edited and a
// new call site cannot forget one:
//
//   - interface           → its asset (`asset_id`)
//   - mac_address         → its interface's asset
//   - ip_address          → the asset of the interface it is assigned to (or the
//     asset itself when it is assigned to one)
//   - journal_entry       → the object the entry is on
//
// A tag assignment is recorded on the tagged object itself, so it needs no
// parent. ok is false when there is no parent or it cannot be found (the
// interface of an address was deleted first); the change is then recorded
// without one — a missing parent loses a row from a parent's tab, never the
// change.
func DeriveRelated(ctx context.Context, tx DBTX, row Row) (dcim.ObjectKind, uuid.UUID, bool) {
	img := row.PostchangeData
	if img == nil {
		img = row.PrechangeData
	}
	if img == nil {
		return "", uuid.Nil, false
	}
	var m map[string]any
	if json.Unmarshal(img, &m) != nil {
		return "", uuid.Nil, false
	}
	id := func(key string) uuid.UUID {
		s, _ := m[key].(string)
		u, _ := uuid.Parse(s)
		return u
	}
	assetOfInterface := func(iface uuid.UUID) (dcim.ObjectKind, uuid.UUID, bool) {
		if iface == uuid.Nil {
			return "", uuid.Nil, false
		}
		var asset uuid.UUID
		if err := tx.QueryRowContext(ctx,
			`SELECT asset_id FROM public.interfaces WHERE tenant_id = $1 AND id = $2`,
			row.TenantID, iface).Scan(&asset); err != nil || asset == uuid.Nil {
			return "", uuid.Nil, false
		}
		return dcim.ObjectKindAsset, asset, true
	}
	switch row.Kind {
	case dcim.ObjectKindInterface:
		if a := id("asset_id"); a != uuid.Nil {
			return dcim.ObjectKindAsset, a, true
		}
	case dcim.ObjectKindMacAddress:
		return assetOfInterface(id("interface_id"))
	case dcim.ObjectKindIpAddress:
		switch k, _ := m["assigned_kind"].(string); k {
		case string(dcim.ObjectKindInterface):
			return assetOfInterface(id("assigned_id"))
		case string(dcim.ObjectKindAsset):
			if a := id("assigned_id"); a != uuid.Nil {
				return dcim.ObjectKindAsset, a, true
			}
		}
	case dcim.ObjectKindJournalEntry:
		k, ok := dcim.ParseObjectKind(strOf(m["object_kind"]))
		if o := id("object_id"); ok && o != uuid.Nil {
			return k, o, true
		}
	}
	return "", uuid.Nil, false
}

func strOf(v any) string { s, _ := v.(string); return s }
