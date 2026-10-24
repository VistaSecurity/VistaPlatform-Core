package postgres

// DCIM row 4.4: the wireless half of an observation's network evidence --
// an access point's SSIDs, the interfaces that serve them, its point-to-point
// links, and a client's own radio joined to a LAN -- recorded on the engine's
// own transaction by the same networkWriter that records its interfaces.
//
// Posture only. A LAN carries its authentication scheme, cipher and whether a
// pre-shared key EXISTS; no field of any input can hold the key. A LAN is
// matched by (SSID, group) -- never by anything an access point's BSSID says --
// and arrives `measured` with its status following the access point that
// serves it, as the AP's interfaces do: `active` from an approved device,
// `pending` otherwise, and a measured LAN still `pending` (or `stale`) is
// promoted the next time an approved device serves it. An existing LAN's auth
// fields are refreshed when nobody declared it (a declared LAN's are filled
// only where empty); its description, VLAN and business unit are never
// written after creation, nor is a status a person set. An interface gains the
// LANs it serves and never loses one.
//
// A station (a client's radio, ObservedWirelessStation) is the asset's
// interface holding the station's MAC: it gains the LAN it joined in
// wireless_lan_ids, rf_role `station` where none is set, and the 802.11 type
// while it is still `other`. The LAN must already exist (an access point
// reported it): a client's join never creates a LAN, and an SSID two LANs
// share (two groups) is not guessed between.

import (
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/dcim/wireless"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

func (w *networkWriter) wirelessOf(n identity.ObservedNetwork) error {
	if len(n.WirelessLANs) == 0 && len(n.WirelessLinks) == 0 && len(n.WirelessStations) == 0 {
		return nil
	}
	lans := map[string]uuid.UUID{} // by SSID, for this observation
	for _, l := range n.WirelessLANs {
		id, err := w.wirelessLAN(l)
		if err != nil {
			return err
		}
		lans[l.SSID] = id
	}
	if err := w.serveLANs(n.Interfaces, lans); err != nil {
		return err
	}
	for _, k := range n.WirelessLinks {
		if err := w.wirelessLink(k); err != nil {
			return err
		}
	}
	for _, st := range n.WirelessStations {
		if err := w.wirelessStation(st, lans); err != nil {
			return err
		}
	}
	return nil
}

// algorithmID is the catalogue row that scores a LAN's protection, nil when
// none can be named (not assessed).
func (w *networkWriter) algorithmID(authType, cipher string) (any, error) {
	code := wireless.AlgorithmCode(authType, cipher)
	if code == "" {
		return nil, nil
	}
	var id uuid.UUID
	err := w.tx.QueryRowContext(w.ctx, `SELECT id FROM public.algorithms WHERE code = $1`, code).Scan(&id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("identity/postgres: read algorithm %s: %w", code, err)
	}
	return id, nil
}

func (w *networkWriter) wirelessGroup(name string) (any, error) {
	if name == "" {
		return nil, nil
	}
	var id uuid.UUID
	err := w.tx.QueryRowContext(w.ctx, `SELECT id FROM public.wireless_lan_groups WHERE tenant_id = $1 AND name = $2`, w.tenant, name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		id = uuid.New()
		slug := slugOf(name)
		if slug == "" {
			slug = id.String()
		}
		if _, err = w.tx.ExecContext(w.ctx, `
			INSERT INTO public.wireless_lan_groups (id, tenant_id, name, slug, source_kind, source_ref)
			VALUES ($1, $2, $3, $4, 'measured', NULLIF($5, ''))
			ON CONFLICT DO NOTHING`, id, w.tenant, name, slug, w.src.Ref); err != nil {
			return nil, fmt.Errorf("identity/postgres: create wireless LAN group %q: %w", name, err)
		}
		// A slug collision (two names, one slug) leaves the row unwritten;
		// read back whichever holds the name.
		if err := w.tx.QueryRowContext(w.ctx, `SELECT id FROM public.wireless_lan_groups WHERE tenant_id = $1 AND name = $2`, w.tenant, name).Scan(&id); err != nil {
			return nil, nil
		}
		return id, w.record(dcim.ObjectKindWirelessLanGroup, id, changes.ActionCreate, nil, map[string]any{"name": name, "source_kind": "measured"})
	}
	if err != nil {
		return nil, fmt.Errorf("identity/postgres: read wireless LAN group %q: %w", name, err)
	}
	return id, nil
}

func slugOf(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func (w *networkWriter) wirelessLAN(l identity.ObservedWirelessLAN) (uuid.UUID, error) {
	group, err := w.wirelessGroup(l.Group)
	if err != nil {
		return uuid.Nil, err
	}
	var vlan any
	if id, ok := w.vlans[l.VLAN]; ok {
		vlan = id
	}
	algo, err := w.algorithmID(l.AuthType, l.AuthCipher)
	if err != nil {
		return uuid.Nil, err
	}
	var (
		id                 uuid.UUID
		srcKind, status    string
		curType, curCipher sql.NullString
		curPSK             bool
		curAlgo            uuid.NullUUID
	)
	err = w.tx.QueryRowContext(w.ctx, `
		SELECT id, source_kind, status, auth_type, auth_cipher, auth_psk_present, algorithm_id FROM public.wireless_lans
		 WHERE tenant_id = $1 AND ssid = $2
		   AND COALESCE(group_id, '00000000-0000-0000-0000-000000000000'::uuid) = COALESCE($3::uuid, '00000000-0000-0000-0000-000000000000'::uuid)
		   AND status <> 'rejected' FOR UPDATE`, w.tenant, l.SSID, group).Scan(&id, &srcKind, &status, &curType, &curCipher, &curPSK, &curAlgo)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		id = uuid.New()
		if _, err := w.tx.ExecContext(w.ctx, `
			INSERT INTO public.wireless_lans (id, tenant_id, ssid, group_id, vlan_id, auth_type, auth_cipher, auth_psk_present,
			                                  algorithm_id, source_kind, source_ref, status, first_seen_at, last_seen_at, observation_count)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'measured', NULLIF($10, ''), $12, $11, $11, 1)`,
			id, w.tenant, l.SSID, group, vlan, nilIfBlank(l.AuthType), nilIfBlank(l.AuthCipher), l.PSKPresent, algo, w.src.Ref, w.at, w.status); err != nil {
			return uuid.Nil, fmt.Errorf("identity/postgres: create wireless LAN %q: %w", l.SSID, err)
		}
		w.res.WirelessLANsCreated++
		post := map[string]any{"ssid": l.SSID, "source_kind": "measured", "status": w.status, "auth_psk_present": l.PSKPresent}
		if l.AuthType != "" {
			post["auth_type"] = l.AuthType
		}
		if l.AuthCipher != "" {
			post["auth_cipher"] = l.AuthCipher
		}
		return id, w.record(dcim.ObjectKindWirelessLan, id, changes.ActionCreate, nil, post)
	case err != nil:
		return uuid.Nil, fmt.Errorf("identity/postgres: read wireless LAN %q: %w", l.SSID, err)
	}
	// Refresh the measurements. A declared LAN keeps what a person said and is
	// filled only where empty.
	declared := srcKind == "declared"
	newType, newCipher := curType, curCipher
	if l.AuthType != "" && (!declared || !curType.Valid) {
		newType = sql.NullString{String: l.AuthType, Valid: true}
		if l.AuthCipher != "" {
			newCipher = sql.NullString{String: l.AuthCipher, Valid: true}
		} else if !declared {
			newCipher = sql.NullString{}
		}
	}
	newPSK := l.PSKPresent
	if declared {
		newPSK = curPSK || l.PSKPresent
	}
	newAlgo := curAlgo
	if code := wireless.AlgorithmCode(newType.String, newCipher.String); newType.Valid && code != "" {
		a, err := w.algorithmID(newType.String, newCipher.String)
		if err != nil {
			return uuid.Nil, err
		}
		if u, ok := a.(uuid.UUID); ok {
			newAlgo = uuid.NullUUID{UUID: u, Valid: true}
		}
	} else if newType != curType || newCipher != curCipher {
		newAlgo = uuid.NullUUID{}
	}
	newStatus := w.followedStatus(srcKind, status)
	if _, err := w.tx.ExecContext(w.ctx, `
		UPDATE public.wireless_lans
		   SET auth_type = $3, auth_cipher = $4, auth_psk_present = $5, algorithm_id = $6,
		       vlan_id = COALESCE(vlan_id, $7::uuid), status = $9,
		       observation_count = observation_count + 1, first_seen_at = COALESCE(first_seen_at, $8),
		       last_seen_at = GREATEST(COALESCE(last_seen_at, $8), $8), updated_at = now()
		 WHERE tenant_id = $1 AND id = $2`,
		w.tenant, id, newType, newCipher, newPSK, newAlgo, vlan, w.at, newStatus); err != nil {
		return uuid.Nil, fmt.Errorf("identity/postgres: refresh wireless LAN %q: %w", l.SSID, err)
	}
	w.res.WirelessLANsUpdated++
	pre, post := map[string]any{}, map[string]any{}
	diff := func(col string, before, after any) {
		if fmt.Sprint(before) != fmt.Sprint(after) {
			pre[col], post[col] = before, after
		}
	}
	diff("auth_type", nullableStr(curType), nullableStr(newType))
	diff("auth_cipher", nullableStr(curCipher), nullableStr(newCipher))
	diff("auth_psk_present", curPSK, newPSK)
	diff("status", status, newStatus)
	if len(post) == 0 {
		return id, nil
	}
	return id, w.record(dcim.ObjectKindWirelessLan, id, changes.ActionUpdate, pre, post)
}

// serveLANs adds each interface's LANs to its wireless_lan_ids and sets an
// empty rf_role, by canonical name on the observed asset.
func (w *networkWriter) serveLANs(obs []identity.ObservedInterface, lans map[string]uuid.UUID) error {
	for _, o := range obs {
		if len(o.SSIDs) == 0 && o.RFRole == "" {
			continue
		}
		var (
			id   uuid.UUID
			cur  []string
			role sql.NullString
		)
		err := w.tx.QueryRowContext(w.ctx, `
			SELECT id, ARRAY(SELECT x::text FROM unnest(wireless_lan_ids) x), rf_role FROM public.interfaces
			 WHERE tenant_id = $1 AND asset_id = $2 AND name = $3 AND status <> 'rejected'`, w.tenant, w.asset, o.Name).Scan(&id, pq.Array(&cur), &role)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return fmt.Errorf("identity/postgres: read interface %q: %w", o.Name, err)
		}
		next := slices.Clone(cur)
		for _, ssid := range o.SSIDs {
			if lid, ok := lans[ssid]; ok && !slices.Contains(next, lid.String()) {
				next = append(next, lid.String())
			}
		}
		newRole := role
		if !role.Valid && o.RFRole != "" {
			newRole = sql.NullString{String: o.RFRole, Valid: true}
		}
		if len(next) == len(cur) && newRole == role {
			continue
		}
		if _, err := w.tx.ExecContext(w.ctx, `
			UPDATE public.interfaces SET wireless_lan_ids = $3::uuid[], rf_role = $4, updated_at = now()
			 WHERE tenant_id = $1 AND id = $2`, w.tenant, id, pq.Array(next), newRole); err != nil {
			return fmt.Errorf("identity/postgres: serve wireless LANs on %q: %w", o.Name, err)
		}
		pre, post := map[string]any{}, map[string]any{}
		if len(next) != len(cur) {
			pre["wireless_lan_ids"], post["wireless_lan_ids"] = cur, next
		}
		if newRole != role {
			pre["rf_role"], post["rf_role"] = nullableStr(role), nullableStr(newRole)
		}
		if err := w.record(dcim.ObjectKindInterface, id, changes.ActionUpdate, pre, post); err != nil {
			return err
		}
	}
	return nil
}

// wirelessLink records a measured link between an interface of the observed
// asset (by name) and the interface the tenant holds with the far MAC.
func (w *networkWriter) wirelessLink(k identity.ObservedWirelessLink) error {
	var a uuid.UUID
	err := w.tx.QueryRowContext(w.ctx, `SELECT id FROM public.interfaces WHERE tenant_id = $1 AND asset_id = $2 AND name = $3 AND status <> 'rejected'`,
		w.tenant, w.asset, k.InterfaceA).Scan(&a)
	if errors.Is(err, sql.ErrNoRows) {
		w.skip("wireless link: no interface %q on the observed asset", k.InterfaceA)
		return nil
	}
	if err != nil {
		return fmt.Errorf("identity/postgres: read link end %q: %w", k.InterfaceA, err)
	}
	rows, err := w.tx.QueryContext(w.ctx, `SELECT id FROM public.interfaces WHERE tenant_id = $1 AND mac_address = $2::macaddr8 AND status <> 'rejected' AND id <> $3 LIMIT 2`,
		w.tenant, k.InterfaceB, a)
	if err != nil {
		return fmt.Errorf("identity/postgres: read link far end %s: %w", k.InterfaceB, err)
	}
	var ends []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		ends = append(ends, id)
	}
	_ = rows.Close()
	if len(ends) != 1 {
		w.skip("wireless link to %s: the tenant holds %d interfaces with that MAC (one is needed)", k.InterfaceB, len(ends))
		return nil
	}
	b := ends[0]
	if k.Status == "" {
		k.Status = "connected"
	}
	var existing uuid.UUID
	err = w.tx.QueryRowContext(w.ctx, `
		SELECT id FROM public.wireless_links WHERE tenant_id = $1 AND status <> 'rejected'
		   AND LEAST(interface_a_id, interface_b_id) = LEAST($2::uuid, $3::uuid) AND GREATEST(interface_a_id, interface_b_id) = GREATEST($2::uuid, $3::uuid)
		 FOR UPDATE`, w.tenant, a, b).Scan(&existing)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		id := uuid.New()
		if _, err := w.tx.ExecContext(w.ctx, `
			INSERT INTO public.wireless_links (id, tenant_id, interface_a_id, interface_b_id, ssid, operational_status, source_kind, source_ref,
			                                   status, first_seen_at, last_seen_at, observation_count)
			VALUES ($1, $2, $3, $4, $5, $6, 'measured', NULLIF($7, ''), 'pending', $8, $8, 1)`,
			id, w.tenant, a, b, nilIfBlank(k.SSID), k.Status, w.src.Ref, w.at); err != nil {
			return fmt.Errorf("identity/postgres: create wireless link: %w", err)
		}
		w.res.WirelessLinksCreated++
		return w.record(dcim.ObjectKindWirelessLink, id, changes.ActionCreate, nil,
			map[string]any{"interface_a_id": a.String(), "interface_b_id": b.String(), "operational_status": k.Status, "source_kind": "measured", "status": "pending"})
	case err != nil:
		return fmt.Errorf("identity/postgres: read wireless link: %w", err)
	}
	if _, err := w.tx.ExecContext(w.ctx, `
		UPDATE public.wireless_links SET observation_count = observation_count + 1,
		       first_seen_at = COALESCE(first_seen_at, $3), last_seen_at = GREATEST(COALESCE(last_seen_at, $3), $3), updated_at = now()
		 WHERE tenant_id = $1 AND id = $2`, w.tenant, existing, w.at); err != nil {
		return fmt.Errorf("identity/postgres: refresh wireless link: %w", err)
	}
	w.res.WirelessLinksUpdated++
	return nil
}

// wirelessStation makes the observed asset's interface holding st.MAC a
// station on the LAN it joined: the LAN this observation reported under that
// SSID, else the tenant's one LAN with it. Nothing is created; a station whose
// interface or LAN cannot be named without a guess is reported as skipped.
func (w *networkWriter) wirelessStation(st identity.ObservedWirelessStation, lans map[string]uuid.UUID) error {
	mac, ok := macAddr8(st.MAC)
	if !ok {
		w.skip("wireless station %s: not a MAC", st.MAC)
		return nil
	}
	ifaces, err := w.uuids(`
		SELECT ifc.id FROM public.interfaces ifc
		 WHERE ifc.tenant_id = $1 AND ifc.asset_id = $2 AND ifc.status <> 'rejected'
		   AND (ifc.mac_address = $3::macaddr8
		        OR EXISTS (SELECT 1 FROM public.mac_addresses m
		                    WHERE m.tenant_id = ifc.tenant_id AND m.interface_id = ifc.id AND m.mac = $3::macaddr8))
		 LIMIT 2`, w.tenant, w.asset, mac)
	if err != nil {
		return fmt.Errorf("identity/postgres: read station interface %s: %w", st.MAC, err)
	}
	if len(ifaces) != 1 {
		w.skip("wireless station %s: the asset holds %d interfaces with that MAC (one is needed)", st.MAC, len(ifaces))
		return nil
	}
	lan, ok := lans[st.SSID]
	if !ok {
		found, err := w.uuids(`SELECT id FROM public.wireless_lans WHERE tenant_id = $1 AND ssid = $2 AND status <> 'rejected' LIMIT 2`, w.tenant, st.SSID)
		if err != nil {
			return fmt.Errorf("identity/postgres: read wireless LAN %q: %w", st.SSID, err)
		}
		if len(found) != 1 {
			w.skip("wireless station %s: the tenant holds %d wireless LANs with SSID %q (one is needed)", st.MAC, len(found), st.SSID)
			return nil
		}
		lan = found[0]
	}
	var (
		cur  []string
		role sql.NullString
		typ  string
	)
	if err := w.tx.QueryRowContext(w.ctx, `
		SELECT ARRAY(SELECT x::text FROM unnest(wireless_lan_ids) x), rf_role, type FROM public.interfaces
		 WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, w.tenant, ifaces[0]).Scan(pq.Array(&cur), &role, &typ); err != nil {
		return fmt.Errorf("identity/postgres: read station interface %s: %w", st.MAC, err)
	}
	next := slices.Clone(cur)
	if !slices.Contains(next, lan.String()) {
		next = append(next, lan.String())
	}
	newRole := role
	if !role.Valid {
		newRole = sql.NullString{String: "station", Valid: true}
	}
	newType := typ
	if typ == identity.SyntheticInterfaceType && st.Type != "" {
		newType = st.Type
	}
	if len(next) == len(cur) && newRole == role && newType == typ {
		return nil
	}
	if _, err := w.tx.ExecContext(w.ctx, `
		UPDATE public.interfaces SET wireless_lan_ids = $3::uuid[], rf_role = $4, type = $5, updated_at = now()
		 WHERE tenant_id = $1 AND id = $2`, w.tenant, ifaces[0], pq.Array(next), newRole, newType); err != nil {
		return fmt.Errorf("identity/postgres: join station %s to %q: %w", st.MAC, st.SSID, err)
	}
	pre, post := map[string]any{}, map[string]any{}
	if len(next) != len(cur) {
		pre["wireless_lan_ids"], post["wireless_lan_ids"] = cur, next
	}
	if newRole != role {
		pre["rf_role"], post["rf_role"] = nullableStr(role), nullableStr(newRole)
	}
	if newType != typ {
		pre["type"], post["type"] = typ, newType
	}
	return w.record(dcim.ObjectKindInterface, ifaces[0], changes.ActionUpdate, pre, post)
}

// uuids runs a query of one uuid column on the writer's transaction.
func (w *networkWriter) uuids(query string, args ...any) ([]uuid.UUID, error) {
	rows, err := w.tx.QueryContext(w.ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return scanUUIDs(rows)
}
