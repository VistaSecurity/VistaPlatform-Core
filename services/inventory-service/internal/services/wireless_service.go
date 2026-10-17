package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim/wireless"
)

// WirelessService is the wireless object store (BUILD_PLAN row 4.4): the IPAM
// engine over wirelessSpecs(), plus the measured upserts intake uses.
//
// It embeds the engine's *IPAMService so the same handler type serves its
// routes; only the three wireless routes are mounted (cmd/wireless_routes.go),
// so the IPAM-only methods it also carries are unreachable.
type WirelessService struct {
	*IPAMService
}

// NewWirelessService returns the store over db (the raw pool; RLS is set per
// transaction).
func NewWirelessService(db *sql.DB) *WirelessService {
	return &WirelessService{IPAMService: newObjectEngine(db, wirelessSpecs())}
}

// ObservedWirelessLAN is a wireless LAN an intake producer measured on an
// access point. Measured fields only: never a pre-shared key.
type ObservedWirelessLAN struct {
	SSID       string
	AuthType   string
	AuthCipher string
	Group      string // the group's name, "" for none
	PSKPresent bool
	SourceRef  string
}

// UpsertObservedWirelessLAN records a measured LAN. A new one arrives
// `pending`; an existing one (same SSID in the same group) has its
// measurements refreshed: authentication, cipher and psk presence when nobody
// declared the LAN (a declared LAN's are filled only where empty), and its
// sighting counters. A person's description, status and VLAN are never
// touched.
func (s *WirelessService) UpsertObservedWirelessLAN(ctx context.Context, tenant uuid.UUID, producer string, o ObservedWirelessLAN) (uuid.UUID, bool, error) {
	if strings.TrimSpace(o.SSID) == "" || len(o.SSID) > 32 {
		return uuid.Nil, false, ipamInvalid("ssid is required and at most 32 bytes")
	}
	if o.AuthType != "" && !wireless.ValidAuthType(o.AuthType) {
		return uuid.Nil, false, ipamInvalid("auth_type %q is not one of %s", o.AuthType, strings.Join(wireless.AuthTypes, ", "))
	}
	if o.AuthCipher != "" && !wireless.ValidAuthCipher(o.AuthCipher) {
		return uuid.Nil, false, ipamInvalid("auth_cipher %q is not one of %s", o.AuthCipher, strings.Join(wireless.AuthCiphers, ", "))
	}
	sp := s.specs["wireless-lans"]
	var (
		id      uuid.UUID
		created bool
	)
	err := s.tx(ctx, tenant, func(tx *sql.Tx) error {
		var group any
		if o.Group != "" {
			var gid uuid.UUID
			err := tx.QueryRowContext(ctx, `SELECT id FROM public.wireless_lan_groups WHERE tenant_id = $1 AND name = $2`, tenant, o.Group).Scan(&gid)
			if errors.Is(err, sql.ErrNoRows) {
				gid = uuid.New()
				_, err = tx.ExecContext(ctx, `INSERT INTO public.wireless_lan_groups (id, tenant_id, name, slug, source_kind, source_ref)
					VALUES ($1, $2, $3, $4, 'measured', NULLIF($5, ''))`, gid, tenant, o.Group, Slugify(o.Group), o.SourceRef)
			}
			if err != nil {
				return err
			}
			group = gid
		}
		var existing uuid.UUID
		err := tx.QueryRowContext(ctx, `SELECT id FROM public.wireless_lans
			WHERE tenant_id = $1 AND ssid = $2 AND COALESCE(group_id, '00000000-0000-0000-0000-000000000000'::uuid) = COALESCE($3::uuid, '00000000-0000-0000-0000-000000000000'::uuid)
			  AND status <> 'rejected' FOR UPDATE`, tenant, o.SSID, group).Scan(&existing)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil {
			id = existing
			if err := s.observedRefresh(ctx, tx, sp, tenant, existing, producer,
				`UPDATE public.wireless_lans AS t SET
				   last_seen_at = now(), observation_count = t.observation_count + 1,
				   auth_type = CASE WHEN t.source_kind = 'declared' THEN COALESCE(t.auth_type, $4::text) ELSE COALESCE($4::text, t.auth_type) END,
				   auth_cipher = CASE WHEN t.source_kind = 'declared' THEN COALESCE(t.auth_cipher, $5::text) ELSE COALESCE($5::text, t.auth_cipher) END,
				   auth_psk_present = CASE WHEN t.source_kind = 'declared' THEN t.auth_psk_present OR $6::boolean ELSE $6::boolean END,
				   source_ref = COALESCE(t.source_ref, $7::text), updated_at = now()
				 WHERE t.tenant_id = $1 AND t.id = $2 AND $3::int = 0 RETURNING to_jsonb(t)`,
				nilIfEmpty(o.AuthType), nilIfEmpty(o.AuthCipher), o.PSKPresent, nilIfEmpty(o.SourceRef)); err != nil {
				return err
			}
			// algorithm_id follows the (possibly refreshed) authentication.
			return repointAlgorithmTx(ctx, tx, tenant, "wireless_lans", existing)
		}
		row := map[string]any{
			"ssid": o.SSID, "source_kind": "measured", "status": "pending",
			"auth_type": nilIfEmpty(o.AuthType), "auth_cipher": nilIfEmpty(o.AuthCipher),
			"auth_psk_present": o.PSKPresent, "source_ref": nilIfEmpty(o.SourceRef),
		}
		if group != nil {
			row["group_id"] = fmt.Sprint(group)
		}
		post, err := s.createTx(ctx, tx, sp, tenant, row, intakeSource(producer))
		if err != nil {
			return err
		}
		created = true
		id, err = uuid.Parse(fmt.Sprint(post["id"]))
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE public.wireless_lans SET first_seen_at = now(), last_seen_at = now(), observation_count = 1 WHERE id = $1`, id)
		return err
	})
	if err != nil {
		return uuid.Nil, false, mapIPAMError(err, false)
	}
	return id, created, nil
}

// repointAlgorithmTx sets algorithm_id on a LAN or link from its current
// authentication, through the same rule an API write uses.
func repointAlgorithmTx(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, table string, id uuid.UUID) error {
	var authType, cipher sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT auth_type, auth_cipher FROM public.`+table+` WHERE tenant_id = $1 AND id = $2`, tenant, id).Scan(&authType, &cipher); err != nil {
		return err
	}
	row := map[string]any{}
	if authType.Valid {
		row["auth_type"] = authType.String
	}
	if cipher.Valid {
		row["auth_cipher"] = cipher.String
	}
	if err := prepareWirelessAuth(ctx, tx, row); err != nil {
		// A stored combination the rules refuse (a measured open LAN that also
		// reported a cipher) is left unassessed, not failed.
		row["algorithm_id"] = nil
	}
	_, err := tx.ExecContext(ctx, `UPDATE public.`+table+` SET algorithm_id = $3::uuid WHERE tenant_id = $1 AND id = $2 AND algorithm_id IS DISTINCT FROM $3::uuid`,
		tenant, id, row["algorithm_id"])
	return err
}

// WirelessObjects describes the wireless objects for the contract tests.
func WirelessObjects() []IPAMObjectInfo {
	var out []IPAMObjectInfo
	for _, sp := range wirelessSpecs() {
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
