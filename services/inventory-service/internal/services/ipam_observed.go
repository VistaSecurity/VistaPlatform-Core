package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/dcim/ipam"
)

// ---------------------------------------------------------------------------
// Observed writes for intake (row 1.5)
// ---------------------------------------------------------------------------

// ObservedPrefix is a prefix an intake producer measured (a cloud subnet, a
// UniFi network, a router's connected route).
type ObservedPrefix struct {
	VRFID           *uuid.UUID
	Prefix          netip.Prefix
	SourceRef       string
	NetworkType     string
	CloudNetworkRef string
}

// ObservedIP is an address an intake producer measured.
type ObservedIP struct {
	VRFID          *uuid.UUID
	Address        netip.Prefix // address with its length; a bare address is /32 or /128
	MACAddress     string
	DNSName        string
	LastSeenSource string // arp, dhcp, passive, probe, agent, cloud
	SourceRef      string
}

// The measured columns an observation may refresh on an existing row. Declared
// columns — operational_status, role, dns_name (once set), description — are
// never in these lists: a person's statement outranks a measurement.
const (
	observedPrefixRefresh = `last_seen_at = now(), observation_count = t.observation_count + 1,
		network_type = COALESCE(t.network_type, $4), cloud_network_ref = COALESCE(t.cloud_network_ref, $5),
		source_ref = COALESCE(t.source_ref, $6), updated_at = now()`
	observedIPRefresh = `last_seen_at = now(), observation_count = t.observation_count + 1,
		mac_address = COALESCE($4::macaddr8, t.mac_address), last_seen_source = COALESCE($5, t.last_seen_source),
		dns_name = COALESCE(t.dns_name, $6), source_ref = COALESCE(t.source_ref, $7), updated_at = now()`
)

// UpsertObservedPrefix records a measured prefix: a new one arrives `pending`
// (approval through the asset lifecycle; shared/approval cannot yet scope a
// rule to a prefix — row 1.4), an existing one has only its measured columns
// refreshed. producer names the intake (`cloud`, `unifi`, …) for the change
// record.
func (s *IPAMService) UpsertObservedPrefix(ctx context.Context, tenant uuid.UUID, producer string, o ObservedPrefix) (uuid.UUID, bool, error) {
	if !o.Prefix.IsValid() {
		return uuid.Nil, false, ipamInvalid("prefix is required")
	}
	cidr := ipam.Normalize(o.Prefix).String()
	sp := s.specs["prefixes"]
	var id uuid.UUID
	created := false
	err := s.tx(ctx, tenant, func(tx *sql.Tx) error {
		var existing uuid.UUID
		err := tx.QueryRowContext(ctx, `SELECT t.id FROM public.prefixes t WHERE t.tenant_id = $1 AND `+vrfClause("t", 2)+
			` AND t.prefix = $3::cidr AND t.status <> 'rejected' FOR UPDATE`, tenant, vrfArg(o.VRFID), cidr).Scan(&existing)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil {
			id = existing
			return s.observedRefresh(ctx, tx, sp, tenant, existing, producer,
				`UPDATE public.prefixes AS t SET `+observedPrefixRefresh+` WHERE t.tenant_id = $1 AND t.id = $2 AND $3::int = 0 RETURNING to_jsonb(t)`,
				nilIfEmpty(o.NetworkType), nilIfEmpty(o.CloudNetworkRef), nilIfEmpty(o.SourceRef))
		}
		row := map[string]any{
			"prefix": cidr, "source_kind": "measured", "status": "pending",
			"source_ref": nilIfEmpty(o.SourceRef), "network_type": nilIfEmpty(o.NetworkType),
			"cloud_network_ref": nilIfEmpty(o.CloudNetworkRef),
		}
		if o.VRFID != nil {
			row["vrf_id"] = o.VRFID.String()
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
		_, err = tx.ExecContext(ctx, `UPDATE public.prefixes SET first_seen_at = now(), last_seen_at = now(), observation_count = 1 WHERE id = $1`, id)
		return err
	})
	return id, created, mapIPAMError(err, false)
}

// UpsertObservedIP records a measured address. A new one arrives `pending`; an
// existing one (same VRF, same host) gets its MAC, source and sighting
// refreshed, and a DNS name only when none is recorded — never over a declared
// one.
func (s *IPAMService) UpsertObservedIP(ctx context.Context, tenant uuid.UUID, producer string, o ObservedIP) (uuid.UUID, bool, error) {
	if !o.Address.IsValid() {
		return uuid.Nil, false, ipamInvalid("address is required")
	}
	addr := netip.PrefixFrom(ipam.StripZone(o.Address.Addr()), o.Address.Bits())
	sp := s.specs["ip-addresses"]
	var id uuid.UUID
	created := false
	err := s.tx(ctx, tenant, func(tx *sql.Tx) error {
		var existing uuid.UUID
		err := tx.QueryRowContext(ctx, `SELECT t.id FROM public.ip_addresses t WHERE t.tenant_id = $1 AND `+vrfClause("t", 2)+
			` AND t.host = public.ipam_host($3::inet) AND t.status <> 'rejected'
			 ORDER BY t.created_at LIMIT 1 FOR UPDATE`, tenant, vrfArg(o.VRFID), addr.String()).Scan(&existing)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil {
			id = existing
			return s.observedRefresh(ctx, tx, sp, tenant, existing, producer,
				`UPDATE public.ip_addresses AS t SET `+observedIPRefresh+` WHERE t.tenant_id = $1 AND t.id = $2 AND $3::int = 0 RETURNING to_jsonb(t)`,
				nilIfEmpty(o.MACAddress), nilIfEmpty(o.LastSeenSource), nilIfEmpty(strings.TrimSuffix(o.DNSName, ".")), nilIfEmpty(o.SourceRef))
		}
		row := map[string]any{
			"address": addr.String(), "source_kind": "measured", "status": "pending",
			"source_ref": nilIfEmpty(o.SourceRef), "dns_name": nilIfEmpty(strings.TrimSuffix(o.DNSName, ".")),
			"mac_address": nilIfEmpty(o.MACAddress), "last_seen_source": nilIfEmpty(o.LastSeenSource),
		}
		if o.VRFID != nil {
			row["vrf_id"] = o.VRFID.String()
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
		_, err = tx.ExecContext(ctx, `UPDATE public.ip_addresses SET first_seen_at = now(), last_seen_at = now(), observation_count = 1 WHERE id = $1`, id)
		return err
	})
	return id, created, mapIPAMError(err, false)
}

func (s *IPAMService) observedRefresh(ctx context.Context, tx *sql.Tx, sp *ipamSpec, tenant, id uuid.UUID, producer, q string, args ...any) error {
	pre, err := getRow(ctx, tx, sp, id, true)
	if err != nil {
		return err
	}
	var raw []byte
	all := append([]any{tenant, id, 0}, args...)
	if err := tx.QueryRowContext(ctx, q, all...).Scan(&raw); err != nil {
		return err
	}
	post, err := decodeRow(sp, raw)
	if err != nil {
		return err
	}
	if err := recordIPAMChange(ctx, tx, sp, tenant, "update", pre, post, intakeSource(producer)); err != nil {
		return err
	}
	if sp.AfterWrite != nil {
		return sp.AfterWrite(ctx, tx, tenant, pre, post)
	}
	return nil
}

func intakeSource(producer string) changes.Source { return changes.IntakeSource(producer) }

func nilIfEmpty(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

// ipamVRFParam parses ?vrf= / ?vrf_id=: "" or "global" is the global table.
func ipamVRFParam(v string) (*uuid.UUID, error) {
	v = strings.TrimSpace(v)
	if v == "" || v == "global" || v == "null" {
		return nil, nil
	}
	id, err := uuid.Parse(v)
	if err != nil {
		return nil, ipamInvalid("vrf must be a UUID or \"global\"")
	}
	return &id, nil
}

// IPAMVRFParam is ipamVRFParam for the handlers.
func IPAMVRFParam(v string) (*uuid.UUID, error) { return ipamVRFParam(v) }
