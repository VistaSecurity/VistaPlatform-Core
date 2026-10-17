package services

// A network's gateway, read ( slice B, spec §3.6; DCIM row 1.6).
//
// The link itself — prefixes.gateway_asset_id, gateway_ip_id and friends — is
// written by one function only, shared/identity/postgres ReconcileGatewayLinks,
// behind the internal gateway-links route an interrogation calls after its
// claimed addresses settled (sighting_handlers.go). Everything here READS it:
//
//   - the prefix detail (Inventory → Networks → a prefix) carries `gateway`
//     (who routes it), `coverage` (which tenant collector can reach it) and
//     `fhrp_groups` (the shared gateway of an HA pair);
//   - the single-asset read carries `routed_prefixes` (the "Networks routed"
//     card) and `prefix_gateway` ("via <gateway>", derived from the host's own
//     prefix, never stored per host — owner decision D1);
//   - the network map's prefixes carry `gateway`.
//
// A gateway is a LIVE asset: the link to a soft-deleted asset reads as no
// gateway (a hard delete nulls the column through its foreign key).

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/reflectx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/identityenrichment"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// ReconcileGatewayLinks is the gateway-links route's service: one
// interrogation's complete list of the device's own addresses on the networks
// it serves (pgidentity ReconcileGatewayLinks has the rules).
func (s *AssetService) ReconcileGatewayLinks(ctx context.Context, tenantID, assetID uuid.UUID, sourceRef string, observedAt time.Time, addresses []string) (pgidentity.GatewayLinkResult, error) {
	return s.identityRepo.ReconcileGatewayLinks(ctx, tenantID.String(), assetID.String(), sourceRef, observedAt, addresses)
}

// gatewayQuerier is the one method the readers need: *sql.Tx and *sqlx.Tx.
type gatewayQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// gatewayDisplayNameSQL names the gateway asset `a` the way the network map
// names a device.
const gatewayDisplayNameSQL = `COALESCE(NULLIF(a.display_name, ''), NULLIF(a.hostname, ''), host(a.primary_address), '')`

// readPrefixGateways returns the live gateway of each of the prefixes that
// has one. The gateway's address is the `ip_addresses` row the link names.
func readPrefixGateways(ctx context.Context, q gatewayQuerier, tenantID uuid.UUID, prefixIDs []uuid.UUID) (map[uuid.UUID]*models.PrefixGateway, error) {
	out := map[uuid.UUID]*models.PrefixGateway{}
	if len(prefixIDs) == 0 {
		return out, nil
	}
	rows, err := q.QueryContext(ctx, `
		SELECT p.id, a.id, `+gatewayDisplayNameSQL+`, host(ip.address), p.gateway_observed_at
		  FROM prefixes p
		  JOIN assets a ON a.tenant_id = p.tenant_id AND a.id = p.gateway_asset_id AND a.deleted_at IS NULL
		  JOIN ip_addresses ip ON ip.tenant_id = p.tenant_id AND ip.id = p.gateway_ip_id
		 WHERE p.tenant_id = $1 AND p.id = ANY($2) AND p.gateway_observed_at IS NOT NULL`,
		tenantID, pq.Array(prefixIDs))
	if err != nil {
		return nil, fmt.Errorf("prefix gateways: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var prefix uuid.UUID
		g := &models.PrefixGateway{}
		if err := rows.Scan(&prefix, &g.AssetID, &g.DisplayName, &g.Address, &g.ObservedAt); err != nil {
			return nil, err
		}
		g.ObservedAt = g.ObservedAt.UTC()
		out[prefix] = g
	}
	return out, rows.Err()
}

// readPrefixFHRPGroups returns, per prefix, the FHRP groups whose virtual
// address lies in it (same VRF), lowest group id first.
func readPrefixFHRPGroups(ctx context.Context, q gatewayQuerier, tenantID uuid.UUID, prefixIDs []uuid.UUID) (map[uuid.UUID][]models.FHRPGroupRef, error) {
	out := map[uuid.UUID][]models.FHRPGroupRef{}
	if len(prefixIDs) == 0 {
		return out, nil
	}
	rows, err := q.QueryContext(ctx, `
		SELECT p.id, g.id, g.protocol, g.group_id, COALESCE(g.name, ''), host(ip.address)
		  FROM prefixes p
		  JOIN ip_addresses ip ON ip.tenant_id = p.tenant_id AND ip.assigned_kind = 'fhrp_group'
		   AND ip.vrf_id IS NOT DISTINCT FROM p.vrf_id AND ip.status <> 'rejected'
		   AND family(ip.host) = family(p.prefix)
		   AND ip.host >= public.ipam_host(network(p.prefix)) AND ip.host <= public.ipam_host(broadcast(p.prefix))
		  JOIN fhrp_groups g ON g.tenant_id = ip.tenant_id AND g.id = ip.assigned_id
		 WHERE p.tenant_id = $1 AND p.id = ANY($2)
		 ORDER BY p.id, g.group_id, g.id, ip.address`,
		tenantID, pq.Array(prefixIDs))
	if err != nil {
		return nil, fmt.Errorf("prefix fhrp groups: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var prefix uuid.UUID
		var g models.FHRPGroupRef
		if err := rows.Scan(&prefix, &g.ID, &g.Protocol, &g.GroupID, &g.Name, &g.VirtualAddress); err != nil {
			return nil, err
		}
		out[prefix] = append(out[prefix], g)
	}
	return out, rows.Err()
}

// prefixRef is what coverage needs to know about a prefix.
type prefixRef struct {
	ID     uuid.UUID
	Prefix netip.Prefix
}

// prefixCoverage answers, per prefix, the first eligible tenant collector that
// reaches it (identityenrichment.EligibleCollectors — the one definition the
// executor selection uses).
func prefixCoverage(ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID, refs []prefixRef, now time.Time) (map[uuid.UUID]*models.PrefixCoverage, error) {
	out := map[uuid.UUID]*models.PrefixCoverage{}
	if len(refs) == 0 {
		return out, nil
	}
	collectors, err := identityenrichment.EligibleCollectors(ctx, tx, tenantID, now)
	if err != nil {
		return nil, fmt.Errorf("prefix coverage: %w", err)
	}
	for _, ref := range refs {
		for _, c := range collectors {
			if c.Reaches(ref.Prefix) {
				out[ref.ID] = &models.PrefixCoverage{SensorID: c.ID, SensorName: c.Name}
				break
			}
		}
	}
	return out, nil
}

// prefixCoverageTx is prefixCoverage for one prefix over a plain *sql.Tx (the
// IPAM service's transaction).
func prefixCoverageTx(ctx context.Context, tx *sql.Tx, tenantID, id uuid.UUID, p netip.Prefix) (*models.PrefixCoverage, error) {
	stx := &sqlx.Tx{Tx: tx, Mapper: reflectx.NewMapperFunc("db", sqlx.NameMapper)}
	collectors, err := identityenrichment.EligibleCollectors(ctx, stx, tenantID, time.Now())
	if err != nil {
		return nil, fmt.Errorf("prefix coverage: %w", err)
	}
	for _, c := range collectors {
		if c.Reaches(p.Masked()) {
			return &models.PrefixCoverage{SensorID: c.ID, SensorName: c.Name}, nil
		}
	}
	return nil, nil
}

// readRoutedPrefixes is the "Networks routed" card: every prefix assetID is
// the gateway of, by network. Empty (never nil) when it routes nothing.
func readRoutedPrefixes(ctx context.Context, tx *sqlx.Tx, tenantID, assetID uuid.UUID, now time.Time) ([]models.RoutedPrefix, error) {
	out := []models.RoutedPrefix{}
	type row struct {
		ID          uuid.UUID      `db:"id"`
		Prefix      string         `db:"prefix"`
		Description string         `db:"description"`
		Address     string         `db:"address"`
		ObservedAt  time.Time      `db:"observed_at"`
		DHCP        sql.NullBool   `db:"dhcp_managed"`
		VID         sql.NullInt64  `db:"vid"`
		VLANName    sql.NullString `db:"vlan_name"`
		HostCount   int            `db:"host_count"`
	}
	var rows []row
	// The gateway's liveness is checked here too: a deleted device routes
	// nothing.
	if err := tx.SelectContext(ctx, &rows, `
		SELECT p.id, p.prefix::text AS prefix, COALESCE(p.description, '') AS description,
		       host(ip.address) AS address, p.gateway_observed_at AS observed_at,
		       p.dhcp_managed, v.vid, v.name AS vlan_name,
		       (SELECT count(*) FROM assets h
		         WHERE h.tenant_id = p.tenant_id AND h.prefix_id = p.id
		           AND h.deleted_at IS NULL) AS host_count
		  FROM prefixes p
		  JOIN assets a ON a.tenant_id = p.tenant_id AND a.id = p.gateway_asset_id AND a.deleted_at IS NULL
		  JOIN ip_addresses ip ON ip.tenant_id = p.tenant_id AND ip.id = p.gateway_ip_id
		  LEFT JOIN vlans v ON v.tenant_id = p.tenant_id AND v.id = p.vlan_id
		 WHERE p.tenant_id = $1 AND p.gateway_asset_id = $2 AND p.gateway_observed_at IS NOT NULL
		 ORDER BY p.prefix, p.id`, tenantID, assetID); err != nil {
		return nil, fmt.Errorf("routed prefixes: %w", err)
	}
	if len(rows) == 0 {
		return out, nil
	}
	tags, err := readGatewayVLANTags(ctx, tx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	refs := make([]prefixRef, 0, len(rows))
	ids := make([]uuid.UUID, 0, len(rows))
	for _, r := range rows {
		if p, err := netip.ParsePrefix(r.Prefix); err == nil {
			refs = append(refs, prefixRef{ID: r.ID, Prefix: p.Masked()})
		}
		ids = append(ids, r.ID)
	}
	coverage, err := prefixCoverage(ctx, tx, tenantID, refs, now)
	if err != nil {
		return nil, err
	}
	groups, err := readPrefixFHRPGroups(ctx, tx, tenantID, ids)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		rp := models.RoutedPrefix{
			PrefixID: r.ID, Prefix: r.Prefix, Description: r.Description,
			Address: r.Address, ObservedAt: r.ObservedAt.UTC(),
			HostCount: r.HostCount, Coverage: coverage[r.ID],
		}
		if r.DHCP.Valid {
			v := r.DHCP.Bool
			rp.Dynamic = &v
		}
		if r.VID.Valid {
			vid := int(r.VID.Int64)
			rp.VLANID = &vid
			if r.VLANName.Valid {
				name := r.VLANName.String
				rp.VLANName = &name
			}
		} else if p, err := netip.ParsePrefix(r.Prefix); err == nil {
			if tag, ok := tags[p.Masked()]; ok {
				rp.VLANID = &tag
			}
		}
		if gs := groups[r.ID]; len(gs) > 0 {
			g := gs[0]
			rp.FHRPGroup = &g
		}
		out = append(out, rp)
	}
	return out, nil
}

// readGatewayVLANTags maps each network the gateway reported in its own
// net.vlans fact to the 802.1Q tag it reported for it. A network reported
// without a tag (untagged) or without a prefix has no entry.
func readGatewayVLANTags(ctx context.Context, tx *sqlx.Tx, tenantID, assetID uuid.UUID) (map[netip.Prefix]int, error) {
	out := map[netip.Prefix]int{}
	var values [][]byte
	if err := tx.SelectContext(ctx, &values, `
		SELECT value FROM asset_facts
		 WHERE tenant_id = $1 AND asset_id = $2 AND key = $3
		 ORDER BY updated_at DESC`, tenantID, assetID, facts.KeyNetVlans); err != nil {
		return nil, fmt.Errorf("routed prefixes: reading the gateway's networks: %w", err)
	}
	for _, raw := range values {
		var entries []map[string]any
		if err := json.Unmarshal(raw, &entries); err != nil {
			continue
		}
		for _, e := range entries {
			subnet, _ := e["subnet"].(string)
			p, err := netip.ParsePrefix(strings.TrimSpace(subnet))
			if err != nil {
				continue
			}
			p = p.Masked()
			if _, seen := out[p]; seen {
				continue // the most recent fact wins
			}
			if tag, ok := vlanTag(e["id"]); ok {
				out[p] = tag
			}
		}
	}
	return out, nil
}

// vlanTag reads an 802.1Q tag (1-4094) from a decoded JSON value.
func vlanTag(v any) (int, bool) {
	f, ok := v.(float64)
	if !ok || f != float64(int(f)) || f < 1 || f > 4094 {
		return 0, false
	}
	return int(f), true
}

// readOwnPrefixGateway is "via <gateway>": the gateway of the asset's own
// prefix, with the FHRP group on that network when one is recorded. Nil when
// the prefix has none, or when the asset IS its gateway.
func readOwnPrefixGateway(ctx context.Context, tx *sqlx.Tx, tenantID, assetID uuid.UUID, prefixID *uuid.UUID) (*models.PrefixGateway, *models.FHRPGroupRef, error) {
	if prefixID == nil || *prefixID == uuid.Nil {
		return nil, nil, nil
	}
	gateways, err := readPrefixGateways(ctx, tx, tenantID, []uuid.UUID{*prefixID})
	if err != nil {
		return nil, nil, err
	}
	g := gateways[*prefixID]
	if g == nil || g.AssetID == assetID {
		return nil, nil, nil
	}
	groups, err := readPrefixFHRPGroups(ctx, tx, tenantID, []uuid.UUID{*prefixID})
	if err != nil {
		return nil, nil, err
	}
	if gs := groups[*prefixID]; len(gs) > 0 {
		fg := gs[0]
		return g, &fg, nil
	}
	return g, nil, nil
}

// loadAssetGatewayContext fills RoutedPrefixes, PrefixGateway and
// PrefixFHRPGroup on a single-asset read. A failure leaves them absent and is
// returned for the caller to log; the rest of the asset is unaffected.
func (s *AssetService) loadAssetGatewayContext(ctx context.Context, tenantID uuid.UUID, asset *models.Asset) error {
	now := time.Now()
	var routed []models.RoutedPrefix
	var via *models.PrefixGateway
	var group *models.FHRPGroupRef
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		var err error
		if routed, err = readRoutedPrefixes(ctx, tx, tenantID, asset.ID, now); err != nil {
			return err
		}
		via, group, err = readOwnPrefixGateway(ctx, tx, tenantID, asset.ID, asset.PrefixID)
		return err
	})
	if err != nil {
		return err
	}
	asset.RoutedPrefixes = &routed
	asset.PrefixGateway = via
	asset.PrefixFHRPGroup = group
	return nil
}
