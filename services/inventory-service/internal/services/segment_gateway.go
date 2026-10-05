package services

// A network's gateway, read ( slice B, spec §3.6).
//
// The link itself — network_segments.gateway_asset_id and friends — is written
// by one function only, shared/identity/postgres ReconcileGatewayLinks, behind
// the internal gateway-links route an interrogation calls after its claimed
// addresses settled (sighting_handlers.go). Everything here READS it:
//
//   - every network-segment read carries `gateway` (who routes it) and
//     `coverage` (which tenant collector can reach it);
//   - the single-asset read carries `routed_segments` (the "Networks routed"
//     card) and `segment_gateway` ("via <gateway>", derived from the host's
//     own segment, never stored per host — owner decision D1);
//   - the network map's segments carry `gateway`.
//
// A gateway is a LIVE asset: the link to a soft-deleted asset reads as no
// gateway (a hard delete nulls the column through its foreign key).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
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

// gatewayDisplayNameSQL names the gateway asset `a` the way the network map
// names a device.
const gatewayDisplayNameSQL = `COALESCE(NULLIF(a.display_name, ''), NULLIF(a.hostname, ''), host(a.primary_address), '')`

// readSegmentGateways returns the live gateway of each of the segments that
// has one.
func readSegmentGateways(ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID, segmentIDs []uuid.UUID) (map[uuid.UUID]*models.SegmentGateway, error) {
	out := map[uuid.UUID]*models.SegmentGateway{}
	if len(segmentIDs) == 0 {
		return out, nil
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT ns.id, a.id, `+gatewayDisplayNameSQL+`, host(ns.gateway_address), ns.gateway_observed_at
		  FROM network_segments ns
		  JOIN assets a ON a.tenant_id = ns.tenant_id AND a.id = ns.gateway_asset_id AND a.deleted_at IS NULL
		 WHERE ns.tenant_id = $1 AND ns.id = ANY($2)
		   AND ns.gateway_address IS NOT NULL AND ns.gateway_observed_at IS NOT NULL`,
		tenantID, pq.Array(segmentIDs))
	if err != nil {
		return nil, fmt.Errorf("segment gateways: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var segment uuid.UUID
		g := &models.SegmentGateway{}
		if err := rows.Scan(&segment, &g.AssetID, &g.DisplayName, &g.Address, &g.ObservedAt); err != nil {
			return nil, err
		}
		g.ObservedAt = g.ObservedAt.UTC()
		out[segment] = g
	}
	return out, rows.Err()
}

// segmentCoverage answers, per cidr segment, the first eligible tenant
// collector that reaches it (identityenrichment.EligibleCollectors — the one
// definition the executor selection uses). A segment that is not a cidr, or
// whose value does not parse, has no entry: coverage does not apply to it.
func segmentCoverage(ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID, segs []segmentRef, now time.Time) (map[uuid.UUID]*models.SegmentCoverage, error) {
	out := map[uuid.UUID]*models.SegmentCoverage{}
	if len(segs) == 0 {
		return out, nil
	}
	collectors, err := identityenrichment.EligibleCollectors(ctx, tx, tenantID, now)
	if err != nil {
		return nil, fmt.Errorf("segment coverage: %w", err)
	}
	for _, seg := range segs {
		prefix, ok := segmentCIDR(seg.Type, seg.Value)
		if !ok {
			continue
		}
		for _, c := range collectors {
			if c.Reaches(prefix) {
				out[seg.ID] = &models.SegmentCoverage{SensorID: c.ID, SensorName: c.Name}
				break
			}
		}
	}
	return out, nil
}

// segmentRef is what coverage needs to know about a segment.
type segmentRef struct {
	ID    uuid.UUID
	Type  string
	Value string
}

// segmentCIDR parses a cidr segment's value.
func segmentCIDR(segmentType, value string) (netip.Prefix, bool) {
	if segmentType != "cidr" {
		return netip.Prefix{}, false
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

// hydrateSegmentGateways fills Gateway and Coverage on segments read in tx.
func hydrateSegmentGateways(ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID, segs []models.NetworkSegment, now time.Time) error {
	if len(segs) == 0 {
		return nil
	}
	ids := make([]uuid.UUID, 0, len(segs))
	refs := make([]segmentRef, 0, len(segs))
	for i := range segs {
		segs[i].Gateway, segs[i].Coverage = nil, nil
		ids = append(ids, segs[i].ID)
		refs = append(refs, segmentRef{ID: segs[i].ID, Type: segs[i].SegmentType, Value: segs[i].Value})
	}
	gateways, err := readSegmentGateways(ctx, tx, tenantID, ids)
	if err != nil {
		return err
	}
	coverage, err := segmentCoverage(ctx, tx, tenantID, refs, now)
	if err != nil {
		return err
	}
	for i := range segs {
		segs[i].Gateway = gateways[segs[i].ID]
		segs[i].Coverage = coverage[segs[i].ID]
	}
	return nil
}

// readRoutedSegments is the "Networks routed" card: every segment assetID is
// the gateway of, by name. Empty (never nil) when it routes nothing.
func readRoutedSegments(ctx context.Context, tx *sqlx.Tx, tenantID, assetID uuid.UUID, now time.Time) ([]models.RoutedSegment, error) {
	out := []models.RoutedSegment{}
	type row struct {
		ID          uuid.UUID `db:"id"`
		Name        string    `db:"name"`
		Value       string    `db:"value"`
		SegmentType string    `db:"segment_type"`
		Address     string    `db:"address"`
		ObservedAt  time.Time `db:"observed_at"`
		Metadata    []byte    `db:"metadata"`
		HostCount   int       `db:"host_count"`
	}
	var rows []row
	// The gateway's liveness is checked here too: a deleted device routes
	// nothing.
	if err := tx.SelectContext(ctx, &rows, `
		SELECT ns.id, ns.name, ns.value, ns.segment_type,
		       host(ns.gateway_address) AS address, ns.gateway_observed_at AS observed_at,
		       coalesce(ns.metadata, '{}'::jsonb) AS metadata,
		       (SELECT count(*) FROM assets h
		         WHERE h.tenant_id = ns.tenant_id AND h.network_segment_id = ns.id
		           AND h.deleted_at IS NULL) AS host_count
		  FROM network_segments ns
		  JOIN assets a ON a.tenant_id = ns.tenant_id AND a.id = ns.gateway_asset_id AND a.deleted_at IS NULL
		 WHERE ns.tenant_id = $1 AND ns.gateway_asset_id = $2
		   AND ns.gateway_address IS NOT NULL AND ns.gateway_observed_at IS NOT NULL
		 ORDER BY ns.name ASC, ns.id ASC`, tenantID, assetID); err != nil {
		return nil, fmt.Errorf("routed segments: %w", err)
	}
	if len(rows) == 0 {
		return out, nil
	}
	tags, err := readGatewayVLANTags(ctx, tx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	refs := make([]segmentRef, len(rows))
	for i, r := range rows {
		refs[i] = segmentRef{ID: r.ID, Type: r.SegmentType, Value: r.Value}
	}
	coverage, err := segmentCoverage(ctx, tx, tenantID, refs, now)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		var meta map[string]interface{}
		_ = json.Unmarshal(r.Metadata, &meta)
		dynamic, _ := pgidentity.PostureFromMetadata(meta)
		rs := models.RoutedSegment{
			SegmentID: r.ID, Name: r.Name, Value: r.Value, SegmentType: r.SegmentType,
			Address: r.Address, ObservedAt: r.ObservedAt.UTC(),
			Dynamic: dynamic, HostCount: r.HostCount, Coverage: coverage[r.ID],
		}
		if p, ok := segmentCIDR(r.SegmentType, r.Value); ok {
			if tag, ok := tags[p]; ok {
				rs.VLANID = &tag
			}
		}
		out = append(out, rs)
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
		return nil, fmt.Errorf("routed segments: reading the gateway's networks: %w", err)
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

// readOwnSegmentGateway is "via <gateway>": the gateway of the asset's own
// segment. Nil when the segment has none, or when the asset IS its gateway.
func readOwnSegmentGateway(ctx context.Context, tx *sqlx.Tx, tenantID, assetID uuid.UUID, segmentID *uuid.UUID) (*models.SegmentGateway, error) {
	if segmentID == nil || *segmentID == uuid.Nil {
		return nil, nil
	}
	gateways, err := readSegmentGateways(ctx, tx, tenantID, []uuid.UUID{*segmentID})
	if err != nil {
		return nil, err
	}
	g := gateways[*segmentID]
	if g == nil || g.AssetID == assetID {
		return nil, nil
	}
	return g, nil
}

// loadAssetGatewayContext fills RoutedSegments and SegmentGateway on a
// single-asset read. A failure leaves both absent and is returned for the
// caller to log; the rest of the asset is unaffected.
func (s *AssetService) loadAssetGatewayContext(ctx context.Context, tenantID uuid.UUID, asset *models.Asset) error {
	now := time.Now()
	var routed []models.RoutedSegment
	var via *models.SegmentGateway
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		var err error
		if routed, err = readRoutedSegments(ctx, tx, tenantID, asset.ID, now); err != nil {
			return err
		}
		via, err = readOwnSegmentGateway(ctx, tx, tenantID, asset.ID, asset.NetworkSegmentID)
		return err
	})
	if err != nil {
		return err
	}
	asset.RoutedSegments = &routed
	asset.SegmentGateway = via
	return nil
}
