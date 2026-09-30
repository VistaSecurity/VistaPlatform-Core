package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// The DHCP posture of a network segment ( Phase 1a).
//
// The rule — who may state it and which statement wins — lives in ONE place,
// shared/identity/postgres/segment_posture.go, because device-interrogation
// writes the same keys and two implementations of a precedence rule disagree
// the first time one is edited. This file is inventory-service's half: the
// operator's write, and reading it back for the Network Segments page.

// ErrDHCPNotApplicable refuses a DHCP answer for a segment address-scoped
// identity never consults. Identity places an address by CIDR or range;
// a domain or cloud-VPC segment cannot hold a lease, so a toggle there would
// be a setting that silently does nothing.
var ErrDHCPNotApplicable = errors.New("dhcp posture applies to cidr and ip_range segments")

func validatePostureApplies(segmentType string, dhcp models.OptionalBool) error {
	if !dhcp.Set || dhcp.Value == nil {
		return nil
	}
	if segmentType != "cidr" && segmentType != "ip_range" {
		return fmt.Errorf("%w: %q is neither", ErrDHCPNotApplicable, segmentType)
	}
	return nil
}

// postureMetadataKeys are the keys the posture helper owns.
var postureMetadataKeys = []string{"dynamic", "dynamic_source", "dynamic_evidence", "dynamic_by_source"}

// withPostureKeys returns base with the posture keys taken from current
// instead of whatever base says about them.
func withPostureKeys(base, current map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(base)+len(postureMetadataKeys))
	for k, v := range base {
		out[k] = v
	}
	for _, k := range postureMetadataKeys {
		delete(out, k)
		if v, ok := current[k]; ok {
			out[k] = v
		}
	}
	return out
}

// applyOperatorPosture writes the operator's answer on the segment: true or
// false sets it (outranking every measurement), null withdraws it, and an
// absent field leaves the segment alone.
//
// Withdrawing falls back to the best remaining statement — the device that
// measured it, or the traffic that implied it — rather than blanking the value,
// because a blank reads as "static" to identity, the unsafe direction on a
// network that hands out leases.
func applyOperatorPosture(ctx context.Context, tx *sqlx.Tx, tenantID, segmentID uuid.UUID, dhcp models.OptionalBool) error {
	if !dhcp.Set {
		return nil
	}
	if dhcp.Value == nil {
		_, err := pgidentity.ClearSegmentPosture(ctx, tx, tenantID.String(), segmentID.String(), pgidentity.PostureOperator)
		return err
	}
	_, err := pgidentity.RecordSegmentPosture(ctx, tx, tenantID.String(), segmentID.String(),
		pgidentity.PostureOperator, *dhcp.Value, pgidentity.PostureEvidence{})
	return err
}

// hydratePostureNames fills DynamicSourceName: the device a measured posture
// came from, so the row can say "measured by <device>" instead of "measured".
// The name is cosmetic — an asset that has since been deleted or renamed away
// simply leaves it empty, and the row falls back to the plain provenance.
func hydratePostureNames(tx *sqlx.Tx, tenantID uuid.UUID, segs []models.NetworkSegment) error {
	ids := make([]string, 0, len(segs))
	seen := map[string]bool{}
	for i := range segs {
		raw := segs[i].PostureEvidenceAssetID()
		if raw == "" {
			continue
		}
		// Parsed here rather than cast in SQL: the value is metadata, and one
		// malformed row must not fail the whole list.
		id, err := uuid.Parse(raw)
		if err != nil || seen[id.String()] {
			continue
		}
		seen[id.String()] = true
		ids = append(ids, id.String())
	}
	if len(ids) == 0 {
		return nil
	}
	rows, err := tx.Query(`SELECT id::text, coalesce(nullif(display_name, ''), nullif(hostname, ''), '')
		FROM public.assets WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND deleted_at IS NULL`,
		tenantID, pq.Array(ids))
	if err != nil {
		return fmt.Errorf("resolve device names for segment posture: %w", err)
	}
	defer func() { _ = rows.Close() }()
	names := map[string]string{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return err
		}
		names[id] = name
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range segs {
		id, err := uuid.Parse(segs[i].PostureEvidenceAssetID())
		if err != nil {
			continue
		}
		if name := names[id.String()]; name != "" {
			n := name
			segs[i].DynamicSourceName = &n
		}
	}
	return nil
}
