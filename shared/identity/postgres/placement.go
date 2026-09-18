package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// ProjectSegmentLocation fills missing physical placement from the segment the
// caller resolved. It never selects a competing segment or replaces a person's
// populated location. Call only for a settled identity, inside its unit of work.
func (r *Repository) ProjectSegmentLocation(ctx context.Context, asset identity.AssetRef, segment string, source identity.Source) error {
	// Tenant/default scopes have no location.
	if _, err := uuid.Parse(segment); err != nil {
		return nil
	}
	return r.RunInTx(ctx, asset.TenantID, func(bound *Repository) error {
		var currentLocation, currentSite, location, site string
		err := bound.Tx().QueryRowContext(ctx, `
   SELECT coalesce(a.location_id::text,''),coalesce(a.site,''),l.id::text,l.name
   FROM public.assets a
   JOIN public.network_segments ns ON ns.id=$3::uuid AND ns.tenant_id=a.tenant_id AND ns.is_active
   JOIN public.locations l ON l.id=ns.location_id AND l.tenant_id=a.tenant_id
   WHERE a.id=$2::uuid AND a.tenant_id=$1::uuid AND a.deleted_at IS NULL
     AND (a.network_segment_id IS NULL OR a.network_segment_id=ns.id)
   FOR UPDATE OF a`, asset.TenantID, asset.ID, segment).Scan(&currentLocation, &currentSite, &location, &site)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read segment placement: %w", err)
		}
		if currentLocation != "" && currentLocation != location {
			return nil
		}
		if strings.TrimSpace(currentSite) != "" && currentSite != site {
			return nil
		}
		changes := map[string]any{}
		if currentLocation == "" {
			changes["location_id"] = map[string]string{"from": "", "to": location}
		}
		if strings.TrimSpace(currentSite) == "" && site != "" {
			changes["site"] = map[string]string{"from": currentSite, "to": site}
		}
		if len(changes) == 0 {
			return nil
		}
		_, err = bound.Tx().ExecContext(ctx, `UPDATE public.assets SET location_id=$3::uuid,site=$4,updated_at=now() WHERE tenant_id=$1::uuid AND id=$2::uuid`, asset.TenantID, asset.ID, location, site)
		if err != nil {
			return fmt.Errorf("project segment placement: %w", err)
		}
		changes["network_segment_id"] = segment
		return bound.RecordHistory(ctx, identity.HistoryEntry{TenantID: asset.TenantID, AssetID: asset.ID, Action: identity.ActionUpdated, Source: source, Changes: changes})
	})
}
