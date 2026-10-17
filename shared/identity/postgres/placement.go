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

// ProjectSegmentLocation fills missing placement (location, site and
// environment) from the prefix the caller resolved (the observation's scope).
// It never selects a competing prefix or replaces a person's populated
// location. Call only for a settled identity, inside its unit of work.
func (r *Repository) ProjectSegmentLocation(ctx context.Context, asset identity.AssetRef, prefix string, source identity.Source) error {
	// Tenant/default scopes have no location.
	if _, err := uuid.Parse(prefix); err != nil {
		return nil
	}
	return r.projectSegmentLocation(ctx, asset, prefix, source)
}

// InheritSegmentLocation fills missing placement from the prefix the asset is
// ALREADY scoped within (assets.prefix_id), whoever set it: the prefix's
// location (scope_kind = 'location'), that location's site, and its environment.
//
// It is the hearsay-safe half of [Repository.ProjectSegmentLocation]: it never
// takes a prefix from the observation, so a peer a controller described
// cannot move an asset into a prefix or a location. It only keeps an asset's
// placement consistent with its own prefix. An asset in a located prefix that
// names no site is drawn twice on the network map — once under the prefix's
// site, once under "Unassigned" — which is what this closes.
//
// Environment follows the same rule, for the same reason: a prefix is where
// the tenant states what an address range is for, and an asset in a
// production prefix with no environment of its own fell outside every
// environment filter — the default "Production" CBOM scope first of all.
//
// The same never-overwrite rules apply: a location_id or site that disagrees
// with the prefix's location (an operator's, a CMDB's) is left alone, as is any
// environment already recorded; a rejected or archived prefix, or none at all,
// writes nothing. Call only for a settled identity (not a conflict), inside its
// unit of work.
func (r *Repository) InheritSegmentLocation(ctx context.Context, asset identity.AssetRef, source identity.Source) error {
	return r.projectSegmentLocation(ctx, asset, "", source)
}

// projectSegmentLocation is the one placement writer behind both methods.
// prefix == "" means the asset's own prefix_id.
//
// Location and environment are decided independently: a prefix with no
// location still lends its environment, and a site the asset disagrees on
// blocks the location fill without blocking the environment one.
func (r *Repository) projectSegmentLocation(ctx context.Context, asset identity.AssetRef, prefix string, source identity.Source) error {
	return r.RunInTx(ctx, asset.TenantID, func(bound *Repository) error {
		var currentLocation, currentSite, currentEnv, prefixID, location, site, prefixEnv string
		err := bound.Tx().QueryRowContext(ctx, `
   SELECT coalesce(a.location_id::text,''),coalesce(a.site_id::text,''),coalesce(a.environment::text,''),
          p.id::text,coalesce(l.id::text,''),coalesce(l.site_id::text,''),coalesce(p.environment,'')
   FROM public.assets a
   JOIN public.prefixes p ON p.id=coalesce(nullif($3::text,'')::uuid,a.prefix_id) AND p.tenant_id=a.tenant_id
        AND p.status NOT IN ('rejected','archived')
   LEFT JOIN public.locations l ON p.scope_kind='location' AND l.id=p.scope_id AND l.tenant_id=a.tenant_id
   WHERE a.id=$2::uuid AND a.tenant_id=$1::uuid AND a.deleted_at IS NULL
     AND (a.prefix_id IS NULL OR a.prefix_id=p.id)
   FOR UPDATE OF a`, asset.TenantID, asset.ID, prefix).Scan(&currentLocation, &currentSite, &currentEnv, &prefixID, &location, &site, &prefixEnv)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read prefix placement: %w", err)
		}
		changes := map[string]any{}
		sets := []string{}
		args := []any{asset.TenantID, asset.ID}
		// Location: only from a located prefix, never over a disagreeing
		// location or site. The site is the location's own site (DCIM row
		// 2.1), so the pair the asset ends up with always agrees.
		if location != "" && site != "" && (currentLocation == "" || currentLocation == location) &&
			(currentSite == "" || currentSite == site) {
			if currentLocation == "" {
				changes["location_id"] = map[string]string{"from": "", "to": location}
			}
			if currentSite == "" {
				changes["site_id"] = map[string]string{"from": "", "to": site}
			}
			if len(changes) > 0 {
				args = append(args, location, site)
				sets = append(sets, fmt.Sprintf("location_id=$%d::uuid,site_id=$%d::uuid", len(args)-1, len(args)))
			}
		}
		// Environment: only where the asset records none.
		if currentEnv == "" && prefixEnv != "" {
			changes["environment"] = map[string]string{"from": "", "to": prefixEnv}
			args = append(args, prefixEnv)
			sets = append(sets, fmt.Sprintf("environment=$%d::environment_type", len(args)))
		}
		if len(sets) == 0 {
			return nil
		}
		_, err = bound.Tx().ExecContext(ctx, `UPDATE public.assets SET `+strings.Join(sets, ",")+`,updated_at=now() WHERE tenant_id=$1::uuid AND id=$2::uuid`, args...)
		if err != nil {
			return fmt.Errorf("project prefix placement: %w", err)
		}
		changes["prefix_id"] = prefixID
		return bound.RecordHistory(ctx, identity.HistoryEntry{TenantID: asset.TenantID, AssetID: asset.ID, Action: identity.ActionUpdated, Source: source, Changes: changes})
	})
}
