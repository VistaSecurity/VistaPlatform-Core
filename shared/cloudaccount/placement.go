package cloudaccount

// Placement: the account's site and its regions' locations (DCIM row 2.1,
// asset-inventory ADR-0009 D1).
//
// One site per account, named by the account and with the provider as its
// `facility`, found again by `source_ref = cloud_account:<provider>:<account>`
// so a person may rename it freely. Each region the account's resources are in
// is a top-level location of that site named by the provider's region code
// (`us-east-1`, `westeurope`). A region is a place inside the account, not an
// asset (cloud_enumeration.go) and not a `regions` row — `regions` is the
// tenant's own geography.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim/sites"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// SiteSourceRef is the source_ref an account's site is found by.
func SiteSourceRef(provider, accountID string) string {
	rid := ResourceID(provider, accountID)
	if rid == "" {
		return ""
	}
	return "cloud_account:" + rid
}

// EnsureSite returns the account's site, creating it when the tenant has none,
// and puts the account asset in it when the asset has no site yet (a site a
// person chose is left alone). name is the account asset's name.
func EnsureSite(ctx context.Context, r *pgidentity.Repository, tenantID, accountAssetID uuid.UUID, provider, accountID, name string) (uuid.UUID, error) {
	tx := r.Tx()
	if tx == nil {
		return uuid.Nil, errors.New("cloudaccount: EnsureSite needs a bound transaction")
	}
	ref := SiteSourceRef(provider, accountID)
	if ref == "" {
		return uuid.Nil, fmt.Errorf("cloudaccount: no account to place (%q, %q)", provider, accountID)
	}
	if strings.TrimSpace(name) == "" {
		name = DisplayName(provider, accountID)
	}
	siteID, _, err := sites.EnsureSite(ctx, tx, tenantID, sites.SiteSpec{
		Name: name, Facility: NormalizeProvider(provider), SourceKind: "declared", SourceRef: ref,
	})
	if err != nil {
		return uuid.Nil, err
	}
	if accountAssetID != uuid.Nil {
		if _, err := tx.ExecContext(ctx, `UPDATE public.assets SET site_id = $3, updated_at = now() WHERE tenant_id = $1 AND id = $2 AND site_id IS NULL`, tenantID, accountAssetID, siteID); err != nil {
			return uuid.Nil, fmt.Errorf("cloudaccount: place account asset: %w", err)
		}
	}
	return siteID, nil
}

// EnsureRegionLocation returns the region's location under the account's site.
func EnsureRegionLocation(ctx context.Context, r *pgidentity.Repository, tenantID, siteID uuid.UUID, provider, region string) (uuid.UUID, error) {
	tx := r.Tx()
	if tx == nil {
		return uuid.Nil, errors.New("cloudaccount: EnsureRegionLocation needs a bound transaction")
	}
	region = strings.TrimSpace(region)
	if region == "" {
		return uuid.Nil, errors.New("cloudaccount: no region")
	}
	id, _, err := sites.EnsureLocation(ctx, tx, tenantID, siteID, region, "declared", "cloud_region:"+NormalizeProvider(provider)+":"+region)
	return id, err
}

// accountSite reads the account asset's site and name.
func accountSite(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, assetID string) (site uuid.NullUUID, name string, err error) {
	err = tx.QueryRowContext(ctx, `SELECT site_id, coalesce(display_name, hostname, '') FROM public.assets WHERE tenant_id = $1 AND id = $2::uuid`, tenantID, assetID).Scan(&site, &name)
	return site, name, err
}

// PlaceInRegion puts a cloud resource in its account's site and its region's
// location there. It reports whether the resource's placement moved. No account
// asset is not an error (see LinkHostedOn): the placement waits for the next
// run. A resource a person placed in another site keeps that site and gains no
// location; a location already recorded is not replaced.
func PlaceInRegion(ctx context.Context, r *pgidentity.Repository, tenantID, resourceAssetID uuid.UUID, provider, accountID, region string) (bool, error) {
	tx := r.Tx()
	if tx == nil {
		return false, errors.New("cloudaccount: PlaceInRegion needs a bound transaction")
	}
	if strings.TrimSpace(region) == "" {
		return false, nil
	}
	accountAsset, err := FindAsset(ctx, r, tenantID.String(), provider, accountID)
	if err != nil || accountAsset == "" {
		return false, err
	}
	current, name, err := accountSite(ctx, tx, tenantID, accountAsset)
	if err != nil {
		return false, err
	}
	accountUUID, err := uuid.Parse(accountAsset)
	if err != nil {
		return false, err
	}
	siteID := current.UUID
	if !current.Valid {
		if siteID, err = EnsureSite(ctx, r, tenantID, accountUUID, provider, accountID, name); err != nil {
			return false, err
		}
	}
	locID, err := EnsureRegionLocation(ctx, r, tenantID, siteID, provider, region)
	if err != nil {
		return false, err
	}
	if resourceAssetID == accountUUID {
		return false, nil
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE public.assets
		   SET site_id = coalesce(site_id, $3),
		       location_id = CASE WHEN location_id IS NULL AND coalesce(site_id, $3) = $3 THEN $4 ELSE location_id END,
		       updated_at = now()
		 WHERE tenant_id = $1 AND id = $2
		   AND (site_id IS NULL OR (site_id = $3 AND location_id IS NULL))`, tenantID, resourceAssetID, siteID, locID)
	if err != nil {
		return false, fmt.Errorf("cloudaccount: place resource: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
