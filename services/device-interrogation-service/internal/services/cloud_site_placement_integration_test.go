package services

// DCIM row 2.1 (asset-inventory ADR-0009 D1): the cloud account's site, its
// regions as locations under it, and the prefixes scoped to those locations,
// written by the real enumeration recording. Remove the EnsureSite call in
// ensureAccountAsset and the declared account has no site; remove scopeToRegions in
// recordNetworkPrefixes and the prefixes carry no scope; remove PlaceInRegion
// in cloudResourceRecorded and the instance has no location.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"database/sql"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_CloudEnumeration_PlacesTheAccountItsRegionsAndPrefixes(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	svc := NewCloudDiscoveryService(appDB, owner, testMasterKey)
	ctx, integrationID := accountRunContext(ctx, t, svc, owner, tenantID)

	// Declaring the account (the integration) places it in its own site
	// before anything is enumerated: one per account, named by the account,
	// the provider as facility.
	accountID := assetIDForCloudResource(t, owner, tenantID, "aws:123456789012")
	var declared int
	if err := owner.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id = $1 AND id = $2 AND site_id IS NOT NULL`, tenantID, accountID).Scan(&declared); err != nil {
		t.Fatal(err)
	}
	if declared != 1 {
		t.Fatal("declaring the cloud account did not place it in a site")
	}

	plan := awsEnumerationPlanForTest(t)
	if _, _, err := svc.recordEnumeration(ctx, tenantID, integrationID, "production", plan); err != nil {
		t.Fatalf("recordEnumeration: %v", err)
	}

	var siteID, siteRef, facility string
	if err := owner.QueryRow(`
		SELECT s.id::text, coalesce(s.source_ref,''), coalesce(s.facility,'')
		  FROM assets a JOIN sites s ON s.id = a.site_id
		 WHERE a.tenant_id = $1 AND a.id = $2`, tenantID, accountID).Scan(&siteID, &siteRef, &facility); err != nil {
		t.Fatalf("the account asset has no site: %v", err)
	}
	if siteRef != "cloud_account:aws:123456789012" || facility != "aws" {
		t.Errorf("account site = (%q, %q), want (cloud_account:aws:123456789012, aws)", siteRef, facility)
	}

	// The region is a location of that site.
	var locID string
	if err := owner.QueryRow(`SELECT id::text FROM locations WHERE tenant_id = $1 AND site_id = $2 AND parent_id IS NULL AND name = 'us-east-1'`,
		tenantID, siteID).Scan(&locID); err != nil {
		t.Fatalf("no us-east-1 location under the account's site: %v", err)
	}

	// Both of the account's prefixes (the VPC and its subnet) are scoped to it.
	rows, err := owner.Query(`SELECT prefix::text, coalesce(scope_kind,''), coalesce(scope_id::text,'') FROM prefixes WHERE tenant_id = $1 AND cloud_network_ref = $2`,
		tenantID, plan.Networks[0].NetworkRef)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for rows.Next() {
		var p, kind, scope string
		if err := rows.Scan(&p, &kind, &scope); err != nil {
			t.Fatal(err)
		}
		n++
		if kind != "location" || scope != locID {
			t.Errorf("prefix %s scope = (%q, %q), want (location, %s)", p, kind, scope, locID)
		}
	}
	_ = rows.Close()
	if n != 2 {
		t.Errorf("found %d of the account's prefixes, want 2 (the VPC and its subnet)", n)
	}

	// The instance is in the account's site and the region's location.
	instID := assetIDForCloudResource(t, owner, tenantID, plan.Instances[0].ResourceID)
	var instSite, instLoc sql.NullString
	if err := owner.QueryRow(`SELECT site_id::text, location_id::text FROM assets WHERE tenant_id = $1 AND id = $2`, tenantID, instID).Scan(&instSite, &instLoc); err != nil {
		t.Fatal(err)
	}
	if instSite.String != siteID || instLoc.String != locID {
		t.Errorf("instance placement = (%s, %s), want (%s, %s)", instSite.String, instLoc.String, siteID, locID)
	}

	// A second run finds the same site and location rather than minting more.
	if _, _, err := svc.recordEnumeration(ctx, tenantID, integrationID, "production", plan); err != nil {
		t.Fatalf("second recordEnumeration: %v", err)
	}
	var sites, locs int
	if err := owner.QueryRow(`SELECT (SELECT count(*) FROM sites WHERE tenant_id = $1), (SELECT count(*) FROM locations WHERE tenant_id = $1)`, tenantID).Scan(&sites, &locs); err != nil {
		t.Fatal(err)
	}
	if sites != 1 || locs != 1 {
		t.Errorf("after a second run: %d sites, %d locations, want 1 and 1", sites, locs)
	}
}
