package dispatchguard

// A learned PUBLIC prefix a person has claimed (owner decision D8; DCIM
// row 1.6: the claim is setting its source to declared) is ownership exactly as
// a declared public prefix is — and nothing more: manual scans only, the
// breadth cap still applies, an exclusion still beats it, an archived prefix
// grants nothing. Each reader of prefixScopeSQL is driven against real rows,
// inside a tenant-scoped app-role transaction: LoadTargetScope (a scan a person
// asks for), AuthorizeAutomaticScan (the unattended sweep) and OwnedNetworks
// (what sensors are told).

import (
	"database/sql"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/autoscan"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestIntegration_ClaimedLearnedPrefix_Ownership pins how every scope loader
// reads a prefix's provenance (DCIM row 1.6; owner decision D8 on): a
// prefix a collector LEARNED (source measured or inferred) is where a device is
// connected, never a claim of ownership; a person claims it by setting its
// source to declared, after which it is read as declared everywhere. An
// exclusion (sensitive, probes disabled) wins over any claim, and a rejected
// or archived prefix grants nothing.
//
// Mutation: make prefixScopeSQL's `learned` false for measured rows and
// "learned, unclaimed" goes red; drop the `blocked` term and the sensitive /
// probes-disabled rows go red.
func TestIntegration_ClaimedLearnedPrefix_Ownership(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	testdb.EnsureRLSAppRole(t, db)
	tenant := testdb.NewTenant(t, db)

	for _, row := range []struct {
		name, value, networkType, sourceKind, status string
		sensitive, probesOff                         bool
	}{
		{"learned, unclaimed", "93.184.216.0/28", "public", "measured", "active", false, false},
		{"learned, claimed", "93.184.216.16/28", "public", "declared", "active", false, false},
		{"claimed, too broad", "40.0.0.0/7", "public", "declared", "active", false, false},
		{"claimed, sensitive", "93.184.216.48/28", "public", "declared", "active", true, false},
		{"claimed, probes disabled", "93.184.216.64/28", "public", "declared", "active", false, true},
		{"claimed, archived", "93.184.216.80/28", "public", "declared", "archived", false, false},
		{"inferred, unclaimed", "93.184.216.96/28", "public", "inferred", "pending", false, false},
		{"learned private", "10.20.30.0/24", "private", "measured", "pending", false, false},
		{"declared public", "93.184.217.0/24", "public", "declared", "active", false, false},
		{"declared, no type stated", "93.184.219.0/24", "", "declared", "active", false, false},
	} {
		var nt any
		if row.networkType != "" {
			nt = row.networkType
		}
		if _, err := db.Exec(`INSERT INTO prefixes (tenant_id, prefix, description, network_type, source_kind, status, sensitive, active_probes_disabled)
			VALUES ($1, $2::cidr, $3, $4, $5, $6, $7, $8)`, tenant, row.value, row.name, nt, row.sourceKind, row.status, row.sensitive, row.probesOff); err != nil {
			t.Fatalf("%s: %v", row.name, err)
		}
	}

	var scope TargetScope
	testdb.AsTenant(t, db, tenant, func(tx *sql.Tx) {
		var err error
		if scope, err = LoadTargetScope(tx, tenant.String()); err != nil {
			t.Fatal(err)
		}
	})
	for _, tc := range []struct {
		target, why string
		allowed     bool
		excluded    bool
	}{
		{"93.184.216.5", "learned public, unclaimed: not the tenant's", false, false},
		{"93.184.216.20", "claimed: the tenant's, for a scan a person asks for", true, false},
		{"40.1.2.3", "claimed but too broad to be anybody's", false, false},
		{"93.184.216.50", "claimed but sensitive: the exclusion wins", false, true},
		{"93.184.216.70", "claimed but probes disabled: the exclusion wins", false, true},
		{"93.184.216.85", "claimed but archived: grants nothing", false, false},
		{"93.184.216.100", "inferred: not a claim", false, false},
		{"10.20.30.40", "learned private: private space is the tenant's", true, false},
		{"93.184.217.9", "declared public", true, false},
		{"93.184.219.9", "declared with no type: its address class (public)", true, false},
	} {
		err := scope.Authorize(tc.target)
		if (err == nil) != tc.allowed {
			t.Errorf("Authorize(%s) = %v, want allowed=%v (%s)", tc.target, err, tc.allowed, tc.why)
		}
		if tc.excluded && (err == nil || !strings.Contains(err.Error(), "excluded")) {
			t.Errorf("Authorize(%s) = %v, want an exclusion (%s)", tc.target, err, tc.why)
		}
	}

	// The unattended sweep never treats public space as the tenant's, claimed
	// or declared: a claim is permission to scan on request, nothing more.
	for _, target := range []string{"93.184.216.20", "93.184.217.9"} {
		var err error
		testdb.AsTenant(t, db, tenant, func(tx *sql.Tx) {
			err = AuthorizeAutomaticScan(tx, sensordispatch.Payload{
				TenantID: tenant.String(), Targets: []string{target},
				Protocols: autoscan.DefaultPolicy().Protocols[:1], Ports: autoscan.DefaultPolicy().Ports[:1],
				Options: map[string]interface{}{"origin": "auto_scan"},
			})
		})
		if err == nil || !strings.Contains(err.Error(), "outside authorized scope") {
			t.Errorf("AuthorizeAutomaticScan(%s) = %v, want outside authorized scope", target, err)
		}
	}

	testdb.AsTenant(t, db, tenant, func(tx *sql.Tx) {
		owned, err := OwnedNetworks(tx, tenant.String())
		if err != nil {
			t.Fatal(err)
		}
		for prefix, want := range map[string]bool{
			"93.184.216.0/28":  false, // learned, unclaimed
			"93.184.216.16/28": true,  // claimed
			"40.0.0.0/7":       false, // too broad
			"93.184.216.48/28": false, // sensitive
			"93.184.216.64/28": false, // probes disabled
			"93.184.216.80/28": false, // archived
			"93.184.216.96/28": false, // inferred
			"93.184.217.0/24":  true,  // declared
		} {
			if got := slices.Contains(owned.Prefixes, prefix); got != want {
				t.Errorf("OwnedNetworks.Prefixes has %s = %v, want %v (got %v)", prefix, got, want, owned.Prefixes)
			}
		}
		for _, prefix := range []string{"93.184.216.48/28", "93.184.216.64/28"} {
			if !slices.Contains(owned.Excluded, prefix) {
				t.Errorf("OwnedNetworks.Excluded lacks %s; a claim must not lift an exclusion (got %v)", prefix, owned.Excluded)
			}
		}
	})
}

// A second tenant's claim is not this tenant's ownership: the claim lives on
// the row, and every reader is tenant-scoped.
func TestIntegration_ClaimedLearnedPrefix_IsPerTenant(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	testdb.EnsureRLSAppRole(t, db)
	claimer, other := testdb.NewTenant(t, db), testdb.NewTenant(t, db)
	if _, err := db.Exec(`INSERT INTO prefixes (tenant_id, prefix, description, network_type, source_kind, source_ref, status)
		VALUES ($1, '93.184.218.0/28'::cidr, 'dmz', 'public', 'declared', 'interrogation:claimed', 'active')`, claimer); err != nil {
		t.Fatal(err)
	}
	for tenant, want := range map[uuid.UUID]bool{claimer: true, other: false} {
		testdb.AsTenant(t, db, tenant, func(tx *sql.Tx) {
			scope, err := LoadTargetScope(tx, tenant.String())
			if err != nil {
				t.Fatal(err)
			}
			if got := scope.Authorize("93.184.218.5") == nil; got != want {
				t.Errorf("tenant %s: in scope = %v, want %v", tenant, got, want)
			}
		})
	}
}
