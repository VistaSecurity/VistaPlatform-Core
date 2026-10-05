package dispatchguard

// A learned PUBLIC segment a person has claimed (owner decision D8) is
// ownership exactly as a declared public segment is — and nothing more: manual
// scans only, the breadth cap still applies, an exclusion still beats it, an
// inactive segment grants nothing. Each reader that uses learnedSegmentSQL is
// driven against real rows, inside a tenant-scoped app-role transaction:
// LoadTargetScope (a scan a person asks for), AuthorizeAutomaticScan (the
// unattended sweep) and OwnedNetworks (what sensors are told).

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

const claimJSON = `"claimed":{"by":"00000000-0000-0000-0000-000000000001","by_name":"Ada Admin","at":"2026-10-01T12:00:00Z"}`

func TestIntegration_ClaimedLearnedSegment_Ownership(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	testdb.EnsureRLSAppRole(t, db)
	tenant := testdb.NewTenant(t, db)

	learned := `"source":"interrogation","source_device_type":"fortinet"`
	for _, row := range []struct {
		name, value, networkType, metadata string
		active                             bool
	}{
		{"learned, unclaimed", "93.184.216.0/28", "public", `{` + learned + `}`, true},
		{"learned, claimed", "93.184.216.16/28", "public", `{` + learned + `,` + claimJSON + `}`, true},
		{"legacy label, claimed", "93.184.216.32/28", "public", `{"source":"unifi",` + claimJSON + `}`, true},
		{"claimed, too broad", "40.0.0.0/7", "public", `{` + learned + `,` + claimJSON + `}`, true},
		{"claimed, sensitive", "93.184.216.48/28", "public", `{` + learned + `,` + claimJSON + `,"sensitive":true}`, true},
		{"claimed, probes disabled", "93.184.216.64/28", "public", `{` + learned + `,` + claimJSON + `,"active_probes_disabled":true}`, true},
		{"claimed, inactive", "93.184.216.80/28", "public", `{` + learned + `,` + claimJSON + `}`, false},
		{"not an object is not a claim", "93.184.216.96/28", "public", `{` + learned + `,"claimed":true}`, true},
		{"learned private", "10.20.30.0/24", "private", `{` + learned + `}`, true},
		{"declared public", "93.184.217.0/24", "public", `{}`, true},
	} {
		if _, err := db.Exec(`INSERT INTO network_segments (tenant_id, name, segment_type, value, network_type, environment, is_active, metadata)
			VALUES ($1, $2, 'cidr', $3, $4, 'production', $5, $6::jsonb)`, tenant, row.name, row.value, row.networkType, row.active, row.metadata); err != nil {
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
		{"93.184.216.40", "claimed under the legacy label", true, false},
		{"40.1.2.3", "claimed but too broad to be anybody's", false, false},
		{"93.184.216.50", "claimed but sensitive: the exclusion wins", false, true},
		{"93.184.216.70", "claimed but probes disabled: the exclusion wins", false, true},
		{"93.184.216.85", "claimed but inactive: grants nothing", false, false},
		{"93.184.216.100", "a non-object under the key is not a claim", false, false},
		{"10.20.30.40", "learned private: unchanged", true, false},
		{"93.184.217.9", "declared public: unchanged", true, false},
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
			"93.184.216.32/28": true,  // claimed, legacy label
			"40.0.0.0/7":       false, // too broad
			"93.184.216.48/28": false, // sensitive
			"93.184.216.64/28": false, // probes disabled
			"93.184.216.80/28": false, // inactive
			"93.184.216.96/28": false, // not an object
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
func TestIntegration_ClaimedLearnedSegment_IsPerTenant(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	testdb.EnsureRLSAppRole(t, db)
	claimer, other := testdb.NewTenant(t, db), testdb.NewTenant(t, db)
	if _, err := db.Exec(`INSERT INTO network_segments (tenant_id, name, segment_type, value, network_type, environment, is_active, metadata)
		VALUES ($1, 'dmz', 'cidr', '93.184.218.0/28', 'public', 'production', true, $2::jsonb)`,
		claimer, `{"source":"interrogation",`+claimJSON+`}`); err != nil {
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
