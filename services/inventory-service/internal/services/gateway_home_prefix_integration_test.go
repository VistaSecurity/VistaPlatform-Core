package services

// §3.4: a device that routes networks has an address on each of them, so
// its prefix must not be "whichever of its addresses the last finding arrived
// on". enrichAssetFromPrefix (every finding) and EnrichAllAssets (the backfill)
// place such a device by its HOME address — the address it is interrogated at
// — and every other asset exactly as before (DCIM row 1.6).
//
// Mutation: drop the homeAddress override in enrichAssetFromPrefix and the
// gateway lands in the finding's prefix.
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_HomePrefix_RoutingDeviceIsPlacedByItsManagementAddress(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	svc := NewAssetService(db)
	ctx := context.Background()

	prefixes := map[string]string{}
	for _, cidr := range []string{"192.0.2.0/24", "198.51.100.0/24"} {
		var id string
		if err := raw.QueryRow(`INSERT INTO prefixes(tenant_id,description,prefix,network_type,environment,source_kind,status) VALUES($1,$2::text,$2::text::cidr,'private','production','declared','active') RETURNING id::text`, tenant, cidr).Scan(&id); err != nil {
			t.Fatal(err)
		}
		prefixes[cidr] = id
	}
	at := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	newAsset := func(name, address string) uuid.UUID {
		ref, err := pgidentity.New(raw).CreateAsset(ctx, tenant.String(), identity.NewAsset{
			ClassKey: "router", ClassSourceKind: identity.ClassSourceMeasured, DisplayName: name,
			Status: identity.StatusMonitoring, PrimaryAddress: address,
			Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "fixture"},
			Identifiers: []identity.Identifier{{Kind: identity.KindSerialNumber, Value: "SN-" + name, Confidence: 1}},
			FirstSeenAt: at, LastSeenAt: at,
		})
		if err != nil {
			t.Fatalf("CreateAsset(%s): %v", name, err)
		}
		return uuid.MustParse(ref.ID)
	}
	// The gateway is managed at 198.51.100.1 and reports the networks it
	// routes; a plain managed switch is managed the same way but routes
	// nothing.
	gateway := newAsset("gateway", "192.0.2.1")
	plain := newAsset("switch", "192.0.2.2")
	for _, a := range []uuid.UUID{gateway, plain} {
		if _, err := raw.Exec(`INSERT INTO asset_management(tenant_id,asset_id,management_url,management_protocol) VALUES($1,$2,'https://198.51.100.1:8443','https')`, tenant, a); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := raw.Exec(`INSERT INTO asset_facts(tenant_id,asset_id,key,value,source_kind,source_ref) VALUES($1,$2,'net.vlans','[{"subnet":"192.0.2.0/24","gateway":"192.0.2.1"}]','measured','interrogation:fixture')`,
		tenant, gateway); err != nil {
		t.Fatal(err)
	}
	prefixOf := func(a uuid.UUID) string {
		t.Helper()
		var s sql.NullString
		if err := raw.QueryRow(`SELECT prefix_id::text FROM assets WHERE id=$1`, a).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s.String
	}

	// A finding on the gateway's address in the first network.
	finding := "192.0.2.1"
	for _, a := range []uuid.UUID{gateway, plain} {
		if _, err := svc.enrichAssetFromPrefix(nil, tenant, a, &finding); err != nil {
			t.Fatalf("enrichAssetFromPrefix: %v", err)
		}
	}
	if got := prefixOf(gateway); got != prefixes["198.51.100.0/24"] {
		t.Errorf("a finding on 192.0.2.1 put the gateway in %q; its home is the management address's prefix %s", got, prefixes["198.51.100.0/24"])
	}
	if got := prefixOf(plain); got != prefixes["192.0.2.0/24"] {
		t.Errorf("a device that routes nothing was placed in %q, want the finding's prefix as before", got)
	}

	// The backfill places by the same rule.
	if _, err := raw.Exec(`UPDATE assets SET prefix_id=NULL WHERE id=$1`, gateway); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EnrichAllAssets(tenant); err != nil {
		t.Fatalf("EnrichAllAssets: %v", err)
	}
	if got := prefixOf(gateway); got != prefixes["198.51.100.0/24"] {
		t.Errorf("reclassify put the gateway in %q, want its home prefix %s", got, prefixes["198.51.100.0/24"])
	}
	if got := prefixOf(plain); got != prefixes["192.0.2.0/24"] {
		t.Errorf("reclassify moved a device that routes nothing to %q", got)
	}
}
