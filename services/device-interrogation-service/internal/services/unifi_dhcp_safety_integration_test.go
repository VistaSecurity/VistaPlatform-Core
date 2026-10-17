package services

import (
	"context"
	"database/sql"
	"github.com/google/uuid"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
	"strings"
	"testing"
)

func TestIntegration_UniFiExistingDHCPAndPreparationFailure(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	var segment string
	if err := db.QueryRow(`INSERT INTO prefixes(tenant_id,description,prefix,network_type,environment,source_kind,status) VALUES($1,'Operator LAN','192.0.2.0/24'::cidr,'private','production','declared','active') RETURNING id`, tenant).Scan(&segment); err != nil {
		t.Fatal(err)
	}
	sink := NewObservationSink(db)
	ctx := context.Background()
	vlans := []map[string]any{{"subnet": "192.0.2.1/24", "name": "Controller LAN", "dhcp_enabled": true}}
	if err := sink.ensureVLANPrefixes(ctx, tenant, uuid.New(), vlans); err != nil {
		t.Fatal(err)
	}
	var name string
	var dhcp sql.NullBool
	if err := db.QueryRow(`SELECT description, dhcp_managed FROM prefixes WHERE id=$1`, segment).Scan(&name, &dhcp); err != nil {
		t.Fatal(err)
	}
	// The operator's prefix keeps its description — and, since, learns
	// what the controller MEASURED about DHCP on it where nobody had said.
	// Before, it stayed silent and addresses kept deciding identity on a DHCP
	// network.
	if name != "Operator LAN" {
		t.Fatalf("operator prefix overwritten: %s", name)
	}
	if !dhcp.Valid || !dhcp.Bool {
		t.Fatalf("the controller's answer did not reach the operator-declared prefix: %v", dhcp)
	}
	// The posture the controller measured is now the segment's STORED
	// posture, which is all Intake reads ( item 7: no per-run overlay).
	peer := di.PeerRef{DisplayName: "Office Alias"}
	peer.AddIdentifier(di.IdentifierIPAddress, "192.0.2.68")
	peer.AddIdentifier(di.IdentifierHostname, "client")
	obs := peerIntakeObservation(t, sink, tenant, peer, identity.Source{Kind: identity.SourceMeasured, Ref: "unifi", Mode: identity.ModeActive})
	if !obs.DynamicScopes[segment] || obs.Hostname != "client" {
		t.Fatalf("unsafe peer: %+v", obs)
	}
	// A cancelled prerequisite cannot fall through and materialise any peers.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	err := sink.Persist(cancelled, tenant, uuid.New(), identity.Source{Kind: identity.SourceMeasured, Ref: "unifi"}, InterrogationObservations{Facts: []di.FactObservation{{Key: facts.KeyNetVlans, Value: vlans}}})
	if err == nil || !strings.Contains(err.Error(), "vlan segments") && !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("expected prerequisite failure, got %v", err)
	}
}

func TestIntegration_UniFiLeaseReuseDoesNotJoinClients(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	if _, err := db.Exec(`INSERT INTO prefixes(tenant_id,description,prefix,network_type,environment,source_kind,status) VALUES($1,'Existing LAN','192.0.2.0/24'::cidr,'private','production','declared','active')`, tenant); err != nil {
		t.Fatal(err)
	}
	sink := NewObservationSink(db)
	controller := seedHexLocalHost(t, db, tenant, "00:1a:2b:3c:4d:5e", "controller")
	for _, host := range []string{"client-a", "client-b"} {
		peer := di.PeerRef{DisplayName: "Shared alias"}
		peer.AddIdentifier(di.IdentifierHostname, host)
		peer.AddIdentifier(di.IdentifierIPAddress, "192.0.2.68")
		err := sink.Persist(context.Background(), tenant, controller, identity.Source{Kind: identity.SourceMeasured, Ref: "unifi", Mode: identity.ModeActive}, InterrogationObservations{Facts: []di.FactObservation{
			{Key: facts.KeyNetVlans, Value: []map[string]any{{"subnet": "192.0.2.0/24", "dhcp_enabled": true}}},
			{Key: facts.KeyHWVendor, Value: "Example", Confidence: 1, Subject: peer},
		}})
		if err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT count(DISTINCT asset_id) FROM asset_identifiers WHERE tenant_id=$1 AND kind='hostname' AND value IN ('client-a','client-b')`, tenant).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("lease reuse joined clients: %d identities", n)
	}
}
