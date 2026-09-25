package services

import (
	"context"
	"github.com/google/uuid"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
	"strings"
	"testing"
	"time"
)

func TestIntegration_UniFiExistingDHCPAndPreparationFailure(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	var segment string
	if err := db.QueryRow(`INSERT INTO network_segments(tenant_id,name,segment_type,value,network_type,environment,is_active,metadata) VALUES($1,'Operator LAN','cidr','192.0.2.0/24','private','production',true,'{"operator":"keep"}') RETURNING id`, tenant).Scan(&segment); err != nil {
		t.Fatal(err)
	}
	sink := NewObservationSink(db)
	ctx := context.Background()
	vlans := []map[string]any{{"subnet": "192.0.2.1/24", "name": "Controller LAN", "dhcp_enabled": true}}
	if err := sink.ensureVLANSegments(ctx, tenant, uuid.New(), vlans); err != nil {
		t.Fatal(err)
	}
	var name, metadata string
	if err := db.QueryRow(`SELECT name,metadata::text FROM network_segments WHERE id=$1`, segment).Scan(&name, &metadata); err != nil {
		t.Fatal(err)
	}
	if name != "Operator LAN" || !strings.Contains(metadata, "keep") || strings.Contains(metadata, "dynamic") {
		t.Fatalf("operator segment overwritten: %s %s", name, metadata)
	}
	ctx = context.WithValue(ctx, observedDHCPKey{}, vlanSegmentSpecs(vlans))
	peer := di.PeerRef{DisplayName: "Office Alias"}
	peer.AddIdentifier(di.IdentifierIPAddress, "192.0.2.68")
	peer.AddIdentifier(di.IdentifierHostname, "client")
	obs, _, err := sink.peerObservation(ctx, tenant, peer, identity.Source{Kind: identity.SourceMeasured, Ref: "unifi", Mode: identity.ModeActive}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !obs.DynamicScopes[segment] || obs.Hostname != "client" {
		t.Fatalf("unsafe peer: %+v", obs)
	}
	// A cancelled prerequisite cannot fall through and materialise any peers.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	err = sink.Persist(cancelled, tenant, uuid.New(), identity.Source{Kind: identity.SourceMeasured, Ref: "unifi"}, InterrogationObservations{Facts: []di.FactObservation{{Key: facts.KeyNetVlans, Value: vlans}}})
	if err == nil || !strings.Contains(err.Error(), "vlan segments") && !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("expected prerequisite failure, got %v", err)
	}
}

func TestIntegration_UniFiLeaseReuseDoesNotJoinClients(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	if _, err := db.Exec(`INSERT INTO network_segments(tenant_id,name,segment_type,value,network_type,environment,is_active) VALUES($1,'Existing LAN','cidr','192.0.2.0/24','private','production',true)`, tenant); err != nil {
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
