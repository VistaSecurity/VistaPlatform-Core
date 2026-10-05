package services

// slice B, driven through the REAL interrogation ingest: after the
// claims settle, the run's complete gateway-address list goes to the
// gateway-links route (the reference route by default, which runs the same
// shared reconcile inventory-service's route runs; set
// SIGHTINGS_TEST_INVENTORY_URL to run against inventory-service itself).

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

func (f *gatewayFixture) links(t *testing.T) map[string]string {
	t.Helper()
	rows, err := f.db.Query(`SELECT value, gateway_asset_id::text FROM network_segments WHERE tenant_id=$1 AND gateway_asset_id IS NOT NULL`, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var cidr, gw string
		if err := rows.Scan(&cidr, &gw); err != nil {
			t.Fatal(err)
		}
		out[cidr] = gw
	}
	return out
}

func (f *gatewayFixture) persistFacts(t *testing.T, at time.Time, fs ...di.FactObservation) {
	t.Helper()
	if err := NewObservationSink(f.db).Persist(context.Background(), f.tenant, f.gateway, interrogationSource(uuid.New()), InterrogationObservations{
		ObservedAt: at, Facts: fs,
	}); err != nil {
		t.Fatalf("Persist: %v", err)
	}
}

func TestIntegration_GatewayLinks_InterrogationLinksHeldNetworksOnly(t *testing.T) {
	f := newGatewayFixture(t)
	seg := f.segments
	// A stronger holder of the gateway's IPv6 address: that claim is
	// contested, so that network must not be linked.
	f.createAsset(t, "other device", "", seg["2001:db8:4::/64"],
		identity.Identifier{Kind: identity.KindIPAddress, Value: "2001:db8:4::1", Scope: seg["2001:db8:4::/64"]},
		identity.Identifier{Kind: identity.KindMACAddress, Value: "00:00:5e:00:53:98"})

	at := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	f.interrogate(t, uuid.New(), at)
	gw := f.gateway.String()
	want := map[string]string{"192.0.2.0/24": gw, "198.51.100.0/24": gw, "203.0.113.0/24": gw}
	got := f.links(t)
	if len(got) != len(want) {
		t.Errorf("links = %v, want %v (the contested IPv6 network unlinked)", got, want)
	}
	for cidr, g := range want {
		if got[cidr] != g {
			t.Errorf("%s gateway = %q, want %s", cidr, got[cidr], g)
		}
	}

	// A run that reports no networks at all says nothing: links stay.
	f.persistFacts(t, at.Add(time.Hour), di.FactObservation{Key: facts.KeyHWModel, Value: "UDR", Confidence: 1})
	if got := f.links(t); len(got) != 3 {
		t.Errorf("a run without net.vlans changed the links: %v", got)
	}

	// A run that no longer reports Cameras unlinks it, and only it.
	var vlans []map[string]any
	for _, v := range gatewayVLANs() {
		if v["name"] != "Cameras" {
			vlans = append(vlans, v)
		}
	}
	f.persistFacts(t, at.Add(2*time.Hour), di.FactObservation{Key: facts.KeyNetVlans, Value: vlans, Confidence: 1})
	got = f.links(t)
	if _, still := got["203.0.113.0/24"]; still || len(got) != 2 {
		t.Errorf("links after Cameras stopped being reported = %v, want Default and Lab only", got)
	}
}
