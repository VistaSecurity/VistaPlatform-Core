package services

//owner decision 1, through the REAL inventory intake: IngestFindings →
// discoveryObservation → the production engine (svc.identityEngine(),
// admission ENFORCED, provisional inventory on) → the Postgres identity
// repository.
//
// The issue's worked example. A gateway's own LAN address sits inside a /24 the
// router reports DHCP for (`dynamic_source = measured`). A sensor measured the
// address first; the operator then declared it on the gateway. Before
// that declaration left the row `measured` (the upsert only upgraded
// `inferred`), and the engine decided on the segment's DHCP flag alone — so
// every scan of the gateway at that address came back `unresolved` with reason
// `dynamic_address_without_device_binding`, three times, once per port.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"net/netip"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// TestIntegration_StaticAddressPin_GatewayLANAddressMatchesInsideDHCPSegment:
// dynamic /24 with dynamic_source=measured, the gateway owns the address as
// declared → a TLS scan at that address on 443/8443/9443 is `matched` on the
// gateway, not `unresolved`.
//
// Mutation checks (each run, each red, each restored):
//   - drop the pinned-address exception in Engine.dynamicAddress → the scans
//     resolve `unresolved` with no asset;
//   - drop the pinned-address exception from AssessAdmission → admission
//     refuses the address as dynamic and the scans are only `supporting`;
//   - make Identifier.StoredAssignment ignore SourceDeclared → the declared
//     row is stored unpinned and the setup assertion fails.
func TestIntegration_StaticAddressPin_GatewayLANAddressMatchesInsideDHCPSegment(t *testing.T) {
	f := newProvisionalFixture(t)
	const gatewayAddr = "192.0.2.1" // inside provSegmentACIDR
	ctx := t.Context()

	// The router reported DHCP on this LAN, so the whole /24 is flagged
	// dynamic — measured, not an operator's choice.
	f.exec(`UPDATE network_segments SET metadata = '{"dynamic":true,"dynamic_source":"measured"}'::jsonb
	         WHERE tenant_id=$1 AND id=$2`, f.tenant, f.segA)
	scope, dynamic, err := f.svc.identityRepo.ScopeForAddress(ctx, f.tenant.String(), netip.MustParseAddr(gatewayAddr), "")
	if err != nil || scope != f.segA.String() || !dynamic {
		t.Fatalf("setup: ScopeForAddress(%s) = %q dynamic=%v (err %v), want the DHCP segment %s",
			gatewayAddr, scope, dynamic, err, f.segA)
	}

	// The gateway as the dev cluster had it: a sensor measured the address,
	// then the operator declared it (the Devices form's write).
	measured := identity.Identifier{
		Kind: identity.KindIPAddress, Value: gatewayAddr, Scope: scope, Confidence: 1,
		Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:lan"}, SeenAt: f.now.Add(-48 * time.Hour),
	}
	gw, err := f.svc.identityRepo.CreateAsset(ctx, f.tenant.String(), identity.NewAsset{
		ClassKey: "router", ClassSourceKind: identity.ClassSourceDeclared, DisplayName: "dream-router",
		Status: identity.StatusMonitoring, IdentityStatus: string(identity.IdentityEstablished),
		Source:      identity.Source{Kind: identity.SourceDeclared, Ref: "manual"},
		Identifiers: []identity.Identifier{measured},
		FirstSeenAt: measured.SeenAt, LastSeenAt: measured.SeenAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	declared := measured
	declared.Source = identity.Source{Kind: identity.SourceDeclared, Ref: "manual"}
	declared.SeenAt = f.now.Add(-24 * time.Hour)
	if _, err := f.svc.identityRepo.AttachIdentifiers(ctx, gw, []identity.Identifier{declared}); err != nil {
		t.Fatal(err)
	}
	var sourceKind, assignment string
	if err := f.raw.QueryRow(`SELECT source_kind, coalesce(address_assignment,'') FROM asset_identifiers
	   WHERE tenant_id=$1 AND kind='ip_address' AND value=$2`, f.tenant, gatewayAddr).Scan(&sourceKind, &assignment); err != nil {
		t.Fatal(err)
	}
	if sourceKind != "declared" || assignment != "static" {
		t.Fatalf("after the declaration the row is %s/%q, want declared/static — the upsert must let a declaration upgrade a measured row",
			sourceKind, assignment)
	}

	// The scans. One finding per port, exactly as the converter delivers an
	// active TLS probe: a passive sensor discovery with a port and a cipher.
	for _, port := range []int{443, 8443, 9443} {
		p := port
		finding := IngestFinding{
			IPAddress:            strPtr(gatewayAddr),
			Port:                 &p,
			Protocol:             "TLS",
			ProtocolVersion:      strPtr("TLS 1.3"),
			CipherSuite:          strPtr("TLS_AES_256_GCM_SHA384"),
			KeyExchangeAlgorithm: strPtr("X25519"),
			RawData: map[string]interface{}{
				"source":      "sensor_discovery",
				"observed_at": f.now.Add(-time.Minute).Format(time.RFC3339Nano),
			},
		}
		report, err := f.svc.IngestFindingsReport(f.tenant, []IngestFinding{finding}, "monitoring")
		if err != nil {
			t.Fatalf("port %d: %v", port, err)
		}
		if len(report.Results) != 1 {
			t.Fatalf("port %d: results = %+v, want one", port, report.Results)
		}
		got := report.Results[0]
		if got.Outcome != string(identity.OutcomeMatched) || got.AssetID != gw.ID {
			t.Fatalf("port %d: the scan at the gateway's pinned address resolved %s on %q, want matched on the gateway %s",
				port, got.Outcome, got.AssetID, gw.ID)
		}
	}
	if n := f.assetCount(); n != 1 {
		t.Errorf("assets = %d, want only the gateway: a pinned address must not mint a second asset", n)
	}
}
