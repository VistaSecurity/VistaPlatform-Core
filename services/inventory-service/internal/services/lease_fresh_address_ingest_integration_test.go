package services

// The lease-fresh address (ADR-0002 D3 erratum, shared/identity/leasefresh.go)
// through the REAL inventory intake: IngestFindings → discoveryObservation →
// the production engine (svc.identityEngine(), admission ENFORCED, provisional
// inventory on) → the Postgres identity repository.
//
// The dev-cluster finding that motivated it. Both of a tenant's segments were
// flagged DHCP; a sensor saw each host's MAC at its address every few minutes;
// and every SSH or TLS probe of those same addresses was held as
// `dynamic_address_without_device_binding` and queued under "Matches an asset"
// for a person to link — 42 rows for 16 devices, 14 of which the platform had
// MAC-confirmed within hours of the probe it refused to attach.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"net/netip"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// TestIntegration_LeaseFreshAddress_ProbeOfAMACConfirmedDeviceMatchesInsideDHCPSegment:
// dynamic /24 with dynamic_source=measured; a sensor's L2 sighting of a MAC at
// an address creates the host and confirms it there; an SSH probe of the
// address an hour later is `matched` on the host with its host key attached;
// the same probe past the window is held again, with `needs = link_existing`.
//
// Mutation checks (each run, each red, each restored):
//   - make Engine.addressDecides return !dynamicAddress alone → the probe
//     resolves `unresolved` with no asset;
//   - drop addressLeaseFresh from AssessAdmission → admission refuses the
//     address as dynamic and the probe is only `supporting`;
//   - drop stampDeviceConfirmation from resolveCreate → the host's address is
//     never confirmed and the probe is held.
func TestIntegration_LeaseFreshAddress_ProbeOfAMACConfirmedDeviceMatchesInsideDHCPSegment(t *testing.T) {
	f := newProvisionalFixture(t)
	const (
		hostAddr = "192.0.2.40" // inside provSegmentACIDR
		hostMAC  = "00:00:5e:00:53:40"
		hostKey  = "SHA256:LeaseFreshAddressIntegrationTestHostKeyFingerprint0"
	)
	ctx := t.Context()

	// The router reported DHCP on this LAN, so the whole /24 is flagged
	// dynamic — measured, not an operator's choice.
	f.exec(`UPDATE network_segments SET metadata = '{"dynamic":true,"dynamic_source":"measured"}'::jsonb
	         WHERE tenant_id=$1 AND id=$2`, f.tenant, f.segA)
	scope, dynamic, err := f.svc.identityRepo.ScopeForAddress(ctx, f.tenant.String(), netip.MustParseAddr(hostAddr), "")
	if err != nil || scope != f.segA.String() || !dynamic {
		t.Fatalf("setup: ScopeForAddress(%s) = %q dynamic=%v (err %v), want the DHCP segment %s",
			hostAddr, scope, dynamic, err, f.segA)
	}

	ingest := func(finding IngestFinding) identity.IngestResult {
		t.Helper()
		report, err := f.svc.IngestFindingsReport(f.tenant, []IngestFinding{finding}, "monitoring")
		if err != nil {
			t.Fatal(err)
		}
		if len(report.Results) != 1 {
			t.Fatalf("results = %+v, want one", report.Results)
		}
		return report.Results[0]
	}
	sshProbe := func(observedAt time.Time) IngestFinding {
		p := 22
		return IngestFinding{
			IPAddress: strPtr(hostAddr),
			Port:      &p,
			Protocol:  "SSH",
			RawData: map[string]interface{}{
				"source":                   "sensor_discovery",
				"observed_at":              observedAt.Format(time.RFC3339Nano),
				"ssh_host_key_fingerprint": hostKey,
				"ssh_host_key_type":        "ed25519",
			},
		}
	}

	// 1. The sensor sees the host's MAC at its address in an ARP frame: a
	//    direct L2 sighting. This creates the host, and confirms the device at
	//    the address.
	confirmedAt := f.now.Add(-time.Hour)
	created := f.ingestHostObs(&hostobs.HostObservation{
		Source: hostobs.SourceARP, MAC: hostMAC, Addresses: addrsFor(t, hostAddr), ObservedAt: confirmedAt,
	})
	if created.Outcome != string(identity.OutcomeCreated) || created.AssetID == "" {
		t.Fatalf("the MAC sighting resolved %s on %q, want created", created.Outcome, created.AssetID)
	}
	var deviceConfirmed time.Time
	if err := f.raw.QueryRow(`SELECT device_confirmed_at FROM asset_identifiers
	   WHERE tenant_id=$1 AND kind='ip_address' AND value=$2`, f.tenant, hostAddr).Scan(&deviceConfirmed); err != nil {
		t.Fatalf("the host's address row has no device confirmation: %v", err)
	}
	if !deviceConfirmed.Equal(confirmedAt) {
		t.Fatalf("device_confirmed_at = %v, want the MAC sighting's time %v", deviceConfirmed, confirmedAt)
	}

	// 2. An SSH probe of the address an hour later, carrying a host key the
	//    host has never held: matched on the host, key attached.
	probed := ingest(sshProbe(f.now))
	if probed.Outcome != string(identity.OutcomeMatched) || probed.AssetID != created.AssetID {
		t.Fatalf("the probe of the confirmed address resolved %s on %q, want matched on the host %s",
			probed.Outcome, probed.AssetID, created.AssetID)
	}
	var keyOwner string
	if err := f.raw.QueryRow(`SELECT asset_id::text FROM asset_identifiers
	   WHERE tenant_id=$1 AND kind='ssh_host_key_fingerprint' AND value=$2`, f.tenant, hostKey).Scan(&keyOwner); err != nil || keyOwner != created.AssetID {
		t.Fatalf("the host key is on %q (err %v), want attached to the host %s", keyOwner, err, created.AssetID)
	}
	if n := f.assetCount(); n != 1 {
		t.Fatalf("assets = %d, want only the host: a lease-fresh match must not mint a second asset", n)
	}

	// 3a. Past the window, the SSH probe is still the host — the key it
	//     attached in step 2 identifies the device now, lease or no lease.
	past := confirmedAt.Add(identity.DefaultLeaseWindow + 2*time.Hour)
	byKey := ingest(sshProbe(past))
	if byKey.AssetID != created.AssetID {
		t.Fatalf("past the window the SSH probe resolved %s on %q, want the host %s by its key", byKey.Outcome, byKey.AssetID, created.AssetID)
	}

	// 3b. An address-only probe past the window is a lease again: held, with
	//     the review table offering Link to the host as before.
	port := 443
	late := ingest(IngestFinding{
		IPAddress:   strPtr(hostAddr),
		Port:        &port,
		Protocol:    "TLS",
		CipherSuite: strPtr("TLS_AES_256_GCM_SHA384"),
		RawData: map[string]interface{}{
			"source":      "sensor_discovery",
			"observed_at": past.Format(time.RFC3339Nano),
		},
	})
	if late.Outcome == string(identity.OutcomeMatched) {
		t.Fatalf("an address-only probe past the lease window still matched: %+v", late)
	}
	var needs string
	if err := f.raw.QueryRow(`SELECT `+observationNeedsSQL+` FROM identity_observations o
	   WHERE o.tenant_id=$1 AND o.state='unresolved' ORDER BY o.last_seen_at DESC LIMIT 1`, f.tenant).Scan(&needs); err != nil {
		t.Fatalf("no unresolved observation for the late probe: %v", err)
	}
	if needs != NeedsLinkExisting {
		t.Fatalf("the late probe needs %q, want %q", needs, NeedsLinkExisting)
	}
}
