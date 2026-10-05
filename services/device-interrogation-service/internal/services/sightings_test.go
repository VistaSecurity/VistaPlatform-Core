package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/memory"
)

func TestPeerChannel(t *testing.T) {
	for _, tc := range []struct {
		ev   di.PeerIdentityEvidence
		want identity.Channel
	}{
		{di.PeerIdentityEvidence{}, identity.ChannelAdvertisement},
		{di.PeerIdentityEvidence{ControllerInventory: true}, identity.ChannelControllerInventory},
		{di.PeerIdentityEvidence{ConnectedInterface: true}, identity.ChannelL2Frame},
		// An adopted device seen online: the interface binding, which can admit.
		{di.PeerIdentityEvidence{ConnectedInterface: true, ControllerInventory: true}, identity.ChannelL2Frame},
	} {
		if got := peerChannel(di.PeerRef{IdentityEvidence: tc.ev}); got != tc.want {
			t.Errorf("%+v: channel %q, want %q", tc.ev, got, tc.want)
		}
	}
}

// The peer path's sighting carries the collector's identifiers unscoped and
// refuses a peer with nothing that could identify it.
func TestPeerSighting(t *testing.T) {
	sink := &ObservationSink{}
	tenant := uuid.New()
	src := interrogationSource(uuid.New())
	peer := di.PeerRef{
		DisplayName:      "gw",
		IdentityEvidence: di.PeerIdentityEvidence{ControllerInventory: true},
		Identifiers: []di.PeerIdentifier{
			{Kind: di.IdentifierIPAddress, Value: "10.0.0.1"},
			{Kind: di.IdentifierIPAddress, Value: "10.0.1.1"},
			{Kind: di.IdentifierMACAddress, Value: "00:00:5e:00:53:01"},
		},
	}
	s, _, err := sink.peerSighting(context.Background(), tenant, peer, src, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if s.Channel != identity.ChannelControllerInventory || len(s.Identifiers) != 3 || s.Confidence != peerConfidence {
		t.Fatalf("sighting %+v", s)
	}
	synthetic := di.PeerRef{Identifiers: []di.PeerIdentifier{{Kind: di.IdentifierHostname, Value: "10-0-0-1"}}}
	if _, _, err := sink.peerSighting(context.Background(), tenant, synthetic, src, time.Now()); !errors.Is(err, errPeerSyntheticNamesOnly) {
		t.Fatalf("synthetic-only peer: err=%v", err)
	}
}

// Add device sends each address once and the probe's MAC as an identifier
// ( item 10).
func TestDeviceSighting_OneAddressAndProbeMAC(t *testing.T) {
	s, err := deviceSighting(uuid.New(), deviceSightingInput{
		deviceObservationInput: deviceObservationInput{
			DeviceType: "unifi", IPAddress: "10.0.0.1", Hostname: "10.0.0.1", ManagementURL: "https://10.0.0.1:443",
			SerialNumber: "S1", Source: declaredSource(), ObservedAt: time.Now(),
			Admission: identity.AdmissionEvidence{Direct: true, Authoritative: true, ReceiptID: "device_probe"},
		},
		ProbeMACAddress: "00:00:5e:00:53:01",
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.Channel != identity.ChannelAuthenticatedSession {
		t.Errorf("channel %q", s.Channel)
	}
	counts := map[identity.Kind]int{}
	for _, id := range s.Identifiers {
		counts[id.Kind]++
		if id.Kind == identity.KindMACAddress && id.Provenance.Kind != identity.SourceMeasured {
			t.Errorf("probe MAC provenance %+v, want measured", id.Provenance)
		}
	}
	if counts[identity.KindIPAddress] != 1 || counts[identity.KindMACAddress] != 1 || counts[identity.KindSerialNumber] != 1 || counts[identity.KindHostname] != 0 {
		t.Errorf("identifiers %+v", s.Identifiers)
	}
	typed, err := deviceSighting(uuid.New(), deviceSightingInput{deviceObservationInput: deviceObservationInput{IPAddress: "10.0.0.2", Source: declaredSource()}})
	if err != nil || typed.Channel != identity.ChannelPerson {
		t.Errorf("typed: %q %v", typed.Channel, err)
	}
	if _, err := deviceSighting(uuid.New(), deviceSightingInput{}); !errors.Is(err, errDeviceHasNoIdentifier) {
		t.Errorf("empty: %v", err)
	}
}

func TestApplyTo_ProbeMACIsEvidence(t *testing.T) {
	var req models.CreateDeviceRequest
	(&DiscoveredDeviceInfo{MacAddress: " 00:00:5e:00:53:01 ", TargetHost: "10.0.0.1"}).ApplyTo(&req, false)
	if req.ProbeMACAddress != "00:00:5e:00:53:01" {
		t.Errorf("ProbeMACAddress %q", req.ProbeMACAddress)
	}
}

// Host inventory: the primary address leads, a static address is
// self-reported (pinned), a lease carries its assignment and is not, and the
// hostname is seen at the primary address.
func TestHostSighting(t *testing.T) {
	subject := di.PeerRef{DisplayName: "gw", Identifiers: []di.PeerIdentifier{{Kind: di.IdentifierHostname, Value: "gw"}}}
	obs := &di.InterrogateResult{Facts: []di.FactObservation{{Key: facts.KeyNetInterfaces, Value: []map[string]any{
		{"name": "eth0", "addresses": []string{"10.9.0.2/24"}, "dynamic_addresses": []string{"10.9.0.2/24"}},
		{"name": "eth1", "addresses": []string{"10.1.0.1/24"}, "static_addresses": []string{"10.1.0.1/24"}},
	}}}}
	s, err := hostSighting(uuid.New(), subject, hostInventoryMetadata{}, obs, hostInventorySource(uuid.New(), uuid.New()), "run")
	if err != nil {
		t.Fatal(err)
	}
	if s.Channel != identity.ChannelAuthenticatedSession || s.ReceiptID != "run" {
		t.Fatalf("sighting %+v", s)
	}
	want := []identity.SightedIdentifier{
		{Kind: identity.KindIPAddress, Value: "10.9.0.2", Assignment: identity.AssignmentDynamic},
		{Kind: identity.KindIPAddress, Value: "10.1.0.1", Assignment: identity.AssignmentStatic, Provenance: identity.IdentifierProvenance{SelfReported: true}},
		{Kind: identity.KindHostname, Value: "gw", Address: "10.9.0.2"},
	}
	if len(s.Identifiers) != len(want) {
		t.Fatalf("identifiers %+v", s.Identifiers)
	}
	for i := range want {
		if s.Identifiers[i] != want[i] {
			t.Errorf("identifier %d = %+v, want %+v", i, s.Identifiers[i], want[i])
		}
	}
	in, _ := identity.NewIntake(memory.New())
	res, err := in.Assess(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range res.Observation.Identifiers {
		if id.Kind == identity.KindIPAddress && id.Pinned != (id.Value == "10.1.0.1") {
			t.Errorf("%s pinned=%t", id.Value, id.Pinned)
		}
	}
}

func TestDeviceUpdateAndSelfIdentitySightings(t *testing.T) {
	known := []identity.SightedIdentifier{{Kind: identity.KindMACAddress, Value: "00:00:5e:00:53:01",
		Provenance: identity.IdentifierProvenance{Kind: identity.SourceInferred, Ref: "asset:x"}}}
	if _, ok := deviceUpdateSighting(uuid.New(), time.Now(), "", "", ""); ok {
		t.Error("an update that names no identifier produced a sighting")
	}
	s, ok := deviceUpdateSighting(uuid.New(), time.Now(), "fw1", "10.0.0.1", "S1")
	if !ok || s.Channel != identity.ChannelPerson || s.Source.Kind != identity.SourceDeclared || len(s.Identifiers) != 3 {
		t.Fatalf("update sighting %+v", s)
	}
	self := selfIdentitySighting(uuid.New(), interrogationSource(uuid.New()), time.Now(), "S1", known)
	if self.Channel != identity.ChannelAuthenticatedSession || len(self.Identifiers) != 2 || self.Identifiers[0].Kind != identity.KindSerialNumber {
		t.Fatalf("self sighting %+v", self)
	}
}

// Add device's per-identifier provenance: what the probe READ off the
// device — its MAC, host key, serial and own address — is measured; what the
// operator typed (the management URL they dialled) stays declared, and a
// value both typed and read keeps the declared claim.
func TestDeviceSighting_ProbeReadIsMeasured(t *testing.T) {
	url := "https://10.0.0.1:443"
	req := models.CreateDeviceRequest{DeviceType: "unifi", ManagementURL: &url}
	(&DiscoveredDeviceInfo{SerialNumber: "SN-1", IPAddress: "10.0.0.9", Hostname: "gw1", MacAddress: "00:00:5e:00:53:01",
		TargetHost: "10.0.0.1", SSHHostKeyFingerprint: "SHA256:abc", SSHHostKeyType: "ssh-ed25519"}).ApplyTo(&req, false)
	s, err := deviceSighting(uuid.New(), deviceSightingInput{
		deviceObservationInput: deviceObservationInput{
			DeviceType: req.DeviceType, Hostname: derefStr(req.Hostname), IPAddress: derefStr(req.IPAddress),
			ManagementURL: url, SerialNumber: derefStr(req.SerialNumber), Source: declaredSource(),
			Admission: probeEvidence(req.ProbeEvidence),
		},
		ProbeMACAddress: req.ProbeMACAddress, ProbeRead: req.ProbeRead,
		ProbeSSHHostKey: req.ProbeSSHHostKeyFingerprint, ProbeSSHHostKeyType: req.ProbeSSHHostKeyType,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]identity.SourceKind{
		"10.0.0.1": "", "10.0.0.9": identity.SourceMeasured, "gw1": identity.SourceMeasured, "SN-1": identity.SourceMeasured,
		"00:00:5e:00:53:01": identity.SourceMeasured, "SHA256:abc": identity.SourceMeasured,
	}
	for _, id := range s.Identifiers {
		w, ok := want[id.Value]
		if !ok {
			t.Errorf("unexpected identifier %+v", id)
			continue
		}
		if id.Provenance.Kind != w {
			t.Errorf("%s provenance %q, want %q", id.Value, id.Provenance.Kind, w)
		}
		delete(want, id.Value)
	}
	if len(want) != 0 {
		t.Errorf("missing identifiers %v", want)
	}

	// The operator typed the serial and the probe confirmed it: declared.
	typedSerial := "SN-2"
	req2 := models.CreateDeviceRequest{DeviceType: "unifi", ManagementURL: &url, SerialNumber: &typedSerial}
	(&DiscoveredDeviceInfo{SerialNumber: "SN-2", TargetHost: "10.0.0.1"}).ApplyTo(&req2, false)
	if req2.ProbeRead.SerialNumber != "" {
		t.Errorf("a typed serial was recorded as probe-read")
	}
}
