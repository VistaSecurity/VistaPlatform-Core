package identity_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/attrlist"
	"github.com/vistasecurity/vistaplatform/shared/identity/derive"
	"github.com/vistasecurity/vistaplatform/shared/identity/memory"
)

const intakeTenant = "tenant-intake"

func measuredSighting(ch identity.Channel, ids ...identity.SightedIdentifier) identity.Sighting {
	return identity.Sighting{
		TenantID:    intakeTenant,
		Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "sensor", Mode: identity.ModePassive},
		Channel:     ch,
		ObservedAt:  time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC),
		Identifiers: ids,
	}
}

func sid(kind identity.Kind, value string) identity.SightedIdentifier {
	return identity.SightedIdentifier{Kind: kind, Value: value}
}

func newIntake(t *testing.T, r identity.Repository) *identity.Intake {
	t.Helper()
	in, err := identity.NewIntake(r)
	if err != nil {
		t.Fatalf("NewIntake: %v", err)
	}
	return in
}

func assess(t *testing.T, r identity.Repository, s identity.Sighting) identity.IntakeResult {
	t.Helper()
	res, err := newIntake(t, r).Assess(context.Background(), s)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	return res
}

func findID(obs identity.Observation, kind identity.Kind, value string) (identity.Identifier, bool) {
	for _, id := range obs.Identifiers {
		if id.Kind == kind && id.Value == value {
			return id, true
		}
	}
	return identity.Identifier{}, false
}

func mustID(t *testing.T, obs identity.Observation, kind identity.Kind, value string) identity.Identifier {
	t.Helper()
	id, ok := findID(obs, kind, value)
	if !ok {
		t.Fatalf("observation has no %s=%q; identifiers: %+v", kind, value, obs.Identifiers)
	}
	return id
}

// ── the channel table ─────────────────────────────────────────────────────

// TestChannelAdmission_Table pins THE table. Every channel appears exactly
// once, and a channel added to AllChannels without a row here fails.
func TestChannelAdmission_Table(t *testing.T) {
	want := map[identity.Channel][3]bool{ // direct, relayed, authoritative
		identity.ChannelL2Frame:              {true, false, false},
		identity.ChannelAdvertisement:        {false, false, false},
		identity.ChannelRelayed:              {false, true, false},
		identity.ChannelL3Probe:              {true, false, false},
		identity.ChannelL3Traffic:            {false, false, false},
		identity.ChannelAuthenticatedSession: {true, false, true},
		identity.ChannelControllerInventory:  {false, false, true},
		identity.ChannelAPI:                  {false, false, true},
		identity.ChannelPerson:               {false, false, false},
	}
	if len(identity.AllChannels()) != len(want) {
		t.Fatalf("AllChannels has %d channels, the table test %d: a channel without a pinned row",
			len(identity.AllChannels()), len(want))
	}
	for _, ch := range identity.AllChannels() {
		w, ok := want[ch]
		if !ok {
			t.Errorf("channel %q has no row in this test", ch)
			continue
		}
		got, ok := identity.ChannelAdmission(ch)
		if !ok {
			t.Errorf("ChannelAdmission(%q) is not ok", ch)
			continue
		}
		if [3]bool{got.Direct, got.Relayed, got.Authoritative} != w {
			t.Errorf("ChannelAdmission(%q) = direct %t relayed %t authoritative %t, want %v",
				ch, got.Direct, got.Relayed, got.Authoritative, w)
		}
		if got.OperatorConfirmed {
			t.Errorf("ChannelAdmission(%q) set OperatorConfirmed; no collector channel may", ch)
		}
		// And Assess carries exactly the table's flags onto the observation.
		r := memory.New()
		res := assess(t, r, measuredSighting(ch, sid(identity.KindSerialNumber, "SN-1")))
		a := res.Observation.Admission
		if [3]bool{a.Direct, a.Relayed, a.Authoritative} != w {
			t.Errorf("Assess(%q) admission = %+v, want %v", ch, a, w)
		}
	}
	for _, bad := range []identity.Channel{"", "sensor", "L2_FRAME"} {
		if _, ok := identity.ChannelAdmission(bad); ok {
			t.Errorf("ChannelAdmission(%q) is ok; an unknown channel must earn nothing", bad)
		}
		_, err := newIntake(t, memory.New()).Build(context.Background(),
			measuredSighting(bad, sid(identity.KindSerialNumber, "SN-1")))
		if !errors.Is(err, identity.ErrInvalidSighting) {
			t.Errorf("Build with channel %q: err = %v, want ErrInvalidSighting", bad, err)
		}
	}
}

func TestIntake_CarriesReceiptAndCollectorVersion(t *testing.T) {
	s := measuredSighting(identity.ChannelL2Frame, sid(identity.KindMACAddress, "00:11:22:33:44:55"))
	s.ReceiptID, s.CollectorVersion = "rcpt-1", "sensor/4.4.0"
	obs := assess(t, memory.New(), s).Observation
	if obs.Admission.ReceiptID != "rcpt-1" || obs.Admission.CollectorVersion != "sensor/4.4.0" {
		t.Errorf("admission = %+v", obs.Admission)
	}
}

// ── one snapshot per call ──────────────────────────────────────────────────

type countingSegments struct {
	*memory.Repository
	snapshots, lookups atomic.Int32
}

func (c *countingSegments) SegmentSnapshot(ctx context.Context, tenantID string) (identity.SegmentSnapshot, error) {
	c.snapshots.Add(1)
	return c.Repository.SegmentSnapshot(ctx, tenantID)
}

func (c *countingSegments) ScopeForAddress(ctx context.Context, tenantID string, addr netip.Addr, ref string) (string, bool, error) {
	c.lookups.Add(1)
	return c.Repository.ScopeForAddress(ctx, tenantID, addr, ref)
}

func TestIntake_LoadsOneSnapshotPerCall(t *testing.T) {
	r := &countingSegments{Repository: memory.New()}
	if err := r.AddSegment(intakeTenant, "192.0.2.0/24", "seg-a", false); err != nil {
		t.Fatal(err)
	}
	s := measuredSighting(identity.ChannelL2Frame,
		sid(identity.KindIPAddress, "192.0.2.1"), sid(identity.KindIPAddress, "192.0.2.2"),
		sid(identity.KindIPAddress, "198.51.100.3"),
		identity.SightedIdentifier{Kind: identity.KindHostname, Value: "alpha", Address: "198.51.100.3"},
		sid(identity.KindHostname, "beta"))
	assess(t, r, s)
	if got := r.snapshots.Load(); got != 1 {
		t.Errorf("SegmentSnapshot called %d times for one sighting, want 1", got)
	}
	if got := r.lookups.Load(); got != 0 {
		t.Errorf("ScopeForAddress called %d times; Intake must scope against the snapshot it loaded", got)
	}
}

// AssessWithSnapshot reads nothing: a caller assessing a batch reads the
// snapshot once (Intake.Snapshot) and every sighting in it is scoped against
// that one read ( F4) — with the same answer Assess gives.
func TestIntake_AssessWithSnapshotReadsNothingAndAgreesWithAssess(t *testing.T) {
	r := &countingSegments{Repository: memory.New()}
	must(t, r.AddSegment(intakeTenant, "192.0.2.0/24", "seg-a", true))
	in := newIntake(t, r)
	ctx := context.Background()
	snap, err := in.Snapshot(ctx, intakeTenant)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		s := measuredSighting(identity.ChannelL2Frame,
			sid(identity.KindIPAddress, fmt.Sprintf("192.0.2.%d", i+1)),
			sid(identity.KindIPAddress, "198.51.100.3"))
		got, err := in.AssessWithSnapshot(ctx, s, snap)
		if err != nil {
			t.Fatalf("AssessWithSnapshot: %v", err)
		}
		if i == 0 {
			want := assess(t, r.Repository, s)
			if !reflect.DeepEqual(got.Observation, want.Observation) {
				t.Fatalf("AssessWithSnapshot and Assess disagree:\n got %+v\nwant %+v", got.Observation, want.Observation)
			}
		}
	}
	if n := r.snapshots.Load(); n != 1 {
		t.Errorf("SegmentSnapshot read %d times for 50 sightings over one snapshot, want 1", n)
	}
}

func TestIntake_AssessWithSnapshotRefusesAnotherTenantsSnapshot(t *testing.T) {
	in := newIntake(t, memory.New())
	_, err := in.AssessWithSnapshot(context.Background(),
		measuredSighting(identity.ChannelL2Frame, sid(identity.KindIPAddress, "192.0.2.1")),
		identity.SegmentSnapshot{TenantID: "another-tenant"})
	if !errors.Is(err, identity.ErrInvalidSighting) {
		t.Fatalf("err = %v, want ErrInvalidSighting for a snapshot of another tenant", err)
	}
	// Validation still runs first: an invalid sighting is invalid whatever
	// snapshot comes with it.
	bad := measuredSighting("not-a-channel", sid(identity.KindIPAddress, "192.0.2.1"))
	if _, err := in.AssessWithSnapshot(context.Background(), bad, identity.SegmentSnapshot{TenantID: intakeTenant}); !errors.Is(err, identity.ErrInvalidSighting) {
		t.Fatalf("err = %v, want ErrInvalidSighting for an unknown channel", err)
	}
}

func TestIntake_SnapshotErrorFailsTheBuild(t *testing.T) {
	boom := errors.New("segments unavailable")
	r := &failingSnapshot{Repository: memory.New(), err: boom}
	_, err := newIntake(t, r).Build(context.Background(),
		measuredSighting(identity.ChannelL2Frame, sid(identity.KindIPAddress, "192.0.2.1")))
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want the snapshot's error: degrading silently to the tenant default is the adapter's call, not Intake's", err)
	}
}

type failingSnapshot struct {
	*memory.Repository
	err error
}

func (f *failingSnapshot) SegmentSnapshot(context.Context, string) (identity.SegmentSnapshot, error) {
	return identity.SegmentSnapshot{}, f.err
}

// ── scope rules ────────────────────────────────────────────────────────────

func TestIntake_ScopesEachAddressSeparately(t *testing.T) {
	r := memory.New()
	must(t, r.AddSegment(intakeTenant, "10.98.0.0/24", "seg-wan", false))
	must(t, r.AddSegment(intakeTenant, "10.99.0.0/24", "seg-lan", true))
	must(t, r.AddCloudSegment(intakeTenant, "10.0.1.0/24", "seg-vpc-a", false, "vpc-a"))
	must(t, r.AddCloudSegment(intakeTenant, "10.0.1.0/24", "seg-vpc-b", false, "vpc-b"))

	// The gateway: WAN 10.98.0.2 and LAN 10.99.0.1 on one device.
	obs := assess(t, r, measuredSighting(identity.ChannelAuthenticatedSession,
		sid(identity.KindIPAddress, "10.98.0.2"), sid(identity.KindIPAddress, "10.99.0.1"))).Observation
	if got := mustID(t, obs, identity.KindIPAddress, "10.98.0.2").Scope; got != "seg-wan" {
		t.Errorf("WAN scoped %q", got)
	}
	if got := mustID(t, obs, identity.KindIPAddress, "10.99.0.1").Scope; got != "seg-lan" {
		t.Errorf("LAN scoped %q", got)
	}
	if obs.Network.SegmentID != "seg-wan" {
		t.Errorf("Network.SegmentID = %q, want the first resolved address's segment", obs.Network.SegmentID)
	}

	// A cloud sighting names its network; without one, two VPCs' identical
	// CIDRs are a question nobody answered and the address falls to the
	// tenant default.
	s := measuredSighting(identity.ChannelAPI, sid(identity.KindIPAddress, "10.0.1.20"))
	s.CloudNetworkRef = "vpc-b"
	if got := mustID(t, assess(t, r, s).Observation, identity.KindIPAddress, "10.0.1.20").Scope; got != "seg-vpc-b" {
		t.Errorf("with vpc-b ref scoped %q", got)
	}
	s.CloudNetworkRef = ""
	if got := mustID(t, assess(t, r, s).Observation, identity.KindIPAddress, "10.0.1.20").Scope; got != identity.ScopeTenantDefault {
		t.Errorf("ambiguous without a ref scoped %q, want the tenant default", got)
	}
}

func TestIntake_NameScopeRule(t *testing.T) {
	r := memory.New()
	must(t, r.AddSegment(intakeTenant, "192.0.2.0/24", "seg-a", false))
	must(t, r.AddSegment(intakeTenant, "198.51.100.0/24", "seg-b", false))
	must(t, r.AddDomainSegment(intakeTenant, "lab.local", "seg-domain"))

	obs := assess(t, r, measuredSighting(identity.ChannelL2Frame,
		sid(identity.KindIPAddress, "203.0.113.9"), // in no segment: not primary
		sid(identity.KindIPAddress, "192.0.2.10"),  // primary
		// 1. its own address, in a real segment
		identity.SightedIdentifier{Kind: identity.KindHostname, Value: "own-addr", Address: "198.51.100.4"},
		// 2. no address of its own → the sighting's primary segment
		sid(identity.KindHostname, "no-addr"),
		// 3. its own address is in no segment → the domain rule
		identity.SightedIdentifier{Kind: identity.KindHostname, Value: "nas.lab.local", Address: "203.0.113.9"},
		// 4. its own address in no segment, no domain match → tenant default
		identity.SightedIdentifier{Kind: identity.KindHostname, Value: "orphan", Address: "203.0.113.9"},
	)).Observation
	for name, want := range map[string]string{
		"own-addr":      "seg-b",
		"no-addr":       "seg-a",
		"nas.lab.local": "seg-domain",
		"orphan":        identity.ScopeTenantDefault,
	} {
		if got := mustID(t, obs, identity.KindHostname, name).Scope; got != want {
			t.Errorf("%s scoped %q, want %q", name, got, want)
		}
	}

	// A sighting with no address at all: the domain rule places the name, and
	// the observation's own segment is that domain segment.
	obs = assess(t, r, measuredSighting(identity.ChannelAdvertisement,
		sid(identity.KindHostname, "tv.lab.local"))).Observation
	if got := mustID(t, obs, identity.KindHostname, "tv.lab.local").Scope; got != "seg-domain" {
		t.Errorf("address-less name scoped %q", got)
	}
	if obs.Network.SegmentID != "seg-domain" {
		t.Errorf("Network.SegmentID = %q", obs.Network.SegmentID)
	}

	// An fqdn-only sighting: the fqdn stays unscoped (it identifies on its
	// own), but the domain segment still places the SIGHTING — domain
	// patterns are dotted, so the names they match are fqdns.
	must(t, r.AddDomainSegment(intakeTenant, "corp.example.test", "seg-corp"))
	obs = assess(t, r, measuredSighting(identity.ChannelL3Traffic,
		sid(identity.KindFQDN, "shadow-store.corp.example.test"))).Observation
	if id := mustID(t, obs, identity.KindFQDN, "shadow-store.corp.example.test"); id.Scope != "" {
		t.Errorf("fqdn carries scope %q", id.Scope)
	}
	if obs.Network.SegmentID != "seg-corp" {
		t.Errorf("fqdn-only sighting placed in %q, want its domain segment", obs.Network.SegmentID)
	}
	// An address in a real segment still outranks the domain pattern.
	obs = assess(t, r, measuredSighting(identity.ChannelL3Traffic,
		sid(identity.KindFQDN, "db.corp.example.test"), sid(identity.KindIPAddress, "192.0.2.77"))).Observation
	if obs.Network.SegmentID != "seg-a" {
		t.Errorf("fqdn + addressed sighting placed in %q, want the address's segment", obs.Network.SegmentID)
	}
}

func TestIntake_NameFiling(t *testing.T) {
	r := memory.New()
	obs := assess(t, r, measuredSighting(identity.ChannelAdvertisement,
		sid(identity.KindHostname, "web01.corp.example"), // dotted → fqdn
		sid(identity.KindFQDN, "Laptop.local."),          // .local → scoped hostname
		sid(identity.KindFQDN, "short"),                  // single label → hostname
	)).Observation
	if id := mustID(t, obs, identity.KindFQDN, "web01.corp.example"); id.Scope != "" {
		t.Errorf("fqdn carries scope %q", id.Scope)
	}
	if _, ok := findID(obs, identity.KindFQDN, "laptop.local"); ok {
		t.Error("`.local` filed as an unscoped fqdn: the mDNS reflector merge")
	}
	if id := mustID(t, obs, identity.KindHostname, "laptop.local"); id.Scope != identity.ScopeTenantDefault {
		t.Errorf(".local scoped %q", id.Scope)
	}
	mustID(t, obs, identity.KindHostname, "short")
}

// ── dynamic scopes ─────────────────────────────────────────────────────────

func TestIntake_DynamicScopesFromStoredPostureOnly(t *testing.T) {
	r := memory.New()
	must(t, r.AddSegment(intakeTenant, "10.99.0.0/24", "seg-lan", false))
	yes, no := true, false
	must(t, r.StateSegmentPosture(intakeTenant, "seg-lan", "operator", nil))
	must(t, r.StateSegmentPosture(intakeTenant, "seg-lan", "measured", &yes))

	s := measuredSighting(identity.ChannelControllerInventory, sid(identity.KindIPAddress, "10.99.0.1"))
	if obs := assess(t, r, s).Observation; !obs.DynamicScopes["seg-lan"] {
		t.Fatalf("measured=dynamic with nothing above it: DynamicScopes = %v", obs.DynamicScopes)
	}

	// The operator marks the segment static. The precedence rule stored that
	// as the effective value, and Intake reads it — even on a sighting from
	// the very controller whose measurement says DHCP ( item 7).
	//
	// Mutation check: rank `measured` above `operator` in the memory store's
	// postureRank and this fails.
	must(t, r.StateSegmentPosture(intakeTenant, "seg-lan", "operator", &no))
	if obs := assess(t, r, s).Observation; obs.DynamicScopes["seg-lan"] {
		t.Fatalf("operator=static must outrank measured=dynamic: DynamicScopes = %v", obs.DynamicScopes)
	}
}

func TestIntake_DynamicScopesNameEveryDynamicScopeAndNoOther(t *testing.T) {
	r := memory.New()
	must(t, r.AddSegment(intakeTenant, "192.0.2.0/24", "seg-dyn", true))
	must(t, r.AddSegment(intakeTenant, "198.51.100.0/24", "seg-static", false))
	obs := assess(t, r, measuredSighting(identity.ChannelL2Frame,
		sid(identity.KindIPAddress, "198.51.100.5"),
		identity.SightedIdentifier{Kind: identity.KindHostname, Value: "kiosk", Address: "192.0.2.5"},
	)).Observation
	// The hostname alone sits in the dynamic segment: the scope is still named
	// dynamic, as host-observation ingest has always done for its name scope.
	if !obs.DynamicScopes["seg-dyn"] || obs.DynamicScopes["seg-static"] || len(obs.DynamicScopes) != 1 {
		t.Errorf("DynamicScopes = %v, want exactly {seg-dyn}", obs.DynamicScopes)
	}
	// The tenant default is never dynamic.
	obs = assess(t, r, measuredSighting(identity.ChannelL2Frame, sid(identity.KindIPAddress, "203.0.113.1"))).Observation
	if len(obs.DynamicScopes) != 0 {
		t.Errorf("tenant default named dynamic: %v", obs.DynamicScopes)
	}
}

// ── hygiene ────────────────────────────────────────────────────────────────

func TestIntake_GenericNamesMarkedOnlyWhenMeasured(t *testing.T) {
	r := memory.New()
	obs := assess(t, r, measuredSighting(identity.ChannelAdvertisement, sid(identity.KindHostname, "iPhone"))).Observation
	if id := mustID(t, obs, identity.KindHostname, "iphone"); !id.Generic || id.Confidence > identity.GenericConfidence {
		t.Errorf("measured `iphone` = %+v, want generic at confidence <= %v", id, identity.GenericConfidence)
	}

	s := measuredSighting(identity.ChannelPerson, sid(identity.KindHostname, "printer"))
	s.Source = identity.Source{Kind: identity.SourceDeclared, Ref: "manual"}
	if id := mustID(t, assess(t, r, s).Observation, identity.KindHostname, "printer"); id.Generic {
		t.Error("a declared `printer` was marked generic; a person's statement is not a default")
	}
}

func TestIntake_SyntheticNamesWithheldAsAttributeEvidence(t *testing.T) {
	r := memory.New()
	res := assess(t, r, measuredSighting(identity.ChannelAdvertisement,
		sid(identity.KindFQDN, "3f2a9c1e-1b2c-4d5e-8f90-0123456789ab.local"),
		sid(identity.KindHostname, "none-2"),
		sid(identity.KindHostname, "living-room-tv"),
	))
	if _, ok := findID(res.Observation, identity.KindHostname, "none-2"); ok {
		t.Error("`none-2` became an identifier")
	}
	got := res.AttributeEvidence[attrlist.KeySyntheticNames]
	if len(got) != 2 {
		t.Errorf("synthetic_names evidence = %v, want both synthetic names", got)
	}
	mustID(t, res.Observation, identity.KindHostname, "living-room-tv")

	// Declared: the same `none-2` is a person's choice, not a placeholder.
	s := measuredSighting(identity.ChannelPerson, sid(identity.KindHostname, "none-2"))
	s.Source = identity.Source{Kind: identity.SourceDeclared, Ref: "manual"}
	mustID(t, assess(t, r, s).Observation, identity.KindHostname, "none-2")
}

func TestIntake_MACHygiene(t *testing.T) {
	r := memory.New()
	const laMAC = "7a:1b:2c:3d:4e:5f"   // U/L bit set: a randomised Wi-Fi address
	const vrrpMAC = "00:00:5e:00:01:0a" // VRRP vhid 10
	for _, tc := range []struct {
		ch           identity.Channel
		keepLA, keep bool
	}{
		{identity.ChannelL2Frame, false, false},
		{identity.ChannelControllerInventory, false, false},
		{identity.ChannelAuthenticatedSession, true, false},
		{identity.ChannelAPI, true, false},
		{identity.ChannelPerson, true, true},
	} {
		res := assess(t, r, measuredSighting(tc.ch,
			sid(identity.KindMACAddress, laMAC), sid(identity.KindMACAddress, vrrpMAC),
			sid(identity.KindSerialNumber, "SN-HYG")))
		if _, ok := findID(res.Observation, identity.KindMACAddress, laMAC); ok != tc.keepLA {
			t.Errorf("%s: locally administered MAC kept=%t, want %t", tc.ch, ok, tc.keepLA)
		}
		if _, ok := findID(res.Observation, identity.KindMACAddress, vrrpMAC); ok != tc.keep {
			t.Errorf("%s: VRRP MAC kept=%t, want %t", tc.ch, ok, tc.keep)
		}
	}
	// Withheld values are reported with their reason.
	res := assess(t, r, measuredSighting(identity.ChannelL2Frame,
		sid(identity.KindMACAddress, laMAC), sid(identity.KindMACAddress, vrrpMAC), sid(identity.KindSerialNumber, "SN-HYG")))
	var reasons []string
	for _, w := range res.Withheld {
		reasons = append(reasons, w.Reason)
	}
	slices.Sort(reasons)
	if !slices.Equal(reasons, []string{identity.WithheldLocallyAdministeredMAC, identity.WithheldVirtualRouterMAC}) {
		t.Errorf("withheld reasons = %v", reasons)
	}
}

func TestIntake_DerivedMACs(t *testing.T) {
	r := memory.New()
	eui := netip.MustParseAddr("2001:db8::211:22ff:fe33:4455")
	obs := assess(t, r, measuredSighting(identity.ChannelL2Frame,
		sid(identity.KindIPAddress, eui.String()), sid(identity.KindSerialNumber, "00000C1A2B3C"))).Observation
	fromEUI := mustID(t, obs, identity.KindMACAddress, "00:11:22:33:44:55")
	if !fromEUI.Inferred() || fromEUI.Source.Ref != derive.RefEUI64(eui) || fromEUI.Confidence != 0.9 {
		t.Errorf("EUI-64 MAC = %+v, want inferred, ref %s, confidence 0.9", fromEUI, derive.RefEUI64(eui))
	}
	fromSerial := mustID(t, obs, identity.KindMACAddress, "00:00:0c:1a:2b:3c")
	if !fromSerial.Inferred() || fromSerial.Source.Ref != derive.RefSerial("00000C1A2B3C") {
		t.Errorf("serial MAC = %+v", fromSerial)
	}

	// A stated MAC — even one hygiene then withholds — is better evidence than
	// any derived one, so nothing is derived.
	obs = assess(t, r, measuredSighting(identity.ChannelL2Frame,
		sid(identity.KindMACAddress, "7a:1b:2c:3d:4e:5f"),
		sid(identity.KindIPAddress, eui.String()), sid(identity.KindSerialNumber, "00000C1A2B3C"))).Observation
	for _, id := range obs.Identifiers {
		if id.Kind == identity.KindMACAddress {
			t.Errorf("derived %s although the sighting stated a MAC", id.Value)
		}
	}
}

func TestIntake_IPv6Hygiene(t *testing.T) {
	r := memory.New()
	const temp = "2001:db8::1a2b:3c4d:5e6f:7a8b"
	const ll = "fe80::1a2b:3c4d:5e6f:7a8b"

	// No real segment: the link-local address has nowhere to be unique.
	res := assess(t, r, measuredSighting(identity.ChannelL2Frame,
		sid(identity.KindIPAddress, temp), sid(identity.KindIPAddress, ll), sid(identity.KindMACAddress, "00:11:22:33:44:55")))
	if _, ok := findID(res.Observation, identity.KindIPAddress, temp); ok {
		t.Error("a temporary IPv6 address became an identifier")
	}
	if _, ok := findID(res.Observation, identity.KindIPAddress, ll); ok {
		t.Error("an unscoped link-local address became an identifier")
	}
	if got := res.AttributeEvidence[attrlist.KeyIPv6Temporary]; !slices.Equal(got, []string{temp}) {
		t.Errorf("ipv6_temporary_addresses = %v", got)
	}
	if got := res.AttributeEvidence[attrlist.KeyLinkLocal]; !slices.Equal(got, []string{ll}) {
		t.Errorf("link_local_addresses = %v", got)
	}

	// With a real segment in the sighting, the link-local address identifies
	// within it.
	must(t, r.AddSegment(intakeTenant, "192.0.2.0/24", "seg-a", false))
	res = assess(t, r, measuredSighting(identity.ChannelL2Frame,
		sid(identity.KindIPAddress, ll+"%eth0"), sid(identity.KindIPAddress, "192.0.2.8")))
	if got := mustID(t, res.Observation, identity.KindIPAddress, ll).Scope; got != "seg-a" {
		t.Errorf("link-local scoped %q, want the sighting's segment", got)
	}
}

func TestIntake_RejectsWhatDoesNotNormalise(t *testing.T) {
	res := assess(t, memory.New(), measuredSighting(identity.ChannelL2Frame,
		sid(identity.KindHostname, "192.0.2.4"), // an IP is never a name
		sid(identity.KindMACAddress, "00:11:22"),
		identity.SightedIdentifier{Kind: identity.KindSerialNumber, Value: "SN-9", Profile: "p1"},
		sid(identity.KindMACAddress, "00:11:22:33:44:55")))
	if len(res.Rejected) != 3 {
		t.Errorf("rejected %d, want 3: %+v", len(res.Rejected), res.Rejected)
	}
	if len(res.Observation.Identifiers) != 1 {
		t.Errorf("identifiers = %+v, want only the MAC", res.Observation.Identifiers)
	}
}

func TestIntake_ScopesNameByClassAndCMDBByProfile(t *testing.T) {
	s := measuredSighting(identity.ChannelAPI,
		sid(identity.KindName, "Payments  API"),
		identity.SightedIdentifier{Kind: identity.KindCMDBSysID, Value: "abc123", Profile: "servicenow-prod"})
	s.ClassHint = "business_service"
	obs := assess(t, memory.New(), s).Observation
	if got := mustID(t, obs, identity.KindName, "payments api").Scope; got != "business_service" {
		t.Errorf("name scoped %q", got)
	}
	if got := mustID(t, obs, identity.KindCMDBSysID, "abc123").Scope; got != "servicenow-prod" {
		t.Errorf("cmdb_sys_id scoped %q", got)
	}
}

// ── Decision 1 marker ──────────────────────────────────────────────────────

func TestIntake_PinnedAddresses(t *testing.T) {
	r := memory.New()
	obs := assess(t, r, measuredSighting(identity.ChannelAuthenticatedSession,
		identity.SightedIdentifier{Kind: identity.KindIPAddress, Value: "192.0.2.1",
			Provenance: identity.IdentifierProvenance{SelfReported: true}},
		identity.SightedIdentifier{Kind: identity.KindIPAddress, Value: "192.0.2.2",
			Provenance: identity.IdentifierProvenance{Kind: identity.SourceDeclared}},
		sid(identity.KindIPAddress, "192.0.2.3"),
		identity.SightedIdentifier{Kind: identity.KindHostname, Value: "gw",
			Provenance: identity.IdentifierProvenance{SelfReported: true}},
	)).Observation
	for v, want := range map[string]bool{"192.0.2.1": true, "192.0.2.2": true, "192.0.2.3": false} {
		if got := mustID(t, obs, identity.KindIPAddress, v).Pinned; got != want {
			t.Errorf("%s pinned=%t, want %t", v, got, want)
		}
	}
	if mustID(t, obs, identity.KindHostname, "gw").Pinned {
		t.Error("a hostname was pinned; the marker is for addresses only")
	}
	// A declared sighting declares every address it carries.
	s := measuredSighting(identity.ChannelPerson, sid(identity.KindIPAddress, "192.0.2.9"))
	s.Source = identity.Source{Kind: identity.SourceDeclared, Ref: "manual"}
	if !mustID(t, assess(t, r, s).Observation, identity.KindIPAddress, "192.0.2.9").Pinned {
		t.Error("an operator-declared address was not pinned")
	}
	// The marker is not identity: it does not split the key.
	a := identity.Identifier{Kind: identity.KindIPAddress, Value: "192.0.2.1", Scope: "s", Pinned: true}
	b := a
	b.Pinned = false
	if a.Key() != b.Key() {
		t.Error("Pinned changed Identifier.Key")
	}
}

// ── the prior-scope bridge ─────────────────────────────────────────────────

// TestIntake_BridgePriorScope pins Sighting.BridgePriorScope both ways: the
// tenant-default copy of a segment-scoped address is carried only when that
// copy already has an owner, and only when the sighting asks — and the bridged
// observation then MATCHES the asset the pre-segment sighting created instead
// of creating a second one.
func TestIntake_BridgePriorScope(t *testing.T) {
	ctx := context.Background()
	r := memory.New()
	engine, err := identity.New(identity.Config{Repo: r})
	if err != nil {
		t.Fatal(err)
	}
	s := measuredSighting(identity.ChannelL3Probe, sid(identity.KindIPAddress, "10.77.0.15"))
	s.BridgePriorScope = true

	// Before the network is registered: the address is tenant-scoped and the
	// bridge has nothing to add.
	before := assess(t, r, s).Observation
	if len(before.Identifiers) != 1 || before.Identifiers[0].Scope != identity.ScopeTenantDefault {
		t.Fatalf("pre-registration identifiers %+v, want one tenant-default address", before.Identifiers)
	}
	first, err := engine.Resolve(ctx, before)
	if err != nil || first.Outcome != identity.OutcomeCreated {
		t.Fatalf("first sighting = %+v, %v; want created", first, err)
	}

	must(t, r.AddSegment(intakeTenant, "10.77.0.0/24", "seg-new", false))

	// Without the flag the address is re-keyed and nothing bridges it.
	plain := s
	plain.BridgePriorScope = false
	if obs := assess(t, r, plain).Observation; len(obs.Identifiers) != 1 || obs.Identifiers[0].Scope != "seg-new" {
		t.Fatalf("unbridged identifiers %+v, want only the segment-scoped address", obs.Identifiers)
	}

	// With it, the owned tenant-default copy rides along…
	after := assess(t, r, s).Observation
	mustID(t, after, identity.KindIPAddress, "10.77.0.15")
	var scopes []string
	for _, id := range after.Identifiers {
		scopes = append(scopes, id.Scope)
	}
	slices.Sort(scopes)
	if !slices.Equal(scopes, []string{"seg-new", identity.ScopeTenantDefault}) {
		t.Fatalf("bridged scopes %v, want the segment and the tenant default", scopes)
	}
	// …and the engine matches the first asset rather than duplicating it.
	second, err := engine.Resolve(ctx, after)
	if err != nil {
		t.Fatal(err)
	}
	if second.Asset != first.Asset || second.Outcome != identity.OutcomeMatched {
		t.Fatalf("bridged sighting = %s on %v, want matched on %v", second.Outcome, second.Asset, first.Asset)
	}

	// An unowned tenant-default copy is never invented.
	fresh := measuredSighting(identity.ChannelL3Probe, sid(identity.KindIPAddress, "10.77.0.99"))
	fresh.BridgePriorScope = true
	if obs := assess(t, r, fresh).Observation; len(obs.Identifiers) != 1 || obs.Identifiers[0].Scope != "seg-new" {
		t.Fatalf("a never-seen address bridged to %+v; the copy is added only when it has an owner", obs.Identifiers)
	}
}

// TestIntake_AddressAssignment: the host's own answer about how it holds an
// address reaches the identifier, and a lease is never pinned — not by
// SelfReported, not by a declaration (host inventory through Intake).
func TestIntake_AddressAssignment(t *testing.T) {
	r := memory.New()
	self := identity.IdentifierProvenance{SelfReported: true}
	obs := assess(t, r, measuredSighting(identity.ChannelAuthenticatedSession,
		identity.SightedIdentifier{Kind: identity.KindIPAddress, Value: "192.0.2.1", Provenance: self, Assignment: identity.AssignmentStatic},
		identity.SightedIdentifier{Kind: identity.KindIPAddress, Value: "192.0.2.2", Provenance: self, Assignment: identity.AssignmentDynamic},
		identity.SightedIdentifier{Kind: identity.KindIPAddress, Value: "192.0.2.3", Assignment: identity.AssignmentStatic},
		identity.SightedIdentifier{Kind: identity.KindIPAddress, Value: "192.0.2.4", Provenance: identity.IdentifierProvenance{Kind: identity.SourceDeclared}, Assignment: identity.AssignmentDynamic},
	)).Observation
	for v, want := range map[string]struct {
		pinned bool
		a      identity.AddressAssignment
	}{
		"192.0.2.1": {true, identity.AssignmentStatic},
		"192.0.2.2": {false, identity.AssignmentDynamic},
		"192.0.2.3": {true, identity.AssignmentStatic},
		"192.0.2.4": {false, identity.AssignmentDynamic},
	} {
		id := mustID(t, obs, identity.KindIPAddress, v)
		if id.Pinned != want.pinned || id.Assignment != want.a {
			t.Errorf("%s pinned=%t assignment=%q, want %t %q", v, id.Pinned, id.Assignment, want.pinned, want.a)
		}
		if got := id.StoredAssignment(); got != want.a {
			t.Errorf("%s stores %q, want %q", v, got, want.a)
		}
	}
	for _, bad := range []identity.SightedIdentifier{
		{Kind: identity.KindIPAddress, Value: "192.0.2.5", Assignment: "leased"},
		{Kind: identity.KindHostname, Value: "gw", Assignment: identity.AssignmentStatic},
	} {
		if _, err := newIntake(t, r).Assess(context.Background(), measuredSighting(identity.ChannelAuthenticatedSession, bad)); !errors.Is(err, identity.ErrInvalidSighting) {
			t.Errorf("%+v: err=%v, want ErrInvalidSighting", bad, err)
		}
	}
}

// TestIntake_SSHKeyAlgorithm: the collector's key type reaches the
// identifier, normalised, so the drift classifier can compare keys.
func TestIntake_SSHKeyAlgorithm(t *testing.T) {
	obs := assess(t, memory.New(), measuredSighting(identity.ChannelAuthenticatedSession,
		identity.SightedIdentifier{Kind: identity.KindSSHHostKeyFingerprint, Value: "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG", KeyAlgorithm: "ssh-ed25519"})).Observation
	if len(obs.Identifiers) != 1 || obs.Identifiers[0].KeyAlgorithm != identity.NormalizeSSHKeyAlgorithm("ssh-ed25519") || obs.Identifiers[0].KeyAlgorithm == "" {
		t.Fatalf("identifiers %+v", obs.Identifiers)
	}
}

// TestIntake_LowerIdentifierProvenance: on a declared sighting, a value the
// probe read is stored measured; one the person typed stays declared; the
// same value both typed and read keeps the stronger claim. Never raised.
func TestIntake_LowerIdentifierProvenance(t *testing.T) {
	s := measuredSighting(identity.ChannelAuthenticatedSession,
		sid(identity.KindIPAddress, "192.0.2.10"),
		identity.SightedIdentifier{Kind: identity.KindMACAddress, Value: "00:00:5e:00:53:01", Provenance: identity.IdentifierProvenance{Kind: identity.SourceMeasured}},
		identity.SightedIdentifier{Kind: identity.KindSerialNumber, Value: "S-1", Provenance: identity.IdentifierProvenance{Kind: identity.SourceMeasured}},
		sid(identity.KindSerialNumber, "S-1"),
	)
	s.Source = identity.Source{Kind: identity.SourceDeclared, Ref: "manual"}
	obs := assess(t, memory.New(), s).Observation
	if k := mustID(t, obs, identity.KindMACAddress, "00:00:5e:00:53:01").Source.Kind; k != identity.SourceMeasured {
		t.Errorf("probe MAC stored %q, want measured", k)
	}
	if k := mustID(t, obs, identity.KindIPAddress, "192.0.2.10").Source.Kind; k == identity.SourceMeasured {
		t.Error("a typed address lost its declared provenance")
	}
	if k := mustID(t, obs, identity.KindSerialNumber, "S-1").Source.Kind; k == identity.SourceMeasured {
		t.Error("a serial both typed and read kept the weaker claim")
	}
	m := measuredSighting(identity.ChannelL2Frame, identity.SightedIdentifier{Kind: identity.KindMACAddress, Value: "00:00:5e:00:53:02", Provenance: identity.IdentifierProvenance{Kind: identity.SourceDeclared}})
	if k := assess(t, memory.New(), m).Observation.Identifiers[0].Source.Kind; k == identity.SourceDeclared {
		t.Error("a measured sighting raised an identifier to declared")
	}
}

// ── validation ─────────────────────────────────────────────────────────────

func TestIntake_InvalidSightings(t *testing.T) {
	in := newIntake(t, memory.New())
	ctx := context.Background()
	ok := measuredSighting(identity.ChannelL2Frame, sid(identity.KindMACAddress, "00:11:22:33:44:55"))

	noTenant := ok
	noTenant.TenantID = " "
	noSource := ok
	noSource.Source = identity.Source{Kind: identity.SourceMeasured}
	decl := ok
	decl.Identifiers = []identity.SightedIdentifier{sid(identity.KindDeclarationID, "d-1")}
	badProv := ok
	badProv.Identifiers = []identity.SightedIdentifier{{Kind: identity.KindSerialNumber, Value: "x",
		Provenance: identity.IdentifierProvenance{Kind: "guessed"}}}
	for name, s := range map[string]identity.Sighting{
		"no tenant": noTenant, "no source ref": noSource, "declaration id": decl, "bad provenance": badProv,
	} {
		if _, err := in.Build(ctx, s); !errors.Is(err, identity.ErrInvalidSighting) {
			t.Errorf("%s: err = %v, want ErrInvalidSighting", name, err)
		}
	}

	// Everything withheld: no usable identifier, but the result still says why.
	only := measuredSighting(identity.ChannelL2Frame, sid(identity.KindMACAddress, "7a:1b:2c:3d:4e:5f"))
	res, err := in.Assess(ctx, only)
	if !errors.Is(err, identity.ErrNoUsableIdentifier) {
		t.Fatalf("err = %v, want ErrNoUsableIdentifier", err)
	}
	if len(res.Withheld) != 1 {
		t.Errorf("withheld = %+v", res.Withheld)
	}
}

// ── the output is what the engine already takes ────────────────────────────

func TestIntake_OutputResolvesThroughTheEngine(t *testing.T) {
	r := memory.New()
	must(t, r.AddSegment(intakeTenant, "192.0.2.0/24", "seg-a", false))
	engine, err := identity.New(identity.Config{Repo: r})
	if err != nil {
		t.Fatal(err)
	}
	s := measuredSighting(identity.ChannelL2Frame,
		sid(identity.KindMACAddress, "00:11:22:33:44:55"), sid(identity.KindIPAddress, "192.0.2.50"),
		sid(identity.KindHostname, "db01"))
	obs := assess(t, r, s).Observation
	first, err := engine.Resolve(context.Background(), obs)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	second, err := engine.Resolve(context.Background(), assess(t, r, s).Observation)
	if err != nil {
		t.Fatalf("Resolve again: %v", err)
	}
	if first.Asset.Zero() || second.Asset != first.Asset {
		t.Errorf("the same sighting twice resolved to %v then %v; Intake output must be stable", first.Asset, second.Asset)
	}
}

// ── Diff ───────────────────────────────────────────────────────────────────

func TestDiff_IdenticalAndEquivalentObservationsAgree(t *testing.T) {
	a := identity.Observation{
		Network:       identity.Network{SegmentID: "seg-a"},
		DynamicScopes: map[string]bool{"seg-a": true, "seg-x": false},
		Admission:     identity.AdmissionEvidence{Direct: true, ReceiptID: "r1"},
		Identifiers: []identity.Identifier{
			{Kind: identity.KindMACAddress, Value: "AA-BB-CC-00-11-22"},
			{Kind: identity.KindIPAddress, Value: "192.0.2.1", Scope: "seg-a"},
		},
		Endpoints: []identity.EndpointObservation{{Address: "192.0.2.1", Port: 443, Transport: "tcp"}},
	}
	b := a
	b.DynamicScopes = map[string]bool{"seg-a": true}
	b.Admission.ReceiptID = "r2" // provenance of the delivery, not admission
	b.Identifiers = []identity.Identifier{
		{Kind: identity.KindIPAddress, Value: "192.0.2.1", Scope: "seg-a"},
		{Kind: identity.KindMACAddress, Value: "aa:bb:cc:00:11:22"},
	}
	b.Endpoints = []identity.EndpointObservation{{Address: "192.0.2.1", FQDN: "192.0.2.1", Port: 443, Transport: "TCP"}}
	if d := identity.Diff(a, b); len(d) != 0 {
		t.Errorf("Diff of equivalent observations = %q", d)
	}
}

func TestDiff_ReportsEveryDecisionRelevantDifference(t *testing.T) {
	a := identity.Observation{
		Network:       identity.Network{SegmentID: "seg-a"},
		DynamicScopes: map[string]bool{"seg-a": true},
		Admission:     identity.AdmissionEvidence{Direct: true},
		Identifiers: []identity.Identifier{
			{Kind: identity.KindIPAddress, Value: "192.0.2.1", Scope: "seg-a"},
			{Kind: identity.KindHostname, Value: "iphone", Scope: "seg-a", Generic: true},
			{Kind: identity.KindMACAddress, Value: "00:11:22:33:44:55"},
		},
		Endpoints: []identity.EndpointObservation{{Address: "192.0.2.1", Port: 443, Transport: "tcp"}},
	}
	b := identity.Observation{
		Network:       identity.Network{SegmentID: identity.ScopeTenantDefault},
		DynamicScopes: map[string]bool{"seg-b": true},
		Admission:     identity.AdmissionEvidence{Authoritative: true, Relayed: true},
		Identifiers: []identity.Identifier{
			{Kind: identity.KindIPAddress, Value: "192.0.2.1", Scope: identity.ScopeTenantDefault, Pinned: true},
			{Kind: identity.KindHostname, Value: "iphone", Scope: "seg-a"},
			{Kind: identity.KindMACAddress, Value: "00:11:22:33:44:55",
				Source: identity.Source{Kind: identity.SourceInferred, Ref: "derived:eui64:x"}},
		},
		Endpoints: []identity.EndpointObservation{{Address: "192.0.2.1", Port: 8443, Transport: "tcp"}},
	}
	got := strings.Join(identity.Diff(a, b), "\n")
	for _, want := range []string{
		`scope: a="seg-a" b="tenant"`,
		`dynamic: scope "seg-a" is dynamic in a only`,
		`dynamic: scope "seg-b" is dynamic in b only`,
		`admission: direct a=true b=false`,
		`admission: relayed a=false b=true`,
		`admission: authoritative a=false b=true`,
		`identifier: ip_address="192.0.2.1"@seg-a in a only`,
		`identifier: ip_address="192.0.2.1"@tenant in b only`,
		`identifier: hostname="iphone"@seg-a generic a=true b=false`,
		`identifier: mac_address="00:11:22:33:44:55" inferred a=false b=true`,
		`endpoint: 192.0.2.1|443|tcp in a only`,
		`endpoint: 192.0.2.1|8443|tcp in b only`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Diff is missing %q; got:\n%s", want, got)
		}
	}
}

func TestDiff_ReportsPinned(t *testing.T) {
	id := identity.Identifier{Kind: identity.KindIPAddress, Value: "192.0.2.1", Scope: "s"}
	pinned := id
	pinned.Pinned = true
	d := identity.Diff(identity.Observation{Identifiers: []identity.Identifier{id}},
		identity.Observation{Identifiers: []identity.Identifier{pinned}})
	if len(d) != 1 || !strings.Contains(d[0], "pinned a=false b=true") {
		t.Errorf("Diff = %q", d)
	}
}

// TestDiff_ShadowOfAHostObservation is what an adapter's shadow run looks
// like: the observation host-observation ingest builds today for an ARP frame
// in a dynamic segment, hand-built here exactly as that builder spells it, and
// Intake's. They agree, so Diff is empty.
func TestDiff_ShadowOfAHostObservation(t *testing.T) {
	r := memory.New()
	must(t, r.AddSegment(intakeTenant, "10.99.0.0/24", "seg-lan", true))
	adapter := identity.Observation{
		TenantID:      intakeTenant,
		Admission:     identity.AdmissionEvidence{Direct: true},
		Network:       identity.Network{SegmentID: "seg-lan"},
		DynamicScopes: map[string]bool{"seg-lan": true},
		Identifiers: []identity.Identifier{
			{Kind: identity.KindMACAddress, Value: "00:11:22:33:44:55", Confidence: 1},
			{Kind: identity.KindHostname, Value: "nas-basement", Scope: "seg-lan", Confidence: 1},
			{Kind: identity.KindIPAddress, Value: "10.99.0.20", Scope: "seg-lan", Confidence: 1},
		},
	}
	intake := assess(t, r, measuredSighting(identity.ChannelL2Frame,
		sid(identity.KindMACAddress, "00:11:22:33:44:55"), sid(identity.KindHostname, "nas-basement"),
		sid(identity.KindIPAddress, "10.99.0.20"))).Observation
	if d := identity.Diff(adapter, intake); len(d) != 0 {
		t.Errorf("shadow diff = %q", d)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// TestIntake_CarriesDriftEvidence: the two inputs the drift classifier reads
// ( Decision 4) survive the intake — the SSH key's algorithm on its
// identifier, the presented leaf certificates on the observation.
func TestIntake_CarriesDriftEvidence(t *testing.T) {
	s := measuredSighting(identity.ChannelL3Probe,
		identity.SightedIdentifier{Kind: identity.KindSSHHostKeyFingerprint, Value: "SHA256:abc", KeyAlgorithm: "ssh-ed25519"},
		sid(identity.KindIPAddress, "192.0.2.40"))
	s.TLSCertFingerprints = []string{"aa11"}
	obs := assess(t, memory.New(), s).Observation
	if got := mustID(t, obs, identity.KindSSHHostKeyFingerprint, "SHA256:abc").KeyAlgorithm; got != "ed25519" {
		t.Errorf("ssh key algorithm = %q, want ed25519", got)
	}
	if !slices.Equal(obs.TLSCertFingerprints, []string{"aa11"}) {
		t.Errorf("TLS fingerprints = %v", obs.TLSCertFingerprints)
	}
}
