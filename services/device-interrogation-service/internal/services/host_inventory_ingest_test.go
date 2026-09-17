package services

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/hostinventory"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// The pure half of the host-inventory consumer: the MAPPING from a collection
// onto the four things the phase-1 model stores. Everything that needs a
// database is in host_inventory_materialise_integration_test.go.

// ---------------------------------------------------------------------------
// endpoints
// ---------------------------------------------------------------------------

// testEndpointSource is the provenance a real run stamps on every endpoint: the
// RUN's ref, which is what the retirement sweep compares against.
var testEndpointSource = identity.Source{
	Kind: identity.SourceMeasured, Ref: "agent:test-agent:test-job", Mode: identity.ModeActive,
}

func TestHostInventoryConnections_ValidatesCoalescesAndCapsAtIntake(t *testing.T) {
	subject := di.PeerRef{Identifiers: []di.PeerIdentifier{{Kind: di.IdentifierAgentID, Value: "agent-1"}}}
	connections := make([]projectedConnection, 0, maxHostInventoryConnections+4)
	connections = append(connections,
		projectedConnection{Transport: " TCP ", LocalAddress: "::ffff:192.0.2.10", RemoteAddress: "::ffff:203.0.113.20", RemotePort: 443},
		projectedConnection{Transport: "tcp", LocalAddress: "192.0.2.10", RemoteAddress: "203.0.113.20", RemotePort: 443, Process: " browser "},
		projectedConnection{Transport: "tcp", LocalAddress: "127.0.0.1", RemoteAddress: "203.0.113.21", RemotePort: 443},
		projectedConnection{Transport: "udp", LocalAddress: "192.0.2.10", RemoteAddress: "169.254.10.1", RemotePort: 53},
	)
	for i := 1; i <= maxHostInventoryConnections+2; i++ {
		connections = append(connections, projectedConnection{
			Transport: "tcp", LocalAddress: "192.0.2.10",
			RemoteAddress: fmt.Sprintf("2400::%x", i), RemotePort: 8443,
		})
	}
	obs := &di.InterrogateResult{Facts: []di.FactObservation{{
		Key: facts.KeyNetOutboundConnections, Value: connections, Subject: subject,
	}}}

	got, err := hostInventoryConnections(obs, subject)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != maxHostInventoryConnections {
		t.Fatalf("connections = %d, want server cap %d", len(got), maxHostInventoryConnections)
	}
	var normalized int
	for _, c := range got {
		if c.LocalAddress == "192.0.2.10" && c.RemoteAddress == "203.0.113.20" && c.RemotePort == 443 {
			normalized++
			if c.Process != "browser" {
				t.Errorf("coalescing did not retain useful process: %#v", c)
			}
		}
		if c.LocalAddress == "127.0.0.1" || c.RemoteAddress == "169.254.10.1" {
			t.Errorf("non-routable address survived intake: %#v", c)
		}
	}
	if normalized != 1 {
		t.Fatalf("IPv4-mapped duplicate count = %d, want 1", normalized)
	}
}

func TestHostInventoryConnections_RejectsForeignSubjectAndMalformedSnapshot(t *testing.T) {
	subject := di.PeerRef{Identifiers: []di.PeerIdentifier{{Kind: di.IdentifierAgentID, Value: "agent-1"}}}
	other := di.PeerRef{Identifiers: []di.PeerIdentifier{{Kind: di.IdentifierAgentID, Value: "agent-2"}}}
	obs := &di.InterrogateResult{Facts: []di.FactObservation{{
		Key: facts.KeyNetOutboundConnections, Value: []projectedConnection{}, Subject: other,
	}}}
	if _, err := hostInventoryConnections(obs, subject); err == nil {
		t.Fatal("foreign-subject connection snapshot was accepted")
	}
	obs.Facts[0].Subject = subject
	obs.Facts[0].Value = "not an array"
	if _, err := hostInventoryConnections(obs, subject); err == nil {
		t.Fatal("malformed connection snapshot was silently treated as empty")
	}
}

func TestConnectionSnapshotReady_PreservesOptOutEmptyAndFailureStates(t *testing.T) {
	tests := []struct {
		name  string
		meta  hostInventoryMetadata
		facts []di.FactObservation
		ready bool
		err   bool
	}{
		{name: "absent means privacy opt-out"},
		{
			name:  "successful empty is a measured zero",
			meta:  hostInventoryMetadata{Sections: map[string]string{hostinventory.SectionConnections: hostinventory.SectionOK}},
			facts: []di.FactObservation{{Key: facts.KeyNetOutboundConnections, Value: []map[string]any{}}},
			ready: true,
		},
		{
			name: "failed collection is visible",
			meta: hostInventoryMetadata{Sections: map[string]string{hostinventory.SectionConnections: hostinventory.SectionFailed}},
			err:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ready, err := connectionSnapshotReady(tc.meta, &di.InterrogateResult{Facts: tc.facts})
			if ready != tc.ready || (err != nil) != tc.err {
				t.Fatalf("ready/error = %t/%v, want %t/error=%t", ready, err, tc.ready, tc.err)
			}
		})
	}
}

func TestHostInventoryEndpoints_AWildcardBindTakesTheHostsOwnAddress(t *testing.T) {
	// 0.0.0.0 means "every interface", not an address. Writing it into
	// asset_endpoints.address is the placeholder row the passive host-observation
	// path had to be stopped from creating, and it would put a literal 0.0.0.0
	// in a customer's inventory.
	obs := &di.InterrogateResult{Assets: []di.CryptoAsset{
		{IPAddress: "0.0.0.0", Port: 22, Protocol: "tcp"},
		{IPAddress: "::", Port: 443, Protocol: "tcp"},
		{IPAddress: "0:0:0:0:0:0:0:0", Port: 8080, Protocol: "tcp"},
	}}
	eps := hostInventoryEndpoints(obs, hostInventoryMetadata{FQDN: "app-01.example.net"}, "198.51.100.20", testEndpointSource)
	if len(eps) != 3 {
		t.Fatalf("endpoints = %d, want 3", len(eps))
	}
	for _, ep := range eps {
		if ep.Address != "198.51.100.20" {
			t.Errorf("wildcard-bound endpoint on port %d got address %q, want the host's own", ep.Port, ep.Address)
		}
	}
}

func TestHostInventoryEndpoints_FallsBackToTheNameWhenThereIsNoAddress(t *testing.T) {
	// A host with no usable interface address still has a name, and an endpoint
	// needs one or the other: asset_endpoints_addressable_check refuses a row
	// with neither.
	obs := &di.InterrogateResult{Assets: []di.CryptoAsset{{IPAddress: "0.0.0.0", Port: 22, Protocol: "tcp"}}}

	eps := hostInventoryEndpoints(obs, hostInventoryMetadata{FQDN: "app-01.example.net"}, "", testEndpointSource)
	if len(eps) != 1 || eps[0].FQDN != "app-01.example.net" || eps[0].Address != "" {
		t.Fatalf("endpoint = %+v, want the FQDN and no address", eps)
	}

	eps = hostInventoryEndpoints(obs, hostInventoryMetadata{Hostname: "app-01"}, "", testEndpointSource)
	if len(eps) != 1 || eps[0].FQDN != "app-01" {
		t.Fatalf("endpoint = %+v, want the short hostname as a last resort", eps)
	}

	// Neither: skipped rather than written as an unaddressable row.
	if eps := hostInventoryEndpoints(obs, hostInventoryMetadata{}, "", testEndpointSource); len(eps) != 0 {
		t.Errorf("an endpoint with neither an address nor a name was kept: %+v", eps)
	}
}

func TestHostInventoryEndpoints_KeepsTheSpecificBindAndItsBoundLocalFlag(t *testing.T) {
	obs := &di.InterrogateResult{Assets: []di.CryptoAsset{
		{IPAddress: "127.0.0.1", Port: 5432, Protocol: "tcp", Metadata: map[string]interface{}{"bound_local": true}},
		{IPAddress: "198.51.100.20", Port: 161, Protocol: "udp", Metadata: map[string]interface{}{"bound_local": false}},
		// No flag at all: nobody established it, and nil is the only honest
		// answer. A false default would have every such endpoint assert it is
		// exposed to the network.
		{IPAddress: "198.51.100.20", Port: 80, Protocol: "tcp"},
	}}
	eps := hostInventoryEndpoints(obs, hostInventoryMetadata{}, "198.51.100.20", testEndpointSource)
	if len(eps) != 3 {
		t.Fatalf("endpoints = %d, want 3", len(eps))
	}
	if eps[0].Address != "127.0.0.1" || eps[0].BoundLocal == nil || !*eps[0].BoundLocal {
		t.Errorf("the loopback endpoint is %+v, want 127.0.0.1 with bound_local true", eps[0])
	}
	if eps[1].BoundLocal == nil || *eps[1].BoundLocal {
		t.Errorf("an explicit false was lost: %+v", eps[1])
	}
	if eps[2].BoundLocal != nil {
		t.Errorf("an absent flag became %v; nil means nobody established it", *eps[2].BoundLocal)
	}
}

// TestHostInventoryEndpoints_CarryTheirOwnBoundLocalAnswer pins that each
// endpoint reports ITS OWN binding — a shared pointer would give every one the
// last socket's answer, invisible whenever the sockets agree and inverting the
// flag on a host where they do not.
//
// It is a SHAPE assertion, not a guard against that aliasing, and the
// difference matters because the name it used to carry claimed otherwise. Go
// declares the type-assertion's `v` fresh on each iteration of the loop in
// hostInventoryEndpoints, so `&v` is already safe and this test passes with the
// explicit copy removed — mutation-checked. The copy stays because it survives
// a refactor that hoists the variable out of the loop; this test does not
// detect that refactor, and a reader who trusted the old name would think it
// did.
func TestHostInventoryEndpoints_CarryTheirOwnBoundLocalAnswer(t *testing.T) {
	obs := &di.InterrogateResult{Assets: []di.CryptoAsset{
		{IPAddress: "127.0.0.1", Port: 1, Protocol: "tcp", Metadata: map[string]interface{}{"bound_local": true}},
		{IPAddress: "10.0.0.1", Port: 2, Protocol: "tcp", Metadata: map[string]interface{}{"bound_local": false}},
	}}
	eps := hostInventoryEndpoints(obs, hostInventoryMetadata{}, "10.0.0.1", testEndpointSource)
	if !*eps[0].BoundLocal || *eps[1].BoundLocal {
		t.Fatalf("bound_local aliased across endpoints: %v / %v", *eps[0].BoundLocal, *eps[1].BoundLocal)
	}
}

func TestHostInventoryEndpoints_CarryTheProcessNameAsReported(t *testing.T) {
	// The host named the process holding the socket. That is the strongest form
	// of this claim available anywhere in the product — stronger than a banner,
	// which is whatever a service chose to say about itself — and the method
	// has to travel with it or the name is a claim with no argument behind it.
	obs := &di.InterrogateResult{Assets: []di.CryptoAsset{{
		IPAddress: "10.0.0.1", Port: 22, Protocol: "tcp",
		ServiceHints: &di.ServiceHints{ServiceName: "sshd", Confidence: "reported", IdentificationMethod: "host_socket_owner"},
	}}}
	eps := hostInventoryEndpoints(obs, hostInventoryMetadata{}, "10.0.0.1", testEndpointSource)
	if eps[0].ServiceName != "sshd" || eps[0].ServiceConfidence != "reported" || eps[0].ServiceIdentificationMethod != "host_socket_owner" {
		t.Fatalf("service hints were lost: %+v", eps[0])
	}
	// And NO application protocol. A host inventory observes that something is
	// listening, never what it speaks; guessing "ssh" from port 22 would be a
	// fact nobody measured.
	if eps[0].Protocol != "" {
		t.Errorf("protocol = %q, want empty — the port number is not a measurement", eps[0].Protocol)
	}
	if eps[0].Transport != "tcp" {
		t.Errorf("transport = %q, want tcp", eps[0].Transport)
	}
}

func TestIsWildcardAddress(t *testing.T) {
	for _, v := range []string{"0.0.0.0", "::", "0:0:0:0:0:0:0:0", "::ffff:0.0.0.0", " 0.0.0.0 "} {
		if !isWildcardAddress(v) {
			t.Errorf("%q was not recognised as a wildcard bind", v)
		}
	}
	for _, v := range []string{"127.0.0.1", "::1", "198.51.100.20", "", "not-an-address"} {
		if isWildcardAddress(v) {
			t.Errorf("%q was treated as a wildcard bind", v)
		}
	}
}

// ---------------------------------------------------------------------------
// facts
// ---------------------------------------------------------------------------

func TestHostInventoryFacts_HoldsBackThePackageCountAndReportsIt(t *testing.T) {
	// sw.package_count is rewritten from the rows that actually landed, so it
	// must not also be written from this batch — but its PRESENCE is what says
	// the package step succeeded, which is the only thing that licenses the
	// install write at all.
	subject := di.PeerRef{Identifiers: []di.PeerIdentifier{{Kind: di.IdentifierSerialNumber, Value: "CZ2X5Y3"}}}
	obs := &di.InterrogateResult{Facts: []di.FactObservation{
		{Key: facts.KeyOSName, Value: "Ubuntu", Subject: subject},
		{Key: facts.KeySWPackageCount, Value: float64(412), Subject: subject},
	}}

	out, enumerated, errs := hostInventoryFacts(obs, subject)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if enumerated == nil || *enumerated != 412 {
		t.Fatalf("enumerated = %v, want 412", enumerated)
	}
	if len(out) != 1 || out[0].Key != facts.KeyOSName {
		t.Fatalf("facts to write = %+v, want only os.name", out)
	}
}

func TestHostInventoryFacts_AFailedPackageStepReportsNoCount(t *testing.T) {
	// The three-valued contract, at the point the consumer reads it. A section
	// that failed emits no sw.package_count, and nil here is what stops the
	// absent-install sweep marking the host's whole software inventory removed.
	subject := di.PeerRef{Identifiers: []di.PeerIdentifier{{Kind: di.IdentifierSerialNumber, Value: "CZ2X5Y3"}}}
	obs := &di.InterrogateResult{Facts: []di.FactObservation{{Key: facts.KeyOSName, Value: "Ubuntu", Subject: subject}}}

	if _, enumerated, _ := hostInventoryFacts(obs, subject); enumerated != nil {
		t.Fatalf("enumerated = %v for a collection with no package count", *enumerated)
	}
}

func TestHostInventoryFacts_RefusesAFactAboutSomebodyElse(t *testing.T) {
	// Every fact in a host inventory is about the host. One with a different
	// subject means the payload was assembled by something this code does not
	// understand, and folding it onto the host would be the "one controller's
	// port table filed under the wrong switch" mistake.
	subject := di.PeerRef{Identifiers: []di.PeerIdentifier{{Kind: di.IdentifierSerialNumber, Value: "CZ2X5Y3"}}}
	other := di.PeerRef{
		DisplayName: "some-other-box",
		Identifiers: []di.PeerIdentifier{{Kind: di.IdentifierSerialNumber, Value: "SOMEONE-ELSE"}},
	}
	obs := &di.InterrogateResult{Facts: []di.FactObservation{
		{Key: facts.KeyOSName, Value: "Ubuntu", Subject: subject},
		{Key: facts.KeyOSKernel, Value: "6.8.0", Subject: other},
	}}

	out, _, errs := hostInventoryFacts(obs, subject)
	if len(out) != 1 || out[0].Key != facts.KeyOSName {
		t.Fatalf("facts to write = %+v, want only the host's own", out)
	}
	if len(errs) != 1 {
		t.Fatalf("errors = %v, want one naming the refused fact", errs)
	}
}

func TestHostInventoryFacts_StripTheSubjectTheEngineAlreadyResolved(t *testing.T) {
	// Leaving the subject on would send the ObservationSink back through the
	// PEER-resolution path — a second, differently-built observation of a host
	// this run has already decided.
	subject := di.PeerRef{Identifiers: []di.PeerIdentifier{{Kind: di.IdentifierSerialNumber, Value: "CZ2X5Y3"}}}
	obs := &di.InterrogateResult{Facts: []di.FactObservation{{Key: facts.KeyOSName, Value: "Ubuntu", Subject: subject}}}

	out, _, _ := hostInventoryFacts(obs, subject)
	if !out[0].Subject.IsZero() {
		t.Fatalf("the subject survived: %+v", out[0].Subject)
	}
}

func TestHostInventorySubject_RecoversTheHostFromAnyFact(t *testing.T) {
	subject := di.PeerRef{Identifiers: []di.PeerIdentifier{{Kind: di.IdentifierAgentID, Value: "agent-1"}}}
	got, ok := hostInventorySubject(&di.InterrogateResult{Facts: []di.FactObservation{
		{Key: facts.KeyAgentMode, Value: "local", Subject: subject},
	}})
	if !ok || identifierKey(got) != identifierKey(subject) {
		t.Fatalf("subject = %+v (ok=%t)", got, ok)
	}

	// A payload with no facts at all carries no identity and cannot be
	// materialised. Saying so is the honest answer; the alternative is an asset
	// nothing can ever recognise again.
	if _, ok := hostInventorySubject(&di.InterrogateResult{}); ok {
		t.Error("a subject was invented for a payload that carries none")
	}
}

// ---------------------------------------------------------------------------
// software
// ---------------------------------------------------------------------------

func TestHostInventoryProducts_DeduplicatesByCatalogueIdentity(t *testing.T) {
	obs := &di.InterrogateResult{DeviceInfo: map[string]interface{}{"packages": []map[string]any{
		{"name": "openssl", "version": "3.0.13", "purl": "pkg:deb/ubuntu/openssl@3.0.13"},
		// The same purl from a second package manager is ONE catalogue row and
		// one install, not two round trips and a doubled count.
		{"name": "openssl", "version": "3.0.13", "purl": "pkg:deb/ubuntu/openssl@3.0.13"},
		{"name": "vendor-agent", "version": "1.4.2"},
		// software_products.name is NOT NULL, and inventing a name for a
		// nameless entry would put a row in the catalogue that matches nothing.
		{"version": "9.9"},
	}}}
	got := hostInventoryProducts(obs)
	if len(got) != 2 {
		t.Fatalf("products = %d (%+v), want 2", len(got), got)
	}
}

func TestHostInventoryProducts_ReadsTheObservationsCopyNotTheReports(t *testing.T) {
	// The report's package list no longer travels (device-agent's
	// withoutPackageList), and only the observations' copy has been through
	// di.Sanitize. A consumer reaching for the other one would read an empty
	// list on every real submission.
	if got := hostInventoryProducts(&di.InterrogateResult{DeviceInfo: map[string]interface{}{}}); len(got) != 0 {
		t.Fatalf("products = %+v for a payload with no package list", got)
	}
	if got := hostInventoryProducts(&di.InterrogateResult{}); len(got) != 0 {
		t.Fatalf("products = %+v for an empty payload", got)
	}
}

// TestSoftwareListArrived is the second half of the absent-install sweep guard.
//
// The first half — `sw.package_count` being present — says the package STEP
// succeeded. It cannot say the resulting LIST is in the payload, because the
// count travels as a fact and the list travels in `device_info.packages`: two
// different fields of two different halves of the submission, lost
// independently (on the remote path they are `JobResult.Facts` and
// `JobResult.Metadata`). A payload carrying the count and not the list reaches
// the writer with no products, and MarkAbsentRemoved marks the host's ENTIRE
// measured software inventory removed.
//
// Mutation check: make softwareListArrived always return ok and the
// "enumerated some, received none" case below goes green while the integration
// test TestIntegration_HostInventory_Materialises_AMissingPackageListSweepsNothing
// starts losing a host's software.
func TestSoftwareListArrived(t *testing.T) {
	for _, tc := range []struct {
		name       string
		enumerated int
		arrived    int
		want       bool
	}{
		// The contradiction: the collector counted packages and not one of them
		// is in the payload.
		{"enumerated some, received none", 412, 0, false},
		{"enumerated one, received none", 1, 0, false},
		// A host that genuinely has no packages enumerates ZERO and sends no
		// list — ToObservations omits the key for an empty slice — so this must
		// stay allowed or a package-less host could never have its stale
		// installs swept.
		{"enumerated none, received none", 0, 0, true},
		// `arrived` is the post-dedup count of identifiable products, so it is
		// legitimately smaller than what the collector counted. A shortfall is
		// not a contradiction; only nothing arriving is.
		{"dedup shrank the list", 412, 410, true},
		{"every entry was nameless but one", 412, 1, true},
		{"exact", 3, 3, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reason, ok := softwareListArrived(tc.enumerated, tc.arrived)
			if ok != tc.want {
				t.Fatalf("softwareListArrived(%d, %d) ok = %t, want %t", tc.enumerated, tc.arrived, ok, tc.want)
			}
			// A refusal that does not say why is a silent drop wearing a
			// different hat: this string is what reaches the job row.
			if !ok && reason == "" {
				t.Error("the refusal carries no reason")
			}
			if ok && reason != "" {
				t.Errorf("an allowed write carries a reason: %q", reason)
			}
		})
	}
}

// TestListenerListArrived is the two-gate licence for retiring endpoints.
//
// A socket absent from a GOOD report has stopped listening, and closing it is
// the whole point — a host inventory reads the machine's own socket table, so
// it is the only source that can say "nothing is listening on 8080 any more".
// Both ways of being wrong cost something real, which is why there are two
// gates and not one:
//
//   - Closing on a FAILED step reports every service on the machine as stopped
//     because one command was unavailable.
//   - Closing on a payload whose sockets were lost in transit does the same
//     thing for a transport gap.
//   - But REFUSING on a successful step that genuinely found nothing would mean
//     a host that stopped serving never retires anything, which is the silence
//     this whole workstream exists to end.
//
// Mutation check: drop the section gate and "a failed step" goes green while
// TestIntegration_HostInventory_Materialises_FailedListenerStepClosesNothing
// starts closing a live host's endpoints.
func TestListenerListArrived(t *testing.T) {
	for _, tc := range []struct {
		name       string
		section    string
		sawFact    bool
		arrived    int
		want       bool
		wantReason bool
	}{
		{"a good report with sockets", hostinventory.SectionOK, true, 3, true, false},
		// A successful step that found NOTHING is an answer, and the sweep must
		// run for it: this is a host that stopped serving.
		{"a good report with no sockets at all", hostinventory.SectionOK, false, 0, true, false},
		// The step failed. Not an error on the job row — a failed section is a
		// normal outcome the collector already reports honestly.
		{"a failed step", hostinventory.SectionFailed, false, 0, false, false},
		{"an unsupported step", hostinventory.SectionUnsupported, false, 0, false, false},
		{"no section outcome at all", "", false, 0, false, false},
		// The contradiction: the collector says it saw sockets and not one
		// reached the endpoint builder.
		{"sockets reported but none arrived", hostinventory.SectionOK, true, 0, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reason, ok := listenerListArrived(tc.section, tc.sawFact, tc.arrived)
			if ok != tc.want {
				t.Fatalf("listenerListArrived(%q, %t, %d) ok = %t, want %t",
					tc.section, tc.sawFact, tc.arrived, ok, tc.want)
			}
			if (reason != "") != tc.wantReason {
				t.Errorf("reason = %q, wantReason = %t — a failed section is a normal "+
					"outcome and must not be reported as an error", reason, tc.wantReason)
			}
		})
	}
}

func TestHasFact(t *testing.T) {
	obs := &di.InterrogateResult{Facts: []di.FactObservation{
		{Key: facts.KeyOSName, Value: "Ubuntu"},
		{Key: facts.KeySvcListeningSockets, Value: []any{}},
	}}
	if !hasFact(obs, facts.KeySvcListeningSockets) {
		t.Error("a present key was not found")
	}
	if hasFact(obs, facts.KeyHWSerial) {
		t.Error("an absent key was found")
	}
}

func TestHostInventoryEndpoints_CarryTheRunsSourceRef(t *testing.T) {
	// The retirement sweep closes every row of this agent's whose ref is not
	// THIS run's. A stable ref makes that test vacuously false and nothing is
	// ever closed — the same trap the install sweep documents.
	obs := &di.InterrogateResult{Assets: []di.CryptoAsset{
		{IPAddress: "10.0.0.1", Port: 22, Protocol: "tcp"},
	}}
	eps := hostInventoryEndpoints(obs, hostInventoryMetadata{}, "10.0.0.1", testEndpointSource)
	if len(eps) != 1 {
		t.Fatalf("endpoints = %d", len(eps))
	}
	if eps[0].Source.Ref != testEndpointSource.Ref {
		t.Errorf("endpoint source ref = %q, want the run's %q — the sweep cannot tell runs apart without it",
			eps[0].Source.Ref, testEndpointSource.Ref)
	}
	if eps[0].Source.Kind != identity.SourceMeasured {
		t.Errorf("endpoint source kind = %q, want measured", eps[0].Source.Kind)
	}
}

// ---------------------------------------------------------------------------
// the metadata block, and the address the scope comes from
// ---------------------------------------------------------------------------

func TestPrimaryAddress_SkipsVirtualInterfacesAndLoopback(t *testing.T) {
	// A veth address is where a container lives, not where this host does;
	// scoping the host's identity by one files it in a segment that exists only
	// inside the machine.
	obs := &di.InterrogateResult{Facts: []di.FactObservation{{
		Key: facts.KeyNetInterfaces,
		Value: []map[string]any{
			{"name": "lo", "addresses": []string{"127.0.0.1/8"}},
			{"name": "veth9a1b", "addresses": []string{"10.244.1.3/24"}, "virtual": true},
			{"name": "eno1", "addresses": []string{"198.51.100.20/24"}},
		},
	}}}
	if got := (hostInventoryMetadata{}).primaryAddress(obs); got != "198.51.100.20" {
		t.Fatalf("primary address = %q, want 198.51.100.20", got)
	}
}

func TestPrimaryAddress_IsEmptyWhenThereIsNoInterfaceFact(t *testing.T) {
	// Which is a normal case: the interfaces section can fail on its own, and
	// an empty scope falls through to the tenant default rather than inventing
	// a segment.
	if got := (hostInventoryMetadata{}).primaryAddress(&di.InterrogateResult{}); got != "" {
		t.Fatalf("primary address = %q for a payload with no interfaces", got)
	}
}

func TestParseHostAddress(t *testing.T) {
	for in, want := range map[string]string{
		"198.51.100.20/24": "198.51.100.20",
		"198.51.100.20":    "198.51.100.20",
		"2001:db8::1/64":   "2001:db8::1",
	} {
		if got, ok := parseHostAddress(in); !ok || got != want {
			t.Errorf("parseHostAddress(%q) = %q, %t; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"127.0.0.1/8", "::1", "0.0.0.0", "169.254.1.1", "", "not-an-address"} {
		if got, ok := parseHostAddress(in); ok {
			t.Errorf("parseHostAddress(%q) = %q; a host does not live there", in, got)
		}
	}
}

func TestHostInventoryMeta_DecodesTheCollectorsOwnAccount(t *testing.T) {
	obs := &di.InterrogateResult{DeviceInfo: map[string]interface{}{"host_inventory": map[string]any{
		"collected": "2026-09-12T09:00:00Z",
		"mode":      "local",
		"platform":  "linux",
		"hostname":  "app-01",
		"fqdn":      "app-01.example.net",
		"sections":  map[string]any{"packages": "failed"},
	}}}
	meta := hostInventoryMeta(obs)
	if meta.FQDN != "app-01.example.net" || meta.Mode != "local" {
		t.Fatalf("metadata = %+v", meta)
	}
	if meta.label() != "app-01.example.net" {
		t.Errorf("label = %q, want the FQDN (the most specific identity)", meta.label())
	}
	if meta.collectedAt().IsZero() {
		t.Error("the collection time did not parse")
	}

	// A missing block is survivable: the facts and identifiers are the
	// substance, and failing the run over the label would lose them.
	empty := hostInventoryMeta(&di.InterrogateResult{})
	if empty.label() != "an unnamed host" {
		t.Errorf("label with no metadata = %q", empty.label())
	}
	if !empty.collectedAt().IsZero() {
		t.Error("an unparseable time was not left zero for the engine to stamp")
	}
}

// ---------------------------------------------------------------------------
// the class proposal
// ---------------------------------------------------------------------------

func TestClassProposal_ExcludesLoopbackPortsFromThePortProfile(t *testing.T) {
	// A port profile describes what a device EXPOSES, and a service bound to
	// 127.0.0.1 exposes nothing. Including it would let a developer laptop
	// running a local database match a database-server profile.
	obs := &di.InterrogateResult{Assets: []di.CryptoAsset{
		{Port: 5432, Metadata: map[string]interface{}{"bound_local": true}},
		{Port: 22, Metadata: map[string]interface{}{"bound_local": false}},
		{Port: 22, Metadata: map[string]interface{}{"bound_local": false}},
	}}
	got := exposedPorts(obs)
	if len(got) != 1 || got[0] != 22 {
		t.Fatalf("exposed ports = %v, want [22]", got)
	}
}

func TestClassifyHost_IsEmptyWhenTheRulesDoNotDecide(t *testing.T) {
	// "The rules did not decide" is a normal outcome with a complete answer,
	// and it must come back as no proposal rather than a guess.
	h := NewHostInventoryIngest(nil, nil)
	ctx := context.Background()

	if got := h.classifyHost(ctx, &di.InterrogateResult{}); got.Class != "" || got.Conflict {
		t.Fatalf("proposal = %+v for a payload with no evidence", got)
	}
	obs := &di.InterrogateResult{Facts: []di.FactObservation{
		{Key: facts.KeyHWVendor, Value: "Some Vendor Nobody Has A Rule For"},
		{Key: facts.KeyHWModel, Value: "XYZ-1"},
		{Key: facts.KeyOSName, Value: "Ubuntu"},
	}}
	if got := h.classifyHost(ctx, obs); got.Class != "" {
		t.Fatalf("proposal = %q for evidence no rule covers", got.Class)
	}
}

// The projection, over the payload the reported asset actually produced.
//
// This is the unit half of the reclassification fix and it drives the REAL
// function the ingest calls, not a re-implementation of it: delete the
// `facts.KeyOSName` case from hostInventoryClassEvidence and this goes red,
// which is the only thing that proves the OS reaches the rules at all. The
// integration test proves it reaches the ASSET.
func TestHostInventoryClassEvidence_CarriesTheOperatingSystemToTheRules(t *testing.T) {
	h := NewHostInventoryIngest(nil, nil)

	// The reported asset, fact for fact.
	xps := &di.InterrogateResult{
		Facts: []di.FactObservation{
			{Key: facts.KeyOSName, Value: "Microsoft Windows 11 Pro"},
			{Key: facts.KeyOSVersion, Value: "10.0.26200"},
			{Key: facts.KeyHWVendor, Value: "Dell Inc."},
			{Key: facts.KeyHWModel, Value: "XPS 16 9640"},
			{Key: facts.KeyHWSerial, Value: "5SDH994"},
		},
		Assets: []di.CryptoAsset{
			{Port: 445, Metadata: map[string]interface{}{"bound_local": false}},
			{Port: 5432, Metadata: map[string]interface{}{"bound_local": true}},
		},
	}

	ev := hostInventoryClassEvidence(xps)
	if ev.OS != "Microsoft Windows 11 Pro" {
		t.Errorf("OS = %q — os.name is the only evidence a general-purpose computer offers", ev.OS)
	}
	if ev.Vendor != "Dell Inc." || ev.Model != "XPS 16 9640" {
		t.Errorf("vendor/model = %q/%q", ev.Vendor, ev.Model)
	}
	if len(ev.OpenPorts) != 1 || ev.OpenPorts[0] != 445 {
		t.Errorf("open ports = %v, want only the non-loopback one", ev.OpenPorts)
	}
	// The interface MACs are deliberately absent — see the doc comment. A veth
	// address reaching the rules classifies a Linux server as a `container`.
	if len(ev.MACs) != 0 {
		t.Errorf("MACs = %v, want none", ev.MACs)
	}

	got := h.classifyHost(context.Background(), xps)
	if got.Class != "computer" {
		t.Fatalf("class = %q, want computer — this asset is the whole reason for the fix (matched %+v)",
			got.Class, got.MatchedRules)
	}
	if got.Conflict {
		t.Errorf("conflict over %v", got.ConflictingClasses)
	}
	if got.ModelID != "" {
		t.Errorf("model id %q — a learned answer must never be applied, only proposed", got.ModelID)
	}

	// The other polarity, on the same code path: a Windows SERVER is a server,
	// and a Linux box is still nothing at all.
	server := &di.InterrogateResult{Facts: []di.FactObservation{
		{Key: facts.KeyOSName, Value: "Microsoft Windows Server 2022 Datacenter"},
	}}
	if c := h.classifyHost(context.Background(), server).Class; c != "server" {
		t.Errorf("Windows Server classified as %q, want server", c)
	}
}

// A fact value that is not a string is an ABSENT input, not a formatted one.
// `%!v(...)` in an OS name would match no rule and read as a catalogue gap
// rather than the producer bug it is.
func TestHostInventoryClassEvidence_IgnoresFactValuesOfTheWrongType(t *testing.T) {
	ev := hostInventoryClassEvidence(&di.InterrogateResult{Facts: []di.FactObservation{
		{Key: facts.KeyOSName, Value: 11},
		{Key: facts.KeyHWVendor, Value: map[string]any{"name": "Dell"}},
		{Key: facts.KeyHWModel, Value: "  XPS 16 9640  "},
	}})
	if ev.OS != "" || ev.Vendor != "" {
		t.Errorf("a non-string fact became evidence: %+v", ev)
	}
	if ev.Model != "XPS 16 9640" {
		t.Errorf("model = %q, want it trimmed", ev.Model)
	}
}

// ---------------------------------------------------------------------------
// counts
// ---------------------------------------------------------------------------

func TestHostInventoryCounts_MaterializedCountsHostsNotParts(t *testing.T) {
	// "451" would read as 451 assets to anybody scanning the Job Logs. The thing
	// a host inventory materialises is one host.
	c := HostInventoryCounts{AssetID: "x", Facts: 14, Endpoints: 18, InstallsCreated: 412}
	if c.Materialized() != 1 {
		t.Errorf("materialized = %d, want 1", c.Materialized())
	}
	if !c.FullyMaterialized() {
		t.Error("a run that landed everything did not report fully_materialized")
	}

	if (HostInventoryCounts{}).Materialized() != 0 {
		t.Error("a run that created nothing reported an asset")
	}
}

func TestHostInventoryCounts_FullyMaterializedIsHardToClaim(t *testing.T) {
	// A contested identity is not a clean run: a merge proposal is waiting, and
	// the numbers describe a pending asset nobody has agreed exists.
	if (HostInventoryCounts{AssetID: "x", Contested: true}).FullyMaterialized() {
		t.Error("a contested run reported a clean success")
	}
	if (HostInventoryCounts{AssetID: "x", Errors: []string{"writing facts: boom"}}).FullyMaterialized() {
		t.Error("a run that lost its facts reported a clean success")
	}
	if (HostInventoryCounts{}).FullyMaterialized() {
		t.Error("a run that created no asset reported a clean success")
	}
}

func TestHostInventorySourceRefs_DifferForFactsAndForTheRun(t *testing.T) {
	// Facts key on the AGENT — a per-run ref would leave one stale asset_facts
	// row per collection, each claiming a value that was true once. Installs key
	// on the RUN, because the absent-install sweep works by comparing against
	// it; a stable ref makes that test vacuously false and nothing is ever swept.
	agent, job1, job2 := uuid.New(), uuid.New(), uuid.New()

	if hostInventorySourceRef(agent, job1) != hostInventorySourceRef(agent, job2) {
		t.Error("the fact ref changed between runs; that leaves a stale row per collection")
	}
	if hostInventoryRunRef(agent, job1) == hostInventoryRunRef(agent, job2) {
		t.Error("the install ref is the same across runs; the absent-install sweep can never fire")
	}
	// Both keep the producer prefix an approval rule filters on.
	for _, ref := range []string{hostInventorySourceRef(agent, job1), hostInventoryRunRef(agent, job1)} {
		if got := hostInventorySource(agent, job1).Producer(); got != "agent" {
			t.Errorf("ref %q has producer %q, want agent", ref, got)
		}
	}
	// An agentless job still gets an auditable ref rather than an empty one.
	if hostInventorySourceRef(uuid.Nil, job1) == "" {
		t.Error("a job with no agent produced an empty source ref")
	}
}

// ---------------------------------------------------------------------------
// the remote envelope
// ---------------------------------------------------------------------------

func TestHostInventoryObservationsFromResult_CarriesTheThreePiecesTheConsumerReads(t *testing.T) {
	// The remote path arrives as models.JobResult, the local one as
	// di.InterrogateResult. Reassembling here means the consumer has ONE input
	// shape rather than two branches free to disagree about what a host
	// inventory is.
	result := &models.JobResult{
		Facts:    []di.FactObservation{{Key: facts.KeyOSName, Value: "Ubuntu"}},
		Metadata: map[string]interface{}{"packages": []map[string]any{{"name": "openssl"}}},
		Assets: []models.DiscoveredAsset{{
			IPAddress: "127.0.0.1", Port: 5432, Protocol: "tcp",
			Metadata:     map[string]interface{}{"bound_local": true},
			ServiceHints: &models.ServiceHints{ServiceName: "postgres", Confidence: "reported", IdentificationMethod: "host_socket_owner"},
		}},
	}
	obs := hostInventoryObservationsFromResult(result)
	if len(obs.Facts) != 1 || obs.Facts[0].Key != facts.KeyOSName {
		t.Errorf("facts were lost: %+v", obs.Facts)
	}
	if obs.DeviceInfo["packages"] == nil {
		t.Error("the package list was lost")
	}
	if len(obs.Assets) != 1 {
		t.Fatalf("assets = %d, want 1", len(obs.Assets))
	}
	if obs.Assets[0].ServiceHints == nil || obs.Assets[0].ServiceHints.ServiceName != "postgres" {
		t.Errorf("the process name was lost: %+v", obs.Assets[0].ServiceHints)
	}
	if v, _ := obs.Assets[0].Metadata["bound_local"].(bool); !v {
		t.Error("bound_local was lost")
	}
	// DeviceInfo is never nil, so the metadata reads below do not have to
	// nil-check a map they will index.
	if hostInventoryObservationsFromResult(&models.JobResult{}).DeviceInfo == nil {
		t.Error("DeviceInfo is nil for a payload that carried no metadata")
	}
	if hostInventoryObservationsFromResult(nil) != nil {
		t.Error("a nil result produced a non-nil observation")
	}
}
