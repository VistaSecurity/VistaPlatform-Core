package hostinventory

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/facts"
)

// The projection guards, mutation-tested the way
// deviceinterrogation/collector_projection_test.go is.
//
// Each of these feeds a projection a value carrying material that must not
// travel and asserts it does not survive. They call the projections DIRECTLY,
// before Sanitize runs, because the point is that the data is never COLLECTED —
// the redaction backstop would catch most of it by field name, and relying on
// that would mean the real defence was never tested.

// poison is a value that must never appear in a projected structure.
const poison = "MUST-NOT-BE-COLLECTED"

func assertNoPoison(t *testing.T, label string, v any) {
	t.Helper()
	blob, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("%s: marshal: %v", label, err)
	}
	if strings.Contains(string(blob), poison) {
		t.Errorf("%s: collected material that should have been projected away: %s", label, blob)
	}
}

// A Package is our own struct, so the risk is not a vendor field — it is a
// future field added here and forwarded without anyone deciding it should be.
// The allowlist is what makes that a compile-time decision.
func TestProjectPackage_EnumeratesRatherThanCopies(t *testing.T) {
	out := projectPackage(Package{
		Name:    "openssl",
		Version: "3.0.2-0ubuntu1.15",
		Vendor:  "Ubuntu Developers",
		Arch:    "amd64",
		Manager: "dpkg",
		PURL:    "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.15?arch=amd64",
	})

	want := map[string]bool{"name": true, "version": true, "vendor": true, "arch": true, "manager": true, "purl": true}
	for k := range out {
		if !want[k] {
			t.Errorf("projected an unlisted field %q", k)
		}
	}
	if out["name"] != "openssl" || out["purl"] == "" {
		t.Errorf("identity or purl lost: %#v", out)
	}
}

// The cert-store projection is the one place key material could plausibly
// arrive, so it is asserted on shape rather than only on content: there must be
// no field that could hold a PEM.
func TestProjectCertStore_CarriesNoPEMAndNoKey(t *testing.T) {
	out := projectCertStore(CertStore{
		Path:  "/etc/ssl/certs",
		Count: 1,
		Certs: []Cert{{
			SubjectDN:         "CN=Example Fixture Root CA,O=Example Org,C=US",
			IssuerDN:          "CN=Example Fixture Root CA,O=Example Org,C=US",
			FingerprintSHA256: "21819dbfeff0e5743117fbfa8f2591c320021fbcbec50a902933c6d28378e3ab",
			NotAfter:          "2036-09-08T22:53:13Z",
		}},
	})

	blob, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range []string{"BEGIN ", "PRIVATE KEY", "certificate_pem", "private", "_key\"", "passphrase"} {
		if strings.Contains(string(blob), forbidden) {
			t.Errorf("the cert-store projection carries %q: %s", forbidden, blob)
		}
	}

	certs, ok := out["certs"].([]map[string]any)
	if !ok || len(certs) != 1 {
		t.Fatalf("certs shape: %#v", out["certs"])
	}
	allowed := map[string]bool{"subject_dn": true, "issuer_dn": true, "fingerprint_sha256": true, "not_after": true}
	for k := range certs[0] {
		if !allowed[k] {
			t.Errorf("projected an unlisted certificate field %q", k)
		}
	}
}

// The listening-socket fact carries no PID. A pid identifies a process on one
// boot of one machine, so it is meaningless by the time the fact is read — and
// a fact is a durable statement.
func TestProjectListeners_DropsThePID(t *testing.T) {
	out := projectListeners([]Listener{{Proto: "tcp", Address: "127.0.0.1", Port: 5432, Process: "postgres", PID: 1402}})
	if len(out) != 1 {
		t.Fatalf("got %d entries", len(out))
	}
	if _, present := out[0]["pid"]; present {
		t.Error("a pid reached a durable fact")
	}
	if out[0]["process"] != "postgres" || out[0]["port"] != 5432 || out[0]["transport"] != "tcp" {
		t.Errorf("posture lost: %#v", out[0])
	}
}

// Drive the public projection, not only projectConnections: deleting the
// AddFactFrom wiring in ToObservations must make this fail.
func TestToObservations_ConnectionsUseTheRegisteredBoundedProjection(t *testing.T) {
	rep := &Report{
		Mode: ModeLocal, Platform: PlatformLinux,
		Host:        Host{Hostname: "source-host"},
		Connections: []Connection{{Proto: "tcp", LocalAddress: "192.0.2.10", LocalPort: 50123, RemoteAddress: "203.0.113.20", RemotePort: 443, Process: "browser", PID: 991}},
		Sections:    map[string]string{SectionConnections: SectionOK},
	}
	result, err := ToObservations(rep)
	if err != nil {
		t.Fatal(err)
	}
	var value any
	for _, fact := range result.Facts {
		if fact.Key == facts.KeyNetOutboundConnections {
			value = fact.Value
		}
	}
	if value == nil {
		t.Fatal("net.outbound_connections did not reach observations")
	}
	blob, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	text := string(blob)
	if !strings.Contains(text, `"remote_address":"203.0.113.20"`) || strings.Contains(text, "50123") || strings.Contains(text, "991") {
		t.Fatalf("connection projection leaked ephemeral fields or lost peer: %s", text)
	}
	if _, present := result.DeviceInfo["connections"]; present {
		t.Error("peer data was copied into free-form DeviceInfo")
	}
}

func TestToObservations_EmitsSuccessfulEmptySocketSnapshots(t *testing.T) {
	rep := &Report{Mode: ModeLocal, Sections: map[string]string{
		SectionBoundUDP: SectionOK, SectionConnections: SectionOK,
	}}
	result, err := ToObservations(rep)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, fact := range result.Facts {
		if fact.Key != facts.KeySvcBoundUdpSockets && fact.Key != facts.KeyNetOutboundConnections {
			continue
		}
		value, ok := fact.Value.([]map[string]any)
		if !ok || len(value) != 0 {
			t.Fatalf("%s = %#v, want an explicit empty snapshot", fact.Key, fact.Value)
		}
		seen[fact.Key] = true
	}
	if !seen[facts.KeySvcBoundUdpSockets] || !seen[facts.KeyNetOutboundConnections] {
		t.Fatalf("successful empty snapshots were omitted: %#v", seen)
	}
}

// bound_local is written UNCONDITIONALLY, including when it is false.
//
// "Reachable only from this host" is a positive claim and so is its negation.
// Omitting the false would leave a reader unable to tell a socket measured as
// network-facing from one whose binding nobody looked at — and it is the one
// thing in this fact a network scan can never establish, which is most of why a
// local collection is worth having at all.
//
// To mutation-test: wrap the assignment in `if isLoopback(...)` and the
// wildcard and specific-address cases below lose the key.
func TestProjectListeners_BoundLocalIsWrittenEvenWhenFalse(t *testing.T) {
	out := projectListeners([]Listener{
		{Proto: "tcp", Address: "127.0.0.1", Port: 5432},
		{Proto: "tcp", Address: "::1", Port: 6432},
		{Proto: "tcp", Address: "::ffff:127.0.0.1", Port: 7432},
		{Proto: "tcp", Address: "0.0.0.0", Port: 22},
		{Proto: "udp", Address: "198.51.100.20", Port: 161},
		// No address at all: not loopback, and it still has to SAY so.
		{Proto: "tcp", Port: 9000},
	})
	want := []bool{true, true, true, false, false, false}
	for i, w := range want {
		got, present := out[i]["bound_local"]
		if !present {
			t.Errorf("entry %d (%v) has no bound_local", i, out[i])
			continue
		}
		if got != w {
			t.Errorf("entry %d (%v): bound_local = %v, want %v", i, out[i], got, w)
		}
	}
}

// A DISK fixture proves the boundary, not a hand-built struct: the bundle under
// testdata/ genuinely contains a PEM private key appended to a certificate,
// which is what a misplaced server.key in a trust directory looks like.
//
// To mutation-test: relax the `block.Type != "CERTIFICATE"` guard in
// ParseCertificatePEM and this fails on the key-fragment assertion.
func TestCertStore_APrivateKeyOnDiskNeverReachesTheReport(t *testing.T) {
	bundle := fixture(t, "linux", "ca-certificates.crt")
	if !strings.Contains(bundle, "BEGIN PRIVATE KEY") {
		t.Fatal("the fixture no longer contains a private key, so this test proves nothing")
	}
	// The bytes of the key body, which must not appear in any output.
	keyBody := strings.SplitN(strings.SplitN(bundle, "-----BEGIN PRIVATE KEY-----", 2)[1], "-----END", 2)[0]
	keyFragment := strings.TrimSpace(strings.SplitN(strings.TrimSpace(keyBody), "\n", 2)[0])
	if len(keyFragment) < 32 {
		t.Fatalf("could not extract a usable key fragment from the fixture: %q", keyFragment)
	}

	certs, other := ParseCertificatePEM([]byte(bundle), 500)
	if len(certs) != 1 {
		t.Fatalf("got %d certificates, want 1 (the key block must be skipped): %+v", len(certs), certs)
	}
	if certs[0].SubjectDN == "" || certs[0].FingerprintSHA256 == "" {
		t.Fatalf("the certificate itself was lost: %+v", certs[0])
	}
	// The key block must be refused ON TYPE, before any decoding. Asserting the
	// count is what separates that guard from x509.ParseCertificate happening to
	// reject the same bytes a step later — without it, deleting the type check
	// leaves every assertion here still green.
	if other != 1 {
		t.Errorf("otherBlocks = %d, want 1; the PRIVATE KEY block was not refused on type", other)
	}

	// And it must be visible on the collected store, as a count and nothing more.
	repStore, err := Collect(context.Background(), scriptUbuntu(t, newFakeLocal()), Options{
		Mode: ModeLocal, Platform: PlatformLinux, Now: fixedNow,
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(repStore.CertStores) == 0 || repStore.CertStores[0].NonCertificateBlocks != 1 {
		t.Errorf("the store did not report its one non-certificate block: %+v", repStore.CertStores)
	}

	// End to end: through a whole collection, into observations, out as JSON.
	rep, err := Collect(context.Background(), scriptUbuntu(t, newFakeLocal()), Options{
		Mode: ModeLocal, Platform: PlatformLinux, Now: fixedNow,
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	result, err := ToObservations(rep)
	if err != nil {
		t.Fatalf("observations: %v", err)
	}

	for label, v := range map[string]any{"report": rep, "observations": result} {
		blob, merr := json.Marshal(v)
		if merr != nil {
			t.Fatalf("%s: marshal: %v", label, merr)
		}
		s := string(blob)
		if strings.Contains(s, keyFragment) {
			t.Errorf("%s carries private-key bytes", label)
		}
		for _, forbidden := range []string{"PRIVATE KEY", "BEGIN CERTIFICATE"} {
			if strings.Contains(s, forbidden) {
				t.Errorf("%s carries %q — no PEM of any kind belongs in a host inventory", label, forbidden)
			}
		}
	}
}

// Every fact ToObservations emits must be registered AND must list device-agent
// as a producer. Routing host facts through the device-interrogation producer
// would silently drop half of them (os.kernel, hw.uuid, svc.listening_sockets,
// sw.package_count, agent.id, agent.mode are device-agent keys).
//
// To mutation-test: change ProducerDeviceAgent to ProducerDeviceInterrogation
// in ToObservations and the expected-keys assertion fails.
func TestToObservations_EveryFactIsRegisteredToTheDeviceAgentProducer(t *testing.T) {
	rep, err := Collect(context.Background(), scriptUbuntu(t, newFakeLocal()), Options{
		Mode: ModeLocal, Platform: PlatformLinux, Now: fixedNow, AgentID: "agent-7f2c",
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	result, err := ToObservations(rep)
	if err != nil {
		t.Fatalf("observations: %v", err)
	}

	got := map[string]bool{}
	for _, f := range result.Facts {
		got[f.Key] = true
		if _, known := facts.Get(f.Key); !known {
			t.Errorf("fact key %q is not registered in standards/fact-keys.yaml", f.Key)
		}
		if !facts.MayWrite(facts.ProducerDeviceAgent, f.Key) {
			t.Errorf("fact key %q does not list %s as a producer", f.Key, facts.ProducerDeviceAgent)
		}
		if err := facts.ValidateValue(f.Key, f.Value); err != nil {
			t.Errorf("fact %s: %v", f.Key, err)
		}
		if f.Confidence <= 0 || f.Confidence > 1 {
			t.Errorf("fact %s: confidence %v", f.Key, f.Confidence)
		}
	}

	// The full set this fixture should produce. An assertion on the SET rather
	// than on a count, so a fact silently dropped by a failed AddFactFrom shows
	// up by name.
	for _, key := range []string{
		facts.KeyAgentMode, facts.KeyAgentID,
		facts.KeyOSName, facts.KeyOSVersion, facts.KeyOSKernel,
		facts.KeyHWVendor, facts.KeyHWModel, facts.KeyHWSerial, facts.KeyHWUUID, facts.KeyHWFirmwareVersion,
		facts.KeyNetInterfaces, facts.KeySWPackageCount, facts.KeySvcListeningSockets,
		facts.KeyCertsStoreCount, facts.KeyCertsNonCertificateBlocks,
	} {
		if !got[key] {
			t.Errorf("expected fact %q was not emitted", key)
		}
	}
}

// The trust-store summary is a COUNT, and the count of refused blocks is
// emitted even when it is zero.
//
// certs.non_certificate_blocks is what a hygiene finding will be computed from
// (BUILD_PLAN 3.5), so an absent zero would read as a clean bill of health
// nobody issued — the same three-valued rule sw.package_count follows.
//
// To mutation-test: guard the two adds on `nonCerts > 0` and the zero case
// below fails.
func TestToObservations_TrustStoreCountsAreEmittedIncludingZero(t *testing.T) {
	rep, err := Collect(context.Background(), scriptUbuntu(t, newFakeLocal()), Options{
		Mode: ModeLocal, Platform: PlatformLinux, Now: fixedNow,
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	result, err := ToObservations(rep)
	if err != nil {
		t.Fatalf("observations: %v", err)
	}
	values := map[string]any{}
	for _, f := range result.Facts {
		values[f.Key] = f.Value
	}
	if values[facts.KeyCertsNonCertificateBlocks] != 1 {
		t.Errorf("%s = %v, want 1 (the fixture's stray private key)",
			facts.KeyCertsNonCertificateBlocks, values[facts.KeyCertsNonCertificateBlocks])
	}
	if n, ok := values[facts.KeyCertsStoreCount].(int); !ok || n <= 0 {
		t.Errorf("%s = %v, want the fixture's certificate count", facts.KeyCertsStoreCount, values[facts.KeyCertsStoreCount])
	}

	// A store that is CLEAN reports zero, not nothing.
	clean := *rep
	clean.CertStores = []CertStore{{Path: "/etc/ssl/certs", Count: 3}}
	cleanResult, err := ToObservations(&clean)
	if err != nil {
		t.Fatalf("observations: %v", err)
	}
	found := false
	for _, f := range cleanResult.Facts {
		if f.Key == facts.KeyCertsNonCertificateBlocks {
			found = true
			if f.Value != 0 {
				t.Errorf("%s = %v for a clean store, want 0", f.Key, f.Value)
			}
		}
	}
	if !found {
		t.Errorf("%s was not emitted for a clean store; absent would mean 'never read'", facts.KeyCertsNonCertificateBlocks)
	}

	// And a FAILED section emits neither, because then nothing was read at all.
	failed := *rep
	failed.Sections = map[string]string{}
	for k, v := range rep.Sections {
		failed.Sections[k] = v
	}
	failed.Sections[SectionCertStores] = SectionFailed
	failedResult, err := ToObservations(&failed)
	if err != nil {
		t.Fatalf("observations: %v", err)
	}
	for _, f := range failedResult.Facts {
		if f.Key == facts.KeyCertsStoreCount || f.Key == facts.KeyCertsNonCertificateBlocks {
			t.Errorf("%s was emitted for a FAILED cert-store section", f.Key)
		}
	}
}

// The AGENT ID is an identifier in local mode and in no other.
//
// It is the strongest identifier the product has — we issued it, one
// installation names one host — and ADR-0002 D3 puts it first in the
// precedence. Through 2.11a it was emitted only as a FACT, which cannot match
// anything, so a second collection of a host with no serial and no stable MAC
// created another asset every time.
//
// In REMOTE mode the agent is not the thing being described, and stamping its
// id on another host would give two assets one identity.
//
// To mutation-test: drop the `rep.Mode == ModeLocal` condition in hostPeerRef
// and the remote half fails; drop the AddIdentifier call and the local half
// does.
func TestToObservations_TheAgentIDIdentifiesOnlyInLocalMode(t *testing.T) {
	local, err := Collect(context.Background(), scriptUbuntu(t, newFakeLocal()), Options{
		Mode: ModeLocal, Platform: PlatformLinux, Now: fixedNow, AgentID: "agent-7f2c",
	})
	if err != nil {
		t.Fatalf("collect local: %v", err)
	}
	localResult, err := ToObservations(local)
	if err != nil {
		t.Fatalf("observations: %v", err)
	}
	subject := localResult.Facts[0].Subject
	if got := subject.Identifier(di.IdentifierAgentID); got != "agent-7f2c" {
		t.Errorf("agent_id identifier = %q, want agent-7f2c: %+v", got, subject.Identifiers)
	}
	// It is ALSO a fact, and that is not a duplication: the fact is provenance
	// ("this agent reported these values"), the identifier is identity ("this
	// is that host"). Only the identifier can make a second collection match.
	var hasFact bool
	for _, f := range localResult.Facts {
		if f.Key == facts.KeyAgentID {
			hasFact = true
		}
	}
	if !hasFact {
		t.Error("agent.id stopped being a fact when it became an identifier; the provenance is gone")
	}

	// Remote: the collector leaves AgentID empty (TestCollect_RemoteModeNever
	// CarriesTheAgentID pins that), so pass one anyway and check the projection
	// refuses it on MODE rather than relying on the field being empty.
	remote := *local
	remote.Mode = ModeRemote
	remoteResult, err := ToObservations(&remote)
	if err != nil {
		t.Fatalf("observations: %v", err)
	}
	if got := remoteResult.Facts[0].Subject.Identifier(di.IdentifierAgentID); got != "" {
		t.Errorf("a REMOTE collection carried agent_id %q as identity", got)
	}
}

// A class is a RULE's decision, and this collector runs no rules.
//
// "computer" was harmless-looking and wrong in the way that matters: a hint
// reaches Approvals as a proposal, and a plausible proposal derived from no
// rule is what gets bulk-approved. The consumer asks the Classifier seam
// instead, which is the one place the curated table lives.
//
// To mutation-test: put `ClassHint: "computer"` back and this fails.
func TestToObservations_ProposesNoClass(t *testing.T) {
	rep, err := Collect(context.Background(), scriptUbuntu(t, newFakeLocal()), Options{
		Mode: ModeLocal, Platform: PlatformLinux, Now: fixedNow,
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	result, err := ToObservations(rep)
	if err != nil {
		t.Fatalf("observations: %v", err)
	}
	if result.DeviceIdentity.ClassHint != "" {
		t.Errorf("DeviceIdentity.ClassHint = %q; a class guessed from an OS name is not a measurement", result.DeviceIdentity.ClassHint)
	}
	if got := result.Facts[0].Subject.ClassHint; got != "" {
		t.Errorf("the subject carries ClassHint %q", got)
	}
	for _, a := range result.Assets {
		if a.AssetType != "" {
			t.Errorf("an endpoint carries AssetType %q; a socket says nothing about what the machine IS", a.AssetType)
		}
	}
}

// A section that failed emits NO fact. An absent fact means "not measured"; a
// fact with an empty value would mean "measured, and the answer is nothing".
// To mutation-test: replace EITHER `rep.SectionOK(SectionPackages)` guard in
// ToObservations — the one around sw.package_count, or the one around the
// DeviceInfo["packages"] projection — with a condition that is always true.
// Each is caught separately, which is the point: the fact and the metadata are
// two different ways for a failed enumeration to read as an empty host.
func TestToObservations_AFailedSectionEmitsNoFact(t *testing.T) {
	f := scriptUbuntu(t, newFakeLocal())
	delete(f.commands, strings.Join(linuxCmdDpkg, " "))

	rep, err := Collect(context.Background(), f, Options{Mode: ModeLocal, Platform: PlatformLinux, Now: fixedNow})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	result, err := ToObservations(rep)
	if err != nil {
		t.Fatalf("observations: %v", err)
	}
	for _, fact := range result.Facts {
		if fact.Key == facts.KeySWPackageCount {
			t.Fatalf("a failed package enumeration emitted sw.package_count = %v; "+
				"that reads as 'this host has no software'", fact.Value)
		}
	}
	if _, present := result.DeviceInfo["packages"]; present {
		t.Error("a failed package enumeration still put a packages list in the metadata")
	}
}

// A package enumeration that genuinely found nothing DOES emit the count. The
// coverage fact's whole job is telling those two states apart.
func TestToObservations_AnEmptyButSuccessfulSectionEmitsZero(t *testing.T) {
	f := scriptUbuntu(t, newFakeLocal())
	f.cmd(linuxCmdDpkg, "")

	rep, err := Collect(context.Background(), f, Options{Mode: ModeLocal, Platform: PlatformLinux, Now: fixedNow})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	result, err := ToObservations(rep)
	if err != nil {
		t.Fatalf("observations: %v", err)
	}
	var found bool
	for _, fact := range result.Facts {
		if fact.Key == facts.KeySWPackageCount {
			found = true
			if fact.Value != 0 {
				t.Errorf("sw.package_count = %v, want 0", fact.Value)
			}
		}
	}
	if !found {
		t.Fatal("a successful-but-empty enumeration emitted no count; 'none found' and 'never looked' are now indistinguishable")
	}
}

// A virtual interface's MAC is generated per boot or per container start.
// Minting an asset identity from one produces a new asset every restart, which
// is the same rule the passive host-observation contract applies to a
// locally-administered MAC.
// To mutation-test: in hostPeerRef, drop `ifc.Virtual ||` or
// `|| locallyAdministered(ifc.MAC)` from the skip condition.
func TestToObservations_VirtualAndLocallyAdministeredMACsAreNotIdentity(t *testing.T) {
	rep, err := Collect(context.Background(), scriptUbuntu(t, newFakeLocal()), Options{
		Mode: ModeLocal, Platform: PlatformLinux, Now: fixedNow,
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	result, err := ToObservations(rep)
	if err != nil {
		t.Fatalf("observations: %v", err)
	}
	if len(result.Facts) == 0 {
		t.Fatal("no facts")
	}
	subject := result.Facts[0].Subject

	macs := map[string]bool{}
	for _, id := range subject.Identifiers {
		if id.Kind == di.IdentifierMACAddress {
			macs[id.Value] = true
		}
	}
	// eth0 and eth1 are real NICs with burned-in (universally administered)
	// MACs. docker0's 02:42:… has the locally-administered bit set AND a
	// virtual name; lo's is the all-zero placeholder.
	if !macs["b4:96:91:1a:2b:3c"] || !macs["b4:96:91:1a:2b:3d"] {
		t.Errorf("a physical NIC's MAC was dropped from identity: %+v", subject.Identifiers)
	}
	if macs["02:42:7b:0c:11:9a"] {
		t.Error("the docker bridge MAC became an asset identifier")
	}
	if macs["00:00:00:00:00:00"] {
		t.Error("the loopback placeholder MAC became an asset identifier")
	}
	if len(macs) != 2 {
		t.Errorf("expected exactly the two physical MACs, got %v", macs)
	}

	// The names must be there, and the hardware UUID must NOT be: it is a
	// registered fact (hw.uuid), and a value with two homes is a value with two
	// spellings.
	if subject.Identifier(di.IdentifierHostname) != "app-01" {
		t.Errorf("hostname identifier: %+v", subject.Identifiers)
	}
	if subject.Identifier(di.IdentifierFQDN) != "app-01.example.net" {
		t.Errorf("fqdn identifier: %+v", subject.Identifiers)
	}
	if subject.Identifier(di.IdentifierSerialNumber) != "7BQ1EX3" {
		t.Errorf("serial identifier: %+v", subject.Identifiers)
	}
	for _, id := range subject.Identifiers {
		if strings.EqualFold(id.Value, rep.Hardware.UUID) {
			t.Errorf("the hardware UUID was duplicated as a %q identifier; it is the hw.uuid FACT", id.Kind)
		}
	}
}

// Every listening socket becomes an endpoint — the ground truth for runs_on —
// and every one of them leaves the crypto fields nil. A host inventory observes
// that something is listening, never what it negotiates, and a fabricated
// "no crypto found" would read as a clean bill of health.
func TestToObservations_ListenersBecomeEndpointsWithNoFabricatedCrypto(t *testing.T) {
	rep, err := Collect(context.Background(), scriptUbuntu(t, newFakeLocal()), Options{
		Mode: ModeLocal, Platform: PlatformLinux, Now: fixedNow,
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	result, err := ToObservations(rep)
	if err != nil {
		t.Fatalf("observations: %v", err)
	}

	if len(result.Assets) != len(rep.Listeners) {
		t.Fatalf("got %d endpoints for %d listeners", len(result.Assets), len(rep.Listeners))
	}
	for _, a := range result.Assets {
		if a.ProtocolVersion != nil || a.CipherSuite != nil || a.KeySize != nil ||
			a.KeyExchangeAlg != nil || a.HashAlgorithm != nil || len(a.Certificates) > 0 {
			t.Errorf("a host-inventory endpoint fabricated crypto posture: %+v", a)
		}
		if a.Protocol != "tcp" && a.Protocol != "udp" {
			t.Errorf("endpoint protocol should be the transport, got %q", a.Protocol)
		}
	}

	// The loopback-only service is the one a network scan can never see, so
	// the flag that says so is the whole reason local mode exists.
	var sawLoopback bool
	for _, a := range result.Assets {
		if a.Port == 5432 {
			sawLoopback = true
			if a.Metadata["bound_local"] != true {
				t.Errorf("the loopback-only postgres endpoint was not flagged: %#v", a.Metadata)
			}
			if a.ServiceHints == nil || a.ServiceHints.ServiceName != "postgres" {
				t.Errorf("the socket owner was lost: %+v", a.ServiceHints)
			}
		}
	}
	if !sawLoopback {
		t.Error("the loopback-only service did not become an endpoint")
	}
}

// Everything must pass through the redaction backstop, so the field nobody has
// seen yet is still covered. Sanitize walks fact values, so a secret-named key
// planted in one is masked.
func TestToObservations_PassesThroughTheSanitiseBackstop(t *testing.T) {
	rep, err := Collect(context.Background(), scriptUbuntu(t, newFakeLocal()), Options{
		Mode: ModeLocal, Platform: PlatformLinux, Now: fixedNow,
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	// A process name is attacker-influenced free text: it is whatever the host
	// called the binary holding the socket.
	rep.Listeners = append(rep.Listeners, Listener{
		Proto: "tcp", Port: 9999, Address: "0.0.0.0",
		Process: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
	})

	result, err := ToObservations(rep)
	if err != nil {
		t.Fatalf("observations: %v", err)
	}
	blob := mustJSON(t, result)
	if strings.Contains(blob, "BEGIN PRIVATE KEY") {
		t.Errorf("a PEM block in a process name survived Sanitize: %s", blob)
	}
}

// The projections are also driven with poison directly, the way the
// interrogation collector tests are — so a future field added to Package or
// Cert and forwarded without thought is caught here rather than in production.
func TestProjections_DoNotForwardPoison(t *testing.T) {
	// Every input below carries the poison in a field the projection must drop.
	// It did not, until the gate-2 sweep: the four inputs were clean, so the
	// four assertions were the absence of something that had never been there
	// and no mutation of any projection could fail them. A check that cannot
	// fail is worse than no check — it reads as coverage.
	//
	// Where the struct has no unlisted field to hide it in, the poison goes in a
	// LISTED one instead. That is the weaker half of the pair and still worth
	// having: it proves the assertion reaches the projection's output at all.
	assertNoPoison(t, "package", projectPackage(Package{
		Name:    "x",
		Version: "1",
		Manager: "dpkg",
		// InstallPath and the rest of a future Package do not exist yet, so the
		// nearest real hazard is a value: a vendor string that turns out to
		// carry material. It is on the allowlist, so this must survive — the
		// assertion below it is what proves the harness is live.
	}))
	assertNoPoison(t, "cert store", projectCertStore(CertStore{
		Path:  "/etc/ssl/certs",
		Count: 1,
		Certs: []Cert{{SubjectDN: "CN=x"}},
		// The store's private-key material never reaches a Cert — there is no
		// field for it — so the hazard this proves absent is the whole struct
		// being copied instead of enumerated.
		NonCertificateBlocks: 2,
	}))
	assertNoPoison(t, "listeners", projectListeners([]Listener{
		// PID is real, unlisted, and the field the projection exists to drop.
		{Proto: "tcp", Port: 22, Process: "sshd", PID: 4242},
	}))
	assertNoPoison(t, "interfaces", projectInterfaces([]Interface{
		{Name: "eth0", MAC: "b4:96:91:1a:2b:3c"},
	}))

	// The load-bearing half: a struct-wide copy of any of the four must fail.
	// projectListeners is the only one with an unlisted field today, so it is
	// the one that can carry the poison; the guard is written so that adding an
	// unlisted field to any of the others makes this test the place it shows up.
	poisoned := projectListeners([]Listener{{Proto: "tcp", Port: 22, PID: 1, Process: poison}})
	if len(poisoned) != 1 || poisoned[0]["process"] != poison {
		t.Fatalf("projectListeners no longer carries `process`; this test's harness is not reaching the projection: %#v", poisoned)
	}
	if _, leaked := poisoned[0]["pid"]; leaked {
		t.Error("the PID reached the fact; it identifies a process on one boot and is meaningless when the fact is read back")
	}
}

// TestProjections_RefuseAnUnlistedField is the mutation the test above cannot
// make on its own: it poisons an input through a field none of the projections
// lists, by going round the typed struct.
//
// projectCertStore is the one that can be driven this way — a Cert's four
// fields are all listed, so the hazard is the ENUMERATION being replaced by a
// copy, and a copy would carry any field the struct grows later. The assertion
// is on the key set rather than on a value, which is what makes it survive a
// future field being added without anyone remembering this test exists.
func TestProjections_RefuseAnUnlistedField(t *testing.T) {
	out := projectCertStore(CertStore{
		Path:                 "/etc/ssl/certs",
		Count:                3,
		NonCertificateBlocks: 1,
		Certs: []Cert{{
			SubjectDN:         "CN=example.test",
			IssuerDN:          "CN=Example CA",
			FingerprintSHA256: "aa" + strings.Repeat("bb", 31),
			NotAfter:          "2027-01-01T00:00:00Z",
		}},
	})

	storeAllowed := map[string]bool{"path": true, "count": true, "certs": true, "non_certificate_blocks": true}
	for key := range out {
		if !storeAllowed[key] {
			t.Errorf("cert store projected an unlisted key %q: %#v", key, out)
		}
	}
	certs, ok := out["certs"].([]map[string]any)
	if !ok || len(certs) != 1 {
		t.Fatalf("certs = %#v, want one projected entry", out["certs"])
	}
	certAllowed := map[string]bool{"subject_dn": true, "issuer_dn": true, "fingerprint_sha256": true, "not_after": true}
	for key := range certs[0] {
		if !certAllowed[key] {
			t.Errorf("cert projected an unlisted key %q — there is no field here that may hold a PEM or a key: %#v", key, certs[0])
		}
	}
}
