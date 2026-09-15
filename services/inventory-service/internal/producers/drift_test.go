package producers

// The drift producer's DECISIONS, without a database.
//
// The judge phase is arithmetic over what the read phase returned, and every
// mistake worth making lives here: a window comparison the wrong way round, a
// subject with no baseline reported as having changed, an observation key that
// drops entries and makes two different changes compare equal. The integration
// tests beside this file prove the lifecycle; these prove the judgement.

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/findings"
)

var (
	testNow    = time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	testCutoff = testNow.AddDate(0, 0, -30)
)

func newInput() *driftInput {
	return &driftInput{baselineDays: 30, now: testNow, cutoff: testCutoff}
}

func testDriftProducer(t *testing.T) *DriftProducer {
	t.Helper()
	p, err := NewDriftProducer(nil)
	if err != nil {
		t.Fatalf("NewDriftProducer: %v", err)
	}
	p.now = func() time.Time { return testNow }
	return p
}

// asset adds one asset to the population.
func (in *driftInput) asset(id uuid.UUID, class string, seg uuid.NullUUID, firstSeen time.Time) *driftInput {
	in.assets = append(in.assets, driftAsset{
		id: id, label: "host-" + id.String()[:4], classKey: class,
		segmentID: seg, segmentName: "seg", firstSeen: firstSeen,
	})
	return in
}

func seg(id uuid.UUID) uuid.NullUUID { return uuid.NullUUID{UUID: id, Valid: true} }

func plannedOf(planned []plannedDrift, kind string) []plannedDrift {
	var out []plannedDrift
	for _, p := range planned {
		if p.finding.Kind == kind {
			out = append(out, p)
		}
	}
	return out
}

// --- the window, both ways --------------------------------------------------

// The one comparison that decides everything, pinned at the boundary in both
// directions. Flip `warmedUp`'s `!...After` to `...Before` and this goes red.
func TestWarmedUp_BoundaryBothWays(t *testing.T) {
	cutoff := testCutoff
	cases := []struct {
		name     string
		earliest time.Time
		want     bool
	}{
		{"a year of history", cutoff.AddDate(-1, 0, 0), true},
		{"one microsecond of baseline", cutoff.Add(-time.Microsecond), true},
		// Exactly ON the cutoff: everything this tenant owns is inside the
		// window and the baseline is empty. Warming up, same rule as a subject
		// with no baseline of its own.
		{"oldest observation exactly at the cutoff", cutoff, false},
		{"one microsecond short of a window", cutoff.Add(time.Microsecond), false},
		{"onboarded this morning", testNow, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := warmedUp(tc.earliest, cutoff); got != tc.want {
				t.Errorf("warmedUp(%v, %v) = %v, want %v", tc.earliest, cutoff, got, tc.want)
			}
		})
	}
}

// The same boundary on the judgement itself: an observation one instant older
// than the cutoff is BASELINE, one instant newer is DRIFT. Both asserted,
// because a test that only pins the drift side passes with a producer that
// calls everything drift.
func TestJudgeUnexpectedProtocol_WindowBoundaryBothWays(t *testing.T) {
	p := testDriftProducer(t)
	assetID := uuid.New()

	for _, tc := range []struct {
		name      string
		firstSeen time.Time
		wantDrift bool
	}{
		{"one instant inside the window", testCutoff.Add(time.Microsecond), true},
		// The window is [cutoff, now] and the baseline is everything strictly
		// older, so an observation exactly ON the cutoff is inside the window.
		{"exactly at the cutoff", testCutoff, true},
		{"one instant before the cutoff", testCutoff.Add(-time.Microsecond), false},
		{"a day before the cutoff", testCutoff.AddDate(0, 0, -1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := newInput().asset(assetID, assetclass.KeyServer, uuid.NullUUID{}, testNow.AddDate(-1, 0, 0))
			in.protos = []protoObservation{
				// The baseline: this asset has been speaking TLS for a year.
				{assetID: assetID, protocol: "TLS", firstSeen: testNow.AddDate(-1, 0, 0), live: true, source: "endpoint", refID: uuid.New()},
				{assetID: assetID, protocol: "SSH", firstSeen: tc.firstSeen, live: true, source: "endpoint", refID: uuid.New()},
			}
			var run DriftRun
			got := plannedOf(p.judge(in, &run), findings.KindUnexpectedProtocol)
			if tc.wantDrift && len(got) != 1 {
				t.Fatalf("%d unexpected_protocol findings, want 1", len(got))
			}
			if !tc.wantDrift && len(got) != 0 {
				t.Fatalf("%d unexpected_protocol findings, want 0 — SSH is inside the baseline", len(got))
			}
			if tc.wantDrift && !strings.Contains(got[0].finding.Summary, "SSH") {
				t.Errorf("summary %q does not name the protocol", got[0].finding.Summary)
			}
		})
	}
}

// --- per-subject baseline ---------------------------------------------------

// An asset with nothing observed before the window has no baseline, and
// "everything about it is new" is not an answer. Counted, not silently dropped.
func TestJudge_SubjectWithNoBaselineIsCountedNotReported(t *testing.T) {
	p := testDriftProducer(t)
	assetID := uuid.New()
	// The asset arrived inside the window; the tenant did not (the tenant-level
	// warm-up is decided in read(), not here).
	in := newInput().asset(assetID, assetclass.KeyServer, uuid.NullUUID{}, testNow.AddDate(0, 0, -3))
	in.protos = []protoObservation{
		{assetID: assetID, protocol: "SSH", firstSeen: testNow.AddDate(0, 0, -3), live: true, source: "endpoint", refID: uuid.New()},
	}
	in.ports = []portObservation{
		{assetID: assetID, port: 22, transport: "tcp", firstSeen: testNow.AddDate(0, 0, -3), lastSeen: testNow, active: true},
	}
	in.issuers = []issuerObservation{
		{assetID: assetID, certID: uuid.New(), issuerDN: "CN=Example CA", fingerprint: strings.Repeat("a", 64),
			firstSeen: testNow.AddDate(0, 0, -3), live: true},
	}

	var run DriftRun
	planned := p.judge(in, &run)
	if len(planned) != 0 {
		t.Fatalf("%d findings for an asset with no history before the window; the first thing an asset does is not a CHANGE", len(planned))
	}
	// Three kinds each declined for want of a baseline.
	if run.NoBaseline != 3 {
		t.Errorf("run.NoBaseline = %d, want 3 — 'we could not compare' has to be reported, not swallowed", run.NoBaseline)
	}
}

// --- new_class_in_segment ---------------------------------------------------

func TestJudgeNewClassInSegment_FirstOfItsClassOnly(t *testing.T) {
	p := testDriftProducer(t)
	segID := uuid.New()
	old := testNow.AddDate(0, 0, -200)
	// Three printers arrive inside the window onto a segment that has only ever
	// held servers.
	first := uuid.New()
	second := uuid.New()
	third := uuid.New()
	in := newInput().
		asset(uuid.New(), assetclass.KeyServer, seg(segID), old).
		asset(second, assetclass.KeyPrinter, seg(segID), testNow.AddDate(0, 0, -4)).
		asset(first, assetclass.KeyPrinter, seg(segID), testNow.AddDate(0, 0, -9)).
		asset(third, assetclass.KeyPrinter, seg(segID), testNow.AddDate(0, 0, -1))

	var run DriftRun
	got := plannedOf(p.judge(in, &run), findings.KindNewClassInSegment)
	if len(got) != 1 {
		t.Fatalf("%d new_class_in_segment findings, want 1 — three printers arriving is one thing to go and look at", len(got))
	}
	if got[0].finding.Subject.ID != first {
		t.Errorf("the finding is on %s, want the EARLIEST arrival %s", got[0].finding.Subject.ID, first)
	}
	observed, _ := got[0].finding.Evidence["observed"].(map[string]any)
	if observed["assets_in_window"] != 3 {
		t.Errorf("evidence.observed.assets_in_window = %v, want 3 — the other two are counted, not hidden", observed["assets_in_window"])
	}
	if observed["class"] != assetclass.KeyPrinter {
		t.Errorf("evidence.observed.class = %v, want %q", observed["class"], assetclass.KeyPrinter)
	}
	if !strings.Contains(got[0].finding.Summary, "Printer") {
		t.Errorf("summary %q does not carry the class LABEL", got[0].finding.Summary)
	}
}

func TestJudgeNewClassInSegment_ClassAlreadyOnTheSegmentIsNotDrift(t *testing.T) {
	p := testDriftProducer(t)
	segID := uuid.New()
	in := newInput().
		asset(uuid.New(), assetclass.KeyPrinter, seg(segID), testNow.AddDate(0, 0, -200)).
		asset(uuid.New(), assetclass.KeyPrinter, seg(segID), testNow.AddDate(0, 0, -2))

	var run DriftRun
	if got := plannedOf(p.judge(in, &run), findings.KindNewClassInSegment); len(got) != 0 {
		t.Fatalf("%d findings; the segment has held printers for 200 days", len(got))
	}
}

func TestJudgeNewClassInSegment_PlaceholderClassIsSkipped(t *testing.T) {
	p := testDriftProducer(t)
	segID := uuid.New()
	in := newInput().
		asset(uuid.New(), assetclass.KeyServer, seg(segID), testNow.AddDate(0, 0, -200)).
		asset(uuid.New(), assetclass.KeyUnknownHost, seg(segID), testNow.AddDate(0, 0, -2))

	var run DriftRun
	if got := plannedOf(p.judge(in, &run), findings.KindNewClassInSegment); len(got) != 0 {
		t.Fatalf("%d findings; 'the first unclassified host on this segment' is a statement about our coverage, not the tenant's network", len(got))
	}
}

func TestJudgeNewClassInSegment_SegmentYoungerThanTheWindowIsNotEvaluated(t *testing.T) {
	p := testDriftProducer(t)
	segID := uuid.New()
	in := newInput().
		asset(uuid.New(), assetclass.KeyServer, seg(segID), testNow.AddDate(0, 0, -3)).
		asset(uuid.New(), assetclass.KeyPrinter, seg(segID), testNow.AddDate(0, 0, -2))

	var run DriftRun
	got := plannedOf(p.judge(in, &run), findings.KindNewClassInSegment)
	if len(got) != 0 {
		t.Fatalf("%d findings on a segment nothing predates the window on", len(got))
	}
	if run.NoBaseline == 0 {
		t.Error("the un-evaluable segment was not counted")
	}
}

// --- port_profile_changed ---------------------------------------------------

func TestJudgePortProfile_OpenedAndClosedBothFire(t *testing.T) {
	p := testDriftProducer(t)
	assetID := uuid.New()
	old := testNow.AddDate(0, 0, -200)
	in := newInput().asset(assetID, assetclass.KeyServer, uuid.NullUUID{}, old)
	in.ports = []portObservation{
		// baseline, still open
		{assetID: assetID, port: 443, transport: "tcp", firstSeen: old, lastSeen: testNow, active: true},
		// baseline, closed INSIDE the window
		{assetID: assetID, port: 8080, transport: "tcp", firstSeen: old, lastSeen: testNow.AddDate(0, 0, -2), active: false},
		// opened inside the window
		{assetID: assetID, port: 22, transport: "tcp", firstSeen: testNow.AddDate(0, 0, -5), lastSeen: testNow, active: true},
		// closed LONG ago: history, not drift
		{assetID: assetID, port: 9999, transport: "tcp", firstSeen: old, lastSeen: testNow.AddDate(0, 0, -120), active: false},
	}

	var run DriftRun
	got := plannedOf(p.judge(in, &run), findings.KindPortProfileChanged)
	if len(got) != 1 {
		t.Fatalf("%d port_profile_changed findings, want 1", len(got))
	}
	observed, _ := got[0].finding.Evidence["observed"].(map[string]any)
	opened, _ := observed["opened"].([]string)
	closed, _ := observed["closed"].([]string)
	if len(opened) != 1 || opened[0] != "22" {
		t.Errorf("opened = %v, want [22]", opened)
	}
	if len(closed) != 1 || closed[0] != "8080" {
		t.Errorf("closed = %v, want [8080] — 9999 stopped answering before the window and is history", closed)
	}
	if !strings.Contains(got[0].finding.Summary, "+22") || !strings.Contains(got[0].finding.Summary, "-8080") {
		t.Errorf("summary %q does not show both directions", got[0].finding.Summary)
	}
}

// A port-profile finding names the ENDPOINT ROWS behind the delta, not only the
// port numbers.
//
// Without them "8080 opened" on a host with four addresses leaves the reader to
// work out which face it appeared on, and the finding — which is about
// `asset_endpoints` rows — could not say. Two shapes: scalar labels the drawer
// renders by joining, and objects carrying `endpoint_id` for the drill-through.
func TestJudgePortProfile_EvidenceNamesTheEndpointsThatChanged(t *testing.T) {
	p := testDriftProducer(t)
	assetID := uuid.New()
	old := testNow.AddDate(0, 0, -200)
	openedEP := uuid.New()
	closedEP := uuid.New()

	in := newInput().asset(assetID, assetclass.KeyServer, uuid.NullUUID{}, old)
	in.ports = []portObservation{
		{assetID: assetID, endpointID: uuid.New(), address: "198.51.100.7", port: 443, transport: "tcp",
			firstSeen: old, lastSeen: testNow, active: true},
		{assetID: assetID, endpointID: closedEP, address: "198.51.100.7", port: 8080, transport: "tcp",
			firstSeen: old, lastSeen: testNow.AddDate(0, 0, -2), active: false},
		{assetID: assetID, endpointID: openedEP, fqdn: "web01.example.test", port: 22, transport: "tcp",
			firstSeen: testNow.AddDate(0, 0, -5), lastSeen: testNow, active: true},
	}

	var run DriftRun
	got := plannedOf(p.judge(in, &run), findings.KindPortProfileChanged)
	if len(got) != 1 {
		t.Fatalf("%d port_profile_changed findings, want 1", len(got))
	}
	observed, _ := got[0].finding.Evidence["observed"].(map[string]any)

	// The readable half: an address (or the name it answers on) with the port.
	openedLabels, _ := observed["opened_endpoints"].([]any)
	if len(openedLabels) != 1 || openedLabels[0] != "web01.example.test:22" {
		t.Errorf("opened_endpoints = %v, want [web01.example.test:22]", openedLabels)
	}
	closedLabels, _ := observed["closed_endpoints"].([]any)
	if len(closedLabels) != 1 || closedLabels[0] != "198.51.100.7:8080" {
		t.Errorf("closed_endpoints = %v, want [198.51.100.7:8080]", closedLabels)
	}

	// The drill-through half: the endpoint ids, each labelled with which way it
	// went. This is what makes the finding reach the row it is about.
	rows, _ := observed["endpoints"].([]any)
	if len(rows) != 2 {
		t.Fatalf("endpoints = %v, want one entry per changed endpoint", rows)
	}
	byID := map[string]map[string]any{}
	for _, r := range rows {
		m, _ := r.(map[string]any)
		id, _ := m["endpoint_id"].(string)
		byID[id] = m
	}
	if m := byID[openedEP.String()]; m == nil || m["change"] != "opened" {
		t.Errorf("the opened endpoint is not in the evidence as opened: %v", rows)
	} else if m["fqdn"] != "web01.example.test" {
		t.Errorf("the opened endpoint lost its fqdn: %v", m)
	} else if _, hasAddr := m["address"]; hasAddr {
		t.Errorf("an endpoint with no address carries an empty one, which reads as a blank: %v", m)
	}
	if m := byID[closedEP.String()]; m == nil || m["change"] != "closed" {
		t.Errorf("the closed endpoint is not in the evidence as closed: %v", rows)
	} else if m["address"] != "198.51.100.7" {
		t.Errorf("the closed endpoint lost its address: %v", m)
	}
}

// The same port on two addresses is two endpoint rows and ONE port in the
// profile. Without the fold, a host that changed IP reports 443 as opened and
// closed at once.
//
// BOTH row orders, because the database returns them in neither: a fold written
// as `agg.anyActive = o.active` gives the right answer whenever the live row
// happens to arrive last, and the wrong one the rest of the time. One ordering
// is a test that passes by luck.
func TestJudgePortProfile_SamePortOnTwoAddressesIsOnePort(t *testing.T) {
	p := testDriftProducer(t)
	assetID := uuid.New()
	old := testNow.AddDate(0, 0, -200)

	gone := portObservation{assetID: assetID, port: 443, transport: "tcp",
		firstSeen: old, lastSeen: testNow.AddDate(0, 0, -1), active: false}
	moved := portObservation{assetID: assetID, port: 443, transport: "tcp",
		firstSeen: testNow.AddDate(0, 0, -1), lastSeen: testNow, active: true}
	settled := portObservation{assetID: assetID, port: 22, transport: "tcp",
		firstSeen: old, lastSeen: testNow, active: true}

	for _, tc := range []struct {
		name  string
		ports []portObservation
	}{
		{"old address first", []portObservation{gone, moved, settled}},
		{"new address first", []portObservation{moved, gone, settled}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := newInput().asset(assetID, assetclass.KeyServer, uuid.NullUUID{}, old)
			in.ports = tc.ports
			var run DriftRun
			got := plannedOf(p.judge(in, &run), findings.KindPortProfileChanged)
			if len(got) != 0 {
				t.Fatalf("%d findings: %q — 443 moved address, it did not open or close",
					len(got), got[0].finding.Summary)
			}
		})
	}
}

// --- new_issuer -------------------------------------------------------------

func TestJudgeNewIssuer_NewCAOnAnAssetWithHistory(t *testing.T) {
	p := testDriftProducer(t)
	assetID := uuid.New()
	old := testNow.AddDate(0, 0, -200)
	newCert := uuid.New()
	in := newInput().asset(assetID, assetclass.KeyServer, uuid.NullUUID{}, old)
	in.issuers = []issuerObservation{
		{assetID: assetID, certID: uuid.New(), issuerDN: "CN=Old CA, O=Example Ltd", fingerprint: strings.Repeat("a", 64), firstSeen: old, live: true},
		{assetID: assetID, certID: newCert, issuerDN: "CN=Surprise CA, O=Nobody", fingerprint: strings.Repeat("b", 64),
			firstSeen: testNow.AddDate(0, 0, -2), live: true},
	}

	var run DriftRun
	got := plannedOf(p.judge(in, &run), findings.KindNewIssuer)
	if len(got) != 1 {
		t.Fatalf("%d new_issuer findings, want 1", len(got))
	}
	if !strings.Contains(got[0].finding.Summary, "Surprise CA") {
		t.Errorf("summary %q does not name the new issuer by its CN", got[0].finding.Summary)
	}
	// The citation: which certificate, by fingerprint. Never the PEM.
	raw, _ := got[0].finding.Evidence["observed"].(map[string]any)
	detail, _ := raw["detail"].([]map[string]any)
	if len(detail) != 1 {
		t.Fatalf("evidence.observed.detail has %d entries, want 1", len(detail))
	}
	certs, _ := detail[0]["certificates"].([]map[string]any)
	if len(certs) != 1 || certs[0]["certificate_id"] != newCert.String() {
		t.Errorf("the finding does not name the certificate it is about: %v", certs)
	}
	for _, e := range evidenceStrings(got[0].finding.Evidence) {
		if strings.Contains(e, "BEGIN CERTIFICATE") {
			t.Fatal("a certificate body reached the finding's evidence")
		}
	}
}

func TestJudgeNewIssuer_SameCAReissuingIsNotDrift(t *testing.T) {
	p := testDriftProducer(t)
	assetID := uuid.New()
	old := testNow.AddDate(0, 0, -200)
	in := newInput().asset(assetID, assetclass.KeyServer, uuid.NullUUID{}, old)
	in.issuers = []issuerObservation{
		{assetID: assetID, certID: uuid.New(), issuerDN: "CN=Example CA", fingerprint: strings.Repeat("a", 64), firstSeen: old, live: false},
		// A renewal from the same CA, inside the window: a different certificate,
		// the same issuer.
		{assetID: assetID, certID: uuid.New(), issuerDN: "CN=Example CA", fingerprint: strings.Repeat("b", 64),
			firstSeen: testNow.AddDate(0, 0, -2), live: true},
	}

	var run DriftRun
	if got := plannedOf(p.judge(in, &run), findings.KindNewIssuer); len(got) != 0 {
		t.Fatalf("%d findings; renewing from the CA you already use is not a new issuer", len(got))
	}
}

// --- the observation key ----------------------------------------------------

// The key has to change when the observation does, and stay the same when it
// does not — it is what decides whether a person's "resolved" still applies.
func TestObservationKey_TracksTheObservation(t *testing.T) {
	p := testDriftProducer(t)
	assetID := uuid.New()
	old := testNow.AddDate(0, 0, -200)

	key := func(protocols ...string) string {
		in := newInput().asset(assetID, assetclass.KeyServer, uuid.NullUUID{}, old)
		in.protos = []protoObservation{
			{assetID: assetID, protocol: "TLS", firstSeen: old, live: true, source: "endpoint", refID: uuid.New()},
		}
		for _, proto := range protocols {
			in.protos = append(in.protos, protoObservation{
				assetID: assetID, protocol: proto, firstSeen: testNow.AddDate(0, 0, -2),
				live: true, source: "endpoint", refID: uuid.New(),
			})
		}
		var run DriftRun
		got := plannedOf(p.judge(in, &run), findings.KindUnexpectedProtocol)
		if len(got) != 1 {
			t.Fatalf("%d findings for %v, want 1", len(got), protocols)
		}
		return got[0].observationKey
	}

	ssh := key("SSH")
	if key("SSH") != ssh {
		t.Error("the same observation produced two different keys — a resolved finding would re-open on every pass")
	}
	// Order of arrival must not change the key either.
	if key("SSH", "SMB") != key("SMB", "SSH") {
		t.Error("the key depends on row order — the same observation would compare unequal to itself")
	}
	if key("SSH", "SMB") == ssh {
		t.Error("a genuinely different observation produced the same key — a new protocol would be swallowed by an earlier 'resolved'")
	}
}

// The port delta's key must carry the WHOLE change, even where the title is
// truncated. Otherwise two different changes compare equal and one person's
// decision silently covers the other.
func TestPortDelta_KeyIsCompleteWhileTheTitleIsCapped(t *testing.T) {
	opened := []portKey{{port: 1, transport: "tcp"}, {port: 2, transport: "tcp"}, {port: 3, transport: "tcp"},
		{port: 4, transport: "tcp"}, {port: 5, transport: "tcp"}, {port: 6, transport: "tcp"}, {port: 7, transport: "tcp"}}
	full := portDelta(opened, nil, 0)
	title := portDelta(opened, nil, maxPortsInTitle)

	if !strings.Contains(full, "+7") {
		t.Errorf("the uncapped delta %q dropped an entry", full)
	}
	if strings.Contains(title, "+7") || !strings.Contains(title, "and 1 more") {
		t.Errorf("the capped title %q did not cap", title)
	}
	if full == title {
		t.Error("the cap had no effect, so the test proves nothing about it")
	}
	// udp is named; tcp is the default and is not.
	if got := portDelta([]portKey{{port: 161, transport: "udp"}}, nil, 0); got != "+161/udp" {
		t.Errorf("portDelta udp = %q, want +161/udp", got)
	}
}

// --- registry agreement -----------------------------------------------------

// Every kind this producer emits must be one the registry declares for it, with
// the registry's own severity and score. A number typed here instead would make
// the YAML documentation of a decision taken in Go.
func TestDriftFindings_MatchTheRegistry(t *testing.T) {
	p := testDriftProducer(t)
	segID := uuid.New()
	assetID := uuid.New()
	old := testNow.AddDate(0, 0, -200)

	in := newInput().
		asset(uuid.New(), assetclass.KeyServer, seg(segID), old).
		asset(assetID, assetclass.KeyPrinter, seg(segID), testNow.AddDate(0, 0, -2))
	in.protos = []protoObservation{
		{assetID: assetID, protocol: "TLS", firstSeen: old, live: true, source: "endpoint", refID: uuid.New()},
		{assetID: assetID, protocol: "SSH", firstSeen: testNow.AddDate(0, 0, -2), live: true, source: "endpoint", refID: uuid.New()},
	}
	in.ports = []portObservation{
		{assetID: assetID, port: 443, transport: "tcp", firstSeen: old, lastSeen: testNow, active: true},
		{assetID: assetID, port: 22, transport: "tcp", firstSeen: testNow.AddDate(0, 0, -2), lastSeen: testNow, active: true},
	}
	in.issuers = []issuerObservation{
		{assetID: assetID, certID: uuid.New(), issuerDN: "CN=Old CA", fingerprint: strings.Repeat("a", 64), firstSeen: old, live: true},
		{assetID: assetID, certID: uuid.New(), issuerDN: "CN=New CA", fingerprint: strings.Repeat("b", 64),
			firstSeen: testNow.AddDate(0, 0, -2), live: true},
	}

	var run DriftRun
	planned := p.judge(in, &run)
	if len(planned) != 4 {
		t.Fatalf("%d findings, want one of each of the four drift kinds", len(planned))
	}

	seen := map[string]bool{}
	for _, pl := range planned {
		k, ok := findings.Get(findings.ProducerDrift, pl.finding.Kind)
		if !ok {
			t.Fatalf("%q is not a registered drift kind", pl.finding.Kind)
		}
		seen[pl.finding.Kind] = true
		if pl.finding.Severity != k.DefaultSeverity {
			t.Errorf("%s severity = %q, registry says %q", k.Key, pl.finding.Severity, k.DefaultSeverity)
		}
		if pl.finding.Score != k.Score {
			t.Errorf("%s score = %d, registry says %d", k.Key, pl.finding.Score, k.Score)
		}
		// The writer refuses these, but failing here names the kind.
		if err := p.writer.Validate(pl.finding); err != nil {
			t.Errorf("%s: %v", k.Key, err)
		}
		if pl.observationKey == "" {
			t.Errorf("%s carries no observation key — a human resolve on it could never be respected", k.Key)
		}
		if pl.finding.Evidence["observation_key"] != pl.observationKey {
			t.Errorf("%s: the planned key and the evidence disagree", k.Key)
		}
		if pl.finding.Evidence["window_days"] != 30 {
			t.Errorf("%s: evidence does not carry the window it was judged under", k.Key)
		}
	}
	for _, kind := range driftKinds {
		if !seen[kind] {
			t.Errorf("the fixture produced no %s finding, so nothing here checks it", kind)
		}
	}
}

// --- small helpers ----------------------------------------------------------

func TestIssuerLabel(t *testing.T) {
	cases := map[string]string{
		"CN=Example CA, O=Example Ltd, C=GB": "Example CA",
		"O=Example Ltd, C=GB":                "Example Ltd",
		"cn=lowercase ca":                    "lowercase ca",
		"not a dn at all":                    "not a dn at all",
		"":                                   "",
	}
	for dn, want := range cases {
		if got := issuerLabel(dn); got != want {
			t.Errorf("issuerLabel(%q) = %q, want %q", dn, got, want)
		}
	}
}

// evidenceStrings flattens an evidence document to every string in it, so a
// test can assert that something is NOT anywhere in it.
func evidenceStrings(e map[string]any) []string {
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			out = append(out, t)
		case []string:
			out = append(out, t...)
		case map[string]any:
			for _, vv := range t {
				walk(vv)
			}
		case []map[string]any:
			for _, vv := range t {
				walk(vv)
			}
		case []any:
			for _, vv := range t {
				walk(vv)
			}
		}
	}
	walk(e)
	return out
}

// --- coverage ---------------------------------------------------------------

// The judge phase decides coverage, and it decides it from the SAME gate that
// decides drift: an asset it could compare is assessed whatever the answer, and
// one it could not is not.
//
// Both directions, because either alone passes something wrong. "Assessed when
// something drifted" would make coverage mean "had a finding" — and an asset
// whose protocols are all in its baseline is exactly the one a reader needs to
// see as ASSESSED CLEAN rather than as unexamined. "Assessed always" would put
// `drift` on every asset in the tenant, including the ones with no history at
// all, which is the collapse the whole producer exists to avoid.
func TestJudge_CoverageIsWhatCouldBeCompared(t *testing.T) {
	p := testDriftProducer(t)
	old := testNow.AddDate(0, 0, -200)
	settledClean := uuid.New() // a baseline, and nothing new
	drifted := uuid.New()      // a baseline, and something new
	noHistory := uuid.New()    // first observed inside the window

	in := newInput().
		asset(settledClean, assetclass.KeyServer, uuid.NullUUID{}, old).
		asset(drifted, assetclass.KeyServer, uuid.NullUUID{}, old).
		asset(noHistory, assetclass.KeyServer, uuid.NullUUID{}, testNow.AddDate(0, 0, -2))
	in.protos = []protoObservation{
		{assetID: settledClean, protocol: "TLS", firstSeen: old, live: true, source: "endpoint", refID: uuid.New()},
		{assetID: drifted, protocol: "TLS", firstSeen: old, live: true, source: "endpoint", refID: uuid.New()},
		{assetID: drifted, protocol: "SSH", firstSeen: testNow.AddDate(0, 0, -2), live: true, source: "endpoint", refID: uuid.New()},
		{assetID: noHistory, protocol: "SSH", firstSeen: testNow.AddDate(0, 0, -2), live: true, source: "endpoint", refID: uuid.New()},
	}

	var run DriftRun
	planned := p.judge(in, &run)

	if !in.assessed[settledClean] {
		t.Error("an asset compared against its own baseline and found unchanged is not assessed — " +
			"\"we checked and it is fine\" would read as \"nobody looked\"")
	}
	if !in.assessed[drifted] {
		t.Error("an asset drift raised on is not assessed")
	}
	if in.assessed[noHistory] {
		t.Error("an asset with nothing observed before the window is assessed — it could not be compared at all")
	}
	if got := coveredAssets(in); len(got) != 2 {
		t.Errorf("coveredAssets returned %d entries, want 2: %v", len(got), got)
	}
	// And the plan itself is unaffected by any of this.
	if n := len(plannedOf(planned, findings.KindUnexpectedProtocol)); n != 1 {
		t.Errorf("%d unexpected_protocol findings, want 1", n)
	}
}

// coveredAssets is what the writer is handed, and two passes over the same
// population must hand it the same list.
func TestAssessedAssets_IsSortedAndStable(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	in := &driftInput{assessed: map[uuid.UUID]bool{a: true, b: true}}
	first := coveredAssets(in)
	second := coveredAssets(in)
	if len(first) != 2 {
		t.Fatalf("%d entries, want 2", len(first))
	}
	if first[0] != second[0] || first[1] != second[1] {
		t.Errorf("two calls returned different orders: %v then %v", first, second)
	}
	if !uuidLess(first[0], first[1]) {
		t.Errorf("not sorted: %v", first)
	}
}
