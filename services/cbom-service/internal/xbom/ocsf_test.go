package xbom

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// renderFixtureOCSF assembles the inventory kind and projects it to OCSF,
// exactly the way the download handler does: document first, then projection of
// the stored bytes. Not a shortcut past the CycloneDX step — the artifact IS
// the CycloneDX bytes, and an OCSF stream built from anything else would not be
// what the content hash covers.
func renderFixtureOCSF(t *testing.T) []byte {
	t.Helper()
	canonical := buildFixture(t, "inventory")
	body, contentType, err := RenderOCSF(canonical)
	if err != nil {
		t.Fatalf("RenderOCSF: %v", err)
	}
	if contentType != "application/x-ndjson" {
		t.Fatalf("content type = %q, want application/x-ndjson", contentType)
	}
	return body
}

func decodeNDJSON(t *testing.T, body []byte) []map[string]any {
	t.Helper()
	var out []map[string]any
	for i, line := range bytes.Split(bytes.TrimSpace(body), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatalf("line %d is not valid JSON: %v\n%s", i+1, err, line)
		}
		out = append(out, event)
	}
	return out
}

// TestOCSF_MatchesGolden pins the exact event stream. The golden file is the
// readable record of the field map — a reviewer checks it by reading the file,
// not by reading ocsf.go.
func TestOCSF_MatchesGolden(t *testing.T) {
	body := renderFixtureOCSF(t)
	// Re-indent each line so the golden is reviewable; the wire form is one
	// compact object per line and that is what RenderOCSF emits.
	var pretty bytes.Buffer
	for _, line := range bytes.Split(bytes.TrimSpace(body), []byte("\n")) {
		var buf bytes.Buffer
		if err := json.Indent(&buf, line, "", "  "); err != nil {
			t.Fatalf("indent: %v", err)
		}
		pretty.Write(buf.Bytes())
		pretty.WriteByte('\n')
	}
	assertGolden(t, "inventory.ocsf.json", pretty.Bytes())
}

// TestOCSF_IsNDJSON: one event per line, every line a complete JSON object.
// A SIEM ingest path reads lines; a pretty-printed object spanning several
// would be silently truncated at the first newline.
func TestOCSF_IsNDJSON(t *testing.T) {
	body := renderFixtureOCSF(t)
	if !bytes.HasSuffix(body, []byte("\n")) {
		t.Error("stream does not end with a newline; the last event would be ambiguous to a line reader")
	}
	for i, line := range bytes.Split(bytes.TrimSpace(body), []byte("\n")) {
		var event map[string]any
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatalf("line %d is not one complete JSON object: %v", i+1, err)
		}
	}
}

// TestOCSF_EveryEventCarriesTheRequiredBaseFields.
//
// OCSF 1.9.0 requires exactly seven on every event: activity_id, category_uid,
// class_uid, metadata, severity_id, time, type_uid — plus metadata.version and
// metadata.product. A missing one is not a cosmetic gap: a strict OCSF consumer
// rejects the event, and a lenient one indexes it into the wrong class.
func TestOCSF_EveryEventCarriesTheRequiredBaseFields(t *testing.T) {
	for i, event := range decodeNDJSON(t, renderFixtureOCSF(t)) {
		for _, field := range []string{"activity_id", "category_uid", "class_uid", "metadata", "severity_id", "time", "type_uid"} {
			if _, ok := event[field]; !ok {
				t.Errorf("event %d is missing required base field %q", i, field)
			}
		}
		meta, _ := event["metadata"].(map[string]any)
		if meta == nil {
			t.Errorf("event %d has no metadata object", i)
			continue
		}
		if meta["version"] != OCSFVersion {
			t.Errorf("event %d metadata.version = %v, want %s", i, meta["version"], OCSFVersion)
		}
		product, _ := meta["product"].(map[string]any)
		if product == nil || product["name"] != "Vista Platform" {
			t.Errorf("event %d metadata.product = %v, want name=Vista Platform", i, meta["product"])
		}
		// type_uid is class_uid*100 + activity_id, by OCSF's own definition. An
		// inconsistent one routes the event to a class it does not match.
		classUID, _ := event["class_uid"].(float64)
		activityID, _ := event["activity_id"].(float64)
		typeUID, _ := event["type_uid"].(float64)
		if want := classUID*100 + activityID; typeUID != want {
			t.Errorf("event %d type_uid = %v, want %v (class_uid*100 + activity_id)", i, typeUID, want)
		}
	}
}

// TestOCSF_EmitsOneDeviceEventPerAsset and one finding event per vulnerability.
//
// The service-class asset and the two endpoints are NOT devices — they are in
// the CycloneDX `services` array and have no `vista:asset:uid` on a component,
// which is exactly the discriminator deviceInventoryEvent uses. Three device
// components in the fixture, so three 5001 events; two vulnerabilities, so two
// 2002 events.
func TestOCSF_EmitsOneDeviceEventPerAsset(t *testing.T) {
	events := decodeNDJSON(t, renderFixtureOCSF(t))
	devices, findings := 0, 0
	seenUIDs := map[string]bool{}
	for _, e := range events {
		switch e["class_uid"] {
		case float64(5001):
			devices++
			device, _ := e["device"].(map[string]any)
			if device == nil {
				t.Error("a 5001 event carries no device object; OCSF requires it")
				continue
			}
			if _, ok := device["type_id"]; !ok {
				t.Error("device is missing the required type_id")
			}
			uid, _ := device["uid"].(string)
			if seenUIDs[uid] {
				t.Errorf("asset %s appears in two device events", uid)
			}
			seenUIDs[uid] = true
		case float64(2002):
			findings++
			if _, ok := e["finding_info"]; !ok {
				t.Error("a 2002 event carries no finding_info; OCSF requires it")
			}
			if _, ok := e["vulnerabilities"]; !ok {
				t.Error("a 2002 event carries no vulnerabilities; OCSF requires it")
			}
		default:
			t.Errorf("unexpected class_uid %v", e["class_uid"])
		}
	}
	if devices != 3 {
		t.Errorf("device events = %d, want 3 (server, switch, bucket — not the service-class asset or the endpoints)", devices)
	}
	if findings != 2 {
		t.Errorf("vulnerability finding events = %d, want 2", findings)
	}
}

// TestOCSF_AbsentStaysAbsent is the honesty guard, and the reason this export
// is worth trusting.
//
// Every field below is one OCSF defines and this fixture has no answer for. A
// SIEM correlating on `device.mac` cannot distinguish "" from "we did not
// observe one", and a rule that fires on an empty string is a rule that fires
// on a measurement nobody made. The switch has no OS facts and no MAC; the
// bucket has neither, plus no vendor and no model.
func TestOCSF_AbsentStaysAbsent(t *testing.T) {
	events := decodeNDJSON(t, renderFixtureOCSF(t))
	for _, e := range events {
		device, _ := e["device"].(map[string]any)
		if device == nil {
			continue
		}
		uid, _ := device["uid"].(string)
		switch uid {
		case assetSwitch.String():
			for _, absent := range []string{"os", "mac", "hostname", "domain"} {
				if v, present := device[absent]; present {
					t.Errorf("switch device carries %q = %v; nothing measured it", absent, v)
				}
			}
			// It DOES have what was measured.
			if device["vendor_name"] != "Cisco Systems" {
				t.Errorf("switch vendor_name = %v, want Cisco Systems", device["vendor_name"])
			}
			if device["ip"] != "192.0.2.20" {
				t.Errorf("switch ip = %v, want 192.0.2.20", device["ip"])
			}
		case assetBucket.String():
			for _, absent := range []string{"os", "mac", "ip", "hostname", "vendor_name", "model"} {
				if v, present := device[absent]; present {
					t.Errorf("bucket device carries %q = %v; nothing measured it", absent, v)
				}
			}
		}
	}
}

// TestOCSF_MultiSourceFactStillReachesTheOSObject is a regression guard.
//
// `factProperties` renames a key with MORE THAN ONE source to
// `vista:fact:os.name@<source_ref>`, to preserve the disagreement the facts
// table exists to hold. The OCSF projection looked the key up by its exact
// name — so a server with BOTH a CMDB record and an agent report came out with
// no operating system at all, while a server with only one came out fine. The
// better-instrumented asset lost the field.
//
// The fixture's server deliberately carries two os.name sources, so this is the
// case, not a contrived one.
func TestOCSF_MultiSourceFactStillReachesTheOSObject(t *testing.T) {
	// Precondition: the fixture really does have the disagreement. Without this
	// the test could pass on a fixture that had quietly lost it.
	sources := 0
	for _, f := range fixtureSnapshot().Facts {
		if f.AssetID == assetServer && f.Key == "os.name" {
			sources++
		}
	}
	if sources < 2 {
		t.Fatalf("fixture has %d os.name sources for the server; this test needs at least 2", sources)
	}

	for _, e := range decodeNDJSON(t, renderFixtureOCSF(t)) {
		device, _ := e["device"].(map[string]any)
		if device == nil || device["uid"] != assetServer.String() {
			continue
		}
		os, _ := device["os"].(map[string]any)
		if os == nil {
			t.Fatal("the server has os.name facts but the event carries no os object")
		}
		if os["name"] == "" || os["name"] == nil {
			t.Errorf("os.name = %v, want a value", os["name"])
		}
		if os["version"] != "24.04.1 LTS" {
			t.Errorf("os.version = %v, want 24.04.1 LTS", os["version"])
		}
		if os["type_id"] != float64(200) {
			t.Errorf("os.type_id = %v, want 200 (Linux)", os["type_id"])
		}
		return
	}
	t.Fatal("the server asset produced no device event")
}

// TestOCSF_UnmappedClassIsUnknownNotOther.
//
// An object-storage bucket is a real kind of thing that OCSF's DEVICE
// enumeration does not model. 0 (Unknown) says "we do not know", which is a
// claim about us and is true. 99 (Other) says "a kind OCSF does not model",
// which is a claim about OCSF and is one we are not entitled to make from a
// class key we simply have no mapping for.
func TestOCSF_UnmappedClassIsUnknownNotOther(t *testing.T) {
	for _, e := range decodeNDJSON(t, renderFixtureOCSF(t)) {
		device, _ := e["device"].(map[string]any)
		if device == nil || device["uid"] != assetBucket.String() {
			continue
		}
		if device["type_id"] != float64(0) {
			t.Fatalf("object_storage device type_id = %v, want 0 (Unknown)", device["type_id"])
		}
		return
	}
	t.Fatal("the bucket asset produced no device event")
}

// TestOCSF_DeviceTypeMapping covers the class→type_id table directly, including
// the cases the fixture does not carry.
func TestOCSF_DeviceTypeMapping(t *testing.T) {
	cases := map[string]int{
		"server": 1, "compute_instance": 1,
		"workstation": 2, "laptop": 3, "mobile": 5,
		"virtual_machine": 6, "container": 6,
		"iot_device": 7, "plc": 7, "printer": 7,
		"firewall": 9, "switch": 10, "router": 12,
		"load_balancer": 15,
		// No OCSF device counterpart → Unknown, never Other.
		"object_storage": 0, "business_service": 0, "unknown_host": 0,
		"": 0,
	}
	for class, want := range cases {
		if got := ocsfDeviceTypeID(class); got != want {
			t.Errorf("ocsfDeviceTypeID(%q) = %d, want %d", class, got, want)
		}
	}
}

// TestOCSF_OSTypeMapping. The Cisco case is the one that matters: "IOS-XE"
// contains "ios", and mapping it to Apple iOS would be a fabricated platform
// attribution in a document a SIEM correlates on.
func TestOCSF_OSTypeMapping(t *testing.T) {
	cases := map[string]int{
		"Ubuntu": 200, "Ubuntu Linux": 200, "Debian GNU/Linux": 200,
		"Red Hat Enterprise Linux": 200, "Alpine Linux": 200,
		"Windows Server 2022": 100, "macOS": 300, "Android": 201,
		"iPadOS": 302, "Solaris": 400, "AIX": 401, "HP-UX": 402,
		// Not Apple. Not Linux either — a network OS we have no OCSF mapping
		// for is Unknown, which is the truthful answer.
		//
		// Every one of these carries the substring "ios", and a
		// `Contains(name, "ios")` test reported all of them as Apple mobile
		// devices. That is what this row is for.
		"IOS-XE": 0, "IOS XE 17.9": 0, "IOS-XR": 0, "Cisco IOS": 0,
		"FortiOS": 0, "PAN-OS": 0, "JunOS": 0, "NX-OS": 0, "ArubaOS": 0,
		// The names that need an Apple SIGNAL and do not have one. `show
		// version` on a Catalyst prints exactly this, and Cisco IOS 15.2 and
		// iOS 15.2 are the same eight characters.
		"IOS": 0, "iOS": 0, "iOS 17.4": 0, "IOS 15.2": 0,
	}
	for name, want := range cases {
		if got, _ := ocsfOSTypeFor(name); got != want {
			t.Errorf("ocsfOSTypeFor(%q) = %d, want %d", name, got, want)
		}
	}
}

// TestOCSF_AppleIOSNeedsAnAppleSignal is the other half of the row above: the
// SAME name maps to iOS once something says Apple, and to Unknown when nothing
// does.
//
// Both polarities in one table on purpose. The over-strict direction is a real
// failure mode — a guard that refused every iOS device would be this fix
// pointed backwards — and a table that only proved the refusals could not tell
// the two apart.
func TestOCSF_AppleIOSNeedsAnAppleSignal(t *testing.T) {
	cases := []struct {
		name          string
		vendor, model string
		want          int
	}{
		// No signal anywhere: Cisco IOS is the likelier reading, and Unknown is
		// the honest one.
		{name: "IOS 15.2", want: 0},
		{name: "iOS", want: 0},
		{name: "iOS 17.4", want: 0},
		// The signal in the name itself.
		{name: "iPhone OS 17.4", want: 301},
		{name: "Apple iOS 17.4", want: 301},
		// The signal in the hardware facts beside it.
		{name: "iOS 17.4", vendor: "Apple", want: 301},
		{name: "IOS 15.2", vendor: "Apple Inc.", want: 301},
		{name: "iOS 17.4", model: "iPhone15,3", want: 301},
		{name: "iOS", vendor: "Apple", want: 301},
		// A Cisco marker still wins over an Apple-looking hint: a Cisco switch
		// whose model string somehow mentions an iPad is not an iPhone.
		{name: "Cisco IOS 15.2", vendor: "Apple", want: 0},
		// The hardware facts do not turn a NON-iOS name into iOS.
		{name: "FortiOS 7.4", vendor: "Apple", want: 0},
	}
	for _, tc := range cases {
		got, _ := ocsfOSTypeFor(tc.name, tc.vendor, tc.model)
		if got != tc.want {
			t.Errorf("ocsfOSTypeFor(%q, vendor=%q, model=%q) = %d, want %d",
				tc.name, tc.vendor, tc.model, got, tc.want)
		}
	}
}

// TestOCSF_NoCVEMeansNoCVEObject: `cve.uid` is required by OCSF, so a finding
// that names no CVE must carry no `cve` object — not one with an empty or
// invented uid.
func TestOCSF_NoCVEMeansNoCVEObject(t *testing.T) {
	for _, e := range decodeNDJSON(t, renderFixtureOCSF(t)) {
		if e["class_uid"] != float64(2002) {
			continue
		}
		finding, _ := e["finding_info"].(map[string]any)
		if finding == nil || finding["uid"] != findingNoCVE.String() {
			continue
		}
		vulns, _ := e["vulnerabilities"].([]any)
		if len(vulns) != 1 {
			t.Fatalf("vulnerabilities = %v, want exactly one", vulns)
		}
		v, _ := vulns[0].(map[string]any)
		if _, present := v["cve"]; present {
			t.Errorf("a finding with no CVE id emitted a cve object: %v", v["cve"])
		}
		if _, present := v["title"]; present {
			t.Errorf("a finding with no CVE id emitted a title: %v", v["title"])
		}
		return
	}
	t.Fatal("the no-CVE finding produced no 2002 event")
}

// TestOCSF_TimeComesFromTheArtifactNotTheDownload.
//
// These events describe the moment the snapshot was taken. Stamping them with
// now() would tell a SIEM the inventory was observed when someone clicked
// Export, which would make every re-download look like a fresh observation.
func TestOCSF_TimeComesFromTheArtifactNotTheDownload(t *testing.T) {
	want := fixtureTime().UnixMilli()
	for i, e := range decodeNDJSON(t, renderFixtureOCSF(t)) {
		got, _ := e["time"].(float64)
		if int64(got) != want {
			t.Errorf("event %d time = %v, want %d (the artifact's own timestamp)", i, got, want)
		}
	}
}

// TestOCSF_EmptyDocumentYieldsEmptyStream. Zero lines is what "no events" looks
// like in NDJSON; every ingest path handles it, and an error would make an
// empty-scope artifact undownloadable.
func TestOCSF_EmptyDocumentYieldsEmptyStream(t *testing.T) {
	doc, err := BuildDocument("inventory", &Snapshot{}, fixtureInput())
	if err != nil {
		t.Fatalf("BuildDocument: %v", err)
	}
	canonical, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body, _, err := RenderOCSF(canonical)
	if err != nil {
		t.Fatalf("RenderOCSF on an empty inventory: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("empty inventory produced %d bytes, want an empty stream:\n%s", len(body), body)
	}
}

// TestOCSF_RejectsNonJSON. A projection that silently produced an empty stream
// from unreadable bytes would report a storage fault as "no assets".
func TestOCSF_RejectsNonJSON(t *testing.T) {
	if _, _, err := RenderOCSF([]byte("not json")); err == nil {
		t.Error("RenderOCSF accepted bytes that are not a CycloneDX document")
	}
}

// TestOCSF_CorrelationUIDIsTheArtifactSerial — every event from one artifact
// shares it, which is how a SIEM groups a whole snapshot.
func TestOCSF_CorrelationUIDIsTheArtifactSerial(t *testing.T) {
	for i, e := range decodeNDJSON(t, renderFixtureOCSF(t)) {
		meta, _ := e["metadata"].(map[string]any)
		got, _ := meta["correlation_uid"].(string)
		if got != fixtureSerial.String() {
			t.Errorf("event %d correlation_uid = %q, want %q", i, got, fixtureSerial.String())
		}
		if strings.HasPrefix(got, "urn:uuid:") {
			t.Errorf("event %d correlation_uid still carries the urn prefix: %q", i, got)
		}
	}
}
