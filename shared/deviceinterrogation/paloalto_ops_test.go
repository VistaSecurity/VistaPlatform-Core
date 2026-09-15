package deviceinterrogation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func panFixture(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(body)
}

// `show system info` was fetched and discarded for the whole life of this
// interrogator. This is the test that it is read, and that reading it did not
// start collecting the secrets a PAN-OS response can carry beside the identity.
func TestPanSystemInfo_ProjectsIdentityAndDropsSecrets(t *testing.T) {
	info, err := panParseSystemInfo(panFixture(t, "paloalto_system_info.xml"))
	if err != nil {
		t.Fatalf("panParseSystemInfo: %v", err)
	}

	if info.Hostname != "fw-edge-01" || info.Model != "PA-3220" || info.Serial != "013201001234" {
		t.Errorf("identity lost: %+v", info)
	}
	if info.SWVersion != "11.1.4-h7" || info.Uptime != "8 days, 4:23:11" {
		t.Errorf("software/uptime lost: %+v", info)
	}
	if info.IPAddress != "192.0.2.5" || info.Netmask != "255.255.255.0" || info.MACAddress != "00:1b:17:0a:0b:0c" {
		t.Errorf("management addressing lost: %+v", info)
	}

	projected := panSystemInfoMap(info)
	assertNoPoison(t, "pan system info", projected)
	if projected["hostname"] != "fw-edge-01" || projected["management_ip"] != "192.0.2.5" {
		t.Errorf("the DeviceInfo projection lost identity: %#v", projected)
	}

	result := &InterrogateResult{}
	panEmitSystemFacts(result, info)
	assertObservationsValid(t, "pan system info", result)
	assertNoPoison(t, "pan system facts", result)

	for key, want := range map[string]any{
		factHWVendor:         panVendor,
		factHWModel:          "PA-3220",
		factHWSerial:         "013201001234",
		factOSName:           "PAN-OS",
		factOSVersion:        "11.1.4-h7",
		factNetUptimeSeconds: 8*86400 + 4*3600 + 23*60 + 11,
		factMgmtProtocol:     "https",
		factMgmtPlaintext:    false,
	} {
		if got := factValue(t, result, key); got != want {
			t.Errorf("%s = %v (%T), want %v", key, got, got, want)
		}
	}

	identity := panIdentity(info)
	if identity.ClassHint != "firewall" {
		t.Errorf("class hint = %q, want firewall", identity.ClassHint)
	}
	if identity.OSVersion != "PAN-OS 11.1.4-h7" || identity.SerialNumber != "013201001234" {
		t.Errorf("device identity wrong: %+v", identity)
	}
	if identity.FirmwareVersion != "" {
		t.Errorf("the software version was repeated as a firmware version: %+v", identity)
	}
}

func TestPanParseUptime(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"8 days, 4:23:11", 8*86400 + 4*3600 + 23*60 + 11, true},
		{"1 day, 0:00:05", 86405, true},
		// The first day of uptime has no days component at all — the case a
		// naive split reads as zero.
		{"4:23:11", 15791, true},
		{"0 days, 0:00:00", 0, true},
		{"", 0, false},
		{"unknown", 0, false},
		{"8 days", 8 * 86400, true},
	}
	for _, tc := range cases {
		got, ok := panParseUptime(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("panParseUptime(%q) = (%d, %v), want (%d, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestPanInterfaces_MergesLayer3AndHardwareViews(t *testing.T) {
	info, err := panParseSystemInfo(panFixture(t, "paloalto_system_info.xml"))
	if err != nil {
		t.Fatalf("panParseSystemInfo: %v", err)
	}
	interfaces, err := panInterfaces(panFixture(t, "paloalto_interfaces.xml"), info)
	if err != nil {
		t.Fatalf("panInterfaces: %v", err)
	}

	byName := map[string]map[string]interface{}{}
	for _, iface := range interfaces {
		byName[iface["name"].(string)] = iface
	}
	if len(byName) != 4 {
		t.Fatalf("expected three data interfaces plus management, got %+v", interfaces)
	}

	eth1 := byName["ethernet1/1"]
	if eth1["mac"] != "00:1b:17:0a:0b:0d" || eth1["state"] != "up" || eth1["speed"] != 1000 {
		t.Errorf("hardware view lost for ethernet1/1: %+v", eth1)
	}
	if addrs, ok := eth1["addresses"].([]interface{}); !ok || len(addrs) != 1 || addrs[0] != "198.51.100.2/24" {
		t.Errorf("address lost for ethernet1/1: %+v", eth1)
	}
	if _, tagged := eth1["vlan"]; tagged {
		t.Errorf("tag 0 was recorded as a VLAN: %+v", eth1)
	}

	sub := byName["ethernet1/2.100"]
	if sub["vlan"] != 100 {
		t.Errorf("subinterface tag lost: %+v", sub)
	}
	if _, hasState := sub["state"]; hasState {
		t.Errorf("a subinterface with no hardware row was given a link state: %+v", sub)
	}

	down := byName["ethernet1/3"]
	if down["state"] != "down" {
		t.Errorf("link state lost: %+v", down)
	}
	if _, addressed := down["addresses"]; addressed {
		t.Errorf("N/A was recorded as an address: %+v", down)
	}
	if _, hasSpeed := down["speed"]; hasSpeed {
		t.Errorf("speed \"unknown\" was recorded as a number: %+v", down)
	}

	mgmt := byName["management"]
	if mgmt["mac"] != "00:1b:17:0a:0b:0c" {
		t.Errorf("management MAC lost: %+v", mgmt)
	}
	if addrs, ok := mgmt["addresses"].([]interface{}); !ok || addrs[0] != "192.0.2.5/24" {
		t.Errorf("the dotted netmask was not combined into a prefix: %+v", mgmt)
	}
}

func TestPanARPNeighbors_SkipsIncompleteEntries(t *testing.T) {
	neighbors, err := panARPNeighbors(panFixture(t, "paloalto_arp.xml"))
	if err != nil {
		t.Fatalf("panARPNeighbors: %v", err)
	}
	if len(neighbors) != 2 {
		t.Fatalf("expected the two complete ARP entries, got %+v", neighbors)
	}
	first := neighbors[0]
	if first["protocol"] != "arp" || first["remote_mac"] != "00:1b:17:00:00:01" ||
		first["remote_address"] != "198.51.100.1" || first["local_port"] != "ethernet1/1" {
		t.Errorf("ARP projection wrong: %+v", first)
	}
}

func TestPanLLDPObservations_EmitsNeighboursAndEdges(t *testing.T) {
	neighbors, edges, err := panLLDPObservations(panFixture(t, "paloalto_lldp.xml"))
	if err != nil {
		t.Fatalf("panLLDPObservations: %v", err)
	}

	if len(neighbors) != 1 {
		t.Fatalf("expected one real neighbour (the second advertises nothing), got %+v", neighbors)
	}
	n := neighbors[0]
	if n["protocol"] != "lldp" || n["remote_name"] != "core-sw-1.example.net" ||
		n["remote_mac"] != "00:1b:17:00:00:01" || n["remote_port"] != "Gi1/0/24" ||
		n["local_port"] != "ethernet1/1" || n["remote_address"] != "198.51.100.1" {
		t.Errorf("LLDP neighbour projection wrong: %+v", n)
	}

	if len(edges) != 1 {
		t.Fatalf("expected one connects_to edge, got %+v", edges)
	}
	edge := edges[0]
	if edge.Type != relTypeConnectsTo || edge.Direction != SubjectToPeer {
		t.Errorf("edge shape wrong: %+v", edge)
	}
	if edge.Peer.Identifier(IdentifierMACAddress) != "00:1b:17:00:00:01" ||
		edge.Peer.Identifier(IdentifierFQDN) != "core-sw-1.example.net" ||
		edge.Peer.Identifier(IdentifierIPAddress) != "198.51.100.1" {
		t.Errorf("peer identifiers lost: %+v", edge.Peer)
	}
	if edge.Attributes["local_port"] != "ethernet1/1" || edge.Attributes["remote_port"] != "Gi1/0/24" {
		t.Errorf("port attributes lost: %+v", edge.Attributes)
	}

	assertNoPoison(t, "pan lldp neighbours", neighbors)
	assertNoPoison(t, "pan lldp edges", edges)
}

// newPanOpsTestServer answers every call the interrogation makes from the
// fixtures, so the test drives the REAL interrogator rather than its parsers.
// Projection has to be wired, not merely available.
func newPanOpsTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		q := r.URL.Query()
		cmd := q.Get("cmd")
		switch {
		case q.Get("type") == "keygen" || r.Method == http.MethodPost:
			_, _ = w.Write([]byte(`<response status="success"><result><key>FAKEAPIKEY==</key></result></response>`))
		case strings.Contains(cmd, "<system>"):
			_, _ = w.Write([]byte(panFixture(t, "paloalto_system_info.xml")))
		case strings.Contains(cmd, "<interface>"):
			_, _ = w.Write([]byte(panFixture(t, "paloalto_interfaces.xml")))
		case strings.Contains(cmd, "<arp>"):
			_, _ = w.Write([]byte(panFixture(t, "paloalto_arp.xml")))
		case strings.Contains(cmd, "<lldp>"):
			_, _ = w.Write([]byte(panFixture(t, "paloalto_lldp.xml")))
		case strings.Contains(q.Get("xpath"), "ssl-decrypt"):
			_, _ = w.Write([]byte(panSSLDecryptResponse))
		case strings.Contains(q.Get("xpath"), "rules"):
			_, _ = w.Write([]byte(panSecurityRulesResponse))
		default:
			_, _ = w.Write([]byte(panEmptyResultResponse))
		}
	}))
}

func TestPaloAltoInterrogator_OpsCollectionIsWired(t *testing.T) {
	srv := newPanOpsTestServer(t)
	defer srv.Close()

	registry := NewRegistry()
	interrogator, err := registry.Get("palo_alto")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Through the Registry, so the result has been through Sanitize as it would
	// be in production.
	result, err := interrogator.Interrogate(
		context.Background(),
		DeviceInfo{DeviceType: "palo_alto", ManagementURL: srv.URL},
		Credentials{Username: "admin", Password: "admin"},
	)
	if err != nil {
		t.Fatalf("Interrogate: %v", err)
	}

	assertObservationsValid(t, "pan interrogator", result)
	assertNoPoison(t, "pan interrogator", result)

	for _, key := range []string{
		factHWVendor, factHWModel, factHWSerial, factOSName, factOSVersion,
		factNetUptimeSeconds, factNetInterfaces, factNetNeighbors,
		factMgmtProtocol, factMgmtPlaintext,
	} {
		if !hasFact(result, key) {
			t.Errorf("no %s fact reached the result; facts: %v", key, factKeys(result))
		}
	}
	if edges := relationshipsOfType(result, relTypeConnectsTo); len(edges) != 1 {
		t.Errorf("expected the LLDP edge to reach the result, got %+v", edges)
	}
	if result.DeviceIdentity == nil || result.DeviceIdentity.Model != "PA-3220" {
		t.Errorf("system info did not reach the device identity: %+v", result.DeviceIdentity)
	}
	// The marker survives as a BOOLEAN. Under its old name (`api_key_obtained`)
	// the redaction backstop matched the `api_key` fragment and replaced it
	// with "[redacted]", so the one field the stub did populate never reached a
	// consumer intact.
	if result.DeviceInfo["session_authenticated"] != true {
		t.Errorf("the session-liveness marker was dropped or redacted: %#v", result.DeviceInfo)
	}
	if result.DeviceInfo["hostname"] != "fw-edge-01" {
		t.Errorf("system info did not reach DeviceInfo: %#v", result.DeviceInfo)
	}
	// The ARP and LLDP neighbours land in one fact, not two.
	neighbors := factValue(t, result, factNetNeighbors).([]map[string]interface{})
	if len(neighbors) != 3 {
		t.Errorf("expected two ARP neighbours and one LLDP neighbour in one fact, got %+v", neighbors)
	}
	// And the crypto assets the interrogator already produced are untouched.
	if len(result.Assets) == 0 {
		t.Error("the ssl-decrypt assets were lost")
	}
}

// A device that answers keygen but not the op commands must still produce a
// usable result — and must not claim facts it never read.
func TestPaloAltoInterrogator_SurvivesUnavailableOpCommands(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		if r.URL.Query().Get("type") == "keygen" || r.Method == http.MethodPost {
			_, _ = w.Write([]byte(`<response status="success"><result><key>FAKEAPIKEY==</key></result></response>`))
			return
		}
		_, _ = w.Write([]byte(`<response status="error" code="403"><result><msg>Permission denied</msg></result></response>`))
	}))
	defer srv.Close()

	result, err := (&PaloAltoInterrogator{}).Interrogate(
		context.Background(),
		DeviceInfo{DeviceType: "palo_alto", ManagementURL: srv.URL},
		Credentials{Username: "admin", Password: "admin"},
	)
	if err != nil {
		t.Fatalf("Interrogate: %v", err)
	}
	if len(result.Facts) != 0 {
		t.Errorf("facts were emitted for responses that never arrived: %v", factKeys(result))
	}
	if result.DeviceIdentity == nil || result.DeviceIdentity.Vendor != panVendor {
		t.Errorf("the fallback identity was lost: %+v", result.DeviceIdentity)
	}
	if result.DeviceIdentity.Model != "" {
		t.Errorf("a model was reported for a device that never answered: %+v", result.DeviceIdentity)
	}
}
