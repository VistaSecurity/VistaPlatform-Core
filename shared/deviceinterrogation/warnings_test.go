package deviceinterrogation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/redact"
)

// Collection warnings (finding P-17). Each vendor test below drives the REAL
// interrogator, through the Registry, against a fake appliance that refuses ONE
// endpoint the way a read-only admin profile does — and asserts both halves of
// best-effort: the refusal is reported with its reason, AND the rest of the
// result is still there. Before warnings existed every one of these runs
// returned a clean result and printed the refusal to stdout.

// refuseHandler wraps a fake appliance so requests matching refuse get status
// and body instead of the fixture answer.
func refuseHandler(inner http.Handler, refuse func(*http.Request) bool, status int, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if refuse(r) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
			return
		}
		inner.ServeHTTP(w, r)
	})
}

// interrogateVia runs deviceType's interrogator through the Registry, so the
// result has been through Sanitize exactly as in production.
func interrogateVia(t *testing.T, deviceType string, device DeviceInfo) *InterrogateResult {
	t.Helper()
	interrogator, err := NewRegistry().Get(deviceType)
	if err != nil {
		t.Fatalf("Get(%s): %v", deviceType, err)
	}
	device.DeviceType = deviceType
	result, err := interrogator.Interrogate(context.Background(), device, Credentials{Username: "admin", Password: "admin"})
	if err != nil {
		t.Fatalf("Interrogate(%s): %v", deviceType, err)
	}
	return result
}

// findWarning returns the warning on endpoint, failing the test with the whole
// list when there is none.
func findWarning(t *testing.T, result *InterrogateResult, endpoint string) CollectionWarning {
	t.Helper()
	for _, w := range result.Warnings {
		if w.Endpoint == endpoint {
			return w
		}
	}
	t.Fatalf("no collection warning for %q; warnings: %+v", endpoint, result.Warnings)
	return CollectionWarning{}
}

func assertWarning(t *testing.T, got CollectionWarning, collector string, reason WarningReason, effectFragment string) {
	t.Helper()
	if got.Collector != collector {
		t.Errorf("warning collector = %q, want %q", got.Collector, collector)
	}
	if got.Reason != reason {
		t.Errorf("warning reason = %q, want %q (detail %q)", got.Reason, reason, got.Detail)
	}
	if !strings.Contains(strings.ToLower(got.Effect), strings.ToLower(effectFragment)) {
		t.Errorf("warning effect = %q, want it to mention %q", got.Effect, effectFragment)
	}
}

func TestFortinetInterrogator_RefusedEndpointIsAWarningNotASilence(t *testing.T) {
	fixture := newFortinetOpsTestServer(t)
	fixture.Close()
	srv := httptest.NewServer(refuseHandler(fixture.Config.Handler,
		func(r *http.Request) bool { return strings.HasSuffix(r.URL.Path, "/cmdb/system/interface") },
		http.StatusForbidden, `{"http_status":403,"status":"error"}`))
	defer srv.Close()

	result := interrogateVia(t, "fortigate", DeviceInfo{ManagementURL: srv.URL})

	w := findWarning(t, result, "/api/v2/cmdb/system/interface")
	assertWarning(t, w, "fortinet", WarningPermissionDenied, "interfaces")

	// The rest of the result is still there: identity from system/status, the
	// route summary from a different endpoint the profile may read.
	if !hasFact(result, factHWSerial) || !hasFact(result, factNetRouteNextHopCount) {
		t.Errorf("the refusal cost the facts other endpoints answered: %v", factKeys(result))
	}
	if len(result.Warnings) != 1 {
		t.Errorf("one refused endpoint produced %d warnings: %+v", len(result.Warnings), result.Warnings)
	}
}

func TestPaloAltoInterrogator_RefusedOpCommandIsAWarningNotASilence(t *testing.T) {
	fixture := newPanOpsTestServer(t)
	fixture.Close()
	srv := httptest.NewServer(refuseHandler(fixture.Config.Handler,
		func(r *http.Request) bool { return strings.Contains(r.URL.Query().Get("cmd"), "<arp>") },
		// PAN-OS refuses inside a 200: the envelope carries the code.
		http.StatusOK, `<response status="error" code="403"><result><msg>Permission denied</msg></result></response>`))
	defer srv.Close()

	result := interrogateVia(t, "palo_alto", DeviceInfo{ManagementURL: srv.URL})

	w := findWarning(t, result, "show arp all")
	assertWarning(t, w, "paloalto", WarningPermissionDenied, "ARP")

	// LLDP answered, so its neighbour and edge are still reported.
	if edges := relationshipsOfType(result, relTypeConnectsTo); len(edges) != 1 {
		t.Errorf("the LLDP edge was lost with the ARP table: %+v", edges)
	}
	if len(result.Assets) == 0 {
		t.Error("the ssl-decrypt assets were lost with the ARP table")
	}
}

func TestF5Interrogator_RefusedEndpointIsAWarningNotASilence(t *testing.T) {
	fixture := newF5OpsTestServer(t)
	fixture.Close()
	srv := httptest.NewServer(refuseHandler(fixture.Config.Handler,
		func(r *http.Request) bool { return strings.HasSuffix(r.URL.Path, "/net/vlan") },
		http.StatusForbidden, `{"code":403,"message":"Forbidden"}`))
	defer srv.Close()

	result := interrogateVia(t, "f5_bigip", DeviceInfo{ManagementURL: srv.URL})

	w := findWarning(t, result, "/mgmt/tm/net/vlan")
	assertWarning(t, w, "f5", WarningPermissionDenied, "VLAN")

	if !hasFact(result, factNetInterfaces) {
		t.Errorf("the interfaces fact was lost with the VLAN table: %v", factKeys(result))
	}
	if len(result.Assets) == 0 {
		t.Error("the VIP assets were lost with the VLAN table")
	}
}

func TestUnifiInterrogator_RefusedEndpointIsAWarningNotASilence(t *testing.T) {
	fixture := newMockUnifiOSController(t)
	fixture.Close()
	// The mock controller does not serve stat/sta at all; refusing it is what a
	// read-only admin sees on a controller that does.
	srv := httptest.NewTLSServer(refuseHandler(fixture.Config.Handler,
		func(r *http.Request) bool { return strings.HasSuffix(r.URL.Path, "/stat/sta") },
		http.StatusForbidden, `{"meta":{"rc":"error","msg":"api.err.NoPermission"},"data":[]}`))
	defer srv.Close()

	interrogator, err := NewRegistry().Get("unifi")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	result, err := interrogator.Interrogate(context.Background(),
		DeviceInfo{DeviceType: "unifi", ManagementURL: srv.URL},
		Credentials{Username: "admin", Password: "admin", InsecureSkipVerify: true})
	if err != nil {
		// Before the re-authenticate-ONCE fix, a persistent 403 re-logged in and
		// retried forever; the test would never get here.
		t.Fatalf("Interrogate: %v", err)
	}

	w := findWarning(t, result, "/proxy/network/api/s/default/stat/sta")
	assertWarning(t, w, "unifi", WarningPermissionDenied, "clients")

	found := false
	for _, a := range result.Assets {
		if a.Metadata["name"] == "office-switch" {
			found = true
		}
	}
	if !found {
		t.Errorf("the managed devices were lost with the client list: %+v", result.Assets)
	}
}

func TestCiscoCryptoConfigs_CommandFailuresAreWarnings(t *testing.T) {
	const isakmp = "IPv4 Crypto ISAKMP SA\ndst             src             state          conn-id status\n" +
		"203.0.113.10    192.0.2.1       QM_IDLE           1001 ACTIVE\n"
	run := func(_ context.Context, command string) (string, bool, error) {
		switch command {
		case "show crypto isakmp sa":
			return isakmp, false, nil
		case "show crypto ipsec sa":
			// What AAA command authorization prints for a refused command.
			return "% Authorization failed.\n", false, nil
		case "show crypto map":
			return "", false, errors.New("command execution failed: Process exited with status 1")
		default:
			return "", false, nil
		}
	}
	result := &InterrogateResult{collector: "cisco"}
	configs := (&ciscoSSHClient{}).getCryptoConfigs(context.Background(), result, run)

	if len(configs) != 1 || configs[0].Type != "isakmp_sa" {
		t.Errorf("the command that answered was lost with the ones that did not: %+v", configs)
	}
	assertWarning(t, findWarning(t, result, "show crypto ipsec sa"), "cisco", WarningPermissionDenied, "IPsec")
	assertWarning(t, findWarning(t, result, "show crypto map"), "cisco", WarningError, "crypto map")
	if len(result.Warnings) != 2 {
		t.Errorf("want exactly the two failed commands warned about, got %+v", result.Warnings)
	}
}

func TestCiscoCollectOps_UnavailableCommandsAreWarnings(t *testing.T) {
	result := &InterrogateResult{collector: "cisco"}
	ciscoCollectOps(context.Background(), result, newCiscoFixtureRunner(t, ciscoIOSFixturesWithout("show vlan brief")), map[string]interface{}{})

	assertWarning(t, findWarning(t, result, "show vlan brief"), "cisco", WarningError, "VLAN")
	if !hasFact(result, factNetInterfaces) {
		t.Errorf("the interfaces fact was lost with the VLAN table: %v", factKeys(result))
	}
}

func TestCiscoCollectOps_TruncatedOutputIsAWarning(t *testing.T) {
	fixtures := ciscoIOSFixtures()
	base := newCiscoFixtureRunner(t, fixtures)
	run := func(ctx context.Context, command string) (string, bool, error) {
		out, _, err := base(ctx, command)
		return out, command == "show ip arp", err
	}
	result := &InterrogateResult{collector: "cisco"}
	ciscoCollectOps(context.Background(), result, run, map[string]interface{}{})

	w := findWarning(t, result, "show ip arp")
	assertWarning(t, w, "cisco", WarningTruncated, strconv.Itoa(ciscoMaxCommandBytes))
}

func ciscoIOSFixturesWithout(command string) map[string]string {
	fixtures := ciscoIOSFixtures()
	delete(fixtures, command)
	return fixtures
}

func TestSNMPInterrogator_TruncatedWalkIsAWarning(t *testing.T) {
	mib := snmpTestMIB()
	// One row past the walk cap, on a table the collector reads.
	for i := 100; i <= 100+snmpMaxWalkRows; i++ {
		mib = append(mib, snmpTestOctet(snmpOIDIfDescr+"."+strconv.Itoa(i), "Gi2/0/"+strconv.Itoa(i)))
	}
	addr := startSNMPTestAgent(t, mib)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	interrogator, err := NewRegistry().Get("generic_snmp")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	result, err := interrogator.Interrogate(context.Background(),
		DeviceInfo{DeviceType: "generic_snmp", IPAddress: host, Port: port},
		Credentials{Custom: map[string]interface{}{"community": "public"}})
	if err != nil {
		t.Fatalf("Interrogate: %v", err)
	}

	var got *CollectionWarning
	for i, w := range result.Warnings {
		if strings.Contains(w.Endpoint, "ifDescr") {
			got = &result.Warnings[i]
		}
	}
	if got == nil {
		t.Fatalf("a walk cut at the row cap raised no warning naming the table; warnings: %+v", result.Warnings)
	}
	assertWarning(t, *got, "snmp", WarningTruncated, strconv.Itoa(snmpMaxWalkRows))
	if !hasFact(result, factNetInterfaces) {
		t.Errorf("the partial interface table was dropped instead of kept: %v", factKeys(result))
	}
}

// --- classification ---------------------------------------------------------

func TestClassifyWarningReason(t *testing.T) {
	deadline, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	<-deadline.Done()

	cases := []struct {
		name string
		err  error
		want WarningReason
	}{
		{"401", statusErrorf(401, "x"), WarningPermissionDenied},
		{"403 wrapped", fmt.Errorf("get interfaces: %w", statusErrorf(403, "x")), WarningPermissionDenied},
		{"404", statusErrorf(404, "x"), WarningNotSupported},
		{"501", statusErrorf(501, "x"), WarningNotSupported},
		{"500", statusErrorf(500, "x"), WarningError},
		{"504", statusErrorf(504, "x"), WarningTimeout},
		{"vendor refusal", &vendorAPIError{reason: WarningPermissionDenied, msg: "x"}, WarningPermissionDenied},
		{"context deadline", fmt.Errorf("API request failed: %w", deadline.Err()), WarningTimeout},
		{"dial refused", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, WarningUnreachable},
		{"dns", &net.DNSError{Err: "no such host", Name: "fw.example.test"}, WarningUnreachable},
		{"json", fmt.Errorf("decode: %w", &json.SyntaxError{Offset: 3}), WarningParseError},
		{"os.ErrNotExist", os.ErrNotExist, WarningError},
		{"nil", nil, WarningError},
	}
	for _, c := range cases {
		if got := ClassifyWarningReason(c.err); got != c.want {
			t.Errorf("%s: ClassifyWarningReason = %q, want %q", c.name, got, c.want)
		}
	}
}

// --- sanitization -----------------------------------------------------------

func TestSanitizeWarnings_StripsCredentialsAndBounds(t *testing.T) {
	const liveKey = "LUFRPT1LIVEKEY"
	in := []CollectionWarning{{
		Collector: "paloalto",
		Endpoint:  "https://admin:hunter2@198.51.100.7/api/?type=op&key=" + liveKey,
		Reason:    "made_up_reason",
		Effect:    "ARP\nnot collected",
		Detail: `Get "https://admin:hunter2@198.51.100.7/api/?type=op&key=` + liveKey + `": EOF ` +
			"-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----" + strings.Repeat("x", 2000),
	}}
	out := SanitizeWarnings(in)
	if len(out) != 1 {
		t.Fatalf("SanitizeWarnings returned %d warnings, want 1", len(out))
	}
	w := out[0]
	blob, _ := json.Marshal(w)
	for _, leaked := range []string{liveKey, "hunter2", "BEGIN RSA PRIVATE KEY"} {
		if strings.Contains(string(blob), leaked) {
			t.Errorf("%q survived SanitizeWarnings: %s", leaked, blob)
		}
	}
	if w.Endpoint != "/api/" {
		t.Errorf("Endpoint = %q, want the path alone", w.Endpoint)
	}
	// A bare path with a query string loses the whole query, not just the
	// parameters the name-based rule recognises.
	for raw, want := range map[string]string{
		"/api/v2/monitor/router/ipv4?vdom=root&sid=0123abcd": "/api/v2/monitor/router/ipv4",
		"/mgmt/tm/ltm/pool?expandSubcollections=true#frag":   "/mgmt/tm/ltm/pool",
		"show ip arp": "show ip arp",
	} {
		if got := SanitizeWarnings([]CollectionWarning{{Endpoint: raw, Reason: WarningError}})[0].Endpoint; got != want {
			t.Errorf("Endpoint %q sanitized to %q, want %q", raw, got, want)
		}
	}
	if w.Reason != WarningError {
		t.Errorf("an unknown reason was kept as %q", w.Reason)
	}
	if w.Effect != "ARP not collected" {
		t.Errorf("Effect = %q; control characters must fold to spaces", w.Effect)
	}
	if n := len([]rune(w.Detail)); n > maxWarningDetail {
		t.Errorf("Detail is %d runes, over the %d bound", n, maxWarningDetail)
	}
	if !strings.Contains(w.Detail, redact.Marker) {
		t.Errorf("Detail = %q; want the redaction marker so the backstop is visible", w.Detail)
	}
	// The input is not mutated.
	if !strings.Contains(in[0].Detail, liveKey) {
		t.Error("SanitizeWarnings mutated its input")
	}
}

func TestSanitizeWarnings_DedupesCapsAndKeepsNilAsNil(t *testing.T) {
	if SanitizeWarnings(nil) != nil || SanitizeWarnings([]CollectionWarning{}) != nil {
		t.Error("an empty warning list must stay nil, the one representation of none")
	}
	var many []CollectionWarning
	for i := 0; i < MaxCollectionWarnings+20; i++ {
		many = append(many, CollectionWarning{Collector: "cisco", Endpoint: "show " + strconv.Itoa(i), Reason: WarningError, Effect: "e"})
	}
	many = append([]CollectionWarning{many[0]}, many...) // a duplicate up front
	out := SanitizeWarnings(many)
	// The cap, plus ONE synthetic entry that says how many more there were:
	// a cap that dropped them silently would be a partial list presented as
	// the whole one.
	if len(out) != MaxCollectionWarnings+1 {
		t.Fatalf("got %d warnings, want the cap %d plus the overflow entry", len(out), MaxCollectionWarnings)
	}
	if out[0].Endpoint != "show 0" || out[1].Endpoint != "show 1" {
		t.Errorf("de-duplication lost insertion order: %+v", out[:2])
	}
	last := out[MaxCollectionWarnings]
	if last.Effect != "20 more warnings not shown" || last.Reason != WarningTruncated || last.Collector != "cisco" {
		t.Errorf("overflow entry = %+v, want \"20 more warnings not shown\" from cisco", last)
	}

	// Re-sanitizing (the platform does, on receipt from an agent) keeps the
	// count rather than re-counting the overflow entry as one more.
	if again := SanitizeWarnings(out); len(again) != len(out) || again[MaxCollectionWarnings].Effect != last.Effect {
		t.Errorf("re-sanitizing a capped list changed it: last = %+v", again[len(again)-1])
	}

	// Exactly at the cap there is nothing to say.
	exact := SanitizeWarnings(many[1 : MaxCollectionWarnings+1])
	if len(exact) != MaxCollectionWarnings || exact[len(exact)-1].Endpoint == overflowEndpoint {
		t.Errorf("a list exactly at the cap grew an overflow entry: %d", len(exact))
	}

	// One over is singular.
	one := SanitizeWarnings(many[1 : MaxCollectionWarnings+2])
	if one[len(one)-1].Effect != "1 more warning not shown" {
		t.Errorf("one over the cap reads %q", one[len(one)-1].Effect)
	}
}

// warningInterrogator emits a warning carrying a credential, the way a vendor
// error string carrying a request URL would.
type warningInterrogator struct{}

func (warningInterrogator) SupportedDeviceTypes() []string { return []string{"warning-test-device"} }
func (warningInterrogator) Interrogate(context.Context, DeviceInfo, Credentials) (*InterrogateResult, error) {
	return &InterrogateResult{Warnings: []CollectionWarning{{
		Endpoint: "/api/v2/monitor?access_token=should-not-escape",
		Reason:   WarningPermissionDenied,
		Effect:   "Routes not collected",
		Detail:   "GET https://192.0.2.1/api/v2/monitor?access_token=should-not-escape: 403",
	}}}, nil
}

// Registry.Get is the chokepoint: warnings go through Sanitize like everything
// else a collector emits, and one without a collector is stamped with the
// device type it was dispatched for.
func TestRegistryGet_ScrubsAndStampsWarnings(t *testing.T) {
	r := NewRegistry()
	r.Register(warningInterrogator{})
	interrogator, err := r.Get("warning-test-device")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	result, err := interrogator.Interrogate(context.Background(), DeviceInfo{DeviceType: "warning-test-device"}, Credentials{})
	if err != nil {
		t.Fatalf("Interrogate: %v", err)
	}
	blob, _ := json.Marshal(result)
	if strings.Contains(string(blob), "should-not-escape") {
		t.Errorf("Registry.Get did not scrub warnings: %s", blob)
	}
	if len(result.Warnings) != 1 || result.Warnings[0].Collector != "warning-test-device" {
		t.Errorf("the warning was lost or not stamped with its collector: %+v", result.Warnings)
	}
}
