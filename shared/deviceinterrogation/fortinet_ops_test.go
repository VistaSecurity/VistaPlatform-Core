package deviceinterrogation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// FortiOS cmdb objects are CONFIGURATION, and configuration is where the
// material lives. `system/interface` carries the PPPoE `password` and the
// dialup `psksecret`; the fixtures below carry both, and the projection must
// drop them before the redaction backstop ever runs.
const fortinetInterfaceResponse = `{
  "http_method": "GET",
  "status": "success",
  "serial": "FGT60F0000000001",
  "version": "v7.4.4",
  "results": [
    {
      "name": "port1",
      "ip": "203.0.113.2 255.255.255.248",
      "macaddr": "00:09:0f:aa:bb:01",
      "status": "up",
      "vlanid": 0,
      "type": "physical",
      "role": "wan",
      "vdom": "root",
      "password": "MUST-NOT-BE-COLLECTED",
      "psksecret": "MUST-NOT-BE-COLLECTED",
      "auth-cert": "MUST-NOT-BE-COLLECTED",
      "secondaryip": [{"ip": "203.0.113.3 255.255.255.248", "password": "MUST-NOT-BE-COLLECTED"}]
    },
    {
      "name": "internal",
      "ip": "192.0.2.1 255.255.255.0",
      "macaddr": "00:09:0f:aa:bb:02",
      "status": "up",
      "vlanid": 0,
      "type": "physical",
      "role": "lan",
      "vdom": "root"
    },
    {
      "name": "vlan-voice",
      "ip": "198.51.100.1 255.255.255.0",
      "status": "up",
      "vlanid": 40,
      "type": "vlan",
      "interface": "internal",
      "role": "lan",
      "vdom": "root",
      "ppp-echo-request": "MUST-NOT-BE-COLLECTED"
    },
    {
      "name": "unused",
      "ip": "0.0.0.0 0.0.0.0",
      "status": "down",
      "vlanid": 0,
      "type": "physical",
      "vdom": "root"
    }
  ]
}`

// The monitor API keys `results` BY INTERFACE NAME rather than returning a
// list. Decoding it with the cmdb response type yields nothing and reports
// success — the silent-empty failure this codebase keeps paying for.
const fortinetMonitorInterfaceResponse = `{
  "http_method": "GET",
  "status": "success",
  "results": {
    "port1": {"id": "port1", "name": "port1", "link": true, "speed": 1000.0, "duplex": 1, "mac": "00:09:0f:aa:bb:01"},
    "internal": {"id": "internal", "name": "internal", "link": true, "speed": 10000.0, "duplex": 1},
    "vlan-voice": {"id": "vlan-voice", "name": "vlan-voice", "link": true, "speed": 10000.0},
    "unused": {"id": "unused", "name": "unused", "link": false, "speed": 0.0},
    "mgmt": {"id": "mgmt", "name": "mgmt", "link": true, "speed": 1000.0, "ip": "10.0.0.1", "mask": "255.255.255.0"}
  }
}`

const fortinetRouteResponse = `{
  "http_method": "GET",
  "status": "success",
  "results": [
    {"ip_version": 4, "type": "static", "ip_mask": "0.0.0.0/0", "gateway": "203.0.113.1", "interface": "port1", "distance": 5},
    {"ip_version": 4, "type": "static", "ip_mask": "10.1.0.0/16", "gateway": "192.0.2.9", "interface": "internal"},
    {"ip_version": 4, "type": "static", "ip_mask": "10.2.0.0/16", "gateway": "192.0.2.9", "interface": "internal"},
    {"ip_version": 4, "type": "connected", "ip_mask": "192.0.2.0/24", "gateway": "0.0.0.0", "interface": "internal"}
  ]
}`

const fortinetSystemStatusResponse = `{
  "http_method": "GET",
  "status": "success",
  "serial": "FGT60F0000000001",
  "version": "v7.4.4",
  "build": 2662,
  "results": [
    {
      "version": "v7.4.4",
      "serial": "FGT60F0000000001",
      "model": "FGT60F",
      "model_name": "FortiGate 60F",
      "hostname": "fw-branch-01",
      "admin_password": "MUST-NOT-BE-COLLECTED",
      "private-key": "MUST-NOT-BE-COLLECTED"
    }
  ]
}`

const fortinetEmptyResponse = `{"http_method":"GET","status":"success","results":[]}`

// newFortinetOpsTestServer answers every call the interrogation makes, so the
// tests drive the REAL interrogator rather than its parsers.
func newFortinetOpsTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/cmdb/system/status"):
			_, _ = w.Write([]byte(fortinetSystemStatusResponse))
		case strings.HasSuffix(path, "/cmdb/system/interface"):
			_, _ = w.Write([]byte(fortinetInterfaceResponse))
		case strings.HasSuffix(path, "/monitor/system/interface"):
			_, _ = w.Write([]byte(fortinetMonitorInterfaceResponse))
		case strings.HasSuffix(path, "/monitor/router/ipv4"):
			_, _ = w.Write([]byte(fortinetRouteResponse))
		default:
			_, _ = w.Write([]byte(fortinetEmptyResponse))
		}
	}))
}

func TestFortinetInterrogator_OpsCollectionIsWired(t *testing.T) {
	srv := newFortinetOpsTestServer(t)
	defer srv.Close()

	registry := NewRegistry()
	interrogator, err := registry.Get("fortigate")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Through the Registry, so the result has been through Sanitize as it
	// would be in production.
	result, err := interrogator.Interrogate(
		context.Background(),
		DeviceInfo{DeviceType: "fortigate", ManagementURL: srv.URL},
		Credentials{Username: "admin", Password: "admin"},
	)
	if err != nil {
		t.Fatalf("Interrogate: %v", err)
	}

	assertObservationsValid(t, "fortinet interrogator", result)
	assertNoPoison(t, "fortinet interrogator", result)

	for key, want := range map[string]any{
		factHWVendor:             fortinetVendor,
		factHWModel:              "FortiGate 60F",
		factHWSerial:             "FGT60F0000000001",
		factOSName:               fortinetOSName,
		factOSVersion:            "v7.4.4",
		factNetRouteNextHopCount: 2, // 203.0.113.1 and 192.0.2.9; 0.0.0.0 is not a next hop
		factMgmtProtocol:         "https",
		factMgmtPlaintext:        false,
	} {
		if got := factValue(t, result, key); got != want {
			t.Errorf("%s = %v (%T), want %v", key, got, got, want)
		}
	}

	if result.DeviceIdentity == nil || result.DeviceIdentity.ClassHint != fortinetClassHint() {
		t.Errorf("class hint lost: %+v", result.DeviceIdentity)
	}
	if result.DeviceIdentity.OSVersion != "FortiOS v7.4.4" {
		t.Errorf("OS version = %q, want \"FortiOS v7.4.4\"", result.DeviceIdentity.OSVersion)
	}

	// A FortiGate has no edges to observe: it reports no neighbour table this
	// collector reads, and inventing one would be worse than an empty list.
	if len(result.Relationships) != 0 {
		t.Errorf("relationships were emitted with nothing to observe them from: %+v", result.Relationships)
	}
}

func TestFortinetInterfaces_MergesConfiguredAndRunningViews(t *testing.T) {
	configured := fortinetResultsFromJSON(t, fortinetInterfaceResponse)
	running := fortinetMonitorResultsFromJSON(t, fortinetMonitorInterfaceResponse)

	interfaces := fortinetInterfaces(configured, running)
	assertNoPoison(t, "fortinet interfaces", interfaces)

	byName := map[string]map[string]interface{}{}
	for _, iface := range interfaces {
		byName[iface["name"].(string)] = iface
	}
	// Four configured plus "mgmt", which only the running view reports.
	if len(byName) != 5 {
		t.Fatalf("interfaces = %v, want four configured plus mgmt", interfaceNames(interfaces))
	}

	wan := byName["port1"]
	if wan["mac"] != "00:09:0f:aa:bb:01" || wan["admin_state"] != "up" || wan["state"] != "up" || wan["speed"] != 1000 {
		t.Errorf("port1 projection wrong: %+v", wan)
	}
	if addrs, ok := wan["addresses"].([]interface{}); !ok || addrs[0] != "203.0.113.2/29" {
		t.Errorf("the \"address netmask\" pair was not combined into a prefix: %+v", wan)
	}

	vlan := byName["vlan-voice"]
	if vlan["vlan"] != 40 {
		t.Errorf("VLAN tag lost: %+v", vlan)
	}

	// Administrative and operational state are different facts: this interface
	// is administratively down AND unlinked, and both have to survive.
	unused := byName["unused"]
	if unused["admin_state"] != "down" || unused["state"] != "down" {
		t.Errorf("unused interface: %+v", unused)
	}
	if _, addressed := unused["addresses"]; addressed {
		t.Errorf("\"0.0.0.0 0.0.0.0\" was recorded as an address: %+v", unused)
	}
	if _, hasSpeed := unused["speed"]; hasSpeed {
		t.Errorf("a link-down interface was given a speed of 0: %+v", unused)
	}

	// The running view states mgmt's address as a separate address and mask.
	mgmt := byName["mgmt"]
	if addrs, ok := mgmt["addresses"].([]interface{}); !ok || addrs[0] != "10.0.0.1/24" {
		t.Errorf("the monitor view's address/mask pair was lost: %+v", mgmt)
	}
}

func TestFortinetVLANs_OnlyTaggedSubinterfaces(t *testing.T) {
	vlans := fortinetVLANs(fortinetResultsFromJSON(t, fortinetInterfaceResponse))
	assertNoPoison(t, "fortinet vlans", vlans)

	if len(vlans) != 1 {
		t.Fatalf("expected the one tagged subinterface, got %+v", vlans)
	}
	vlan := vlans[0]
	if vlan["id"] != 40 || vlan["name"] != "vlan-voice" {
		t.Errorf("VLAN projection wrong: %+v", vlan)
	}
	// The subinterface's address is the firewall's own address on that segment
	// — the same reading UniFi's ip_subnet gets.
	if vlan["subnet"] != "198.51.100.0/24" || vlan["gateway"] != "198.51.100.1" {
		t.Errorf("segment/gateway split wrong: %+v", vlan)
	}
}

// The routing table is retrieved and ONE integer is kept from it: no prefix, no
// next-hop address, nothing else.
func TestFortinetNextHopCount_CountsDistinctGatewaysOnly(t *testing.T) {
	routes := fortinetMonitorResultsFromJSON(t, fortinetRouteResponse)
	count, ok := fortinetNextHopCount(routes)
	if !ok || count != 2 {
		t.Errorf("fortinetNextHopCount = (%d, %v), want (2, true)", count, ok)
	}

	// A table that could not be read is not a device with no routes. An
	// unanswered query must not read as "this box forwards nowhere".
	if count, ok := fortinetNextHopCount(nil); ok {
		t.Errorf("an unread routing table reported %d next hops as a fact", count)
	}
	if count, ok := fortinetNextHopCount([]map[string]interface{}{}); !ok || count != 0 {
		t.Errorf("an empty-but-read table = (%d, %v), want (0, true)", count, ok)
	}
}

// The monitor API's object-keyed `results` decodes to nothing under the cmdb
// response type. This is the test that both shapes are accepted.
func TestFortinetGetMonitorResults_AcceptsBothResultShapes(t *testing.T) {
	srv := newFortinetOpsTestServer(t)
	defer srv.Close()
	c := newFortinetClient(srv.URL, "admin", "admin", true)

	keyed, err := c.getMonitorResults(context.Background(), "/api/v2/monitor/system/interface")
	if err != nil {
		t.Fatalf("getMonitorResults (object): %v", err)
	}
	if len(keyed) != 5 {
		t.Fatalf("object-shaped results decoded to %d entries, want 5", len(keyed))
	}
	for _, entry := range keyed {
		if _, named := entry["name"]; !named {
			t.Errorf("the object key was not folded in as a name: %+v", entry)
		}
	}

	listed, err := c.getMonitorResults(context.Background(), "/api/v2/monitor/router/ipv4")
	if err != nil {
		t.Fatalf("getMonitorResults (array): %v", err)
	}
	if len(listed) != 4 {
		t.Errorf("array-shaped results decoded to %d entries, want 4", len(listed))
	}
}

// The endpoints this collector calls are a closed list, and the ones it must
// never call are named in the file comment. This is the check that they stay
// uncalled.
func TestFortinetOps_NeverAsksForPolicyOrAccountObjects(t *testing.T) {
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fortinetEmptyResponse))
	}))
	defer srv.Close()

	_, _ = (&FortinetInterrogator{}).Interrogate(
		context.Background(),
		DeviceInfo{DeviceType: "fortigate", ManagementURL: srv.URL},
		Credentials{Username: "admin", Password: "admin"},
	)

	if len(asked) == 0 {
		t.Fatal("the interrogation called nothing at all")
	}
	forbidden := []string{
		"firewall/address", "firewall/addrgrp", "firewall/policy",
		"/user/", "system/admin", "system/api-user",
		"vpn.certificate/ca", "vpn.certificate/remote",
		"monitor/user/", "available-interfaces",
	}
	for _, path := range asked {
		for _, fragment := range forbidden {
			if strings.Contains(path, fragment) {
				t.Errorf("the interrogation called %q, which returns policy objects or accounts", path)
			}
		}
	}
}

// --- helpers ----------------------------------------------------------------

func fortinetResultsFromJSON(t *testing.T, body string) []map[string]interface{} {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	c := newFortinetClient(srv.URL, "admin", "admin", true)
	results, err := c.getResults(context.Background(), "/api/v2/cmdb/anything")
	if err != nil {
		t.Fatalf("getResults: %v", err)
	}
	return results
}

func fortinetMonitorResultsFromJSON(t *testing.T, body string) []map[string]interface{} {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	c := newFortinetClient(srv.URL, "admin", "admin", true)
	results, err := c.getMonitorResults(context.Background(), "/api/v2/monitor/anything")
	if err != nil {
		t.Fatalf("getMonitorResults: %v", err)
	}
	return results
}

// A 200 with no `results` member is an answer we could not read, not a device
// that forwards nowhere.
//
// getMonitorResults used to flatten the two into one empty-but-non-nil slice,
// which made fortinetNextHopCount's `ok=false` path unreachable from
// production: the only caller that can produce nil is the error branch, and the
// error branch never calls it. net.route_next_hop_count is read as "how
// connected is this box", so a fabricated 0 says the opposite of what an
// unanswered query means — the same three-valued-logic flattening this codebase
// keeps paying for.
//
// To mutation-test: return []map[string]interface{}{} for the absent case and
// the first subtest fails.
func TestFortinetGetMonitorResults_AnUnreadableAnswerIsNotAnEmptyOne(t *testing.T) {
	body := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	c := newFortinetClient(srv.URL, "admin", "admin", true)

	// No `results` member: unreadable. Nothing may be recorded from it.
	body = `{"http_method":"GET","status":"success"}`
	routes, err := c.getMonitorResults(context.Background(), "/api/v2/monitor/router/ipv4")
	if err != nil {
		t.Fatalf("getMonitorResults: %v", err)
	}
	if routes != nil {
		t.Errorf("a response with no results decoded to %#v, want nil", routes)
	}
	if count, ok := fortinetNextHopCount(routes); ok {
		t.Errorf("an unreadable routing table reported %d next hops as a fact", count)
	}

	// An explicit empty list IS an answer: this device really has no routes
	// with a next hop, and 0 is the true value.
	body = `{"http_method":"GET","status":"success","results":[]}`
	routes, err = c.getMonitorResults(context.Background(), "/api/v2/monitor/router/ipv4")
	if err != nil {
		t.Fatalf("getMonitorResults (empty list): %v", err)
	}
	if routes == nil {
		t.Fatal("an explicit empty list decoded to nil; the two cases have been flattened again")
	}
	if count, ok := fortinetNextHopCount(routes); !ok || count != 0 {
		t.Errorf("an empty-but-read table = (%d, %v), want (0, true)", count, ok)
	}
}
