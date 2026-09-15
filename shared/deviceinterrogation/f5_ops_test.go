package deviceinterrogation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// `sys/version` was the one system call in this package that copied a vendor
// object into DeviceInfo whole.
const f5VersionResponse = `{
  "kind": "tm:sys:version:versionstats",
  "items": [{
    "Version": "17.1.1.3",
    "Product": "BIG-IP",
    "Build": "0.0.5",
    "Edition": "Point Release 3",
    "adminPassphrase": "MUST-NOT-BE-COLLECTED",
    "sslPrivateKey": "MUST-NOT-BE-COLLECTED"
  }]
}`

// `sys/hardware` is a recursive stats tree whose keys the DEVICE chooses, so a
// typed struct cannot bound it the way it bounds the other collections. The
// leaves go through a named allowlist instead, and the two poison leaves below
// are what proves the allowlist is consulted rather than decorative.
const f5HardwareResponse = `{
  "kind": "tm:sys:hardware:hardwarestats",
  "entries": {
    "https://localhost/mgmt/tm/sys/hardware/system-info": {
      "nestedStats": {
        "entries": {
          "https://localhost/mgmt/tm/sys/hardware/system-info/0": {
            "nestedStats": {
              "entries": {
                "bigipChassisSerialNum": {"description": "f5-abcd-efgh"},
                "hostBoardSerialNum":    {"description": "hb-1234"},
                "platform":              {"description": "Z100"},
                "marketingName":         {"description": "BIG-IP Virtual Edition"},
                "cpuCount":              {"description": "4"},
                "passphrase":            {"description": "MUST-NOT-BE-COLLECTED"},
                "privateKey":            {"description": "MUST-NOT-BE-COLLECTED"}
              }
            }
          }
        }
      }
    }
  }
}`

const f5InterfaceResponse = `{
  "kind": "tm:net:interface:interfacecollectionstate",
  "items": [
    {"name": "1.1", "macAddress": "00:23:e9:aa:bb:01", "enabled": true, "mediaActive": "1000T-FD",
     "description": "MUST-NOT-BE-COLLECTED", "lldpAdmin": "txrx"},
    {"name": "1.2", "macAddress": "00:23:e9:aa:bb:02", "disabled": true, "mediaActive": "none"},
    {"name": "mgmt", "macAddress": "00:23:e9:aa:bb:00", "enabled": true, "mediaActive": "100TX-FD"},
    {"name": "1.3", "macAddress": "00:23:e9:aa:bb:03", "enabled": true, "mediaActive": "auto"}
  ]
}`

const f5VLANResponse = `{
  "kind": "tm:net:vlan:vlancollectionstate",
  "items": [
    {"name": "internal", "fullPath": "/Common/internal", "tag": 20, "mtu": 1500},
    {"name": "external", "fullPath": "/Common/external", "tag": 10},
    {"name": "unconfigured", "fullPath": "/Common/unconfigured", "tag": 0}
  ]
}`

const f5SelfResponse = `{
  "kind": "tm:net:self:selfcollectionstate",
  "items": [
    {"name": "self-internal", "fullPath": "/Common/self-internal", "address": "192.0.2.5/24",
     "vlan": "/Common/internal", "allowService": "MUST-NOT-BE-COLLECTED"},
    {"name": "self-external", "fullPath": "/Common/self-external", "address": "198.51.100.5/24",
     "vlan": "/Common/external"}
  ]
}`

const f5VirtualResponse = `{
  "kind": "tm:ltm:virtual:virtualcollectionstate",
  "items": [
    {"name": "vs_web_443", "destination": "/Common/198.51.100.10:443", "enabled": true,
     "pool": "/Common/web-pool", "profiles": [{"name": "clientssl-secure"}],
     "rules": ["MUST-NOT-BE-COLLECTED"]},
    {"name": "vs_api_8443", "destination": "/Common/198.51.100.11:8443", "enabled": true,
     "pool": "/Common/api-pool", "profiles": []},
    {"name": "vs_retired", "destination": "/Common/198.51.100.12:443", "disabled": true,
     "pool": "/Common/web-pool", "profiles": []},
    {"name": "vs_no_pool", "destination": "/Common/198.51.100.13:443", "enabled": true, "profiles": []}
  ]
}`

const f5PoolResponse = `{
  "kind": "tm:ltm:pool:poolcollectionstate",
  "items": [
    {"name": "web-pool", "fullPath": "/Common/web-pool",
     "monitor": "MUST-NOT-BE-COLLECTED", "description": "MUST-NOT-BE-COLLECTED",
     "membersReference": {"items": [
       {"name": "198.51.100.20:8080", "fullPath": "/Common/198.51.100.20:8080",
        "address": "198.51.100.20", "state": "up", "session": "monitor-enabled",
        "fqdn": {"autopopulate": "disabled"}},
       {"name": "web2.example.net:8080", "fullPath": "/Common/web2.example.net:8080",
        "state": "down", "fqdn": {"autopopulate": "enabled", "tmName": "web2.example.net"}}
     ]}},
    {"name": "api-pool", "fullPath": "/Common/api-pool",
     "membersReference": {"items": [
       {"name": "198.51.100.30:8443", "fullPath": "/Common/198.51.100.30:8443",
        "address": "198.51.100.30", "state": "up", "fqdn": {}}
     ]}}
  ]
}`

const f5ClientSSLResponse = `{
  "kind": "tm:ltm:profile:client-ssl:client-sslcollectionstate",
  "items": [{
    "name": "clientssl-secure",
    "kind": "tm:ltm:profile:client-ssl:client-sslstate",
    "ciphers": "ECDHE-RSA-AES256-GCM-SHA384",
    "tlsVersion": "1.2-1.3",
    "passphrase": "MUST-NOT-BE-COLLECTED",
    "certKeyChain": [{"name": "default", "cert": "/Common/default.crt", "key": "/Common/default.key"}]
  }]
}`

const f5EmptyCollection = `{"items": []}`

// newF5OpsTestServer answers every call the interrogation makes, so the tests
// drive the REAL interrogator rather than its parsers.
func newF5OpsTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/mgmt/shared/authn/login"):
			_, _ = w.Write([]byte(`{"token":{"token":"FAKE-TOKEN"}}`))
		case strings.HasSuffix(path, "/sys/version"):
			_, _ = w.Write([]byte(f5VersionResponse))
		case strings.HasSuffix(path, "/sys/hardware"):
			_, _ = w.Write([]byte(f5HardwareResponse))
		case strings.HasSuffix(path, "/net/interface"):
			_, _ = w.Write([]byte(f5InterfaceResponse))
		case strings.HasSuffix(path, "/net/vlan"):
			_, _ = w.Write([]byte(f5VLANResponse))
		case strings.HasSuffix(path, "/net/self"):
			_, _ = w.Write([]byte(f5SelfResponse))
		case strings.HasSuffix(path, "/ltm/virtual"):
			_, _ = w.Write([]byte(f5VirtualResponse))
		case strings.HasSuffix(path, "/ltm/pool"):
			_, _ = w.Write([]byte(f5PoolResponse))
		case strings.HasSuffix(path, "/profile/client-ssl"):
			_, _ = w.Write([]byte(f5ClientSSLResponse))
		default:
			_, _ = w.Write([]byte(f5EmptyCollection))
		}
	}))
}

func TestF5Interrogator_OpsCollectionIsWired(t *testing.T) {
	srv := newF5OpsTestServer(t)
	defer srv.Close()

	registry := NewRegistry()
	interrogator, err := registry.Get("f5_bigip")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Through the Registry, so the result has been through Sanitize as it
	// would be in production.
	result, err := interrogator.Interrogate(
		context.Background(),
		DeviceInfo{DeviceType: "f5_bigip", ManagementURL: srv.URL},
		Credentials{Username: "admin", Password: "admin"},
	)
	if err != nil {
		t.Fatalf("Interrogate: %v", err)
	}

	assertObservationsValid(t, "f5 interrogator", result)
	assertNoPoison(t, "f5 interrogator", result)

	for key, want := range map[string]any{
		factHWVendor:      f5Vendor,
		factHWSerial:      "f5-abcd-efgh",
		factHWModel:       "BIG-IP Virtual Edition",
		factOSName:        f5OSName,
		factOSVersion:     "17.1.1.3",
		factMgmtProtocol:  "https",
		factMgmtPlaintext: false,
	} {
		if got := factValue(t, result, key); got != want {
			t.Errorf("%s = %v (%T), want %v", key, got, got, want)
		}
	}
	for _, key := range []string{factNetInterfaces, factNetVlans} {
		if !hasFact(result, key) {
			t.Errorf("no %s fact reached the result; facts: %v", key, factKeys(result))
		}
	}

	if result.DeviceIdentity == nil || result.DeviceIdentity.ClassHint != f5ClassHint() {
		t.Errorf("class hint lost: %+v", result.DeviceIdentity)
	}
	// The `sys/version` projection must not have cost the identity anything.
	if result.DeviceIdentity.OSVersion != "TMOS 17.1.1.3" || result.DeviceIdentity.Model != "BIG-IP" {
		t.Errorf("device identity wrong: %+v", result.DeviceIdentity)
	}
	// And the crypto assets the interrogator already produced are untouched.
	if len(result.Assets) == 0 {
		t.Error("the VIP × SSL-profile assets were lost")
	}

	// The pool edges are the point of this collector.
	edges := relationshipsOfType(result, relTypeDependsOn)
	if len(edges) != 3 {
		t.Fatalf("expected three depends_on edges (two web-pool members, one api-pool), got %d: %+v", len(edges), edges)
	}
}

func TestF5PoolDependencies_VirtualServerDependsOnItsMembers(t *testing.T) {
	srv := newF5OpsTestServer(t)
	defer srv.Close()
	c := newF5Client(srv.URL, "admin", "admin", "", true)

	virtualServers, err := c.getVirtualServers(context.Background())
	if err != nil {
		t.Fatalf("getVirtualServers: %v", err)
	}
	pools, err := f5GetCollection[f5Pool](context.Background(), c, "/mgmt/tm/ltm/pool?expandSubcollections=true")
	if err != nil {
		t.Fatalf("pools: %v", err)
	}

	edges := f5PoolDependencies(virtualServers, pools)
	assertNoPoison(t, "f5 pool edges", edges)
	if len(edges) != 3 {
		t.Fatalf("expected three edges, got %d: %+v", len(edges), edges)
	}

	first := edges[0]
	if first.Type != relTypeDependsOn {
		t.Errorf("type = %q, want depends_on", first.Type)
	}
	// Canonical direction runs virtual server → member: a member going away
	// breaks the service, not the other way round.
	if first.Direction != SubjectToPeer {
		t.Errorf("direction = %q, want %q", first.Direction, SubjectToPeer)
	}
	if first.Subject.Identifier(IdentifierIPAddress) != "198.51.100.10" {
		t.Errorf("subject is not the virtual server: %+v", first.Subject)
	}
	if first.Subject.ClassHint != f5ClassHint() {
		t.Errorf("subject class hint = %q, want %q", first.Subject.ClassHint, f5ClassHint())
	}
	if first.Peer.Identifier(IdentifierIPAddress) != "198.51.100.20" {
		t.Errorf("peer is not the pool member: %+v", first.Peer)
	}
	// A pool member gets NO class hint. A pool declares an address, a port and a
	// monitor verdict; it does not declare whether the thing on the other end is
	// a server, another load balancer or a container ingress. The member lands
	// as `unknown_host` until something measures it, because a plausible-looking
	// wrong proposal is what gets bulk-approved.
	if first.Peer.ClassHint != "" {
		t.Errorf("peer class hint = %q, want none — a pool states nothing about what its member IS", first.Peer.ClassHint)
	}
	if first.Attributes["pool"] != "web-pool" || first.Attributes["remote_port"] != 8080 ||
		first.Attributes["member_state"] != "up" {
		t.Errorf("edge attributes wrong: %+v", first.Attributes)
	}

	// An FQDN node has no address; its name is the identity.
	second := edges[1]
	if second.Peer.Identifier(IdentifierFQDN) != "web2.example.net" {
		t.Errorf("FQDN pool member lost its identity: %+v", second.Peer)
	}
	if second.Attributes["member_state"] != "down" {
		t.Errorf("a monitor's verdict was dropped: %+v", second.Attributes)
	}

	// A disabled virtual server serves nothing, and a virtual server with no
	// pool forwards nowhere. Neither declares a dependency.
	for _, edge := range edges {
		// No member, of any node kind, may carry a class proposal.
		if edge.Peer.ClassHint != "" {
			t.Errorf("pool member %+v was proposed as %q; a pool declares nothing about what its member is", edge.Peer.DisplayName, edge.Peer.ClassHint)
		}
		// The near end is a different matter: a virtual server on a BIG-IP IS a
		// load balancer, measured from the box we are standing on.
		if edge.Subject.ClassHint != f5ClassHint() {
			t.Errorf("virtual server class hint = %q, want %q", edge.Subject.ClassHint, f5ClassHint())
		}
		if edge.Subject.Identifier(IdentifierIPAddress) == "198.51.100.12" {
			t.Errorf("a disabled virtual server produced a dependency: %+v", edge)
		}
		if edge.Subject.Identifier(IdentifierIPAddress) == "198.51.100.13" {
			t.Errorf("a virtual server with no pool produced a dependency: %+v", edge)
		}
	}
}

// A virtual server carrying no identifier must produce NO edge. An empty
// subject means "the interrogated device", so the edge would say the BIG-IP
// itself depends on the member — a different and wrong claim.
func TestF5PoolDependencies_SkipsUnidentifiableVirtualServers(t *testing.T) {
	edges := f5PoolDependencies(
		[]f5VirtualServer{{
			// A destination naming a virtual-address object, and a name with a
			// space in it, so neither normalises to an identifier.
			Name: "retired vip", Destination: "/Common/some-virtual-address", Enabled: true, Pool: "/Common/web-pool",
		}},
		[]f5Pool{{
			Name: "web-pool", FullPath: "/Common/web-pool",
			MembersRefence: struct {
				Items []f5PoolMember `json:"items"`
			}{Items: []f5PoolMember{{Name: "198.51.100.20:8080", Address: "198.51.100.20"}}},
		}},
	)
	if len(edges) != 0 {
		t.Errorf("an unidentifiable virtual server produced %d edges, which would attribute the dependency to the BIG-IP itself: %+v", len(edges), edges)
	}
}

// The hardware tree's keys are the device's to choose, so the leaves go through
// a named allowlist. This feeds it two secret-shaped leaves.
func TestF5Hardware_ProjectsLeavesOntoTheAllowlist(t *testing.T) {
	srv := newF5OpsTestServer(t)
	defer srv.Close()
	c := newF5Client(srv.URL, "admin", "admin", "", true)

	hardware := c.f5Hardware(context.Background())
	assertNoPoison(t, "f5 hardware", hardware)

	if hardware["bigipChassisSerialNum"] != "f5-abcd-efgh" || hardware["marketingName"] != "BIG-IP Virtual Edition" {
		t.Errorf("hardware identity lost: %+v", hardware)
	}
	// cpuCount is a real leaf that is simply not on the allowlist: nothing
	// reads it, so it is not collected.
	for _, unlisted := range []string{"cpuCount", "passphrase", "privateKey"} {
		if _, present := hardware[unlisted]; present {
			t.Errorf("%q survived the allowlist: %+v", unlisted, hardware)
		}
	}
}

func TestF5Interfaces_ReadsMediaAsStateAndSpeed(t *testing.T) {
	srv := newF5OpsTestServer(t)
	defer srv.Close()
	c := newF5Client(srv.URL, "admin", "admin", "", true)

	items, err := f5GetCollection[f5NetInterface](context.Background(), c, "/mgmt/tm/net/interface")
	if err != nil {
		t.Fatalf("interfaces: %v", err)
	}
	interfaces := f5Interfaces(items)
	// The typed struct is the allowlist: `description` and `lldpAdmin` have
	// nowhere to be decoded into.
	assertNoPoison(t, "f5 interfaces", interfaces)

	byName := map[string]map[string]interface{}{}
	for _, iface := range interfaces {
		byName[iface["name"].(string)] = iface
	}
	if len(byName) != 4 {
		t.Fatalf("interfaces = %v", interfaceNames(interfaces))
	}

	up := byName["1.1"]
	if up["mac"] != "00:23:e9:aa:bb:01" || up["state"] != "up" || up["admin_state"] != "up" || up["speed"] != 1000 {
		t.Errorf("1.1 projection wrong: %+v", up)
	}
	// F5 states the administrative state as one of two mutually exclusive
	// booleans; `disabled: true` is an administrative down, and "none" media is
	// an operational one.
	down := byName["1.2"]
	if down["admin_state"] != "down" || down["state"] != "down" {
		t.Errorf("1.2 projection wrong: %+v", down)
	}
	if _, hasSpeed := down["speed"]; hasSpeed {
		t.Errorf("an unlinked interface was given a speed: %+v", down)
	}
	if byName["mgmt"]["speed"] != 100 {
		t.Errorf("100TX-FD was not read as 100 Mbit/s: %+v", byName["mgmt"])
	}
	// "auto" is a link that has never negotiated: it is up, with no speed to
	// state.
	auto := byName["1.3"]
	if auto["state"] != "up" {
		t.Errorf("1.3 state = %v, want up", auto["state"])
	}
	if _, hasSpeed := auto["speed"]; hasSpeed {
		t.Errorf("\"auto\" was read as a speed: %+v", auto)
	}
}

func TestF5VLANs_SelfIPGivesTheSegmentAndTheDeviceAddress(t *testing.T) {
	srv := newF5OpsTestServer(t)
	defer srv.Close()
	c := newF5Client(srv.URL, "admin", "admin", "", true)

	vlans, err := f5GetCollection[f5NetVLAN](context.Background(), c, "/mgmt/tm/net/vlan")
	if err != nil {
		t.Fatalf("vlans: %v", err)
	}
	selfIPs, err := f5GetCollection[f5SelfIP](context.Background(), c, "/mgmt/tm/net/self")
	if err != nil {
		t.Fatalf("self IPs: %v", err)
	}

	projected := f5VLANs(vlans, selfIPs)
	assertNoPoison(t, "f5 vlans", projected)

	byName := map[string]map[string]interface{}{}
	for _, vlan := range projected {
		byName[vlan["name"].(string)] = vlan
	}
	// The untagged VLAN with no self IP is a name and nothing else.
	if len(byName) != 2 {
		t.Fatalf("VLANs = %+v, want the two with a tag", projected)
	}
	internal := byName["internal"]
	if internal["id"] != 20 || internal["subnet"] != "192.0.2.0/24" || internal["gateway"] != "192.0.2.5" {
		t.Errorf("internal VLAN projection wrong: %+v", internal)
	}
	if _, present := byName["unconfigured"]; present {
		t.Errorf("a VLAN with neither a tag nor a prefix was reported as a segment: %+v", projected)
	}
}

// The collections this interrogator reads are a closed list, and the ones it
// must never read are named in f5_ops.go's file comment.
func TestF5Ops_NeverAsksForKeysRulesOrAccounts(t *testing.T) {
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/mgmt/shared/authn/login") {
			_, _ = w.Write([]byte(`{"token":{"token":"FAKE-TOKEN"}}`))
			return
		}
		_, _ = w.Write([]byte(f5EmptyCollection))
	}))
	defer srv.Close()

	_, _ = (&F5Interrogator{}).Interrogate(
		context.Background(),
		DeviceInfo{DeviceType: "f5_bigip", ManagementURL: srv.URL},
		Credentials{Username: "admin", Password: "admin"},
	)

	if len(asked) == 0 {
		t.Fatal("the interrogation called nothing at all")
	}
	forbidden := []string{
		"sys/crypto/key", "sys/file/ssl-key", "auth/user", "sys/db",
		"ltm/rule", "ltm/monitor", "net/route",
	}
	for _, path := range asked {
		for _, fragment := range forbidden {
			if strings.Contains(path, fragment) {
				t.Errorf("the interrogation called %q, which returns key material, iRules or accounts", path)
			}
		}
	}
}

func TestF5SplitMember(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
	}{
		{"198.51.100.20:8080", "198.51.100.20", 8080},
		{"web2.example.net:443", "web2.example.net", 443},
		{"2001:db8::20.8080", "2001:db8::20", 8080},
		{"198.51.100.20:any", "198.51.100.20", 0},
		{"", "", 0},
	}
	for _, tc := range cases {
		host, port := f5SplitMember(tc.in)
		if host != tc.wantHost || port != tc.wantPort {
			t.Errorf("f5SplitMember(%q) = (%q, %d), want (%q, %d)", tc.in, host, port, tc.wantHost, tc.wantPort)
		}
	}
}
