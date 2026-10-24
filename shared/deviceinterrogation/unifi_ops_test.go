package deviceinterrogation

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// unifiNetworkConfFixture is a site's networkconf response: two ordinary
// networks, a WAN, a disabled VLAN and a site-to-site VPN, each carrying the
// secret fields a real controller returns.
func unifiNetworkConfFixture() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"_id":              "net-lan",
			"name":             "Default",
			"purpose":          "corporate",
			"enabled":          true,
			"ip_subnet":        "192.0.2.1/24",
			"dhcpd_enabled":    true,
			"dhcpd_start":      "192.0.2.100",
			"dhcpd_stop":       "192.0.2.200",
			"dhcpd_dns_1":      "192.0.2.53",
			"domain_name":      "example.net",
			"x_radius_secret":  poison,
			"radiusprofile_id": "rp-1",
		},
		{
			"_id":           "net-iot",
			"name":          "IoT",
			"purpose":       "corporate",
			"enabled":       true,
			"vlan_enabled":  true,
			"vlan":          float64(20),
			"ip_subnet":     "198.51.100.1/24",
			"dhcpd_enabled": false,
			"x_wpa_psk":     poison,
			"x_passphrase":  poison,
			"x_iapp_key":    poison,
		},
		{
			"_id":       "net-wan",
			"name":      "WAN",
			"purpose":   "wan",
			"enabled":   true,
			"wan_type":  "dhcp",
			"x_wan_psk": poison,
		},
		{
			"_id":       "net-old",
			"name":      "Retired VLAN",
			"purpose":   "corporate",
			"enabled":   false,
			"vlan":      float64(66),
			"ip_subnet": "203.0.113.1/24",
		},
		{
			"_id":                    "net-vpn",
			"name":                   "Branch tunnel",
			"purpose":                "site-vpn",
			"vpn_type":               "ipsec-vpn",
			"ipsec_encryption":       "aes256",
			"ipsec_hash":             "sha256",
			"x_ipsec_pre_shared_key": poison,
		},
	}
}

// unifiSwitchFixture is a `stat/device` object for an adopted switch, with the
// nested tables the ops set reads and the x_-prefixed secrets the controller
// returns alongside them.
func unifiSwitchFixture() map[string]interface{} {
	return map[string]interface{}{
		"name":           "Office Switch",
		"ip":             "192.0.2.11",
		"mac":            "78:8a:20:4b:ee:41",
		"model":          "US8P150",
		"type":           "usw",
		"version":        "6.6.77.15402",
		"serial":         "788A204BEE41",
		"adopted":        true,
		"state":          float64(1),
		"uptime":         float64(1234567),
		"x_authkey":      poison,
		"x_vwirekey":     poison,
		"x_ssh_password": poison,
		"syslog_key":     poison,
		"ethernet_table": []interface{}{
			map[string]interface{}{"name": "eth0", "mac": "78:8a:20:4b:ee:41", "num_port": float64(8)},
		},
		"port_table": []interface{}{
			map[string]interface{}{
				"port_idx":              float64(1),
				"name":                  "Uplink",
				"up":                    true,
				"enable":                true,
				"speed":                 float64(1000),
				"native_networkconf_id": "net-lan",
				"poe_power":             "6.20",
				"x_port_key":            poison,
			},
			map[string]interface{}{
				"port_idx":              float64(2),
				"name":                  "Camera 1",
				"up":                    false,
				"enable":                false,
				"speed":                 float64(0),
				"native_networkconf_id": "net-iot",
			},
		},
		"lldp_table": []interface{}{
			map[string]interface{}{
				"chassis_id":      "00:1b:17:00:00:01",
				"system_name":     "core-sw-1.example.net",
				"port_id":         "Gi1/0/24",
				"local_port_name": "Uplink",
				"local_port_idx":  float64(1),
				"is_wired":        true,
				"system_desc":     "Cisco IOS Software, C9300 " + poison,
			},
			map[string]interface{}{
				// An empty port: the controller reports the all-zero chassis id
				// and no name. Nothing to say about it.
				"chassis_id":     "00:00:00:00:00:00",
				"local_port_idx": float64(7),
			},
		},
		"uplink": map[string]interface{}{
			"uplink_mac":         "00:1b:17:00:00:01",
			"uplink_device_name": "core-sw-1.example.net",
			"uplink_remote_port": float64(24),
			"port_idx":           float64(1),
			"type":               "wire",
			"x_uplink_key":       poison,
		},
	}
}

func factValue(t *testing.T, result *InterrogateResult, key string) any {
	t.Helper()
	for _, f := range result.Facts {
		if f.Key == key {
			return f.Value
		}
	}
	t.Fatalf("no %s fact was emitted; facts present: %v", key, factKeys(result))
	return nil
}

func factKeys(result *InterrogateResult) []string {
	keys := make([]string, 0, len(result.Facts))
	for _, f := range result.Facts {
		keys = append(keys, f.Key)
	}
	return keys
}

func hasFact(result *InterrogateResult, key string) bool {
	for _, f := range result.Facts {
		if f.Key == key {
			return true
		}
	}
	return false
}

func relationshipsOfType(result *InterrogateResult, relType string) []RelationshipObservation {
	var out []RelationshipObservation
	for _, rel := range result.Relationships {
		if rel.Type == relType {
			out = append(out, rel)
		}
	}
	return out
}

func peerWithHostname(result *InterrogateResult, hostname string) *PeerRef {
	for i := range result.Facts {
		if result.Facts[i].Subject.Identifier(IdentifierHostname) == hostname {
			p := result.Facts[i].Subject
			return &p
		}
	}
	for i := range result.Relationships {
		if result.Relationships[i].Subject.Identifier(IdentifierHostname) == hostname {
			p := result.Relationships[i].Subject
			return &p
		}
	}
	return nil
}

func TestUnifiNetworkFacts_ProjectsLANsAndDropsDHCPDetail(t *testing.T) {
	result := &InterrogateResult{}
	unifiEmitNetworkFacts(result, unifiNetworkConfFixture(), true)

	assertObservationsValid(t, "unifi networkconf", result)
	assertNoPoison(t, "unifi networkconf", result)

	value := factValue(t, result, factNetVlans)
	vlans, ok := value.([]map[string]interface{})
	if !ok {
		t.Fatalf("net.vlans is %T, want []map[string]interface{} — a typed struct would be invisible to Sanitize", value)
	}
	if len(vlans) != 2 {
		t.Fatalf("expected the two enabled LAN/VLAN networks, got %d: %+v", len(vlans), vlans)
	}

	// The untagged default LAN: a name, a prefix and a gateway, and NO id.
	lan := vlans[0]
	if _, hasID := lan["id"]; hasID {
		t.Errorf("an untagged network was given a VLAN id: %+v", lan)
	}
	if lan["name"] != "Default" || lan["subnet"] != "192.0.2.0/24" || lan["gateway"] != "192.0.2.1" {
		t.Errorf("LAN projection wrong: %+v", lan)
	}
	if lan["dhcp_enabled"] != true || lan["dhcp_range_configured"] != true {
		t.Errorf("DHCP posture lost: %+v", lan)
	}

	// The tagged VLAN.
	iot := vlans[1]
	if iot["id"] != 20 || iot["name"] != "IoT" || iot["subnet"] != "198.51.100.0/24" {
		t.Errorf("VLAN projection wrong: %+v", iot)
	}
	if iot["dhcp_enabled"] != false || iot["dhcp_range_configured"] != false {
		t.Errorf("a network with no DHCP was not recorded as such: %+v", iot)
	}

	// The addressing plan itself is not collected — only whether a pool exists.
	blob, _ := json.Marshal(result.Facts)
	for _, leaked := range []string{"192.0.2.100", "192.0.2.200", "192.0.2.53", "example.net"} {
		if strings.Contains(string(blob), leaked) {
			t.Errorf("DHCP detail %q was collected: %s", leaked, blob)
		}
	}
	// WAN, disabled and VPN networks are not segments.
	for _, absent := range []string{"WAN", "Retired VLAN", "Branch tunnel"} {
		if strings.Contains(string(blob), absent) {
			t.Errorf("network %q should not appear in net.vlans: %s", absent, blob)
		}
	}
}

func TestUnifiDeviceObservations_EmitsOpsFactsAndTopology(t *testing.T) {
	confs := unifiNetworkConfFixture()
	result := &InterrogateResult{}
	controller := unifiControllerPeer("unifi.example.net", map[string]interface{}{"controller_name": "HQ Controller"})

	unifiEmitDeviceObservations(result, unifiSwitchFixture(), controller, unifiVLANByNetworkID(confs), unifiWLANIndex{})

	assertObservationsValid(t, "unifi device", result)
	assertNoPoison(t, "unifi device", result)

	// --- identity ---------------------------------------------------------
	for key, want := range map[string]any{
		factHWVendor:          unifiVendor,
		factHWModel:           "US8P150",
		factHWSerial:          "788A204BEE41",
		factHWFirmwareVersion: "6.6.77.15402",
		factNetUptimeSeconds:  1234567,
	} {
		if got := factValue(t, result, key); got != want {
			t.Errorf("%s = %v, want %v", key, got, want)
		}
	}

	// Every device fact is about the DEVICE, not the controller.
	for _, f := range result.Facts {
		if f.Subject.Identifier(IdentifierMACAddress) != "78:8a:20:4b:ee:41" {
			t.Errorf("fact %s is not attributed to the managed device: %+v", f.Key, f.Subject)
		}
		if f.Subject.ClassHint != "switch" {
			t.Errorf("fact %s subject class hint = %q, want switch", f.Key, f.Subject.ClassHint)
		}
	}

	// --- interfaces -------------------------------------------------------
	interfaces := factValue(t, result, factNetInterfaces).([]map[string]interface{})
	if len(interfaces) != 3 {
		t.Fatalf("expected eth0 plus two ports, got %+v", interfaces)
	}
	byName := map[string]map[string]interface{}{}
	for _, iface := range interfaces {
		byName[iface["name"].(string)] = iface
	}
	if byName["eth0"]["mac"] != "78:8a:20:4b:ee:41" {
		t.Errorf("ethernet_table MAC lost: %+v", byName["eth0"])
	}
	// The management address lands on the interface carrying the device's MAC.
	if addrs, _ := byName["eth0"]["addresses"].([]string); len(addrs) != 1 || addrs[0] != "192.0.2.11" {
		t.Errorf("management address not on eth0: %+v", byName["eth0"])
	}
	// Ports are named by their number, not by the operator's label
	// ("Uplink", "Camera 1"), which describes what is plugged in.
	uplink := byName["Port 1"]
	if uplink["state"] != "up" || uplink["admin_state"] != "up" || uplink["speed"] != 1000 {
		t.Errorf("port state lost: %+v", uplink)
	}
	if uplink["vlan"] != nil {
		t.Errorf("the untagged default network gave a port a VLAN id: %+v", uplink)
	}
	camera := byName["Port 2"]
	if camera["vlan"] != 20 || camera["mode"] != "access" {
		t.Errorf("native_networkconf_id was not resolved to a VLAN: %+v", camera)
	}
	if camera["state"] != "down" || camera["admin_state"] != "down" {
		t.Errorf("a disabled port must record both states: %+v", camera)
	}
	if _, present := uplink["poe_power"]; present {
		t.Errorf("a port field outside the allowlist was collected: %+v", uplink)
	}

	// --- neighbours -------------------------------------------------------
	// The one real LLDP neighbour (the all-zero chassis id is a placeholder)
	// and the wired uplink, as cable ends (DCIM row 3.3).
	neighbors := factValue(t, result, factNetNeighbors).([]map[string]interface{})
	if len(neighbors) != 2 {
		t.Fatalf("expected the LLDP neighbour and the wired uplink, got %+v", neighbors)
	}
	n := neighbors[0]
	if up := neighbors[1]; up["protocol"] != "lldp" || up["local_port"] != "Port 1" || up["remote_port"] != "Port 24" ||
		up["remote_mac"] != "00:1b:17:00:00:01" {
		t.Errorf("wired uplink neighbour wrong: %+v", up)
	}
	if n["protocol"] != "lldp" || n["remote_mac"] != "00:1b:17:00:00:01" ||
		n["remote_name"] != "core-sw-1.example.net" || n["remote_port"] != "Gi1/0/24" || n["local_port"] != "Uplink" {
		t.Errorf("LLDP neighbour projection wrong: %+v", n)
	}
	if strings.Contains(strings.Join(factKeys(result), ","), "system_desc") {
		t.Errorf("the neighbour's system description was collected")
	}

	// --- edges ------------------------------------------------------------
	// Controller membership only: the wired uplink is a cable now, not a
	// member_of edge with port names (row 3.3).
	memberships := relationshipsOfType(result, relTypeMemberOf)
	if len(memberships) != 1 {
		t.Fatalf("expected the one member_of edge to the controller, got %+v", memberships)
	}
	var adoption, uplinkEdge RelationshipObservation
	for _, rel := range memberships {
		switch rel.Attributes["membership"] {
		case "adopted":
			adoption = rel
		case "uplink":
			uplinkEdge = rel
		}
	}
	if adoption.Peer.Identifier(IdentifierFQDN) != "unifi.example.net" {
		t.Errorf("adoption edge does not point at the controller: %+v", adoption.Peer)
	}
	if adoption.Peer.ClassHint != "wireless_controller" {
		t.Errorf("controller class hint = %q", adoption.Peer.ClassHint)
	}
	if uplinkEdge.Type != "" {
		t.Errorf("a wired uplink still wrote a member_of edge: %+v", uplinkEdge)
	}

	connections := relationshipsOfType(result, relTypeConnectsTo)
	if len(connections) != 1 {
		t.Fatalf("expected one connects_to edge from LLDP, got %+v", connections)
	}
	edge := connections[0]
	if edge.Direction != SubjectToPeer {
		t.Errorf("direction = %q", edge.Direction)
	}
	if edge.Subject.Identifier(IdentifierMACAddress) != "78:8a:20:4b:ee:41" {
		t.Errorf("edge subject is not the managed device: %+v", edge.Subject)
	}
	if edge.Peer.Identifier(IdentifierFQDN) != "core-sw-1.example.net" {
		t.Errorf("edge peer lost its name: %+v", edge.Peer)
	}
	if edge.Attributes["local_port"] != "Uplink" || edge.Attributes["remote_port"] != "Gi1/0/24" {
		t.Errorf("LLDP port attributes lost: %+v", edge.Attributes)
	}
}

// One interrogation of a controller reports facts about MANY devices. Each
// device's facts must carry its own subject, or a consumer that reads the
// result as "facts about the interrogated device" attributes every switch's
// serial, port table and uptime to the controller — one asset with four
// serials, which is worse than not collecting them.
//
// The single-device test above cannot catch that: with one device, a correct
// subject and a wrong-but-constant subject look identical.
func TestUnifiDeviceObservations_TwoDevicesKeepDistinctSubjects(t *testing.T) {
	confs := unifiNetworkConfFixture()
	controller := unifiControllerPeer("unifi.example.net", map[string]interface{}{"controller_name": "HQ Controller"})

	sw := unifiSwitchFixture()

	ap := unifiSwitchFixture()
	ap["name"] = "AC LR"
	ap["type"] = "uap"
	ap["mac"] = "78:8a:20:4b:ee:99"
	ap["ip"] = "192.0.2.12"
	ap["model"] = "U7LR"
	ap["serial"] = "788A204BEE99"
	delete(ap, "ethernet_table")
	delete(ap, "port_table")
	delete(ap, "lldp_table")

	result := &InterrogateResult{}
	vlans := unifiVLANByNetworkID(confs)
	unifiEmitDeviceObservations(result, sw, controller, vlans, unifiWLANIndex{})
	unifiEmitDeviceObservations(result, ap, controller, vlans, unifiWLANIndex{})

	// The whole-result gate: two subjects means two hw.serial facts, which
	// would be a duplicate under one subject.
	assertObservationsValid(t, "unifi two devices", result)
	assertNoPoison(t, "unifi two devices", result)

	serials := map[string]string{} // subject MAC → serial
	for _, f := range result.Facts {
		if f.Key != factHWSerial {
			continue
		}
		mac := f.Subject.Identifier(IdentifierMACAddress)
		if mac == "" {
			t.Fatalf("a per-device fact carries no subject; it would be read as the controller's: %+v", f)
		}
		serials[mac] = f.Value.(string)
	}
	want := map[string]string{
		"78:8a:20:4b:ee:41": "788A204BEE41",
		"78:8a:20:4b:ee:99": "788A204BEE99",
	}
	if len(serials) != len(want) {
		t.Fatalf("expected one hw.serial per device, got %v", serials)
	}
	for mac, serial := range want {
		if serials[mac] != serial {
			t.Errorf("device %s got serial %q, want %q", mac, serials[mac], serial)
		}
	}

	// Class hints follow the device, not the controller.
	classes := map[string]string{}
	for _, f := range result.Facts {
		if mac := f.Subject.Identifier(IdentifierMACAddress); mac != "" {
			classes[mac] = f.Subject.ClassHint
		}
	}
	if classes["78:8a:20:4b:ee:41"] != "switch" || classes["78:8a:20:4b:ee:99"] != "access_point" {
		t.Errorf("class hints did not follow their devices: %v", classes)
	}

	// Both adoptions point at the one controller, from two different subjects.
	var adoptions []RelationshipObservation
	for _, rel := range relationshipsOfType(result, relTypeMemberOf) {
		if rel.Attributes["membership"] == "adopted" {
			adoptions = append(adoptions, rel)
		}
	}
	if len(adoptions) != 2 {
		t.Fatalf("expected one adoption edge per device, got %d", len(adoptions))
	}
	if adoptions[0].Subject.Identifier(IdentifierMACAddress) == adoptions[1].Subject.Identifier(IdentifierMACAddress) {
		t.Errorf("both adoption edges came from the same subject: %+v", adoptions)
	}
	for _, rel := range adoptions {
		if rel.Peer.Identifier(IdentifierFQDN) != "unifi.example.net" {
			t.Errorf("adoption edge does not point at the controller: %+v", rel.Peer)
		}
	}
}

func TestUnifiDeviceObservations_UnadoptedDeviceIsNotAMember(t *testing.T) {
	device := unifiSwitchFixture()
	device["adopted"] = false
	delete(device, "uplink")

	result := &InterrogateResult{}
	controller := unifiControllerPeer("192.0.2.1", nil)
	unifiEmitDeviceObservations(result, device, controller, nil, unifiWLANIndex{})

	if edges := relationshipsOfType(result, relTypeMemberOf); len(edges) != 0 {
		t.Errorf("an unadopted device was recorded as a member of the controller: %+v", edges)
	}
	// It is still a device the controller can see, so its facts stand.
	if !hasFact(result, factHWModel) {
		t.Errorf("facts about an unadopted device were dropped: %v", factKeys(result))
	}
}

func TestUnifiDeviceObservations_SkipsDevicesWithNoIdentifier(t *testing.T) {
	result := &InterrogateResult{}
	unifiEmitDeviceObservations(result, map[string]interface{}{
		"name":    "Unknown AP",
		"mac":     "00:00:00:00:00:00",
		"model":   "U7LR",
		"adopted": true,
	}, unifiControllerPeer("192.0.2.1", nil), nil, unifiWLANIndex{})

	if len(result.Facts) != 0 || len(result.Relationships) != 0 {
		t.Errorf("facts were emitted for a device nothing can resolve: %v / %+v", factKeys(result), result.Relationships)
	}
}

func TestUnifiManagementProtocol(t *testing.T) {
	if proto, plaintext := unifiManagementProtocol("https://unifi.example.net:8443"); proto != "https" || plaintext {
		t.Errorf("https controller reported as %q plaintext=%v", proto, plaintext)
	}
	if proto, plaintext := unifiManagementProtocol("http://192.0.2.1:8080"); proto != "http" || !plaintext {
		t.Errorf("a controller reached over plain HTTP must be recorded as plaintext, got %q plaintext=%v", proto, plaintext)
	}
}

// A wireless client's interface item says it is a station on the SSID it
// joined, typed by the 802.11 generation it associated with (else its band);
// a wired client's, a client the controller does not say is wireless, and a
// randomised-MAC client's do not.
func TestUnifiClientInterface_WirelessStation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		client map[string]interface{}
		want   map[string]interface{} // the station keys; nil for none
	}{
		{"wifi 6", map[string]interface{}{"mac": "28:6b:b4:b0:1b:99", "is_wired": false, "essid": "Home", "radio": "na", "radio_proto": "ax"},
			map[string]interface{}{"rf_role": "station", "ssids": []string{"Home"}, "type": "ieee802.11ax"}},
		{"band only", map[string]interface{}{"mac": "28:6b:b4:b0:1b:99", "is_wired": false, "essid": "Home", "radio": "ng"},
			map[string]interface{}{"rf_role": "station", "ssids": []string{"Home"}, "type": "ieee802.11n"}},
		{"no radio", map[string]interface{}{"mac": "28:6b:b4:b0:1b:99", "is_wired": false, "essid": "Home"},
			map[string]interface{}{"rf_role": "station", "ssids": []string{"Home"}}},
		{"wired", map[string]interface{}{"mac": "28:6b:b4:b0:1b:99", "is_wired": true, "essid": "Home", "radio_proto": "ax"}, nil},
		{"unsaid", map[string]interface{}{"mac": "28:6b:b4:b0:1b:99", "essid": "Home"}, nil},
		{"randomised MAC", map[string]interface{}{"mac": "da:a1:19:00:00:02", "ip": "192.0.2.9", "is_wired": false, "essid": "Home"}, nil},
	} {
		got := unifiClientInterface(tc.client)
		station := map[string]interface{}{}
		for _, k := range []string{"rf_role", "ssids", "type"} {
			if v, ok := got[k]; ok {
				station[k] = v
			}
		}
		if tc.want == nil {
			if len(station) != 0 {
				t.Errorf("%s: station keys %v, want none", tc.name, station)
			}
			continue
		}
		if !reflect.DeepEqual(station, tc.want) {
			t.Errorf("%s: station keys %v, want %v", tc.name, station, tc.want)
		}
	}
}

func TestUnifiClientObservations_AllowlistMACHostnameAndAPEdge(t *testing.T) {
	result := &InterrogateResult{}
	unifiEmitClientObservations(result, []map[string]interface{}{
		{
			"mac":           "4c:6e:0a:87:d4:80",
			"ip":            "192.168.1.68",
			"hostname":      "linux-2",
			"name":          "linux-2",
			"oui":           "Intel",
			"is_wired":      false,
			"ap_mac":        "78:8a:20:4b:ee:41",
			"essid":         "corp-wifi",
			"network":       "Default",
			"vlan":          float64(1),
			"last_seen":     float64(1_700_000_000),
			"x_fingerprint": poison,
			"fingerprint":   poison,
			"note":          "operator@example.com " + poison,
			"user_id":       poison,
		},
		{
			// Locally-administered MAC must not become an identifier or a CI.
			"mac":      "4e:6e:0a:87:d4:80",
			"ip":       "192.168.1.99",
			"hostname": "phone-random",
			"ap_mac":   "78:8a:20:4b:ee:41",
		},
		{
			// Globally-administered MAC, no AP: still a peer (via a subject
			// fact). `.local` must stay a hostname, not an unscoped FQDN.
			"mac":      "4c:6e:0a:87:d4:81",
			"hostname": "4c6e0a87d480.local",
			"ip":       "192.168.1.70",
		},
	})

	assertObservationsValid(t, "unifi clients", result)
	assertNoPoison(t, "unifi clients", result)

	edges := relationshipsOfType(result, relTypeConnectsTo)
	var linux2, laa *RelationshipObservation
	for i := range edges {
		h := edges[i].Subject.Identifier(IdentifierHostname)
		switch h {
		case "linux-2":
			linux2 = &edges[i]
		case "phone-random":
			laa = &edges[i]
		}
	}
	if linux2 == nil {
		t.Fatalf("expected a connects_to edge for linux-2, got %+v", edges)
	}
	if linux2.Subject.Identifier(IdentifierMACAddress) != "4c:6e:0a:87:d4:80" {
		t.Errorf("linux-2 MAC = %q", linux2.Subject.Identifier(IdentifierMACAddress))
	}
	if linux2.Subject.Identifier(IdentifierIPAddress) != "192.168.1.68" {
		t.Errorf("linux-2 IP = %q", linux2.Subject.Identifier(IdentifierIPAddress))
	}
	if linux2.Peer.Identifier(IdentifierMACAddress) != "78:8a:20:4b:ee:41" {
		t.Errorf("AP MAC = %q", linux2.Peer.Identifier(IdentifierMACAddress))
	}
	if linux2.Subject.Identifier(IdentifierFQDN) != "" {
		t.Errorf("linux-2 must not be filed as an FQDN: %+v", linux2.Subject.Identifiers)
	}

	localName := peerWithHostname(result, "4c6e0a87d480.local")
	if localName == nil {
		t.Fatalf("expected a peer for the .local hostname (fact or edge), facts=%v edges=%+v", factKeys(result), edges)
	}
	if localName.Identifier(IdentifierFQDN) != "" {
		t.Errorf(".local client was filed as FQDN: %+v", localName.Identifiers)
	}
	if localName.Identifier(IdentifierHostname) != "4c6e0a87d480.local" {
		t.Errorf(".local hostname = %q", localName.Identifier(IdentifierHostname))
	}
	if localName.Identifier(IdentifierMACAddress) != "4c:6e:0a:87:d4:81" {
		t.Errorf(".local MAC = %q, want the globally-administered station MAC", localName.Identifier(IdentifierMACAddress))
	}
	if laa != nil && laa.Subject.Identifier(IdentifierMACAddress) != "" {
		t.Errorf("LAA MAC became an identifier: %+v", laa.Subject.Identifiers)
	}
	phone := peerWithHostname(result, "phone-random")
	if phone != nil && phone.Identifier(IdentifierMACAddress) != "" {
		t.Errorf("LAA MAC became an identifier on the fact subject: %+v", phone.Identifiers)
	}

	projected := unifiProject(map[string]interface{}{
		"mac": "4c:6e:0a:87:d4:80", "hostname": "linux-2", "x_fingerprint": poison, "note": poison,
	}, unifiClientInventoryFields)
	assertNoPoison(t, "unifi sta projection", projected)
	assertKeysWithin(t, "unifi sta projection", projected, unifiClientInventoryFields)
}

func TestUniFiAliasIsOnlyDisplayContext(t *testing.T) {
	for _, alias := range []string{"printer", "printer.example.test", "Office Printer"} {
		peer := unifiClientPeer(map[string]interface{}{"name": alias, "hostname": "actual-host", "mac": "00:1a:2b:3c:4d:5e"})
		if peer.DisplayName != alias {
			t.Fatalf("lost alias: %+v", peer)
		}
		for _, id := range peer.Identifiers {
			if id.Value == alias {
				t.Fatalf("alias became identifier: %+v", peer)
			}
		}
	}
}

func TestUniFiManagedPeerIdentityEvidence(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		adopted               bool
		state                 int
		authoritative, direct bool
	}{
		{"connected", true, 1, true, true}, {"offline", true, 0, true, false}, {"unadopted", false, 1, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer := unifiDeviceSubject(map[string]interface{}{"name": "alias.example.test", "hostname": "actual-host", "adopted": tc.adopted, "state": float64(tc.state), "serial": "SERIAL", "mac": "00:1a:2b:3c:4d:5e"})
			if peer.IdentityEvidence.ControllerInventory != tc.authoritative || peer.IdentityEvidence.ConnectedInterface != tc.direct {
				t.Fatalf("incorrect controller proof: %+v", peer.IdentityEvidence)
			}
			if peer.DisplayName != "alias.example.test" || peer.Identifier(IdentifierHostname) != "actual-host" || peer.Identifier(IdentifierFQDN) != "" {
				t.Fatalf("alias promoted as identity: %+v", peer)
			}
		})
	}
	controller := unifiControllerPeer("controller.example.test", map[string]interface{}{"controller_name": "alias.example.test"})
	for _, id := range controller.Identifiers {
		if id.Value == "alias.example.test" {
			t.Fatalf("controller alias promoted: %+v", controller)
		}
	}
	client := unifiClientPeer(map[string]interface{}{"hostname": "station", "mac": "00:1a:2b:3c:4d:5e"})
	if !client.IdentityEvidence.ConnectedInterface || client.IdentityEvidence.ControllerInventory {
		t.Fatalf("station proof: %+v", client.IdentityEvidence)
	}
}

// unifiGatewayFixture is a `stat/device` object for a UniFi gateway: its `ip`
// names a LAN interface, and its two WAN objects carry the upstream
// configuration a real controller returns beside each address.
func unifiGatewayFixture() map[string]interface{} {
	return map[string]interface{}{
		"name":    "Edge Gateway",
		"ip":      "192.0.2.1",
		"mac":     "74:ac:b9:00:00:01",
		"model":   "UDR",
		"type":    "udm",
		"serial":  "74ACB9000001",
		"adopted": true,
		"state":   float64(1),
		"wan1": map[string]interface{}{
			"ip":               "203.0.113.10",
			"gateway":          poison,
			"dns":              []interface{}{poison},
			"netmask":          poison,
			"type":             "pppoe",
			"pppoe_username":   poison,
			"x_pppoe_password": poison,
		},
		"wan2": map[string]interface{}{
			"ip":      "198.51.100.20",
			"gateway": poison,
		},
	}
}

// D2: a gateway's WAN addresses are identifiers of the gateway, read
// from its own device record — and nothing else of the WAN configuration is
// collected. To mutation-test: add "gateway" or "pppoe_username" to
// unifiWANFields (poison appears), or drop the WAN loop in unifiDeviceSubject
// (the WAN addresses go missing).
func TestUnifiDeviceSubject_CarriesWANAddressesAndNothingElseOfTheWAN(t *testing.T) {
	result := &InterrogateResult{}
	unifiEmitDeviceObservations(result, unifiGatewayFixture(), unifiControllerPeer("192.0.2.1", nil), nil, unifiWLANIndex{})

	assertObservationsValid(t, "unifi gateway", result)
	assertNoPoison(t, "unifi gateway", result)

	if len(result.Facts) == 0 {
		t.Fatal("no facts were emitted for the gateway")
	}
	subject := result.Facts[0].Subject
	var addresses []string
	for _, id := range subject.Identifiers {
		if id.Kind == IdentifierIPAddress {
			addresses = append(addresses, id.Value)
		}
	}
	want := []string{"192.0.2.1", "203.0.113.10", "198.51.100.20"}
	if strings.Join(addresses, ",") != strings.Join(want, ",") {
		t.Fatalf("gateway subject addresses = %v, want %v", addresses, want)
	}

}

// A WAN that is down reports no address (or the unspecified one); it adds no
// identifier and the device's own address still identifies it.
func TestUnifiDeviceSubject_DownWANAddsNothing(t *testing.T) {
	device := unifiGatewayFixture()
	device["wan1"] = map[string]interface{}{"ip": "0.0.0.0"}
	device["wan2"] = map[string]interface{}{"ip": ""}
	subject := unifiDeviceSubject(device)
	for _, id := range subject.Identifiers {
		if id.Kind == IdentifierIPAddress && id.Value != "192.0.2.1" {
			t.Errorf("a down WAN contributed the address %q", id.Value)
		}
	}
}

// DCIM row 1.5b: the interface projection reads four more nested tables —
// vap_table, network_table, and more of port_table and the WAN objects — and
// each stays on its allowlist: the SSID passphrase, a network's RADIUS
// secret, a port's auth key and the WAN's PPPoE password are planted and must
// not appear in any fact. The readers copy named fields only, so widening an
// allowlist alone changes nothing a test can see; what this pins is that no
// reader hands the vendor object on. To mutation-test: copy the raw vap_table
// entry into the interface item in unifiInterfaces (poison appears).
func TestUnifiInterfaces_NewTablesStayOnTheirAllowlists(t *testing.T) {
	device := unifiGatewayFixture()
	device["wan1"] = map[string]interface{}{
		"ip": "203.0.113.10", "netmask": "255.255.255.0", "ifname": "eth8", "mac": "74:ac:b9:00:00:09", "up": true,
		"gateway": poison, "x_pppoe_password": poison,
	}
	device["ethernet_table"] = []interface{}{
		map[string]interface{}{"name": "eth0", "mac": "74:ac:b9:00:00:01"},
		map[string]interface{}{"name": "eth8", "mac": "74:ac:b9:00:00:09"},
	}
	device["port_table"] = []interface{}{
		map[string]interface{}{"port_idx": float64(9), "name": "Port 9", "ifname": "eth8", "media": "GE", "up": true,
			"enable": true, "speed": float64(1000), "x_port_auth_key": poison, "poe_mode": poison},
	}
	device["network_table"] = []interface{}{
		map[string]interface{}{"name": "LAN", "purpose": "corporate", "ip_subnet": "192.0.2.1/24", "enabled": true,
			"x_radius_secret": poison, "dhcpd_dns_1": poison},
		map[string]interface{}{"name": "IoT", "purpose": "corporate", "ip_subnet": "198.51.100.1/24", "vlan": float64(20)},
		map[string]interface{}{"name": "WAN", "purpose": "wan", "ip_subnet": "203.0.113.10/24"},
	}
	device["vap_table"] = []interface{}{
		map[string]interface{}{"name": "ra0", "radio": "ng", "essid": "Corp", "bssid": "74:ac:b9:00:00:20", "up": true,
			"x_passphrase": poison, "wlan_psk": poison},
	}
	result := &InterrogateResult{}
	unifiEmitDeviceObservations(result, device, unifiControllerPeer("192.0.2.1", nil), map[string]int{}, unifiWLANIndex{})

	assertObservationsValid(t, "unifi gateway interfaces", result)
	assertNoPoison(t, "unifi gateway interfaces", result)

	byName := map[string]map[string]interface{}{}
	for _, iface := range factValue(t, result, factNetInterfaces).([]map[string]interface{}) {
		byName[iface["name"].(string)] = iface
	}
	if got := fmt.Sprintf("%v %v", byName["Port 9"]["addresses"], byName["Port 9"]["mac"]); got != "[203.0.113.10/24] 74:ac:b9:00:00:09" {
		t.Errorf("the WAN did not land on the port it is: %+v", byName["Port 9"])
	}
	if _, ok := byName["eth8"]; ok {
		t.Errorf("eth8 is Port 9's kernel name, not a second interface: %+v", byName)
	}
	if got := fmt.Sprintf("%v %v %v", byName["br20"]["addresses"], byName["br20"]["vlan"], byName["br20"]["static_addresses"]); got != "[198.51.100.1/24] 20 [198.51.100.1/24]" {
		t.Errorf("br20 = %+v", byName["br20"])
	}
	if _, ok := byName["br0"]; !ok {
		t.Errorf("the untagged LAN's bridge is missing: %+v", byName)
	}
	if byName["ra0"]["type"] != "ieee802.11n" {
		t.Errorf("ra0 = %+v", byName["ra0"])
	}
	// The gateway's address on the LAN is held by br0; the management address
	// is not written twice.
	if addrs, _ := byName["eth0"]["addresses"].([]string); len(addrs) != 0 {
		t.Errorf("eth0 carries %v; 192.0.2.1 is br0's", addrs)
	}
}

// A WAN that is down adds no interface address.
func TestUnifiInterfaces_DownWANAddsNoInterface(t *testing.T) {
	device := unifiGatewayFixture()
	device["wan1"] = map[string]interface{}{"ip": "0.0.0.0"}
	device["wan2"] = map[string]interface{}{"ip": ""}
	for _, iface := range unifiInterfaces(device, nil, unifiWLANIndex{}) {
		if iface["addresses"] != nil {
			t.Errorf("a down WAN contributed an interface address: %+v", iface)
		}
	}
}
