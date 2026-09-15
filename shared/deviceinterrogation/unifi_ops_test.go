package deviceinterrogation

import (
	"encoding/json"
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

func TestUnifiNetworkFacts_ProjectsLANsAndDropsDHCPDetail(t *testing.T) {
	result := &InterrogateResult{}
	unifiEmitNetworkFacts(result, unifiNetworkConfFixture())

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

	unifiEmitDeviceObservations(result, unifiSwitchFixture(), controller, unifiVLANByNetworkID(confs))

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
	uplink := byName["Uplink"]
	if uplink["state"] != "up" || uplink["admin_state"] != "up" || uplink["speed"] != 1000 {
		t.Errorf("port state lost: %+v", uplink)
	}
	if uplink["vlan"] != nil {
		t.Errorf("the untagged default network gave a port a VLAN id: %+v", uplink)
	}
	camera := byName["Camera 1"]
	if camera["vlan"] != 20 {
		t.Errorf("native_networkconf_id was not resolved to a VLAN: %+v", camera)
	}
	if camera["state"] != "down" || camera["admin_state"] != "down" {
		t.Errorf("a disabled port must record both states: %+v", camera)
	}
	if _, present := uplink["poe_power"]; present {
		t.Errorf("a port field outside the allowlist was collected: %+v", uplink)
	}

	// --- neighbours -------------------------------------------------------
	neighbors := factValue(t, result, factNetNeighbors).([]map[string]interface{})
	if len(neighbors) != 1 {
		t.Fatalf("expected the one real LLDP neighbour (the all-zero chassis id is a placeholder), got %+v", neighbors)
	}
	n := neighbors[0]
	if n["protocol"] != "lldp" || n["remote_mac"] != "00:1b:17:00:00:01" ||
		n["remote_name"] != "core-sw-1.example.net" || n["remote_port"] != "Gi1/0/24" || n["local_port"] != "Uplink" {
		t.Errorf("LLDP neighbour projection wrong: %+v", n)
	}
	if strings.Contains(strings.Join(factKeys(result), ","), "system_desc") {
		t.Errorf("the neighbour's system description was collected")
	}

	// --- edges ------------------------------------------------------------
	memberships := relationshipsOfType(result, relTypeMemberOf)
	if len(memberships) != 2 {
		t.Fatalf("expected member_of edges to the controller and to the uplink switch, got %+v", memberships)
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
	if uplinkEdge.Peer.Identifier(IdentifierMACAddress) != "00:1b:17:00:00:01" {
		t.Errorf("uplink edge peer wrong: %+v", uplinkEdge.Peer)
	}
	if uplinkEdge.Attributes["local_port"] != "Port 1" || uplinkEdge.Attributes["remote_port"] != "Port 24" {
		t.Errorf("uplink port attributes lost: %+v", uplinkEdge.Attributes)
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
	unifiEmitDeviceObservations(result, sw, controller, vlans)
	unifiEmitDeviceObservations(result, ap, controller, vlans)

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
	unifiEmitDeviceObservations(result, device, controller, nil)

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
	}, unifiControllerPeer("192.0.2.1", nil), nil)

	if len(result.Facts) != 0 || len(result.Relationships) != 0 {
		t.Errorf("facts were emitted for a device nothing can resolve: %v / %+v", factKeys(result), result.Relationships)
	}
}

// The metadata allowlist is what keeps the ~120-field device object out of
// asset metadata. Widening it for the ops set must not have widened it into the
// nested tables, which are read for facts and edges instead.
func TestConvertDeviceToAsset_AllowlistStaysScalar(t *testing.T) {
	c := &unifiClient{}
	asset := c.convertDeviceToAsset(unifiSwitchFixture(), "default")

	assertNoPoison(t, "unifi device metadata", asset)

	allowed := map[string]bool{
		// derived keys convertDeviceToAsset adds by hand
		"mac_address": true, "firmware_version": true, "device_type": true,
		"site_id": true, "source": true,
	}
	for _, field := range unifiDeviceInventoryFields {
		allowed[field] = true
	}
	for key := range asset.Metadata {
		if !allowed[key] {
			t.Errorf("metadata key %q is on neither the allowlist nor the derived list", key)
		}
	}
	for _, table := range unifiDeviceStructuredFields {
		if _, present := asset.Metadata[table]; present {
			t.Errorf("nested table %q was copied into metadata; it is read for facts, not stored raw", table)
		}
	}
	if asset.Metadata["uptime"] != float64(1234567) {
		t.Errorf("uptime was not kept by the widened allowlist: %#v", asset.Metadata["uptime"])
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
