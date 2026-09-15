package deviceinterrogation

import (
	"net/netip"
	"strconv"
	"strings"
)

// UniFi ops facts and observed topology (asset-inventory ADR-0004 D1 item 1).
//
// The controller already hands us everything below on calls the interrogator
// was ALREADY making. `rest/networkconf` carries every LAN and VLAN with its
// prefix, gateway and DHCP configuration, and was filtered to VPN entries only.
// Each `stat/device` object carries its uplink, its port table, its LLDP
// neighbours and its uptime, and 14 of its ~120 fields survived projection.
//
// What is added here is the ops set of D1: identity, interfaces, neighbours and
// VLANs, plus the two edge kinds a controller can see — adoption and uplink
// (`member_of`) and LLDP neighbours (`connects_to`).
//
// What is NOT added, and why:
//   - The DHCP range, its DNS servers, domain name, boot server and every other
//     option. That is the operator's addressing plan and nothing reads it; the
//     fact records only THAT a pool exists (see net.vlans in fact-keys.yaml).
//   - `x_`-prefixed fields of any object. UniFi marks its secrets that way —
//     the mesh PSK, per-device auth keys, the vwire key — and the original leak
//     this projection exists to close was exactly those.
//   - An LLDP neighbour's `system_desc`. It is a vendor banner, unbounded, and
//     no consumer reads it; the neighbour's name, MAC and port are the identity.
//   - The client list (`stat/sta`). Endpoint discovery from clients is its own
//     decision with its own privacy shape, deliberately out of this workstream.

// unifiDeviceStructuredFields names the device-object fields that are READ for
// facts and edges but never copied into asset metadata.
//
// They are nested vendor objects — an array of ports, a table of neighbours —
// and copying one into metadata is the mistake `unifiDeviceInventoryFields`
// exists to prevent, just one level down. Each is projected field by field by
// the functions below; the per-entry allowlists are beside them.
var unifiDeviceStructuredFields = []string{
	"uplink",         // → member_of edge to the uplink device
	"port_table",     // → net.interfaces, and the VLAN a port is on
	"ethernet_table", // → net.interfaces MACs
	"lldp_table",     // → net.neighbors and connects_to edges
}

// unifiPortFields is the allowlist of `port_table` entry fields. PoE draw,
// 802.1X state, per-port counters and the rest of the ~40 fields are not
// interface identity and have no consumer.
var unifiPortFields = []string{
	"port_idx",              // port number
	"name",                  // port name as configured
	"up",                    // operational state
	"enable",                // administrative state
	"speed",                 // negotiated speed, Mbit/s
	"native_networkconf_id", // which network the port is untagged on → VLAN id
}

// unifiEthernetFields is the allowlist of `ethernet_table` entry fields: the
// per-interface MAC addresses a device reports for itself.
var unifiEthernetFields = []string{"name", "mac", "num_port"}

// unifiLLDPFields is the allowlist of `lldp_table` entry fields.
var unifiLLDPFields = []string{
	"chassis_id",      // neighbour MAC
	"system_name",     // neighbour name as advertised
	"port_id",         // neighbour port
	"local_port_name", // our port
	"local_port_idx",
	"is_wired",
	// Posture the neighbour broadcast about ITSELF, added so a peer's class has
	// evidence beyond its MAC prefix. Both are 802.1AB fields, both are
	// advertised in the clear to the whole segment, and neither is an identity.
	"chassis_descr", // the LLDP system description
	"capabilities",  // the 802.1AB system capabilities, as a string array
}

// unifiUplinkFields is the allowlist of `uplink` object fields.
var unifiUplinkFields = []string{
	"uplink_mac",         // the device we uplink to
	"ap_mac",             // wireless uplink: the AP we are meshed to
	"uplink_device_name", // display name of that device
	"uplink_remote_port", // its port
	"remote_port",
	"port_idx", // our port
	"type",     // "wire" | "wireless"
}

// unifiVendor is the hardware vendor of every device a UniFi controller
// manages. Derived rather than reported: the controller states a model and a
// version but never a manufacturer — it does not need to, because it adopts
// nothing else.
//
// Spelled as standards/oui-vendors.csv spells it, which is not cosmetic in two
// places at once. It is the vendor GUARD on the `model` rules for UniFi device
// types, so a different spelling here silently stops every one of them from
// firing; and it is the same string shared/hostobs derives from a captured
// frame, so a device seen passively and a device seen through the controller
// have to agree or they read as two manufacturers.
const unifiVendor = "Ubiquiti Networks"

// unifiEmitNetworkFacts emits the site's LAN and VLAN networks as a net.vlans
// fact on the controller.
//
// VPN networks are excluded: they are already converted to vpn_gateway assets
// with their crypto posture by unifiVPNAssets, and a tunnel is not a segment.
// WAN networks are excluded because a WAN is the far side of the boundary, not
// a network the device serves. A disabled network is excluded: it is configured
// but carries nothing, and a segment nobody can be on would be a phantom on the
// map.
func unifiEmitNetworkFacts(result *InterrogateResult, confs []map[string]interface{}) {
	vlans := make([]map[string]interface{}, 0, len(confs))
	for _, conf := range confs {
		if unifiIsVPNNetwork(conf) {
			continue
		}
		if purpose, _ := conf["purpose"].(string); purpose == "wan" {
			continue
		}
		if enabled, ok := conf["enabled"].(bool); ok && !enabled {
			continue
		}
		if entry := unifiVLANEntry(conf); entry != nil {
			vlans = append(vlans, entry)
		}
	}
	if len(vlans) == 0 {
		return
	}
	result.addFact(factNetVlans, vlans, ConfidenceReported)
}

// unifiVLANEntry projects one networkconf entry onto a net.vlans item, or nil
// when the entry says nothing worth recording.
func unifiVLANEntry(conf map[string]interface{}) map[string]interface{} {
	entry := map[string]interface{}{}

	// `vlan` is the 802.1Q tag, serialized as a number or a string depending on
	// controller version. An untagged network has none, and gets no id: see the
	// net.vlans item schema for why 0 or 1 would be a fabrication.
	if raw := firstUnifiValue(conf, "vlan"); raw != "" {
		if id, err := strconv.Atoi(raw); err == nil && id > 0 {
			entry["id"] = id
		}
	}
	if name := firstUnifiString(conf, "name"); name != "" {
		entry["name"] = name
	}
	// UniFi's ip_subnet is the GATEWAY address with a prefix length
	// ("192.168.1.1/24"), not the prefix. Masking it yields the segment, and
	// the address it was masked from is the device's own address on that
	// network — two facts from one field, neither of them a guess.
	if subnet := firstUnifiString(conf, "ip_subnet"); subnet != "" {
		if prefix, err := netip.ParsePrefix(subnet); err == nil {
			entry["subnet"] = prefix.Masked().String()
			if addr := prefix.Addr(); addr != prefix.Masked().Addr() {
				entry["gateway"] = addr.String()
			}
		}
	}
	if dhcp, ok := conf["dhcpd_enabled"].(bool); ok {
		entry["dhcp_enabled"] = dhcp
	}
	entry["dhcp_range_configured"] = firstUnifiString(conf, "dhcpd_start") != "" &&
		firstUnifiString(conf, "dhcpd_stop") != ""

	// A network with neither a tag nor a prefix is a name and nothing else.
	if _, hasID := entry["id"]; !hasID {
		if _, hasSubnet := entry["subnet"]; !hasSubnet {
			return nil
		}
	}
	return entry
}

// unifiDeviceSubject builds the PeerRef naming a managed device: the subject of
// its facts and the near end of its edges.
//
// The controller's display name ("AC LR", "Office Switch") is a label, not a
// hostname — it has spaces — so it lands in DisplayName and the identifiers are
// the MAC and the address. AddIdentifier drops whatever does not normalise,
// which is how the all-zero MACs an unadopted device reports never become an
// identity.
func unifiDeviceSubject(device map[string]interface{}) PeerRef {
	name := firstUnifiString(device, "name")
	subject := peerRef(name, unifiClassHint(firstUnifiString(device, "type")))
	subject.AddIdentifier(IdentifierMACAddress, firstUnifiString(device, "mac"))
	subject.AddIdentifier(IdentifierIPAddress, firstUnifiString(device, "ip"))
	subject.AddIdentifier(IdentifierSerialNumber, firstUnifiString(device, "serial"))
	// A name without a space may well BE the hostname; one with a space is a
	// label. canonicalDNSName is the arbiter, not a guess here.
	subject.AddIdentifier(IdentifierHostname, name)
	return subject
}

// unifiControllerPeer builds the PeerRef naming the controller itself, for the
// far end of every managed device's member_of edge.
func unifiControllerPeer(host string, deviceInfo map[string]interface{}) PeerRef {
	display, _ := deviceInfo["controller_name"].(string)
	if display == "" {
		display, _ = deviceInfo["controller_hostname"].(string)
	}
	peer := peerRef(display, unifiControllerClassHint())
	if !peer.AddIdentifier(IdentifierIPAddress, host) {
		if !peer.AddIdentifier(IdentifierFQDN, host) {
			peer.AddIdentifier(IdentifierHostname, host)
		}
	}
	if display != "" {
		peer.AddIdentifier(IdentifierHostname, display)
	}
	return peer
}

// unifiEmitDeviceObservations emits one managed device's ops facts and edges.
//
// vlanByNetworkID maps a networkconf id to its 802.1Q tag so a port's untagged
// network can be reported as a VLAN id rather than an opaque controller id.
func unifiEmitDeviceObservations(
	result *InterrogateResult,
	device map[string]interface{},
	controller PeerRef,
	vlanByNetworkID map[string]int,
) {
	subject := unifiDeviceSubject(device)
	if len(subject.Identifiers) == 0 {
		// Nothing downstream could resolve these facts to an asset, so writing
		// them would create rows nothing can ever join to.
		return
	}

	// --- identity ---------------------------------------------------------
	result.addSubjectFact(subject, factHWVendor, unifiVendor, ConfidenceDerived)
	if model := firstUnifiString(device, "model"); model != "" {
		result.addSubjectFact(subject, factHWModel, model, ConfidenceReported)
	}
	if serial := firstUnifiString(device, "serial"); serial != "" {
		result.addSubjectFact(subject, factHWSerial, serial, ConfidenceReported)
	}
	if version := firstUnifiString(device, "version"); version != "" {
		result.addSubjectFact(subject, factHWFirmwareVersion, version, ConfidenceReported)
	}
	if uptime := firstUnifiNumber(device, "uptime"); uptime > 0 {
		result.addSubjectFact(subject, factNetUptimeSeconds, uptime, ConfidenceReported)
	}

	// --- interfaces -------------------------------------------------------
	if interfaces := unifiInterfaces(device, vlanByNetworkID); len(interfaces) > 0 {
		result.addSubjectFact(subject, factNetInterfaces, interfaces, ConfidenceReported)
	}

	// --- neighbours and edges --------------------------------------------
	neighbors := unifiLLDPNeighbors(device)
	if len(neighbors) > 0 {
		result.addSubjectFact(subject, factNetNeighbors, neighbors, ConfidenceReported)
	}
	for _, rel := range unifiLLDPEdges(subject, device) {
		result.addRelationship(rel)
	}

	// Adoption: an adopted device is a member of the controller that manages
	// it. An unadopted one is visible to the controller but not managed by it,
	// and asserting membership would put a neighbour's device in the customer's
	// topology.
	if adopted, ok := device["adopted"].(bool); ok && adopted && len(controller.Identifiers) > 0 {
		result.addRelationship(RelationshipObservation{
			Type:      relTypeMemberOf,
			Direction: SubjectToPeer,
			Subject:   subject,
			Peer:      controller,
			Attributes: map[string]interface{}{
				"membership": "adopted",
			},
		})
	}

	if rel, ok := unifiUplinkEdge(subject, device); ok {
		result.addRelationship(rel)
	}
}

// unifiInterfaces builds the net.interfaces value from the device's ethernet
// and port tables, merging the two by interface name.
//
// The two tables describe the same hardware from different angles:
// ethernet_table has the MACs and no state, port_table has state, speed and the
// untagged VLAN but no MAC. An operator expects one list.
func unifiInterfaces(device map[string]interface{}, vlanByNetworkID map[string]int) []map[string]interface{} {
	var out []map[string]interface{}
	byName := map[string]int{} // interface name → index in out

	for _, raw := range unifiTableEntries(device, "ethernet_table") {
		name := firstUnifiString(raw, "name")
		if name == "" {
			continue
		}
		entry := map[string]interface{}{"name": name}
		if mac, err := canonicalMAC(firstUnifiString(raw, "mac")); err == nil {
			entry["mac"] = mac
		}
		byName[strings.ToLower(name)] = len(out)
		out = append(out, entry)
	}

	for _, raw := range unifiTableEntries(device, "port_table") {
		name := firstUnifiString(raw, "name")
		if name == "" {
			if idx := firstUnifiNumber(raw, "port_idx"); idx > 0 {
				name = "Port " + strconv.Itoa(idx)
			} else {
				continue
			}
		}
		entry := map[string]interface{}{"name": name}
		if i, ok := byName[strings.ToLower(name)]; ok {
			entry = out[i]
		}

		// `up` is the operational state and `enable` the administrative one.
		// A port that is down because it is disabled is a different fact from
		// one that is down because nothing is plugged in, and the fact schema
		// keeps them apart for exactly that reason.
		if up, ok := raw["up"].(bool); ok {
			entry["state"] = unifiUpDown(up)
		}
		if enabled, ok := raw["enable"].(bool); ok {
			entry["admin_state"] = unifiUpDown(enabled)
		}
		if speed := firstUnifiNumber(raw, "speed"); speed > 0 {
			entry["speed"] = speed
		}
		if netID := firstUnifiString(raw, "native_networkconf_id"); netID != "" {
			if vlan, ok := vlanByNetworkID[netID]; ok {
				entry["vlan"] = vlan
			}
		}

		if i, ok := byName[strings.ToLower(name)]; ok {
			out[i] = entry
			continue
		}
		byName[strings.ToLower(name)] = len(out)
		out = append(out, entry)
	}

	return out
}

func unifiUpDown(up bool) string {
	if up {
		return "up"
	}
	return "down"
}

// unifiLLDPNeighbors projects the device's lldp_table onto net.neighbors items.
func unifiLLDPNeighbors(device map[string]interface{}) []map[string]interface{} {
	var out []map[string]interface{}
	for _, raw := range unifiTableEntries(device, "lldp_table") {
		entry := map[string]interface{}{"protocol": "lldp"}
		if mac, err := canonicalMAC(firstUnifiString(raw, "chassis_id")); err == nil {
			entry["remote_mac"] = mac
		}
		if name := firstUnifiString(raw, "system_name"); name != "" {
			entry["remote_name"] = name
		}
		if port := firstUnifiString(raw, "port_id"); port != "" {
			entry["remote_port"] = port
		}
		if local := unifiLocalPort(raw); local != "" {
			entry["local_port"] = local
		}
		// A neighbour with neither a MAC nor a name is a port with something on
		// it — true, but not a neighbour anything can be said about.
		if entry["remote_mac"] == nil && entry["remote_name"] == nil {
			continue
		}
		out = append(out, entry)
	}
	return out
}

// unifiLLDPEdges builds the connects_to edges for the device's LLDP neighbours.
func unifiLLDPEdges(subject PeerRef, device map[string]interface{}) []RelationshipObservation {
	var out []RelationshipObservation
	for _, raw := range unifiTableEntries(device, "lldp_table") {
		name := firstUnifiString(raw, "system_name")
		peer := peerRef(name, "")
		descr := firstUnifiString(raw, "chassis_descr")
		peer.Platform = advertisedProduct(descr)
		peer.SoftwareVersion = advertisedVersion(descr)
		peer.LLDPCapabilities = unifiLLDPCapabilityNames(raw)
		peer.AddIdentifier(IdentifierMACAddress, firstUnifiString(raw, "chassis_id"))
		addHostIdentifiers(&peer, name)
		if len(peer.Identifiers) == 0 {
			continue
		}

		attributes := map[string]interface{}{}
		if local := unifiLocalPort(raw); local != "" {
			attributes["local_port"] = local
		}
		if remote := firstUnifiString(raw, "port_id"); remote != "" {
			attributes["remote_port"] = remote
		}
		if wired, ok := raw["is_wired"].(bool); ok {
			attributes["wired"] = wired
		}
		attributes["discovery_protocol"] = "lldp"

		out = append(out, RelationshipObservation{
			Type:       relTypeConnectsTo,
			Direction:  SubjectToPeer,
			Subject:    subject,
			Peer:       peer,
			Attributes: attributes,
		})
	}
	return out
}

// unifiLLDPCapabilityNames normalises the controller's `capabilities` array
// onto the shared LLDP vocabulary.
//
// A wrapper rather than a copy of the mapping: the controller returns an ARRAY
// where the CLI vendors return a string, so the only thing that differs is how
// the tokens are separated. [lldpCapabilityNames] owns which words mean what.
func unifiLLDPCapabilityNames(raw map[string]interface{}) []string {
	values, ok := raw["capabilities"].([]interface{})
	if !ok {
		return nil
	}
	var words []string
	for _, v := range values {
		if word, ok := v.(string); ok {
			words = append(words, word)
		}
	}
	return lldpCapabilityNames(strings.Join(words, ","))
}

// unifiUplinkEdge builds the member_of edge from a device to the switch or
// gateway it uplinks through, with the port names on both ends.
func unifiUplinkEdge(subject PeerRef, device map[string]interface{}) (RelationshipObservation, bool) {
	raw, ok := device["uplink"].(map[string]interface{})
	if !ok {
		return RelationshipObservation{}, false
	}
	uplink := unifiProject(raw, unifiUplinkFields)

	peer := peerRef(firstUnifiString(uplink, "uplink_device_name"), "")
	// A wired uplink names the upstream device's MAC; a meshed AP names the AP
	// it is meshed to in ap_mac. Either way it is one peer.
	peer.AddIdentifier(IdentifierMACAddress, firstUnifiString(uplink, "uplink_mac", "ap_mac"))
	if len(peer.Identifiers) == 0 {
		return RelationshipObservation{}, false
	}
	// Do not emit a self-edge: a gateway's uplink table can name the gateway
	// itself, and a self-edge is rejected by the schema anyway.
	if mac := subject.Identifier(IdentifierMACAddress); mac != "" && mac == peer.Identifier(IdentifierMACAddress) {
		return RelationshipObservation{}, false
	}

	attributes := map[string]interface{}{"membership": "uplink"}
	if local := firstUnifiNumber(uplink, "port_idx"); local > 0 {
		attributes["local_port"] = "Port " + strconv.Itoa(local)
	}
	if remote := firstUnifiNumber(uplink, "uplink_remote_port", "remote_port"); remote > 0 {
		attributes["remote_port"] = "Port " + strconv.Itoa(remote)
	}
	if kind := firstUnifiString(uplink, "type"); kind != "" {
		attributes["uplink_type"] = kind
	}

	return RelationshipObservation{
		Type:       relTypeMemberOf,
		Direction:  SubjectToPeer,
		Subject:    subject,
		Peer:       peer,
		Attributes: attributes,
	}, true
}

// unifiLocalPort returns the local port name an LLDP entry was seen on, falling
// back to the port index the controller reports instead of a name.
func unifiLocalPort(entry map[string]interface{}) string {
	if name := firstUnifiString(entry, "local_port_name"); name != "" {
		return name
	}
	if idx := firstUnifiNumber(entry, "local_port_idx"); idx > 0 {
		return "Port " + strconv.Itoa(idx)
	}
	return ""
}

// unifiTableEntries returns the entries of a nested device table, projected
// onto the allowlist for that table.
//
// Projecting HERE rather than at each reader is what keeps the promise made by
// unifiDeviceStructuredFields: the callers below can only ever see the fields
// named in the allowlists, whatever the controller version returns.
func unifiTableEntries(device map[string]interface{}, table string) []map[string]interface{} {
	var allow []string
	switch table {
	case "port_table":
		allow = unifiPortFields
	case "ethernet_table":
		allow = unifiEthernetFields
	case "lldp_table":
		allow = unifiLLDPFields
	default:
		return nil
	}

	raw, ok := device[table].([]interface{})
	if !ok {
		return nil
	}
	out := make([]map[string]interface{}, 0, len(raw))
	for _, item := range raw {
		entry, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if projected := unifiProject(entry, allow); len(projected) > 0 {
			out = append(out, projected)
		}
	}
	return out
}

// unifiProject copies the allowlisted fields of one vendor object and nothing
// else. Every reader of a nested UniFi object goes through it, so a controller
// version that adds a field cannot widen what we collect.
func unifiProject(entry map[string]interface{}, allow []string) map[string]interface{} {
	projected := make(map[string]interface{}, len(allow))
	for _, field := range allow {
		if v, present := entry[field]; present && v != nil {
			projected[field] = v
		}
	}
	return projected
}

// unifiVLANByNetworkID indexes the site's networks by controller id so a port's
// untagged network resolves to a VLAN tag.
func unifiVLANByNetworkID(confs []map[string]interface{}) map[string]int {
	out := map[string]int{}
	for _, conf := range confs {
		id := firstUnifiString(conf, "_id")
		if id == "" {
			continue
		}
		if raw := firstUnifiValue(conf, "vlan"); raw != "" {
			if vlan, err := strconv.Atoi(raw); err == nil && vlan > 0 {
				out[id] = vlan
			}
		}
	}
	return out
}
