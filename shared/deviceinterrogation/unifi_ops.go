package deviceinterrogation

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/dcim/ifnames"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/identity/hostnamequality"
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
//
// Clients (`stat/sta`) are collected as PeerRefs: MAC (skipping LAA and
// virtual-router addresses), scoped IP, DHCP hostname. `.local` stays a
// hostname. Secrets, fingerprints and notes are not on the allowlist.

// unifiDeviceStructuredFields names the device-object fields that are READ for
// facts and edges but never copied into asset metadata.
//
// They are nested vendor objects — an array of ports, a table of neighbours —
// and copying one into metadata is the mistake `unifiDeviceInventoryFields`
// exists to prevent, just one level down. Each is projected field by field by
// the functions below; the per-entry allowlists are beside them.
var unifiDeviceStructuredFields = []string{
	"uplink",         // → a wired uplink's neighbour (cable end); a meshed one's member_of edge
	"port_table",     // → interfaces (DCIM row 1.5b), their LAGs and VLANs
	"ethernet_table", // → interface MACs
	"vap_table",      // → wireless interfaces, one per broadcast SSID
	"network_table",  // → a gateway's interface and address on each network it serves
	"lldp_table",     // → net.neighbors and connects_to edges
	"wan1",           // → the gateway's WAN address, an identifier and an interface address (unifiWANFields)
	"wan2",           // → the second WAN's address, on a dual-WAN gateway
}

// unifiWANTables are the device-object fields a UniFi gateway describes its
// WAN interfaces in.
var unifiWANTables = []string{"wan1", "wan2"}

// unifiWANFields is the allowlist of a `wan1` / `wan2` object's fields: the
// interface's address ( D2) and, since DCIM row 1.5b, what places that
// address on an interface — the kernel name of the port it is (`ifname`), the
// interface's MAC, its length (`netmask`) and its state. The upstream network
// is not a tenant prefix, so the address is an identifier and an interface
// address of the gateway and nothing more. Its gateway, name servers,
// connection type and — on the networkconf side, which is never read for a
// WAN — PPPoE user and password are the operator's upstream configuration,
// and have no consumer.
var unifiWANFields = []string{"ip", "ifname", "mac", "netmask", "up"}

// unifiPortFields is the allowlist of `port_table` entry fields. PoE draw and
// mode, 802.1X state, per-port counters and the rest of the ~40 fields are not
// interface posture the inventory records (the interface model has no PoE
// column) and have no consumer.
var unifiPortFields = []string{
	"port_idx",              // port number → `Port N`
	"name",                  // port name as configured; used only when it IS a port name
	"up",                    // operational state
	"enable",                // administrative state
	"speed",                 // negotiated speed, Mbit/s
	"media",                 // GE, SFP+, … → interface type
	"native_networkconf_id", // which network the port is untagged on → VLAN id
	"tagged_vlan_mgmt",      // auto | block_all | custom → 802.1Q mode (Network 7.4+)
	"forward",               // all | native | customize | disabled → 802.1Q mode (older controllers)
	"excluded_networkconf_ids",
	"op_mode",       // switch | aggregate | mirror → a LAG's master port
	"aggregated_by", // the master port_idx of the LAG a port is a member of
	"ifname",        // a gateway port's kernel name (eth8): its MAC and WAN address
}

// unifiVAPFields is the allowlist of `vap_table` entry fields: which radio
// broadcasts which SSID, under which interface name and BSSID, and whether it
// is up. The SSID's passphrase (`x_passphrase`), its security settings, the
// per-VAP client counters and the rest are not on it.
var unifiVAPFields = []string{"name", "radio", "essid", "bssid", "up", "wlanconf_id"}

// unifiWLANFields is the allowlist of a `rest/wlanconf` entry's fields: the
// name (the SSID), whether it is enabled, and the authentication posture --
// `security` (open, wpapsk, wpaeap), `wpa_enc` (ccmp, tkip, auto) -- plus the
// VLAN it maps to. The passphrase (`x_passphrase`) is NOT on it: unifiWLANPSKPresent
// is the only code that looks at it, and it returns a bool.
var unifiWLANFields = []string{"_id", "name", "enabled", "security", "wpa_enc", "vlan", "vlan_enabled", "networkconf_id"}

// unifiWLANPosture is one wireless network's posture: what the inventory
// records about an SSID. There is no field for the passphrase.
type unifiWLANPosture struct {
	SSID       string
	AuthType   string // open | wep | wpa-personal | wpa-enterprise | ""
	AuthCipher string // auto | tkip | aes | ""
	VLAN       int
	PSKPresent bool
}

// item is the posture as the net.interfaces `wireless` object. Typed keys,
// every one posture: psk_present is a boolean.
func (w unifiWLANPosture) item(ssid string) map[string]interface{} {
	out := map[string]interface{}{"ssid": ssid, "psk_present": w.PSKPresent}
	if w.AuthType != "" {
		out["auth_type"] = w.AuthType
	}
	if w.AuthCipher != "" {
		out["auth_cipher"] = w.AuthCipher
	}
	if w.VLAN > 0 {
		out["vlan"] = w.VLAN
	}
	return out
}

// unifiWLANIndex finds a VAP's wireless network by its wlanconf id, else by
// SSID.
type unifiWLANIndex struct {
	byID, byName map[string]unifiWLANPosture
}

func (x unifiWLANIndex) lookup(vap map[string]interface{}) (unifiWLANPosture, bool) {
	if id := firstUnifiString(vap, "wlanconf_id"); id != "" {
		if w, ok := x.byID[id]; ok {
			return w, true
		}
	}
	w, ok := x.byName[firstUnifiString(vap, "essid")]
	return w, ok
}

// unifiWLANPSKPresent reports whether a wlanconf entry has a passphrase set.
// It is the ONLY reader of `x_passphrase`, and what it returns is a bool.
func unifiWLANPSKPresent(raw map[string]interface{}) bool {
	s, _ := raw["x_passphrase"].(string)
	return strings.TrimSpace(s) != ""
}

// unifiWLANPostures projects `rest/wlanconf` onto per-SSID posture.
func unifiWLANPostures(confs []map[string]interface{}, vlanByNetworkID map[string]int) unifiWLANIndex {
	idx := unifiWLANIndex{byID: map[string]unifiWLANPosture{}, byName: map[string]unifiWLANPosture{}}
	for _, raw := range confs {
		p := unifiProject(raw, unifiWLANFields)
		name := firstUnifiString(p, "name")
		if name == "" {
			continue
		}
		w := unifiWLANPosture{SSID: name}
		switch strings.ToLower(firstUnifiString(p, "security")) {
		case "open":
			w.AuthType = "open"
		case "wep":
			w.AuthType = "wep"
		case "wpapsk":
			w.AuthType = "wpa-personal"
			w.PSKPresent = unifiWLANPSKPresent(raw)
		case "wpaeap":
			w.AuthType = "wpa-enterprise"
		}
		if w.AuthType == "wpa-personal" || w.AuthType == "wpa-enterprise" {
			// UniFi's wpa_enc is ccmp, tkip, or ccmp-tkip / auto (both offered).
			switch strings.ToLower(firstUnifiString(p, "wpa_enc")) {
			case "ccmp":
				w.AuthCipher = "aes"
			case "tkip":
				w.AuthCipher = "tkip"
			case "auto", "ccmp-tkip", "tkip-ccmp":
				w.AuthCipher = "auto"
			}
		}
		if enabled, ok := p["vlan_enabled"].(bool); ok && enabled {
			w.VLAN = firstUnifiNumber(p, "vlan")
		} else if id := firstUnifiString(p, "networkconf_id"); id != "" {
			w.VLAN = vlanByNetworkID[id]
		}
		if id := firstUnifiString(p, "_id"); id != "" {
			idx.byID[id] = w
		}
		idx.byName[name] = w
	}
	return idx
}

// unifiNetworkTableFields is the allowlist of a gateway's `network_table`
// entry fields: the network it serves and its own address on it. DHCP ranges,
// name servers and every option stay off it, as they do for networkconf.
var unifiNetworkTableFields = []string{"name", "purpose", "enabled", "up", "ip_subnet", "vlan"}

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
// Spelled as standards/oui/vendors.yaml spells it, which is not cosmetic in two
// places at once. It is the vendor GUARD on the `model` rules for UniFi device
// types, so a different spelling here silently stops every one of them from
// firing; and it is the same string the platform resolves from a captured
// frame's MAC, so a device seen passively and a device seen through the controller
// have to agree or they read as two manufacturers.
const unifiVendor = "Ubiquiti Networks"

// unifiEmitNetworkFacts emits the site's LAN and VLAN networks as a net.vlans
// fact on the controller.
//
// That fact is what the gateway-claims path reads (: the controller's own
// address on each network is claimed for it). Since DCIM row 1.5b it is not
// what records the networks: unifiEmitSiteNetworks carries the same entries on
// the site gateway's subject, and device-interrogation-service turns those into
// the tenant's prefixes and VLANs. Neither copy is stored as a fact.
//
// VPN networks are excluded: they are already converted to vpn_gateway assets
// with their crypto posture by unifiVPNAssets, and a tunnel is not a prefix.
// WAN networks are excluded because a WAN is the far side of the boundary, not
// a network the device serves. A disabled network is excluded: it is configured
// but carries nothing, and a prefix nobody can be on would be a phantom on the
// map.
//
// claimGateway says whether the controller may be the site's gateway
// (unifiControllerIsGateway); when it is known not to be, the entries carry no
// `gateway` address, so the platform claims none of the gateway's addresses
// for the controller.
func unifiEmitNetworkFacts(result *InterrogateResult, confs []map[string]interface{}, claimGateway bool) {
	vlans := unifiSiteNetworkEntries(confs)
	if len(vlans) == 0 {
		return
	}
	if !claimGateway {
		for _, entry := range vlans {
			delete(entry, "gateway")
		}
	}
	result.addFact(factNetVlans, vlans, ConfidenceReported)
}

// unifiEmitSiteNetworks carries the site's networks — the same entries as the
// controller's net.vlans fact — on the subject of the device that serves them:
// the site's adopted gateway, or, on a site whose gateway is not a UniFi device
// (switches and access points behind someone else's router), the first adopted
// device, so the site's VLANs and prefixes are still recorded by the one
// network source that measured them. device-interrogation-service turns a
// subject-scoped net.vlans into that sighting's observed prefixes and VLANs
// (DCIM row 1.5b); it is never stored as a fact.
func unifiEmitSiteNetworks(result *InterrogateResult, devices []map[string]interface{}, confs []map[string]interface{}) {
	entries := unifiSiteNetworkEntries(confs)
	if len(entries) == 0 {
		return
	}
	var carrier *PeerRef
	for _, gatewayFirst := range []bool{true, false} {
		for _, device := range devices {
			if adopted, _ := device["adopted"].(bool); !adopted {
				continue
			}
			if gatewayFirst && !unifiGatewayTypes[strings.ToLower(firstUnifiString(device, "type"))] {
				continue
			}
			subject := unifiDeviceSubject(device)
			if len(subject.Identifiers) == 0 {
				continue
			}
			carrier = &subject
			break
		}
		if carrier != nil {
			break
		}
	}
	if carrier == nil {
		return
	}
	result.addSubjectFact(*carrier, factNetVlans, entries, ConfidenceReported)
}

// unifiSiteNetworkEntries projects the site's networkconf onto net.vlans items:
// the enabled LAN and VLAN networks, never a VPN or a WAN.
func unifiSiteNetworkEntries(confs []map[string]interface{}) []map[string]interface{} {
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
	return vlans
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
	// What the network is for (corporate, guest, vlan-only): the prefix's
	// network type.
	if purpose := firstUnifiString(conf, "purpose"); purpose != "" {
		entry["purpose"] = purpose
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

// UnifiSite is what a UniFi controller returned for one site, as the
// interrogator fetched it: the controller's own identity (`/api/self` merged
// with the site settings' controller name), `rest/networkconf`, `stat/device`
// and `stat/sta`. Each list is the raw controller objects; nothing has been
// projected yet.
type UnifiSite struct {
	// ControllerHost is the host the controller was reached at.
	ControllerHost string
	Controller     map[string]interface{}
	NetworkConfs   []map[string]interface{}
	// WLANConfs is `rest/wlanconf`: the site's wireless networks. Read only
	// through unifiWLANPostures, which keeps authentication posture and
	// whether a passphrase EXISTS, and drops everything else -- the
	// passphrase above all.
	WLANConfs []map[string]interface{}
	Devices   []map[string]interface{}
	Clients   []map[string]interface{}
}

// UnifiSiteObservations is the ops half of a UniFi interrogation — every
// fact and edge the controller's responses yield, each projected onto its
// allowlist — without the crypto assets or the network calls. The
// interrogator runs exactly this over what it fetched
// (unifiEmitSiteObservations); it is exported so an intake adapter's parity
// test can drive the real projection from a recorded response set (DCIM row
// 1.5b).
func UnifiSiteObservations(site UnifiSite) *InterrogateResult {
	result := &InterrogateResult{collector: unifiCollector}
	unifiEmitSiteObservations(result, site)
	return result
}

// unifiEmitSiteObservations emits a site's ops facts and edges: each managed
// device's (about the DEVICE, not the controller, which is why they carry a
// subject — a switch's port table is not the controller's), the site's
// networks on the device that serves them, the controller's own net.vlans
// copy for the gateway-address claims, and the clients.
func unifiEmitSiteObservations(result *InterrogateResult, site UnifiSite) {
	vlanByNetworkID := unifiVLANByNetworkID(site.NetworkConfs)
	wlans := unifiWLANPostures(site.WLANConfs, vlanByNetworkID)
	if len(site.Devices) > 0 {
		controllerPeer := unifiControllerPeer(site.ControllerHost, site.Controller)
		for _, device := range site.Devices {
			unifiEmitDeviceObservations(result, device, controllerPeer, vlanByNetworkID, wlans)
		}
		unifiEmitSiteNetworks(result, site.Devices, site.NetworkConfs)
	}
	unifiEmitNetworkFacts(result, site.NetworkConfs, unifiControllerIsGateway(site))
	unifiEmitClientObservations(result, site.Clients)
}

// unifiControllerIsGateway reports whether the controller the interrogation
// reached may be the site's gateway — the assumption the controller's own
// net.vlans `gateway` addresses rest on, since the platform claims them for
// the interrogated device (gateway_claims.go).
//
// It is false only when that is KNOWN not to be so: the controller was
// reached at an IP address, the site has an adopted UniFi gateway, and the
// address is none of the gateway's (its `ip`, a WAN address, or its own
// address on a network it serves) — a Cloud Key or a self-hosted Network
// application in front of a UDM, USG or UXG. Claiming the gateway's addresses
// for that controller would be wrong, and since DCIM row 1.5b the gateway's
// own sighting reports them on its bridge interfaces, so the two would
// contest the gateway's identity on every run. Reached by name, the
// controller may well be the console it names, and nothing changes.
func unifiControllerIsGateway(site UnifiSite) bool {
	host, err := netip.ParseAddr(strings.Trim(site.ControllerHost, "[]"))
	if err != nil {
		return true
	}
	host = host.Unmap()
	sawGateway := false
	for _, device := range site.Devices {
		if adopted, _ := device["adopted"].(bool); !adopted || !unifiGatewayTypes[strings.ToLower(firstUnifiString(device, "type"))] {
			continue
		}
		sawGateway = true
		for _, a := range unifiGatewayAddresses(device) {
			if a == host {
				return true
			}
		}
	}
	return !sawGateway
}

// unifiGatewayAddresses are the addresses a gateway device states as its own.
func unifiGatewayAddresses(device map[string]interface{}) []netip.Addr {
	var out []netip.Addr
	add := func(v string) {
		if a, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
			out = append(out, a.Unmap())
		}
	}
	add(firstUnifiString(device, "ip"))
	for _, table := range unifiWANTables {
		if wan, ok := device[table].(map[string]interface{}); ok {
			add(firstUnifiString(unifiProject(wan, unifiWANFields), "ip"))
		}
	}
	for _, raw := range unifiTableEntries(device, "network_table") {
		if p, err := netip.ParsePrefix(firstUnifiString(raw, "ip_subnet")); err == nil {
			out = append(out, p.Addr().Unmap())
		}
	}
	return out
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
	// A gateway's WAN addresses, from its own device record ( D2). On a
	// UniFi gateway `ip` is usually the first WAN's address already; reading
	// the WAN objects as well catches the second WAN, and a gateway whose
	// `ip` names a LAN interface. AddIdentifier drops a duplicate and an
	// address that does not normalise (a WAN that is down reports none).
	for _, table := range unifiWANTables {
		if wan, ok := device[table].(map[string]interface{}); ok {
			projected := unifiProject(wan, unifiWANFields)
			subject.AddIdentifier(IdentifierIPAddress, firstUnifiString(projected, "ip"))
		}
	}
	subject.AddIdentifier(IdentifierSerialNumber, firstUnifiString(device, "serial"))
	// The controller's name is an operator alias, including DNS-shaped aliases.
	// Only its explicit hostname field may supply a hostname identifier.
	unifiAddClientName(&subject, firstUnifiString(device, "hostname"))
	adopted, _ := device["adopted"].(bool)
	subject.IdentityEvidence.ControllerInventory = adopted
	subject.IdentityEvidence.ConnectedInterface = adopted && firstUnifiNumber(device, "state") == 1
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
	peer.IdentityEvidence.ConnectedInterface = true
	if !peer.AddIdentifier(IdentifierIPAddress, host) {
		if !peer.AddIdentifier(IdentifierFQDN, host) {
			peer.AddIdentifier(IdentifierHostname, host)
		}
	}
	if hostname, _ := deviceInfo["controller_hostname"].(string); hostname != "" {
		unifiAddClientName(&peer, hostname)
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
	wlans unifiWLANIndex,
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
	// Carried as net.interfaces on the wire; device-interrogation-service turns
	// it into the device's observed interfaces and does not store the fact.
	if interfaces := unifiInterfaces(device, vlanByNetworkID, wlans); len(interfaces) > 0 {
		result.addSubjectFact(subject, factNetInterfaces, interfaces, ConfidenceReported)
	}

	// --- neighbours and edges --------------------------------------------
	// LLDP neighbours and the wired uplink are cable ends (DCIM row 3.3). They
	// travel as the subject-bound net.neighbors fact; device-interrogation-
	// service turns that into the subject's sighting neighbours and does not
	// store it.
	neighbors := unifiLLDPNeighbors(device)
	if up, ok := unifiUplinkNeighbor(subject, device); ok {
		dup := false
		for _, n := range neighbors {
			dup = dup || n["local_port"] == up["local_port"]
		}
		if !dup {
			neighbors = append(neighbors, up)
		}
	}
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

// unifiInterfaces builds the device's net.interfaces value: every interface
// the controller describes for it, which device-interrogation-service turns
// into identity.ObservedInterfaces on the device's sighting so the identity
// engine records them as `interfaces` and `ip_addresses` rows (DCIM row 1.5b,
// ADR-0010 D3). The list travels in the fact's shape on the wire, so an agent
// build and the platform agree on it, but it is no longer STORED as a fact.
//
// Sources, merged by canonical interface name (shared/dcim/ifnames, vendor
// unifi — `port1`, `Port1` and `Port 1` are one interface):
//
//   - port_table: one interface per switch port, named `Port N` (`SFP+ N`
//     where the controller names it so), typed from its `media`, with its
//     negotiated speed, operational (`up`) and administrative (`enable`)
//     state, and its 802.1Q mode and VLANs from the port's native and tagged
//     networks (unifiPortVLANs). An aggregated port names its LAG.
//   - LAGs: a port in `aggregate` mode and every port `aggregated_by` it are
//     members of one `lag` interface, `LAG N` after the master port; the
//     master's VLAN configuration is the LAG's (NetBox puts it there).
//   - ethernet_table: the device's own MACs. An entry whose name is a port's
//     `ifname` (a gateway's eth8 behind Port 9) gives that port its MAC; the
//     rest are interfaces of their own (a switch's eth0).
//   - vap_table: one wireless interface per SSID a radio broadcasts, typed
//     from the radio's band, with the BSSID as its MAC.
//   - A gateway's network_table: one bridge interface per network it serves
//     (`br0` for the untagged LAN, `br<vid>` for a VLAN, the names UniFi OS
//     gives them) carrying the gateway's own address on that network; and its
//     WAN objects, whose address lands on the port the WAN is (`ifname`).
//   - The device's own `ip` lands on the interface carrying the device's own
//     MAC when no interface already holds it.
//
// Every nested table is projected onto its allowlist first (unifiTableEntries),
// so nothing here can see an `x_`-prefixed secret.
func unifiInterfaces(device map[string]interface{}, vlanByNetworkID map[string]int, wlans unifiWLANIndex) []map[string]interface{} {
	b := newUnifiInterfaceSet()

	// --- switch ports and their LAGs ---------------------------------------
	ports := unifiTableEntries(device, "port_table")
	masters := map[int]bool{}
	for _, raw := range ports {
		if firstUnifiString(raw, "op_mode") == "aggregate" {
			masters[firstUnifiNumber(raw, "port_idx")] = true
		}
	}
	lagOf := func(raw map[string]interface{}) int {
		if by := firstUnifiNumber(raw, "aggregated_by"); by > 0 {
			return by
		}
		if idx := firstUnifiNumber(raw, "port_idx"); masters[idx] {
			return idx
		}
		return 0
	}
	ifnameAlias := map[string]string{} // a gateway port's kernel name → its interface
	for _, raw := range ports {
		name := unifiPortName(raw)
		if name == "" {
			continue
		}
		entry := b.get(name)
		if t := unifiPortType(raw); t != "" {
			entry["type"] = t
		}
		// `up` is the operational state and `enable` the administrative one.
		// A port that is down because it is disabled is a different fact from
		// one that is down because nothing is plugged in.
		up, hasUp := raw["up"].(bool)
		if hasUp {
			entry["state"] = unifiUpDown(up)
		}
		if enabled, ok := raw["enable"].(bool); ok {
			entry["admin_state"] = unifiUpDown(enabled)
		}
		// A speed is the NEGOTIATED one: a down port reports its last or 0,
		// which is not a measurement of anything.
		if speed := firstUnifiNumber(raw, "speed"); speed > 0 && (!hasUp || up) {
			entry["speed"] = speed
		}
		mode, untagged, tagged := unifiPortVLANs(raw, vlanByNetworkID)
		lag := lagOf(raw)
		if lag > 0 {
			lagName := "LAG " + strconv.Itoa(lag)
			entry["lag"] = lagName
			agg := b.get(lagName)
			agg["type"] = "lag"
			if hasUp && (up || agg["state"] == nil) {
				agg["state"] = unifiUpDown(up)
			}
			if firstUnifiNumber(raw, "port_idx") == lag {
				// The master port carries the aggregate's configuration.
				if enabled, ok := raw["enable"].(bool); ok {
					agg["admin_state"] = unifiUpDown(enabled)
				}
				setUnifiVLANs(agg, mode, untagged, tagged)
			}
		} else {
			setUnifiVLANs(entry, mode, untagged, tagged)
		}
		if ifname := firstUnifiString(raw, "ifname"); ifname != "" {
			ifnameAlias[strings.ToLower(ifname)] = name
		}
	}

	// --- the device's own MACs ---------------------------------------------
	for _, raw := range unifiTableEntries(device, "ethernet_table") {
		name := firstUnifiString(raw, "name")
		if name == "" {
			continue
		}
		mac, err := canonicalMAC(firstUnifiString(raw, "mac"))
		if alias, ok := ifnameAlias[strings.ToLower(name)]; ok {
			if err == nil {
				b.get(alias)["mac"] = mac
			}
			continue
		}
		entry := b.get(unifiCanonicalName(name))
		if err == nil {
			entry["mac"] = mac
		}
	}

	// --- wireless ----------------------------------------------------------
	for _, raw := range unifiTableEntries(device, "vap_table") {
		name := unifiVAPName(raw)
		if name == "" {
			continue
		}
		entry := b.get(name)
		if t := unifiRadioType(firstUnifiString(raw, "radio")); t != "" {
			entry["type"] = t
		}
		if mac, err := canonicalMAC(firstUnifiString(raw, "bssid")); err == nil {
			entry["mac"] = mac
		}
		if up, ok := raw["up"].(bool); ok {
			entry["state"] = unifiUpDown(up)
		}
		// The VAP is an access point's radio serving one wireless LAN (row
		// 4.4): its role, the SSID, and what the site's wlanconf says that
		// SSID's authentication is. The posture rides on the interface item
		// and is lifted onto the sighting's wireless LANs by the platform.
		entry["rf_role"] = "ap"
		if essid := firstUnifiString(raw, "essid"); essid != "" {
			entry["ssids"] = []string{essid}
			if wlan, ok := wlans.lookup(raw); ok {
				entry["wireless"] = wlan.item(essid)
			}
		}
	}

	// --- a gateway's networks and WANs --------------------------------------
	for _, raw := range unifiTableEntries(device, "network_table") {
		name, addr, vid, ok := unifiGatewayNetworkInterface(raw)
		if !ok {
			continue
		}
		entry := b.get(name)
		b.addAddress(entry, addr)
		// The gateway's own address on a network it serves is configured, not
		// leased: it stays the gateway's inside a DHCP-managed prefix.
		static, _ := entry["static_addresses"].([]string)
		entry["static_addresses"] = append(static, addr)
		if vid > 0 {
			setUnifiVLANs(entry, "access", vid, nil)
		}
		if up, ok := raw["up"].(bool); ok {
			entry["state"] = unifiUpDown(up)
		}
	}
	for i, table := range unifiWANTables {
		wan, ok := device[table].(map[string]interface{})
		if !ok {
			continue
		}
		projected := unifiProject(wan, unifiWANFields)
		ip := firstUnifiString(projected, "ip")
		addr, err := netip.ParseAddr(ip)
		if err != nil || addr.IsUnspecified() {
			continue // a WAN that is down reports none, or 0.0.0.0
		}
		name := ""
		if ifname := firstUnifiString(projected, "ifname"); ifname != "" {
			if alias, ok := ifnameAlias[strings.ToLower(ifname)]; ok {
				name = alias
			} else {
				name = unifiCanonicalName(ifname)
			}
		}
		if name == "" {
			name = "wan" + strconv.Itoa(i+1)
		}
		entry := b.get(name)
		cidr := addr.String()
		if bits := unifiMaskBits(firstUnifiString(projected, "netmask")); bits > 0 {
			cidr = netip.PrefixFrom(addr, bits).String()
		}
		b.addAddress(entry, cidr)
		if mac, err := canonicalMAC(firstUnifiString(projected, "mac")); err == nil && entry["mac"] == nil {
			entry["mac"] = mac
		}
		if up, ok := projected["up"].(bool); ok && entry["state"] == nil {
			entry["state"] = unifiUpDown(up)
		}
	}

	// --- the management address -------------------------------------------
	if ip, err := netip.ParseAddr(firstUnifiString(device, "ip")); err == nil && !b.holds(ip) {
		if mac, err := canonicalMAC(firstUnifiString(device, "mac")); err == nil {
			if entry := b.withMAC(mac); entry != nil {
				b.addAddress(entry, ip.String())
			}
		}
	}

	return b.list()
}

// unifiInterfaceSet is the device's interfaces under construction, in the
// order each was first named.
type unifiInterfaceSet struct {
	order  []string
	byName map[string]map[string]interface{}
}

func newUnifiInterfaceSet() *unifiInterfaceSet {
	return &unifiInterfaceSet{byName: map[string]map[string]interface{}{}}
}

func (s *unifiInterfaceSet) get(name string) map[string]interface{} {
	key := strings.ToLower(name)
	if e, ok := s.byName[key]; ok {
		return e
	}
	e := map[string]interface{}{"name": name}
	s.byName[key] = e
	s.order = append(s.order, key)
	return e
}

func (s *unifiInterfaceSet) addAddress(entry map[string]interface{}, cidr string) {
	list, _ := entry["addresses"].([]string)
	for _, a := range list {
		if a == cidr {
			return
		}
	}
	entry["addresses"] = append(list, cidr)
}

// holds reports whether any interface already carries addr.
func (s *unifiInterfaceSet) holds(addr netip.Addr) bool {
	for _, e := range s.byName {
		list, _ := e["addresses"].([]string)
		for _, a := range list {
			if p, err := netip.ParsePrefix(a); err == nil && p.Addr() == addr {
				return true
			}
			if v, err := netip.ParseAddr(a); err == nil && v == addr {
				return true
			}
		}
	}
	return false
}

// withMAC returns the first interface (in order) carrying mac, or nil.
func (s *unifiInterfaceSet) withMAC(mac string) map[string]interface{} {
	for _, key := range s.order {
		if e := s.byName[key]; e["mac"] == mac {
			return e
		}
	}
	return nil
}

func (s *unifiInterfaceSet) list() []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(s.order))
	for _, key := range s.order {
		out = append(out, s.byName[key])
	}
	return out
}

// unifiCanonicalName is a UniFi interface name in the spelling the inventory
// keys interfaces by (`port1` → `Port 1`, `SFP+1` → `SFP+ 1`; Linux names
// such as eth0 and br0 unchanged).
func unifiCanonicalName(raw string) string {
	name, _ := ifnames.Canonical(ifnames.VendorUniFi, raw)
	return strings.TrimSpace(name)
}

// unifiPortName names a switch port: the controller's own name when it IS a
// port name (`Port 3`, `SFP+ 1`, in any spelling), otherwise `Port <idx>` —
// an operator's label ("Office AP") describes what is plugged in, not the
// port, and would rename the interface every time someone retyped it.
func unifiPortName(raw map[string]interface{}) string {
	if configured := firstUnifiString(raw, "name"); configured != "" {
		if name, kind := ifnames.Canonical(ifnames.VendorUniFi, configured); kind == string(ifnames.KindPhysical) &&
			(strings.HasPrefix(name, "Port ") || strings.HasPrefix(name, "SFP")) {
			return name
		}
	}
	if idx := firstUnifiNumber(raw, "port_idx"); idx > 0 {
		return unifiCanonicalName("Port " + strconv.Itoa(idx))
	}
	return ""
}

// unifiMediaTypes maps a port's `media` onto the interface-type registry
// (shared/dcim types). A medium not listed leaves the type to the engine.
var unifiMediaTypes = map[string]string{
	"FE":     "100base-tx",
	"GE":     "1000base-t",
	"2P5GE":  "2.5gbase-t",
	"5GE":    "5gbase-t",
	"10GE":   "10gbase-t",
	"SFP":    "1000base-x-sfp",
	"SFP+":   "10gbase-x-sfpp",
	"SFP28":  "25gbase-x-sfp28",
	"QSFP28": "100gbase-x-qsfp28",
}

// unifiPortType is the port's interface type: its `media` where the
// controller names one, else — for a copper port that is up — its negotiated
// speed's copper type. A 10 Gbit/s link with no medium could be copper or
// optics, so it is left unsaid rather than guessed.
func unifiPortType(raw map[string]interface{}) string {
	if t, ok := unifiMediaTypes[strings.ToUpper(strings.TrimSpace(firstUnifiString(raw, "media")))]; ok {
		return t
	}
	if up, _ := raw["up"].(bool); !up {
		return ""
	}
	switch firstUnifiNumber(raw, "speed") {
	case 100:
		return "100base-tx"
	case 1000:
		return "1000base-t"
	case 2500:
		return "2.5gbase-t"
	}
	return ""
}

// unifiPortVLANs is a port's 802.1Q configuration: its mode, its native
// (untagged) VLAN and the VLANs it trunks.
//
// Read from the port's own entry: `native_networkconf_id` is the untagged
// network; `tagged_vlan_mgmt` (Network 7.4+: auto, block_all, custom) or the
// older `forward` (all, native, customize, disabled) says what else it
// carries, and `excluded_networkconf_ids` what it does not. Every network id
// resolves through the site's networkconf to its VLAN id; the untagged
// default LAN has none, so a port on it has no untagged VLAN rather than an
// invented VLAN 1.
func unifiPortVLANs(raw map[string]interface{}, vlanByNetworkID map[string]int) (mode string, untagged int, tagged []int) {
	untagged = vlanByNetworkID[firstUnifiString(raw, "native_networkconf_id")]
	mgmt := strings.ToLower(firstUnifiString(raw, "tagged_vlan_mgmt"))
	forward := strings.ToLower(firstUnifiString(raw, "forward"))
	excluded := map[int]bool{}
	if list, ok := raw["excluded_networkconf_ids"].([]interface{}); ok {
		for _, v := range list {
			if id, ok := v.(string); ok {
				if vid, ok := vlanByNetworkID[id]; ok {
					excluded[vid] = true
				}
			}
		}
	}
	allBut := func() []int {
		var out []int
		for _, vid := range vlanByNetworkID {
			if vid != untagged && !excluded[vid] && !slices.Contains(out, vid) {
				out = append(out, vid)
			}
		}
		slices.Sort(out)
		return out
	}
	switch {
	case forward == "disabled":
		return "", 0, nil
	case mgmt == "block_all" || forward == "native":
		return "access", untagged, nil
	case mgmt == "auto" || forward == "all":
		if len(excluded) == 0 {
			return "tagged-all", untagged, nil
		}
		if t := allBut(); len(t) > 0 {
			return "tagged", untagged, t
		}
		return "access", untagged, nil
	case mgmt == "custom" || forward == "customize":
		if t := allBut(); len(t) > 0 {
			return "tagged", untagged, t
		}
		return "access", untagged, nil
	}
	if untagged > 0 {
		return "access", untagged, nil
	}
	return "", 0, nil
}

// setUnifiVLANs writes a port's 802.1Q configuration onto its interface entry.
func setUnifiVLANs(entry map[string]interface{}, mode string, untagged int, tagged []int) {
	if mode != "" {
		entry["mode"] = mode
	}
	if untagged > 0 {
		entry["vlan"] = untagged
	}
	if len(tagged) > 0 {
		entry["tagged_vlans"] = tagged
	}
}

// unifiVAPName names a wireless interface: the radio's own interface name
// (`ra0`, `rai0`, `wifi0ap0`) where the controller reports it, else
// `<radio>-<essid>`.
func unifiVAPName(raw map[string]interface{}) string {
	if name := firstUnifiString(raw, "name"); name != "" {
		return unifiCanonicalName(name)
	}
	radio, essid := firstUnifiString(raw, "radio"), firstUnifiString(raw, "essid")
	if radio == "" || essid == "" {
		return ""
	}
	return radio + "-" + essid
}

// unifiRadioType is a radio band's interface type. The band is what the
// controller states on every VAP; the 802.11 generation the radio supports is
// not on the VAP, so each band is typed by the standard that introduced it
// for UniFi access points: 2.4 GHz `ng` → 802.11n, 5 GHz `na` → 802.11ac,
// 6 GHz `6e` → 802.11ax.
func unifiRadioType(radio string) string {
	switch strings.ToLower(strings.TrimSpace(radio)) {
	case "ng":
		return "ieee802.11n"
	case "na":
		return "ieee802.11ac"
	case "6e":
		return "ieee802.11ax"
	}
	return ""
}

// unifiGatewayNetworkInterface is the gateway interface one network_table
// entry describes: `br0` for the untagged LAN or `br<vid>`, with the
// gateway's own address on it (UniFi's ip_subnet is that address with the
// network's length). WAN, VPN and disabled networks are not interfaces of
// the LAN side, and an entry whose ip_subnet is the network address itself
// names no gateway address.
func unifiGatewayNetworkInterface(raw map[string]interface{}) (name, cidr string, vid int, ok bool) {
	switch strings.ToLower(firstUnifiString(raw, "purpose")) {
	case "wan", "site-vpn", "remote-user-vpn", "vpn-client":
		return "", "", 0, false
	}
	if enabled, present := raw["enabled"].(bool); present && !enabled {
		return "", "", 0, false
	}
	p, err := netip.ParsePrefix(firstUnifiString(raw, "ip_subnet"))
	if err != nil || p.Addr() == p.Masked().Addr() {
		return "", "", 0, false
	}
	if v := firstUnifiValue(raw, "vlan"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 4094 {
			vid = n
		}
	}
	return "br" + strconv.Itoa(vid), p.String(), vid, true
}

// unifiMaskBits is a dotted IPv4 netmask's prefix length, 0 when it is not one.
func unifiMaskBits(mask string) int {
	addr, err := netip.ParseAddr(strings.TrimSpace(mask))
	if err != nil || !addr.Is4() {
		return 0
	}
	b := addr.As4()
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	bits := 0
	for n&0x80000000 != 0 {
		bits++
		n <<= 1
	}
	if n != 0 { // not contiguous
		return 0
	}
	return bits
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

	// A WIRED uplink is a cable (DCIM row 3.3): it is reported as a neighbour
	// (unifiUplinkNeighbor) and the platform proposes the cable, so no
	// member_of edge with port names is written for it. A meshed (wireless)
	// uplink has no cable to propose and keeps its edge, without ports.
	kind := firstUnifiString(uplink, "type")
	if kind == "wire" || (kind == "" && firstUnifiString(uplink, "uplink_mac") != "") {
		return RelationshipObservation{}, false
	}
	attributes := map[string]interface{}{"membership": "uplink"}
	if kind != "" {
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

// unifiUplinkNeighbor is a device's WIRED uplink as a neighbour item (the
// net.neighbors item shape, protocol lldp: the controller learns wired uplinks
// from LLDP): our port, the upstream device's MAC and name, and its port.
// Without both port numbers there is no cable end to name.
func unifiUplinkNeighbor(subject PeerRef, device map[string]interface{}) (map[string]interface{}, bool) {
	raw, ok := device["uplink"].(map[string]interface{})
	if !ok {
		return nil, false
	}
	uplink := unifiProject(raw, unifiUplinkFields)
	if kind := firstUnifiString(uplink, "type"); kind != "" && kind != "wire" {
		return nil, false
	}
	mac, err := canonicalMAC(firstUnifiString(uplink, "uplink_mac"))
	if err != nil || mac == subject.Identifier(IdentifierMACAddress) {
		return nil, false
	}
	local := firstUnifiNumber(uplink, "port_idx")
	remote := firstUnifiNumber(uplink, "uplink_remote_port", "remote_port")
	if local <= 0 || remote <= 0 {
		return nil, false
	}
	item := map[string]interface{}{
		"protocol":    "lldp",
		"remote_mac":  mac,
		"remote_port": "Port " + strconv.Itoa(remote),
		"local_port":  "Port " + strconv.Itoa(local),
	}
	if name := firstUnifiString(uplink, "uplink_device_name"); name != "" {
		item["remote_name"] = name
	}
	return item, true
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
	case "vap_table":
		allow = unifiVAPFields
	case "network_table":
		allow = unifiNetworkTableFields
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

// unifiClientInventoryFields is the allowlist of `stat/sta` fields we keep.
// Fingerprints, notes (emails), raw user objects and every `x_*` secret stay
// off this list — the same discipline as unifiDeviceInventoryFields.
var unifiClientInventoryFields = []string{
	"mac",       // hardware identity; skipped when LAA or virtual-router
	"ip",        // lease address; recorded, does not vote on a DHCP segment
	"hostname",  // DHCP hostname
	"name",      // controller alias → DisplayName, even with spaces
	"oui",       // manufacturer prefix; class evidence, not identity
	"is_wired",  // wired vs wireless
	"ap_mac",    // wireless attachment
	"sw_mac",    // wired attachment
	"essid",     // SSID
	"network",   // UniFi network name
	"vlan",      // 802.1Q tag
	"last_seen", // unix seconds
}

// unifiEmitClientObservations turns the controller's station list into peer
// subjects and connects_to edges to the AP or switch they attach to.
//
// A client with no AP/switch MAC still has to land as an identity observation
// — that is how a DHCP hostname joins an existing ARP row. Subject facts are
// the ingest vehicle when there is no edge; ObservationSink resolves a fact's
// Subject the same way it resolves a relationship end.
func unifiEmitClientObservations(result *InterrogateResult, clients []map[string]interface{}) {
	if result == nil {
		return
	}
	for _, raw := range clients {
		client := unifiProject(raw, unifiClientInventoryFields)
		peer := unifiClientPeer(client)
		if len(peer.Identifiers) == 0 {
			continue
		}
		if oui := firstUnifiString(client, "oui"); oui != "" {
			result.addSubjectFact(peer, factHWVendor, oui, ConfidenceDerived)
		}
		if iface := unifiClientInterface(client); len(iface) > 0 {
			result.addSubjectFact(peer, factNetInterfaces, []map[string]interface{}{iface}, ConfidenceReported)
		}
		attrs := map[string]interface{}{}
		if essid := firstUnifiString(client, "essid"); essid != "" {
			attrs["essid"] = essid
		}
		if netName := firstUnifiString(client, "network"); netName != "" {
			attrs["network"] = netName
		}
		if wired, ok := client["is_wired"].(bool); ok {
			attrs["is_wired"] = wired
		}
		if vlan := firstUnifiNumber(client, "vlan"); vlan > 0 {
			attrs["vlan"] = vlan
		}
		if seen := firstUnifiNumber(client, "last_seen"); seen > 0 {
			attrs["last_seen"] = seen
		}
		for _, key := range []string{"ap_mac", "sw_mac"} {
			mac := firstUnifiString(client, key)
			if unifiSkipHardwareMAC(mac) {
				continue
			}
			infra := PeerRef{}
			if !infra.AddIdentifier(IdentifierMACAddress, mac) {
				continue
			}
			edgeAttrs := map[string]interface{}{}
			for k, v := range attrs {
				edgeAttrs[k] = v
			}
			edgeAttrs["via"] = key
			result.addRelationship(RelationshipObservation{
				Type:       relTypeConnectsTo,
				Direction:  SubjectToPeer,
				Subject:    peer,
				Peer:       infra,
				Attributes: edgeAttrs,
			})
		}
	}
}

// unifiClientPeer builds the PeerRef naming a controller-reported client.
func unifiClientPeer(client map[string]interface{}) PeerRef {
	alias := firstUnifiString(client, "name")
	hostname := firstUnifiString(client, "hostname")
	display := alias
	if display == "" {
		display = hostname
	}
	peer := peerRef(display, "")
	peer.IdentityEvidence.ConnectedInterface = true
	mac := firstUnifiString(client, "mac")
	if !unifiSkipHardwareMAC(mac) {
		peer.AddIdentifier(IdentifierMACAddress, mac)
	}
	peer.AddIdentifier(IdentifierIPAddress, firstUnifiString(client, "ip"))
	unifiAddClientName(&peer, hostname)
	return peer
}

// unifiAddClientName files a client name as hostname or FQDN. `.local` stays
// a hostname so ingest cannot promote it to an unscoped FQDN.
func unifiAddClientName(peer *PeerRef, name string) {
	if peer == nil || strings.TrimSpace(name) == "" {
		return
	}
	if _, err := canonicalIP(name); err == nil {
		return
	}
	if _, err := canonicalMAC(name); err == nil {
		return
	}
	if hostnamequality.IsMDNSLocalName(name) || !strings.Contains(strings.TrimSuffix(name, "."), ".") {
		peer.AddIdentifier(IdentifierHostname, name)
		return
	}
	peer.AddIdentifier(IdentifierFQDN, name)
	peer.AddIdentifier(IdentifierHostname, name)
}

// unifiSkipHardwareMAC reports MACs that must not become identifiers: empty,
// locally-administered, and virtual-router addresses. Relayed mDNS plus a
// rotating phone MAC is how one host becomes many CIs.
func unifiSkipHardwareMAC(mac string) bool {
	mac = strings.TrimSpace(mac)
	if mac == "" {
		return true
	}
	if hostobs.MACLocallyAdministered(mac) {
		return true
	}
	_, virtual := hostobs.VirtualMACProtocol(mac)
	return virtual
}

// unifiClientInterface projects the station's MAC/IP/VLAN onto one
// net.interfaces item so ObservationSink can resolve the peer even when there
// is no AP/switch edge. LAA/virtual MACs stay off the item — they are not
// identity, and putting them here would reintroduce the rotating-CI path
// through a fact instead of an identifier.
//
// The item has NO name (DCIM row 1.5b). The controller does not know what the
// client calls its interface — the "lan"/"wlan" this used to write were
// invented — so device-interrogation-service sends the MAC and address as the
// client's identifiers with no interface, and the identity engine files them
// on a synthetic `observed-<n>` interface that a later named report (the
// client's own agent) renames by MAC. The item is still the client's ingest
// vehicle; it is not stored as a fact.
func unifiClientInterface(client map[string]interface{}) map[string]interface{} {
	entry := map[string]interface{}{}
	mac := firstUnifiString(client, "mac")
	if !unifiSkipHardwareMAC(mac) {
		if canon, err := canonicalMAC(mac); err == nil {
			entry["mac"] = canon
		}
	}
	if ip := firstUnifiString(client, "ip"); ip != "" {
		if addr, err := netip.ParseAddr(ip); err == nil {
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			entry["addresses"] = []string{netip.PrefixFrom(addr, bits).String()}
		}
	}
	if vlan := firstUnifiNumber(client, "vlan"); vlan > 0 {
		entry["vlan"] = vlan
	}
	if _, hasMAC := entry["mac"]; !hasMAC {
		if _, hasAddr := entry["addresses"]; !hasAddr {
			return nil
		}
	}
	return entry
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
