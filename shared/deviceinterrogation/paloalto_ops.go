package deviceinterrogation

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// PAN-OS ops facts and observed topology (asset-inventory ADR-0004 D1 item 2).
//
// `show system info` was already being FETCHED and thrown away — getSystemInfo
// issued the op command, discarded the body and returned
// `{"api_key_obtained": true}`. Everything an inventory wants about a firewall
// was in that response: hostname, model, serial, software version, uptime,
// management address and MAC. It is parsed now, onto the explicit allowlist
// below.
//
// Three more op commands are added, each the cheapest available answer to a
// question the ops set asks: `show interface all` (interfaces), `show arp all`
// (layer-3 neighbours) and `show lldp neighbors all` (layer-2 neighbours and
// the connects_to edges built from them).
//
// Every response is bound to a typed struct with explicit xml tags, so unknown
// elements are discarded STRUCTURALLY — a PAN-OS version that adds a field
// cannot widen what we collect, and there is no path by which a `psksecret`,
// an `api-key` or a `private-key` element from a differently-shaped response
// reaches the result. The projection tests feed exactly that and assert it does
// not survive.
//
// Not collected, deliberately:
//   - Zones, virtual routers and vsys names. They are the firewall's policy
//     structure, not the asset's posture, and nothing reads them.
//   - The routing table (`show routing route`). ADR-0004 D1 names routes as
//     "summarised as next-hop count"; a full table is an attacker's map of the
//     network and is left to the workstream that decides on the summary.
//   - Anything from `show config`. A running config carries pre-shared keys and
//     certificates' private keys; interrogation never asks for it.

// panSystemInfo is the allowlist projection of `show system info`. Every field
// here is an ops fact or an identifier; the response also carries content
// versions, licence state, GlobalProtect client versions and a dozen more
// elements, none of which have a reader.
type panSystemInfo struct {
	Hostname       string `xml:"hostname"`
	DeviceName     string `xml:"devicename"`
	IPAddress      string `xml:"ip-address"`
	Netmask        string `xml:"netmask"`
	DefaultGateway string `xml:"default-gateway"`
	MACAddress     string `xml:"mac-address"`
	Serial         string `xml:"serial"`
	Model          string `xml:"model"`
	Family         string `xml:"family"`
	SWVersion      string `xml:"sw-version"`
	Uptime         string `xml:"uptime"`
}

// panIfnetEntry is one entry of the `<ifnet>` half of `show interface all`:
// the layer-3 view, which has the addresses and the 802.1Q tag.
type panIfnetEntry struct {
	Name string `xml:"name"`
	IP   string `xml:"ip"`
	Tag  string `xml:"tag"`
}

type panIfnetBlock struct {
	Entries []panIfnetEntry `xml:"entry"`
}

// panHWEntry is one entry of the `<hw>` half: the physical view, which has the
// MAC, the link state and the negotiated speed.
type panHWEntry struct {
	Name  string `xml:"name"`
	MAC   string `xml:"mac"`
	State string `xml:"state"`
	Speed string `xml:"speed"`
}

type panHWBlock struct {
	Entries []panHWEntry `xml:"entry"`
}

// panARPEntry is one entry of `show arp all`.
type panARPEntry struct {
	IP        string `xml:"ip"`
	MAC       string `xml:"mac"`
	Interface string `xml:"interface"`
	Status    string `xml:"status"`
}

type panARPBlock struct {
	Entries []panARPEntry `xml:"entry"`
}

// panLLDPNeighbor is one neighbour of `show lldp neighbors all`.
//
// `system-description` is bound but deliberately unused for anything but the
// vendor hint below: it is an unbounded vendor banner, and storing whole
// banners is what the secrets rule forbids.
type panLLDPNeighbor struct {
	ChassisID         string `xml:"chassis-id"`
	PortID            string `xml:"port-id"`
	PortDescription   string `xml:"port-description"`
	SystemName        string `xml:"system-name"`
	ManagementAddress string `xml:"management-address"`
	// The posture halves of the 802.1AB advertisement. A typed struct, so every
	// element PAN-OS adds later is discarded structurally rather than by a
	// human remembering to project it.
	SystemDescription   string `xml:"system-description"`
	SystemCapabilities  string `xml:"system-capabilities"`
	EnabledCapabilities string `xml:"enabled-capabilities"`
}

// panLLDPInterface groups the neighbours seen on one local interface.
type panLLDPInterface struct {
	LocalInterface string            `xml:"local-interface"`
	Neighbors      []panLLDPNeighbor `xml:"lldp-neighbors>entry"`
}

// panOpCommand runs an operational command and returns the raw XML body,
// failing when PAN-OS reports anything but success.
//
// The command is percent-encoded, which the previous inline system-info call
// was not: an op command is XML, and `<show><arp><entry name='all'/></arp>` in
// a bare query string is neither valid nor parseable by the device.
func (c *panClient) panOpCommand(ctx context.Context, cmd string) (string, error) {
	// No `&key=`: the API key travels in the X-PAN-KEY header that apiRequest
	// sets. See the note there — this URL is what a *url.Error prints, and that
	// string is persisted and served.
	apiURL := fmt.Sprintf("%s/api/?type=op&cmd=%s", c.baseURL, url.QueryEscape(cmd))
	body, err := c.apiRequest(ctx, "GET", apiURL)
	if err != nil {
		return "", err
	}
	var resp panResponse
	if err := xml.NewDecoder(strings.NewReader(body)).Decode(&resp); err != nil {
		return "", fmt.Errorf("failed to decode response to %s: %w", cmd, err)
	}
	if resp.Status != "success" {
		return "", fmt.Errorf("%s failed: %s", cmd, resp.Code)
	}
	return body, nil
}

// panParseSystemInfo extracts the allowlisted system-info fields from a
// `show system info` response.
func panParseSystemInfo(body string) (panSystemInfo, error) {
	blocks, err := panFindElements[panSystemInfo](body, "system")
	if err != nil {
		return panSystemInfo{}, err
	}
	if len(blocks) == 0 {
		return panSystemInfo{}, fmt.Errorf("no <system> element in the show-system-info response")
	}
	return blocks[0], nil
}

// panSystemInfoMap is the projection that lands in DeviceInfo — the same
// allowlist, flattened to the freeform map the result model carries.
func panSystemInfoMap(info panSystemInfo) map[string]interface{} {
	out := map[string]interface{}{}
	for key, value := range map[string]string{
		"hostname":           info.Hostname,
		"model":              info.Model,
		"family":             info.Family,
		"serial_number":      info.Serial,
		"sw_version":         info.SWVersion,
		"uptime":             info.Uptime,
		"management_ip":      info.IPAddress,
		"management_mac":     info.MACAddress,
		"default_gateway":    info.DefaultGateway,
		"management_netmask": info.Netmask,
	} {
		if value != "" {
			out[key] = value
		}
	}
	return out
}

// panEmitSystemFacts turns the system-info projection into identity and ops
// facts on the interrogated firewall.
func panEmitSystemFacts(result *InterrogateResult, info panSystemInfo) {
	result.addFact(factHWVendor, panVendor, ConfidenceDerived)
	if info.Model != "" {
		result.addFact(factHWModel, info.Model, ConfidenceReported)
	}
	if info.Serial != "" {
		result.addFact(factHWSerial, info.Serial, ConfidenceReported)
	}
	if info.SWVersion != "" {
		// PAN-OS is an operating system, not a firmware blob: a vendor advisory
		// names "PAN-OS 11.1.4", and the EOL catalogue is keyed on product plus
		// version. hw.firmware_version is left for devices whose firmware IS
		// their software.
		result.addFact(factOSName, "PAN-OS", ConfidenceDerived)
		result.addFact(factOSVersion, info.SWVersion, ConfidenceReported)
	}
	if seconds, ok := panParseUptime(info.Uptime); ok {
		result.addFact(factNetUptimeSeconds, seconds, ConfidenceReported)
	}
	// We reached the management plane over the XML API, which is HTTPS.
	result.addFact(factMgmtProtocol, "https", ConfidenceReported)
	result.addFact(factMgmtPlaintext, false, ConfidenceReported)
}

// panVendor is the manufacturer of any device answering the PAN-OS API.
const panVendor = "Palo Alto Networks"

// panIdentity builds the structured device identity from system info.
func panIdentity(info panSystemInfo) *DeviceIdentity {
	identity := &DeviceIdentity{
		Vendor:    panVendor,
		Model:     info.Model,
		OSVersion: strings.TrimSpace("PAN-OS " + info.SWVersion),
		ClassHint: panClassHint(),
	}
	identity.SerialNumber = info.Serial
	// PAN-OS reports one version; it is the software version, and repeating it
	// as a firmware version would invent a second fact from one measurement.
	return identity
}

// panParseUptime converts PAN-OS's "8 days, 4:23:11" into seconds.
//
// The days part is absent for the first day of uptime ("4:23:11"), which is
// exactly the case a naive split gets wrong — and getting it wrong reads as a
// device rebooted seconds ago, which is a patching signal nobody asked for.
func panParseUptime(uptime string) (int, bool) {
	s := strings.TrimSpace(uptime)
	if s == "" {
		return 0, false
	}
	total := 0
	if i := strings.Index(s, "day"); i >= 0 {
		days, err := strconv.Atoi(strings.TrimSpace(s[:i]))
		if err != nil {
			return 0, false
		}
		total += days * 86400
		// Skip past "days," / "day,".
		rest := s[i:]
		if j := strings.Index(rest, ","); j >= 0 {
			s = strings.TrimSpace(rest[j+1:])
		} else {
			s = ""
		}
	}
	if s == "" {
		return total, true
	}
	parts := strings.Split(s, ":")
	if len(parts) != 3 {
		return 0, false
	}
	units := []int{3600, 60, 1}
	for i, part := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return 0, false
		}
		total += n * units[i]
	}
	return total, true
}

// panInterfaces builds the net.interfaces value from a `show interface all`
// response plus the management interface from system info.
//
// The management interface is included because it is an interface — PAN-OS
// reports it separately from the data plane, and an inventory that lists a
// firewall's interfaces without the one it is managed on is missing the one an
// operator most wants to see.
func panInterfaces(body string, info panSystemInfo) ([]map[string]interface{}, error) {
	var out []map[string]interface{}
	byName := map[string]int{}

	upsert := func(name string) map[string]interface{} {
		key := strings.ToLower(name)
		if i, ok := byName[key]; ok {
			return out[i]
		}
		entry := map[string]interface{}{"name": name}
		byName[key] = len(out)
		out = append(out, entry)
		return entry
	}

	if body != "" {
		ifnets, err := panFindElements[panIfnetBlock](body, "ifnet")
		if err != nil {
			return nil, err
		}
		for _, block := range ifnets {
			for _, iface := range block.Entries {
				if iface.Name == "" {
					continue
				}
				entry := upsert(iface.Name)
				if addr := panNormalizeCIDR(iface.IP); addr != "" {
					entry["addresses"] = []interface{}{addr}
				}
				// PAN-OS reports an untagged subinterface as tag 0; 0 is not a
				// VLAN, it is the absence of one.
				if tag, err := strconv.Atoi(strings.TrimSpace(iface.Tag)); err == nil && tag > 0 {
					entry["vlan"] = tag
				}
			}
		}

		hw, err := panFindElements[panHWBlock](body, "hw")
		if err != nil {
			return nil, err
		}
		for _, block := range hw {
			for _, iface := range block.Entries {
				if iface.Name == "" {
					continue
				}
				entry := upsert(iface.Name)
				if mac, err := canonicalMAC(iface.MAC); err == nil {
					entry["mac"] = mac
				}
				entry["state"] = panLinkState(iface.State)
				// "speed" is "10000", or "auto"/"unknown" on an interface that
				// has never linked. Only a number is a speed.
				if speed, err := strconv.Atoi(strings.TrimSpace(iface.Speed)); err == nil && speed > 0 {
					entry["speed"] = speed
				}
			}
		}
	}

	if info.IPAddress != "" || info.MACAddress != "" {
		entry := upsert("management")
		if addr := panManagementCIDR(info); addr != "" {
			entry["addresses"] = []interface{}{addr}
		}
		if mac, err := canonicalMAC(info.MACAddress); err == nil {
			entry["mac"] = mac
		}
	}

	return out, nil
}

// panLinkState maps PAN-OS's link state onto the fact vocabulary. An
// unrecognised state becomes "unknown" rather than "down": a state we cannot
// read is not an interface that is off.
func panLinkState(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "up":
		return "up"
	case "down":
		return "down"
	default:
		return "unknown"
	}
}

// panNormalizeCIDR canonicalises an address PAN-OS reports in CIDR form,
// returning "" for the "N/A" it uses for an unaddressed interface.
func panNormalizeCIDR(v string) string {
	s := strings.TrimSpace(v)
	if s == "" || strings.EqualFold(s, "N/A") {
		return ""
	}
	if prefix, err := netip.ParsePrefix(s); err == nil {
		return prefix.String()
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.String()
	}
	return ""
}

// panManagementCIDR combines the management address and dotted netmask system
// info reports separately into one CIDR string.
func panManagementCIDR(info panSystemInfo) string {
	return cidrFromAddressAndMask(info.IPAddress, info.Netmask)
}

// panARPNeighbors projects `show arp all` onto net.neighbors items.
func panARPNeighbors(body string) ([]map[string]interface{}, error) {
	blocks, err := panFindElements[panARPBlock](body, "entries")
	if err != nil {
		return nil, err
	}
	var out []map[string]interface{}
	for _, block := range blocks {
		for _, arp := range block.Entries {
			entry := map[string]interface{}{"protocol": "arp"}
			mac, macErr := canonicalMAC(arp.MAC)
			if macErr == nil {
				entry["remote_mac"] = mac
			}
			if addr, addrErr := canonicalIP(arp.IP); addrErr == nil {
				entry["remote_address"] = addr
			}
			if iface := strings.TrimSpace(arp.Interface); iface != "" {
				entry["local_port"] = iface
			}
			// An incomplete ARP entry (no MAC yet) is an address we asked
			// about, not a neighbour we saw.
			if entry["remote_mac"] == nil {
				continue
			}
			out = append(out, entry)
		}
	}
	return out, nil
}

// panLLDPObservations projects `show lldp neighbors all` onto net.neighbors
// items and the connects_to edges built from them.
func panLLDPObservations(body string) ([]map[string]interface{}, []RelationshipObservation, error) {
	blocks, err := panFindElements[panLLDPInterface](body, "entry")
	if err != nil {
		return nil, nil, err
	}

	var neighbors []map[string]interface{}
	var edges []RelationshipObservation
	for _, block := range blocks {
		local := strings.TrimSpace(block.LocalInterface)
		for _, n := range block.Neighbors {
			entry := map[string]interface{}{"protocol": "lldp"}
			if mac, err := canonicalMAC(n.ChassisID); err == nil {
				entry["remote_mac"] = mac
			}
			if name := strings.TrimSpace(n.SystemName); name != "" {
				entry["remote_name"] = name
			}
			if port := strings.TrimSpace(n.PortID); port != "" {
				entry["remote_port"] = port
			}
			if addr, err := canonicalIP(n.ManagementAddress); err == nil {
				entry["remote_address"] = addr
			}
			if local != "" {
				entry["local_port"] = local
			}
			if entry["remote_mac"] == nil && entry["remote_name"] == nil {
				continue
			}
			neighbors = append(neighbors, entry)

			peer := peerRef(n.SystemName, "")
			peer.Platform = advertisedProduct(n.SystemDescription)
			peer.SoftwareVersion = advertisedVersion(n.SystemDescription)
			// Enabled wins over merely capable: a switch with routing compiled
			// in but not configured is a switch.
			caps := n.EnabledCapabilities
			if strings.TrimSpace(caps) == "" {
				caps = n.SystemCapabilities
			}
			peer.LLDPCapabilities = lldpCapabilityNames(caps)
			peer.AddIdentifier(IdentifierMACAddress, n.ChassisID)
			peer.AddIdentifier(IdentifierIPAddress, n.ManagementAddress)
			addHostIdentifiers(&peer, n.SystemName)
			if len(peer.Identifiers) == 0 {
				continue
			}
			attributes := map[string]interface{}{"discovery_protocol": "lldp"}
			if local != "" {
				attributes["local_port"] = local
			}
			if port := strings.TrimSpace(n.PortID); port != "" {
				attributes["remote_port"] = port
			}
			if desc := strings.TrimSpace(n.PortDescription); desc != "" {
				attributes["remote_port_description"] = desc
			}
			edges = append(edges, RelationshipObservation{
				Type:       relTypeConnectsTo,
				Direction:  SubjectToPeer,
				Peer:       peer,
				Attributes: attributes,
			})
		}
	}
	return neighbors, edges, nil
}
