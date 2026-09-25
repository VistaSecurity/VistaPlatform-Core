package deviceinterrogation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

// FortiOS ops facts (asset-inventory ADR-0004 D1 item 5).
//
// The Fortinet interrogator already authenticates to the REST API and reads
// three cmdb objects, all of them about crypto. Three more calls answer the ops
// set: `cmdb/system/interface` (the configured interfaces, their addresses and
// their 802.1Q tags), `monitor/system/interface` (what those interfaces are
// actually doing — link and negotiated speed) and `monitor/router/ipv4`, from
// which ONE integer is kept.
//
// Every response goes through a named field allowlist, because FortiOS cmdb
// objects are CONFIGURATION and configuration is where the material lives.
// `system/interface` alone carries the PPPoE `password`, the `auth-cert` and
// the `ike` settings of a dialup interface. The projection is the real defence;
// Sanitize is the backstop for the field a FortiOS release adds next week.
//
// Deliberately NOT retrieved, each for its own reason:
//
//   - `firewall/address`, `firewall/addrgrp`, `firewall/policy`. Policy objects
//     are the customer's security posture written down — which source may reach
//     which destination on which port. An inventory has no reader for them, and
//     holding them makes our database a better map of the network than the
//     firewall is.
//   - Anything under `user/` (`user/local`, `user/radius`, `user/ldap`,
//     `user/group`). These are accounts and directory bind credentials.
//     `user/radius` carries the shared secret in `secret`.
//   - `vpn.certificate/ca`, `vpn.certificate/crl`, `vpn.certificate/remote`.
//     The local certificate store IS read (it is crypto posture, and its
//     private key is projected away); the CA and remote stores add trust-store
//     bulk with no posture in it.
//   - `system/admin`, `system/api-user`. Administrator accounts, their trusted
//     hosts and their API keys.
//   - `monitor/system/available-interfaces`. It enumerates what COULD be
//     configured, which is not an inventory of what is.
//   - `monitor/user/device` / `monitor/user/detected-device`. The client list —
//     endpoint discovery, deferred with UniFi's and SNMP's for the same
//     reason.

// fortinetVendor is the manufacturer of any device answering the FortiOS API.
const fortinetVendor = "Fortinet"

// fortinetOSName is what runs on one. FortiOS is an operating system, not a
// firmware blob: an advisory names "FortiOS 7.4.4" and the EOL catalogue is
// keyed on product plus version.
const fortinetOSName = "FortiOS"

// fortinetInterfaceFields is the `cmdb/system/interface` allowlist: the
// configured view.
//
// Absent, and named here so the next person does not have to diff two lists to
// see it: `password` (the PPPoE password), `ppp-*`, `auth-cert`, `ike-*`,
// `dhcp-*` option detail, and the `secondaryip` table. The last is addresses
// rather than material, but it is a nested vendor table and copying one
// wholesale is the mistake this file exists to avoid.
var fortinetInterfaceFields = []string{
	"name",      // interface name
	"ip",        // "address netmask", space separated
	"macaddr",   // the interface's MAC, where FortiOS reports one
	"status",    // administrative status: "up" | "down"
	"vlanid",    // 802.1Q tag, 0 on an untagged interface
	"type",      // "physical" | "vlan" | "aggregate" | "tunnel" | …
	"interface", // parent interface of a VLAN subinterface
	"role",      // "lan" | "wan" | "dmz" | "undefined"
	"vdom",      // virtual domain the interface belongs to
}

// fortinetMonitorInterfaceFields is the `monitor/system/interface` allowlist:
// the running view. It is a status endpoint and carries no configuration, but
// it is projected like everything else — an allowlist that is skipped where the
// response "looks safe" is an allowlist nobody can rely on.
var fortinetMonitorInterfaceFields = []string{
	"name",
	"link",  // operational state, boolean
	"speed", // negotiated speed, Mbit/s
	"mac",   // some releases report the MAC here and not in cmdb
	"ip",    // dotted address
	"mask",  // dotted netmask
}

// fortinetRouteFields is the `monitor/router/ipv4` allowlist, and it has ONE
// field. The prefixes, their interfaces, their metrics and their protocols are
// never read and never stored — only how many DISTINCT next hops there are
// (net.route_next_hop_count). A routing table is a map of the customer's
// network; the count is the part an inventory can act on.
var fortinetRouteFields = []string{"gateway"}

// fortinetMaxRouteRows bounds the route response a device may make us walk. A
// full BGP table is hundreds of thousands of rows, and the answer we want from
// it is one small integer.
const fortinetMaxRouteRows = 200000

// fortinetCollectOps reads the ops endpoints and emits the facts they describe.
//
// Every step is best-effort: a FortiGate with a restricted API profile answers
// some of these and 403s the rest, and losing the whole interrogation over one
// endpoint would be worse than losing one fact.
func (c *fortinetClient) fortinetCollectOps(ctx context.Context, result *InterrogateResult, sysInfo map[string]interface{}) {
	// --- identity ---------------------------------------------------------
	result.addFact(factHWVendor, fortinetVendor, ConfidenceDerived)
	if model := fortinetString(sysInfo, "model_name", "model"); model != "" {
		result.addFact(factHWModel, model, ConfidenceReported)
	}
	if serial := fortinetString(sysInfo, "serial"); serial != "" {
		result.addFact(factHWSerial, serial, ConfidenceReported)
	}
	if version := fortinetString(sysInfo, "version"); version != "" {
		result.addFact(factOSName, fortinetOSName, ConfidenceDerived)
		result.addFact(factOSVersion, version, ConfidenceReported)
	}

	// --- interfaces and VLANs --------------------------------------------
	configured, err := c.getResults(ctx, "/api/v2/cmdb/system/interface")
	if err != nil {
		result.warn("/api/v2/cmdb/system/interface", err, "Configured interfaces and VLANs not collected")
	}
	running, err := c.getMonitorResults(ctx, "/api/v2/monitor/system/interface")
	if err != nil {
		result.warn("/api/v2/monitor/system/interface", err, "Interface link state not collected")
	}

	if interfaces := fortinetInterfaces(configured, running); len(interfaces) > 0 {
		result.addFact(factNetInterfaces, interfaces, ConfidenceReported)
	}
	if vlans := fortinetVLANs(configured); len(vlans) > 0 {
		result.addFact(factNetVlans, vlans, ConfidenceReported)
	}

	// --- routing, as one integer -----------------------------------------
	if routes, err := c.getMonitorResults(ctx, "/api/v2/monitor/router/ipv4"); err != nil {
		result.warn("/api/v2/monitor/router/ipv4", err, "Routing next-hop count not collected")
	} else if count, ok := fortinetNextHopCount(routes); ok {
		if len(routes) > fortinetMaxRouteRows {
			result.warnTruncated("/api/v2/monitor/router/ipv4", "Routing table", fortinetMaxRouteRows)
		}
		result.addFact(factNetRouteNextHopCount, count, ConfidenceDerived)
	}

	// --- management plane -------------------------------------------------
	// We reached the management plane over the REST API, which is HTTPS.
	result.addFact(factMgmtProtocol, "https", ConfidenceReported)
	result.addFact(factMgmtPlaintext, false, ConfidenceReported)
}

// getMonitorResults reads a FortiOS monitor endpoint.
//
// The monitor API returns `results` as an ARRAY on some endpoints and as an
// OBJECT KEYED BY NAME on others — `monitor/system/interface` is keyed by
// interface name, `monitor/router/ipv4` is a list. The cmdb response type
// binds `results` to a slice, so pointing it at a monitor endpoint decodes to
// nothing at all and reports success. Both shapes are accepted here and the
// object's key is folded in as `name`, which is where the array form carries
// it.
func (c *fortinetClient) getMonitorResults(ctx context.Context, path string) ([]map[string]interface{}, error) {
	resp, err := c.apiRequestRaw(ctx, "GET", c.baseURL+path)
	if err != nil {
		return nil, err
	}
	// A response with no `results` member at all is not a device with nothing
	// to report — it is an answer we could not read. nil is what says so, and
	// fortinetNextHopCount reads exactly that distinction: an empty-but-read
	// table is a real zero, an unread one must not be recorded as one. An
	// explicit `[]` still decodes below into an empty, non-nil slice.
	if len(resp.Results) == 0 {
		return nil, nil
	}

	var asArray []map[string]interface{}
	if err := json.Unmarshal(resp.Results, &asArray); err == nil {
		return asArray, nil
	}

	var asObject map[string]map[string]interface{}
	if err := json.Unmarshal(resp.Results, &asObject); err != nil {
		return nil, fmt.Errorf("failed to decode %s results: %w", path, err)
	}
	out := make([]map[string]interface{}, 0, len(asObject))
	for key, entry := range asObject {
		if _, named := entry["name"]; !named {
			entry["name"] = key
		}
		out = append(out, entry)
	}
	return out, nil
}

// fortinetRawResponse is the FortiOS envelope with `results` left undecoded, so
// the caller can accept either shape the monitor API uses.
type fortinetRawResponse struct {
	Status       string          `json:"status"`
	Serial       string          `json:"serial"`
	Version      string          `json:"version"`
	Results      json.RawMessage `json:"results"`
	Error        int             `json:"error"`
	ErrorMessage string          `json:"error_message"`
}

func (c *fortinetClient) apiRequestRaw(ctx context.Context, method, url string) (*fortinetRawResponse, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.username, c.password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, statusErrorf(resp.StatusCode, "API returned status %d%s", resp.StatusCode, fortinetErrorCode(resp.Body))
	}

	// Bounded: `monitor/router/ipv4` on a box carrying a full BGP table is the
	// largest response this collector asks for, and one integer is all we want
	// out of it.
	var apiResp fortinetRawResponse
	if err := decodeBoundedJSON(resp.Body, "FortiOS "+url, &apiResp); err != nil {
		return nil, err
	}
	if apiResp.Status != "success" && apiResp.Error != 0 {
		// The numeric code only; error_message is vendor free text.
		return nil, fmt.Errorf("API error (FortiOS code %d)", apiResp.Error)
	}
	return &apiResp, nil
}

// fortinetInterfaces merges the configured and running views of the interfaces
// into the net.interfaces value.
//
// The two views answer different questions and an operator expects one list:
// cmdb has the address, the tag and the ADMINISTRATIVE status, monitor has the
// link state and the negotiated speed. Keeping the two statuses apart is the
// point — an interface that is down because someone disabled it is a different
// fact from one that is down because nothing is plugged in.
func fortinetInterfaces(configured, running []map[string]interface{}) []map[string]interface{} {
	var out []map[string]interface{}
	byName := map[string]int{}

	for _, raw := range configured {
		projected := projectFortinet(raw, fortinetInterfaceFields)
		name := fortinetString(projected, "name")
		if name == "" {
			continue
		}
		entry := map[string]interface{}{"name": name}
		if mac, err := canonicalMAC(fortinetString(projected, "macaddr")); err == nil {
			entry["mac"] = mac
		}
		// FortiOS states an interface address as "address netmask", space
		// separated. An unconfigured interface reports "0.0.0.0 0.0.0.0",
		// which is the absence of an address rather than an address of zero.
		if addr := fortinetAddress(fortinetString(projected, "ip")); addr != "" {
			entry["addresses"] = []interface{}{addr}
		}
		if vlan := fortinetInt(projected, "vlanid"); vlan > 0 {
			entry["vlan"] = vlan
		}
		if status := fortinetString(projected, "status"); status != "" {
			entry["admin_state"] = fortinetUpDown(status)
		}
		byName[strings.ToLower(name)] = len(out)
		out = append(out, entry)
	}

	for _, raw := range running {
		projected := projectFortinet(raw, fortinetMonitorInterfaceFields)
		name := fortinetString(projected, "name")
		if name == "" {
			continue
		}
		entry := map[string]interface{}{"name": name}
		if i, ok := byName[strings.ToLower(name)]; ok {
			entry = out[i]
		}
		if link, ok := projected["link"].(bool); ok {
			entry["state"] = fortinetUpDown(link)
		}
		if speed := fortinetInt(projected, "speed"); speed > 0 {
			entry["speed"] = speed
		}
		if _, seen := entry["mac"]; !seen {
			if mac, err := canonicalMAC(fortinetString(projected, "mac")); err == nil {
				entry["mac"] = mac
			}
		}
		if _, seen := entry["addresses"]; !seen {
			if addr := cidrFromAddressAndMask(fortinetString(projected, "ip"), fortinetString(projected, "mask")); addr != "" {
				entry["addresses"] = []interface{}{addr}
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

// fortinetVLANs projects the tagged interfaces onto net.vlans items.
//
// A FortiGate has no VLAN database: a VLAN exists on it because a subinterface
// is tagged with it, so the subinterface IS the segment declaration. Its
// address is the firewall's own address on that network, which is the same
// reading UniFi's `ip_subnet` gets.
func fortinetVLANs(configured []map[string]interface{}) []map[string]interface{} {
	var out []map[string]interface{}
	for _, raw := range configured {
		projected := projectFortinet(raw, fortinetInterfaceFields)
		vlan := fortinetInt(projected, "vlanid")
		if vlan <= 0 {
			continue
		}
		entry := map[string]interface{}{"id": vlan}
		if name := fortinetString(projected, "name"); name != "" {
			entry["name"] = name
		}
		if addr := fortinetAddress(fortinetString(projected, "ip")); addr != "" {
			if prefix, gateway := splitPrefixAndAddress(addr); prefix != "" {
				entry["subnet"] = prefix
				if gateway != "" {
					entry["gateway"] = gateway
				}
			}
		}
		out = append(out, entry)
	}
	return out
}

// fortinetNextHopCount counts the DISTINCT next hops of the routing table, and
// returns nothing else from it.
//
// `ok` is false when the table could not be read at all, which is not the same
// statement as a device with no routes — net.route_next_hop_count is read as
// "how connected is this box", and a fabricated zero says the opposite of what
// an unanswered query means.
//
// A connected route reports gateway 0.0.0.0: that is "directly attached", not a
// next hop, and canonicalIP rejects the unspecified address for exactly this
// class of placeholder.
func fortinetNextHopCount(routes []map[string]interface{}) (int, bool) {
	if routes == nil {
		return 0, false
	}
	if len(routes) > fortinetMaxRouteRows {
		// The caller records the cut as a truncated collection warning.
		routes = routes[:fortinetMaxRouteRows]
	}
	seen := map[string]bool{}
	for _, raw := range routes {
		projected := projectFortinet(raw, fortinetRouteFields)
		if hop, err := canonicalIP(fortinetString(projected, "gateway")); err == nil {
			seen[hop] = true
		}
	}
	return len(seen), true
}

// splitPrefixAndAddress turns "192.0.2.1/24" into its masked prefix
// ("192.0.2.0/24") and the address it was masked from, which is the device's
// own address on that network. The address is returned empty when it IS the
// network address and therefore says nothing about where the device sits.
func splitPrefixAndAddress(cidr string) (prefix, address string) {
	parsed, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", ""
	}
	masked := parsed.Masked()
	if parsed.Addr() == masked.Addr() {
		return masked.String(), ""
	}
	return masked.String(), parsed.Addr().String()
}

// fortinetAddress turns FortiOS's "address netmask" pair into a CIDR string,
// returning "" for the all-zero pair an unconfigured interface reports.
func fortinetAddress(v string) string {
	fields := strings.Fields(v)
	switch len(fields) {
	case 0:
		return ""
	case 1:
		// Some releases already state it as a prefix.
		if strings.Contains(fields[0], "/") {
			if prefix, err := netip.ParsePrefix(fields[0]); err == nil && !prefix.Addr().IsUnspecified() {
				return prefix.String()
			}
			return ""
		}
		if addr, err := canonicalIP(fields[0]); err == nil {
			return addr
		}
		return ""
	default:
		if _, err := canonicalIP(fields[0]); err != nil {
			return ""
		}
		return cidrFromAddressAndMask(fields[0], fields[1])
	}
}

func fortinetUpDown(v any) string {
	switch typed := v.(type) {
	case bool:
		if typed {
			return "up"
		}
		return "down"
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "up", "enable", "enabled":
			return "up"
		case "down", "disable", "disabled":
			return "down"
		}
	}
	return "unknown"
}

// fortinetString reads the first non-empty string among the given keys.
func fortinetString(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if v, ok := m[key].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// fortinetInt reads a numeric field. FortiOS serialises integers as JSON
// numbers, which decode to float64, and as strings on a few older releases.
func fortinetInt(m map[string]interface{}, key string) int {
	switch typed := m[key].(type) {
	case float64:
		return int(typed)
	case int:
		return typed
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(typed)); err == nil {
			return n
		}
	}
	return 0
}
