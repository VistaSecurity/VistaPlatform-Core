package deviceinterrogation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
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

	// The ARP table: evidence about the hosts on the FortiGate's networks
	// (DCIM row 1.5c). A status endpoint; it carries no configuration.
	arp, err := c.getMonitorResults(ctx, "/api/v2/monitor/network/arp")
	if err != nil {
		result.warn("/api/v2/monitor/network/arp", err, "ARP neighbours not collected")
	}

	// As objects (fortinet_network.go), no longer the net.interfaces /
	// net.vlans facts.
	result.setNetwork(fortinetNetwork(configured, running, arp), "/api/v2/cmdb/system/interface")

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
	c.authorize(req)
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
