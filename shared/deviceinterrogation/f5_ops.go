package deviceinterrogation

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// F5 BIG-IP ops facts and observed dependencies (asset-inventory ADR-0004 D1
// item 5, ADR-0003 D2).
//
// The F5 interrogator already reads `ltm/virtual` and both SSL profile
// collections; it knows every VIP on the box and nothing about the box itself
// or about what the VIPs are actually load-balancing to. Five more iControl
// collections close that: `sys/hardware` (the chassis serial and platform),
// `net/interface`, `net/vlan` and `net/self` (the ops network view), and
// `ltm/pool` with its members expanded — which is what turns a list of VIPs
// into a dependency graph.
//
// **The pool edges are the point of this collector.** ADR-0004 D1 (5) names
// them specifically: "F5 pools give `depends_on` edges from a virtual server to
// its members". A load balancer is the one device on a customer's network that
// states, in its own configuration, which services depend on which servers.
// Nothing else we collect says that, and an impact traversal without it is
// guessing.
//
// Every response here is bound to a TYPED STRUCT with explicit json tags, so
// unknown fields are discarded STRUCTURALLY. That is the strongest form the
// projection rule takes: there is no path by which a `passphrase`, a
// `privateKey` or an SNMP community from a differently-shaped response reaches
// the result, because the decoder has nowhere to put it. `sys/hardware` is the
// exception in shape only — its response is a recursive stats tree with
// vendor-chosen keys — so its leaves go through a named allowlist instead, and
// the tree itself is never stored.
//
// Deliberately NOT read:
//
//   - `sys/crypto/key`, `sys/file/ssl-key`. The private keys of every
//     certificate on the box. The interrogator reads `sys/crypto/cert` — the
//     public half — and that is the whole of what a CBOM needs.
//   - `auth/user`, `sys/db` (`systemauth.*`). Administrator accounts and the
//     authentication configuration, including LDAP and RADIUS bind secrets.
//   - `ltm/rule` (iRules). Customer-written TCL, unbounded, and a place people
//     do put credentials.
//   - `ltm/monitor/*`. Health monitors carry the `password` a monitor
//     authenticates to the backend with.
//   - `net/route`. The same decision Cisco gets: ADR-0004 D1 asks for a
//     next-hop summary, and iControl cannot be asked for one — only for the
//     whole table.

// f5Vendor is the manufacturer of any device answering iControl REST, spelled
// to match the sysObjectID enterprise-3375 hint in classhint.go so the same
// appliance does not get two vendor spellings depending on how it was reached.
const f5Vendor = "F5 Networks"

// f5OSName is what runs on a BIG-IP. TMOS is an operating system: an F5
// security advisory names "TMOS 17.1.1" and the EOL catalogue is keyed on
// product plus version.
const f5OSName = "TMOS"

// f5SystemVersionFields is the `sys/version` allowlist. The response is benign
// today, but it was being copied WHOLESALE into DeviceInfo — the one collector
// in this package with no projection on its system call — and "benign today" is
// not a property a vendor guarantees across releases.
var f5SystemVersionFields = []string{"Version", "Build", "Product", "Edition", "Date", "Title"}

// f5HardwareFields is the leaf allowlist for `sys/hardware`.
//
// The response is a recursive stats tree whose keys are chosen by the device,
// so a typed struct cannot bound it the way it bounds the other collections —
// the tree is walked into a flat leaf map, that map is projected through this
// list, and the map itself never leaves the function.
var f5HardwareFields = []string{
	"bigipChassisSerialNum", // chassis serial — the CMDB join key
	"hostBoardSerialNum",    // fallback on platforms with no chassis serial
	"platform",              // platform id, e.g. "Z100"
	"marketingName",         // product name, e.g. "BIG-IP Virtual Edition"
}

// f5MaxHardwareDepth bounds the recursion through the stats tree. The tree is
// three levels deep on every platform; the bound is there because its shape is
// the device's to choose, not ours.
const f5MaxHardwareDepth = 8

// f5NetInterface is the `net/interface` projection.
type f5NetInterface struct {
	Name        string `json:"name"`
	MACAddress  string `json:"macAddress"`
	Enabled     bool   `json:"enabled"`
	Disabled    bool   `json:"disabled"`
	MediaActive string `json:"mediaActive"`
}

// f5NetVLAN is the `net/vlan` projection.
type f5NetVLAN struct {
	Name     string `json:"name"`
	FullPath string `json:"fullPath"`
	Tag      int    `json:"tag"`
}

// f5SelfIP is the `net/self` projection: the device's own address on a VLAN.
//
// `allowService` is bound by neither name nor type: it is the management
// port-lockdown list, which is firewall posture rather than inventory, and
// nothing reads it.
type f5SelfIP struct {
	Name     string `json:"name"`
	Address  string `json:"address"`
	VLAN     string `json:"vlan"`
	FullPath string `json:"fullPath"`
}

// f5Pool is the `ltm/pool?expandSubcollections=true` projection.
type f5Pool struct {
	Name           string `json:"name"`
	FullPath       string `json:"fullPath"`
	MembersRefence struct {
		Items []f5PoolMember `json:"items"`
	} `json:"membersReference"`
}

// f5PoolMember is one member of a pool: an address (or an FQDN node) and a
// port. It is the far end of a virtual server's depends_on edge.
type f5PoolMember struct {
	Name     string `json:"name"`
	Address  string `json:"address"`
	FullPath string `json:"fullPath"`
	State    string `json:"state"`
	FQDN     struct {
		TMName string `json:"tmName"`
	} `json:"fqdn"`
}

// f5Collection is the iControl REST collection envelope.
type f5Collection[T any] struct {
	Items []T `json:"items"`
}

// f5HardwareStats / f5HardwareEntry bind the `sys/hardware` stats tree. The
// entry type carries exactly two fields, so however many keys a platform puts
// in the tree, the only thing that can be read out of one is a description.
type f5HardwareStats struct {
	Entries map[string]f5HardwareEntry `json:"entries"`
}

type f5HardwareEntry struct {
	NestedStats f5HardwareStats `json:"nestedStats"`
	Description string          `json:"description"`
}

// f5CollectOps reads the ops collections and emits the facts and edges they
// describe.
//
// virtualServers is what the interrogation already fetched; the pool edges are
// built from it rather than from a second fetch, because the VIP→pool binding
// is a field of the virtual server and re-reading it could see a different
// configuration.
func (c *f5Client) f5CollectOps(ctx context.Context, result *InterrogateResult, virtualServers []f5VirtualServer) {
	// --- identity ---------------------------------------------------------
	result.addFact(factHWVendor, f5Vendor, ConfidenceDerived)

	hardware := c.f5Hardware(ctx)
	if serial := f5FirstNonEmpty(hardware, "bigipChassisSerialNum", "hostBoardSerialNum"); serial != "" {
		result.addFact(factHWSerial, serial, ConfidenceReported)
	}
	model := f5FirstNonEmpty(hardware, "marketingName", "platform")
	if model == "" {
		// sys/version names the product on a platform with no hardware stats
		// (a Virtual Edition under some hypervisors reports an empty tree).
		model = f5GetString(result.DeviceInfo, "Product")
	}
	if model != "" {
		result.addFact(factHWModel, model, ConfidenceReported)
	}
	if version := f5GetString(result.DeviceInfo, "Version"); version != "" {
		result.addFact(factOSName, f5OSName, ConfidenceDerived)
		result.addFact(factOSVersion, version, ConfidenceReported)
	}

	// --- interfaces and VLANs --------------------------------------------
	interfaces, err := f5GetCollection[f5NetInterface](ctx, c, "/mgmt/tm/net/interface")
	if err != nil {
		fmt.Printf("Warning: failed to get F5 interfaces: %v\n", err)
	} else if projected := f5Interfaces(interfaces); len(projected) > 0 {
		result.addFact(factNetInterfaces, projected, ConfidenceReported)
	}

	vlans, err := f5GetCollection[f5NetVLAN](ctx, c, "/mgmt/tm/net/vlan")
	if err != nil {
		fmt.Printf("Warning: failed to get F5 VLANs: %v\n", err)
	}
	selfIPs, err := f5GetCollection[f5SelfIP](ctx, c, "/mgmt/tm/net/self")
	if err != nil {
		fmt.Printf("Warning: failed to get F5 self IPs: %v\n", err)
	}
	if projected := f5VLANs(vlans, selfIPs); len(projected) > 0 {
		result.addFact(factNetVlans, projected, ConfidenceReported)
	}

	// --- pool membership → depends_on ------------------------------------
	pools, err := f5GetCollection[f5Pool](ctx, c, "/mgmt/tm/ltm/pool?expandSubcollections=true")
	if err != nil {
		fmt.Printf("Warning: failed to get F5 pools: %v\n", err)
	} else {
		for _, edge := range f5PoolDependencies(virtualServers, pools) {
			result.addRelationship(edge)
		}
	}

	// --- management plane -------------------------------------------------
	// iControl REST is HTTPS; reaching it at all is the measurement.
	result.addFact(factMgmtProtocol, "https", ConfidenceReported)
	result.addFact(factMgmtPlaintext, false, ConfidenceReported)
}

// f5Hardware reads `sys/hardware` and returns the allowlisted leaves.
func (c *f5Client) f5Hardware(ctx context.Context) map[string]string {
	stats, err := f5GetJSON[f5HardwareStats](ctx, c, "/mgmt/tm/sys/hardware")
	if err != nil {
		fmt.Printf("Warning: failed to get F5 hardware info: %v\n", err)
		return nil
	}
	leaves := map[string]string{}
	f5WalkHardware(stats, leaves, 0)

	projected := make(map[string]string, len(f5HardwareFields))
	for _, field := range f5HardwareFields {
		if v, ok := leaves[field]; ok && v != "" {
			projected[field] = v
		}
	}
	return projected
}

// f5WalkHardware flattens the stats tree into leaf-name → description.
func f5WalkHardware(stats f5HardwareStats, out map[string]string, depth int) {
	if depth > f5MaxHardwareDepth {
		return
	}
	for key, entry := range stats.Entries {
		if entry.Description != "" {
			name := key
			if i := strings.LastIndex(name, "/"); i >= 0 {
				name = name[i+1:]
			}
			if _, seen := out[name]; !seen {
				out[name] = strings.TrimSpace(entry.Description)
			}
		}
		f5WalkHardware(entry.NestedStats, out, depth+1)
	}
}

func f5FirstNonEmpty(m map[string]string, keys ...string) string {
	for _, key := range keys {
		if v := strings.TrimSpace(m[key]); v != "" {
			return v
		}
	}
	return ""
}

// f5Interfaces projects `net/interface` onto net.interfaces items.
//
// F5 states the administrative state as one of two mutually exclusive booleans
// — an item carries `enabled: true` OR `disabled: true`, never both and
// sometimes neither — so an item that states neither gets no admin_state at
// all rather than a default. `mediaActive` is the operational state AND the
// negotiated speed in one string: "1000T-FD" is a linked gigabit port, "none"
// is a port with nothing in it.
func f5Interfaces(interfaces []f5NetInterface) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(interfaces))
	for _, iface := range interfaces {
		name := strings.TrimSpace(iface.Name)
		if name == "" {
			continue
		}
		entry := map[string]interface{}{"name": name}
		if mac, err := canonicalMAC(iface.MACAddress); err == nil {
			entry["mac"] = mac
		}
		switch {
		case iface.Disabled:
			entry["admin_state"] = "down"
		case iface.Enabled:
			entry["admin_state"] = "up"
		}
		media := strings.ToLower(strings.TrimSpace(iface.MediaActive))
		switch media {
		case "":
			// Nothing said. "unknown" would be a claim; absence is not.
		case "none":
			entry["state"] = "down"
		default:
			entry["state"] = "up"
			if speed := f5MediaSpeed(iface.MediaActive); speed > 0 {
				entry["speed"] = speed
			}
		}
		out = append(out, entry)
	}
	return out
}

// f5MediaSpeed reads the Mbit/s out of an F5 media string ("1000T-FD" → 1000,
// "10000SR-FD" → 10000). A string with no leading number ("auto", "none") has
// no speed in it, and 0 is what the fact schema reads as unknown.
func f5MediaSpeed(media string) int {
	s := strings.TrimSpace(media)
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	speed, err := strconv.Atoi(s[:end])
	if err != nil {
		return 0
	}
	return speed
}

// f5VLANs projects `net/vlan` and `net/self` onto net.vlans items.
//
// A self IP is the device's own address on a VLAN, so it yields two things
// from one field: the segment (the address masked to its prefix) and the
// device's address on it. That is the same reading UniFi's `ip_subnet` gets,
// and it is deliberately the same reading — one fact key must not mean two
// things depending on which collector wrote it.
func f5VLANs(vlans []f5NetVLAN, selfIPs []f5SelfIP) []map[string]interface{} {
	selfByVLAN := map[string]string{}
	for _, self := range selfIPs {
		vlan := f5ObjectName(self.VLAN)
		if vlan == "" || self.Address == "" {
			continue
		}
		if _, seen := selfByVLAN[vlan]; !seen {
			selfByVLAN[vlan] = self.Address
		}
	}

	out := make([]map[string]interface{}, 0, len(vlans))
	for _, vlan := range vlans {
		name := strings.TrimSpace(vlan.Name)
		if name == "" {
			name = f5ObjectName(vlan.FullPath)
		}
		entry := map[string]interface{}{}
		if name != "" {
			entry["name"] = name
		}
		// An untagged VLAN reports tag 0, which is the absence of a tag rather
		// than VLAN zero.
		if vlan.Tag > 0 {
			entry["id"] = vlan.Tag
		}
		if address, ok := selfByVLAN[name]; ok {
			if prefix, gateway := splitPrefixAndAddress(f5StripRouteDomain(address)); prefix != "" {
				entry["subnet"] = prefix
				if gateway != "" {
					entry["gateway"] = gateway
				}
			}
		}
		// A VLAN with neither a tag nor a prefix is a name and nothing else.
		if _, hasID := entry["id"]; !hasID {
			if _, hasSubnet := entry["subnet"]; !hasSubnet {
				continue
			}
		}
		out = append(out, entry)
	}
	return out
}

// f5PoolDependencies builds the depends_on edges from each virtual server to
// the members of the pool it forwards to.
//
// Direction: the VIRTUAL SERVER depends on its members, so the canonical
// direction runs subject → peer and the reverse reads "used_by" (ADR-0003 D2).
// A member that goes away breaks the service; the service going away does not
// break the member.
//
// A virtual server carrying no identifier is skipped rather than emitted with
// an empty subject: an empty subject means "the interrogated device", so the
// edge would say the BIG-IP itself depends on the member, which is a different
// and wrong claim.
func f5PoolDependencies(virtualServers []f5VirtualServer, pools []f5Pool) []RelationshipObservation {
	byPath := map[string]f5Pool{}
	for _, pool := range pools {
		if path := strings.TrimSpace(pool.FullPath); path != "" {
			byPath[path] = pool
		}
		if name := f5ObjectName(pool.FullPath); name != "" {
			if _, seen := byPath[name]; !seen {
				byPath[name] = pool
			}
		}
		if name := strings.TrimSpace(pool.Name); name != "" {
			if _, seen := byPath[name]; !seen {
				byPath[name] = pool
			}
		}
	}

	var out []RelationshipObservation
	for _, vs := range virtualServers {
		// A disabled virtual server serves nothing. It is excluded for the same
		// reason a disabled UniFi network is not reported as a segment, and —
		// more importantly — so a VIP's asset and its dependency edges appear
		// and disappear together: the crypto-asset loop skips disabled virtual
		// servers too, and a dependency graph that outlived the service it
		// belongs to would be a map of a network that is not there.
		if !vs.Enabled {
			continue
		}
		poolRef := strings.TrimSpace(vs.Pool)
		if poolRef == "" {
			continue
		}
		pool, ok := byPath[poolRef]
		if !ok {
			pool, ok = byPath[f5ObjectName(poolRef)]
		}
		if !ok {
			continue
		}

		subject := f5VirtualServerPeer(vs)
		if len(subject.Identifiers) == 0 {
			continue
		}

		for _, member := range pool.MembersRefence.Items {
			peer, port := f5PoolMemberPeer(member)
			if len(peer.Identifiers) == 0 {
				continue
			}
			attributes := map[string]interface{}{
				"pool": f5ObjectName(pool.FullPath),
			}
			if attributes["pool"] == "" {
				attributes["pool"] = pool.Name
			}
			if port > 0 {
				attributes["remote_port"] = port
			}
			// The monitor's verdict on the member. A measured attribute of the
			// dependency, not a judgement: a finding is what turns "down" into
			// something someone is told about.
			if state := strings.TrimSpace(member.State); state != "" {
				attributes["member_state"] = state
			}
			out = append(out, RelationshipObservation{
				Type:       relTypeDependsOn,
				Direction:  SubjectToPeer,
				Subject:    subject,
				Peer:       peer,
				Attributes: attributes,
			})
		}
	}
	return out
}

// f5VirtualServerPeer names a virtual server: the near end of its dependency
// edges. Its address is the strong identifier; its name is a label that MAY be
// a hostname, and canonicalDNSName is the arbiter of that rather than a guess
// here.
func f5VirtualServerPeer(vs f5VirtualServer) PeerRef {
	name := f5ObjectName(vs.Name)
	subject := peerRef(name, f5ClassHint())
	if address, _ := f5ParseDestination(vs.Destination); address != "" {
		subject.AddIdentifier(IdentifierIPAddress, address)
	}
	addHostIdentifiers(&subject, name)
	return subject
}

// f5PoolMemberPeer names a pool member and returns its service port.
//
// A member is "<address or node name>:<port>"; the address is stated separately
// for an address node and the FQDN in `fqdn.tmName` for an FQDN node. Both are
// tried, and whichever normalises is kept.
//
// No class hint: a pool states an address, a port and a monitor verdict, and
// none of those says whether the member is a server, another load balancer or a
// container ingress. See classhint.go for the argument.
func f5PoolMemberPeer(member f5PoolMember) (PeerRef, int) {
	name := f5ObjectName(member.Name)
	host, port := f5SplitMember(name)

	peer := peerRef(host, "")
	peer.AddIdentifier(IdentifierIPAddress, f5StripRouteDomain(member.Address))
	peer.AddIdentifier(IdentifierIPAddress, f5StripRouteDomain(host))
	addHostIdentifiers(&peer, member.FQDN.TMName)
	addHostIdentifiers(&peer, host)
	return peer, port
}

// f5SplitMember splits "<host>:<port>" or IPv6's "<host>.<port>", by the same
// family-dependent rule f5ParseDestination handles for a VIP destination.
func f5SplitMember(member string) (host string, port int) {
	s := strings.TrimSpace(member)
	if s == "" {
		return "", 0
	}
	host, portStr := s, ""
	if strings.Count(s, ":") > 1 {
		if idx := strings.LastIndex(s, "."); idx >= 0 {
			host, portStr = s[:idx], s[idx+1:]
		}
	} else if idx := strings.LastIndex(s, ":"); idx >= 0 {
		host, portStr = s[:idx], s[idx+1:]
	}
	if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p <= 65535 {
		port = p
	}
	return host, port
}

// f5ObjectName strips the partition and folder prefix iControl puts on every
// object name ("/Common/Prod/web-pool" → "web-pool").
func f5ObjectName(name string) string {
	s := strings.TrimSpace(name)
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// f5GetCollection reads an iControl REST collection into a typed slice.
func f5GetCollection[T any](ctx context.Context, c *f5Client, path string) ([]T, error) {
	collection, err := f5GetJSON[f5Collection[T]](ctx, c, path)
	if err != nil {
		return nil, err
	}
	return collection.Items, nil
}

// f5GetJSON reads an iControl REST endpoint into a typed value.
//
// Typed, not map-shaped, on purpose: the struct IS the allowlist, and a field
// the decoder has no home for is discarded before any of our code sees it.
func f5GetJSON[T any](ctx context.Context, c *f5Client, path string) (T, error) {
	var out T

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return out, err
	}
	if c.token != "" {
		req.Header.Set("X-F5-Auth-Token", c.token)
	} else {
		req.SetBasicAuth(c.username, c.password)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return out, fmt.Errorf("API request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return out, fmt.Errorf("API returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	// Bounded: `ltm/pool?expandSubcollections=true` is the largest response this
	// collector asks for and its size is the device's to choose.
	if err := decodeBoundedJSON(resp.Body, "F5 "+path, &out); err != nil {
		return out, err
	}
	return out, nil
}
