package tools

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The interface, IPAM and Business Unit read tools (DCIM BUILD_PLAN row 1.10;
// asset-inventory ADR-0006 D9).
//
// Same rules as the asset tools: read-only, one GET per call, tenant scope
// carried by the exchanged JWT (never by an argument), and the token
// permission gate below. These tools gate on `assets.read` because that is the
// inventory permission an API token can carry (the token permission set is a
// closed list); the platform still enforces the user's own `dcim.read` /
// `ipam.read` on the route, so a token minted by a user without them gets the
// platform's 403, relayed as an error.
//
// Paging is limit/offset, because that is what these endpoints speak; the
// `total` in the platform's pagination block describes the whole match.

const (
	dcimPath = "/api/v2/inventory-service/dcim"
	ipamPath = "/api/v2/inventory-service/ipam"

	dcimIPAMPerm = "assets.read"
)

type listInterfacesInput struct {
	AssetID    string `json:"asset_id,omitempty" jsonschema:"UUID of an asset. Omit to search interfaces across the whole estate."`
	Name       string `json:"name,omitempty" jsonschema:"Exact interface name, e.g. Gi0/1 or eth0"`
	MACAddress string `json:"mac_address,omitempty" jsonschema:"A MAC address in any common notation. Matches the primary or any additional address of an interface; across assets this is an identity signal (the same MAC on two assets means a duplicate or a move)."`
	Type       string `json:"type,omitempty" jsonschema:"Interface type key, e.g. 1000base-t, virtual, lag, 10gbase-x-sfpp"`
	Enabled    *bool  `json:"enabled,omitempty" jsonschema:"Only administratively enabled (true) or disabled (false) interfaces"`
	Query      string `json:"q,omitempty" jsonschema:"Substring of name, label or description"`
	Limit      int    `json:"limit,omitempty" jsonschema:"Rows to return, 1-100 (default 25)"`
	Offset     int    `json:"offset,omitempty" jsonschema:"Rows to skip, for paging"`
}

type assetInterfacesInput struct {
	AssetID string `json:"asset_id" jsonschema:"UUID of the asset"`
	Query   string `json:"q,omitempty" jsonschema:"Substring of name, label or description"`
	Limit   int    `json:"limit,omitempty" jsonschema:"Rows to return, 1-100 (default 50)"`
	Offset  int    `json:"offset,omitempty" jsonschema:"Rows to skip, for paging"`
}

type listPrefixesInput struct {
	VRF            string `json:"vrf_id,omitempty" jsonschema:"A VRF UUID, or the word global for the global routing table. Omit for every VRF."`
	Parent         string `json:"parent,omitempty" jsonschema:"CIDR. Only prefixes strictly inside this one, e.g. 203.0.113.0/24"`
	Contains       string `json:"contains,omitempty" jsonschema:"An IP address. Only prefixes that contain it, most specific last"`
	Status         string `json:"status,omitempty" jsonschema:"Prefix status filter, e.g. active, reserved, deprecated, container"`
	BusinessUnitID string `json:"business_unit_id,omitempty" jsonschema:"UUID of a Business Unit (see vistaplatform_list_business_units)"`
	Query          string `json:"q,omitempty" jsonschema:"Free-text search"`
	Limit          int    `json:"limit,omitempty" jsonschema:"Rows to return, 1-100 (default 25)"`
	Offset         int    `json:"offset,omitempty" jsonschema:"Rows to skip, for paging"`
}

type getPrefixInput struct {
	PrefixID       string `json:"prefix_id" jsonschema:"UUID of the prefix"`
	AvailableLimit int    `json:"available_limit,omitempty" jsonschema:"How many free blocks to list, 1-100 (default 10)"`
}

type listIPAddressesInput struct {
	Parent              string `json:"parent,omitempty" jsonschema:"CIDR. Only addresses inside this prefix. Pass vrf_id too: containment is per VRF."`
	VRF                 string `json:"vrf_id,omitempty" jsonschema:"A VRF UUID, or the word global for the global routing table"`
	AssignedInterfaceID string `json:"assigned_interface_id,omitempty" jsonschema:"UUID of an interface (see vistaplatform_get_asset_interfaces). Only addresses assigned to it."`
	Status              string `json:"status,omitempty" jsonschema:"Address status filter, e.g. active, reserved, deprecated, dhcp, slaac"`
	DNSName             string `json:"dns_name,omitempty" jsonschema:"Exact DNS name"`
	Query               string `json:"q,omitempty" jsonschema:"Free-text search over the address, DNS name and description"`
	Limit               int    `json:"limit,omitempty" jsonschema:"Rows to return, 1-100 (default 25)"`
	Offset              int    `json:"offset,omitempty" jsonschema:"Rows to skip, for paging"`
}

type findIPInput struct {
	Address string `json:"address" jsonschema:"An IPv4 or IPv6 address. A zone or prefix length is ignored."`
	VRF     string `json:"vrf,omitempty" jsonschema:"A VRF UUID, or the word global. Omit to look in every VRF."`
}

type listVLANsInput struct {
	GroupID string `json:"group_id,omitempty" jsonschema:"UUID of a VLAN group"`
	SiteID  string `json:"site_id,omitempty" jsonschema:"UUID of a Site"`
	VID     int    `json:"vid,omitempty" jsonschema:"The 802.1Q VLAN id, 1-4094"`
	Status  string `json:"status,omitempty" jsonschema:"VLAN status filter, e.g. active, reserved, deprecated"`
	Query   string `json:"q,omitempty" jsonschema:"Free-text search over the name and description"`
	Limit   int    `json:"limit,omitempty" jsonschema:"Rows to return, 1-100 (default 25)"`
	Offset  int    `json:"offset,omitempty" jsonschema:"Rows to skip, for paging"`
}

type objectChangesInput struct {
	Kind   string `json:"kind" jsonschema:"The object noun, as a key: asset, interface, prefix, ip_address, vlan, vrf, business_unit, site, rack, ..."`
	ID     string `json:"id" jsonschema:"UUID of the object"`
	Since  string `json:"since,omitempty" jsonschema:"RFC 3339 time. Only changes at or after it, e.g. 2026-10-01T00:00:00Z"`
	Limit  int    `json:"limit,omitempty" jsonschema:"Rows to return, 1-100 (default 25)"`
	Offset int    `json:"offset,omitempty" jsonschema:"Rows to skip, for paging"`
}

// pageArgs applies the shared limit/offset clamps.
func pageArgs(q url.Values, limit, offset, def int) {
	q.Set("limit", strconv.Itoa(clampLimit(limit, def, 100)))
	if o := clampOffset(offset); o > 0 {
		q.Set("offset", strconv.Itoa(o))
	}
}

// optionalUUID validates a UUID argument that may be blank.
func optionalUUID(field, v string) (string, error) {
	if strings.TrimSpace(v) == "" {
		return "", nil
	}
	return requireUUID(field, strings.TrimSpace(v))
}

// optionalVRF accepts a UUID or the literal "global".
func optionalVRF(field, v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" || strings.EqualFold(v, "global") {
		return strings.ToLower(v), nil
	}
	return requireUUID(field, v)
}

func registerDcimIPAMTools(s *mcp.Server, d *Deps) {
	get := func(ctx context.Context, base, path string, q url.Values) (any, error) {
		return d.Client.Get(ctx, d.Client.InventoryURL, base+path, q)
	}

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_list_interfaces",
		Description: "List network interfaces, physical and virtual, across the tenant's assets. " +
			"An Interface belongs to one asset and carries its name, type, speed, enabled state, MAC addresses, " +
			"LAG and parent links, 802.1Q mode and the virtual device contexts (VDOM, vsys, VDC, route domain) it belongs to " +
			"(`virtual_device_contexts`, by id and name). Filter by asset_id for one device, or by mac_address to find which " +
			"asset owns a MAC (the same MAC on two assets is a duplicate or a move). Returns `data` (the page) and " +
			"`pagination.total` (the whole match). To see every interface of ONE asset in natural name order use " +
			"vistaplatform_get_asset_interfaces. To find who holds an IP address use vistaplatform_find_ip.",
		Annotations: readOnly("List interfaces"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in listInterfacesInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, dcimIPAMPerm, in, func() (any, error) {
			asset, err := optionalUUID("asset_id", in.AssetID)
			if err != nil {
				return nil, err
			}
			q := url.Values{}
			set(q, "asset_id", asset)
			set(q, "name", in.Name)
			set(q, "mac_address", in.MACAddress)
			set(q, "type", in.Type)
			setBool(q, "enabled", in.Enabled)
			set(q, "q", in.Query)
			pageArgs(q, in.Limit, in.Offset, 25)
			return get(ctx, dcimPath, "/interfaces", q)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_get_asset_interfaces",
		Description: "List one asset's interfaces in natural name order (Gi0/2 before Gi0/10). " +
			"Use after vistaplatform_get_asset when the question is about a device's ports, its LAG members or " +
			"its MAC addresses, or which of the device's virtual device contexts (VDOMs, vsys, VDCs, route domains) each interface " +
			"belongs to (`virtual_device_contexts`). An unknown asset id returns an empty list, not an error.",
		Annotations: readOnly("Get an asset's interfaces"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in assetInterfacesInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, dcimIPAMPerm, in, func() (any, error) {
			id, err := requireUUID("asset_id", in.AssetID)
			if err != nil {
				return nil, err
			}
			q := url.Values{}
			set(q, "q", in.Query)
			pageArgs(q, in.Limit, in.Offset, 50)
			return get(ctx, dcimPath, "/assets/"+id+"/interfaces", q)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_list_prefixes",
		Description: "List IP Prefixes (CIDR blocks) from the tenant's IPAM. A Prefix sits in one VRF (or the global " +
			"table), nests under the longest prefix that contains it, and may belong to a Business Unit, a VLAN and a " +
			"scope (site, location, ...). Use `parent` to walk down a block, `contains` to find the prefixes holding " +
			"an address, and `vrf_id` to stay in one routing table. For utilisation, children and free space of ONE " +
			"prefix use vistaplatform_get_prefix.",
		Annotations: readOnly("List prefixes"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in listPrefixesInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, dcimIPAMPerm, in, func() (any, error) {
			vrf, err := optionalVRF("vrf_id", in.VRF)
			if err != nil {
				return nil, err
			}
			bu, err := optionalUUID("business_unit_id", in.BusinessUnitID)
			if err != nil {
				return nil, err
			}
			q := url.Values{}
			set(q, "vrf_id", vrf)
			set(q, "within", in.Parent)
			set(q, "contains", in.Contains)
			set(q, "status", in.Status)
			set(q, "business_unit_id", bu)
			set(q, "q", in.Query)
			pageArgs(q, in.Limit, in.Offset, 25)
			return get(ctx, ipamPath, "/prefixes", q)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_get_prefix",
		Description: "Fetch one Prefix with its place in the hierarchy: the `parent`, the direct `children`, " +
			"`child_count`, `ip_count`, `utilization` and the free space (`available_prefixes`, `available_ips`). " +
			"HONESTY: a prefix with no addresses is 0% utilised with a count, not unknown; a prefix flagged as a pool " +
			"or mark-utilized is reported as the platform computes it, so quote `utilization` as returned rather than " +
			"recomputing it from ip_count.",
		Annotations: readOnly("Get a prefix"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in getPrefixInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, dcimIPAMPerm, in, func() (any, error) {
			id, err := requireUUID("prefix_id", in.PrefixID)
			if err != nil {
				return nil, err
			}
			q := url.Values{}
			if in.AvailableLimit > 0 {
				q.Set("limit", strconv.Itoa(clampLimit(in.AvailableLimit, 10, 100)))
			}
			return get(ctx, ipamPath, "/prefixes/"+id, q)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_list_ip_addresses",
		Description: "List IP Addresses recorded in IPAM, with their status, DNS name and what they are assigned to. " +
			"Filter by `parent` (a CIDR; pass vrf_id as well) to see the addresses of one prefix, or by " +
			"`assigned_interface_id` to see an interface's addresses. This lists recorded addresses; it does not say " +
			"who is using an address that was never recorded — to ask 'what holds 10.1.2.3?' use vistaplatform_find_ip.",
		Annotations: readOnly("List IP addresses"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in listIPAddressesInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, dcimIPAMPerm, in, func() (any, error) {
			vrf, err := optionalVRF("vrf_id", in.VRF)
			if err != nil {
				return nil, err
			}
			iface, err := optionalUUID("assigned_interface_id", in.AssignedInterfaceID)
			if err != nil {
				return nil, err
			}
			q := url.Values{}
			set(q, "vrf_id", vrf)
			set(q, "parent", in.Parent)
			if iface != "" {
				q.Set("assigned_kind", "interface")
				q.Set("assigned_id", iface)
			}
			set(q, "status", in.Status)
			set(q, "dns_name", in.DNSName)
			set(q, "q", in.Query)
			pageArgs(q, in.Limit, in.Offset, 25)
			return get(ctx, ipamPath, "/ip-addresses", q)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_find_ip",
		Description: "Answer 'what holds this IP address?'. Returns one result per VRF the address appears in: the most specific " +
			"Prefix containing it, the recorded IP Address (if any), what it is assigned to, and the asset that holds it " +
			"(`asset.via` says how: interface, primary_ip4, primary_ip6 or oob_ip). A result with a prefix but a null " +
			"ip_address and asset means 'inside an allocated block, nobody recorded it' — not 'unused'. An empty list " +
			"means no prefix or address in the tenant's IPAM matches. Omit `vrf` to search every VRF.",
		Annotations: readOnly("Find an IP address"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in findIPInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, dcimIPAMPerm, in, func() (any, error) {
			addr := strings.TrimSpace(in.Address)
			if addr == "" {
				return nil, errRequired("address")
			}
			vrf, err := optionalVRF("vrf", in.VRF)
			if err != nil {
				return nil, err
			}
			q := url.Values{}
			q.Set("address", addr)
			set(q, "vrf", vrf)
			return get(ctx, ipamPath, "/find", q)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_list_vlans",
		Description: "List VLANs: VID, name, status, the VLAN group and Site they belong to. " +
			"Use `vid` to find every VLAN with that 802.1Q id across groups (the same VID legitimately appears in " +
			"several groups). Prefixes and interfaces reference VLANs by id.",
		Annotations: readOnly("List VLANs"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in listVLANsInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, dcimIPAMPerm, in, func() (any, error) {
			group, err := optionalUUID("group_id", in.GroupID)
			if err != nil {
				return nil, err
			}
			site, err := optionalUUID("site_id", in.SiteID)
			if err != nil {
				return nil, err
			}
			q := url.Values{}
			set(q, "group_id", group)
			set(q, "site_id", site)
			if in.VID > 0 {
				q.Set("vid", strconv.Itoa(in.VID))
			}
			set(q, "status", in.Status)
			set(q, "q", in.Query)
			pageArgs(q, in.Limit, in.Offset, 25)
			return get(ctx, ipamPath, "/vlans", q)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_list_business_units",
		Description: "List the tenant's Business Units — the organisational owners that assets, prefixes and " +
			"other objects are attributed to. Returns every Business Unit (the list is small and unpaged) with its id; " +
			"pass an id as `business_unit_id` to vistaplatform_list_prefixes, or use `business_unit` in an asset query.",
		Annotations: readOnly("List business units"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in emptyInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, dcimIPAMPerm, in, func() (any, error) {
			return get(ctx, dcimPath, "/business-units", nil)
		})
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vistaplatform_get_object_changes",
		Description: "Show the recorded change history of ONE object (an asset, interface, prefix, IP address, VLAN, " +
			"Business Unit, ...), newest first: who changed it (user or discovery source), when, what action, which " +
			"fields, and the before/after images (secrets are redacted by the platform). Use `since` to ask 'what " +
			"changed this week'. Answers 'who changed this prefix?' and 'when did this interface go down?'. An " +
			"object with no recorded changes returns an empty list.",
		Annotations: readOnly("Get an object's changes"),
	}, func(ctx context.Context, req *mcp.CallToolRequest, in objectChangesInput) (*mcp.CallToolResult, any, error) {
		return d.run(ctx, req, dcimIPAMPerm, in, func() (any, error) {
			kind := strings.TrimSpace(in.Kind)
			if kind == "" {
				return nil, errRequired("kind")
			}
			id, err := requireUUID("id", in.ID)
			if err != nil {
				return nil, err
			}
			q := url.Values{}
			q.Set("object_kind", kind)
			q.Set("object_id", id)
			set(q, "since", strings.TrimSpace(in.Since))
			pageArgs(q, in.Limit, in.Offset, 25)
			return get(ctx, dcimPath, "/changes", q)
		})
	})
}

func errRequired(field string) error {
	return fmt.Errorf("%s is required", field)
}
