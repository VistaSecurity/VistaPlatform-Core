package services

// Virtualisation as engine specs (DCIM BUILD_PLAN row 4.2; ADR-0010 D8;
// DATA_MODEL §7): cluster types (a catalogue: platform-seeded rows readable,
// never writable), cluster groups, clusters and virtual disks. Column names
// are binding — they are the API property names, the OpenAPI schema properties
// (virtualization_contract_test.go) and the query-language fields.
//
// A virtual machine is an ASSET, not a row here: its cluster, vCPUs, memory
// and disk are asset columns written through UpdateAssetVirtualization, and a
// hypervisor's cluster is a cluster_hosts row (AddClusterHost).

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// VirtualizationObjectRoutes are the object routes under /virtualization.
func VirtualizationObjectRoutes() []string {
	return []string{"cluster-types", "cluster-groups", "clusters", "virtual-disks"}
}

// ClusterOperationalStatuses is NetBox's ClusterStatusChoices.
var ClusterOperationalStatuses = []string{"planned", "staging", "active", "decommissioning", "offline"}

// clusterScopeKinds are what a cluster may be scoped to (NetBox 4.2 Cluster
// scope: region, site group, site, location).
var clusterScopeKinds = []string{"region", "site_group", "site", "location"}

// vmClassPath reports whether a class path may carry a VM's cluster and
// resources: the virtual_machine class, or a cloud compute instance (whose
// cluster is its account+region mirror).
func vmClassPath(path string) bool {
	return path == "virtual.virtual_machine" || strings.HasPrefix(path, "virtual.virtual_machine.") ||
		path == "cloud_resource.compute_instance" || strings.HasPrefix(path, "cloud_resource.compute_instance.")
}

// hostClassPath reports whether a class path may be a cluster host: a
// hypervisor, or any hardware (NetBox lets any device join a cluster).
func hostClassPath(path string) bool {
	return path == "virtual.hypervisor" || strings.HasPrefix(path, "virtual.hypervisor.") ||
		path == "hardware" || strings.HasPrefix(path, "hardware.")
}

// assetClassPath reads a live asset's class path under RLS.
func assetClassPath(ctx context.Context, tx *sql.Tx, asset any) (string, error) {
	var path string
	err := tx.QueryRowContext(ctx, `SELECT class_path FROM assets WHERE id = $1::uuid AND deleted_at IS NULL`, fmt.Sprint(asset)).Scan(&path)
	if err == sql.ErrNoRows {
		return "", ipamInvalid("no such asset %v", asset)
	}
	return path, mapIPAMError(err, false)
}

func virtualizationSpecs() []*ipamSpec {
	return []*ipamSpec{
		{
			Kind: dcim.ObjectKindClusterType, Table: "cluster_types", Route: "cluster-types", Catalogue: true,
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "slug", Type: colText},
			),
			Filters: []ipamFilter{{Param: "slug", Column: "slug", Type: colText}, {Param: "scope", Custom: scopeFilter}},
			Search:  []string{"name", "slug", "description"},
			Order:   "lower(t.name), t.id",
			Prepare: prepareSlug,
		},
		{
			Kind: dcim.ObjectKindClusterGroup, Table: "cluster_groups", Route: "cluster-groups",
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "slug", Type: colText},
				externalIDsCol,
			),
			Filters: []ipamFilter{{Param: "slug", Column: "slug", Type: colText}},
			Search:  []string{"name", "slug", "description"},
			Order:   "lower(t.name), t.id",
			Prepare: prepareSlug,
		},
		clusterSpec(),
		{
			Kind: dcim.ObjectKindVirtualDisk, Table: "virtual_disks", Route: "virtual-disks",
			Cols: withSubstrate(
				ipamCol{Name: "asset_id", Type: colUUID, Required: true},
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "size_mb", Type: colInt, Required: true},
				externalIDsCol,
			),
			Filters: []ipamFilter{{Param: "asset_id", Column: "asset_id", Type: colUUID}},
			Search:  []string{"name", "description"},
			Order:   "t.asset_id, t.name, t.id",
			Prepare: func(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
				path, err := assetClassPath(ctx, tx, row["asset_id"])
				if err != nil {
					return err
				}
				if !vmClassPath(path) {
					return ipamInvalid("a virtual disk belongs to a virtual machine (this asset is %s)", path)
				}
				return nil
			},
		},
	}
}

// clusterListSelect adds, per cluster, its type, its group and how many hosts
// and VMs it has, so the Clusters lens needs one request.
const clusterListSelect = `to_jsonb(t) || jsonb_build_object(
	'type', jsonb_build_object('id', ct.id, 'name', ct.name, 'slug', ct.slug),
	'group', CASE WHEN g.id IS NULL THEN NULL ELSE jsonb_build_object('id', g.id, 'name', g.name, 'slug', g.slug) END,
	'host_count', (SELECT count(*) FROM public.cluster_hosts h WHERE h.tenant_id = t.tenant_id AND h.cluster_id = t.id),
	'vm_count', (SELECT count(*) FROM public.assets a WHERE a.tenant_id = t.tenant_id AND a.cluster_id = t.id AND a.deleted_at IS NULL))`

func clusterSpec() *ipamSpec {
	return &ipamSpec{
		Kind: dcim.ObjectKindCluster, Table: "clusters", Route: "clusters", Lifecycle: true,
		Cols: withSubstrate(append([]ipamCol{
			{Name: "name", Type: colText, Required: true},
			{Name: "type_id", Type: colUUID, Required: true},
			{Name: "group_id", Type: colUUID},
			{Name: "operational_status", Type: colText},
			{Name: "scope_kind", Type: colText},
			{Name: "scope_id", Type: colUUID},
			{Name: "business_unit_id", Type: colUUID},
			externalIDsCol,
		}, lifecycleCols...)...),
		Filters: []ipamFilter{
			{Param: "type_id", Column: "type_id", Type: colUUID},
			{Param: "group_id", Column: "group_id", Type: colUUID},
			{Param: "status", Column: "status", Type: colText},
			{Param: "operational_status", Column: "operational_status", Type: colText},
			{Param: "business_unit_id", Column: "business_unit_id", Type: colUUID},
			{Param: "scope_kind", Column: "scope_kind", Type: colText},
			{Param: "scope_id", Column: "scope_id", Type: colUUID},
		},
		Search:     []string{"name", "description"},
		Order:      "lower(t.name), t.id",
		ListSelect: clusterListSelect,
		Join:       "JOIN public.cluster_types ct ON ct.id = t.type_id LEFT JOIN public.cluster_groups g ON g.id = t.group_id",
		Prepare: func(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
			if n, ok := row["name"].(string); ok {
				row["name"] = strings.TrimSpace(n)
			}
			if err := oneOf(row, "operational_status", ClusterOperationalStatuses); err != nil {
				return err
			}
			if row["operational_status"] == nil {
				delete(row, "operational_status") // NOT NULL with a default
			}
			if err := oneOf(row, "scope_kind", clusterScopeKinds); err != nil {
				return err
			}
			if (row["scope_kind"] == nil) != isEmpty(row["scope_id"]) {
				return ipamInvalid("scope_kind and scope_id are set together")
			}
			if err := visible(ctx, tx, "cluster_types", row["type_id"]); err != nil {
				return err
			}
			return visible(ctx, tx, "cluster_groups", row["group_id"])
		},
	}
}

// VirtualizationObjects lists every object the virtualisation engine serves,
// for the contract tests.
func VirtualizationObjects() []IPAMObjectInfo {
	var out []IPAMObjectInfo
	for _, sp := range virtualizationSpecs() {
		info := IPAMObjectInfo{Route: sp.Route, Table: sp.Table, Kind: string(sp.Kind)}
		for _, c := range sp.Cols {
			if c.Computed {
				continue
			}
			info.Writable = append(info.Writable, c.Name)
			if c.Required {
				info.Required = append(info.Required, c.Name)
			}
		}
		out = append(out, info)
	}
	return out
}
