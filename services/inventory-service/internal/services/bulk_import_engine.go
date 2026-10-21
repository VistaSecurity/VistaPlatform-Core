package services

// The engine-backed kinds of the bulk importer (bulk_import.go): IPAM and the
// device catalogue. Each is described by its CSV fields; types, required
// flags, validation and change recording come from the engine spec it names,
// so a column the spec gains is a column the guard test asks this file to
// either expose or list as Skipped.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/customfields"
	"github.com/vistasecurity/vistaplatform/shared/dcim/ipam"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// bulkField is one CSV column of an engine kind.
type bulkField struct {
	Name    string // CSV header
	Field   string // engine column; defaults to Name
	Ref     string // reference kind in bulkRefs
	Example string
	Help    string
}

func (f bulkField) field() string {
	if f.Field != "" {
		return f.Field
	}
	return f.Name
}

type bulkEngineKind struct {
	Kind   dcim.ObjectKind
	Label  string
	Plural string
	Route  string
	// DeviceCatalogue selects the device-catalogue engine (catalogue_specs.go);
	// otherwise the IPAM engine serves the route.
	DeviceCatalogue bool
	Perm            string
	Fields          []bulkField
	// Identity are the engine columns that make a row "the same object" as an
	// existing one (compared case-insensitively for text).
	Identity []string
	// Skipped are writable engine columns this kind deliberately has no CSV
	// column for, with the reason; the guard holds Fields ∪ Skipped to the
	// spec's writable columns.
	Skipped map[string]string

	spec *ipamSpec
	eng  *IPAMService
}

// bulkRefSpec resolves a reference column: SQL returns (id, label) for every
// row the tenant can see.
type bulkRefSpec struct {
	Table string
	SQL   string
}

var bulkRefs = map[string]bulkRefSpec{
	"business_unit": {Table: "business_units", SQL: `WITH RECURSIVE p AS (
		SELECT id, name::text AS path FROM public.business_units WHERE parent_id IS NULL
		UNION ALL SELECT b.id, p.path || '/' || b.name FROM public.business_units b JOIN p ON b.parent_id = p.id)
		SELECT id::text, path FROM p`},
	"rir":          {Table: "rirs", SQL: `SELECT id::text, name FROM public.rirs`},
	"vrf":          {Table: "vrfs", SQL: `SELECT id::text, name FROM public.vrfs`},
	"prefix_role":  {Table: "prefix_roles", SQL: `SELECT id::text, name FROM public.prefix_roles`},
	"manufacturer": {Table: "manufacturers", SQL: `SELECT id::text, name FROM public.manufacturers`},
	"device_role":  {Table: "device_roles", SQL: `SELECT id::text, name FROM public.device_roles`},
	"platform":     {Table: "platforms", SQL: `SELECT id::text, name FROM public.platforms`},
	"vlan_group":   {Table: "vlan_groups", SQL: `SELECT id::text, name FROM public.vlan_groups`},
	"device_type": {Table: "device_types", SQL: `SELECT dt.id::text, m.name || '/' || dt.model
		FROM public.device_types dt JOIN public.manufacturers m ON m.id = dt.manufacturer_id`},
	"vlan": {Table: "vlans", SQL: `SELECT v.id::text, COALESCE(g.name || '/', '') || v.vid::text
		FROM public.vlans v LEFT JOIN public.vlan_groups g ON g.id = v.group_id`},
}

type bulkRefIndex struct {
	byLabel map[string][]string
	byID    map[string]string
}

func loadBulkRef(ctx context.Context, tx *sql.Tx, key string) (*bulkRefIndex, error) {
	spec, ok := bulkRefs[key]
	if !ok {
		return nil, fmt.Errorf("bulk import: no reference spec %q", key)
	}
	rows, err := tx.QueryContext(ctx, spec.SQL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	idx := &bulkRefIndex{byLabel: map[string][]string{}, byID: map[string]string{}}
	for rows.Next() {
		var id, label string
		if err := rows.Scan(&id, &label); err != nil {
			return nil, err
		}
		l := strings.ToLower(label)
		idx.byLabel[l] = append(idx.byLabel[l], id)
		idx.byID[id] = label
	}
	return idx, rows.Err()
}

// bulkUnresolvedErr is a reference to a row that does not exist (yet).
type bulkUnresolvedErr struct{ msg string }

func (e *bulkUnresolvedErr) Error() string { return e.msg }

func bulkEngineKinds() []*bulkEngineKind {
	// Common skipped columns: the JSON bags have no flat CSV form, and the
	// provenance columns are set by the importer.
	return []*bulkEngineKind{
		{
			Kind: dcim.ObjectKindManufacturer, Label: "Manufacturer", Plural: "Manufacturers", Route: "manufacturers", DeviceCatalogue: true, Perm: rbac.PermissionDcimManage,
			Fields: []bulkField{
				{Name: "name", Example: "Cisco"}, {Name: "slug", Example: "cisco"}, {Name: "description", Example: "Network equipment"},
			},
			Identity: []string{"name"},
			Skipped:  map[string]string{"external_ids": "sync keys are written by sync, not by a file"},
		},
		{
			Kind: dcim.ObjectKindDeviceRole, Label: "Device role", Plural: "Device roles", Route: "device-roles", DeviceCatalogue: true, Perm: rbac.PermissionDcimManage,
			Fields: []bulkField{
				{Name: "name", Example: "Core switch"}, {Name: "slug", Example: "core-switch"}, {Name: "color", Example: "2196f3", Help: "Six hex digits."},
				{Name: "vm_role", Example: "false"}, {Name: "parent", Field: "parent_id", Ref: "device_role", Help: "Name of the parent role."},
				{Name: "description", Example: "Aggregation and core"},
			},
			Identity: []string{"name"},
			Skipped:  map[string]string{"external_ids": "sync keys are written by sync, not by a file"},
		},
		{
			Kind: dcim.ObjectKindPlatform, Label: "Platform", Plural: "Platforms", Route: "platforms", DeviceCatalogue: true, Perm: rbac.PermissionDcimManage,
			Fields: []bulkField{
				{Name: "name", Example: "IOS XE"}, {Name: "slug", Example: "ios-xe"},
				{Name: "manufacturer", Field: "manufacturer_id", Ref: "manufacturer", Example: "Cisco", Help: "Manufacturer name."},
				{Name: "description", Example: "Cisco IOS XE"},
				{Name: "end_of_sale", Example: "", Help: "YYYY-MM-DD."}, {Name: "end_of_support", Example: "", Help: "YYYY-MM-DD."},
				{Name: "end_of_life", Example: "", Help: "YYYY-MM-DD."},
			},
			Identity: []string{"name"},
			Skipped: map[string]string{
				"external_ids":     "sync keys are written by sync, not by a file",
				"eol_catalogue_id": "an end-of-life catalogue entry has no stable name to write in a file; link it in the platform form",
			},
		},
		{
			Kind: dcim.ObjectKindDeviceType, Label: "Device type", Plural: "Device types", Route: "device-types", DeviceCatalogue: true, Perm: rbac.PermissionDcimManage,
			Fields: []bulkField{
				{Name: "manufacturer", Field: "manufacturer_id", Ref: "manufacturer", Example: "Cisco", Help: "Manufacturer name."},
				{Name: "model", Example: "C9300-48P"}, {Name: "slug", Example: "c9300-48p"}, {Name: "part_number", Example: "C9300-48P-E"},
				{Name: "u_height", Example: "1"}, {Name: "is_full_depth", Example: "true"}, {Name: "exclude_from_utilization", Example: "false"},
				{Name: "subdevice_role", Example: "", Help: "parent or child."}, {Name: "airflow", Example: "front-to-rear"},
				{Name: "weight", Example: "7.3"}, {Name: "weight_unit", Example: "kg"},
				{Name: "default_platform", Field: "default_platform_id", Ref: "platform", Example: "", Help: "Platform name."},
				{Name: "description", Example: "48-port PoE+ access switch"},
				{Name: "end_of_sale", Example: "2025-10-31", Help: "YYYY-MM-DD."}, {Name: "end_of_support", Example: "2030-10-31", Help: "YYYY-MM-DD."},
				{Name: "end_of_life", Example: "", Help: "YYYY-MM-DD."},
			},
			Identity: []string{"manufacturer_id", "model"},
			Skipped: map[string]string{
				"external_ids":     "sync keys are written by sync, not by a file",
				"eol_catalogue_id": "an end-of-life catalogue entry has no stable name to write in a file; link it in the device type form",
			},
		},
		{
			Kind: dcim.ObjectKindRir, Label: "RIR", Plural: "RIRs", Route: "rirs", Perm: rbac.PermissionIpamManage,
			Fields: []bulkField{
				{Name: "name", Example: "Internal registry"}, {Name: "slug", Example: "internal-registry"},
				{Name: "is_private", Example: "true"}, {Name: "description", Example: "RFC 1918 space"},
			},
			Identity: []string{"name"},
		},
		{
			Kind: dcim.ObjectKindAggregate, Label: "Aggregate", Plural: "Aggregates", Route: "aggregates", Perm: rbac.PermissionIpamManage,
			Fields: []bulkField{
				{Name: "prefix", Example: "10.16.0.0/12"}, {Name: "rir", Field: "rir_id", Ref: "rir", Example: "Internal registry", Help: "RIR name."},
				{Name: "business_unit", Field: "business_unit_id", Ref: "business_unit", Example: "", Help: "Business unit path, Parent/Child."},
				{Name: "date_added", Example: "2026-01-31", Help: "YYYY-MM-DD."}, {Name: "description", Example: "Corporate space"},
			},
			Identity: []string{"prefix"},
			Skipped:  map[string]string{"external_ids": "sync keys are written by sync, not by a file"},
		},
		{
			Kind: dcim.ObjectKindVrf, Label: "VRF", Plural: "VRFs", Route: "vrfs", Perm: rbac.PermissionIpamManage,
			Fields: []bulkField{
				{Name: "name", Example: "blue"}, {Name: "rd", Example: "65000:1"},
				{Name: "business_unit", Field: "business_unit_id", Ref: "business_unit", Example: ""},
				{Name: "enforce_unique", Example: "true"}, {Name: "description", Example: "Blue tenant routing"},
			},
			Identity: []string{"name"},
			Skipped:  map[string]string{"external_ids": "sync keys are written by sync, not by a file"},
		},
		{
			Kind: dcim.ObjectKindVlanGroup, Label: "VLAN group", Plural: "VLAN groups", Route: "vlan-groups", Perm: rbac.PermissionIpamManage,
			Fields: []bulkField{
				{Name: "name", Example: "Campus"}, {Name: "slug", Example: "campus"},
				{Name: "vid_ranges", Example: "1-99|200-299", Help: "Allowed VIDs: low-high pairs separated by |."},
				{Name: "business_unit", Field: "business_unit_id", Ref: "business_unit", Example: ""},
				{Name: "description", Example: "Campus access VLANs"},
			},
			Identity: []string{"name"},
			Skipped: map[string]string{
				"external_ids": "sync keys are written by sync, not by a file",
				"scope_kind":   "scope columns arrive with the site kinds (rows 2.1/2.3)",
				"scope_id":     "scope columns arrive with the site kinds (rows 2.1/2.3)",
			},
		},
		{
			Kind: dcim.ObjectKindVlan, Label: "VLAN", Plural: "VLANs", Route: "vlans", Perm: rbac.PermissionIpamManage,
			Fields: []bulkField{
				{Name: "vid", Example: "100"}, {Name: "name", Example: "Users"},
				{Name: "group", Field: "group_id", Ref: "vlan_group", Example: "Campus", Help: "VLAN group name."},
				{Name: "business_unit", Field: "business_unit_id", Ref: "business_unit", Example: ""},
				{Name: "status", Example: "active"}, {Name: "operational_status", Example: ""},
				{Name: "role", Field: "role_id", Ref: "prefix_role", Example: "", Help: "Prefix role name."},
				{Name: "qinq_role", Example: ""}, {Name: "description", Example: "User access"},
			},
			Identity: []string{"group_id", "vid"},
			Skipped: map[string]string{
				"external_ids":  "sync keys are written by sync, not by a file",
				"site_id":       "site columns arrive with the site kind (row 2.1)",
				"qinq_svlan_id": "the S-VLAN reference has no stable name to write in a file",
			},
		},
		{
			Kind: dcim.ObjectKindPrefix, Label: "Prefix", Plural: "Prefixes", Route: "prefixes", Perm: rbac.PermissionIpamManage,
			Fields: []bulkField{
				{Name: "prefix", Example: "10.10.0.0/24"}, {Name: "vrf", Field: "vrf_id", Ref: "vrf", Example: "", Help: "VRF name; blank is the global table."},
				{Name: "business_unit", Field: "business_unit_id", Ref: "business_unit", Example: ""},
				{Name: "vlan", Field: "vlan_id", Ref: "vlan", Example: "Campus/100", Help: "Group/VID, or the VID of an ungrouped VLAN."},
				{Name: "role", Field: "role_id", Ref: "prefix_role", Example: ""},
				{Name: "status", Example: "active"}, {Name: "operational_status", Example: ""},
				{Name: "is_pool", Example: "false"}, {Name: "mark_utilized", Example: "false"},
				{Name: "network_type", Example: ""}, {Name: "environment", Example: ""},
				{Name: "auto_approve_discoveries", Example: "false"}, {Name: "auto_approve_sources", Example: "", Help: "Source kinds separated by |."},
				{Name: "dhcp_managed", Example: "false"}, {Name: "active_probes_disabled", Example: "false"}, {Name: "sensitive", Example: "false"},
				{Name: "gateway_source_ref", Example: ""}, {Name: "cloud_network_ref", Example: ""},
				{Name: "description", Example: "User access"},
			},
			Identity: []string{"vrf_id", "prefix"},
			Skipped: map[string]string{
				"external_ids":     "sync keys are written by sync, not by a file",
				"scope_kind":       "scope columns arrive with the site kinds (rows 2.1/2.3)",
				"scope_id":         "scope columns arrive with the site kinds (rows 2.1/2.3)",
				"gateway_ip_id":    "an address reference has no stable name to write in a file",
				"gateway_asset_id": "an asset reference is set from the asset, not the prefix file",
			},
		},
		{
			Kind: dcim.ObjectKindIpRange, Label: "IP range", Plural: "IP ranges", Route: "ip-ranges", Perm: rbac.PermissionIpamManage,
			Fields: []bulkField{
				{Name: "start_address", Example: "10.10.0.10/24"}, {Name: "end_address", Example: "10.10.0.50/24"},
				{Name: "vrf", Field: "vrf_id", Ref: "vrf", Example: ""},
				{Name: "business_unit", Field: "business_unit_id", Ref: "business_unit", Example: ""},
				{Name: "operational_status", Example: ""}, {Name: "role", Field: "role_id", Ref: "prefix_role", Example: ""},
				{Name: "mark_utilized", Example: "false"}, {Name: "description", Example: "DHCP pool"},
			},
			Identity: []string{"vrf_id", "start_address"},
			Skipped:  map[string]string{"external_ids": "sync keys are written by sync, not by a file"},
		},
		{
			Kind: dcim.ObjectKindIpAddress, Label: "IP address", Plural: "IP addresses", Route: "ip-addresses", Perm: rbac.PermissionIpamManage,
			Fields: []bulkField{
				{Name: "address", Example: "10.10.0.1/24"}, {Name: "vrf", Field: "vrf_id", Ref: "vrf", Example: ""},
				{Name: "business_unit", Field: "business_unit_id", Ref: "business_unit", Example: ""},
				{Name: "status", Example: "active"}, {Name: "operational_status", Example: ""},
				{Name: "role", Example: "", Help: "loopback, secondary, anycast, vip, vrrp, hsrp, glbp or carp."},
				{Name: "dns_name", Example: "gw.example.test"}, {Name: "mac_address", Example: ""},
				{Name: "last_seen_source", Example: ""}, {Name: "description", Example: "Default gateway"},
			},
			Identity: []string{"vrf_id", "address"},
			Skipped: map[string]string{
				"external_ids":  "sync keys are written by sync, not by a file",
				"assigned_kind": "assignment is made from the interface or asset, not the address file",
				"assigned_id":   "assignment is made from the interface or asset, not the address file",
				"nat_inside_id": "an address reference has no stable name to write in a file",
			},
		},
	}
}

// substrateSkipped are the engine columns every kind leaves to the importer.
var substrateSkipped = map[string]bool{"comments": true, "custom_fields": true, "source_kind": true, "source_ref": true}

func (k *bulkEngineKind) info() BulkKindInfo {
	info := BulkKindInfo{Kind: string(k.Kind), Label: k.Label, Plural: k.Plural, Permission: k.Perm}
	for _, f := range k.Fields {
		col, _ := k.spec.col(f.field())
		info.Columns = append(info.Columns, BulkColumn{Name: f.Name, Required: col.Required, Ref: f.Ref, Example: f.Example, Help: f.Help})
	}
	return info
}

// ---- running ---------------------------------------------------------------

var errBulkDryRun = errors.New("dry run: roll back")

type bulkEngineRun struct {
	k      *bulkEngineKind
	tenant uuid.UUID
	refs   map[string]*bulkRefIndex
	// cf are the tenant's custom field definitions for the kind, read on the
	// run's first transaction (DCIM row 5.1: the `cf.<name>` columns).
	cf map[string]customfields.Definition
}

// customFields reads the `cf.<name>` cells of rec into a custom_fields patch
// (nil when the row names none). A blank cell leaves the field alone; "-"
// clears it.
func (r *bulkEngineRun) customFields(ctx context.Context, tx *sql.Tx, rec BulkRecord) (map[string]any, error) {
	var out map[string]any
	for col, cell := range rec {
		name, ok := strings.CutPrefix(col, customfields.ColumnPrefix)
		if !ok || strings.TrimSpace(cell) == "" {
			continue
		}
		if r.cf == nil {
			defs, err := customfields.Load(ctx, tx, r.k.Kind)
			if err != nil {
				return nil, err
			}
			r.cf = customfields.ByName(defs)
		}
		d, known := r.cf[name]
		if !known {
			return nil, fmt.Errorf("%s: no custom field %q applies to %s", col, name, r.k.Plural)
		}
		if out == nil {
			out = map[string]any{}
		}
		if strings.TrimSpace(cell) == "-" {
			out[name] = nil
			continue
		}
		v, err := customfields.ParseCell(d, cell)
		if err != nil {
			return nil, err
		}
		out[name] = v
	}
	return out, nil
}

func (r *bulkEngineRun) ref(ctx context.Context, tx *sql.Tx, key string) (*bulkRefIndex, error) {
	if idx, ok := r.refs[key]; ok {
		return idx, nil
	}
	idx, err := loadBulkRef(ctx, tx, key)
	if err != nil {
		return nil, err
	}
	r.refs[key] = idx
	return idx, nil
}

func (r *bulkEngineRun) invalidate(table string) {
	for key, spec := range bulkRefs {
		if spec.Table == table {
			delete(r.refs, key)
		}
	}
}

// run plans or applies recs. A dry run executes every row in one transaction
// and rolls it back; an apply commits in chunks of bulkChunkRows.
func (k *bulkEngineKind) run(ctx context.Context, db *sql.DB, tenant uuid.UUID, recs []BulkRecord, dryRun bool) ([]BulkRowResult, error) {
	r := &bulkEngineRun{k: k, tenant: tenant, refs: map[string]*bulkRefIndex{}}
	results := make([]BulkRowResult, len(recs))
	pending := make([]int, len(recs))
	for i := range recs {
		pending[i] = i
	}
	doPass := func(tx *sql.Tx, idxs []int, last bool) (retry []int) {
		for _, i := range idxs {
			res := r.row(ctx, tx, recs[i])
			results[i] = res
			if res.unresolved && !last {
				retry = append(retry, i)
			}
		}
		return retry
	}
	passes := func(each func(idxs []int, last bool) ([]int, error)) error {
		for pass := 0; pass < bulkMaxPasses && len(pending) > 0; pass++ {
			retry, err := each(pending, pass == bulkMaxPasses-1)
			if err != nil {
				return err
			}
			if len(retry) == len(pending) {
				return nil // no progress: the unresolved rows stay errors
			}
			pending = retry
		}
		return nil
	}
	if dryRun {
		err := database.WithTenantTx(ctx, db, tenant, func(tx *sql.Tx) error {
			if err := passes(func(idxs []int, last bool) ([]int, error) { return doPass(tx, idxs, last), nil }); err != nil {
				return err
			}
			return errBulkDryRun
		})
		if err != nil && !errors.Is(err, errBulkDryRun) {
			return nil, err
		}
		return results, nil
	}
	err := passes(func(idxs []int, last bool) ([]int, error) {
		var retry []int
		for off := 0; off < len(idxs); off += bulkChunkRows {
			end := off + bulkChunkRows
			if end > len(idxs) {
				end = len(idxs)
			}
			chunk := idxs[off:end]
			err := database.WithTenantTx(ctx, db, tenant, func(tx *sql.Tx) error {
				retry = append(retry, doPass(tx, chunk, last)...)
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
		return retry, nil
	})
	return results, err
}

func bulkReason(err error) string {
	var pe *pq.Error
	if errors.As(err, &pe) {
		err = mapIPAMError(err, false)
	}
	msg := err.Error()
	for _, p := range []string{"invalid: ", "conflict: "} {
		msg = strings.TrimPrefix(msg, p)
	}
	return msg
}

// row plans or applies one record inside tx. Every write is under a
// savepoint, so one bad row leaves its neighbours (and the chunk) intact.
func (r *bulkEngineRun) row(ctx context.Context, tx *sql.Tx, rec BulkRecord) BulkRowResult {
	k := r.k
	patch := map[string]any{}
	ident := map[string]any{}
	isIdent := map[string]bool{}
	for _, f := range k.Identity {
		isIdent[f] = true
		ident[f] = nil
	}
	var keyParts []string
	for _, f := range k.Fields {
		cell := strings.TrimSpace(rec[f.Name])
		if cell == "" {
			continue
		}
		col, _ := k.spec.col(f.field())
		if isIdent[f.field()] {
			keyParts = append(keyParts, cell)
		}
		if cell == "-" {
			patch[f.field()] = nil
			continue
		}
		v, err := r.convert(ctx, tx, f, col, cell)
		if err != nil {
			var ue *bulkUnresolvedErr
			return BulkRowResult{Action: BulkError, Key: strings.Join(keyParts, " "), Reason: bulkReason(err), unresolved: errors.As(err, &ue)}
		}
		patch[f.field()] = v
		if isIdent[f.field()] {
			ident[f.field()] = v
		}
	}
	key := strings.Join(keyParts, " ")
	fail := func(err error) BulkRowResult {
		return BulkRowResult{Action: BulkError, Key: key, Reason: bulkReason(err)}
	}
	if _, ok := k.spec.col("custom_fields"); ok {
		cf, err := r.customFields(ctx, tx, rec)
		if err != nil {
			return fail(err)
		}
		if cf != nil {
			patch["custom_fields"] = cf
		}
	}
	for _, f := range k.Identity {
		col, _ := k.spec.col(f)
		if col.Required && ident[f] == nil {
			return fail(fmt.Errorf("%s is required", k.csvName(f)))
		}
	}

	var res BulkRowResult
	if err := r.guarded(ctx, tx, func() error {
		res = r.write(ctx, tx, key, patch, ident)
		if res.Action == BulkError {
			return errors.New(res.Reason)
		}
		return nil
	}); err != nil && res.Action != BulkError {
		return fail(err)
	}
	return res
}

// write finds the existing row and creates, updates or leaves it. It runs
// under the row's savepoint.
func (r *bulkEngineRun) write(ctx context.Context, tx *sql.Tx, key string, patch, ident map[string]any) BulkRowResult {
	k := r.k
	fail := func(err error) BulkRowResult {
		return BulkRowResult{Action: BulkError, Key: key, Reason: bulkReason(err)}
	}
	id, found, err := r.find(ctx, tx, ident)
	if err != nil {
		return fail(err)
	}
	if !found {
		patch["source_kind"] = "imported"
		patch["source_ref"] = bulkSourceRef
		post, err := k.eng.createTx(ctx, tx, k.spec, r.tenant, patch, BulkChangeSource)
		if err != nil {
			return fail(err)
		}
		r.invalidate(k.spec.Table)
		return BulkRowResult{Action: BulkCreate, Key: key, ID: fmt.Sprint(post["id"])}
	}

	pre, err := getRow(ctx, tx, k.spec, id, false)
	if err != nil {
		return fail(err)
	}
	var changed []string
	for f, v := range patch {
		col, _ := k.spec.col(f)
		if f == "custom_fields" {
			// The file names some fields; the engine merges them over the
			// stored ones. Changed means a named field's value differs.
			stored, _ := pre[f].(map[string]any)
			named, _ := v.(map[string]any)
			var moved []string
			for name, nv := range named {
				if bulkCustomFieldCanon(stored[name]) != bulkCustomFieldCanon(nv) {
					moved = append(moved, customfields.ColumnPrefix+name)
				}
			}
			if len(moved) == 0 {
				delete(patch, f)
				continue
			}
			changed = append(changed, moved...)
			continue
		}
		if bulkCanon(col, pre[f]) == bulkCanon(col, v) {
			delete(patch, f)
			continue
		}
		changed = append(changed, f)
	}
	sort.Strings(changed)
	if len(patch) == 0 {
		return BulkRowResult{Action: BulkUnchanged, Key: key, ID: id.String()}
	}
	if _, err := k.eng.updateTx(ctx, tx, k.spec, r.tenant, id, patch, BulkChangeSource); err != nil {
		return fail(err)
	}
	r.invalidate(k.spec.Table)
	for i, f := range changed {
		changed[i] = k.csvName(f)
	}
	return BulkRowResult{Action: BulkUpdate, Key: key, ID: id.String(), Changed: changed}
}

func (k *bulkEngineKind) csvName(field string) string {
	for _, f := range k.Fields {
		if f.field() == field {
			return f.Name
		}
	}
	return field
}

// guarded runs fn under a savepoint: on error the savepoint is rolled back,
// so the failed row leaves no trace in the transaction.
func (r *bulkEngineRun) guarded(ctx context.Context, tx *sql.Tx, fn func() error) error {
	if _, err := tx.ExecContext(ctx, "SAVEPOINT bulk_row"); err != nil {
		return err
	}
	if err := fn(); err != nil {
		if _, rerr := tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT bulk_row"); rerr != nil {
			return rerr
		}
		return err
	}
	_, err := tx.ExecContext(ctx, "RELEASE SAVEPOINT bulk_row")
	return err
}

// find returns the existing row with the identity's natural key.
func (r *bulkEngineRun) find(ctx context.Context, tx *sql.Tx, ident map[string]any) (uuid.UUID, bool, error) {
	k := r.k
	conds := []string{"t.tenant_id = $1"}
	if k.spec.Catalogue {
		conds[0] = "(t.tenant_id = $1 OR t.tenant_id IS NULL)"
	}
	args := []any{r.tenant}
	for _, f := range k.Identity {
		col, _ := k.spec.col(f)
		q := "t." + pq.QuoteIdentifier(f)
		v := ident[f]
		if v == nil {
			conds = append(conds, q+" IS NULL")
			continue
		}
		p, err := sqlParam(col, v)
		if err != nil {
			return uuid.Nil, false, err
		}
		args = append(args, p)
		if col.Type == colText {
			conds = append(conds, fmt.Sprintf("lower(%s) = lower($%d)", q, len(args)))
		} else {
			conds = append(conds, fmt.Sprintf("%s = $%d::%s", q, len(args), col.Type.cast()))
		}
	}
	rows, err := tx.QueryContext(ctx, fmt.Sprintf(`SELECT t.id, t.tenant_id IS NULL FROM public.%s t WHERE %s ORDER BY (t.tenant_id IS NULL), t.id`,
		pq.QuoteIdentifier(k.spec.Table), strings.Join(conds, " AND ")), args...)
	if err != nil {
		return uuid.Nil, false, mapIPAMError(err, false)
	}
	defer func() { _ = rows.Close() }()
	var ids []uuid.UUID
	var platform []bool
	for rows.Next() {
		var id uuid.UUID
		var plat bool
		if err := rows.Scan(&id, &plat); err != nil {
			return uuid.Nil, false, err
		}
		ids = append(ids, id)
		platform = append(platform, plat)
	}
	if err := rows.Err(); err != nil {
		return uuid.Nil, false, err
	}
	switch {
	case len(ids) == 0:
		return uuid.Nil, false, nil
	case len(ids) == 1 || (platform[1] && !platform[0]):
		return ids[0], true, nil
	}
	return uuid.Nil, false, fmt.Errorf("%d existing rows match this row's key; resolve the duplicates first", len(ids))
}

// convert turns a cell into the engine's API-shape value.
func (r *bulkEngineRun) convert(ctx context.Context, tx *sql.Tx, f bulkField, col ipamCol, cell string) (any, error) {
	if f.Ref != "" {
		idx, err := r.ref(ctx, tx, f.Ref)
		if err != nil {
			return nil, err
		}
		ids := idx.byLabel[strings.ToLower(cell)]
		switch len(ids) {
		case 0:
			return nil, &bulkUnresolvedErr{msg: fmt.Sprintf("%s: no %s named %q", f.Name, strings.ReplaceAll(f.Ref, "_", " "), cell)}
		case 1:
			return ids[0], nil
		}
		return nil, fmt.Errorf("%s: %q names %d %ss; make it unambiguous", f.Name, cell, len(ids), strings.ReplaceAll(f.Ref, "_", " "))
	}
	return bulkParseCell(f.Name, col, cell)
}

func bulkParseCell(name string, col ipamCol, cell string) (any, error) {
	switch col.Type {
	case colBool:
		switch strings.ToLower(cell) {
		case "true", "yes", "y", "1":
			return true, nil
		case "false", "no", "n", "0":
			return false, nil
		}
		return nil, fmt.Errorf("%s: %q is not true or false", name, cell)
	case colInt, colBigint:
		n, err := strconv.ParseInt(cell, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not a whole number", name, cell)
		}
		return n, nil
	case colNumeric:
		if _, err := strconv.ParseFloat(cell, 64); err != nil {
			return nil, fmt.Errorf("%s: %q is not a number", name, cell)
		}
		return json.Number(cell), nil
	case colDate:
		if _, err := time.Parse("2006-01-02", cell); err != nil {
			return nil, fmt.Errorf("%s: %q is not a date (YYYY-MM-DD)", name, cell)
		}
		return cell, nil
	case colCidr:
		p, err := ipam.ParsePrefix(cell)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", name, err)
		}
		return p.String(), nil
	case colTextArray:
		var out []any
		for _, p := range strings.Split(cell, "|") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out, nil
	case colVidRanges:
		var out [][2]int
		for _, p := range strings.Split(cell, "|") {
			lo, hi, ok := strings.Cut(strings.TrimSpace(p), "-")
			a, e1 := strconv.Atoi(strings.TrimSpace(lo))
			b, e2 := strconv.Atoi(strings.TrimSpace(hi))
			if !ok || e1 != nil || e2 != nil {
				return nil, fmt.Errorf("%s: %q is not low-high pairs separated by |", name, cell)
			}
			out = append(out, [2]int{a, b})
		}
		return out, nil
	case colUUID:
		if _, err := uuid.Parse(cell); err != nil {
			return nil, fmt.Errorf("%s: %q is not a reference this file can resolve", name, cell)
		}
		return cell, nil
	case colJSON:
		return nil, fmt.Errorf("%s: JSON columns are not importable", name)
	}
	return cell, nil
}

// bulkCanon renders a value (API shape, patch value or stored) in one form so
// "the file says what is already there" is a string comparison.
func bulkCanon(col ipamCol, v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case bool:
		return strconv.FormatBool(x)
	case json.Number:
		return bulkCanonNumber(x.String())
	case int:
		return bulkCanonNumber(strconv.Itoa(x))
	case int64:
		return bulkCanonNumber(strconv.FormatInt(x, 10))
	case float64:
		return bulkCanonNumber(strconv.FormatFloat(x, 'f', -1, 64))
	case string:
		switch col.Type {
		case colNumeric, colInt, colBigint:
			return bulkCanonNumber(x)
		case colMAC:
			return strings.ToLower(x)
		}
		return x
	case [][2]int:
		parts := make([]string, len(x))
		for i, p := range x {
			parts[i] = fmt.Sprintf("%d-%d", p[0], p[1])
		}
		return strings.Join(parts, "|")
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			if pair, ok := e.([]any); ok && col.Type == colVidRanges && len(pair) == 2 {
				parts[i] = fmt.Sprintf("%v-%v", pair[0], pair[1])
				continue
			}
			parts[i] = fmt.Sprint(e)
		}
		return strings.Join(parts, "|")
	}
	return fmt.Sprint(v)
}

// bulkCustomFieldCanon renders a custom field value in one form for the
// "unchanged" comparison: numbers by value, lists joined, nil as blank.
func bulkCustomFieldCanon(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case json.Number:
		return bulkCanonNumber(x.String())
	case int64:
		return bulkCanonNumber(strconv.FormatInt(x, 10))
	case float64:
		return bulkCanonNumber(strconv.FormatFloat(x, 'f', -1, 64))
	case string:
		return x
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func bulkCanonNumber(s string) string {
	r, ok := new(big.Rat).SetString(strings.TrimSpace(s))
	if !ok {
		return s
	}
	return r.FloatString(6)
}

// ---- export ----------------------------------------------------------------

func (k *bulkEngineKind) export(ctx context.Context, db *sql.DB, tenant uuid.UUID, q BulkExportQuery, emit func(BulkRecord) error) error {
	refs := map[string]*bulkRefIndex{}
	var cfDefs []customfields.Definition
	err := database.WithTenantTx(ctx, db, tenant, func(tx *sql.Tx) error {
		if _, ok := k.spec.col("custom_fields"); ok {
			var err error
			if cfDefs, err = customfields.Load(ctx, tx, k.Kind); err != nil {
				return err
			}
		}
		for _, f := range k.Fields {
			if f.Ref == "" || refs[f.Ref] != nil {
				continue
			}
			idx, err := loadBulkRef(ctx, tx, f.Ref)
			if err != nil {
				return err
			}
			refs[f.Ref] = idx
		}
		return nil
	})
	if err != nil {
		return err
	}
	const page = 1000
	for off := 0; ; off += page {
		items, total, err := k.eng.List(ctx, tenant, k.Route, IPAMListParams{Filters: q.Filters, Q: q.Q, Limit: page, Offset: off})
		if err != nil {
			return err
		}
		for _, raw := range items {
			dec := json.NewDecoder(strings.NewReader(string(raw)))
			dec.UseNumber()
			var row map[string]any
			if err := dec.Decode(&row); err != nil {
				return err
			}
			rec := BulkRecord{}
			for _, f := range k.Fields {
				col, _ := k.spec.col(f.field())
				rec[f.Name] = bulkFormat(col, f, row[f.field()], refs)
			}
			stored, _ := row["custom_fields"].(map[string]any)
			for _, d := range cfDefs {
				rec[customfields.ColumnPrefix+d.Name] = customfields.FormatCell(d, stored[d.Name])
			}
			if err := emit(rec); err != nil {
				return err
			}
		}
		if off+page >= total || len(items) == 0 {
			return nil
		}
	}
}

func bulkFormat(col ipamCol, f bulkField, v any, refs map[string]*bulkRefIndex) string {
	if v == nil {
		return ""
	}
	if f.Ref != "" {
		id := fmt.Sprint(v)
		if idx := refs[f.Ref]; idx != nil {
			if label, ok := idx.byID[id]; ok {
				return label
			}
		}
		return id
	}
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	}
	return bulkCanon(col, v)
}
