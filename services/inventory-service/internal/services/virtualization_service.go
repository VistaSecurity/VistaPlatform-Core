package services

// VirtualizationService owns virtualisation (DCIM BUILD_PLAN row 4.2;
// ADR-0010 D8; DATA_MODEL §7): cluster types, cluster groups, clusters and
// virtual disks on the IPAM object engine (one tenant-scoped transaction per
// call, RLS in force, every write recorded in object_changes, platform cluster
// types refused with ErrIPAMReadOnly), plus the two memberships that are not
// rows of their own: a hypervisor's cluster (cluster_hosts) and a virtual
// machine's cluster and resources (assets.cluster_id / vcpus / memory_mb /
// disk_mb).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"

	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
)

// VirtualizationService is the virtualisation store.
type VirtualizationService struct {
	db  *sql.DB
	eng *IPAMService
}

// NewVirtualizationService returns the store over db (the raw pool; RLS is set
// per transaction).
func NewVirtualizationService(db *sql.DB) *VirtualizationService {
	return &VirtualizationService{db: db, eng: newObjectEngine(db, virtualizationSpecs())}
}

func isVirtualizationObject(route string) error {
	for _, r := range VirtualizationObjectRoutes() {
		if r == route {
			return nil
		}
	}
	return fmt.Errorf("%w: unknown virtualization object %q", ErrIPAMNotFound, route)
}

// List returns one page of a virtualisation object.
func (s *VirtualizationService) List(ctx context.Context, tenant uuid.UUID, route string, p IPAMListParams) ([]json.RawMessage, int, error) {
	if err := isVirtualizationObject(route); err != nil {
		return nil, 0, err
	}
	return s.eng.List(ctx, tenant, route, p)
}

// Get returns one object.
func (s *VirtualizationService) Get(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) (json.RawMessage, error) {
	if err := isVirtualizationObject(route); err != nil {
		return nil, err
	}
	return s.eng.Get(ctx, tenant, route, id)
}

// Create creates a tenant object.
func (s *VirtualizationService) Create(ctx context.Context, tenant uuid.UUID, route string, body []byte) (json.RawMessage, error) {
	if err := isVirtualizationObject(route); err != nil {
		return nil, err
	}
	return s.eng.Create(ctx, tenant, route, body)
}

// Update patches an object (a platform cluster type answers ErrIPAMReadOnly).
func (s *VirtualizationService) Update(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID, body []byte) (json.RawMessage, error) {
	if err := isVirtualizationObject(route); err != nil {
		return nil, err
	}
	return s.eng.Update(ctx, tenant, route, id, body)
}

// Delete removes an object. A cluster type a cluster uses answers ErrIPAMInUse
// (NetBox PROTECT); deleting a cluster clears its VMs' cluster and drops its
// host memberships.
func (s *VirtualizationService) Delete(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) error {
	if err := isVirtualizationObject(route); err != nil {
		return err
	}
	return s.eng.Delete(ctx, tenant, route, id)
}

// ErrVirtualizationAssetNotFound is an asset the tenant does not have.
var ErrVirtualizationAssetNotFound = fmt.Errorf("%w: no such asset", ErrIPAMNotFound)

// ClusterRef names a cluster on a host or VM card.
type ClusterRef struct {
	ID       uuid.UUID `json:"id"`
	Name     string    `json:"name"`
	TypeName string    `json:"type_name"`
	TypeSlug string    `json:"type_slug"`
}

// ClusterMember is one host or VM of a cluster.
type ClusterMember struct {
	AssetID     uuid.UUID `json:"asset_id"`
	DisplayName *string   `json:"display_name"`
	Hostname    *string   `json:"hostname"`
	ClassKey    string    `json:"class_key"`
	AssetStatus string    `json:"asset_status"`
	// Hosts only.
	SourceKind *string `json:"source_kind,omitempty"`
	// VMs only.
	VCPUs            *float64 `json:"vcpus,omitempty"`
	MemoryMB         *int64   `json:"memory_mb,omitempty"`
	DiskMB           *int64   `json:"disk_mb,omitempty"`
	VirtualDiskCount *int     `json:"virtual_disk_count,omitempty"`
}

// clusterExists answers ErrIPAMNotFound for a cluster the tenant cannot see.
func clusterExists(ctx context.Context, tx *sql.Tx, cluster uuid.UUID) error {
	var ok bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM clusters WHERE id = $1)`, cluster).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return ErrIPAMNotFound
	}
	return nil
}

// ClusterHosts lists a cluster's hosts.
func (s *VirtualizationService) ClusterHosts(ctx context.Context, tenant, cluster uuid.UUID) ([]ClusterMember, error) {
	out := []ClusterMember{}
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		if err := clusterExists(ctx, tx, cluster); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `
			SELECT a.id, a.display_name, a.hostname, a.class_key, a.asset_status, h.source_kind
			  FROM cluster_hosts h JOIN assets a ON a.tenant_id = h.tenant_id AND a.id = h.asset_id
			 WHERE h.tenant_id = $1 AND h.cluster_id = $2 AND a.deleted_at IS NULL
			 ORDER BY lower(COALESCE(a.display_name, a.hostname, '')), a.id`, tenant, cluster)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var m ClusterMember
			var dn, hn, sk sql.NullString
			if err := rows.Scan(&m.AssetID, &dn, &hn, &m.ClassKey, &m.AssetStatus, &sk); err != nil {
				return err
			}
			m.DisplayName, m.Hostname, m.SourceKind = ifaceStrPtr(dn), ifaceStrPtr(hn), ifaceStrPtr(sk)
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, mapIPAMError(err, false)
}

// ClusterVMs lists a cluster's virtual machines with their resources.
func (s *VirtualizationService) ClusterVMs(ctx context.Context, tenant, cluster uuid.UUID) ([]ClusterMember, error) {
	out := []ClusterMember{}
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		if err := clusterExists(ctx, tx, cluster); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `
			SELECT a.id, a.display_name, a.hostname, a.class_key, a.asset_status,
			       a.vcpus::float8, a.memory_mb, a.disk_mb,
			       (SELECT count(*) FROM virtual_disks d WHERE d.tenant_id = a.tenant_id AND d.asset_id = a.id)
			  FROM assets a
			 WHERE a.tenant_id = $1 AND a.cluster_id = $2 AND a.deleted_at IS NULL
			 ORDER BY lower(COALESCE(a.display_name, a.hostname, '')), a.id`, tenant, cluster)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var m ClusterMember
			var dn, hn sql.NullString
			var cpus sql.NullFloat64
			var mem, disk sql.NullInt64
			var n int
			if err := rows.Scan(&m.AssetID, &dn, &hn, &m.ClassKey, &m.AssetStatus, &cpus, &mem, &disk, &n); err != nil {
				return err
			}
			m.DisplayName, m.Hostname = ifaceStrPtr(dn), ifaceStrPtr(hn)
			if cpus.Valid {
				v := cpus.Float64
				m.VCPUs = &v
			}
			m.MemoryMB, m.DiskMB = nullInt(mem), nullInt(disk)
			m.VirtualDiskCount = &n
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, mapIPAMError(err, false)
}

func nullInt(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	n := v.Int64
	return &n
}

// hostIDs reads a cluster's host asset ids, sorted (the change images).
func hostIDs(ctx context.Context, tx *sql.Tx, cluster uuid.UUID) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT asset_id::text FROM cluster_hosts WHERE cluster_id = $1`, cluster)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	sort.Strings(out)
	return out, rows.Err()
}

// AddClusterHost makes asset a host of cluster (a hypervisor or any hardware).
// A host is in one cluster (NetBox Device.cluster): adding it to a second one
// moves it. Recorded as a change to the cluster's host list.
func (s *VirtualizationService) AddClusterHost(ctx context.Context, tenant, cluster, asset uuid.UUID) ([]ClusterMember, error) {
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT 1 FROM clusters WHERE id = $1 FOR UPDATE`, cluster); err != nil {
			return err
		}
		if err := clusterExists(ctx, tx, cluster); err != nil {
			return err
		}
		path, err := assetClassPath(ctx, tx, asset)
		if err != nil {
			return err
		}
		if !hostClassPath(path) {
			return ipamInvalid("a cluster host is a hypervisor or a hardware device (this asset is %s)", path)
		}
		var prior uuid.NullUUID
		if err := tx.QueryRowContext(ctx, `SELECT cluster_id FROM cluster_hosts WHERE tenant_id = $1 AND asset_id = $2`, tenant, asset).Scan(&prior); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if prior.Valid && prior.UUID == cluster {
			return nil
		}
		if prior.Valid {
			if err := setHost(ctx, tx, tenant, prior.UUID, asset, false, ""); err != nil {
				return err
			}
		}
		return setHost(ctx, tx, tenant, cluster, asset, true, "")
	})
	if err != nil {
		return nil, mapIPAMError(err, false)
	}
	return s.ClusterHosts(ctx, tenant, cluster)
}

// RemoveClusterHost removes asset from cluster's hosts.
func (s *VirtualizationService) RemoveClusterHost(ctx context.Context, tenant, cluster, asset uuid.UUID) error {
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		if err := clusterExists(ctx, tx, cluster); err != nil {
			return err
		}
		var ok bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM cluster_hosts WHERE tenant_id = $1 AND cluster_id = $2 AND asset_id = $3)`, tenant, cluster, asset).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return ErrIPAMNotFound
		}
		return setHost(ctx, tx, tenant, cluster, asset, false, "")
	})
	return mapIPAMError(err, true)
}

// setHost adds or removes one host row and records the cluster's host list
// before and after. source "" is the request's; intake passes its own.
func setHost(ctx context.Context, tx *sql.Tx, tenant, cluster, asset uuid.UUID, add bool, source changes.Source) error {
	pre, err := hostIDs(ctx, tx, cluster)
	if err != nil {
		return err
	}
	sourceKind := "declared"
	if source != "" {
		sourceKind = "measured"
	}
	if add {
		_, err = tx.ExecContext(ctx, `INSERT INTO cluster_hosts (tenant_id, cluster_id, asset_id, source_kind) VALUES ($1, $2, $3, $4)`, tenant, cluster, asset, sourceKind)
	} else {
		_, err = tx.ExecContext(ctx, `DELETE FROM cluster_hosts WHERE tenant_id = $1 AND cluster_id = $2 AND asset_id = $3`, tenant, cluster, asset)
	}
	if err != nil {
		return err
	}
	post, err := hostIDs(ctx, tx, cluster)
	if err != nil {
		return err
	}
	return changes.InTx(tx).Record(ctx, changes.Change{
		TenantID: tenant, Kind: dcim.ObjectKindCluster, ID: cluster, Action: changes.ActionUpdate,
		Pre: map[string]any{"host_asset_ids": pre}, Post: map[string]any{"host_asset_ids": post}, Source: source,
	})
}

// AssetVirtualization is an asset's virtualisation card: for a VM its cluster,
// resources and virtual disks; for a host the cluster it is in and the VMs
// recorded as running on it (hosted_on / virtualized_by edges).
type AssetVirtualization struct {
	AssetID   uuid.UUID `json:"asset_id"`
	ClassKey  string    `json:"class_key"`
	ClassPath string    `json:"class_path"`
	// IsVM / IsHost say which card the asset gets.
	IsVM   bool `json:"is_vm"`
	IsHost bool `json:"is_host"`
	// The VM half.
	Cluster      *ClusterRef       `json:"cluster"`
	VCPUs        *float64          `json:"vcpus"`
	MemoryMB     *int64            `json:"memory_mb"`
	DiskMB       *int64            `json:"disk_mb"`
	VirtualDisks []json.RawMessage `json:"virtual_disks"`
	// The host half.
	HostCluster *ClusterRef     `json:"host_cluster"`
	HostedVMs   []ClusterMember `json:"hosted_vms"`
}

// AssetVirtualization reads an asset's card.
func (s *VirtualizationService) AssetVirtualization(ctx context.Context, tenant, asset uuid.UUID) (*AssetVirtualization, error) {
	var out *AssetVirtualization
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		var err error
		out, err = assetVirtualizationTx(ctx, tx, tenant, asset)
		return err
	})
	return out, mapIPAMError(err, false)
}

func clusterRef(ctx context.Context, tx *sql.Tx, id uuid.UUID) (*ClusterRef, error) {
	r := &ClusterRef{ID: id}
	err := tx.QueryRowContext(ctx, `SELECT c.name, ct.name, ct.slug FROM clusters c JOIN cluster_types ct ON ct.id = c.type_id WHERE c.id = $1`, id).
		Scan(&r.Name, &r.TypeName, &r.TypeSlug)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return r, err
}

func assetVirtualizationTx(ctx context.Context, tx *sql.Tx, tenant, asset uuid.UUID) (*AssetVirtualization, error) {
	v := &AssetVirtualization{AssetID: asset, VirtualDisks: []json.RawMessage{}, HostedVMs: []ClusterMember{}}
	var cluster uuid.NullUUID
	var cpus sql.NullFloat64
	var mem, disk sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT class_key, class_path, cluster_id, vcpus::float8, memory_mb, disk_mb
		FROM assets WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`, tenant, asset).
		Scan(&v.ClassKey, &v.ClassPath, &cluster, &cpus, &mem, &disk)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrVirtualizationAssetNotFound
	}
	if err != nil {
		return nil, err
	}
	v.IsVM, v.IsHost = vmClassPath(v.ClassPath), strings.HasPrefix(v.ClassPath, "virtual.hypervisor")
	if cluster.Valid {
		if v.Cluster, err = clusterRef(ctx, tx, cluster.UUID); err != nil {
			return nil, err
		}
	}
	if cpus.Valid {
		c := cpus.Float64
		v.VCPUs = &c
	}
	v.MemoryMB, v.DiskMB = nullInt(mem), nullInt(disk)
	rows, err := tx.QueryContext(ctx, `SELECT to_jsonb(d) FROM virtual_disks d WHERE d.tenant_id = $1 AND d.asset_id = $2 ORDER BY d.name, d.id`, tenant, asset)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			_ = rows.Close()
			return nil, err
		}
		v.VirtualDisks = append(v.VirtualDisks, raw)
	}
	_ = rows.Close()
	var hc uuid.NullUUID
	if err := tx.QueryRowContext(ctx, `SELECT cluster_id FROM cluster_hosts WHERE tenant_id = $1 AND asset_id = $2`, tenant, asset).Scan(&hc); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if hc.Valid {
		v.IsHost = true
		if v.HostCluster, err = clusterRef(ctx, tx, hc.UUID); err != nil {
			return nil, err
		}
	}
	if v.IsHost {
		vms, err := tx.QueryContext(ctx, `
			SELECT DISTINCT a.id, a.display_name, a.hostname, a.class_key, a.asset_status, a.vcpus::float8, a.memory_mb, a.disk_mb,
			       lower(COALESCE(a.display_name, a.hostname, ''))
			  FROM asset_relationships r JOIN assets a ON a.tenant_id = r.tenant_id AND a.id = r.from_asset_id
			 WHERE r.tenant_id = $1 AND r.to_asset_id = $2 AND r.type IN ('hosted_on', 'virtualized_by')
			   AND r.status <> 'rejected' AND a.deleted_at IS NULL
			 ORDER BY 9, a.id`, tenant, asset)
		if err != nil {
			return nil, err
		}
		defer func() { _ = vms.Close() }()
		for vms.Next() {
			var m ClusterMember
			var dn, hn sql.NullString
			var c sql.NullFloat64
			var mm, dd sql.NullInt64
			var sortKey string
			if err := vms.Scan(&m.AssetID, &dn, &hn, &m.ClassKey, &m.AssetStatus, &c, &mm, &dd, &sortKey); err != nil {
				return nil, err
			}
			m.DisplayName, m.Hostname = ifaceStrPtr(dn), ifaceStrPtr(hn)
			if c.Valid {
				f := c.Float64
				m.VCPUs = &f
			}
			m.MemoryMB, m.DiskMB = nullInt(mm), nullInt(dd)
			v.HostedVMs = append(v.HostedVMs, m)
		}
		if err := vms.Err(); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// VirtualizationPatch is a partial update of a VM's columns: cluster_id
// (uuid or null), vcpus (number or null), memory_mb and disk_mb (integers or
// null). A field absent from the body is left alone.
type VirtualizationPatch map[string]json.RawMessage

var vmColumns = []string{"cluster_id", "vcpus", "memory_mb", "disk_mb"}

// UpdateAssetVirtualization writes a VM's cluster and resources and records
// one asset change with the before/after of the columns it changed.
func (s *VirtualizationService) UpdateAssetVirtualization(ctx context.Context, tenant, asset uuid.UUID, patch VirtualizationPatch) (*AssetVirtualization, error) {
	sets := map[string]any{}
	for k, raw := range patch {
		switch k {
		case "cluster_id":
			var v *string
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, ipamInvalid("cluster_id must be a UUID or null")
			}
			if v == nil || strings.TrimSpace(*v) == "" {
				sets[k] = nil
				continue
			}
			id, err := uuid.Parse(strings.TrimSpace(*v))
			if err != nil {
				return nil, ipamInvalid("cluster_id must be a UUID")
			}
			sets[k] = id.String()
		case "vcpus":
			var v *float64
			if err := json.Unmarshal(raw, &v); err != nil || (v != nil && (*v < 0 || *v > 9999.99)) {
				return nil, ipamInvalid("vcpus must be a number from 0 to 9999.99, or null")
			}
			if v == nil {
				sets[k] = nil
			} else {
				sets[k] = *v
			}
		case "memory_mb", "disk_mb":
			var v *int64
			if err := json.Unmarshal(raw, &v); err != nil || (v != nil && (*v < 0 || *v > 2147483647)) {
				return nil, ipamInvalid("%s must be a non-negative whole number of MB, or null", k)
			}
			if v == nil {
				sets[k] = nil
			} else {
				sets[k] = *v
			}
		default:
			return nil, ipamInvalid("unknown or read-only field %q", k)
		}
	}
	var out *AssetVirtualization
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		pre := map[string]any{}
		var path string
		var cl uuid.NullUUID
		var cpus sql.NullFloat64
		var mem, disk sql.NullInt64
		err := tx.QueryRowContext(ctx, `SELECT class_path, cluster_id, vcpus::float8, memory_mb, disk_mb FROM assets
			WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL FOR UPDATE`, tenant, asset).Scan(&path, &cl, &cpus, &mem, &disk)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrVirtualizationAssetNotFound
		}
		if err != nil {
			return err
		}
		if len(sets) > 0 && !vmClassPath(path) {
			return ipamInvalid("a cluster, vCPUs, memory and disk apply to a virtual machine (this asset is %s)", path)
		}
		pre["cluster_id"], pre["vcpus"], pre["memory_mb"], pre["disk_mb"] = nil, nil, nil, nil
		if cl.Valid {
			pre["cluster_id"] = cl.UUID.String()
		}
		if cpus.Valid {
			pre["vcpus"] = cpus.Float64
		}
		if mem.Valid {
			pre["memory_mb"] = mem.Int64
		}
		if disk.Valid {
			pre["disk_mb"] = disk.Int64
		}
		if id, ok := sets["cluster_id"]; ok && id != nil {
			if err := clusterExists(ctx, tx, uuid.MustParse(id.(string))); err != nil {
				return ipamInvalid("no such cluster %v", id)
			}
		}
		if err := writeVMColumns(ctx, tx, tenant, asset, pre, sets, ""); err != nil {
			return err
		}
		out, err = assetVirtualizationTx(ctx, tx, tenant, asset)
		return err
	})
	return out, mapIPAMError(err, false)
}

// writeVMColumns writes the changed VM columns and records one asset change.
func writeVMColumns(ctx context.Context, tx *sql.Tx, tenant, asset uuid.UUID, pre, sets map[string]any, source changes.Source) error {
	var clauses []string
	args := []any{tenant, asset}
	before, after := map[string]any{}, map[string]any{}
	casts := map[string]string{"cluster_id": "::uuid", "vcpus": "::numeric", "memory_mb": "::integer", "disk_mb": "::integer"}
	for _, k := range vmColumns {
		v, ok := sets[k]
		if !ok || fmt.Sprint(v) == fmt.Sprint(pre[k]) {
			continue
		}
		args = append(args, v)
		clauses = append(clauses, fmt.Sprintf("%s = $%d%s", k, len(args), casts[k]))
		before[k], after[k] = pre[k], v
	}
	if len(clauses) == 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE assets SET `+strings.Join(clauses, ", ")+`, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, args...); err != nil {
		return err
	}
	return changes.InTx(tx).Record(ctx, changes.Change{
		TenantID: tenant, Kind: dcim.ObjectKindAsset, ID: asset, Action: changes.ActionUpdate,
		Pre: before, Post: after, Source: source,
	})
}
