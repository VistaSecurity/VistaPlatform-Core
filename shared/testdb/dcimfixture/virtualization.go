package dcimfixture

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// The virtualisation populator (DCIM BUILD_PLAN row 4.2).
//
// One tenant cluster type and one cluster group, then one cluster per site.
// The fixture's assets are fixed (servers, switches, firewalls, routers — the
// asset count is asserted), so the populator lends them roles rather than
// adding assets: every server in a site's first rack is a HOST of the site's
// cluster (cluster_hosts), and every server in its second rack carries the
// cluster and VM resources (assets.cluster_id, vcpus, memory_mb, disk_mb) with
// one virtual disk — enough for the Clusters lens, the cluster page and the
// cluster query fields to run at scale.
const (
	FixtureVCPUs    = 4
	FixtureMemoryMB = 8192
	FixtureDiskMB   = 102400
)

func populateVirtualization(ctx context.Context, tx *sql.Tx, e *Env) (int, error) {
	if len(e.Assets) == 0 || e.Scale.Sites == 0 {
		return -1, nil
	}
	var typeID, groupID uuid.UUID
	if err := tx.QueryRowContext(ctx, `INSERT INTO cluster_types (tenant_id, name, slug) VALUES ($1, 'Fixture KVM', 'fixture-kvm') RETURNING id`, e.Tenant).Scan(&typeID); err != nil {
		return 0, err
	}
	if err := tx.QueryRowContext(ctx, `INSERT INTO cluster_groups (tenant_id, name, slug) VALUES ($1, 'Fixture', 'fixture') RETURNING id`, e.Tenant).Scan(&groupID); err != nil {
		return 0, err
	}
	clusters := make([]uuid.UUID, e.Scale.Sites)
	for site := range clusters {
		name := fmt.Sprintf("cluster-%04d", site)
		e.Witness(name)
		if err := tx.QueryRowContext(ctx, `INSERT INTO clusters (tenant_id, name, type_id, group_id) VALUES ($1, $2, $3, $4) RETURNING id`,
			e.Tenant, name, typeID, groupID).Scan(&clusters[site]); err != nil {
			return 0, err
		}
	}
	var hosts, vms []Asset
	for _, a := range e.Assets {
		if a.Class != "server" {
			continue
		}
		switch a.Rack {
		case 0:
			hosts = append(hosts, a)
		case 1:
			vms = append(vms, a)
		}
	}
	if err := copyRows(ctx, tx, "cluster_hosts", []string{"tenant_id", "cluster_id", "asset_id"}, len(hosts), func(i int) []any {
		return []any{e.Tenant, clusters[hosts[i].Site], hosts[i].ID}
	}); err != nil {
		return 0, err
	}
	bySite := map[int][]string{}
	for _, a := range vms {
		bySite[a.Site] = append(bySite[a.Site], a.ID.String())
	}
	for site, ids := range bySite {
		if _, err := tx.ExecContext(ctx, `UPDATE assets SET cluster_id = $2, vcpus = $3, memory_mb = $4, disk_mb = $5
			WHERE tenant_id = $1 AND id = ANY($6::uuid[])`, e.Tenant, clusters[site], FixtureVCPUs, FixtureMemoryMB, FixtureDiskMB, pq.Array(ids)); err != nil {
			return 0, err
		}
	}
	if err := copyRows(ctx, tx, "virtual_disks", []string{"tenant_id", "asset_id", "name", "size_mb"}, len(vms), func(i int) []any {
		return []any{e.Tenant, vms[i].ID, "disk0", FixtureDiskMB}
	}); err != nil {
		return 0, err
	}
	return len(clusters), nil
}
