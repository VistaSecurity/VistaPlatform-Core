package query_test

// The virtualisation fields on the asset target (QUERY_LANGUAGE §15, DCIM row
// 4.2) over real rows: a VM's cluster (assets.cluster_id) and a hypervisor's
// (cluster_hosts) both answer `cluster`, by name, type and group.
//
// Mutation: drop the cluster_hosts arm of the membership in sql/shapes.go →
// "a host is in its cluster" goes red.

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_QueryClusterFields(t *testing.T) {
	db := testdb.Connect(t)
	requireInventorySchema(t, db)
	testdb.HoldSchemaShareLock(t, db)
	tenant := testdb.NewTenant(t, db)

	typ := ipamRow(t, db, `INSERT INTO cluster_types (tenant_id, name, slug) VALUES ($1, 'Fixture vSphere', 'fixture-vsphere') RETURNING id`, tenant)
	grp := ipamRow(t, db, `INSERT INTO cluster_groups (tenant_id, name, slug) VALUES ($1, 'DC East', 'dc-east') RETURNING id`, tenant)
	prod := ipamRow(t, db, `INSERT INTO clusters (tenant_id, name, type_id, group_id) VALUES ($1, 'Prod-A', $2, $3) RETURNING id`, tenant, typ, grp)

	vm := insertAsset(t, db, tenant, "vm-1", 0, nil)
	host := insertAsset(t, db, tenant, "esx-1", 0, nil)
	other := insertAsset(t, db, tenant, "lonely", 0, nil)
	if _, err := db.Exec(`UPDATE assets SET cluster_id = $1 WHERE tenant_id = $2 AND id = $3`, prod, tenant, vm); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO cluster_hosts (tenant_id, cluster_id, asset_id) VALUES ($1, $2, $3)`, tenant, prod, host); err != nil {
		t.Fatal(err)
	}
	only := func(t *testing.T, q string, n int) map[string]bool {
		t.Helper()
		got := matchIDs(t, db, tenant, q)
		if len(got) != n {
			t.Errorf("%q: matched %d assets, want %d (%v)", q, len(got), n, got)
		}
		out := map[string]bool{}
		for id := range got {
			out[id.String()] = true
		}
		return out
	}
	t.Run("a VM is in its cluster", func(t *testing.T) {
		if got := only(t, "cluster.id = "+prod.String(), 1); !got[vm.String()] {
			t.Error("cluster.id did not match the VM")
		}
	})
	t.Run("a host is in its cluster", func(t *testing.T) {
		got := only(t, "cluster = Prod-A", 2)
		if !got[vm.String()] || !got[host.String()] {
			t.Errorf("cluster = Prod-A matched %v, want the VM and the host", got)
		}
		only(t, "cluster.type = fixture-vsphere", 2)
		only(t, `cluster.group = "DC East"`, 2)
	})
	t.Run("!= negates the whole EXISTS", func(t *testing.T) {
		if got := only(t, "cluster != Prod-A", 1); !got[other.String()] {
			t.Error("cluster != Prod-A did not match the asset in no cluster")
		}
	})
}
