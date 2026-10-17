package services

// DB-integration tests for virtualisation (DCIM BUILD_PLAN row 4.2). Skipped
// unless TEST_DATABASE_URL is set; run with make test-integration-db.
//
// The service runs on the NON-OWNER app role, so RLS is in force exactly as in
// production; the owner connection seeds assets.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func virtSeedAsset(t *testing.T, owner *sql.DB, tenant uuid.UUID, class, path string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := owner.Exec(`
		INSERT INTO assets (id, tenant_id, hostname, display_name, class_key, class_path, asset_status)
		VALUES ($1, $2, $3, $3, $4, $5, 'monitoring')`, id, tenant, class+"-"+id.String()[:8], class, path); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	return id
}

// virtPlatformType is a seeded platform cluster type's id (seed.sql), created
// here when the database was not seeded.
func virtPlatformType(t *testing.T, owner *sql.DB, slug string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := owner.QueryRow(`
		INSERT INTO cluster_types (tenant_id, name, slug) VALUES (NULL, $1, $1)
		ON CONFLICT ((COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid)), slug) DO UPDATE SET slug = EXCLUDED.slug
		RETURNING id`, slug).Scan(&id); err != nil {
		t.Fatalf("platform cluster type %s: %v", slug, err)
	}
	return id
}

func rawField(t *testing.T, raw json.RawMessage, field string) any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return m[field]
}

// A cluster is the tenant's alone: tenant B cannot list, read, change, delete
// or attach to it, and the app role cannot insert a row naming another tenant
// (RLS USING doubles as WITH CHECK). Platform cluster types are readable and
// refused on write.
//
// Mutation: drop the clusters_tenant_isolation policy (or the ENABLE ROW
// LEVEL SECURITY) from the 4.2 block → tenant B lists A's cluster and the
// cross-tenant INSERT succeeds; drop `Catalogue: true` from the cluster-types
// spec → the platform PATCH answers not-found instead of read-only.
func TestIntegration_Virtualization_ClustersRLS(t *testing.T) {
	owner, app, tenantA := ifaceFixture(t)
	tenantB := testdb.NewTenant(t, owner)
	ctx := ifaceActorCtx()
	svc := NewVirtualizationService(app)
	kvm := virtPlatformType(t, owner, "kvm")

	if _, err := svc.Get(ctx, tenantA, "cluster-types", kvm); err != nil {
		t.Fatalf("tenant cannot read a platform cluster type: %v", err)
	}
	if _, err := svc.Update(ctx, tenantA, "cluster-types", kvm, []byte(`{"comments":"mine"}`)); !errors.Is(err, ErrIPAMReadOnly) {
		t.Fatalf("PATCH of a platform cluster type: %v, want read-only", err)
	}

	grp, err := svc.Create(ctx, tenantA, "cluster-groups", []byte(`{"name":"Prod clusters"}`))
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if got := rawField(t, grp, "slug"); got != "prod-clusters" {
		t.Errorf("group slug = %v, want derived prod-clusters", got)
	}
	cl, err := svc.Create(ctx, tenantA, "clusters", []byte(fmt.Sprintf(`{"name":"pve-a","type_id":%q,"group_id":%q}`, kvm, catID(t, grp))))
	if err != nil {
		t.Fatalf("create cluster: %v", err)
	}
	clID := catID(t, cl)
	if _, err := svc.Create(ctx, tenantA, "clusters", []byte(fmt.Sprintf(`{"name":"pve-a","type_id":%q}`, kvm))); !errors.Is(err, ErrIPAMConflict) {
		t.Fatalf("second cluster with the same (type, name): %v, want conflict", err)
	}
	rows, total, err := svc.List(ctx, tenantA, "clusters", IPAMListParams{Limit: 50})
	if err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("tenant A lists %d/%d clusters (%v), want 1", len(rows), total, err)
	}
	if typ, _ := rawField(t, rows[0], "type").(map[string]any); typ["slug"] != "kvm" {
		t.Errorf("list row type = %v, want the kvm type", rawField(t, rows[0], "type"))
	}

	// Tenant B: nothing.
	if rows, total, err := svc.List(ctx, tenantB, "clusters", IPAMListParams{Limit: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Fatalf("tenant B listed %d/%d of A's clusters (%v)", len(rows), total, err)
	}
	if _, err := svc.Get(ctx, tenantB, "clusters", clID); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("tenant B GET of A's cluster: %v, want not found", err)
	}
	if _, err := svc.Update(ctx, tenantB, "clusters", clID, []byte(`{"comments":"x"}`)); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("tenant B PATCH of A's cluster: %v, want not found", err)
	}
	if err := svc.Delete(ctx, tenantB, "clusters", clID); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("tenant B DELETE of A's cluster: %v, want not found", err)
	}
	hostB := virtSeedAsset(t, owner, tenantB, "hypervisor", "virtual.hypervisor")
	if _, err := svc.AddClusterHost(ctx, tenantB, clID, hostB); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("tenant B attaching a host to A's cluster: %v, want not found", err)
	}

	// The insert path across tenants (RLS USING doubles as WITH CHECK).
	tx, err := app.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_tenant_context($1)`, tenantB); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO clusters (tenant_id, name, type_id) VALUES ($1, 'smuggled', $2)`, tenantA, kvm); err == nil {
		t.Fatal("tenant B's session inserted a cluster for tenant A: the RLS policy is missing")
	}
}

// Hosts and VMs: a hypervisor joins a cluster (once: a second cluster moves
// it), a VM is given the cluster and its resources, a virtual disk belongs to
// a VM only, and the cards and lists read them back. Every write is recorded.
func TestIntegration_Virtualization_HostsVMsAndCards(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	svc := NewVirtualizationService(app)
	kvm := virtPlatformType(t, owner, "kvm")
	c1 := catID(t, must(t)(svc.Create(ctx, tenant, "clusters", []byte(fmt.Sprintf(`{"name":"c1","type_id":%q}`, kvm)))))
	c2 := catID(t, must(t)(svc.Create(ctx, tenant, "clusters", []byte(fmt.Sprintf(`{"name":"c2","type_id":%q}`, kvm)))))
	host := virtSeedAsset(t, owner, tenant, "hypervisor", "virtual.hypervisor")
	vm := virtSeedAsset(t, owner, tenant, "virtual_machine", "virtual.virtual_machine")
	app2 := virtSeedAsset(t, owner, tenant, "web_application", "application.web_application")

	if _, err := svc.AddClusterHost(ctx, tenant, c1, app2); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("an application as a cluster host: %v, want invalid", err)
	}
	if hosts, err := svc.AddClusterHost(ctx, tenant, c1, host); err != nil || len(hosts) != 1 || hosts[0].AssetID != host {
		t.Fatalf("add host: %v %v", hosts, err)
	}
	if _, err := svc.AddClusterHost(ctx, tenant, c2, host); err != nil {
		t.Fatalf("move host: %v", err)
	}
	if hosts, _ := svc.ClusterHosts(ctx, tenant, c1); len(hosts) != 0 {
		t.Fatalf("host still in c1 after moving to c2: %v", hosts)
	}

	if _, err := svc.UpdateAssetVirtualization(ctx, tenant, host, VirtualizationPatch{"vcpus": json.RawMessage(`4`)}); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("VM columns on a hypervisor: %v, want invalid", err)
	}
	card, err := svc.UpdateAssetVirtualization(ctx, tenant, vm, VirtualizationPatch{
		"cluster_id": json.RawMessage(fmt.Sprintf("%q", c2)), "vcpus": json.RawMessage(`2.5`),
		"memory_mb": json.RawMessage(`4096`), "disk_mb": json.RawMessage(`81920`),
	})
	if err != nil || card.Cluster == nil || card.Cluster.ID != c2 || card.VCPUs == nil || *card.VCPUs != 2.5 || !card.IsVM {
		t.Fatalf("VM card after patch: %+v %v", card, err)
	}
	if _, err := svc.Create(ctx, tenant, "virtual-disks", []byte(fmt.Sprintf(`{"asset_id":%q,"name":"disk0","size_mb":40960}`, host))); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("a virtual disk on a hypervisor: %v, want invalid", err)
	}
	if _, err := svc.Create(ctx, tenant, "virtual-disks", []byte(fmt.Sprintf(`{"asset_id":%q,"name":"disk0","size_mb":40960}`, vm))); err != nil {
		t.Fatalf("virtual disk: %v", err)
	}
	vms, err := svc.ClusterVMs(ctx, tenant, c2)
	if err != nil || len(vms) != 1 || vms[0].AssetID != vm || vms[0].VirtualDiskCount == nil || *vms[0].VirtualDiskCount != 1 {
		t.Fatalf("c2 VMs: %+v %v", vms, err)
	}
	rows, _, err := svc.List(ctx, tenant, "clusters", IPAMListParams{Filters: map[string]string{}, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if catID(t, r) == c2 && (rawField(t, r, "host_count") != float64(1) || rawField(t, r, "vm_count") != float64(1)) {
			t.Errorf("c2 list row counts host=%v vm=%v, want 1 and 1", rawField(t, r, "host_count"), rawField(t, r, "vm_count"))
		}
	}

	// The hypervisor's card: its cluster, and the VM a hosted_on edge names.
	if _, err := owner.Exec(`INSERT INTO asset_relationships (tenant_id, from_asset_id, to_asset_id, type, status) VALUES ($1, $2, $3, 'hosted_on', 'active')`, tenant, vm, host); err != nil {
		t.Fatal(err)
	}
	hc, err := svc.AssetVirtualization(ctx, tenant, host)
	if err != nil || !hc.IsHost || hc.HostCluster == nil || hc.HostCluster.ID != c2 || len(hc.HostedVMs) != 1 || hc.HostedVMs[0].AssetID != vm {
		t.Fatalf("hypervisor card: %+v %v", hc, err)
	}

	// Deleting the cluster clears the VM's cluster and the host membership.
	if err := svc.Delete(ctx, tenant, "clusters", c2); err != nil {
		t.Fatalf("delete cluster: %v", err)
	}
	if card, _ := svc.AssetVirtualization(ctx, tenant, vm); card.Cluster != nil {
		t.Fatalf("VM still in a deleted cluster: %+v", card.Cluster)
	}
	var n int
	if err := owner.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1 AND object_kind IN ('cluster', 'asset', 'virtual_disk')`, tenant).Scan(&n); err != nil || n < 6 {
		t.Fatalf("object_changes recorded %d (%v), want every write", n, err)
	}
}

func must(t *testing.T) func(json.RawMessage, error) json.RawMessage {
	return func(r json.RawMessage, err error) json.RawMessage {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
}
