package postgres_test

// DCIM row 4.2: clusters through the intake seam. A cluster is the clusters
// object — an intake that reports one produces a clusters row, idempotently,
// and never an asset; a sighted hypervisor becomes a cluster host and a VM
// gets the cluster; a cloud account + region is mirrored as ONE cluster per
// pair with its instances as members.

import (
	"context"
	"errors"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgrepo "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

func (h *ifaceHarness) count(q string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRow(q, append([]any{h.tenant}, args...)...).Scan(&n); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
	return n
}

// UpsertObservedCluster is idempotent on (tenant, type, name) — one row,
// observations counted, the group filled once — and never writes an asset.
//
// Mutation: drop the ON CONFLICT / existing-row branch (insert every time) →
// the second report fails or makes a second row; make it create an asset →
// the asset count moves.
func TestIntegration_ObservedCluster_UpsertIdempotentNeverAnAsset(t *testing.T) {
	h := newIfaceHarness(t)
	ctx := context.Background()
	src := identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:vcenter-1", Mode: identity.ModeActive}
	before := h.count(`SELECT count(*) FROM public.assets WHERE tenant_id = $1`)

	c := identity.ObservedCluster{Name: "Prod-A", Type: "vmware-vsphere", Group: "DC East", ExternalID: "domain-c7", ExternalKey: "vcenter"}
	first, err := h.intake.RecordCluster(ctx, h.tenant, c, src)
	if err != nil || !first.Created {
		t.Fatalf("first report: %+v %v", first, err)
	}
	second, err := h.intake.RecordCluster(ctx, h.tenant, c, src)
	if err != nil || second.Created || second.ID != first.ID {
		t.Fatalf("second report: %+v %v, want the same row, not created", second, err)
	}
	if n := h.count(`SELECT count(*) FROM public.clusters WHERE tenant_id = $1`); n != 1 {
		t.Fatalf("clusters = %d, want 1", n)
	}
	if n := h.count(`SELECT observation_count FROM public.clusters WHERE tenant_id = $1`); n != 2 {
		t.Errorf("observation_count = %d, want 2", n)
	}
	if n := h.count(`SELECT count(*) FROM public.clusters c JOIN public.cluster_groups g ON g.id = c.group_id
		WHERE c.tenant_id = $1 AND g.name = 'DC East' AND c.status = 'pending' AND c.source_kind = 'measured'
		  AND c.external_ids ->> 'vcenter' = 'domain-c7'`); n != 1 {
		t.Error("the cluster is not pending/measured in its group with its external id")
	}
	if n := h.count(`SELECT count(*) FROM public.cluster_groups WHERE tenant_id = $1`); n != 1 {
		t.Errorf("cluster groups = %d, want 1", n)
	}
	if after := h.count(`SELECT count(*) FROM public.assets WHERE tenant_id = $1`); after != before {
		t.Fatalf("assets %d → %d: reporting a cluster created an asset", before, after)
	}
	if _, err := h.intake.RecordCluster(ctx, h.tenant, identity.ObservedCluster{Name: "x", Type: "no-such-type"}, src); !errors.Is(err, pgrepo.ErrUnknownClusterType) {
		t.Errorf("an unknown cluster type: %v, want ErrUnknownClusterType", err)
	}
}

// The retired class can mint no asset: Intake refuses the sighting, and the
// store refuses the create even for an observation built without Intake.
//
// Mutation: delete the class check in validateSighting → the first assertion
// fails; delete the check in CreateAsset → the second does.
func TestIntegration_ObservedCluster_ClusterClassNeverAnAsset(t *testing.T) {
	h := newIfaceHarness(t)
	ctx := context.Background()
	s := h.agent(identity.SightedIdentifier{Kind: identity.KindHostname, Value: "k8s-prod"})
	s.ClassHint = "cluster"
	if _, err := h.intake.Build(ctx, s); !errors.Is(err, identity.ErrClusterNotAnAsset) {
		t.Fatalf("a sighting classed cluster: %v, want ErrClusterNotAnAsset", err)
	}
	if _, err := h.repo.CreateAsset(ctx, h.tenant, identity.NewAsset{ClassKey: "cluster", DisplayName: "k8s-prod",
		Identifiers: []identity.Identifier{{Kind: identity.KindHostname, Value: "k8s-prod"}}}); !errors.Is(err, identity.ErrClusterNotAnAsset) {
		t.Fatalf("CreateAsset with class cluster: %v, want ErrClusterNotAnAsset", err)
	}
	if n := h.count(`SELECT count(*) FROM public.assets WHERE tenant_id = $1 AND class_key = 'cluster'`); n != 0 {
		t.Fatalf("%d cluster-class assets exist", n)
	}
}

// A sighted hypervisor joins its cluster as a host (and moves when seen in
// another), a sighted VM gets the cluster, through the real engine.
//
// Mutation: drop recordObservedCluster from Engine.Resolve → no host row and
// no cluster_id.
func TestIntegration_ObservedCluster_MembershipThroughTheEngine(t *testing.T) {
	h := newIfaceHarness(t)
	host := h.agent(identity.SightedIdentifier{Kind: identity.KindSerialNumber, Value: "ESX-01"})
	host.ClassHint = "hypervisor"
	host.Cluster = &identity.ObservedCluster{Name: "Prod-A", Type: "vmware-vsphere"}
	hostID := h.resolve(host).Asset.ID

	vm := h.agent(identity.SightedIdentifier{Kind: identity.KindSerialNumber, Value: "VMware-42 1a"})
	vm.ClassHint = "virtual_machine"
	vm.Cluster = &identity.ObservedCluster{Name: "Prod-A", Type: "vmware-vsphere"}
	vmID := h.resolve(vm).Asset.ID

	if n := h.count(`SELECT count(*) FROM public.cluster_hosts h JOIN public.clusters c ON c.id = h.cluster_id
		WHERE h.tenant_id = $1 AND h.asset_id = $2 AND c.name = 'Prod-A' AND h.source_kind = 'measured'`, hostID); n != 1 {
		t.Fatalf("the hypervisor is not a measured host of Prod-A (%d rows)", n)
	}
	if n := h.count(`SELECT count(*) FROM public.assets a JOIN public.clusters c ON c.id = a.cluster_id
		WHERE a.tenant_id = $1 AND a.id = $2 AND c.name = 'Prod-A'`, vmID); n != 1 {
		t.Fatal("the VM has no cluster")
	}
	moved := h.agent(identity.SightedIdentifier{Kind: identity.KindSerialNumber, Value: "ESX-01"})
	moved.ClassHint = "hypervisor"
	moved.Cluster = &identity.ObservedCluster{Name: "Prod-B", Type: "vmware-vsphere"}
	if got := h.resolve(moved).Asset.ID; got != hostID {
		t.Fatalf("re-sighting resolved to %s, want %s", got, hostID)
	}
	if n := h.count(`SELECT count(*) FROM public.cluster_hosts h JOIN public.clusters c ON c.id = h.cluster_id WHERE h.tenant_id = $1 AND h.asset_id = $2 AND c.name = 'Prod-B'`, hostID); n != 1 {
		t.Fatal("the host did not move to Prod-B")
	}
	if n := h.count(`SELECT count(*) FROM public.cluster_hosts WHERE tenant_id = $1 AND asset_id = $2`, hostID); n != 1 {
		t.Fatalf("the host is in %d clusters, want 1", n)
	}
	if n := h.count(`SELECT count(*) FROM public.object_changes WHERE tenant_id = $1 AND object_kind = 'cluster' AND source = 'intake:identity'`); n < 4 {
		t.Errorf("cluster changes recorded = %d, want the two creates and the host-list changes", n)
	}
}

// The cloud mirror: ONE cluster per account + region, of the provider's type,
// external_ids.cloud = account:region, with every instance a member; another
// region is another cluster; mirroring again changes nothing.
//
// Mutation: key the mirror on the instance instead of account:region → three
// clusters; drop recordMembership from the mirror → no member.
func TestIntegration_ObservedCluster_CloudMirrorOnePerAccountRegion(t *testing.T) {
	h := newIfaceHarness(t)
	ctx := context.Background()
	var instances []string
	for _, id := range []string{"i-01", "i-02", "i-03"} {
		s := h.agent(identity.SightedIdentifier{Kind: identity.KindCloudResourceID, Value: "arn:aws:ec2:us-east-1:123456789012:instance/" + id})
		s.ClassHint = "compute_instance"
		instances = append(instances, h.resolve(s).Asset.ID)
	}
	regions := []string{"us-east-1", "us-east-1", "eu-west-1"}
	for pass := 0; pass < 2; pass++ {
		for i, a := range instances {
			if err := h.repo.MirrorCloudCluster(ctx, identity.AssetRef{TenantID: h.tenant, ID: a}, "aws", "123456789012", regions[i]); err != nil {
				t.Fatalf("mirror: %v", err)
			}
		}
	}
	if n := h.count(`SELECT count(*) FROM public.clusters c JOIN public.cluster_types t ON t.id = c.type_id WHERE c.tenant_id = $1 AND t.slug = 'aws'`); n != 2 {
		t.Fatalf("aws clusters = %d, want 2 (one per account+region)", n)
	}
	if n := h.count(`SELECT count(*) FROM public.assets a JOIN public.clusters c ON c.id = a.cluster_id
		WHERE a.tenant_id = $1 AND c.external_ids ->> 'cloud' = '123456789012:us-east-1' AND c.name = '123456789012/us-east-1' AND c.status = 'active'`); n != 2 {
		t.Fatalf("us-east-1 mirror has %d members, want 2", n)
	}
	if n := h.count(`SELECT count(*) FROM public.assets a JOIN public.clusters c ON c.id = a.cluster_id
		WHERE a.tenant_id = $1 AND c.external_ids ->> 'cloud' = '123456789012:eu-west-1'`); n != 1 {
		t.Fatalf("eu-west-1 mirror has %d members, want 1", n)
	}
	if n := h.count(`SELECT count(*) FROM public.assets WHERE tenant_id = $1 AND class_key = 'cluster'`); n != 0 {
		t.Fatal("the mirror created a cluster-class asset")
	}
}
