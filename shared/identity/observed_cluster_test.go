package identity_test

// DCIM row 4.2 without a database: the class guard, the sighting's cluster
// carried to the observation, and a malformed cluster dropped with a reason.

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/memory"
)

// Mutation: delete the class check in validateSighting → red.
func TestIntake_RefusesTheRetiredClusterClass(t *testing.T) {
	in, err := identity.NewIntake(memory.New())
	if err != nil {
		t.Fatal(err)
	}
	for _, hint := range []string{"cluster", " Cluster "} {
		s := agentSighting(time.Now())
		s.ClassHint = hint
		if _, err := in.Build(context.Background(), s); !errors.Is(err, identity.ErrClusterNotAnAsset) || !errors.Is(err, identity.ErrInvalidSighting) {
			t.Errorf("class hint %q: %v, want ErrClusterNotAnAsset (an invalid sighting)", hint, err)
		}
	}
	if _, err := in.RecordCluster(context.Background(), "t1", identity.ObservedCluster{Name: "c", Type: "kvm"},
		identity.Source{Kind: identity.SourceMeasured, Ref: "x:y"}); !errors.Is(err, identity.ErrNoClusterStore) {
		t.Errorf("RecordCluster on a store without clusters: %v, want ErrNoClusterStore", err)
	}
}

func TestIntake_CarriesTheSightingsCluster(t *testing.T) {
	in, err := identity.NewIntake(memory.New())
	if err != nil {
		t.Fatal(err)
	}
	s := agentSighting(time.Now())
	s.Cluster = &identity.ObservedCluster{Name: "  Prod-A ", Type: "VMware-vSphere", Member: identity.ClusterMemberVM}
	obs, err := in.Build(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Cluster == nil || obs.Cluster.Name != "Prod-A" || obs.Cluster.Type != "vmware-vsphere" {
		t.Fatalf("observation cluster = %+v, want the normalised Prod-A / vmware-vsphere", obs.Cluster)
	}
	s.Cluster = &identity.ObservedCluster{Name: "", Type: "kvm"}
	res, err := in.Assess(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if res.Observation.Cluster != nil || !slices.ContainsFunc(res.DroppedNetwork, func(d string) bool { return strings.HasPrefix(d, "cluster:") }) {
		t.Fatalf("a nameless cluster: carried %+v, dropped %v — want it dropped with a reason", res.Observation.Cluster, res.DroppedNetwork)
	}
}
