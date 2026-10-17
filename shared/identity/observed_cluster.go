package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// The cluster half of the intake seam (DCIM row 4.2; asset-inventory ADR-0010
// D8). A cluster — a vSphere or Proxmox cluster, a Hyper-V failover cluster, a
// Kubernetes cluster, a cloud account+region — is the `clusters` OBJECT, never
// an asset: the `cluster` asset class was retired by this row.
//
// Two ways a collector reports one:
//
//   - A cluster on its own (a hypervisor manager enumerating its clusters):
//     [Intake.RecordCluster] upserts the clusters row by its identity
//     (tenant, type, name) and creates nothing else.
//   - A cluster a sighted asset belongs to: [Sighting.Cluster] names it, and
//     once the sighting resolved to an asset the engine records the membership
//     ([ObservedClusterRepository.RecordClusterMembership]) — a hypervisor
//     becomes a cluster host (cluster_hosts), a virtual machine gets the
//     cluster (assets.cluster_id).
//
// Neither path can mint an asset for the cluster itself, and a sighting whose
// class hint is the retired `cluster` key is refused ([ErrClusterNotAnAsset])
// so an adapter that still thinks of clusters as assets fails loudly rather
// than creating one under a class nothing knows.

// RetiredClusterClass is the asset class key DCIM row 4.2 retired.
const RetiredClusterClass = "cluster"

// ErrClusterNotAnAsset refuses a sighting classed as a cluster.
var ErrClusterNotAnAsset = fmt.Errorf("%w: a cluster is not an asset (DCIM row 4.2): report it as an ObservedCluster", ErrInvalidSighting)

// ClusterMember is the sighted asset's role in its cluster.
type ClusterMember string

const (
	// ClusterMemberHost — a hypervisor (or hardware node) of the cluster.
	ClusterMemberHost ClusterMember = "host"
	// ClusterMemberVM — a virtual machine (or cloud instance) running in it.
	ClusterMemberVM ClusterMember = "vm"
)

// ObservedCluster is a cluster as a collector saw it. Posture only: a name, a
// type, a group, an external id — nothing that could carry a credential.
type ObservedCluster struct {
	// Name as the source spelled it; with Type it is the cluster's identity.
	Name string `json:"name"`
	// Type is a cluster type slug (`vmware-vsphere`, `proxmox`, `hyper-v`,
	// `kvm`, `nutanix`, `aws`, `azure`, `gcp`, `kubernetes`, or a tenant's
	// own). A type the tenant cannot see is refused, never invented.
	Type string `json:"type"`
	// Group names a cluster group, created when the tenant has none of that
	// name. Filled on a cluster that has no group; never overwrites one.
	Group string `json:"group,omitempty"`
	// ExternalID is the source's own id for the cluster (a vSphere MoRef, a
	// Proxmox cluster name, a cloud `<account>:<region>`), stored under
	// external_ids.<ExternalKey>.
	ExternalID  string `json:"external_id,omitempty"`
	ExternalKey string `json:"external_key,omitempty"`
	// Member is the sighted asset's role in the cluster, on a sighting. Empty
	// lets the asset's class decide (a hypervisor is a host, a virtual
	// machine or compute instance a VM; anything else is not recorded).
	Member ClusterMember `json:"member,omitempty"`
}

// Normalize trims the cluster and checks what the schema would refuse.
func (c ObservedCluster) Normalize() (ObservedCluster, error) {
	c.Name = strings.TrimSpace(c.Name)
	c.Type = strings.ToLower(strings.TrimSpace(c.Type))
	c.Group = strings.TrimSpace(c.Group)
	c.ExternalID = strings.TrimSpace(c.ExternalID)
	c.ExternalKey = strings.TrimSpace(c.ExternalKey)
	switch {
	case c.Name == "":
		return c, errors.New("a cluster has no name")
	case len(c.Name) > 100:
		return c, fmt.Errorf("cluster name %q is longer than 100 characters", c.Name)
	case c.Type == "":
		return c, fmt.Errorf("cluster %q has no type", c.Name)
	}
	switch c.Member {
	case "", ClusterMemberHost, ClusterMemberVM:
	default:
		return c, fmt.Errorf("cluster %q: member %q is not host or vm", c.Name, c.Member)
	}
	if c.ExternalID != "" && c.ExternalKey == "" {
		return c, fmt.Errorf("cluster %q: an external id needs the key it is stored under", c.Name)
	}
	return c, nil
}

// ClusterRef is the clusters row an observation resolved to.
type ClusterRef struct {
	TenantID string
	ID       string
	// Created: this call created the row. Rejected: the identity names a
	// cluster a person rejected, so nothing was recorded on it.
	Created, Rejected bool
}

// ObservedClusterRepository is implemented by a store that records clusters.
type ObservedClusterRepository interface {
	// UpsertObservedCluster finds the cluster by (tenant, type, name) or
	// creates it `measured` and `pending`, and counts the observation.
	UpsertObservedCluster(ctx context.Context, tenantID string, c ObservedCluster, src Source) (ClusterRef, error)
	// RecordClusterMembership upserts c and records asset's membership in it
	// (host or VM, by c.Member or the asset's class).
	RecordClusterMembership(ctx context.Context, asset AssetRef, c ObservedCluster, src Source) error
}

// ErrNoClusterStore is returned when the intake's repository cannot record
// clusters.
var ErrNoClusterStore = errors.New("identity: the repository does not record clusters")

// RecordCluster records a cluster a collector enumerated — the clusters row
// and nothing else. It is how an intake reports a cluster; a sighting classed
// `cluster` is refused.
func (in *Intake) RecordCluster(ctx context.Context, tenantID string, c ObservedCluster, src Source) (ClusterRef, error) {
	if strings.TrimSpace(tenantID) == "" {
		return ClusterRef{}, fmt.Errorf("%w: no tenant", ErrInvalidSighting)
	}
	if !src.Valid() {
		return ClusterRef{}, fmt.Errorf("%w: source %+v is not a valid provenance", ErrInvalidSighting, src)
	}
	nc, err := c.Normalize()
	if err != nil {
		return ClusterRef{}, fmt.Errorf("%w: %v", ErrInvalidSighting, err)
	}
	store, ok := in.repo.(ObservedClusterRepository)
	if !ok {
		return ClusterRef{}, ErrNoClusterStore
	}
	return store.UpsertObservedCluster(ctx, tenantID, nc, src)
}

// recordObservedCluster records the resolved asset's cluster membership.
func (e *Engine) recordObservedCluster(ctx context.Context, obs Observation, res Resolution) error {
	if obs.Cluster == nil || !recordsObservedNetwork(res) {
		return nil
	}
	store, ok := e.repo.(ObservedClusterRepository)
	if !ok {
		return nil
	}
	if err := store.RecordClusterMembership(ctx, res.Asset, *obs.Cluster, obs.Source); err != nil {
		return fmt.Errorf("identity: recording the cluster of %s: %w", res.Asset.ID, err)
	}
	return nil
}
