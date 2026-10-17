package services

// GCP half of workstream 2.4: Compute Engine instances, networks, subnetworks
// and firewalls.
//
// The API calls, and the IAM permissions a customer has to grant:
//
//	compute.instances.aggregatedList    compute.instances.list
//	compute.networks.list               compute.networks.list
//	compute.subnetworks.aggregatedList  compute.subnetworks.list
//	compute.firewalls.list              compute.firewalls.list
//
// All four are in the predefined **roles/compute.viewer** (and in
// roles/viewer). The integration's existing OAuth scope,
// `cloud-platform.read-only`, already covers them, so no credential change is
// needed for an integration that already works.
//
// The two AGGREGATED forms are deliberate: GCP has ~100 zones and ~40 regions,
// and the per-zone `instances.list` loop would be a hundred calls to find a
// project with three VMs in it.
//
// GCP has no security-group object. A firewall rule attaches to a NETWORK and
// selects instances by network tag, so membership is computed
// (`FirewallsForInstance`) rather than read off the instance. The rule CONTENT
// — allowed protocols and ports, source ranges — is never retrieved into a
// struct that has a field for it.

import (
	"context"
	"errors"
	"strings"

	gcpclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/gcp"
)

// enumerateGCP runs the selected listings and builds the plan.
//
// The listings are project-wide (the aggregated forms), so each type has one
// `global` row for the call plus one row per region its resources are in
// (asset-inventory ADR-0009 D3). A failing listing is recorded; the others
// still run.
func (s *CloudDiscoveryService) enumerateGCP(ctx context.Context, client *gcpclient.Client, sel cloudEnumerationSelection) (cloudEnumerationPlan, error) {
	outcomes := cloudOutcomesFrom(ctx)

	var (
		networks    []gcpclient.ComputeNetwork
		subnetworks []gcpclient.ComputeSubnetwork
		firewalls   []gcpclient.ComputeFirewall
		instances   []gcpclient.ComputeInstance
	)
	if sel.needsNetworks() {
		var nErr, sErr error
		networks, nErr = client.ListNetworks(ctx)
		subnetworks, sErr = client.ListSubnetworks(ctx)
		err := errors.Join(nErr, sErr)
		outcomes.Attempt(CloudTypeNetworks, cloudScopeGlobal, len(networks)+len(subnetworks), err)
		logCloudCollectorFailure(CloudTypeNetworks, cloudScopeGlobal, err)
		if sErr == nil {
			per := map[string]int{}
			for _, sn := range subnetworks {
				per[gcpclient.ResourceShortName(sn.Region)]++
			}
			outcomes.AttributeRegions(CloudTypeNetworks, per)
		}
	}
	if sel.needsGroups() {
		var err error
		firewalls, err = client.ListFirewalls(ctx)
		outcomes.Attempt(CloudTypeSecurityGroups, cloudScopeGlobal, len(firewalls), err)
		logCloudCollectorFailure(CloudTypeSecurityGroups, cloudScopeGlobal, err)
	}
	if sel.Instances {
		var err error
		instances, err = client.ListInstances(ctx)
		outcomes.Attempt(CloudTypeComputeInstances, cloudScopeGlobal, len(instances), err)
		logCloudCollectorFailure(CloudTypeComputeInstances, cloudScopeGlobal, err)
		if err == nil {
			per := map[string]int{}
			for _, inst := range instances {
				per[gcpclient.ZoneRegion(inst.Zone)]++
			}
			outcomes.AttributeRegions(CloudTypeComputeInstances, per)
		}
	}

	plan := buildGCPEnumerationPlan(client.GetProjectID(), instances, networks, subnetworks, firewalls)
	for i := range plan.Instances {
		plan.Instances[i].annotateListing(CloudListingKey(CloudTypeComputeInstances, cloudScopeGlobal))
	}
	gcpSecurityGroups(&plan, client.GetProjectID(), firewalls)
	return plan, nil
}

// buildGCPEnumerationPlan turns GCP's projections into the
// provider-independent plan. Pure function of its inputs.
//
// Networks and subnetworks become prefixes carrying the network's resource
// name as `cloud_network_ref` (DCIM row 1.5f) — a custom-mode network has no
// range of its own, so only a legacy network contributes a container prefix.
// Each instance's NICs become `virtual` interfaces (`nic0`, …) with their
// internal addresses. GCE states no MAC for a NIC, and its external address
// (`accessConfigs`) is not collected (see gcpclient.ComputeNetworkInterface).
func buildGCPEnumerationPlan(
	projectID string,
	instances []gcpclient.ComputeInstance,
	networks []gcpclient.ComputeNetwork,
	subnetworks []gcpclient.ComputeSubnetwork,
	firewalls []gcpclient.ComputeFirewall,
) cloudEnumerationPlan {
	plan := cloudEnumerationPlan{Provider: "gcp", Vendor: "GCP", SecurityGroupIDs: map[string]bool{}}

	for _, n := range networks {
		id := gcpclient.ResourceName(n.SelfLink)
		if id == "" {
			continue
		}
		var cidrs []string
		if n.IPv4Range != "" {
			// Only a legacy (non-subnet) network has a range of its own. A
			// modern VPC's address space lives entirely on the subnetworks, and
			// claiming a CIDR it does not have would be an invented fact.
			cidrs = []string{n.IPv4Range}
		}
		plan.Networks = append(plan.Networks, cloudNetwork{
			ResourceID: id,
			NetworkRef: id,
			Account:    projectID,
			// GCP networks are GLOBAL: no region.
			Name:  n.Name,
			CIDRs: cidrs,
		})
	}

	for _, sn := range subnetworks {
		id := gcpclient.ResourceName(sn.SelfLink)
		if id == "" {
			continue
		}
		var cidrs []string
		if c := strings.TrimSpace(sn.IPCidrRange); c != "" {
			cidrs = []string{c}
		}
		plan.Subnets = append(plan.Subnets, cloudNetwork{
			ResourceID: id,
			NetworkRef: gcpclient.ResourceName(sn.Network),
			Account:    projectID,
			Region:     gcpclient.ResourceShortName(sn.Region),
			Name:       sn.Name,
			CIDRs:      cidrs,
		})
	}
	lengths := subnetPrefixLengths(plan.Subnets)

	for _, fw := range firewalls {
		if id := gcpclient.ResourceName(fw.SelfLink); id != "" {
			plan.SecurityGroupIDs[id] = true
		}
	}

	for _, inst := range instances {
		id := gcpclient.ResourceName(inst.SelfLink)
		if id == "" {
			continue
		}
		zone := gcpclient.ResourceShortName(inst.Zone)
		region := gcpclient.ZoneRegion(inst.Zone)

		matched := gcpclient.FirewallsForInstance(inst, firewalls)
		groups := make([]map[string]any, 0, len(matched))
		for _, fw := range matched {
			fwID := gcpclient.ResourceName(fw.SelfLink)
			plan.SecurityGroupIDs[fwID] = true
			groups = append(groups, securityGroupEntry(fwID, fw.Name))
		}

		networkID, subnetID, addresses := gcpInstancePlacement(inst)
		nics := make([]cloudNIC, 0, len(inst.NetworkInterfaces))
		for _, ni := range inst.NetworkInterfaces {
			nic := cloudNIC{Name: ni.Name, Subnet: gcpclient.ResourceName(ni.Subnetwork)}
			if a := strings.TrimSpace(ni.NetworkIP); a != "" {
				nic.Addresses = []string{a}
			}
			nics = append(nics, nic)
		}

		plan.Instances = append(plan.Instances, cloudEnumResource{
			DeviceType:  DeviceTypeGCPComputeInstance,
			ResourceID:  id,
			DisplayName: inst.Name,
			// `hostname` is the custom internal DNS name, which GCE states only
			// when the operator set one. The default `<name>.c.<project>.
			// internal` form is DERIVED, not stated, and deriving a name the
			// API did not give would put a guess in the column hostname search
			// reads.
			Hostname:  inst.Hostname,
			IPAddress: firstAddress(addresses),
			// The network, not the subnetwork: which address space the
			// instance's internal address belongs to.
			CloudNetworkRef: networkID,
			Interfaces:      cloudInterfaces(nics, lengths),
			Prefixes:        instancePrefixes(networkID, nics, plan.Networks, plan.Subnets),
			Facts:           cloudPlacementFacts("gcp", projectID, region, id, groups),
			Attributes: mergeAttributes(
				cloudResourceAttributes("gcp", projectID, region),
				map[string]any{
					"instance_type": gcpclient.ResourceShortName(inst.MachineType),
					// image_id absent: GCE's instance listing does not name the
					// source image. It is on the boot disk, and `disks[]` is
					// not collected (it carries diskEncryptionKey).
				},
			),
			Tags: tagsToJSONB(inst.Labels),
			Metadata: map[string]interface{}{
				"resource_type": "compute_instance",
				"self_link":     inst.SelfLink,
				"project_id":    projectID,
				"region":        region,
				"zone":          zone,
				"machine_type":  gcpclient.ResourceShortName(inst.MachineType),
				"status":        inst.Status,
				"cpu_platform":  inst.CPUPlatform,
				"network":       networkID,
				"subnetwork":    subnetID,
				"network_tags":  gcpNetworkTags(inst),
			},
		})
	}
	return plan
}

// gcpInstancePlacement returns the instance's first network, its first
// subnetwork, and every internal address across its NICs.
func gcpInstancePlacement(inst gcpclient.ComputeInstance) (networkID, subnetID string, addresses []string) {
	seen := map[string]bool{}
	for _, ni := range inst.NetworkInterfaces {
		if networkID == "" {
			networkID = gcpclient.ResourceName(ni.Network)
		}
		if subnetID == "" {
			subnetID = gcpclient.ResourceName(ni.Subnetwork)
		}
		if a := strings.TrimSpace(ni.NetworkIP); a != "" && !seen[a] {
			seen[a] = true
			addresses = append(addresses, a)
		}
	}
	return networkID, subnetID, addresses
}

// gcpNetworkTags returns the instance's network tags — the strings firewall
// rules select on. They are not labels and not `assets.tags`; they are the
// input to the membership computation, recorded so an operator can see why a
// rule matched.
func gcpNetworkTags(inst gcpclient.ComputeInstance) []string {
	if inst.Tags == nil {
		return nil
	}
	out := make([]string, 0, len(inst.Tags.Items))
	for _, t := range inst.Tags.Items {
		if v := strings.TrimSpace(t); v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
