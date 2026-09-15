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
	"log"
	"strings"

	gcpclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/gcp"
	"github.com/vistasecurity/vistaplatform/shared/facts"
)

// enumerateGCP runs the four listings and builds the plan.
func (s *CloudDiscoveryService) enumerateGCP(ctx context.Context, client *gcpclient.Client) (cloudEnumerationPlan, error) {
	plan := cloudEnumerationPlan{Provider: "gcp", Vendor: "GCP", SecurityGroupIDs: map[string]bool{}}

	networks, err := client.ListNetworks(ctx)
	if err != nil {
		return plan, err
	}
	subnetworks, err := client.ListSubnetworks(ctx)
	if err != nil {
		return plan, err
	}
	firewalls, err := client.ListFirewalls(ctx)
	if err != nil {
		log.Printf("[cloud enumeration] gcp: %v (instances will carry no firewall membership)", err)
		firewalls = nil
	}
	instances, err := client.ListInstances(ctx)
	if err != nil {
		return plan, err
	}

	return buildGCPEnumerationPlan(client.GetProjectID(), instances, networks, subnetworks, firewalls), nil
}

// buildGCPEnumerationPlan turns GCP's projections into the
// provider-independent plan. Pure function of its inputs.
func buildGCPEnumerationPlan(
	projectID string,
	instances []gcpclient.ComputeInstance,
	networks []gcpclient.ComputeNetwork,
	subnetworks []gcpclient.ComputeSubnetwork,
	firewalls []gcpclient.ComputeFirewall,
) cloudEnumerationPlan {
	plan := cloudEnumerationPlan{Provider: "gcp", Vendor: "GCP", SecurityGroupIDs: map[string]bool{}}

	networkName := map[string]string{}
	for _, n := range networks {
		id := gcpclient.ResourceName(n.SelfLink)
		if id == "" {
			continue
		}
		networkName[id] = id
		attrs := map[string]any{}
		if n.IPv4Range != "" {
			// Only a legacy (non-subnet) network has a range of its own. A
			// modern VPC's address space lives entirely on the subnetworks, and
			// claiming a CIDR it does not have would be an invented fact.
			attrs["cidr_blocks"] = []string{n.IPv4Range}
		}
		plan.Networks = append(plan.Networks, cloudEnumResource{
			DeviceType:  DeviceTypeGCPNetwork,
			ResourceID:  id,
			DisplayName: n.Name,
			Hostname:    n.Name,
			// GCP networks are GLOBAL: no region. `cloud.region` is omitted
			// rather than filled with the project's default, which the network
			// does not have.
			Facts: cloudPlacementFacts("gcp", projectID, "", id, id, "", nil),
			Attributes: mergeAttributes(
				cloudResourceAttributes("gcp", projectID, ""),
				attrs,
			),
			Metadata: map[string]interface{}{
				"resource_type":           "network",
				"self_link":               n.SelfLink,
				"project_id":              projectID,
				"auto_create_subnetworks": n.AutoCreateSubnetworks,
				"routing_mode":            gcpRoutingMode(n),
			},
		})
	}

	subnetByLink := map[string]gcpclient.ComputeSubnetwork{}
	for _, sn := range subnetworks {
		id := gcpclient.ResourceName(sn.SelfLink)
		if id == "" {
			continue
		}
		subnetByLink[id] = sn
		region := gcpclient.ResourceShortName(sn.Region)
		parent := gcpclient.ResourceName(sn.Network)
		if _, known := networkName[parent]; !known {
			// A subnetwork whose network was not enumerated — a Shared VPC host
			// project we cannot list — gets no containment edge rather than one
			// pointing at nothing.
			parent = ""
		}
		plan.Subnets = append(plan.Subnets, cloudEnumResource{
			DeviceType:      DeviceTypeGCPSubnetwork,
			ResourceID:      id,
			DisplayName:     sn.Name,
			Hostname:        sn.Name,
			ParentID:        parent,
			SegmentCIDR:     sn.IPCidrRange,
			CloudNetworkRef: gcpclient.ResourceName(sn.Network),
			Facts: cloudPlacementFacts("gcp", projectID, region, id,
				gcpclient.ResourceName(sn.Network), id, nil),
			Attributes: mergeAttributes(
				cloudResourceAttributes("gcp", projectID, region),
				map[string]any{"cidr_block": sn.IPCidrRange},
			),
			Metadata: map[string]interface{}{
				"resource_type":            "subnetwork",
				"self_link":                sn.SelfLink,
				"project_id":               projectID,
				"region":                   region,
				"network":                  gcpclient.ResourceName(sn.Network),
				"ip_cidr_range":            sn.IPCidrRange,
				"private_ip_google_access": sn.PrivateIPGoogleAccess,
				"purpose":                  sn.Purpose,
			},
		})
	}

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
		parent := ""
		if _, known := subnetByLink[subnetID]; known {
			parent = subnetID
		}

		factValues := cloudPlacementFacts("gcp", projectID, region, id, networkID, subnetID, groups)
		if ifaces := gcpInterfaceFact(inst); len(ifaces) > 0 {
			factValues[facts.KeyNetInterfaces] = ifaces
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
			ParentID:  parent,
			// The network, not the subnetwork: which address space the
			// instance's internal address belongs to.
			CloudNetworkRef: networkID,
			Facts:           factValues,
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

// gcpInterfaceFact renders an instance's NICs as the `net.interfaces` value.
//
// GCE states no MAC address for a NIC on the instance resource, so the `mac`
// key is absent rather than empty — "not stated" and "stated as nothing" are
// different facts, and the item schema makes only `name` required.
func gcpInterfaceFact(inst gcpclient.ComputeInstance) []map[string]any {
	out := make([]map[string]any, 0, len(inst.NetworkInterfaces))
	for _, ni := range inst.NetworkInterfaces {
		name := ni.Name
		if name == "" {
			continue
		}
		entry := map[string]any{"name": name}
		if a := strings.TrimSpace(ni.NetworkIP); a != "" {
			entry["addresses"] = []string{a}
		}
		out = append(out, entry)
	}
	return out
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

func gcpRoutingMode(n gcpclient.ComputeNetwork) string {
	if n.RoutingConfig == nil {
		return ""
	}
	return n.RoutingConfig.RoutingMode
}
