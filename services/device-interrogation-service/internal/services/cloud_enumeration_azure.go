package services

// Azure half of workstream 2.4: virtual machines, virtual networks, subnets and
// network security groups.
//
// The API calls, and the Azure RBAC actions a customer has to grant:
//
//	Microsoft.Compute/virtualMachines/read        virtual machines
//	Microsoft.Network/virtualNetworks/read        VNets (and their subnets,
//	                                              which ARM returns inline)
//	Microsoft.Network/networkSecurityGroups/read  NSG membership
//	Microsoft.Network/networkInterfaces/read      NIC MAC, private addresses,
//	                                              and the VM ↔ subnet link
//
// All four are in the built-in **Reader** role. The VM's own payload carries no
// addressing at all — a VM names its NICs by resource id and nothing else —
// which is why the NIC listing is not optional on Azure the way the security
// groups are on AWS.
//
// Subnets cost no call of their own: ARM returns them inside the VNet.

import (
	"context"
	"log"
	"strings"

	azureclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/azure"
	"github.com/vistasecurity/vistaplatform/shared/facts"
)

// enumerateAzure runs the four listings and builds the plan.
func (s *CloudDiscoveryService) enumerateAzure(ctx context.Context, client *azureclient.Client) (cloudEnumerationPlan, error) {
	plan := cloudEnumerationPlan{Provider: "azure", Vendor: "Azure", SecurityGroupIDs: map[string]bool{}}

	vnetClient, err := client.GetVirtualNetworksClient()
	if err != nil {
		return plan, err
	}
	vnets, err := azureclient.ListVirtualNetworks(ctx, vnetClient)
	if err != nil {
		return plan, err
	}

	nsgClient, err := client.GetNetworkSecurityGroupsClient()
	if err != nil {
		return plan, err
	}
	nsgs, err := azureclient.ListNetworkSecurityGroups(ctx, nsgClient)
	if err != nil {
		// Membership is an attribute, not the inventory.
		log.Printf("[cloud enumeration] azure: %v (resources will carry no NSG membership from the NSG listing)", err)
		nsgs = nil
	}

	nicClient, err := client.GetNetworkInterfacesClient()
	if err != nil {
		return plan, err
	}
	nics, err := azureclient.ListNetworkInterfaces(ctx, nicClient)
	if err != nil {
		// Without NICs a VM has no address and no subnet. It is still recorded
		// — its resource id is its identity — but it will not be placed, and
		// saying so beats a silently unplaced fleet.
		log.Printf("[cloud enumeration] azure: %v (VMs will carry no addresses and no subnet containment)", err)
		nics = nil
	}

	vmClient, err := client.GetVirtualMachinesClient()
	if err != nil {
		return plan, err
	}
	vms, err := azureclient.ListVirtualMachines(ctx, vmClient, nics)
	if err != nil {
		return plan, err
	}

	return buildAzureEnumerationPlan(vms, vnets, nsgs), nil
}

// buildAzureEnumerationPlan turns Azure's projections into the
// provider-independent plan. Pure function of its inputs.
func buildAzureEnumerationPlan(
	vms []azureclient.VirtualMachine,
	vnets []azureclient.VirtualNetwork,
	nsgs []azureclient.NetworkSecurityGroup,
) cloudEnumerationPlan {
	plan := cloudEnumerationPlan{Provider: "azure", Vendor: "Azure", SecurityGroupIDs: map[string]bool{}}

	// Azure resource ids are case-insensitive; the API echoes `resourceGroups`
	// and `resourcegroups` for the same group depending on which surface
	// produced the reference. Indexing case-folded is what stops a VM's NIC
	// pointing at a subnet the plan already holds under a differently-cased id.
	subnetByID := map[string]azureclient.Subnet{}

	for _, nsg := range nsgs {
		if nsg.ResourceID != "" {
			plan.SecurityGroupIDs[strings.ToLower(nsg.ResourceID)] = true
		}
	}

	for _, vnet := range vnets {
		if vnet.ResourceID == "" {
			continue
		}
		plan.Networks = append(plan.Networks, cloudEnumResource{
			DeviceType:  DeviceTypeAzureVNet,
			ResourceID:  vnet.ResourceID,
			DisplayName: vnet.Name,
			Hostname:    vnet.Name,
			Facts: cloudPlacementFacts("azure", vnet.SubscriptionID, vnet.Location, vnet.ResourceID,
				vnet.ResourceID, "", nil),
			Attributes: mergeAttributes(
				cloudResourceAttributes("azure", vnet.SubscriptionID, vnet.Location),
				map[string]any{"cidr_blocks": vnet.AddressPrefixes},
			),
			Tags: tagsToJSONB(vnet.Tags),
			Metadata: map[string]interface{}{
				"resource_type":     "virtual_network",
				"region":            vnet.Location,
				"azure_resource_id": vnet.ResourceID,
				"resource_group":    vnet.ResourceGroup,
				"address_prefixes":  vnet.AddressPrefixes,
			},
		})

		for _, sn := range vnet.Subnets {
			if sn.ResourceID == "" {
				continue
			}
			subnetByID[strings.ToLower(sn.ResourceID)] = sn
			var subnetNSGs []map[string]any
			if sn.NSG != nil && sn.NSG.ID != "" {
				plan.SecurityGroupIDs[strings.ToLower(sn.NSG.ID)] = true
				subnetNSGs = []map[string]any{securityGroupEntry(sn.NSG.ID, sn.NSG.Name)}
			}
			plan.Subnets = append(plan.Subnets, cloudEnumResource{
				DeviceType:      DeviceTypeAzureSubnet,
				ResourceID:      sn.ResourceID,
				DisplayName:     sn.Name,
				Hostname:        sn.Name,
				ParentID:        vnet.ResourceID,
				SegmentCIDR:     firstAddress(sn.AddressPrefixes),
				CloudNetworkRef: vnet.ResourceID,
				Facts: cloudPlacementFacts("azure", sn.SubscriptionID, sn.Location, sn.ResourceID,
					vnet.ResourceID, sn.ResourceID, subnetNSGs),
				Attributes: mergeAttributes(
					cloudResourceAttributes("azure", sn.SubscriptionID, sn.Location),
					map[string]any{"cidr_block": firstAddress(sn.AddressPrefixes)},
				),
				Metadata: map[string]interface{}{
					"resource_type":     "subnet",
					"region":            sn.Location,
					"azure_resource_id": sn.ResourceID,
					"resource_group":    sn.ResourceGroup,
					"vnet_id":           vnet.ResourceID,
					"address_prefixes":  sn.AddressPrefixes,
				},
			})
		}
	}

	for _, vm := range vms {
		if vm.ResourceID == "" {
			continue
		}
		groups := make([]map[string]any, 0, len(vm.NSGs))
		for _, g := range vm.NSGs {
			plan.SecurityGroupIDs[strings.ToLower(g.ID)] = true
			groups = append(groups, securityGroupEntry(g.ID, g.Name))
		}

		// The VM's subnet, and therefore its containment. A VM with several
		// NICs in several subnets is placed in the FIRST — an asset has one
		// container — and the rest are still visible on net.interfaces.
		subnetID := firstAddress(vm.SubnetIDs)
		parent := ""
		if sn, ok := subnetByID[strings.ToLower(subnetID)]; ok {
			parent = sn.ResourceID
			// Inherit the subnet's NSG as membership too: an Azure VM is
			// governed by both its NIC's NSG and its subnet's.
			if sn.NSG != nil && sn.NSG.ID != "" && !containsGroup(groups, sn.NSG.ID) {
				plan.SecurityGroupIDs[strings.ToLower(sn.NSG.ID)] = true
				groups = append(groups, securityGroupEntry(sn.NSG.ID, sn.NSG.Name))
			}
		}

		vnetID := ""
		if subnetID != "" {
			// A subnet's id is its VNet's id plus `/subnets/<name>`.
			if idx := strings.LastIndex(strings.ToLower(subnetID), "/subnets/"); idx > 0 {
				vnetID = subnetID[:idx]
			}
		}

		factValues := cloudPlacementFacts("azure", vm.SubscriptionID, vm.Location, vm.ResourceID,
			vnetID, subnetID, groups)
		if ifaces := azureInterfaceFact(vm); len(ifaces) > 0 {
			factValues[facts.KeyNetInterfaces] = ifaces
		}
		if vm.VMID != "" {
			// Azure's per-VM UUID is what the guest reads back through IMDS, so
			// it is the join between a VM enumerated from outside and the same
			// machine reporting from inside.
			factValues[facts.KeyHWUUID] = vm.VMID
		}

		plan.Instances = append(plan.Instances, cloudEnumResource{
			DeviceType:  DeviceTypeAzureVM,
			ResourceID:  vm.ResourceID,
			DisplayName: vm.Name,
			// Azure states no DNS name for a VM on the compute API — the name
			// a VM answers to lives on its NIC's dnsSettings, which is a
			// different resource and an Azure-internal suffix. The VM's
			// resource NAME is a label, so it is the display name and not the
			// hostname.
			IPAddress: firstAddress(vm.PrivateIPs),
			ParentID:  parent,
			// The VNet the VM's NIC sits in, derived from the subnet id above.
			CloudNetworkRef: vnetID,
			Facts:           factValues,
			Attributes: mergeAttributes(
				cloudResourceAttributes("azure", vm.SubscriptionID, vm.Location),
				map[string]any{
					"instance_type": vm.VMSize,
					"image_id":      vm.ImageReference,
					// operating_system / os_version absent: Azure states an OS
					// FAMILY ("Linux") on the OS disk, which is not a product
					// name, and an image reference is what the VM booted from
					// rather than what it runs now.
				},
			),
			Tags: tagsToJSONB(vm.Tags),
			Metadata: map[string]interface{}{
				"resource_type":      "virtual_machine",
				"region":             vm.Location,
				"azure_resource_id":  vm.ResourceID,
				"resource_group":     vm.ResourceGroup,
				"vm_size":            vm.VMSize,
				"vm_id":              vm.VMID,
				"os_type":            vm.OSType,
				"image_reference":    vm.ImageReference,
				"provisioning_state": vm.ProvisioningState,
				"zones":              vm.Zones,
			},
		})
	}
	return plan
}

// azureInterfaceFact renders a VM's NICs as the `net.interfaces` value.
func azureInterfaceFact(vm azureclient.VirtualMachine) []map[string]any {
	out := make([]map[string]any, 0, len(vm.Interfaces))
	for _, iface := range vm.Interfaces {
		name := iface.Name
		if name == "" {
			name = iface.ID
		}
		if name == "" {
			continue
		}
		entry := map[string]any{"name": name}
		if iface.MAC != "" {
			entry["mac"] = iface.MAC
		}
		if len(iface.Addresses) > 0 {
			entry["addresses"] = iface.Addresses
		}
		out = append(out, entry)
	}
	return out
}

func securityGroupEntry(id, name string) map[string]any {
	entry := map[string]any{"id": id}
	if strings.TrimSpace(name) != "" {
		entry["name"] = name
	}
	return entry
}

func containsGroup(groups []map[string]any, id string) bool {
	for _, g := range groups {
		if existing, ok := g["id"].(string); ok && strings.EqualFold(existing, id) {
			return true
		}
	}
	return false
}
