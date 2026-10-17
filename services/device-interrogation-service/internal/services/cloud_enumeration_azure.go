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
	"errors"
	"strings"

	azureclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/azure"
	"github.com/vistasecurity/vistaplatform/shared/facts"
)

// enumerateAzure runs the selected listings and builds the plan.
//
// Every Azure listing is subscription-wide, so each type has one `global` row
// for the call plus one row per location its resources turned out to be in
// (asset-inventory ADR-0009 D3). A listing that fails is recorded and the
// others still run: a credential without networkSecurityGroups/read loses the
// group membership, not the VMs.
func (s *CloudDiscoveryService) enumerateAzure(ctx context.Context, client *azureclient.Client, sel cloudEnumerationSelection) (cloudEnumerationPlan, error) {
	plan := cloudEnumerationPlan{Provider: "azure", Vendor: "Azure", SecurityGroupIDs: map[string]bool{}}
	outcomes := cloudOutcomesFrom(ctx)

	var (
		vnets []azureclient.VirtualNetwork
		nsgs  []azureclient.NetworkSecurityGroup
		vms   []azureclient.VirtualMachine
	)
	if sel.needsNetworks() {
		vnetClient, err := client.GetVirtualNetworksClient()
		if err == nil {
			vnets, err = azureclient.ListVirtualNetworks(ctx, vnetClient)
		}
		outcomes.Attempt(CloudTypeNetworks, cloudScopeGlobal, len(vnets), err)
		logCloudCollectorFailure(CloudTypeNetworks, cloudScopeGlobal, err)
		if err == nil {
			per := map[string]int{}
			for _, v := range vnets {
				per[v.Location]++
			}
			outcomes.AttributeRegions(CloudTypeNetworks, per)
		}
	}
	if sel.needsGroups() {
		nsgClient, err := client.GetNetworkSecurityGroupsClient()
		if err == nil {
			nsgs, err = azureclient.ListNetworkSecurityGroups(ctx, nsgClient)
		}
		outcomes.Attempt(CloudTypeSecurityGroups, cloudScopeGlobal, len(nsgs), err)
		logCloudCollectorFailure(CloudTypeSecurityGroups, cloudScopeGlobal, err)
		if err == nil {
			per := map[string]int{}
			for _, g := range nsgs {
				per[g.Location]++
			}
			outcomes.AttributeRegions(CloudTypeSecurityGroups, per)
		}
	}
	if sel.Instances {
		// The NIC listing is part of the instance listing: a VM's payload
		// names its NICs by id and nothing else. Without NICs a VM is still
		// recorded (its resource id is its identity) but unplaced, and that
		// is a PARTIAL instance listing, not a clean one.
		var nics map[string]azureclient.NetworkInterface
		nicClient, nicErr := client.GetNetworkInterfacesClient()
		if nicErr == nil {
			nics, nicErr = azureclient.ListNetworkInterfaces(ctx, nicClient)
		}
		vmClient, err := client.GetVirtualMachinesClient()
		if err == nil {
			vms, err = azureclient.ListVirtualMachines(ctx, vmClient, nics)
		}
		if err == nil && nicErr != nil {
			outcomes.AttemptPartial(CloudTypeComputeInstances, cloudScopeGlobal, len(vms), nicErr)
		} else {
			outcomes.Attempt(CloudTypeComputeInstances, cloudScopeGlobal, len(vms), err)
		}
		logCloudCollectorFailure(CloudTypeComputeInstances, cloudScopeGlobal, errors.Join(err, nicErr))
		if err == nil {
			per := map[string]int{}
			for _, vm := range vms {
				per[vm.Location]++
			}
			outcomes.AttributeRegions(CloudTypeComputeInstances, per)
		}
	}

	plan = buildAzureEnumerationPlan(vms, vnets, nsgs)
	for i := range plan.Instances {
		plan.Instances[i].annotateListing(CloudListingKey(CloudTypeComputeInstances, cloudScopeGlobal))
	}
	azureSecurityGroups(&plan, nsgs)
	return plan, nil
}

// buildAzureEnumerationPlan turns Azure's projections into the
// provider-independent plan. Pure function of its inputs.
//
// VNets and their subnets become prefixes carrying the VNet's resource id as
// `cloud_network_ref` (DCIM row 1.5f); each VM's NICs become `virtual`
// interfaces named by the NIC's resource name, with their private addresses.
// Azure's NIC listing names a public address only by the public-IP
// resource's id, so no NAT-outside address is recorded for a VM.
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
		plan.Networks = append(plan.Networks, cloudNetwork{
			ResourceID: vnet.ResourceID,
			NetworkRef: vnet.ResourceID,
			Account:    vnet.SubscriptionID,
			Region:     vnet.Location,
			Name:       vnet.Name,
			CIDRs:      vnet.AddressPrefixes,
		})
		for _, sn := range vnet.Subnets {
			if sn.ResourceID == "" {
				continue
			}
			subnetByID[strings.ToLower(sn.ResourceID)] = sn
			if sn.NSG != nil && sn.NSG.ID != "" {
				plan.SecurityGroupIDs[strings.ToLower(sn.NSG.ID)] = true
			}
			plan.Subnets = append(plan.Subnets, cloudNetwork{
				ResourceID: sn.ResourceID,
				NetworkRef: vnet.ResourceID,
				Account:    sn.SubscriptionID,
				Region:     sn.Location,
				Name:       sn.Name,
				CIDRs:      sn.AddressPrefixes,
			})
		}
	}
	lengths := subnetPrefixLengths(plan.Subnets)

	for _, vm := range vms {
		if vm.ResourceID == "" {
			continue
		}
		groups := make([]map[string]any, 0, len(vm.NSGs))
		for _, g := range vm.NSGs {
			plan.SecurityGroupIDs[strings.ToLower(g.ID)] = true
			groups = append(groups, securityGroupEntry(g.ID, g.Name))
		}
		// Inherit each NIC subnet's NSG as membership too: an Azure VM is
		// governed by both its NIC's NSG and its subnet's.
		for _, subnetID := range vm.SubnetIDs {
			if sn, ok := subnetByID[strings.ToLower(subnetID)]; ok && sn.NSG != nil && sn.NSG.ID != "" && !containsGroup(groups, sn.NSG.ID) {
				plan.SecurityGroupIDs[strings.ToLower(sn.NSG.ID)] = true
				groups = append(groups, securityGroupEntry(sn.NSG.ID, sn.NSG.Name))
			}
		}

		nics := make([]cloudNIC, 0, len(vm.Interfaces))
		for _, iface := range vm.Interfaces {
			name := firstNonEmpty(iface.Name, iface.ID)
			nics = append(nics, cloudNIC{Name: name, MAC: iface.MAC, Addresses: iface.Addresses, Subnet: iface.SubnetID})
		}
		// The VNet the VM's first NIC sits in: a subnet's id is its VNet's id
		// plus `/subnets/<name>`.
		vnetID := azureVNetOfSubnet(firstAddress(vm.SubnetIDs))

		factValues := cloudPlacementFacts("azure", vm.SubscriptionID, vm.Location, vm.ResourceID, groups)
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
			IPAddress:       firstAddress(vm.PrivateIPs),
			CloudNetworkRef: vnetID,
			Interfaces:      cloudInterfaces(nics, lengths),
			Prefixes:        instancePrefixes(vnetID, nics, plan.Networks, plan.Subnets),
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

// azureVNetOfSubnet is the VNet a subnet id belongs to, "" when it is not a
// subnet id.
func azureVNetOfSubnet(subnetID string) string {
	if idx := strings.LastIndex(strings.ToLower(subnetID), "/subnets/"); idx > 0 {
		return subnetID[:idx]
	}
	return ""
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
