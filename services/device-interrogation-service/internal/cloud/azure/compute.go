package azure

// Azure enumeration: virtual machines, virtual networks, subnets and network
// security groups.
//
// Like the AWS half, this file is a PROJECTION BOUNDARY: every exported
// function returns a struct declared here whose fields are an explicit
// allowlist. An `armcompute.VirtualMachine` carries the whole OS profile —
// including `osProfile.adminPassword` and `osProfile.customData`, which is
// Azure's user-data field and is base64 of whatever bootstrap script the
// customer wrote. Neither is projected, and neither is read.
//
// `armnetwork.SecurityGroup` carries `properties.securityRules`. Those are NOT
// projected: `cloud.security_groups` is membership, never the rules inside the
// group (standards/fact-keys.yaml).

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"

	"github.com/vistasecurity/vistaplatform/shared/redact"
)

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

// GetVirtualMachinesClient returns an armcompute VirtualMachines client.
func (c *Client) GetVirtualMachinesClient() (*armcompute.VirtualMachinesClient, error) {
	client, err := armcompute.NewVirtualMachinesClient(c.subscriptionID, c.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create virtual machines client: %w", err)
	}
	return client, nil
}

// GetVirtualNetworksClient returns an armnetwork VirtualNetworks client.
func (c *Client) GetVirtualNetworksClient() (*armnetwork.VirtualNetworksClient, error) {
	client, err := armnetwork.NewVirtualNetworksClient(c.subscriptionID, c.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create virtual networks client: %w", err)
	}
	return client, nil
}

// GetNetworkSecurityGroupsClient returns an armnetwork SecurityGroups client.
func (c *Client) GetNetworkSecurityGroupsClient() (*armnetwork.SecurityGroupsClient, error) {
	client, err := armnetwork.NewSecurityGroupsClient(c.subscriptionID, c.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create network security groups client: %w", err)
	}
	return client, nil
}

// GetNetworkInterfacesClient returns an armnetwork Interfaces client.
func (c *Client) GetNetworkInterfacesClient() (*armnetwork.InterfacesClient, error) {
	client, err := armnetwork.NewInterfacesClient(c.subscriptionID, c.credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create network interfaces client: %w", err)
	}
	return client, nil
}

// ---------------------------------------------------------------------------
// Projections
// ---------------------------------------------------------------------------

// SecurityGroupRef is an NSG a resource is attached to — the shape
// `cloud.security_groups` declares. `Name` is the NSG's resource name; `ID` is
// its full Azure resource id, which is what is unique across the subscription.
type SecurityGroupRef struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// NetworkInterface is one NIC, projected onto the `net.interfaces` shape.
type NetworkInterface struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	MAC       string   `json:"mac,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	SubnetID  string   `json:"subnet_id,omitempty"`
	// NSG is the NSG attached to the NIC itself. A VM can also inherit one from
	// its subnet; both are recorded as membership, neither is a rule.
	NSG *SecurityGroupRef `json:"nsg,omitempty"`
	// VirtualMachineID is the VM this NIC is attached to, as an Azure resource
	// id. It is how a NIC's MAC and address reach the right VM: the VM's own
	// payload names its NICs by id and carries no addressing of its own.
	VirtualMachineID string `json:"virtual_machine_id,omitempty"`
}

// VirtualMachine is an Azure VM, projected.
//
// OperatingSystem/OSVersion are deliberately absent — see the note on
// [VirtualMachine.OSType]. `VMID` is Azure's per-VM UUID, which is the value
// the guest reads back through IMDS and therefore the join between a VM
// enumerated here and the same machine reporting from inside.
type VirtualMachine struct {
	ResourceID string `json:"resource_id"`
	Name       string `json:"name"`
	Location   string `json:"location,omitempty"`
	// SubscriptionID and ResourceGroup are parsed out of the resource id rather
	// than taken from the client, so a VM in a subscription the credential can
	// see but was not configured for is still attributed correctly.
	SubscriptionID string `json:"subscription_id,omitempty"`
	ResourceGroup  string `json:"resource_group,omitempty"`
	VMSize         string `json:"vm_size,omitempty"`
	VMID           string `json:"vm_id,omitempty"`
	// OSType is what Azure states: "Linux" or "Windows". It is a FAMILY, not a
	// product, and is therefore never written to the `os.name` fact — that key
	// is the join into the end-of-life catalogue and a family there would match
	// nothing while looking like an answer.
	OSType            string            `json:"os_type,omitempty"`
	ImageReference    string            `json:"image_reference,omitempty"`
	ProvisioningState string            `json:"provisioning_state,omitempty"`
	NetworkInterfaces []string          `json:"network_interface_ids,omitempty"`
	Zones             []string          `json:"zones,omitempty"`
	Tags              map[string]string `json:"tags,omitempty"`
	// Resolved from the NIC listing; empty when the NICs could not be read.
	PrivateIPs []string           `json:"private_ips,omitempty"`
	Interfaces []NetworkInterface `json:"interfaces,omitempty"`
	SubnetIDs  []string           `json:"subnet_ids,omitempty"`
	NSGs       []SecurityGroupRef `json:"nsgs,omitempty"`
}

// VirtualNetwork is a VNet, projected.
type VirtualNetwork struct {
	ResourceID      string            `json:"resource_id"`
	Name            string            `json:"name"`
	Location        string            `json:"location,omitempty"`
	SubscriptionID  string            `json:"subscription_id,omitempty"`
	ResourceGroup   string            `json:"resource_group,omitempty"`
	AddressPrefixes []string          `json:"address_prefixes,omitempty"`
	Tags            map[string]string `json:"tags,omitempty"`
	Subnets         []Subnet          `json:"-"`
}

// Subnet is a VNet subnet, projected. Azure returns subnets INSIDE the VNet
// payload, so enumerating them costs no extra call.
type Subnet struct {
	ResourceID      string            `json:"resource_id"`
	Name            string            `json:"name"`
	VNetID          string            `json:"vnet_id,omitempty"`
	SubscriptionID  string            `json:"subscription_id,omitempty"`
	ResourceGroup   string            `json:"resource_group,omitempty"`
	Location        string            `json:"location,omitempty"`
	AddressPrefixes []string          `json:"address_prefixes,omitempty"`
	NSG             *SecurityGroupRef `json:"nsg,omitempty"`
}

// NetworkSecurityGroup is an NSG as an ATTRIBUTE source: identity and placement
// only. The rules are not collected.
type NetworkSecurityGroup struct {
	ResourceID     string            `json:"resource_id"`
	Name           string            `json:"name"`
	Location       string            `json:"location,omitempty"`
	SubscriptionID string            `json:"subscription_id,omitempty"`
	ResourceGroup  string            `json:"resource_group,omitempty"`
	Tags           map[string]string `json:"tags,omitempty"`
}

// ---------------------------------------------------------------------------
// List calls
// ---------------------------------------------------------------------------

// ListVirtualMachines enumerates every VM in the subscription.
//
// `nics` is the output of [ListNetworkInterfaces], indexed by NIC resource id
// (lower-cased). It is passed in rather than fetched here because the NIC list
// is ONE call for the whole subscription, while resolving each VM's NICs
// individually would be one call per NIC. Pass nil to skip NIC resolution; the
// VMs then carry no addresses, which is honest — Azure's VM payload has none.
func ListVirtualMachines(ctx context.Context, client *armcompute.VirtualMachinesClient, nics map[string]NetworkInterface) ([]VirtualMachine, error) {
	var out []VirtualMachine
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list Azure virtual machines: %w", err)
		}
		for _, vm := range page.Value {
			projected := projectVirtualMachine(vm, nics)
			if projected.ResourceID == "" {
				continue
			}
			out = append(out, projected)
		}
	}
	return out, nil
}

// ListVirtualNetworks enumerates every VNet in the subscription, with its
// subnets.
func ListVirtualNetworks(ctx context.Context, client *armnetwork.VirtualNetworksClient) ([]VirtualNetwork, error) {
	var out []VirtualNetwork
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list Azure virtual networks: %w", err)
		}
		for _, vnet := range page.Value {
			projected := projectVirtualNetwork(vnet)
			if projected.ResourceID == "" {
				continue
			}
			out = append(out, projected)
		}
	}
	return out, nil
}

// ListNetworkSecurityGroups enumerates every NSG in the subscription.
func ListNetworkSecurityGroups(ctx context.Context, client *armnetwork.SecurityGroupsClient) ([]NetworkSecurityGroup, error) {
	var out []NetworkSecurityGroup
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list Azure network security groups: %w", err)
		}
		for _, nsg := range page.Value {
			projected := projectNetworkSecurityGroup(nsg)
			if projected.ResourceID == "" {
				continue
			}
			out = append(out, projected)
		}
	}
	return out, nil
}

// ListNetworkInterfaces enumerates every NIC in the subscription, keyed by
// lower-cased resource id.
func ListNetworkInterfaces(ctx context.Context, client *armnetwork.InterfacesClient) (map[string]NetworkInterface, error) {
	out := map[string]NetworkInterface{}
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list Azure network interfaces: %w", err)
		}
		for _, nic := range page.Value {
			projected := projectNetworkInterface(nic)
			if projected.ID == "" {
				continue
			}
			out[strings.ToLower(projected.ID)] = projected
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Projection functions — the allowlist
// ---------------------------------------------------------------------------

func projectVirtualMachine(vm *armcompute.VirtualMachine, nics map[string]NetworkInterface) VirtualMachine {
	if vm == nil {
		return VirtualMachine{}
	}
	id := derefString(vm.ID)
	out := VirtualMachine{
		ResourceID:     id,
		Name:           derefString(vm.Name),
		Location:       derefString(vm.Location),
		SubscriptionID: ResourceIDSegment(id, "subscriptions"),
		ResourceGroup:  ResourceIDSegment(id, "resourceGroups"),
		Tags:           projectAzureTags(vm.Tags),
	}
	for _, z := range vm.Zones {
		if v := derefString(z); v != "" {
			out.Zones = append(out.Zones, v)
		}
	}
	p := vm.Properties
	if p == nil {
		return out
	}
	out.VMID = derefString(p.VMID)
	out.ProvisioningState = derefString(p.ProvisioningState)
	if p.HardwareProfile != nil && p.HardwareProfile.VMSize != nil {
		out.VMSize = string(*p.HardwareProfile.VMSize)
	}
	if p.StorageProfile != nil {
		if p.StorageProfile.OSDisk != nil && p.StorageProfile.OSDisk.OSType != nil {
			out.OSType = string(*p.StorageProfile.OSDisk.OSType)
		}
		out.ImageReference = imageReferenceString(p.StorageProfile.ImageReference)
	}

	seenIP := map[string]bool{}
	seenSubnet := map[string]bool{}
	seenNSG := map[string]bool{}
	if p.NetworkProfile != nil {
		for _, ref := range p.NetworkProfile.NetworkInterfaces {
			nicID := derefString(ref.ID)
			if nicID == "" {
				continue
			}
			out.NetworkInterfaces = append(out.NetworkInterfaces, nicID)
			nic, ok := nics[strings.ToLower(nicID)]
			if !ok {
				continue
			}
			out.Interfaces = append(out.Interfaces, nic)
			for _, a := range nic.Addresses {
				if a != "" && !seenIP[a] {
					seenIP[a] = true
					out.PrivateIPs = append(out.PrivateIPs, a)
				}
			}
			if nic.SubnetID != "" && !seenSubnet[strings.ToLower(nic.SubnetID)] {
				seenSubnet[strings.ToLower(nic.SubnetID)] = true
				out.SubnetIDs = append(out.SubnetIDs, nic.SubnetID)
			}
			if nic.NSG != nil && nic.NSG.ID != "" && !seenNSG[strings.ToLower(nic.NSG.ID)] {
				seenNSG[strings.ToLower(nic.NSG.ID)] = true
				out.NSGs = append(out.NSGs, *nic.NSG)
			}
		}
	}
	return out
}

func projectVirtualNetwork(vnet *armnetwork.VirtualNetwork) VirtualNetwork {
	if vnet == nil {
		return VirtualNetwork{}
	}
	id := derefString(vnet.ID)
	out := VirtualNetwork{
		ResourceID:     id,
		Name:           derefString(vnet.Name),
		Location:       derefString(vnet.Location),
		SubscriptionID: ResourceIDSegment(id, "subscriptions"),
		ResourceGroup:  ResourceIDSegment(id, "resourceGroups"),
		Tags:           projectAzureTags(vnet.Tags),
	}
	if vnet.Properties == nil {
		return out
	}
	if vnet.Properties.AddressSpace != nil {
		for _, prefix := range vnet.Properties.AddressSpace.AddressPrefixes {
			if v := derefString(prefix); v != "" {
				out.AddressPrefixes = append(out.AddressPrefixes, v)
			}
		}
	}
	for _, sn := range vnet.Properties.Subnets {
		projected := projectSubnet(sn, out)
		if projected.ResourceID == "" {
			continue
		}
		out.Subnets = append(out.Subnets, projected)
	}
	return out
}

func projectSubnet(sn *armnetwork.Subnet, parent VirtualNetwork) Subnet {
	if sn == nil {
		return Subnet{}
	}
	id := derefString(sn.ID)
	out := Subnet{
		ResourceID:     id,
		Name:           derefString(sn.Name),
		VNetID:         parent.ResourceID,
		SubscriptionID: ResourceIDSegment(id, "subscriptions"),
		ResourceGroup:  ResourceIDSegment(id, "resourceGroups"),
		// A subnet has no location of its own; it is wherever its VNet is.
		Location: parent.Location,
	}
	if sn.Properties == nil {
		return out
	}
	if v := derefString(sn.Properties.AddressPrefix); v != "" {
		out.AddressPrefixes = append(out.AddressPrefixes, v)
	}
	for _, prefix := range sn.Properties.AddressPrefixes {
		if v := derefString(prefix); v != "" && v != derefString(sn.Properties.AddressPrefix) {
			out.AddressPrefixes = append(out.AddressPrefixes, v)
		}
	}
	if nsg := sn.Properties.NetworkSecurityGroup; nsg != nil {
		out.NSG = securityGroupRef(derefString(nsg.ID), derefString(nsg.Name))
	}
	return out
}

func projectNetworkSecurityGroup(nsg *armnetwork.SecurityGroup) NetworkSecurityGroup {
	if nsg == nil {
		return NetworkSecurityGroup{}
	}
	id := derefString(nsg.ID)
	return NetworkSecurityGroup{
		ResourceID:     id,
		Name:           derefString(nsg.Name),
		Location:       derefString(nsg.Location),
		SubscriptionID: ResourceIDSegment(id, "subscriptions"),
		ResourceGroup:  ResourceIDSegment(id, "resourceGroups"),
		Tags:           projectAzureTags(nsg.Tags),
		// NB: nsg.Properties.SecurityRules is deliberately not read.
	}
}

func projectNetworkInterface(nic *armnetwork.Interface) NetworkInterface {
	if nic == nil {
		return NetworkInterface{}
	}
	out := NetworkInterface{
		ID:   derefString(nic.ID),
		Name: derefString(nic.Name),
	}
	if nic.Properties == nil {
		return out
	}
	out.MAC = normalizeAzureMAC(derefString(nic.Properties.MacAddress))
	if vm := nic.Properties.VirtualMachine; vm != nil {
		out.VirtualMachineID = derefString(vm.ID)
	}
	if nsg := nic.Properties.NetworkSecurityGroup; nsg != nil {
		out.NSG = securityGroupRef(derefString(nsg.ID), derefString(nsg.Name))
	}
	for _, cfg := range nic.Properties.IPConfigurations {
		if cfg == nil || cfg.Properties == nil {
			continue
		}
		if addr := derefString(cfg.Properties.PrivateIPAddress); addr != "" {
			out.Addresses = append(out.Addresses, addr)
		}
		// The PUBLIC address is deliberately not projected here: a NIC's public
		// IP belongs to a separate resource whose payload we do not read, and
		// an instance's public exposure is a posture question answered by
		// probing, not by an inventory field.
		if sn := cfg.Properties.Subnet; sn != nil && out.SubnetID == "" {
			out.SubnetID = derefString(sn.ID)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ResourceIDSegment pulls one path segment's VALUE out of an Azure resource id.
//
// An Azure resource id is `/subscriptions/<sub>/resourceGroups/<rg>/providers/...`
// — a flat, case-insensitively-keyed path. This reads the value that follows
// the named key, or "" when the id does not carry it.
//
// It exists because the subscription and resource group are the only place
// Azure states a VM's account and its grouping, and parsing them out of the id
// the API returned is more truthful than assuming the client's configured
// subscription: a service principal with rights across several subscriptions
// lists VMs from all of them.
func ResourceIDSegment(resourceID, key string) string {
	parts := strings.Split(strings.TrimPrefix(resourceID, "/"), "/")
	for i := 0; i+1 < len(parts); i += 2 {
		if strings.EqualFold(parts[i], key) {
			return parts[i+1]
		}
	}
	return ""
}

// imageReferenceString renders an Azure image reference as the
// publisher:offer:sku:version form the portal and the CLI both use, or the
// gallery/custom image id when that is what the VM was built from.
//
// It is an IMAGE identity, recorded as such. It is never turned into `os.name`:
// the image a VM booted from two years ago does not say what it is running now,
// and the EOL catalogue join has to be on something the host states about
// itself (which the host agent, ADR-0004 D3, is what provides).
func imageReferenceString(ref *armcompute.ImageReference) string {
	if ref == nil {
		return ""
	}
	if id := derefString(ref.CommunityGalleryImageID); id != "" {
		return id
	}
	if id := derefString(ref.SharedGalleryImageID); id != "" {
		return id
	}
	parts := []string{
		derefString(ref.Publisher), derefString(ref.Offer),
		derefString(ref.SKU), derefString(ref.Version),
	}
	joined := strings.Trim(strings.Join(parts, ":"), ":")
	if strings.Trim(joined, ":") == "" {
		return derefString(ref.ID)
	}
	return joined
}

// normalizeAzureMAC turns Azure's "00-0D-3A-1B-2C-3D" into the colon-separated
// lower-case form every other producer uses. A MAC spelled two ways is two
// identifiers for one interface.
func normalizeAzureMAC(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	return strings.ToLower(strings.ReplaceAll(v, "-", ":"))
}

// securityGroupRef builds an NSG membership reference from an inline ARM
// reference, which carries an `id` and usually nothing else.
//
// The NAME is taken from the id's last segment when ARM did not state one
// separately. That is not a guess: an Azure resource id ends in the resource's
// own name by construction, so reading it back is the same fact in a different
// place. Without it every inline reference would carry a blank name and the
// membership fact would render as a bare id in the UI.
func securityGroupRef(id, name string) *SecurityGroupRef {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = ResourceShortName(id)
	}
	return &SecurityGroupRef{ID: id, Name: name}
}

// ResourceShortName returns the last segment of an Azure resource id — the
// resource's own name.
func ResourceShortName(resourceID string) string {
	v := strings.TrimRight(strings.TrimSpace(resourceID), "/")
	if idx := strings.LastIndex(v, "/"); idx >= 0 {
		return v[idx+1:]
	}
	return v
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return strings.TrimSpace(*p)
}

// projectAzureTags copies an Azure tag map, masking values whose KEY looks like
// a secret. Same reasoning as the AWS half: a tag name is the customer's, so
// projection cannot pre-empt it and the name-based backstop is the primary
// defence.
func projectAzureTags(tags map[string]*string) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	out := make(map[string]string, len(tags))
	for k, v := range tags {
		key := strings.TrimSpace(k)
		if key == "" {
			continue
		}
		out[key] = redact.String(key, derefString(v))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
