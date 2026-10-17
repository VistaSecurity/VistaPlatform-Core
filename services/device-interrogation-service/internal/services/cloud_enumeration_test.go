package services

import (
	"fmt"
	"sort"
	"testing"
	"time"

	awsclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/aws"
	azureclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/azure"
	gcpclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/gcp"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// The plan builders are pure functions of a provider's projections, which is
// what lets these tests pin the exact class, identifier, fact, interface and
// prefix each provider produces without a database, a credential or a network.

func findResource(t *testing.T, group []cloudEnumResource, resourceID string) cloudEnumResource {
	t.Helper()
	for _, r := range group {
		if r.ResourceID == resourceID {
			return r
		}
	}
	t.Fatalf("no resource with id %q in %d candidates", resourceID, len(group))
	return cloudEnumResource{}
}

// ---------------------------------------------------------------------------
// AWS
// ---------------------------------------------------------------------------

func awsFixture() ([]awsclient.Instance, []awsclient.VPC, []awsclient.Subnet, []awsclient.SecurityGroup) {
	const acct = "123456789012"
	vpcARN := "arn:aws:ec2:us-east-1:" + acct + ":vpc/vpc-01"
	subnetARN := "arn:aws:ec2:us-east-1:" + acct + ":subnet/subnet-01"
	instARN := "arn:aws:ec2:us-east-1:" + acct + ":instance/i-01"

	return []awsclient.Instance{{
			InstanceID:       "i-01",
			ARN:              instARN,
			AccountID:        acct,
			Region:           "us-east-1",
			InstanceType:     "m6i.large",
			State:            "running",
			PrivateDNSName:   "ip-10-0-1-20.ec2.internal",
			PrivateIPs:       []string{"10.0.1.20"},
			ImageID:          "ami-01",
			VPCID:            "vpc-01",
			SubnetID:         "subnet-01",
			AvailabilityZone: "us-east-1a",
			KeyName:          "bastion",
			SecurityGroups:   []awsclient.SecurityGroupRef{{ID: "sg-01", Name: "web"}},
			Interfaces: []awsclient.NetworkInterface{{
				Name: "eni-01", MAC: "0a:1b:2c:3d:4e:5f", Addresses: []string{"10.0.1.20"}, State: "in-use",
				SubnetID: "subnet-01", VPCID: "vpc-01", PublicIP: "203.0.113.20",
			}},
			Tags: map[string]string{"Name": "web-01", "environment": "production"},
		}}, []awsclient.VPC{{
			VPCID: "vpc-01", ARN: vpcARN, AccountID: acct, Region: "us-east-1",
			CIDRBlocks: []string{"10.0.0.0/16"}, Tags: map[string]string{"Name": "prod"},
		}}, []awsclient.Subnet{{
			SubnetID: "subnet-01", ARN: subnetARN, VPCID: "vpc-01", AccountID: acct, Region: "us-east-1",
			CIDRBlock: "10.0.1.0/24", AvailabilityZone: "us-east-1a", MapPublicIPOnLaunch: true,
		}}, []awsclient.SecurityGroup{{
			GroupID: "sg-01", GroupName: "web", VPCID: "vpc-01", AccountID: acct, Region: "us-east-1",
		}}
}

func findNetwork(t *testing.T, group []cloudNetwork, resourceID string) cloudNetwork {
	t.Helper()
	for _, n := range group {
		if n.ResourceID == resourceID {
			return n
		}
	}
	t.Fatalf("no network with id %q in %d candidates", resourceID, len(group))
	return cloudNetwork{}
}

// prefixStrings renders observed prefixes as "prefix@ref dhcp=<v>" for
// comparison.
func prefixStrings(ps []identity.ObservedPrefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		dhcp := "unset"
		if p.DHCPManaged != nil {
			dhcp = fmt.Sprint(*p.DHCPManaged)
		}
		out = append(out, p.Prefix+"@"+p.CloudNetworkRef+" type="+p.NetworkType+" dhcp="+dhcp)
	}
	sort.Strings(out)
	return out
}

func TestBuildAWSEnumerationPlan(t *testing.T) {
	instances, vpcs, subnets, groups := awsFixture()
	plan := buildAWSEnumerationPlan(instances, vpcs, subnets, groups)

	if got := plan.counts(); got != (CloudEnumerationCounts{Instances: 1, Networks: 1, Subnets: 1, SecurityGroups: 1}) {
		t.Fatalf("counts = %+v", got)
	}
	const vpcARN = "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-01"

	// The VPC and its subnet are prefixes, both in the VPC's address space
	// (row 1.5f): no asset, no class, no containment edge.
	vpc := findNetwork(t, plan.Networks, vpcARN)
	subnet := findNetwork(t, plan.Subnets, "arn:aws:ec2:us-east-1:123456789012:subnet/subnet-01")
	if vpc.NetworkRef != vpcARN || subnet.NetworkRef != vpcARN {
		t.Errorf("network refs = %q / %q, want both the VPC's ARN", vpc.NetworkRef, subnet.NetworkRef)
	}
	wantPrefixes := []string{
		"10.0.0.0/16@" + vpcARN + " type=cloud dhcp=false",
		"10.0.1.0/24@" + vpcARN + " type=cloud dhcp=false",
	}
	byAccount, order := plan.networkPrefixesByAccount()
	if len(order) != 1 || order[0] != "123456789012" {
		t.Fatalf("prefix accounts = %v", order)
	}
	if got := prefixStrings(byAccount["123456789012"]); fmt.Sprint(got) != fmt.Sprint(wantPrefixes) {
		t.Errorf("account prefixes = %v, want %v", got, wantPrefixes)
	}

	inst := findResource(t, plan.Instances, "arn:aws:ec2:us-east-1:123456789012:instance/i-01")
	if got := DeviceTypeClassKey(inst.DeviceType); got != string(assetclass.KeyComputeInstance) {
		t.Errorf("an EC2 instance must class as compute_instance, got %q", got)
	}
	if inst.CloudNetworkRef != vpcARN {
		t.Errorf("instance network = %q, want the VPC's ARN (its address space)", inst.CloudNetworkRef)
	}
	// The ENI is a virtual interface named by its id, with its address at the
	// subnet's length; the instance's sighting carries the prefixes it sits in.
	if len(inst.Interfaces) != 1 {
		t.Fatalf("interfaces = %+v", inst.Interfaces)
	}
	eni := inst.Interfaces[0]
	if eni.Name != "eni-01" || eni.Type != "virtual" || eni.MAC != "0a:1b:2c:3d:4e:5f" || eni.OperStatus != "up" {
		t.Errorf("ENI = %+v", eni)
	}
	if len(eni.Addresses) != 1 || eni.Addresses[0] != (identity.ObservedAddress{Address: "10.0.1.20", PrefixLen: 24, Source: "cloud"}) {
		t.Errorf("ENI addresses = %+v", eni.Addresses)
	}
	if got := prefixStrings(inst.Prefixes); fmt.Sprint(got) != fmt.Sprint(wantPrefixes) {
		t.Errorf("instance prefixes = %v, want %v", got, wantPrefixes)
	}
	// The public address is the NAT-outside side: on the instance, never an
	// interface address.
	if got := inst.Attributes["nat_outside_addresses"]; fmt.Sprint(got) != "[203.0.113.20]" {
		t.Errorf("nat_outside_addresses = %v", got)
	}
	// The fixture's private DNS name is EC2's IP-NAME form, which is an alias
	// of the private address and is unique only inside one VPC's resolver. It
	// is refused as a hostname — a dotted hostname becomes an unscoped `fqdn`
	// identifier, and two instances sharing a private address would then be
	// merged into one asset. The Name tag is NOT the fallback either: it is
	// duplicated across environments as a matter of routine, and a bare
	// hostname is scoped only to the tenant default.
	if inst.Hostname != "" {
		t.Errorf("hostname = %q — the IP-name form is not a hostname, and neither is the Name tag", inst.Hostname)
	}
	if inst.Metadata["private_dns_name"] != "ip-10-0-1-20.ec2.internal" {
		t.Errorf("private_dns_name metadata = %v — refusing it as a hostname must not discard it",
			inst.Metadata["private_dns_name"])
	}
	if inst.DisplayName != "web-01" {
		t.Errorf("display name = %q, want the Name tag", inst.DisplayName)
	}
	if inst.IPAddress != "10.0.1.20" {
		t.Errorf("primary address = %q", inst.IPAddress)
	}

	// Facts: the cloud.* placement set. No VPC / subnet id (retired: prefix
	// containment answers it) and no net.interfaces (the ENIs are interfaces).
	assertFact(t, inst.Facts, facts.KeyCloudProvider, "aws")
	assertFact(t, inst.Facts, facts.KeyCloudAccountID, "123456789012")
	assertFact(t, inst.Facts, facts.KeyCloudRegion, "us-east-1")
	assertFact(t, inst.Facts, facts.KeyCloudResourceID, inst.ResourceID)
	for _, gone := range []string{facts.KeyCloudVPCID, facts.KeyCloudSubnetID, facts.KeyNetInterfaces} {
		if _, present := inst.Facts[gone]; present {
			t.Errorf("fact %q is still written; it is retired by row 1.5f", gone)
		}
	}
	sgs, ok := inst.Facts[facts.KeyCloudSecurityGroups].([]map[string]any)
	if !ok || len(sgs) != 1 || sgs[0]["id"] != "sg-01" || sgs[0]["name"] != "web" {
		t.Errorf("cloud.security_groups = %#v", inst.Facts[facts.KeyCloudSecurityGroups])
	}

	// Attributes must be declarable by the class, or they are dropped at write
	// time and become invisible data.
	assertAttributesDeclared(t, DeviceTypeClassKey(inst.DeviceType), inst.Attributes)
	if inst.Attributes["instance_type"] != "m6i.large" {
		t.Errorf("instance_type attribute = %v", inst.Attributes["instance_type"])
	}
	// No guessed OS. EC2 states no guest OS product, and `os.name` is the join
	// into the end-of-life catalogue.
	if _, present := inst.Attributes["operating_system"]; present {
		t.Error("operating_system must not be guessed from PlatformDetails or the image")
	}
	if _, present := inst.Facts[facts.KeyOSName]; present {
		t.Error("os.name must not be written from an EC2 listing")
	}
}

// Both polarities of the hostname rule, at the level the plan is built.
//
// The resource-name form of EC2's private DNS name encodes the instance id and
// is globally unique, so it IS a hostname and must survive. The IP-name form
// encodes the private address and repeats wherever that address repeats, so it
// must not become one. A rule that only ever refused would be as wrong as one
// that only ever accepted.
func TestBuildAWSEnumerationPlan_HostnameOnlyFromAGloballyUniqueName(t *testing.T) {
	for _, tc := range []struct {
		name         string
		privateDNS   string
		wantHostname string
	}{
		{"ip-name form is refused", "ip-10-0-1-20.ec2.internal", ""},
		{"regional ip-name form is refused", "ip-10-0-1-20.eu-west-1.compute.internal", ""},
		{"resource-name form is kept", "i-0abc.ec2.internal", "i-0abc.ec2.internal"},
		{"a custom private zone is kept", "web-01.corp.example.com", "web-01.corp.example.com"},
		{"absent stays absent", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			instances, vpcs, subnets, groups := awsFixture()
			instances[0].PrivateDNSName = tc.privateDNS
			plan := buildAWSEnumerationPlan(instances, vpcs, subnets, groups)
			inst := findResource(t, plan.Instances, "arn:aws:ec2:us-east-1:123456789012:instance/i-01")
			if inst.Hostname != tc.wantHostname {
				t.Errorf("hostname = %q, want %q", inst.Hostname, tc.wantHostname)
			}
			if inst.Metadata["private_dns_name"] != tc.privateDNS {
				t.Errorf("private_dns_name metadata = %v, want %q — the name is kept either way",
					inst.Metadata["private_dns_name"], tc.privateDNS)
			}
		})
	}
}

// A VPC that is missing its account id has no ARN, and a network with no
// canonical id must not be recorded under a weaker one.
func TestBuildAWSEnumerationPlan_DropsResourcesWithNoCanonicalID(t *testing.T) {
	instances, vpcs, subnets, groups := awsFixture()
	vpcs[0].ARN = ""
	plan := buildAWSEnumerationPlan(instances, vpcs, subnets, groups)
	if len(plan.Networks) != 0 {
		t.Errorf("a VPC with no ARN was recorded: %+v", plan.Networks)
	}
	// Its subnet survives, but names no address space rather than a dangling one.
	if len(plan.Subnets) != 1 || plan.Subnets[0].NetworkRef != "" {
		t.Errorf("subnet network = %+v, want empty rather than a dangling id", plan.Subnets)
	}
}

// ---------------------------------------------------------------------------
// Azure
// ---------------------------------------------------------------------------

func TestBuildAzureEnumerationPlan(t *testing.T) {
	const (
		vnetID   = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet"
		subnetID = vnetID + "/subnets/app"
		nsgID    = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-web"
		vmID     = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/web-01"
	)

	plan := buildAzureEnumerationPlan(
		[]azureclient.VirtualMachine{{
			ResourceID: vmID, Name: "web-01", Location: "westeurope",
			SubscriptionID: "sub-1", ResourceGroup: "rg",
			VMSize: "Standard_D2s_v5", VMID: "b0c1d2e3-4f56-7890-abcd-ef0123456789",
			OSType: "Linux", ImageReference: "Canonical:jammy:22_04-lts:latest",
			PrivateIPs: []string{"10.10.1.20"}, SubnetIDs: []string{subnetID},
			Interfaces: []azureclient.NetworkInterface{{ID: "nic", Name: "nic-01", MAC: "00:0d:3a:1b:2c:3d", Addresses: []string{"10.10.1.20"}, SubnetID: subnetID}},
			Tags:       map[string]string{"environment": "production"},
		}},
		[]azureclient.VirtualNetwork{{
			ResourceID: vnetID, Name: "vnet", Location: "westeurope",
			SubscriptionID: "sub-1", ResourceGroup: "rg",
			AddressPrefixes: []string{"10.10.0.0/16"},
			Subnets: []azureclient.Subnet{{
				ResourceID: subnetID, Name: "app", VNetID: vnetID,
				SubscriptionID: "sub-1", ResourceGroup: "rg", Location: "westeurope",
				AddressPrefixes: []string{"10.10.1.0/24"},
				NSG:             &azureclient.SecurityGroupRef{ID: nsgID, Name: "nsg-web"},
			}},
		}},
		[]azureclient.NetworkSecurityGroup{{ResourceID: nsgID, Name: "nsg-web"}},
	)

	if got := plan.counts(); got != (CloudEnumerationCounts{Instances: 1, Networks: 1, Subnets: 1, SecurityGroups: 1}) {
		t.Fatalf("counts = %+v", got)
	}

	vnet := findNetwork(t, plan.Networks, vnetID)
	subnet := findNetwork(t, plan.Subnets, subnetID)
	if vnet.NetworkRef != vnetID || subnet.NetworkRef != vnetID || fmt.Sprint(subnet.CIDRs) != "[10.10.1.0/24]" {
		t.Errorf("VNet / subnet = %+v / %+v", vnet, subnet)
	}

	vm := findResource(t, plan.Instances, vmID)
	if got := DeviceTypeClassKey(vm.DeviceType); got != string(assetclass.KeyComputeInstance) {
		t.Errorf("an Azure VM must class as compute_instance, got %q", got)
	}
	if vm.CloudNetworkRef != vnetID {
		t.Errorf("vm network = %q, want the VNet resolved from its NIC's subnet", vm.CloudNetworkRef)
	}
	if len(vm.Interfaces) != 1 || vm.Interfaces[0].Name != "nic-01" || vm.Interfaces[0].Type != "virtual" ||
		vm.Interfaces[0].MAC != "00:0d:3a:1b:2c:3d" ||
		fmt.Sprint(vm.Interfaces[0].Addresses) != fmt.Sprint([]identity.ObservedAddress{{Address: "10.10.1.20", PrefixLen: 24, Source: "cloud"}}) {
		t.Errorf("NIC = %+v", vm.Interfaces)
	}
	if got := prefixStrings(vm.Prefixes); fmt.Sprint(got) != fmt.Sprint([]string{
		"10.10.0.0/16@" + vnetID + " type=cloud dhcp=false",
		"10.10.1.0/24@" + vnetID + " type=cloud dhcp=false",
	}) {
		t.Errorf("vm prefixes = %v", got)
	}
	if vm.Hostname != "" {
		t.Errorf("hostname = %q — Azure states no DNS name for a VM on the compute API", vm.Hostname)
	}
	assertFact(t, vm.Facts, facts.KeyHWUUID, "b0c1d2e3-4f56-7890-abcd-ef0123456789")
	// The VM inherits its subnet's NSG as membership.
	sgs, _ := vm.Facts[facts.KeyCloudSecurityGroups].([]map[string]any)
	if len(sgs) != 1 || sgs[0]["id"] != nsgID {
		t.Errorf("NSG membership = %#v, want the subnet's NSG inherited", sgs)
	}
	if _, present := vm.Facts[facts.KeyOSName]; present {
		t.Error("os.name must not be written from an OS TYPE — 'Linux' is a family, not a product")
	}
	assertAttributesDeclared(t, DeviceTypeClassKey(vm.DeviceType), vm.Attributes)
}

// ---------------------------------------------------------------------------
// GCP
// ---------------------------------------------------------------------------

func TestBuildGCPEnumerationPlan(t *testing.T) {
	const base = "https://www.googleapis.com/compute/v1/projects/my-project"
	plan := buildGCPEnumerationPlan("my-project",
		[]gcpclient.ComputeInstance{{
			ID: "1", Name: "web-01",
			SelfLink:    base + "/zones/us-central1-a/instances/web-01",
			Status:      "RUNNING",
			MachineType: base + "/zones/us-central1-a/machineTypes/e2-medium",
			Zone:        base + "/zones/us-central1-a",
			Tags:        &gcpclient.ComputeInstanceTags{Items: []string{"http-server"}},
			Labels:      map[string]string{"env": "prod"},
			NetworkInterfaces: []gcpclient.ComputeNetworkInterface{{
				Name:       "nic0",
				Network:    base + "/global/networks/prod-vpc",
				Subnetwork: base + "/regions/us-central1/subnetworks/app",
				NetworkIP:  "10.128.0.5",
			}},
		}},
		[]gcpclient.ComputeNetwork{{ID: "2", Name: "prod-vpc", SelfLink: base + "/global/networks/prod-vpc"}},
		[]gcpclient.ComputeSubnetwork{{
			ID: "3", Name: "app", SelfLink: base + "/regions/us-central1/subnetworks/app",
			Network: base + "/global/networks/prod-vpc", Region: base + "/regions/us-central1",
			IPCidrRange: "10.128.0.0/20",
		}},
		[]gcpclient.ComputeFirewall{{
			ID: "4", Name: "allow-http", SelfLink: base + "/global/firewalls/allow-http",
			Network: base + "/global/networks/prod-vpc", TargetTags: []string{"http-server"},
		}},
	)

	if got := plan.counts(); got != (CloudEnumerationCounts{Instances: 1, Networks: 1, Subnets: 1, SecurityGroups: 1}) {
		t.Fatalf("counts = %+v", got)
	}

	// Every id is the host-independent partial resource name.
	const netID = "projects/my-project/global/networks/prod-vpc"
	net := findNetwork(t, plan.Networks, netID)
	// A GCP network is GLOBAL, and a custom-mode network has no CIDR of its
	// own: it contributes no prefix, and claiming one would be invented.
	if net.Region != "" || len(net.prefixes()) != 0 {
		t.Errorf("custom-mode network = %+v, prefixes %v", net, net.prefixes())
	}
	sn := findNetwork(t, plan.Subnets, "projects/my-project/regions/us-central1/subnetworks/app")
	if sn.NetworkRef != netID || sn.Region != "us-central1" {
		t.Errorf("subnetwork = %+v", sn)
	}

	inst := findResource(t, plan.Instances, "projects/my-project/zones/us-central1-a/instances/web-01")
	if got := DeviceTypeClassKey(inst.DeviceType); got != string(assetclass.KeyComputeInstance) {
		t.Errorf("a GCE instance must class as compute_instance, got %q", got)
	}
	if inst.CloudNetworkRef != netID {
		t.Errorf("instance network = %q", inst.CloudNetworkRef)
	}
	// GCE states no MAC for a NIC: the interface carries none rather than an
	// invented one.
	if len(inst.Interfaces) != 1 || inst.Interfaces[0].Name != "nic0" || inst.Interfaces[0].MAC != "" ||
		fmt.Sprint(inst.Interfaces[0].Addresses) != fmt.Sprint([]identity.ObservedAddress{{Address: "10.128.0.5", PrefixLen: 20, Source: "cloud"}}) {
		t.Errorf("NIC = %+v", inst.Interfaces)
	}
	if got := prefixStrings(inst.Prefixes); fmt.Sprint(got) != fmt.Sprint([]string{"10.128.0.0/20@" + netID + " type=cloud dhcp=false"}) {
		t.Errorf("instance prefixes = %v", got)
	}
	if inst.IPAddress != "10.128.0.5" {
		t.Errorf("primary address = %q", inst.IPAddress)
	}
	// GCE states a hostname only when the operator set one; the default
	// `<name>.c.<project>.internal` form is derived, not stated.
	if inst.Hostname != "" {
		t.Errorf("hostname = %q, want empty when GCE states none", inst.Hostname)
	}
	assertFact(t, inst.Facts, facts.KeyCloudRegion, "us-central1")
	assertFact(t, inst.Facts, facts.KeyCloudProvider, "gcp")
	assertFact(t, inst.Facts, facts.KeyCloudAccountID, "my-project")
	sgs, _ := inst.Facts[facts.KeyCloudSecurityGroups].([]map[string]any)
	if len(sgs) != 1 || sgs[0]["name"] != "allow-http" {
		t.Errorf("firewall membership = %#v, want the tag-matched rule", sgs)
	}
	assertAttributesDeclared(t, DeviceTypeClassKey(inst.DeviceType), inst.Attributes)
	if inst.Attributes["instance_type"] != "e2-medium" {
		t.Errorf("instance_type = %v, want the machine type's short name", inst.Attributes["instance_type"])
	}
}

// ---------------------------------------------------------------------------
// Shared behaviour
// ---------------------------------------------------------------------------

// Every fact an enumeration emits must be registered for the cloud-collector
// producer and type-check against the registry, or it is dropped at write time
// and the placement silently disappears.
func TestEnumerationFactsAreRegisteredForTheCloudCollector(t *testing.T) {
	instances, vpcs, subnets, groups := awsFixture()
	plan := buildAWSEnumerationPlan(instances, vpcs, subnets, groups)

	all := plan.Instances
	if len(all) == 0 {
		t.Fatal("no resources to check — the fixture has stopped producing any")
	}
	for _, res := range all {
		for key, value := range res.Facts {
			if !facts.MayWrite(facts.ProducerCloudCollector, key) {
				t.Errorf("%s: fact %q is not registered for producer %s", res.DeviceType, key, facts.ProducerCloudCollector)
				continue
			}
			if err := facts.ValidateValue(key, value); err != nil {
				t.Errorf("%s: fact %q: %v", res.DeviceType, key, err)
			}
		}
	}
}

// cloudFactRows must DROP an unregistered key rather than carry it into
// UpsertFacts, which returns on the first bad key and would abort the
// transaction that is also writing the class attributes.
func TestCloudFactRows_DropsUnregisteredAndInvalidKeys(t *testing.T) {
	rows := cloudFactRows(map[string]any{
		facts.KeyCloudProvider: "aws",
		"not.a.registered.key": "whatever",
		// os.kernel is registered, but only the device-agent may write it.
		facts.KeyOSKernel: "6.8.0",
		// A registered key with the wrong type.
		facts.KeyCloudRegion: 42,
		// A nil value is the absence of a fact, not a fact with no value.
		facts.KeyCloudResourceID: nil,
	}, cloudSource(stringPtr("AWS")), nowUTCForTest())

	if len(rows) != 1 || rows[0].Key != facts.KeyCloudProvider {
		t.Fatalf("rows = %+v, want only the one registered, valid, non-nil fact", rows)
	}
	if rows[0].SourceRef != "cloud:aws" {
		t.Errorf("source ref = %q, want the cloud:<provider> producer shape", rows[0].SourceRef)
	}
}

// filterClassAttributes drops what the class schema does not declare. The
// schemas are additionalProperties:false and nothing enforces that in SQL, so
// an undeclared attribute would be stored, facet on nothing, and look like data.
func TestFilterClassAttributes(t *testing.T) {
	got := filterClassAttributes(string(assetclass.KeyComputeInstance), map[string]any{
		"provider":       "aws",       // inherited from cloud_resource
		"instance_type":  "m6i.large", // declared on compute_instance
		"listener_count": 3,           // declared on cloud_load_balancer, NOT here
		"nonsense":       "x",
	}, "aws_ec2_instance")

	if len(got) != 2 || got["provider"] != "aws" || got["instance_type"] != "m6i.large" {
		t.Errorf("filtered attributes = %v", got)
	}
}

// An enumerated resource must never reach the crypto findings pipeline: it
// negotiated no protocol and states no at-rest encryption, and the fallback
// there is a fabricated TLS:443 endpoint.
func TestInventoryOnlyDeviceTypesCoverEveryEnumeratedKind(t *testing.T) {
	for _, dt := range []string{DeviceTypeAWSEC2Instance, DeviceTypeAzureVM, DeviceTypeGCPComputeInstance} {
		if !inventoryOnlyDeviceTypes[dt] {
			t.Errorf("%s is enumerated but not inventory-only: WriteSensorDiscoveries would fabricate a TLS:443 endpoint for it", dt)
		}
		if atRestDeviceTypes[dt] {
			t.Errorf("%s is marked at-rest; it makes no cryptographic statement at all", dt)
		}
		if DeviceTypeClassKey(dt) == "" {
			t.Errorf("%s maps to no class; it would be inventoried as unclassified", dt)
		}
	}
}

func TestCloudEnumerationCounts(t *testing.T) {
	var zero CloudEnumerationCounts
	if !zero.Empty() || zero.Total() != 0 {
		t.Errorf("zero counts: Empty=%v Total=%d", zero.Empty(), zero.Total())
	}
	// Security groups are not assets, so they do not count towards the total —
	// but a run that saw only groups is not "empty" either.
	onlyGroups := CloudEnumerationCounts{SecurityGroups: 3}
	if onlyGroups.Empty() {
		t.Error("a run that saw 3 security groups is not empty")
	}
	if onlyGroups.Total() != 0 {
		t.Errorf("Total = %d; a security group is not an asset", onlyGroups.Total())
	}
	// Networks and subnets are prefixes since row 1.5f: only the instances are
	// assets.
	full := CloudEnumerationCounts{Instances: 2, Networks: 1, Subnets: 4, SecurityGroups: 9}
	if full.Total() != 2 {
		t.Errorf("Total = %d, want 2", full.Total())
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func assertFact(t *testing.T, got map[string]any, key string, want any) {
	t.Helper()
	v, ok := got[key]
	if !ok {
		t.Errorf("fact %q missing; have %v", key, sortedKeys(got))
		return
	}
	if v != want {
		t.Errorf("fact %q = %#v, want %#v", key, v, want)
	}
}

func assertAttributesDeclared(t *testing.T, classKey string, attrs map[string]any) {
	t.Helper()
	declared, ok := assetclass.Attributes(classKey)
	if !ok {
		t.Fatalf("class %q is not in the registry", classKey)
	}
	for k := range attrs {
		if _, present := declared[k]; !present {
			t.Errorf("class %s does not declare attribute %q; it would be dropped at write time", classKey, k)
		}
	}
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// nowUTCForTest is a fixed clock: these assertions are about which facts are
// emitted, not when.
func nowUTCForTest() time.Time {
	return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
}
