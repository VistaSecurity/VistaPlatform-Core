package services

import (
	"testing"
	"time"

	awsclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/aws"
	azureclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/azure"
	gcpclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/gcp"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/facts"
)

// The plan builders are pure functions of a provider's projections, which is
// what lets these tests pin the exact class, identifier, fact and containment
// each provider produces without a database, a credential or a network.

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

func TestBuildAWSEnumerationPlan(t *testing.T) {
	instances, vpcs, subnets, groups := awsFixture()
	plan := buildAWSEnumerationPlan(instances, vpcs, subnets, groups)

	if got := plan.counts(); got != (CloudEnumerationCounts{Instances: 1, Networks: 1, Subnets: 1, SecurityGroups: 1}) {
		t.Fatalf("counts = %+v", got)
	}

	vpc := findResource(t, plan.Networks, "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-01")
	if vpc.DeviceType != DeviceTypeAWSVPC {
		t.Errorf("vpc device type = %q", vpc.DeviceType)
	}
	if got := DeviceTypeClassKey(vpc.DeviceType); got != string(assetclass.KeyVirtualNetwork) {
		t.Errorf("a VPC must class as virtual_network, got %q", got)
	}
	if vpc.ParentID != "" {
		t.Errorf("a VPC has no container we model; got parent %q", vpc.ParentID)
	}

	subnet := findResource(t, plan.Subnets, "arn:aws:ec2:us-east-1:123456789012:subnet/subnet-01")
	if got := DeviceTypeClassKey(subnet.DeviceType); got != string(assetclass.KeySubnet) {
		t.Errorf("a subnet must class as subnet, got %q", got)
	}
	if subnet.ParentID != vpc.ResourceID {
		t.Errorf("subnet parent = %q, want the VPC's ARN", subnet.ParentID)
	}
	if subnet.SegmentCIDR != "10.0.1.0/24" {
		t.Errorf("subnet segment CIDR = %q — without it an instance's address has no scope", subnet.SegmentCIDR)
	}
	// MapPublicIpOnLaunch is NOT `is_public`: the class schema defines is_public
	// as "routes to an internet gateway", which is a different question and
	// needs DescribeRouteTables.
	if _, present := subnet.Attributes["is_public"]; present {
		t.Error("is_public must not be inferred from map_public_ip_on_launch")
	}

	inst := findResource(t, plan.Instances, "arn:aws:ec2:us-east-1:123456789012:instance/i-01")
	if got := DeviceTypeClassKey(inst.DeviceType); got != string(assetclass.KeyComputeInstance) {
		t.Errorf("an EC2 instance must class as compute_instance, got %q", got)
	}
	if inst.ParentID != subnet.ResourceID {
		t.Errorf("instance parent = %q, want the subnet's ARN", inst.ParentID)
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

	// Facts: the cloud.* placement set, plus the interfaces.
	assertFact(t, inst.Facts, facts.KeyCloudProvider, "aws")
	assertFact(t, inst.Facts, facts.KeyCloudAccountID, "123456789012")
	assertFact(t, inst.Facts, facts.KeyCloudRegion, "us-east-1")
	assertFact(t, inst.Facts, facts.KeyCloudResourceID, inst.ResourceID)
	assertFact(t, inst.Facts, facts.KeyCloudVPCID, "vpc-01")
	assertFact(t, inst.Facts, facts.KeyCloudSubnetID, "subnet-01")
	sgs, ok := inst.Facts[facts.KeyCloudSecurityGroups].([]map[string]any)
	if !ok || len(sgs) != 1 || sgs[0]["id"] != "sg-01" || sgs[0]["name"] != "web" {
		t.Errorf("cloud.security_groups = %#v", inst.Facts[facts.KeyCloudSecurityGroups])
	}
	ifaces, ok := inst.Facts[facts.KeyNetInterfaces].([]map[string]any)
	if !ok || len(ifaces) != 1 || ifaces[0]["mac"] != "0a:1b:2c:3d:4e:5f" || ifaces[0]["state"] != "up" {
		t.Errorf("net.interfaces = %#v", inst.Facts[facts.KeyNetInterfaces])
	}

	// Attributes must be declarable by the class, or they are dropped at write
	// time and become invisible data.
	assertAttributesDeclared(t, DeviceTypeClassKey(inst.DeviceType), inst.Attributes)
	assertAttributesDeclared(t, DeviceTypeClassKey(vpc.DeviceType), vpc.Attributes)
	assertAttributesDeclared(t, DeviceTypeClassKey(subnet.DeviceType), subnet.Attributes)
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

// A VPC that is missing its account id has no ARN, and a resource with no
// canonical id must not be recorded under a weaker one.
func TestBuildAWSEnumerationPlan_DropsResourcesWithNoCanonicalID(t *testing.T) {
	instances, vpcs, subnets, groups := awsFixture()
	vpcs[0].ARN = ""
	plan := buildAWSEnumerationPlan(instances, vpcs, subnets, groups)
	if len(plan.Networks) != 0 {
		t.Errorf("a VPC with no ARN was recorded: %+v", plan.Networks)
	}
	// Its subnet survives, but with no container to point at.
	if len(plan.Subnets) != 1 || plan.Subnets[0].ParentID != "" {
		t.Errorf("subnet parent = %+v, want empty rather than a dangling id", plan.Subnets)
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
			Interfaces: []azureclient.NetworkInterface{{ID: "nic", Name: "nic-01", MAC: "00:0d:3a:1b:2c:3d", Addresses: []string{"10.10.1.20"}}},
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

	vnet := findResource(t, plan.Networks, vnetID)
	if got := DeviceTypeClassKey(vnet.DeviceType); got != string(assetclass.KeyVirtualNetwork) {
		t.Errorf("a VNet must class as virtual_network, got %q", got)
	}

	subnet := findResource(t, plan.Subnets, subnetID)
	if got := DeviceTypeClassKey(subnet.DeviceType); got != string(assetclass.KeySubnet) {
		t.Errorf("an Azure subnet must class as subnet, got %q", got)
	}
	if subnet.ParentID != vnetID || subnet.SegmentCIDR != "10.10.1.0/24" {
		t.Errorf("subnet placement = %+v", subnet)
	}

	vm := findResource(t, plan.Instances, vmID)
	if got := DeviceTypeClassKey(vm.DeviceType); got != string(assetclass.KeyComputeInstance) {
		t.Errorf("an Azure VM must class as compute_instance, got %q", got)
	}
	if vm.ParentID != subnetID {
		t.Errorf("vm parent = %q, want the subnet resolved from its NIC", vm.ParentID)
	}
	if vm.Hostname != "" {
		t.Errorf("hostname = %q — Azure states no DNS name for a VM on the compute API", vm.Hostname)
	}
	assertFact(t, vm.Facts, facts.KeyCloudVPCID, vnetID)
	assertFact(t, vm.Facts, facts.KeyCloudSubnetID, subnetID)
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
	net := findResource(t, plan.Networks, "projects/my-project/global/networks/prod-vpc")
	if got := DeviceTypeClassKey(net.DeviceType); got != string(assetclass.KeyVirtualNetwork) {
		t.Errorf("a GCP network must class as virtual_network, got %q", got)
	}
	// A GCP network is GLOBAL. Claiming a region it does not have would be an
	// invented fact.
	if _, present := net.Facts[facts.KeyCloudRegion]; present {
		t.Errorf("a GCP network has no region: %v", net.Facts)
	}
	// A custom-mode network has no CIDR of its own either.
	if _, present := net.Attributes["cidr_blocks"]; present {
		t.Errorf("a custom-mode network's address space lives on its subnetworks: %v", net.Attributes)
	}

	sn := findResource(t, plan.Subnets, "projects/my-project/regions/us-central1/subnetworks/app")
	if sn.ParentID != net.ResourceID || sn.SegmentCIDR != "10.128.0.0/20" {
		t.Errorf("subnet placement = %+v", sn)
	}
	assertFact(t, sn.Facts, facts.KeyCloudRegion, "us-central1")

	inst := findResource(t, plan.Instances, "projects/my-project/zones/us-central1-a/instances/web-01")
	if got := DeviceTypeClassKey(inst.DeviceType); got != string(assetclass.KeyComputeInstance) {
		t.Errorf("a GCE instance must class as compute_instance, got %q", got)
	}
	if inst.ParentID != sn.ResourceID {
		t.Errorf("instance parent = %q, want the subnetwork", inst.ParentID)
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

	all := append(append(append([]cloudEnumResource{}, plan.Networks...), plan.Subnets...), plan.Instances...)
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
		facts.KeyCloudVPCID: nil,
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
	for _, dt := range []string{
		DeviceTypeAWSEC2Instance, DeviceTypeAWSVPC, DeviceTypeAWSSubnet,
		DeviceTypeAzureVM, DeviceTypeAzureVNet, DeviceTypeAzureSubnet,
		DeviceTypeGCPComputeInstance, DeviceTypeGCPNetwork, DeviceTypeGCPSubnetwork,
	} {
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

func TestNormalizeSegmentEnvironment(t *testing.T) {
	cases := map[string]string{
		"production": "production", "PROD": "production",
		"staging": "staging", "dev": "development", "development": "development",
		"test": "test", "qa": "test",
		// The default matches inventory-service's own cloud-segment path.
		"": "production", "whatever": "production",
	}
	for in, want := range cases {
		if got := normalizeSegmentEnvironment(in); got != want {
			t.Errorf("normalizeSegmentEnvironment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBoolFromConfig(t *testing.T) {
	// The AWS credential decrypt path stringifies every non-string value, so a
	// stored `false` can come back as "false". Reading only the bool would have
	// treated that as "not set" and silently turned the toggle back on.
	for _, tc := range []struct {
		in       any
		want, ok bool
	}{
		{true, true, true}, {false, false, true},
		{"true", true, true}, {"false", false, true},
		{"FALSE", false, true}, {"0", false, true}, {"1", true, true},
		{"maybe", false, false}, {nil, false, false}, {42, false, false},
	} {
		got, ok := boolFromConfig(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("boolFromConfig(%#v) = %v, %v; want %v, %v", tc.in, got, ok, tc.want, tc.ok)
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
	full := CloudEnumerationCounts{Instances: 2, Networks: 1, Subnets: 4, SecurityGroups: 9}
	if full.Total() != 7 {
		t.Errorf("Total = %d, want 7", full.Total())
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
