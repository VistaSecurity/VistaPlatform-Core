package assetclass

import "testing"

// ADR-0009 D2: one provider-type → class mapping, keyed on the provider's own
// type strings, that every collector spelling resolves through.
func TestCloudProviderTypes_OneMappingForEverySpelling(t *testing.T) {
	cases := map[string]Key{
		"AWS::EC2::Instance":                         KeyComputeInstance,
		"Microsoft.Compute/virtualMachines":          KeyComputeInstance,
		"compute.googleapis.com/Instance":            KeyComputeInstance,
		"AWS::Lambda::Function":                      KeyServerlessFunction,
		"Microsoft.ContainerService/managedClusters": KeyContainerCluster,
		"secretmanager.googleapis.com/Secret":        KeySecretStore,
		"AWS::Route53::HostedZone":                   KeyDnsZone,
		"Microsoft.Network/networkSecurityGroups":    KeySecurityGroup,
	}
	for spelling, want := range cases {
		if got, ok := FromCloudResourceType(spelling); !ok || got != want {
			t.Errorf("FromCloudResourceType(%q) = %q, want %q", spelling, got, want)
		}
	}
	// A device type and a collector resource type reach the same entry.
	for _, spelling := range []string{"aws_ec2_instance", "ec2", "AWS::EC2::Instance"} {
		pt, ok := ProviderTypeOf(spelling)
		if !ok || pt.Type != "AWS::EC2::Instance" || pt.Class != KeyComputeInstance {
			t.Errorf("ProviderTypeOf(%q) = %+v, %v", spelling, pt, ok)
		}
	}
	if FromDeviceType("gcp_gke_cluster") != KeyContainerCluster {
		t.Error("the device-type half is not folded from the mapping")
	}
	// Every mapped class is a real cloud_resource leaf.
	for _, pt := range CloudProviderTypes() {
		c, ok := Get(string(pt.Class))
		if !ok || c.Parent != KeyCloudResource {
			t.Errorf("%s maps to %q, not a cloud_resource leaf", pt.Type, pt.Class)
		}
	}
}
