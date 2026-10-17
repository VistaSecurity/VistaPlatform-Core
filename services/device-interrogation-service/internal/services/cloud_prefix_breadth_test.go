package services

import "testing"

// A cloud subnet's prefix is a consent and approval scope like any other
// (DCIM row 1.6), so the cloud enumeration is held to the rule every scope
// write is: a subnet too broad to be anybody's (0.0.0.0/0 here) is logged and
// skipped, while an ordinary subnet beside it is recorded. Mutation check: drop
// the TooBroadToClaim skip in cloudNetwork.prefixes and the /0 is recorded.
func TestCloudEnumeration_TooBroadSubnetIsNotAPrefix(t *testing.T) {
	plan := cloudEnumerationPlan{Provider: "aws", Subnets: []cloudNetwork{
		{ResourceID: "subnet-everything", NetworkRef: "vpc-1", CIDRs: []string{"0.0.0.0/0"}},
		{ResourceID: "subnet-byoip", NetworkRef: "vpc-1", CIDRs: []string{"198.51.100.0/24"}},
	}}
	if got := plan.Subnets[0].prefixes(); len(got) != 0 {
		t.Errorf("a cloud subnet of 0.0.0.0/0 became a prefix: %+v", got)
	}
	got := plan.Subnets[1].prefixes()
	if len(got) != 1 || got[0].Prefix != "198.51.100.0/24" || got[0].CloudNetworkRef != "vpc-1" {
		t.Errorf("the ordinary cloud subnet's prefix = %+v", got)
	}
}
