package services

import (
	"context"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// A cloud-discovered segment is a segment like any other to scan scope and
// probe consent, so the cloud writer is held to the rule every segment write
// is: a subnet too broad to be anybody's (0.0.0.0/0 here) is logged and
// skipped, while an ordinary subnet beside it is recorded. Mutation check: drop the TooBroadToClaim skip in
// ensureSubnetSegments and the /0 is stored.
func TestIntegration_CloudEnumeration_TooBroadSubnetIsNotASegment(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	tenantID := testdb.NewTenant(t, owner)
	appDB := testdb.ConnectAsAppRole(t, owner)
	svc := NewCloudDiscoveryService(appDB, owner, testMasterKey)

	plan := cloudEnumerationPlan{Provider: "aws", Subnets: []cloudEnumResource{
		{ResourceID: "subnet-everything", SegmentCIDR: "0.0.0.0/0"},
		{ResourceID: "subnet-byoip", SegmentCIDR: "198.51.100.0/24"},
	}}
	svc.ensureSubnetSegments(context.Background(), tenantID, plan, "production")

	count := func(value string) int {
		t.Helper()
		var n int
		if err := owner.QueryRow(`SELECT count(*) FROM network_segments WHERE tenant_id = $1 AND value = $2`, tenantID, value).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count("0.0.0.0/0"); n != 0 {
		t.Errorf("a cloud subnet of 0.0.0.0/0 was recorded as a segment (%d rows)", n)
	}
	if n := count("198.51.100.0/24"); n != 1 {
		t.Errorf("the ordinary cloud subnet beside it was not recorded (%d rows)", n)
	}
}
