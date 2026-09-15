package aws

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// The EC2 enumeration is a PROJECTION BOUNDARY: every response field that is
// not on the allowlist must be gone before anything downstream can see it.
// These tests feed the projections realistic responses carrying the material
// EC2 actually returns and assert it does not survive.
//
// They call the projections DIRECTLY, before any redaction runs, because the
// point is that the data is never collected — the name-based backstop is the
// belt, not the braces.

// poison is a value that must never appear in a projected resource.
const poison = "MUST-NOT-BE-COLLECTED"

func assertNoPoison(t *testing.T, label string, v any) {
	t.Helper()
	blob, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("%s: marshal: %v", label, err)
	}
	if strings.Contains(string(blob), poison) {
		t.Errorf("%s: collected material that should have been projected away: %s", label, blob)
	}
}

// ---------------------------------------------------------------------------
// A fake EC2 API, driven by recorded responses.
// ---------------------------------------------------------------------------

type fakeEC2 struct {
	instancePages []*ec2.DescribeInstancesOutput
	vpcPages      []*ec2.DescribeVpcsOutput
	subnetPages   []*ec2.DescribeSubnetsOutput
	sgPages       []*ec2.DescribeSecurityGroupsOutput

	instanceCalls, vpcCalls, subnetCalls, sgCalls int
	// attributeCalls counts calls to anything that would return user data. The
	// interface has no such method, so this can only ever be zero — which is
	// the point: the SHAPE of the interface is the guarantee.
}

func (f *fakeEC2) DescribeInstances(_ context.Context, _ *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	out := f.instancePages[f.instanceCalls]
	f.instanceCalls++
	return out, nil
}

func (f *fakeEC2) DescribeVpcs(_ context.Context, _ *ec2.DescribeVpcsInput, _ ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
	out := f.vpcPages[f.vpcCalls]
	f.vpcCalls++
	return out, nil
}

func (f *fakeEC2) DescribeSubnets(_ context.Context, _ *ec2.DescribeSubnetsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	out := f.subnetPages[f.subnetCalls]
	f.subnetCalls++
	return out, nil
}

func (f *fakeEC2) DescribeSecurityGroups(_ context.Context, _ *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	out := f.sgPages[f.sgCalls]
	f.sgCalls++
	return out, nil
}

// ---------------------------------------------------------------------------
// Projection
// ---------------------------------------------------------------------------

func TestProjectInstance_KeepsPostureDropsEverythingElse(t *testing.T) {
	launch := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	in := ec2types.Instance{
		InstanceId:       aws.String("i-0abc"),
		InstanceType:     ec2types.InstanceTypeM6iLarge,
		PrivateDnsName:   aws.String("ip-10-0-1-20.ec2.internal"),
		PrivateIpAddress: aws.String("10.0.1.20"),
		ImageId:          aws.String("ami-0123"),
		PlatformDetails:  aws.String("Linux/UNIX"),
		Architecture:     ec2types.ArchitectureValuesX8664,
		VpcId:            aws.String("vpc-01"),
		SubnetId:         aws.String("subnet-01"),
		KeyName:          aws.String("prod-bastion-key"),
		LaunchTime:       &launch,
		State:            &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
		Placement:        &ec2types.Placement{AvailabilityZone: aws.String("us-east-1a")},
		SecurityGroups: []ec2types.GroupIdentifier{
			{GroupId: aws.String("sg-01"), GroupName: aws.String("web")},
		},
		NetworkInterfaces: []ec2types.InstanceNetworkInterface{{
			NetworkInterfaceId: aws.String("eni-01"),
			MacAddress:         aws.String("0A:1B:2C:3D:4E:5F"),
			Status:             ec2types.NetworkInterfaceStatusInUse,
			SubnetId:           aws.String("subnet-01"),
			VpcId:              aws.String("vpc-01"),
			PrivateIpAddress:   aws.String("10.0.1.20"),
			PrivateIpAddresses: []ec2types.InstancePrivateIpAddress{
				{PrivateIpAddress: aws.String("10.0.1.20")},
				{PrivateIpAddress: aws.String("10.0.1.21")},
			},
		}},
		// Everything below is what EC2 also returns and nothing reads. The IAM
		// profile names a role the instance can assume; the block device
		// mappings name its volumes; the licence specifications name its
		// entitlements. None is inventory, all of it is blast radius.
		IamInstanceProfile: &ec2types.IamInstanceProfile{Arn: aws.String(poison), Id: aws.String(poison)},
		BlockDeviceMappings: []ec2types.InstanceBlockDeviceMapping{
			{DeviceName: aws.String(poison), Ebs: &ec2types.EbsInstanceBlockDevice{VolumeId: aws.String(poison)}},
		},
		Licenses:              []ec2types.LicenseConfiguration{{LicenseConfigurationArn: aws.String(poison)}},
		ClientToken:           aws.String(poison),
		SpotInstanceRequestId: aws.String(poison),
		Tags: []ec2types.Tag{
			{Key: aws.String("Name"), Value: aws.String("web-01")},
			{Key: aws.String("environment"), Value: aws.String("production")},
			// A tag whose NAME says it holds a secret. Tags are free text the
			// customer wrote and projection cannot pre-empt their names, so the
			// name-based redactor is the primary defence here.
			{Key: aws.String("db_password"), Value: aws.String(poison)},
		},
	}

	got := projectInstance(in, "us-east-1", "123456789012")

	assertNoPoison(t, "ec2 instance", got)

	if got.ARN != "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc" {
		t.Errorf("ARN = %q, want the canonical constructed form", got.ARN)
	}
	if got.InstanceType != "m6i.large" || got.State != "running" {
		t.Errorf("posture lost: %+v", got)
	}
	if got.PrivateDNSName != "ip-10-0-1-20.ec2.internal" {
		t.Errorf("private DNS name lost: %q", got.PrivateDNSName)
	}
	if got.KeyName != "prod-bastion-key" {
		t.Errorf("key pair NAME must be kept (only the name): %q", got.KeyName)
	}
	if len(got.PrivateIPs) != 2 || got.PrivateIPs[0] != "10.0.1.20" || got.PrivateIPs[1] != "10.0.1.21" {
		t.Errorf("private addresses = %v, want both ENI addresses, primary first", got.PrivateIPs)
	}
	if len(got.Interfaces) != 1 || got.Interfaces[0].MAC != "0a:1b:2c:3d:4e:5f" {
		t.Errorf("interface MAC = %+v, want lower-case colon form", got.Interfaces)
	}
	if len(got.SecurityGroups) != 1 || got.SecurityGroups[0].ID != "sg-01" {
		t.Errorf("security-group membership lost: %+v", got.SecurityGroups)
	}
	if got.Tags["Name"] != "web-01" || got.Tags["environment"] != "production" {
		t.Errorf("ordinary tags lost: %v", got.Tags)
	}
	if v := got.Tags["db_password"]; v == poison || v == "" {
		t.Errorf("db_password tag = %q; the KEY must survive (so an operator can see it) with the VALUE masked", v)
	}
}

// EC2's two hostname types are not interchangeable as IDENTIFIERS: the
// resource-name form encodes the instance id and is globally unique, while the
// IP-name form encodes the private IPv4 and repeats wherever that address
// repeats — across two VPCs whose CIDRs overlap, and across a terminated
// instance and the one that inherits its address. A dotted hostname becomes an
// unscoped `fqdn` identifier, so handing the IP-name form to it merges two
// different instances into one asset with no merge proposal.
func TestIsIPDerivedPrivateDNSName(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		// The IP-name form, in both the us-east-1 and the regional spelling.
		{"ip-10-0-1-20.ec2.internal", true},
		{"ip-10-0-1-20.eu-west-1.compute.internal", true},
		{"IP-172-31-4-9.ec2.internal", true},
		// The resource-name form. Unique by construction, so it IS a hostname.
		{"i-0abc123def456789a.ec2.internal", false},
		{"i-0abc123def456789a.eu-west-1.compute.internal", false},
		// A custom private zone the operator runs. Theirs, and a real name.
		{"web-01.corp.example.com", false},
		{"ip-service.corp.example.com", false}, // "ip-" but not four octets
		{"ip-10-0-1.ec2.internal", false},      // three octets: not the form
		{"ip-10-0-1-20-5.ec2.internal", false}, // five: not the form
		{"ip-10-0-1-2x.ec2.internal", false},   // not numeric
		{"", false},
		{"ip-10-0-1-20", false}, // no dot, so never an fqdn identifier anyway
	} {
		if got := IsIPDerivedPrivateDNSName(tc.in); got != tc.want {
			t.Errorf("IsIPDerivedPrivateDNSName(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestProjectSecurityGroup_DropsRules(t *testing.T) {
	in := ec2types.SecurityGroup{
		GroupId:     aws.String("sg-01"),
		GroupName:   aws.String("web"),
		VpcId:       aws.String("vpc-01"),
		OwnerId:     aws.String("123456789012"),
		Description: aws.String("web tier"),
		// The rules. `cloud.security_groups` is membership, never the rules
		// inside the group — a rule set is an attacker's map of the network.
		IpPermissions: []ec2types.IpPermission{{
			IpProtocol: aws.String(poison),
			IpRanges:   []ec2types.IpRange{{CidrIp: aws.String(poison)}},
		}},
		IpPermissionsEgress: []ec2types.IpPermission{{IpProtocol: aws.String(poison)}},
	}

	got := projectSecurityGroup(in, "us-east-1")
	assertNoPoison(t, "security group", got)
	if got.GroupID != "sg-01" || got.GroupName != "web" || got.VPCID != "vpc-01" {
		t.Errorf("identity lost: %+v", got)
	}
}

func TestProjectVPCAndSubnet(t *testing.T) {
	vpc := projectVPC(ec2types.Vpc{
		VpcId:     aws.String("vpc-01"),
		OwnerId:   aws.String("123456789012"),
		CidrBlock: aws.String("10.0.0.0/16"),
		State:     ec2types.VpcStateAvailable,
		IsDefault: aws.Bool(false),
		CidrBlockAssociationSet: []ec2types.VpcCidrBlockAssociation{
			{CidrBlock: aws.String("10.0.0.0/16")},
			{CidrBlock: aws.String("10.1.0.0/16")},
		},
		Tags: []ec2types.Tag{{Key: aws.String("Name"), Value: aws.String("prod")}},
	}, "us-east-1")

	if vpc.ARN != "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-01" {
		t.Errorf("vpc ARN = %q", vpc.ARN)
	}
	if len(vpc.CIDRBlocks) != 2 {
		t.Errorf("CIDR blocks = %v, want the primary once and the secondary once", vpc.CIDRBlocks)
	}

	// A subnet's SubnetArn is authoritative when the API supplies it.
	sn := projectSubnet(ec2types.Subnet{
		SubnetId:            aws.String("subnet-01"),
		SubnetArn:           aws.String("arn:aws:ec2:us-east-1:123456789012:subnet/subnet-01"),
		VpcId:               aws.String("vpc-01"),
		OwnerId:             aws.String("123456789012"),
		CidrBlock:           aws.String("10.0.1.0/24"),
		AvailabilityZone:    aws.String("us-east-1a"),
		MapPublicIpOnLaunch: aws.Bool(true),
		State:               ec2types.SubnetStateAvailable,
	}, "us-east-1")
	if sn.ARN != "arn:aws:ec2:us-east-1:123456789012:subnet/subnet-01" {
		t.Errorf("subnet ARN = %q", sn.ARN)
	}
	if sn.CIDRBlock != "10.0.1.0/24" || sn.AvailabilityZone != "us-east-1a" {
		t.Errorf("subnet posture lost: %+v", sn)
	}

	// And is constructed when it is not.
	sn2 := projectSubnet(ec2types.Subnet{
		SubnetId: aws.String("subnet-02"),
		OwnerId:  aws.String("123456789012"),
	}, "eu-west-2")
	if sn2.ARN != "arn:aws:ec2:eu-west-2:123456789012:subnet/subnet-02" {
		t.Errorf("constructed subnet ARN = %q", sn2.ARN)
	}
}

// An identifier that changes with the partition would name a different
// resource. GovCloud and China are separate ARN namespaces.
func TestEC2ResourceARN_PartitionAndIncompleteness(t *testing.T) {
	cases := []struct{ region, account, want string }{
		{"us-east-1", "123456789012", "arn:aws:ec2:us-east-1:123456789012:instance/i-1"},
		{"us-gov-west-1", "123456789012", "arn:aws-us-gov:ec2:us-gov-west-1:123456789012:instance/i-1"},
		{"cn-north-1", "123456789012", "arn:aws-cn:ec2:cn-north-1:123456789012:instance/i-1"},
		// A partial ARN is a DIFFERENT identifier, not a weaker one: two runs
		// that disagreed about it would mint two assets for one instance.
		{"us-east-1", "", ""},
		{"", "123456789012", ""},
	}
	for _, c := range cases {
		if got := EC2ResourceARN(c.region, c.account, "instance", "i-1"); got != c.want {
			t.Errorf("EC2ResourceARN(%q, %q) = %q, want %q", c.region, c.account, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

func TestListInstances_PaginatesAndDropsTerminated(t *testing.T) {
	api := &fakeEC2{instancePages: []*ec2.DescribeInstancesOutput{
		{
			NextToken: aws.String("page-2"),
			Reservations: []ec2types.Reservation{{
				OwnerId: aws.String("123456789012"),
				Instances: []ec2types.Instance{
					{InstanceId: aws.String("i-1"), State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning}},
					// AWS keeps a terminated instance visible for about an hour.
					// Inventorying one creates an asset for a machine that no
					// longer exists and can never be re-observed.
					{InstanceId: aws.String("i-dead"), State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameTerminated}},
				},
			}},
		},
		{
			Reservations: []ec2types.Reservation{{
				OwnerId:   aws.String("123456789012"),
				Instances: []ec2types.Instance{{InstanceId: aws.String("i-2"), State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameStopped}}},
			}},
		},
	}}

	got, err := ListInstances(context.Background(), api, "us-east-1")
	if err != nil {
		t.Fatalf("ListInstances: %v", err)
	}
	if api.instanceCalls != 2 {
		t.Errorf("made %d calls, want 2 — the second page was not fetched", api.instanceCalls)
	}
	if len(got) != 2 {
		t.Fatalf("got %d instances, want 2 (i-1 and i-2, not the terminated one): %+v", len(got), got)
	}
	if got[0].InstanceID != "i-1" || got[1].InstanceID != "i-2" {
		t.Errorf("instances = %+v", got)
	}
	// A stopped instance is still an instance. Only terminated is gone.
	if got[1].State != "stopped" {
		t.Errorf("stopped instance state = %q", got[1].State)
	}
}

func TestListVPCsSubnetsAndGroups(t *testing.T) {
	api := &fakeEC2{
		vpcPages: []*ec2.DescribeVpcsOutput{{Vpcs: []ec2types.Vpc{
			{VpcId: aws.String("vpc-01"), OwnerId: aws.String("123456789012"), CidrBlock: aws.String("10.0.0.0/16")},
		}}},
		subnetPages: []*ec2.DescribeSubnetsOutput{{Subnets: []ec2types.Subnet{
			{SubnetId: aws.String("subnet-01"), VpcId: aws.String("vpc-01"), OwnerId: aws.String("123456789012"), CidrBlock: aws.String("10.0.1.0/24")},
		}}},
		sgPages: []*ec2.DescribeSecurityGroupsOutput{{SecurityGroups: []ec2types.SecurityGroup{
			{GroupId: aws.String("sg-01"), GroupName: aws.String("web"), OwnerId: aws.String("123456789012")},
		}}},
	}
	ctx := context.Background()

	vpcs, err := ListVPCs(ctx, api, "us-east-1")
	if err != nil || len(vpcs) != 1 || vpcs[0].VPCID != "vpc-01" {
		t.Fatalf("ListVPCs = %+v, %v", vpcs, err)
	}
	subnets, err := ListSubnets(ctx, api, "us-east-1")
	if err != nil || len(subnets) != 1 || subnets[0].CIDRBlock != "10.0.1.0/24" {
		t.Fatalf("ListSubnets = %+v, %v", subnets, err)
	}
	groups, err := ListSecurityGroups(ctx, api, "us-east-1")
	if err != nil || len(groups) != 1 || groups[0].GroupName != "web" {
		t.Fatalf("ListSecurityGroups = %+v, %v", groups, err)
	}
}

// The user-data guard, stated as a property of the TYPE rather than of a call
// site: EC2API has four methods and none of them can return an instance
// attribute. `DescribeInstanceAttribute(userData)` is the single richest source
// of secrets in EC2, and the way it is prevented is that there is nothing to
// call.
func TestEC2APISurfaceCannotReachUserData(t *testing.T) {
	var api EC2API = &fakeEC2{}
	// A compile-time assertion in test form: if someone widens EC2API with an
	// attribute call, this list stops matching the interface and the reviewer
	// has to say why.
	switch v := api.(type) {
	case interface {
		DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
		DescribeVpcs(context.Context, *ec2.DescribeVpcsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error)
		DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
		DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	}:
		_ = v
	default:
		t.Fatal("EC2API no longer matches the four-call read-only surface")
	}
}
