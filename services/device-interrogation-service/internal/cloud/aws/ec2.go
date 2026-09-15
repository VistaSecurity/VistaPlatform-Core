package aws

// EC2 enumeration: compute instances, VPCs, subnets and security groups.
//
// This file is a PROJECTION BOUNDARY. Nothing here hands an SDK response object
// onward — every call returns a struct declared in this file whose fields are an
// explicit allowlist of what the platform actually reads ("Collect posture,
// never key material"). The EC2 API is unusually generous: a `DescribeInstances`
// reservation carries the instance's whole IAM profile, its block-device
// mappings, its CPU options, its spot request, its licence specifications and
// its full tag set, none of which anything downstream reads.
//
// Two things are deliberately NOT retrieved at all, which is the first and
// strongest of the three layers:
//
//   - **User data.** `DescribeInstanceAttribute(Attribute: userData)` is the
//     single richest source of secrets in EC2 — bootstrap scripts routinely
//     carry database passwords, API tokens and private keys. It is never
//     called. Not projected away, not redacted: never asked for, so an IAM
//     policy that grants it still yields nothing.
//   - **Security-group RULES.** `DescribeSecurityGroups` returns
//     `IpPermissions`/`IpPermissionsEgress`, and those are an attacker's map of
//     the network. Only the group's id, name and VPC are projected —
//     membership, per `standards/fact-keys.yaml` `cloud.security_groups`:
//     "this is the group the resource is IN, never the rules inside it".
//
// The EC2 key pair is projected by NAME only (`KeyName`). A key pair name is a
// label an operator chose; the private half never leaves the customer's hands
// and the public half is not requested.

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/vistasecurity/vistaplatform/shared/redact"
)

// EC2API is the subset of the generated EC2 client this package calls.
//
// It exists so the enumeration paths can be driven by recorded responses in a
// test without a network, an endpoint resolver or a credential. The method set
// is deliberately exactly four calls wide: adding a fifth is a decision about
// what we collect, and it should have to be made here.
//
// The signatures match the SDK's own paginator client interfaces
// (ec2.DescribeInstancesAPIClient and friends), so the SDK paginators are used
// verbatim rather than a hand-rolled NextToken loop.
type EC2API interface {
	DescribeInstances(ctx context.Context, in *ec2.DescribeInstancesInput, opts ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeVpcs(ctx context.Context, in *ec2.DescribeVpcsInput, opts ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error)
	DescribeSubnets(ctx context.Context, in *ec2.DescribeSubnetsInput, opts ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
	DescribeSecurityGroups(ctx context.Context, in *ec2.DescribeSecurityGroupsInput, opts ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
}

// EC2ClientForRegion builds an EC2 client for one region from the integration's
// resolved credentials.
func (c *Client) EC2ClientForRegion(region string) *ec2.Client {
	cfg := c.config
	if strings.TrimSpace(region) != "" {
		cfg.Region = region
	}
	return ec2.NewFromConfig(cfg)
}

// ---------------------------------------------------------------------------
// Projections
// ---------------------------------------------------------------------------

// SecurityGroupRef is a security group a resource is a MEMBER of: its id and
// name, and nothing else. It is the shape `cloud.security_groups` declares.
type SecurityGroupRef struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// NetworkInterface is one ENI of an instance, projected onto the shape
// `net.interfaces` declares: a name, a MAC, and the addresses on it.
type NetworkInterface struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	State     string   `json:"state,omitempty"`
	SubnetID  string   `json:"subnet_id,omitempty"`
	VPCID     string   `json:"vpc_id,omitempty"`
}

// Instance is an EC2 instance, projected.
//
// OperatingSystem and OSVersion are absent on purpose: EC2 does not state a
// guest OS. `PlatformDetails` is a BILLING string ("Linux/UNIX", "Windows",
// "Red Hat Enterprise Linux") and `Platform` is the legacy "windows"-or-empty
// flag; neither is the product the guest runs, and an image NAME is a label an
// operator chose. Guessing `os.name` from any of them would put a fabricated
// value in the key the EOL catalogue joins on (ADR-0004 D1). The one honest
// statement EC2 makes is the platform family, and it is carried under its own
// name.
type Instance struct {
	InstanceID       string             `json:"instance_id"`
	ARN              string             `json:"arn"`
	AccountID        string             `json:"account_id,omitempty"`
	Region           string             `json:"region,omitempty"`
	InstanceType     string             `json:"instance_type,omitempty"`
	State            string             `json:"state,omitempty"`
	PrivateDNSName   string             `json:"private_dns_name,omitempty"`
	PrivateIPs       []string           `json:"private_ips,omitempty"`
	ImageID          string             `json:"image_id,omitempty"`
	PlatformDetails  string             `json:"platform_details,omitempty"`
	Architecture     string             `json:"architecture,omitempty"`
	VPCID            string             `json:"vpc_id,omitempty"`
	SubnetID         string             `json:"subnet_id,omitempty"`
	AvailabilityZone string             `json:"availability_zone,omitempty"`
	KeyName          string             `json:"key_name,omitempty"`
	LaunchTime       string             `json:"launch_time,omitempty"`
	SecurityGroups   []SecurityGroupRef `json:"security_groups,omitempty"`
	Interfaces       []NetworkInterface `json:"interfaces,omitempty"`
	Tags             map[string]string  `json:"tags,omitempty"`
}

// VPC is a virtual private cloud, projected.
type VPC struct {
	VPCID      string            `json:"vpc_id"`
	ARN        string            `json:"arn"`
	AccountID  string            `json:"account_id,omitempty"`
	Region     string            `json:"region,omitempty"`
	CIDRBlocks []string          `json:"cidr_blocks,omitempty"`
	State      string            `json:"state,omitempty"`
	IsDefault  bool              `json:"is_default,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
}

// Subnet is a subnet, projected.
type Subnet struct {
	SubnetID            string            `json:"subnet_id"`
	ARN                 string            `json:"arn"`
	VPCID               string            `json:"vpc_id,omitempty"`
	AccountID           string            `json:"account_id,omitempty"`
	Region              string            `json:"region,omitempty"`
	CIDRBlock           string            `json:"cidr_block,omitempty"`
	AvailabilityZone    string            `json:"availability_zone,omitempty"`
	MapPublicIPOnLaunch bool              `json:"map_public_ip_on_launch,omitempty"`
	State               string            `json:"state,omitempty"`
	Tags                map[string]string `json:"tags,omitempty"`
}

// SecurityGroup is a security group as an ATTRIBUTE source — id, name, VPC and
// nothing else. The rules are not collected; see the file comment.
type SecurityGroup struct {
	GroupID   string            `json:"group_id"`
	GroupName string            `json:"group_name,omitempty"`
	VPCID     string            `json:"vpc_id,omitempty"`
	AccountID string            `json:"account_id,omitempty"`
	Region    string            `json:"region,omitempty"`
	Tags      map[string]string `json:"tags,omitempty"`
}

// ---------------------------------------------------------------------------
// Canonical resource ids
// ---------------------------------------------------------------------------

// ARNPartition returns the ARN partition a region belongs to.
//
// GovCloud and China are separate partitions with separate ARN namespaces, and
// an instance id is only unique WITHIN one. Hardcoding "aws" would give a
// GovCloud instance an ARN that names a commercial-partition resource.
func ARNPartition(region string) string {
	switch {
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov"
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn"
	case strings.HasPrefix(region, "us-iso-"), strings.HasPrefix(region, "us-isob-"):
		// The ISO partitions are unreachable from this platform, but naming
		// them is cheaper than emitting a wrong partition if one ever appears.
		return "aws-iso"
	default:
		return "aws"
	}
}

// EC2ResourceARN is the canonical `cloud_resource_id` for an EC2-namespace
// resource: `arn:<partition>:ec2:<region>:<account>:<kind>/<id>`.
//
// This is the identity the identification engine deduplicates a cloud asset on,
// so it has to be byte-stable across runs and across collectors. DescribeVpcs
// and DescribeSecurityGroups do not return an ARN at all and DescribeSubnets
// does, so the constructed form is what every kind uses — with the subnet's own
// `SubnetArn` preferred when the API supplies one, because the two agree and
// the API's answer is authoritative if they ever stop agreeing.
//
// An empty account or region yields "": a partial ARN is not a weaker
// identifier, it is a DIFFERENT one, and two runs that disagreed about it would
// mint two assets for one instance.
func EC2ResourceARN(region, accountID, kind, id string) string {
	region, accountID = strings.TrimSpace(region), strings.TrimSpace(accountID)
	id = strings.TrimSpace(id)
	if region == "" || accountID == "" || id == "" {
		return ""
	}
	return fmt.Sprintf("arn:%s:ec2:%s:%s:%s/%s", ARNPartition(region), region, accountID, kind, id)
}

// IsIPDerivedPrivateDNSName reports whether an EC2 private DNS name is the
// IP-NAME form — `ip-10-0-1-20.ec2.internal`, or `ip-10-0-1-20.<region>.
// compute.internal` outside us-east-1.
//
// The distinction is an IDENTITY one, not cosmetic. EC2 offers two hostname
// types. The RESOURCE-NAME form (`i-0abc…def.ec2.internal`) encodes the
// instance id and is therefore globally unique. The IP-NAME form encodes the
// private IPv4 and nothing else, so it is unique only inside one VPC's
// resolver: two instances with the same private address — two VPCs whose CIDRs
// overlap, or one instance launched into an address a terminated instance just
// freed — carry byte-identical names.
//
// That matters because `assets.hostname` becomes an identifier, and a DOTTED
// hostname becomes an `fqdn` one: globally unique by definition, unscoped, and
// above `ip_address` in the `compute_instance` precedence. Feeding a name that
// is not globally unique into the kind that means "globally unique" makes the
// engine MATCH two different instances and merge them into one asset, silently
// and with no merge proposal — the outcome ADR-0002 D5 exists to prevent.
//
// So the IP-name form is not offered as a hostname at all. It is an alias of
// the private address, which is already recorded as the address (scoped to the
// subnet's segment, where it can be reasoned about), and it stays visible on
// the resource's `private_dns_name` metadata. This is the same call Azure and
// GCP already make in this collector: a VM gets no hostname from ARM, and a GCE
// instance gets one only when the operator set a custom internal name.
func IsIPDerivedPrivateDNSName(name string) bool {
	first, _, found := strings.Cut(strings.ToLower(strings.TrimSpace(name)), ".")
	if !found {
		return false
	}
	octets, ok := strings.CutPrefix(first, "ip-")
	if !ok {
		return false
	}
	parts := strings.Split(octets, "-")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// List calls
// ---------------------------------------------------------------------------

// ListInstances enumerates every EC2 instance in one region.
//
// TERMINATED instances are dropped: AWS keeps them visible for about an hour
// after termination, and inventorying one would create an asset for a machine
// that no longer exists and cannot be re-observed.
func ListInstances(ctx context.Context, api EC2API, region string) ([]Instance, error) {
	var out []Instance
	p := ec2.NewDescribeInstancesPaginator(api, &ec2.DescribeInstancesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe EC2 instances in %s: %w", region, err)
		}
		for _, res := range page.Reservations {
			owner := aws.ToString(res.OwnerId)
			for i := range res.Instances {
				inst := projectInstance(res.Instances[i], region, owner)
				if inst.InstanceID == "" || inst.State == string(ec2types.InstanceStateNameTerminated) {
					continue
				}
				out = append(out, inst)
			}
		}
	}
	return out, nil
}

// ListVPCs enumerates every VPC in one region.
func ListVPCs(ctx context.Context, api EC2API, region string) ([]VPC, error) {
	var out []VPC
	p := ec2.NewDescribeVpcsPaginator(api, &ec2.DescribeVpcsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe VPCs in %s: %w", region, err)
		}
		for i := range page.Vpcs {
			v := projectVPC(page.Vpcs[i], region)
			if v.VPCID == "" {
				continue
			}
			out = append(out, v)
		}
	}
	return out, nil
}

// ListSubnets enumerates every subnet in one region.
func ListSubnets(ctx context.Context, api EC2API, region string) ([]Subnet, error) {
	var out []Subnet
	p := ec2.NewDescribeSubnetsPaginator(api, &ec2.DescribeSubnetsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe subnets in %s: %w", region, err)
		}
		for i := range page.Subnets {
			s := projectSubnet(page.Subnets[i], region)
			if s.SubnetID == "" {
				continue
			}
			out = append(out, s)
		}
	}
	return out, nil
}

// ListSecurityGroups enumerates every security group in one region.
//
// The rules are not read; see the file comment.
func ListSecurityGroups(ctx context.Context, api EC2API, region string) ([]SecurityGroup, error) {
	var out []SecurityGroup
	p := ec2.NewDescribeSecurityGroupsPaginator(api, &ec2.DescribeSecurityGroupsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe security groups in %s: %w", region, err)
		}
		for i := range page.SecurityGroups {
			g := projectSecurityGroup(page.SecurityGroups[i], region)
			if g.GroupID == "" {
				continue
			}
			out = append(out, g)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Projection functions — the allowlist
// ---------------------------------------------------------------------------

func projectInstance(in ec2types.Instance, region, ownerID string) Instance {
	id := aws.ToString(in.InstanceId)
	out := Instance{
		InstanceID:      id,
		AccountID:       ownerID,
		Region:          region,
		ARN:             EC2ResourceARN(region, ownerID, "instance", id),
		InstanceType:    string(in.InstanceType),
		PrivateDNSName:  aws.ToString(in.PrivateDnsName),
		ImageID:         aws.ToString(in.ImageId),
		PlatformDetails: aws.ToString(in.PlatformDetails),
		Architecture:    string(in.Architecture),
		VPCID:           aws.ToString(in.VpcId),
		SubnetID:        aws.ToString(in.SubnetId),
		KeyName:         aws.ToString(in.KeyName),
		Tags:            projectTags(in.Tags),
	}
	if in.State != nil {
		out.State = string(in.State.Name)
	}
	if in.Placement != nil {
		out.AvailabilityZone = aws.ToString(in.Placement.AvailabilityZone)
	}
	if in.LaunchTime != nil {
		out.LaunchTime = in.LaunchTime.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	for _, g := range in.SecurityGroups {
		if gid := aws.ToString(g.GroupId); gid != "" {
			out.SecurityGroups = append(out.SecurityGroups, SecurityGroupRef{ID: gid, Name: aws.ToString(g.GroupName)})
		}
	}

	// Addresses come from the ENIs rather than from the instance's own
	// PrivateIpAddress, because an instance with several interfaces has several
	// addresses and the top-level field names only one of them. The top-level
	// value is folded in so a response that carries it and no interface detail
	// still yields an address.
	seen := map[string]bool{}
	addAddr := func(a string) {
		a = strings.TrimSpace(a)
		if a == "" || seen[a] {
			return
		}
		seen[a] = true
		out.PrivateIPs = append(out.PrivateIPs, a)
	}
	addAddr(aws.ToString(in.PrivateIpAddress))
	for _, ni := range in.NetworkInterfaces {
		iface := NetworkInterface{
			Name:     aws.ToString(ni.NetworkInterfaceId),
			MAC:      strings.ToLower(aws.ToString(ni.MacAddress)),
			State:    string(ni.Status),
			SubnetID: aws.ToString(ni.SubnetId),
			VPCID:    aws.ToString(ni.VpcId),
		}
		if a := aws.ToString(ni.PrivateIpAddress); a != "" {
			iface.Addresses = append(iface.Addresses, a)
			addAddr(a)
		}
		for _, pa := range ni.PrivateIpAddresses {
			a := aws.ToString(pa.PrivateIpAddress)
			if a == "" || a == aws.ToString(ni.PrivateIpAddress) {
				continue
			}
			iface.Addresses = append(iface.Addresses, a)
			addAddr(a)
		}
		if iface.Name == "" {
			continue
		}
		out.Interfaces = append(out.Interfaces, iface)
	}
	return out
}

func projectVPC(in ec2types.Vpc, region string) VPC {
	id := aws.ToString(in.VpcId)
	owner := aws.ToString(in.OwnerId)
	out := VPC{
		VPCID:     id,
		AccountID: owner,
		Region:    region,
		ARN:       EC2ResourceARN(region, owner, "vpc", id),
		State:     string(in.State),
		IsDefault: aws.ToBool(in.IsDefault),
		Tags:      projectTags(in.Tags),
	}
	if primary := aws.ToString(in.CidrBlock); primary != "" {
		out.CIDRBlocks = append(out.CIDRBlocks, primary)
	}
	for _, assoc := range in.CidrBlockAssociationSet {
		cidr := aws.ToString(assoc.CidrBlock)
		if cidr == "" || cidr == aws.ToString(in.CidrBlock) {
			continue
		}
		out.CIDRBlocks = append(out.CIDRBlocks, cidr)
	}
	for _, assoc := range in.Ipv6CidrBlockAssociationSet {
		if cidr := aws.ToString(assoc.Ipv6CidrBlock); cidr != "" {
			out.CIDRBlocks = append(out.CIDRBlocks, cidr)
		}
	}
	return out
}

func projectSubnet(in ec2types.Subnet, region string) Subnet {
	id := aws.ToString(in.SubnetId)
	owner := aws.ToString(in.OwnerId)
	arn := strings.TrimSpace(aws.ToString(in.SubnetArn))
	if arn == "" {
		arn = EC2ResourceARN(region, owner, "subnet", id)
	}
	return Subnet{
		SubnetID:            id,
		AccountID:           owner,
		Region:              region,
		ARN:                 arn,
		VPCID:               aws.ToString(in.VpcId),
		CIDRBlock:           aws.ToString(in.CidrBlock),
		AvailabilityZone:    aws.ToString(in.AvailabilityZone),
		MapPublicIPOnLaunch: aws.ToBool(in.MapPublicIpOnLaunch),
		State:               string(in.State),
		Tags:                projectTags(in.Tags),
	}
}

func projectSecurityGroup(in ec2types.SecurityGroup, region string) SecurityGroup {
	id := aws.ToString(in.GroupId)
	owner := aws.ToString(in.OwnerId)
	return SecurityGroup{
		GroupID:   id,
		GroupName: aws.ToString(in.GroupName),
		VPCID:     aws.ToString(in.VpcId),
		AccountID: owner,
		Region:    region,
		Tags:      projectTags(in.Tags),
	}
}

// projectTags turns an EC2 tag list into a map, with the name-based redactor
// applied to the VALUES.
//
// Tags are free text the customer wrote, and a tag called `db_password` holds
// exactly what its name says often enough to matter. Projection cannot help
// here — the whole point of a tag is that we do not know its name in advance —
// so this is the one place in the cloud collectors where the name-based
// backstop is the primary defence rather than the belt to a braces.
//
// The tag is KEPT with its value masked rather than dropped: "this instance
// carries a tag called db_password" is itself worth knowing, and silently
// dropping it would hide it from the operator who should go and remove it.
func projectTags(tags []ec2types.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	out := make(map[string]string, len(tags))
	for _, t := range tags {
		k := strings.TrimSpace(aws.ToString(t.Key))
		if k == "" {
			continue
		}
		out[k] = redact.String(k, aws.ToString(t.Value))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
