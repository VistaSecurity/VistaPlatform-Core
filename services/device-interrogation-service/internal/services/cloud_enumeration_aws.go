package services

// AWS half of workstream 2.4: EC2 instances, VPCs, subnets and security groups.
//
// The API calls, and the IAM actions a customer has to grant for them:
//
//	ec2:DescribeInstances       compute instances (paginated, per region)
//	ec2:DescribeVpcs            virtual networks
//	ec2:DescribeSubnets         subnets
//	ec2:DescribeSecurityGroups  group membership (identity only, never rules)
//
// All four are read-only and all four are in the AWS-managed
// `ReadOnlyAccess`/`AmazonEC2ReadOnlyAccess` policies. Nothing here calls
// `ec2:DescribeInstanceAttribute`, which is what would return user data.

import (
	"context"
	"errors"
	"slices"
	"strings"

	awsclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/aws"
)

// enumerateAWS runs the selected listings in each region and builds the plan.
//
// One selection, per type, per region (asset-inventory ADR-0009 D3): each
// region is asked for every selected enumeration type, and each answer —
// or refusal — is recorded as that type's row for that region. A region that
// refuses one listing still answers the others: a credential without
// ec2:DescribeVpcs loses the networks, not the instances. Instances need the
// network listings to be placed (their ENIs' prefixes) and the group listing
// to name their groups, so selecting instances runs those too.
func (s *CloudDiscoveryService) enumerateAWS(ctx context.Context, client *awsclient.Client, regions []string, sel cloudEnumerationSelection) (cloudEnumerationPlan, error) {
	plan := cloudEnumerationPlan{Provider: "aws", Vendor: "AWS", SecurityGroupIDs: map[string]bool{}}
	if len(regions) == 0 {
		regions = []string{client.GetRegion()}
	}
	outcomes := cloudOutcomesFrom(ctx)
	for _, region := range regions {
		region = strings.TrimSpace(region)
		if region == "" {
			continue
		}
		api := client.EC2ClientForRegion(region)

		var (
			vpcs      []awsclient.VPC
			subnets   []awsclient.Subnet
			groups    []awsclient.SecurityGroup
			instances []awsclient.Instance
			gone      []awsclient.Instance
		)
		if sel.needsNetworks() {
			var vErr, sErr error
			vpcs, vErr = awsclient.ListVPCs(ctx, api, region)
			subnets, sErr = awsclient.ListSubnets(ctx, api, region)
			// One row per region for the type: a VPC listing that answered
			// and a subnet listing that did not is a partial `networks`.
			outcomes.Attempt(CloudTypeNetworks, region, len(vpcs)+len(subnets), errors.Join(vErr, sErr))
			logCloudCollectorFailure(CloudTypeNetworks, region, errors.Join(vErr, sErr))
		}
		if sel.needsGroups() {
			var err error
			groups, err = awsclient.ListSecurityGroups(ctx, api, region)
			outcomes.Attempt(CloudTypeSecurityGroups, region, len(groups), err)
			logCloudCollectorFailure(CloudTypeSecurityGroups, region, err)
		}
		if sel.Instances {
			var err error
			instances, gone, err = awsclient.ListInstancesWithTerminated(ctx, api, region)
			outcomes.Attempt(CloudTypeComputeInstances, region, len(instances), err)
			logCloudCollectorFailure(CloudTypeComputeInstances, region, err)
		}

		regional := buildAWSEnumerationPlan(instances, vpcs, subnets, groups)
		for i := range regional.Instances {
			regional.Instances[i].annotateListing(CloudListingKey(CloudTypeComputeInstances, region))
		}
		awsSecurityGroups(&regional, groups, region)
		for _, inst := range gone {
			if inst.ARN != "" {
				plan.Terminal = append(plan.Terminal, cloudTerminalResource{ResourceID: inst.ARN, State: normalizeProviderState("aws", inst.State)})
			}
		}
		plan.merge(regional)
	}
	return plan, nil
}

// buildAWSEnumerationPlan turns one region's projections into the
// provider-independent plan.
//
// A pure function of its inputs: no client, no clock, no database. That is what
// lets a test drive it from a recorded DescribeInstances response and assert
// the exact interfaces, addresses, prefixes, facts and attributes it produces.
//
// VPCs and subnets become prefixes (DCIM row 1.5f): each VPC CIDR block a
// container-shaped prefix and each subnet a prefix, all carrying the VPC's ARN
// as `cloud_network_ref`. Each instance's ENIs become `virtual` interfaces
// named by their ENI id, with their private addresses (configured with the
// subnet's length); the public address an ENI is associated with is the
// NAT-outside side and is recorded as the instance's `nat_outside_addresses`.
func buildAWSEnumerationPlan(
	instances []awsclient.Instance,
	vpcs []awsclient.VPC,
	subnets []awsclient.Subnet,
	groups []awsclient.SecurityGroup,
) cloudEnumerationPlan {
	plan := cloudEnumerationPlan{Provider: "aws", Vendor: "AWS", SecurityGroupIDs: map[string]bool{}}

	// vpc-id / subnet-id → canonical resource id, so an instance and an ENI
	// name their network by the same identity the prefix was recorded under.
	vpcARN := make(map[string]string, len(vpcs))
	subnetARN := make(map[string]string, len(subnets))

	for _, vpc := range vpcs {
		if vpc.ARN == "" {
			// No account id means no ARN, and a network named by its bare
			// vpc-id would collide with the same id in another account.
			continue
		}
		vpcARN[vpc.VPCID] = vpc.ARN
		plan.Networks = append(plan.Networks, cloudNetwork{
			ResourceID: vpc.ARN,
			NetworkRef: vpc.ARN,
			Account:    vpc.AccountID,
			Region:     vpc.Region,
			Name:       awsTagName(vpc.Tags, vpc.VPCID),
			CIDRs:      vpc.CIDRBlocks,
		})
	}

	for _, sn := range subnets {
		if sn.ARN == "" {
			continue
		}
		subnetARN[sn.SubnetID] = sn.ARN
		var cidrs []string
		if c := strings.TrimSpace(sn.CIDRBlock); c != "" {
			cidrs = []string{c}
		}
		plan.Subnets = append(plan.Subnets, cloudNetwork{
			ResourceID: sn.ARN,
			// The subnet's ADDRESS SPACE is its VPC: two VPCs may use the same
			// CIDR, and the identity scope of an address in this subnet must
			// say which. A subnet whose VPC was not listed names no network.
			NetworkRef: vpcARN[sn.VPCID],
			Account:    sn.AccountID,
			Region:     sn.Region,
			Name:       awsTagName(sn.Tags, sn.SubnetID),
			CIDRs:      cidrs,
		})
	}
	lengths := subnetPrefixLengths(plan.Subnets)

	// Group names, for the membership fact. An instance's own SecurityGroups
	// list already carries id and name, so this index only fills in a name the
	// instance payload omitted.
	groupName := make(map[string]string, len(groups))
	for _, g := range groups {
		if g.GroupID == "" {
			continue
		}
		plan.SecurityGroupIDs[g.GroupID] = true
		groupName[g.GroupID] = g.GroupName
	}

	for _, inst := range instances {
		if inst.ARN == "" {
			continue
		}
		sgs := make([]map[string]any, 0, len(inst.SecurityGroups))
		for _, g := range inst.SecurityGroups {
			plan.SecurityGroupIDs[g.ID] = true
			name := g.Name
			if name == "" {
				name = groupName[g.ID]
			}
			entry := map[string]any{"id": g.ID}
			if name != "" {
				entry["name"] = name
			}
			sgs = append(sgs, entry)
		}

		nics := make([]cloudNIC, 0, len(inst.Interfaces))
		var natOutside []string
		for _, ni := range inst.Interfaces {
			nics = append(nics, cloudNIC{
				Name: ni.Name, MAC: ni.MAC, State: ni.State, Addresses: ni.Addresses,
				Subnet: subnetARN[firstNonEmpty(ni.SubnetID, inst.SubnetID)],
			})
			if ip := strings.TrimSpace(ni.PublicIP); ip != "" && !slices.Contains(natOutside, ip) {
				natOutside = append(natOutside, ip)
			}
		}
		network := vpcARN[inst.VPCID]

		display := awsTagName(inst.Tags, inst.InstanceID)
		plan.Instances = append(plan.Instances, cloudEnumResource{
			DeviceType:  DeviceTypeAWSEC2Instance,
			ResourceID:  inst.ARN,
			DisplayName: display,
			// The PRIVATE DNS name, not the Name tag: `assets.hostname` is a
			// name the machine answers to, and a tag is a label. The tag is
			// still the display name above.
			//
			// Except when that name is EC2's IP-name form, which is an alias of
			// the private address rather than a name of the machine and is
			// unique only inside one VPC's resolver. A dotted hostname becomes
			// an unscoped `fqdn` identifier, and giving that kind a value that
			// is not globally unique merges two instances into one asset
			// silently — see awsclient.IsIPDerivedPrivateDNSName. It stays on
			// the metadata below, where it is a description rather than a key.
			Hostname:  awsInstanceHostname(inst),
			IPAddress: firstAddress(inst.PrivateIPs),
			// The VPC, not the subnet: this is which ADDRESS SPACE the
			// instance's private addresses are in, and two VPCs may use the
			// same CIDR.
			CloudNetworkRef: network,
			Interfaces:      cloudInterfaces(nics, lengths),
			Prefixes:        instancePrefixes(network, nics, plan.Networks, plan.Subnets),
			Facts:           cloudPlacementFacts("aws", inst.AccountID, inst.Region, inst.ARN, sgs),
			Attributes: mergeAttributes(
				cloudResourceAttributes("aws", inst.AccountID, inst.Region),
				map[string]any{
					"instance_type":         inst.InstanceType,
					"image_id":              inst.ImageID,
					"nat_outside_addresses": natOutside,
					// operating_system / os_version are deliberately absent:
					// EC2 states no guest OS. See the note on
					// awsclient.Instance.
				},
			),
			Tags: tagsToJSONB(inst.Tags),
			Metadata: map[string]interface{}{
				"resource_type":     "ec2",
				"region":            inst.Region,
				"vpc_id":            inst.VPCID,
				"subnet_id":         inst.SubnetID,
				"instance_id":       inst.InstanceID,
				"instance_type":     inst.InstanceType,
				"state":             inst.State,
				"availability_zone": inst.AvailabilityZone,
				"image_id":          inst.ImageID,
				"platform_details":  inst.PlatformDetails,
				"architecture":      inst.Architecture,
				// The key pair NAME. The private half never leaves the
				// customer and the public half is not requested.
				"key_name":    inst.KeyName,
				"launch_time": inst.LaunchTime,
				// Kept whichever form it takes. The IP-name form is refused as
				// a hostname (it is not globally unique) but it is still what
				// the instance answers to inside its own VPC, and an operator
				// reading the resource should see it.
				"private_dns_name": inst.PrivateDNSName,
			},
		})
	}
	return plan
}

// awsInstanceHostname is the name an instance ANSWERS TO, or "" when EC2 states
// none that is safe to use as one.
//
// The Name tag is deliberately not a fallback. It is a label the operator
// chose, duplicated across environments as a matter of routine ("web-01" in
// dev and in prod), and a bare hostname identifier is scoped only to the
// tenant-wide default — so falling back to it would reintroduce, one
// precedence level down, exactly the silent merge that refusing the IP-name
// form avoids. An instance with no usable hostname has none; the Name tag is
// still its display name and still on `assets.tags`.
func awsInstanceHostname(inst awsclient.Instance) string {
	name := strings.TrimSpace(inst.PrivateDNSName)
	if name == "" || awsclient.IsIPDerivedPrivateDNSName(name) {
		return ""
	}
	return name
}

// awsTagName returns the value of the `Name` tag, falling back to the resource
// id. AWS's console shows the Name tag as the resource's label and operators
// search for it, so it is the display name — but never the hostname.
func awsTagName(tags map[string]string, fallback string) string {
	for _, key := range []string{"Name", "name"} {
		if v := strings.TrimSpace(tags[key]); v != "" {
			return v
		}
	}
	return fallback
}

// cloudResourceAttributes is the `cloud_resource` base attribute set every
// cloud class inherits.
func cloudResourceAttributes(provider, accountID, region string) map[string]any {
	out := map[string]any{"provider": provider}
	if v := strings.TrimSpace(accountID); v != "" {
		out["account_id"] = v
	}
	if v := strings.TrimSpace(region); v != "" {
		out["region"] = v
	}
	return out
}

// mergeAttributes folds the class-specific attributes onto the inherited ones,
// dropping empty values. An attribute set to "" or an empty list is not a
// weaker fact, it is an absent one, and storing it would make "not collected"
// and "collected as nothing" the same row.
func mergeAttributes(base map[string]any, extra map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(extra))
	add := func(m map[string]any) {
		for k, v := range m {
			switch t := v.(type) {
			case nil:
				continue
			case string:
				if strings.TrimSpace(t) == "" {
					continue
				}
			case []string:
				if len(t) == 0 {
					continue
				}
			case []any:
				if len(t) == 0 {
					continue
				}
			}
			out[k] = v
		}
	}
	add(base)
	add(extra)
	return out
}
