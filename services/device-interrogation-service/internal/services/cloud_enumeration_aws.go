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
	"log"
	"strings"

	awsclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/aws"
	"github.com/vistasecurity/vistaplatform/shared/facts"
)

// enumerateAWS runs the four calls in each region and builds the plan.
//
// A region that fails is LOGGED AND SKIPPED rather than failing the run: an
// account with an opted-out region, or a credential scoped to a subset,
// otherwise loses every other region's inventory to one AuthFailure. The error
// is not swallowed silently — it names the region and the call.
func (s *CloudDiscoveryService) enumerateAWS(ctx context.Context, client *awsclient.Client, regions []string) (cloudEnumerationPlan, error) {
	plan := cloudEnumerationPlan{Provider: "aws", Vendor: "AWS", SecurityGroupIDs: map[string]bool{}}
	if len(regions) == 0 {
		regions = []string{client.GetRegion()}
	}
	for _, region := range regions {
		region = strings.TrimSpace(region)
		if region == "" {
			continue
		}
		api := client.EC2ClientForRegion(region)

		vpcs, err := awsclient.ListVPCs(ctx, api, region)
		if err != nil {
			log.Printf("[cloud enumeration] aws %s: %v", region, err)
			continue
		}
		subnets, err := awsclient.ListSubnets(ctx, api, region)
		if err != nil {
			log.Printf("[cloud enumeration] aws %s: %v", region, err)
			continue
		}
		groups, err := awsclient.ListSecurityGroups(ctx, api, region)
		if err != nil {
			// Group membership is an attribute, not the inventory. Losing it
			// must not lose the instances.
			log.Printf("[cloud enumeration] aws %s: %v (instances will carry no security-group membership)", region, err)
			groups = nil
		}
		instances, err := awsclient.ListInstances(ctx, api, region)
		if err != nil {
			log.Printf("[cloud enumeration] aws %s: %v", region, err)
			continue
		}

		regional := buildAWSEnumerationPlan(instances, vpcs, subnets, groups)
		plan.Networks = append(plan.Networks, regional.Networks...)
		plan.Subnets = append(plan.Subnets, regional.Subnets...)
		plan.Instances = append(plan.Instances, regional.Instances...)
		for id := range regional.SecurityGroupIDs {
			plan.SecurityGroupIDs[id] = true
		}
	}
	return plan, nil
}

// buildAWSEnumerationPlan turns one region's projections into the
// provider-independent plan.
//
// A pure function of its inputs: no client, no clock, no database. That is what
// lets a test drive it from a recorded DescribeInstances response and assert
// the exact facts, attributes and containment it produces.
func buildAWSEnumerationPlan(
	instances []awsclient.Instance,
	vpcs []awsclient.VPC,
	subnets []awsclient.Subnet,
	groups []awsclient.SecurityGroup,
) cloudEnumerationPlan {
	plan := cloudEnumerationPlan{Provider: "aws", Vendor: "AWS", SecurityGroupIDs: map[string]bool{}}

	// vpc-id / subnet-id → canonical resource id, so a child can name its
	// container by the same identity the container was recorded under.
	vpcARN := make(map[string]string, len(vpcs))
	subnetARN := make(map[string]string, len(subnets))

	for _, vpc := range vpcs {
		if vpc.ARN == "" {
			// No account id means no ARN, and a VPC recorded under its bare
			// vpc-id would collide with the same id in another account.
			continue
		}
		vpcARN[vpc.VPCID] = vpc.ARN
		name := awsTagName(vpc.Tags, vpc.VPCID)
		plan.Networks = append(plan.Networks, cloudEnumResource{
			DeviceType:  DeviceTypeAWSVPC,
			ResourceID:  vpc.ARN,
			DisplayName: name,
			Hostname:    name,
			Facts: cloudPlacementFacts("aws", vpc.AccountID, vpc.Region, vpc.ARN,
				vpc.VPCID, "", nil),
			Attributes: mergeAttributes(
				cloudResourceAttributes("aws", vpc.AccountID, vpc.Region),
				map[string]any{"cidr_blocks": vpc.CIDRBlocks},
			),
			Tags: tagsToJSONB(vpc.Tags),
			Metadata: map[string]interface{}{
				"resource_type": "vpc",
				"region":        vpc.Region,
				"vpc_id":        vpc.VPCID,
				"state":         vpc.State,
				"is_default":    vpc.IsDefault,
				"cidr_blocks":   vpc.CIDRBlocks,
			},
		})
	}

	for _, sn := range subnets {
		if sn.ARN == "" {
			continue
		}
		subnetARN[sn.SubnetID] = sn.ARN
		name := awsTagName(sn.Tags, sn.SubnetID)
		plan.Subnets = append(plan.Subnets, cloudEnumResource{
			DeviceType:  DeviceTypeAWSSubnet,
			ResourceID:  sn.ARN,
			DisplayName: name,
			Hostname:    name,
			ParentID:    vpcARN[sn.VPCID],
			SegmentCIDR: sn.CIDRBlock,
			// The subnet's network IS its parent; spelled out rather than
			// derived so the recording path never has to know the shape.
			CloudNetworkRef: vpcARN[sn.VPCID],
			Facts: cloudPlacementFacts("aws", sn.AccountID, sn.Region, sn.ARN,
				sn.VPCID, sn.SubnetID, nil),
			Attributes: mergeAttributes(
				cloudResourceAttributes("aws", sn.AccountID, sn.Region),
				map[string]any{
					"cidr_block":        sn.CIDRBlock,
					"availability_zone": sn.AvailabilityZone,
					// `is_public` is NOT set from MapPublicIpOnLaunch. The class
					// schema defines it as "whether the subnet routes to an
					// internet gateway", and auto-assign-public-IP is a
					// different setting: a subnet can auto-assign and have no
					// IGW route, or route to one and not auto-assign. Answering
					// it needs ec2:DescribeRouteTables, which is a further IAM
					// grant and a further call; until it is made, the attribute
					// stays absent rather than carrying a near-miss.
				},
			),
			Tags: tagsToJSONB(sn.Tags),
			Metadata: map[string]interface{}{
				"resource_type":           "subnet",
				"region":                  sn.Region,
				"vpc_id":                  sn.VPCID,
				"subnet_id":               sn.SubnetID,
				"cidr_block":              sn.CIDRBlock,
				"availability_zone":       sn.AvailabilityZone,
				"map_public_ip_on_launch": sn.MapPublicIPOnLaunch,
				"state":                   sn.State,
			},
		})
	}

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

		factValues := cloudPlacementFacts("aws", inst.AccountID, inst.Region, inst.ARN,
			inst.VPCID, inst.SubnetID, sgs)
		if ifaces := awsInterfaceFact(inst); len(ifaces) > 0 {
			factValues[facts.KeyNetInterfaces] = ifaces
		}

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
			ParentID:  subnetARN[inst.SubnetID],
			// The VPC, not the subnet: this is which ADDRESS SPACE the
			// instance's private address is in, and two VPCs may use the same
			// CIDR.
			CloudNetworkRef: vpcARN[inst.VPCID],
			Facts:           factValues,
			Attributes: mergeAttributes(
				cloudResourceAttributes("aws", inst.AccountID, inst.Region),
				map[string]any{
					"instance_type": inst.InstanceType,
					"image_id":      inst.ImageID,
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

// awsInterfaceFact renders an instance's ENIs as the `net.interfaces` value.
func awsInterfaceFact(inst awsclient.Instance) []map[string]any {
	out := make([]map[string]any, 0, len(inst.Interfaces))
	for _, iface := range inst.Interfaces {
		entry := map[string]any{"name": iface.Name}
		if iface.MAC != "" {
			entry["mac"] = iface.MAC
		}
		if len(iface.Addresses) > 0 {
			entry["addresses"] = iface.Addresses
		}
		switch strings.ToLower(iface.State) {
		case "in-use", "attached", "available":
			entry["state"] = "up"
		case "detaching", "attaching":
			entry["state"] = "unknown"
		case "":
		default:
			entry["state"] = "unknown"
		}
		out = append(out, entry)
	}
	return out
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
