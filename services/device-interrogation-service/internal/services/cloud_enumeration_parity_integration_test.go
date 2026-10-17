package services

// DCIM row 1.5f: the cloud collectors' network projection through the intake
// seam, held to identitytest.RunAdapterParity.
//
// Each adapter drives the REAL path from a RECORDED provider response: the
// provider projection (for AWS the EC2 list calls themselves, over a fake
// EC2API serving the recorded DescribeVpcs / DescribeSubnets /
// DescribeSecurityGroups / DescribeInstances pages), the provider's plan
// builder, the enumerated instance's device record and the sighting
// production resolves it by (cloudResourceSighting) → identity.Intake →
// identity.Engine → Postgres. The harness then requires exactly the ENIs as
// `virtual` interfaces with their private addresses, the VPC / VNet and its
// subnets as prefixes in the network's address space (`cloud_network_ref`),
// the primary address, an idempotent re-run, and every planted secret absent
// from every tenant table.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/google/uuid"

	awsclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/aws"
	azureclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/azure"
	gcpclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/gcp"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/identitytest"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func cloudParityFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "cloud_parity", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// parityEC2 serves one recorded page of each EC2 list call.
type parityEC2 struct {
	instances *ec2.DescribeInstancesOutput
	vpcs      *ec2.DescribeVpcsOutput
	subnets   *ec2.DescribeSubnetsOutput
	groups    *ec2.DescribeSecurityGroupsOutput
}

func (f parityEC2) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return f.instances, nil
}
func (f parityEC2) DescribeVpcs(context.Context, *ec2.DescribeVpcsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
	return f.vpcs, nil
}
func (f parityEC2) DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	return f.subnets, nil
}
func (f parityEC2) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return f.groups, nil
}

// enumeratedInstanceSighting is the sighting production resolves one
// enumerated instance by: the device record recordCloudResource builds, and
// cloudResourceSighting with the instance in the context, exactly as
// upsertDeviceAssetWith calls it.
func enumeratedInstanceSighting(tenantID string, vendor string, res cloudEnumResource, at time.Time) (identity.Sighting, error) {
	tenant, err := uuid.Parse(tenantID)
	if err != nil {
		return identity.Sighting{}, err
	}
	device := enumeratedDevice(tenant, uuid.New(), vendor, res, at)
	ctx := context.WithValue(context.Background(), cloudEnumerationContextKey{}, &res)
	return cloudResourceSighting(ctx, &device, res.ResourceID, res.CloudNetworkRef, "parity:"+res.ResourceID+":"+at.Format(time.RFC3339), at)
}

func onlyInstance(plan cloudEnumerationPlan) (cloudEnumResource, error) {
	if len(plan.Instances) != 1 {
		return cloudEnumResource{}, fmt.Errorf("the recorded response projects %d instances, want 1", len(plan.Instances))
	}
	return plan.Instances[0], nil
}

// awsParityAdapter: recorded EC2 pages → awsclient.List* (the projection
// boundary, tag redaction included) → buildAWSEnumerationPlan → the
// instance's sighting. The recorded account also lists an S3 bucket, which is
// another collector's and must contribute nothing to the network.
var awsParityAdapter = identitytest.ParityAdapterFunc{
	AdapterName: "cloud/aws",
	Fn: func(tenantID string, response []byte, at time.Time) (identity.Sighting, error) {
		var rec struct {
			Region    string                            `json:"region"`
			Instances *ec2.DescribeInstancesOutput      `json:"describe_instances"`
			VPCs      *ec2.DescribeVpcsOutput           `json:"describe_vpcs"`
			Subnets   *ec2.DescribeSubnetsOutput        `json:"describe_subnets"`
			Groups    *ec2.DescribeSecurityGroupsOutput `json:"describe_security_groups"`
			Buckets   json.RawMessage                   `json:"list_buckets"`
		}
		if err := json.Unmarshal(response, &rec); err != nil {
			return identity.Sighting{}, err
		}
		api := parityEC2{instances: rec.Instances, vpcs: rec.VPCs, subnets: rec.Subnets, groups: rec.Groups}
		ctx := context.Background()
		vpcs, err := awsclient.ListVPCs(ctx, api, rec.Region)
		if err != nil {
			return identity.Sighting{}, err
		}
		subnets, err := awsclient.ListSubnets(ctx, api, rec.Region)
		if err != nil {
			return identity.Sighting{}, err
		}
		groups, err := awsclient.ListSecurityGroups(ctx, api, rec.Region)
		if err != nil {
			return identity.Sighting{}, err
		}
		instances, err := awsclient.ListInstances(ctx, api, rec.Region)
		if err != nil {
			return identity.Sighting{}, err
		}
		res, err := onlyInstance(buildAWSEnumerationPlan(instances, vpcs, subnets, groups))
		if err != nil {
			return identity.Sighting{}, err
		}
		return enumeratedInstanceSighting(tenantID, "AWS", res, at)
	},
}

// azureParityAdapter: recorded, already-projected Azure listings (the ARM
// projection is pinned in internal/cloud/azure) → buildAzureEnumerationPlan →
// the VM's sighting. A field the projection does not declare is discarded by
// the JSON decode, structurally.
var azureParityAdapter = identitytest.ParityAdapterFunc{
	AdapterName: "cloud/azure",
	Fn: func(tenantID string, response []byte, at time.Time) (identity.Sighting, error) {
		var rec struct {
			VNets []struct {
				azureclient.VirtualNetwork
				Subnets []azureclient.Subnet `json:"subnets"`
			} `json:"virtual_networks"`
			VMs []azureclient.VirtualMachine `json:"virtual_machines"`
		}
		if err := json.Unmarshal(response, &rec); err != nil {
			return identity.Sighting{}, err
		}
		vnets := make([]azureclient.VirtualNetwork, 0, len(rec.VNets))
		for _, v := range rec.VNets {
			vn := v.VirtualNetwork
			vn.Subnets = v.Subnets
			vnets = append(vnets, vn)
		}
		res, err := onlyInstance(buildAzureEnumerationPlan(rec.VMs, vnets, nil))
		if err != nil {
			return identity.Sighting{}, err
		}
		return enumeratedInstanceSighting(tenantID, "Azure", res, at)
	},
}

// gcpParityAdapter: recorded Compute Engine REST items decoded into the
// collector's own types (their JSON tags ARE the projection: `accessConfigs`
// and `metadata` have no field) → buildGCPEnumerationPlan → the instance's
// sighting.
var gcpParityAdapter = identitytest.ParityAdapterFunc{
	AdapterName: "cloud/gcp",
	Fn: func(tenantID string, response []byte, at time.Time) (identity.Sighting, error) {
		var rec struct {
			Project     string                        `json:"project"`
			Networks    []gcpclient.ComputeNetwork    `json:"networks"`
			Subnetworks []gcpclient.ComputeSubnetwork `json:"subnetworks"`
			Instances   []gcpclient.ComputeInstance   `json:"instances"`
		}
		if err := json.Unmarshal(response, &rec); err != nil {
			return identity.Sighting{}, err
		}
		res, err := onlyInstance(buildGCPEnumerationPlan(rec.Project, rec.Instances, rec.Networks, rec.Subnetworks, nil))
		if err != nil {
			return identity.Sighting{}, err
		}
		return enumeratedInstanceSighting(tenantID, "GCP", res, at)
	},
}

func notDHCP() *bool { f := false; return &f }

// TestIntegration_CloudEnumeration_AWSAdapterParity — a VPC, two subnets, an
// instance with two ENIs (the first with a secondary private address and a
// public association), a security group and a bucket.
//
// Mutations, each red: drop `CloudNetworkRef` from cloudNetwork.prefixes (the
// prefixes' cloud_network_ref); drop the Interfaces assignment in withEnumeratedNetwork
// (no interfaces, the primary address on a synthetic one); drop the subnet
// length in cloudInterfaces (the /24s become /32s); put the ENI Description
// into the projection (the planted secret is found).
func TestIntegration_CloudEnumeration_AWSAdapterParity(t *testing.T) {
	const vpc = "arn:aws:ec2:us-east-1:111122223333:vpc/vpc-0a1f00000000000a1"
	identitytest.RunAdapterParity(t, awsParityAdapter, []identitytest.ParityFixture{{
		Name:     "vpc-two-subnets-two-enis-bucket",
		Response: cloudParityFixture(t, "aws-us-east-1.json"),
		Secrets:  []string{"AKIAPLANTEDSECRET0001wJalrXUtnFEMI", "PlantedEniSecret7731"},
		Want: identitytest.ParityWant{
			Interfaces: []identitytest.WantInterface{
				{Name: "eni-0d1f0000000000d1", Type: "virtual", MAC: "0a:11:22:33:44:01", OperStatus: "up",
					Addresses: []string{"10.20.1.10/24", "10.20.1.11/24"}},
				{Name: "eni-0d2f0000000000d2", Type: "virtual", MAC: "0a:11:22:33:44:02", OperStatus: "up",
					Addresses: []string{"10.20.2.10/24"}},
			},
			Prefixes: []identitytest.WantPrefix{
				{Prefix: "10.20.0.0/16", DHCPManaged: notDHCP(), CloudNetworkRef: vpc},
				{Prefix: "10.20.1.0/24", DHCPManaged: notDHCP(), CloudNetworkRef: vpc},
				{Prefix: "10.20.2.0/24", DHCPManaged: notDHCP(), CloudNetworkRef: vpc},
			},
			PrimaryIP4: "10.20.1.10",
		},
	}})
}

// TestIntegration_CloudEnumeration_AzureAdapterParity — a VNet, a subnet and
// a VM with one NIC.
func TestIntegration_CloudEnumeration_AzureAdapterParity(t *testing.T) {
	const vnet = "/subscriptions/sub-0001/resourceGroups/rg-prod/providers/Microsoft.Network/virtualNetworks/vnet-prod"
	identitytest.RunAdapterParity(t, azureParityAdapter, []identitytest.ParityFixture{{
		Name:     "vnet-subnet-vm",
		Response: cloudParityFixture(t, "azure-westeurope.json"),
		Secrets:  []string{"PlantedAzureSecret4410"},
		Want: identitytest.ParityWant{
			Interfaces: []identitytest.WantInterface{
				{Name: "app-01-nic", Type: "virtual", MAC: "00:0d:3a:aa:bb:01", Addresses: []string{"10.30.1.4/24"}},
			},
			Prefixes: []identitytest.WantPrefix{
				{Prefix: "10.30.0.0/16", DHCPManaged: notDHCP(), CloudNetworkRef: vnet},
				{Prefix: "10.30.1.0/24", DHCPManaged: notDHCP(), CloudNetworkRef: vnet},
			},
			PrimaryIP4: "10.30.1.4",
		},
	}})
}

// TestIntegration_CloudEnumeration_GCPAdapterParity — a custom-mode network
// (no range of its own, so no container prefix), a subnetwork and an
// instance with one NIC and an external NAT address that is not collected.
func TestIntegration_CloudEnumeration_GCPAdapterParity(t *testing.T) {
	identitytest.RunAdapterParity(t, gcpParityAdapter, []identitytest.ParityFixture{{
		Name:     "network-subnetwork-instance",
		Response: cloudParityFixture(t, "gcp-us-central1.json"),
		Secrets:  []string{"PlantedGcpSecret9921"},
		Want: identitytest.ParityWant{
			Interfaces: []identitytest.WantInterface{
				{Name: "nic0", Type: "virtual", Addresses: []string{"10.40.0.7/20"}},
			},
			Prefixes: []identitytest.WantPrefix{{Prefix: "10.40.0.0/20", DHCPManaged: notDHCP(),
				CloudNetworkRef: "projects/proj-parity/global/networks/prod-vpc"}},
			PrimaryIP4: "10.40.0.7",
		},
	}})
}

// awsRecordedPlan is the AWS fixture's plan through the real projection, for
// the tests that record it through the whole funnel.
func awsRecordedPlan(t *testing.T) cloudEnumerationPlan {
	t.Helper()
	var rec struct {
		Region    string                            `json:"region"`
		Instances *ec2.DescribeInstancesOutput      `json:"describe_instances"`
		VPCs      *ec2.DescribeVpcsOutput           `json:"describe_vpcs"`
		Subnets   *ec2.DescribeSubnetsOutput        `json:"describe_subnets"`
		Groups    *ec2.DescribeSecurityGroupsOutput `json:"describe_security_groups"`
	}
	if err := json.Unmarshal(cloudParityFixture(t, "aws-us-east-1.json"), &rec); err != nil {
		t.Fatal(err)
	}
	api := parityEC2{instances: rec.Instances, vpcs: rec.VPCs, subnets: rec.Subnets, groups: rec.Groups}
	ctx := context.Background()
	vpcs, err := awsclient.ListVPCs(ctx, api, rec.Region)
	if err != nil {
		t.Fatal(err)
	}
	subnets, err := awsclient.ListSubnets(ctx, api, rec.Region)
	if err != nil {
		t.Fatal(err)
	}
	groups, err := awsclient.ListSecurityGroups(ctx, api, rec.Region)
	if err != nil {
		t.Fatal(err)
	}
	instances, err := awsclient.ListInstances(ctx, api, rec.Region)
	if err != nil {
		t.Fatal(err)
	}
	return buildAWSEnumerationPlan(instances, vpcs, subnets, groups)
}

// TestIntegration_CloudEnumeration_PlantedSecretsNeverPersisted records the
// AWS fixture through the WHOLE funnel — the account's network listing, the
// instance with its tags, facts, attributes and management fields — and looks
// for the planted access key (in a tag) and ENI secret (in a field the
// projection does not declare) in every row of every tenant table.
//
// Mutation: take the redactor out of awsclient.projectTags — red (the access
// key reaches assets.tags).
func TestIntegration_CloudEnumeration_PlantedSecretsNeverPersisted(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	appDB := testdb.ConnectAsAppRole(t, owner)
	svc := NewCloudDiscoveryService(appDB, owner, testMasterKey)
	integration := seedAccountIntegration(t, owner, tenantID, "111122223333", true)
	ctx := svc.beginCloudRun(context.Background(), tenantID, integration, "aws")

	plan := awsRecordedPlan(t)
	devices, _, err := svc.recordEnumeration(ctx, tenantID, integration, "production", plan)
	if err != nil || len(devices) != 1 {
		t.Fatalf("recordEnumeration: %d devices, %v", len(devices), err)
	}
	// The tag is kept, masked: "this instance carries a tag called
	// aws_secret_access_key" is worth knowing.
	var tag string
	if err := owner.QueryRow(`SELECT coalesce(tags->>'aws_secret_access_key', '') FROM assets WHERE tenant_id = $1 AND id = $2`,
		tenantID, devices[0].ID).Scan(&tag); err != nil {
		t.Fatal(err)
	}
	if tag == "" {
		t.Error("the secret-named tag vanished; it should be kept with its value masked")
	}

	rows, err := owner.Query(`
		SELECT c.table_name FROM information_schema.columns c
		  JOIN information_schema.tables tb ON tb.table_schema = c.table_schema AND tb.table_name = c.table_name
		 WHERE c.table_schema = 'public' AND c.column_name = 'tenant_id' AND tb.table_type = 'BASE TABLE'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	_ = rows.Close()
	if len(tables) < 10 {
		t.Fatalf("found only %d tenant tables to search; the check would prove nothing", len(tables))
	}
	for _, table := range tables {
		for _, secret := range []string{"AKIAPLANTEDSECRET0001wJalrXUtnFEMI", "PlantedEniSecret7731"} {
			var n int
			if err := owner.QueryRow(`SELECT count(*) FROM public."`+table+`" t
				WHERE t.tenant_id = $1 AND strpos(to_jsonb(t)::text, $2) > 0`, tenantID, secret).Scan(&n); err != nil {
				t.Fatalf("searching %s: %v", table, err)
			}
			if n > 0 {
				t.Errorf("planted secret %q reached %d row(s) of %s", secret, n, table)
			}
		}
	}
}
