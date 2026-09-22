package services

// Cloud account and region as scoping attributes on EVERY cloud-discovered
// asset ( slice D, owner decision D6).
//
// Enumeration already wrote `cloud.account_id` and `cloud.region` for
// instances, VPCs and subnets. The crypto and at-rest collectors — buckets, CDN
// distributions, key stores, load balancers — wrote neither, which is why a
// bucket had nothing to be grouped under on the map and sat there as an
// isolated box.
//
// Account and region are attributes, not asset classes: no asset rows, no
// findings, no risk scores, and nothing here touches `shared/assetclass`. What
// is easy to get wrong is the honesty of the empty cases, so most of what
// follows is about those.

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/facts"
)

func TestAccountIDFromARN(t *testing.T) {
	for _, tc := range []struct {
		name string
		arn  string
		want string
	}{
		{"an EC2 instance ARN carries the account", "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc", "123456789012"},
		{
			// CloudFront is global: the REGION field is the empty one, and the
			// account is still there. Splitting on ':' positionally is what
			// makes this work; anything that assumed a region was present would
			// read the account out of the wrong field.
			"a CloudFront ARN has no region but does have an account",
			"arn:aws:cloudfront::123456789012:distribution/E123", "123456789012",
		},
		{
			// The case that forces the integration fallback to exist. S3 bucket
			// ARNs legitimately name no account, and returning "aws" or "s3"
			// here would stamp every bucket with an account that is a word.
			"an S3 bucket ARN names no account",
			"arn:aws:s3:::assets-bucket", "",
		},
		{"an Azure resource id is not an ARN", "/subscriptions/abc/resourceGroups/rg/providers/x", ""},
		{"a GCP self link is not an ARN", "https://www.googleapis.com/compute/v1/projects/p/zones/z/instances/i", ""},
		{"a bare instance id is not an ARN", "i-0abc", ""},
		{"empty in, empty out", "", ""},
		{"a string that merely starts with arn is not one", "arn:aws:ec2", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := accountIDFromARN(tc.arn); got != tc.want {
				t.Errorf("accountIDFromARN(%q) = %q, want %q", tc.arn, got, tc.want)
			}
		})
	}
}

func bucketDevice(meta models.JSONB) models.Device {
	return models.Device{
		ID:         uuid.New(),
		TenantID:   uuid.New(),
		DeviceType: "aws_s3_bucket",
		Vendor:     stringPtr("AWS"),
		Metadata:   meta,
	}
}

func TestCloudScopeValues(t *testing.T) {
	scope := cloudScope{Provider: "aws", AccountID: "123456789012"}

	t.Run("a bucket takes its region from the resource and its account from the integration", func(t *testing.T) {
		values, attrs := cloudScopeValues(scope, bucketDevice(models.JSONB{
			"arn":    "arn:aws:s3:::assets-bucket",
			"region": "us-east-1",
		}))
		if values[facts.KeyCloudRegion] != "us-east-1" {
			t.Errorf("cloud.region = %v, want us-east-1", values[facts.KeyCloudRegion])
		}
		if values[facts.KeyCloudAccountID] != "123456789012" {
			t.Errorf("cloud.account_id = %v, want the integration's account", values[facts.KeyCloudAccountID])
		}
		if values[facts.KeyCloudProvider] != "aws" {
			t.Errorf("cloud.provider = %v, want aws", values[facts.KeyCloudProvider])
		}
		// The same three, mirrored onto the class attributes the Inventory
		// facets read. `object_storage` inherits them from `cloud_resource`.
		if attrs["region"] != "us-east-1" || attrs["account_id"] != "123456789012" || attrs["provider"] != "aws" {
			t.Errorf("attributes = %v", attrs)
		}
	})

	t.Run("the resource's OWN account wins over the integration's", func(t *testing.T) {
		// A shared VPC belongs to the account that created it, not to the
		// credential that happened to be able to read it.
		values, _ := cloudScopeValues(scope, bucketDevice(models.JSONB{
			"arn":    "arn:aws:ec2:us-east-1:210987654321:vpc/vpc-0abc",
			"region": "us-east-1",
		}))
		if values[facts.KeyCloudAccountID] != "210987654321" {
			t.Errorf("cloud.account_id = %v, want the ARN's account", values[facts.KeyCloudAccountID])
		}
	})

	t.Run("a CloudFront distribution keeps the honest literal global", func(t *testing.T) {
		device := models.Device{
			ID: uuid.New(), TenantID: uuid.New(),
			DeviceType: "aws_cloudfront", Vendor: stringPtr("AWS"),
			Metadata: models.JSONB{"distribution_id": "E123"},
		}
		values, _ := cloudScopeValues(scope, device)
		if values[facts.KeyCloudRegion] != "global" {
			t.Errorf("cloud.region = %v, want the literal \"global\"", values[facts.KeyCloudRegion])
		}
	})

	t.Run("no region recorded writes NO region fact", func(t *testing.T) {
		// Unknown is not a default. A `cloud.region: ""` here would draw a
		// grouping node on the map labelled with nothing, and a facet value
		// nobody can act on.
		values, attrs := cloudScopeValues(scope, bucketDevice(models.JSONB{"arn": "arn:aws:s3:::assets-bucket"}))
		if _, present := values[facts.KeyCloudRegion]; present {
			t.Errorf("cloud.region was written for a resource that records none: %v", values)
		}
		if _, present := attrs["region"]; present {
			t.Errorf("region attribute was written for a resource that records none: %v", attrs)
		}
		// The account it DOES know still lands — an absent region must not cost
		// the resource the scope it has.
		if values[facts.KeyCloudAccountID] != "123456789012" {
			t.Errorf("cloud.account_id = %v, want it kept", values[facts.KeyCloudAccountID])
		}
	})

	t.Run("no account anywhere writes NO account fact", func(t *testing.T) {
		values, attrs := cloudScopeValues(
			cloudScope{Provider: "aws"},
			bucketDevice(models.JSONB{"arn": "arn:aws:s3:::assets-bucket", "region": "us-east-1"}),
		)
		if _, present := values[facts.KeyCloudAccountID]; present {
			t.Errorf("cloud.account_id was invented: %v", values)
		}
		if _, present := attrs["account_id"]; present {
			t.Errorf("account_id attribute was invented: %v", attrs)
		}
		if values[facts.KeyCloudRegion] != "us-east-1" {
			t.Errorf("cloud.region = %v, want it kept", values[facts.KeyCloudRegion])
		}
	})

	t.Run("nothing known at all writes nothing", func(t *testing.T) {
		values, attrs := cloudScopeValues(cloudScope{}, bucketDevice(models.JSONB{}))
		if len(values) != 0 || len(attrs) != 0 {
			t.Errorf("values = %v, attrs = %v; want both empty", values, attrs)
		}
	})
}

func TestCloudScopeExtra_NilWhenThereIsNothingToSay(t *testing.T) {
	svc := &CloudDiscoveryService{}
	if svc.cloudScopeExtra(context.Background(), nil) != nil {
		t.Error("a nil device produced a hook")
	}
	// No scope in the context and no region on the device: nothing to write, so
	// no hook — rather than a hook that opens a transaction to write nothing.
	device := bucketDevice(models.JSONB{"arn": "arn:aws:s3:::assets-bucket"})
	if svc.cloudScopeExtra(context.Background(), &device) != nil {
		t.Error("a device with no scope at all produced a hook")
	}
	// And the other polarity: a device that DOES know something gets one.
	ctx := context.WithValue(context.Background(), cloudScopeKey{}, cloudScope{Provider: "aws", AccountID: "123456789012"})
	if svc.cloudScopeExtra(ctx, &device) == nil {
		t.Error("a device whose account is known produced no hook")
	}
}
