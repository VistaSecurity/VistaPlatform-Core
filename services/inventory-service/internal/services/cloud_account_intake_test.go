package services

import "testing"

func TestCloudFindingAttributes_ProjectCloudLensFields(t *testing.T) {
	r := &cloudAccountResolver{}
	f := IngestFinding{RawData: map[string]interface{}{
		"source":              "cloud_discovery",
		"discovery_method":    "cloud_api",
		"cloud_provider":      "AWS",
		"cloud_account_id":    "123456789012",
		"cloud_region":        "us-east-2",
		"device_type":         "aws_s3_bucket",
		"cloud_resource_type": "s3_bucket",
	}}
	got := r.attributes(f)
	want := map[string]interface{}{
		"provider": "aws", "account_id": "123456789012", "region": "us-east-2", "provider_type": "AWS::S3::Bucket",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v (all attributes: %v)", k, got[k], v, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("attributes contain fields outside the cloud_resource allowlist: %v", got)
	}
}

func TestCloudFindingAttributes_IgnoreNonCloudFinding(t *testing.T) {
	r := &cloudAccountResolver{}
	f := IngestFinding{RawData: map[string]interface{}{
		"source": "sensor", "cloud_provider": "aws", "cloud_account_id": "123456789012", "cloud_region": "us-east-2",
	}}
	if got := r.attributes(f); got != nil {
		t.Fatalf("sensor finding projected cloud attributes: %v", got)
	}
}
