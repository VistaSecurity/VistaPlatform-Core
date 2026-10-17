package services

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/facts"
)

// The cloud mirror's key (DCIM row 4.2): only a compute instance with all
// three of provider, account and region is mirrored; an AWS instance's
// enumerated facts produce one.
//
// Mutation: drop the class check → the bucket case is mirrored; accept a
// missing region → the third case is.
func TestCloudMirrorKey(t *testing.T) {
	inst := cloudPlacementFacts("aws", "123456789012", "us-east-1", "arn:aws:ec2:us-east-1:123456789012:instance/i-1", nil)
	if p, a, r, ok := cloudMirrorKey("compute_instance", inst); !ok || p != "aws" || a != "123456789012" || r != "us-east-1" {
		t.Fatalf("instance: %q %q %q %t", p, a, r, ok)
	}
	if _, _, _, ok := cloudMirrorKey("object_storage", inst); ok {
		t.Error("a bucket is mirrored as a cluster member")
	}
	noRegion := map[string]any{facts.KeyCloudProvider: "gcp", facts.KeyCloudAccountID: "proj"}
	if _, _, _, ok := cloudMirrorKey("compute_instance", noRegion); ok {
		t.Error("an instance with no region is mirrored")
	}
}
