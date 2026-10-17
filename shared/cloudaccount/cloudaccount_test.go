package cloudaccount

import "testing"

func TestResourceID(t *testing.T) {
	for _, c := range []struct{ provider, account, want string }{
		{"aws", "123456789012", "aws:123456789012"},
		{" AWS ", " 123456789012 ", "aws:123456789012"},
		{"azure", "3b0a1c2d-0000-4000-8000-000000000001", "azure:3b0a1c2d-0000-4000-8000-000000000001"},
		{"gcp", "my-project", "gcp:my-project"},
		{"aws", "", ""},
		{"", "123", ""},
		{"slack", "123", ""}, // not a cloud provider an account can be declared for
	} {
		if got := ResourceID(c.provider, c.account); got != c.want {
			t.Errorf("ResourceID(%q, %q) = %q; want %q", c.provider, c.account, got, c.want)
		}
	}
}

func TestAccountFromResourceID(t *testing.T) {
	for _, c := range []struct{ provider, rid, want string }{
		{"aws", "arn:aws:kms:us-east-1:210987654321:key/abc", "210987654321"},
		{"aws", "arn:aws:cloudfront::210987654321:distribution/E1", "210987654321"},
		{"aws", "arn:aws:s3:::my-bucket", ""}, // bucket ARNs carry no account
		{"aws", "E1ABCDEF", ""},
		{"azure", "/subscriptions/3b0a1c2d/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1", "3b0a1c2d"},
		{"gcp", "projects/my-project/zones/us-central1-a/instances/vm-1", "my-project"},
		{"gcp", "https://www.googleapis.com/compute/v1/projects/p2/global/networks/n", "p2"},
		{"gcp", "gs://bucket", ""},
	} {
		if got := AccountFromResourceID(c.provider, c.rid); got != c.want {
			t.Errorf("AccountFromResourceID(%q, %q) = %q; want %q", c.provider, c.rid, got, c.want)
		}
	}
}

func TestResolvePrecedence(t *testing.T) {
	// stated > resource id > integration
	if got := Resolve("aws", "111", "arn:aws:ec2:us-east-1:222:instance/i-1", "333"); got != "111" {
		t.Errorf("stated account must win, got %q", got)
	}
	if got := Resolve("aws", "", "arn:aws:ec2:us-east-1:222:instance/i-1", "333"); got != "222" {
		t.Errorf("the resource's own account must beat the integration's, got %q", got)
	}
	if got := Resolve("aws", "", "arn:aws:s3:::bucket", "333"); got != "333" {
		t.Errorf("an addressless bucket falls back to the integration's account, got %q", got)
	}
	if got := Resolve("aws", "", "", ""); got != "" {
		t.Errorf("nothing known must stay unknown, got %q", got)
	}
}
