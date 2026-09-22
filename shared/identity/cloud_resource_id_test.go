package identity

import "testing"

func TestCloudResourceIDKeysHaveNoDuplicates(t *testing.T) {
	seen := map[string]bool{}
	for _, k := range CloudResourceIDKeys {
		if seen[k] {
			t.Errorf("CloudResourceIDKeys lists %q twice — precedence is decided by position, so a "+
				"duplicate makes the second entry unreachable and the list a lie about what wins", k)
		}
		seen[k] = true
	}
}

// The list is ordered, and the order is additive-only: an entry that resolved
// before must resolve to the same value now. Pinning the historical prefix
// makes a reordering a deliberate act rather than an accident — reordering can
// silently re-identify resources already in a customer's inventory, which is a
// merge or a split of existing assets.
func TestCloudResourceIDKeysKeepTheHistoricalPrefix(t *testing.T) {
	historical := []string{"arn", "resource_id", "cloud_resource_id", "self_link", "resource_uri"}
	if len(CloudResourceIDKeys) < len(historical) {
		t.Fatalf("CloudResourceIDKeys has %d entries, fewer than the %d it started with",
			len(CloudResourceIDKeys), len(historical))
	}
	for i, want := range historical {
		if CloudResourceIDKeys[i] != want {
			t.Errorf("CloudResourceIDKeys[%d] = %q, want %q — new keys are APPENDED. Reordering the "+
				"existing ones changes which id an already-inventoried resource resolves by",
				i, CloudResourceIDKeys[i], want)
		}
	}
}

// No weak identifier may enter this list. A cloud_resource_id that is really a
// hostname or an address is worse than no identifier: it merges resources that
// merely share a name or a CDN edge address.
func TestCloudResourceIDKeysHoldNoWeakIdentifier(t *testing.T) {
	forbidden := map[string]string{
		"hostname":    "a name, not the provider's id — two resources can share one",
		"fqdn":        "a name, not the provider's id",
		"dns_name":    "a name, not the provider's id",
		"domain_name": "a name, not the provider's id",
		"ip_address":  "an address — a CDN edge address is shared by design",
		"ip":          "an address",
		"name":        "a label anyone can set",
		"resource_short_name": "the last path segment of an id, which collides between " +
			"two containers holding a resource of the same name",
	}
	for _, k := range CloudResourceIDKeys {
		if why, bad := forbidden[k]; bad {
			t.Errorf("CloudResourceIDKeys includes %q: %s", k, why)
		}
	}
}

func TestCloudResourceIDFromMetadataPrecedence(t *testing.T) {
	// An AWS KMS key's metadata carries both an ARN and a bare key id. The ARN
	// is the namespaced one and must win.
	got := CloudResourceIDFromMetadata(map[string]interface{}{
		"key_id": "00000000-0000-4000-8000-000000000001",
		"arn":    "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001",
	})
	if got != "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001" {
		t.Errorf("got %q, want the ARN — it is earlier in the list and it is the namespaced id", got)
	}

	// A non-string value is not an id. Returning a formatted number would
	// invent an identifier out of something that is not one.
	if got := CloudResourceIDFromMetadata(map[string]interface{}{"arn": 42}); got != "" {
		t.Errorf("got %q for a non-string arn, want \"\"", got)
	}

	// Whitespace is trimmed, not treated as a value.
	if got := CloudResourceIDFromMetadata(map[string]interface{}{"distribution_id": "  EXAMPLEDIST123  "}); got != "EXAMPLEDIST123" {
		t.Errorf("got %q, want the trimmed id", got)
	}
}
