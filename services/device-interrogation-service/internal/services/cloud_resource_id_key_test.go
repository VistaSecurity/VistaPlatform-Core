package services

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// The cloud-resource-id key guard.
//
// A cloud resource's identity is the provider's own id — an ARN, an ARM
// resource path, a GCP selfLink, a CloudFront distribution id. It is the
// strongest identifier such a resource ever has and it sits at the top of the
// precedence list for every cloud class (ADR-0002 D3). A collector that writes
// its resource's id under a key nothing reads has, in effect, written no id:
// the identity engine falls back to hostname, and one resource under two names
// becomes two assets.
//
// That is not hypothetical. A CloudFront distribution writes `distribution_id`
// and nothing else that names it, and the distribution domain plus each alias
// arrive as separate findings with different hostnames. Until this fix the
// distribution and its alias became two assets — reproduced end to end in
// inventory-service's TestIntegration_CloudFrontAliasAndDomain_ResolveToOneAsset.
//
// Two checks, because the failure has two halves:
//
//  1. Every cloud device type a collector emits DECLARES which metadata key
//     carries its resource id, and that key is one the extraction point reads.
//     A new collector that invents a key, or forgets one entirely, fails here.
//  2. The extraction point actually returns the id for each declared key.
//
// A table on its own would only pin what someone typed; check 2 drives the real
// function.

// cloudResourceIDKeyByDeviceType is the sweep, recorded. For every cloud device
// type any collector in this service emits, the metadata key under which that
// collector writes the resource's own identifier.
//
// Every value must appear in identity.CloudResourceIDKeys — that is the whole
// assertion. Where a collector had no such key, it was given one rather than
// the key list being widened with a generic name: the key stores write
// `cloud_resource_id` explicitly, because `key_id` is a field name that turns
// up throughout device-interrogation output and this list is consulted for
// every finding, cloud or not.
var cloudResourceIDKeyByDeviceType = map[string]string{
	// AWS — load balancers, storage and key store all carry a real ARN.
	"aws_alb":          "arn",
	"aws_nlb":          "arn",
	"aws_elb":          "arn",
	"aws_kms":          "arn",
	"aws_s3_bucket":    "arn",
	"aws_rds_instance": "arn",
	// AWS — two resource kinds whose collector never had an ARN to write.
	// Both values are the provider's own id; see identity.CloudResourceIDKeys
	// for the uniqueness of each.
	"aws_api_gateway": "api_id",
	"aws_cloudfront":  "distribution_id",
	// AWS enumeration writes the canonical key for everything it records.
	"aws_ec2_instance": "cloud_resource_id",
	"aws_vpc":          "cloud_resource_id",
	"aws_subnet":       "cloud_resource_id",

	// Azure — the ARM resource path, under two spellings depending on which
	// collector wrote it. The storage/SQL collectors reuse the provider-neutral
	// `arn` field of StorageEncryptionFinding.
	"azure_application_gateway": "azure_resource_id",
	"azure_load_balancer":       "azure_resource_id",
	"azure_storage_account":     "arn",
	"azure_sql_database":        "arn",
	"azure_keyvault_key":        "cloud_resource_id",
	"azure_vm":                  "cloud_resource_id",
	"azure_virtual_network":     "cloud_resource_id",
	"azure_subnet":              "cloud_resource_id",

	// GCP — the selfLink, or the provider-neutral `arn` field for the storage
	// collectors (which carry `gs://…` and `gcp:cloudsql:…`).
	"gcp_https_load_balancer": "gcp_resource_id",
	"gcp_ssl_proxy":           "gcp_resource_id",
	"gcp_storage_bucket":      "arn",
	"gcp_cloudsql_instance":   "arn",
	"gcp_kms_crypto_key":      "cloud_resource_id",
	"gcp_compute_instance":    "cloud_resource_id",
	"gcp_network":             "cloud_resource_id",
	"gcp_subnetwork":          "cloud_resource_id",
}

// cloudDeviceTypeScanExclusions are strings that match the device-type shape but
// are not device types. Each must still be found, or the exclusion is stale.
var cloudDeviceTypeScanExclusions = map[string]string{
	"azure_resource_id": "a metadata KEY (in identity.CloudResourceIDKeys), not a device type",
	"gcp_resource_id":   "a metadata KEY (in identity.CloudResourceIDKeys), not a device type",
}

func TestEveryCloudDeviceTypeDeclaresItsResourceIDKey(t *testing.T) {
	dir := cloudResourceIDScanDir(t)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	// A device type is a lowercase provider-prefixed literal. Matching the
	// LITERAL rather than the `DeviceType:` field is deliberate: the load
	// balancers assign theirs to a local variable through a switch, so a
	// field-shaped pattern would miss exactly the three collectors that build
	// the type dynamically.
	typeLiteral := regexp.MustCompile(`"((?:aws|azure|gcp)_[a-z0-9]+(?:_[a-z0-9]+)*)"`)

	found := map[string]string{} // device type -> first file it was seen in
	usedExclusion := map[string]bool{}
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, readErr := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // a known repo subtree
		if readErr != nil {
			t.Fatalf("reading %s: %v", name, readErr)
		}
		scanned++
		for _, m := range typeLiteral.FindAllStringSubmatch(string(body), -1) {
			lit := m[1]
			if _, ok := cloudDeviceTypeScanExclusions[lit]; ok {
				usedExclusion[lit] = true
				continue
			}
			if _, seen := found[lit]; !seen {
				found[lit] = name
			}
		}
	}
	if scanned == 0 {
		t.Fatal("the scan read no files — it would pass whatever the collectors do")
	}
	if len(found) == 0 {
		t.Fatal("the scan found no cloud device types — the pattern no longer matches anything")
	}

	var missing []string
	for deviceType, where := range found {
		key, ok := cloudResourceIDKeyByDeviceType[deviceType]
		if !ok {
			missing = append(missing, fmt.Sprintf("  %-26s %s  (no entry)", deviceType, where))
			continue
		}
		if !slicesContains(identity.CloudResourceIDKeys, key) {
			missing = append(missing, fmt.Sprintf("  %-26s %s  (declares %q, which nothing reads)", deviceType, where, key))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("cloud device type(s) with no readable resource id:\n%s\n\n"+
			"A cloud resource's identity is the provider's own id. A collector that writes it under\n"+
			"a key identity.CloudResourceIDKeys does not read has written no id at all: the engine\n"+
			"falls back to hostname, and one resource seen under two names becomes two assets.\n"+
			"Either write the id under a key that list already reads (%q is the canonical one), or\n"+
			"add the key to identity.CloudResourceIDKeys — but only if its values are the provider's\n"+
			"own stable ids and cannot collide with another provider's.",
			strings.Join(missing, "\n"), "cloud_resource_id")
	}

	for deviceType := range cloudResourceIDKeyByDeviceType {
		if _, ok := found[deviceType]; !ok {
			t.Errorf("cloudResourceIDKeyByDeviceType has an entry for %q, which no collector emits any more.\n"+
				"Delete it — a table that outlives its subject is how a guard stops guarding.", deviceType)
		}
	}
	for lit, reason := range cloudDeviceTypeScanExclusions {
		if !usedExclusion[lit] {
			t.Errorf("cloudDeviceTypeScanExclusions entry %q (%s) matched nothing — delete it.", lit, reason)
		}
	}
}

// The second half: the extraction point really does return the id for every key
// the table declares. Check 1 pins what the collectors write; this pins what is
// read back.
func TestCloudResourceIDFromMetadataReadsEveryDeclaredKey(t *testing.T) {
	seen := map[string]bool{}
	for deviceType, key := range cloudResourceIDKeyByDeviceType {
		if seen[key] {
			continue
		}
		seen[key] = true
		want := "id-under-" + key
		got := cloudResourceIDFromMetadata(map[string]interface{}{
			// Beside the id, the noise a real collector's metadata carries.
			"region":         "us-east-1",
			"integration_id": "00000000-0000-4000-8000-000000000001",
			key:              want,
		})
		if got != want {
			t.Errorf("%s: cloudResourceIDFromMetadata read %q from key %q, want %q", deviceType, got, key, want)
		}
	}
}

// Nothing weaker is ever an answer. A finding that names no cloud resource must
// produce NO identifier rather than a hostname or an address promoted into the
// strongest identifier slot.
func TestCloudResourceIDFromMetadataNeverFallsBackToAWeakIdentifier(t *testing.T) {
	for _, meta := range []map[string]interface{}{
		nil,
		{},
		{"hostname": "shop.example.com", "ip_address": "203.0.113.55", "name": "shop", "device_type": "aws_cloudfront"},
		// Present but empty is the same as absent: an unconditional envelope
		// key is written whether or not there is a value behind it.
		{"arn": "", "distribution_id": "   "},
	} {
		if got := cloudResourceIDFromMetadata(meta); got != "" {
			t.Errorf("cloudResourceIDFromMetadata(%v) = %q, want \"\" — a cloud resource id is the "+
				"provider's own stable id or it is nothing", meta, got)
		}
	}
}

// The key stores are the two collectors that had NO readable identifier at all
// and were given one, so the emission itself is pinned rather than only the
// table entry. Deleting `cloud_resource_id` from keyStoreDeviceMetadata turns
// this red; the table-driven guard above would not, because a table only pins
// what somebody typed into it.
func TestKeyStoreDeviceMetadataCarriesTheResourceID(t *testing.T) {
	f := KMSKeyFinding{
		KeyID:     "https://example-vault.vault.azure.net/keys/signing/0123456789abcdef",
		KeyARN:    "https://example-vault.vault.azure.net/keys/signing/0123456789abcdef",
		KeyState:  "Enabled",
		KeySpec:   "RSA_2048",
		Region:    "eastus",
		AccountID: "00000000-0000-4000-8000-000000000001",
	}

	for _, accountKey := range []string{"subscription_id", "project_id"} {
		meta := keyStoreDeviceMetadata(f, accountKey)

		if got := cloudResourceIDFromMetadata(meta); got != f.KeyARN {
			t.Errorf("%s: a key-store key resolves to cloud resource id %q, want %q — without it the key "+
				"is identified by its short name, which collides between two vaults holding a key of "+
				"the same name", accountKey, got, f.KeyARN)
		}
		if _, ok := meta[accountKey]; !ok {
			t.Errorf("%s: the account the key lives in is missing from the metadata", accountKey)
		}
		// The posture facts the keys producer reads must survive the shared
		// helper — this replaced two hand-written copies.
		for _, k := range []string{"key_id", "key_state", "key_spec", "key_usage", "protection_level", "rotation_enabled", "location", "creation_date"} {
			if _, ok := meta[k]; !ok {
				t.Errorf("%s: metadata lost %q", accountKey, k)
			}
		}
	}
}

func slicesContains(hay []string, needle string) bool {
	for _, v := range hay {
		if v == needle {
			return true
		}
	}
	return false
}

// cloudResourceIDScanDir is this package's own directory, located from the
// repository root so the scan cannot silently read nothing.
func cloudResourceIDScanDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(repoRootForCertKeyScan(t), "services", "device-interrogation-service", "internal", "services")
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("scan directory %s is missing — the guard would scan nothing: %v", dir, err)
	}
	return dir
}
