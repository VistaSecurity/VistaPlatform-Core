package assetclass_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
)

// repoRoot walks up from this test until it finds go.work.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skip("go.work not found above the working directory; not a full checkout")
	return ""
}

var resourceTypeLiteral = regexp.MustCompile(`"(?:cloud_)?resource_type":\s*"([^"]+)"`)

// TestCloudResourceTypesTheCollectorsWriteAllMap scans what the collectors
// actually emit and holds the table to it.
//
// This is the guard the defect needed. inventory-service's cloud class hint
// knew `s3`, `bucket`, `rds` and `sql_database`; the collectors write
// `s3_bucket`, `gcs_bucket`, `rds_instance` and `cloudsql_instance`. Nothing
// failed to compile, no test went red, and every S3 bucket in the tenant was
// inventoried as an APPLICATION because the unmapped hint fell through to the
// finding's legacy `asset_type` of `service`.
//
// A hand-written list of strings could not have caught it — the hand-written
// list WAS the bug. This derives the list from the source.
func TestCloudResourceTypesTheCollectorsWriteAllMap(t *testing.T) {
	root := repoRoot(t)
	found := map[string][]string{}

	for _, sub := range []string{"services", "sensor", "device-agent"} {
		base := filepath.Join(root, sub)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			body, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			for _, m := range resourceTypeLiteral.FindAllStringSubmatch(string(body), -1) {
				v := m[1]
				// The struct-tag / map-key spellings of the field name itself.
				if v == "resource_type" || v == "cloud_resource_type" {
					continue
				}
				rel, _ := filepath.Rel(root, path)
				found[v] = append(found[v], rel)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", sub, err)
		}
	}

	if len(found) == 0 {
		t.Fatal("found no resource_type literals at all; the scanner has stopped scanning, " +
			"which is the one way this guard can pass while proving nothing")
	}

	for value, files := range found {
		key, ok := assetclass.FromCloudResourceType(value)
		if !ok {
			t.Errorf("resource_type %q (written by %v) maps to no class", value, files)
			continue
		}
		if _, known := assetclass.Get(string(key)); !known {
			t.Errorf("resource_type %q maps to %q, which is not a class in the registry", value, key)
			continue
		}
		// The two classes the old fall-through produced. A cloud resource is
		// never an application and never a server; those were the finding's
		// legacy asset_type leaking in because the hint was empty.
		if key == assetclass.KeyApplication || assetclass.IsAncestor(assetclass.KeyApplication, string(key)) {
			t.Errorf("resource_type %q maps to %q — a cloud resource is not an application "+
				"(this is the s3_bucket defect returning)", value, key)
		}
		if key == assetclass.KeyServer {
			t.Errorf("resource_type %q maps to server; a managed database is not a server", value)
		}
	}
}

// TestFromCloudResourceTypeFallsBackToCloudResource pins the "no opinion"
// answer in BOTH directions: an unrecognised type is a cloud resource (coarse
// and true), and an EMPTY one is no answer at all (there is no cloud resource
// here to classify).
func TestFromCloudResourceTypeFallsBackToCloudResource(t *testing.T) {
	for _, in := range []string{"some_future_service", "aws_quantum_thing"} {
		key, ok := assetclass.FromCloudResourceType(in)
		if !ok || key != assetclass.KeyCloudResource {
			t.Errorf("FromCloudResourceType(%q) = %q, %v; want cloud_resource, true", in, key, ok)
		}
	}
	for _, in := range []string{"", "   "} {
		if key, ok := assetclass.FromCloudResourceType(in); ok {
			t.Errorf("FromCloudResourceType(%q) = %q, true; an absent resource type is not a cloud resource", in, key)
		}
	}
}

// TestCloudAndDeviceVocabulariesDisagreeOnPurpose: "load_balancer" means a box
// in a rack as a device_type and a provider's managed load balancer as a cloud
// resource_type. One merged table would silently pick one answer for both.
func TestCloudAndDeviceVocabulariesDisagreeOnPurpose(t *testing.T) {
	if got := assetclass.FromDeviceType("load_balancer"); got != assetclass.KeyLoadBalancer {
		t.Errorf("device_type load_balancer = %q, want load_balancer (hardware)", got)
	}
	got, _ := assetclass.FromCloudResourceType("load_balancer")
	if got != assetclass.KeyCloudLoadBalancer {
		t.Errorf("resource_type load_balancer = %q, want cloud_load_balancer", got)
	}
}

// TestVocabularyClassKeysAreRegistered holds BOTH tables to the generated
// taxonomy. A class key that is not a real class is still written into
// `assets.class_key` (class_path falls back to the key itself), producing an
// asset in a class no facet can select and no CMDB sync can map.
func TestVocabularyClassKeysAreRegistered(t *testing.T) {
	for name, table := range map[string]map[string]assetclass.Key{
		"device_type":   assetclass.DeviceTypeVocabulary(),
		"resource_type": assetclass.CloudResourceTypeVocabulary(),
	} {
		if len(table) == 0 {
			t.Errorf("%s vocabulary is empty; the guard would pass over nothing", name)
		}
		for value, key := range table {
			if _, ok := assetclass.Get(string(key)); !ok {
				t.Errorf("%s %q maps to class %q, which is not in the generated registry", name, value, key)
			}
		}
	}
}
