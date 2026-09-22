package assetclass_test

// The `device_type` half of the collector-vocabulary guard.
//
// TestCloudResourceTypesTheCollectorsWriteAllMap (device_types_test.go) scans
// the `resource_type` literals the collectors write and holds the table to
// them. Nothing did the same for `device_type`, and `device_type` is the ONLY
// thing naming the resource on half the cloud paths: CloudFront, API Gateway,
// the three key stores and the managed load balancers write no
// `resource_type` at all.
//
// What that cost. inventory-service's findingClassHint read `resource_type`
// and then fell through to the legacy `asset_type`, which the converter stamps
// `service` for every one of those — so they were classed `application`. The
// class is not cosmetic: it selects the identifier PRECEDENCE, and
// `application` identifies by `[cmdb_sys_id, name]`. A CloudFront
// distribution's findings therefore carried the distribution id, had it
// recorded, and were never allowed to vote with it — so one distribution
// became three assets on demo and its ACM certificate reached the certificate
// inventory never.
//
// A hand-written list of device types could not catch that; the hand-written
// list IS the failure mode. This derives the list from the source.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
)

// Both spellings a producer uses: the struct field on models.Device, and the
// metadata key the discovery writer stamps. Plus the exported constants the
// enumeration paths assign, which are the same strings by another name.
var deviceTypeLiterals = []*regexp.Regexp{
	regexp.MustCompile(`\bDeviceType:\s*"([^"]+)"`),
	regexp.MustCompile(`"device_type":\s*"([^"]+)"`),
	regexp.MustCompile(`\bDeviceType[A-Za-z0-9_]*\s+=\s*"([^"]+)"`),
}

func TestDeviceTypesTheCollectorsWriteAllMap(t *testing.T) {
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
			for _, re := range deviceTypeLiterals {
				for _, m := range re.FindAllStringSubmatch(string(body), -1) {
					v := m[1]
					// The field name itself, where a constant names the key
					// rather than a value.
					if v == "device_type" {
						continue
					}
					rel, _ := filepath.Rel(root, path)
					found[v] = append(found[v], rel)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", sub, err)
		}
	}

	if len(found) == 0 {
		t.Fatal("found no device_type literals at all; the scanner has stopped scanning, " +
			"which is the one way this guard can pass while proving nothing")
	}

	for value, files := range found {
		key := assetclass.FromDeviceType(value)
		if key == "" {
			t.Errorf("device_type %q (written by %v) maps to no class — a producer's own name for what "+
				"it found, with no row in the table, means the intake falls back to the legacy asset_type "+
				"and guesses", value, files)
			continue
		}
		if _, known := assetclass.Get(string(key)); !known {
			t.Errorf("device_type %q maps to %q, which is not a class in the registry", value, key)
			continue
		}
		// The two classes the fall-through produced. `application` is the one
		// that mattered: it is the only class in the taxonomy whose precedence
		// omits `cloud_resource_id`, so landing there makes the provider's own
		// identifier mute.
		if key == assetclass.KeyApplication || assetclass.IsAncestor(assetclass.KeyApplication, string(key)) {
			t.Errorf("device_type %q maps to %q — a resource a collector names is not an application", value, key)
		}
		if key == assetclass.KeyServer && strings.Contains(value, "_") && isCloudPrefixed(value) {
			t.Errorf("device_type %q maps to server; a managed cloud resource is not a server", value)
		}
	}
}

// isCloudPrefixed reports whether a device_type names a cloud resource by its
// provider prefix. Used only to scope the "not a server" assertion: a
// hardware device_type legitimately maps to `server`.
func isCloudPrefixed(v string) bool {
	for _, p := range []string{"aws_", "azure_", "gcp_"} {
		if strings.HasPrefix(v, p) {
			return true
		}
	}
	return false
}

// The application branch is the whole reason the guard above exists, so the
// property it depends on is asserted directly rather than assumed: every class
// a cloud collector's device_type maps to must be able to identify BY the
// provider's own resource id. A class whose precedence omits
// `cloud_resource_id` records the strongest identifier a cloud resource ever
// has and then ignores it.
func TestCloudDeviceTypeClassesIdentifyByCloudResourceID(t *testing.T) {
	for deviceType, key := range assetclass.DeviceTypeVocabulary() {
		if !isCloudPrefixed(deviceType) {
			continue
		}
		c, ok := assetclass.Get(string(key))
		if !ok {
			t.Errorf("device_type %q maps to %q, which is not a class in the registry", deviceType, key)
			continue
		}
		votes := false
		for _, k := range c.IdentifierPrecedence {
			if k == "cloud_resource_id" {
				votes = true
				break
			}
		}
		if !votes {
			t.Errorf("device_type %q is classed %q, whose identifier precedence is %v — it holds no "+
				"`cloud_resource_id`, so the provider's own id is recorded on the observation and never "+
				"allowed to decide a match. One resource then becomes an asset per hostname.",
				deviceType, key, c.IdentifierPrecedence)
		}
	}
}
