package services

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/connectors"
)

// The connector registry's `produces_classes` for aws, azure and gcp is a claim
// about what the cloud collectors create assets of. It used to claim
// `serverless_function` for all three when no Lambda / Functions / Cloud
// Functions collector exists, and to omit the CDN, API-gateway, network and
// subnet classes the collectors do produce (integrations review M35).
//
// So the claim is derived here from the code: every provider-prefixed
// device_type a non-test file in this package assigns to a discovered device
// (`DeviceType: "aws_alb"`, `deviceType = "azure_vm"`, the enumeration
// constants), mapped through the same device_type → class table the ingest
// path uses (assetclass.FromDeviceType). The registry entry must equal that
// set for the provider.
//
// It is a source scan because the device types are string literals spread over
// a dozen files with no common list to import, and a hand-kept list here would
// be a second copy of the thing being audited. The regexp is anchored on the
// assignment forms in use, and the test refuses to pass on an empty scan.
//
// MUTATION (each goes red, restore afterwards): add "serverless_function" to a
// cloud connector's produces_classes in standards/connectors.yaml
// (`make generate`); drop `key_store` from one; introduce
// `DeviceType: "aws_lambda_function"` in a collector.
var cloudDeviceTypeLiteral = regexp.MustCompile(
	`(?:DeviceType|deviceType)\w*\s*(?::=|=|:)\s*"((?:aws|azure|gcp)_[a-z0-9_]+)"`)

func TestRegistryProducesClassesMatchTheCloudCollectors(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	perProvider := map[string]map[string]bool{"aws": {}, "azure": {}, "gcp": {}}
	scanned := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range cloudDeviceTypeLiteral.FindAllStringSubmatch(string(src), -1) {
			deviceType := m[1]
			provider := deviceType[:strings.Index(deviceType, "_")]
			class := DeviceTypeClassKey(deviceType)
			if class == "" || class == "cloud_resource" {
				t.Errorf("%s: device_type %q maps to class %q — a collector emitting it would file a real resource under the generic parent", f, deviceType, class)
			}
			perProvider[provider][class] = true
			scanned++
		}
	}
	if scanned < 20 {
		t.Fatalf("scanned only %d cloud device_type literals; the pattern no longer matches the code and this test would pass whatever the registry said", scanned)
	}

	for provider, set := range perProvider {
		c, ok := connectors.Get(provider)
		if !ok {
			t.Fatalf("%s is not in the connector registry", provider)
		}
		want := make([]string, 0, len(set))
		for k := range set {
			want = append(want, k)
		}
		sort.Strings(want)
		got := append([]string(nil), c.ProducesClasses...)
		sort.Strings(got)
		if !slices.Equal(got, want) {
			t.Errorf("%s: registry produces_classes = %v\nthe collectors' device types map to        = %v", provider, got, want)
		}
	}
}
