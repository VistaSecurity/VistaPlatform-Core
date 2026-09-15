package services

// `GET /crypto-inventory`'s asset_type filter, which compared the caller's raw
// strings against `class_key`.
//
// The strings callers actually send are the four values of the RETIRED
// asset_type enum — that is what every saved link and doc example carries.
// `server` happens to be a class key; `appliance`, `endpoint` and `service` are
// not, so those returned 200 with an empty list. A filter that silently matches
// nothing is the worst answer available: it reads as "you have none of those"
// rather than "I did not understand you".

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
)

func TestResolveAssetTypeFilter(t *testing.T) {
	// The retired enum's four values, each mapped to the SHALLOWEST class that
	// honestly covers it — never a guess at which kind of appliance.
	//
	// `service` is deliberately NOT in this table: it is BOTH a retired enum
	// value and a live class key, and the live key wins (see the collision note
	// on resolveAssetTypeFilter). Asserting the legacy meaning here would pin
	// the wrong one.
	for legacy, want := range map[string]string{
		"server":    assetclass.KeyServer,
		"endpoint":  assetclass.KeyComputer,
		"appliance": assetclass.KeyHardware,
	} {
		got, err := resolveAssetTypeFilter([]string{legacy})
		if err != nil {
			t.Errorf("resolveAssetTypeFilter(%q) = %v; the retired enum's values are exactly what "+
				"existing callers still send", legacy, err)
			continue
		}
		if len(got) != 1 || got[0] != want {
			t.Errorf("resolveAssetTypeFilter(%q) = %v, want [%s]", legacy, got, want)
		}
	}

	// A real class key passes through untouched, including a leaf the enum
	// could never express — and including `service`, the one spelling the two
	// vocabularies share.
	for _, key := range []string{
		assetclass.KeyFirewall, assetclass.KeyObjectStorage, assetclass.KeyServer, assetclass.KeyService,
	} {
		got, err := resolveAssetTypeFilter([]string{key})
		if err != nil || len(got) != 1 || got[0] != key {
			t.Errorf("resolveAssetTypeFilter(%q) = %v, %v; a class key must pass through", key, got, err)
		}
	}

	// And nonsense is REFUSED, not answered with an empty list.
	for _, bad := range []string{"not_a_class", "widget", "network_asset"} {
		got, err := resolveAssetTypeFilter([]string{bad})
		if err == nil {
			t.Errorf("resolveAssetTypeFilter(%q) = %v, nil — an unrecognised value must be refused, "+
				"not silently matched against nothing", bad, got)
			continue
		}
		if !strings.Contains(err.Error(), bad) {
			t.Errorf("the error must name the value that was rejected: %v", err)
		}
	}

	// Empty strings are skipped rather than rejected: a repeated query
	// parameter with one blank is a client quirk, not a request to be refused.
	got, err := resolveAssetTypeFilter([]string{"", "server", "   "})
	if err != nil || len(got) != 1 || got[0] != assetclass.KeyServer {
		t.Errorf("blank values must be skipped; got %v, %v", got, err)
	}
}
