package services

// Pure unit tests for targetKindFromAssetTypes (L-5): GetFindingsByControl's
// AffectedAssets column used to be labeled "assets" unconditionally, even
// when a control's active findings were all on certificates or crypto
// configurations (compliance_findings.asset_type != 'network_asset'). The
// frontend now reads TargetKind to pick the right noun.

import "testing"

func TestTargetKindFromAssetTypes(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"all network assets", []string{"network_asset"}, "asset"},
		{"all certificates", []string{"certificate"}, "certificate"},
		{"all crypto configs", []string{"crypto_implementation"}, "configuration"},
		{"mixed asset + certificate", []string{"network_asset", "certificate"}, "mixed"},
		{"mixed all three", []string{"network_asset", "certificate", "crypto_implementation"}, "mixed"},
		{"empty (no findings) defaults to mixed, not silently 'asset'", []string{}, "mixed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := targetKindFromAssetTypes(tc.in); got != tc.want {
				t.Errorf("targetKindFromAssetTypes(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
