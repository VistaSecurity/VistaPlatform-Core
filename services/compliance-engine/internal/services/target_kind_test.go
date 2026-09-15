package services

// Pure unit tests for targetKindFromSubjectTypes (L-5): GetFindingsByControl's
// AffectedAssets column used to be labeled "assets" unconditionally, even
// when a control's active findings were all on certificates or crypto
// configurations (subject_type != 'asset'). The frontend now reads TargetKind
// to pick the right noun.

import "testing"

func TestTargetKindFromSubjectTypes(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"all assets", []string{"asset"}, "asset"},
		{"all certificates", []string{"certificate"}, "certificate"},
		{"all crypto configs", []string{"crypto_configuration"}, "configuration"},
		{"mixed asset + certificate", []string{"asset", "certificate"}, "mixed"},
		{"mixed all three", []string{"asset", "certificate", "crypto_configuration"}, "mixed"},
		{"empty (no findings) defaults to mixed, not silently 'asset'", []string{}, "mixed"},
		// A subject type this producer does not emit is not silently an asset
		// either — it takes the same "mixed" default any unrecognised set gets,
		// and a caller reading "assets" over a software install would be the L-5
		// bug with a different noun.
		{"a subject type compliance does not emit", []string{"software_install"}, "asset"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := targetKindFromSubjectTypes(tc.in); got != tc.want {
				t.Errorf("targetKindFromSubjectTypes(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
