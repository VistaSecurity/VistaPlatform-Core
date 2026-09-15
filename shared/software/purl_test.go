package software

import "testing"

func TestNormalizePURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"already canonical", "pkg:npm/left-pad@1.3.0", "pkg:npm/left-pad@1.3.0"},
		{"scheme case folded", "PKG:npm/left-pad@1.3.0", "pkg:npm/left-pad@1.3.0"},
		{"type case folded", "pkg:NPM/left-pad@1.3.0", "pkg:npm/left-pad@1.3.0"},
		{"tolerated double slash stripped", "pkg://npm/left-pad@1.3.0", "pkg:npm/left-pad@1.3.0"},
		{"surrounding whitespace trimmed", "  pkg:npm/left-pad@1.3.0  ", "pkg:npm/left-pad@1.3.0"},
		{"no version", "pkg:npm/left-pad", "pkg:npm/left-pad"},

		{
			name: "github namespace lowercased (spec rule for this type)",
			in:   "pkg:github/VistaSecurity/VistaPlatform@v1.0.0",
			want: "pkg:github/vistasecurity/VistaPlatform@v1.0.0",
		},
		{
			// Maven group ids are case-sensitive, so folding them would merge
			// two different artefacts into one catalogue row.
			name: "maven namespace preserved (no spec rule for this type)",
			in:   "pkg:maven/org.Apache.Commons/commons-lang3@3.12.0",
			want: "pkg:maven/org.Apache.Commons/commons-lang3@3.12.0",
		},
		{
			name: "npm scope is a namespace",
			in:   "pkg:npm/@Babel/core@7.0.0",
			want: "pkg:npm/@babel/core@7.0.0",
		},
		{
			name: "deb namespace preserved",
			in:   "pkg:deb/Debian/openssl@3.0.11-1?arch=amd64",
			want: "pkg:deb/Debian/openssl@3.0.11-1?arch=amd64",
		},

		{
			name: "qualifier keys lowercased and sorted",
			in:   "pkg:deb/debian/openssl@3.0.11?OS=linux&arch=amd64",
			want: "pkg:deb/debian/openssl@3.0.11?arch=amd64&os=linux",
		},
		{
			name: "empty-valued qualifier discarded per the spec",
			in:   "pkg:deb/debian/openssl@3.0.11?arch=&os=linux",
			want: "pkg:deb/debian/openssl@3.0.11?os=linux",
		},
		{
			name: "qualifier with no equals discarded",
			in:   "pkg:deb/debian/openssl@3.0.11?bare&os=linux",
			want: "pkg:deb/debian/openssl@3.0.11?os=linux",
		},
		{
			name: "subpath preserved, surrounding slashes trimmed",
			in:   "pkg:golang/Google.Golang.Org/genproto#/googleapis/api/annotations/",
			want: "pkg:golang/google.golang.org/genproto#googleapis/api/annotations",
		},
		{
			// Percent-encoded octets pass through untouched. Decoding and
			// re-encoding through a different escaping table would change an
			// identity string, which is the one thing a dedupe key may not do.
			name: "percent encoding passes through",
			in:   "pkg:generic/openssl@3.0.13?download_url=https%3A%2F%2Fexample.test%2Fx.tgz",
			want: "pkg:generic/openssl@3.0.13?download_url=https%3A%2F%2Fexample.test%2Fx.tgz",
		},
		{
			// The namespace folds (golang is in lowercaseNamespaceTypes); the
			// NAME does not, because the per-type name rules are scoped out of
			// 2.6a — see the note on NormalizePURL.
			name: "multi-segment namespace folds, name does not",
			in:   "pkg:golang/GitHub.com/Vista/Thing@v1",
			want: "pkg:golang/github.com/vista/Thing@v1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizePURL(tc.in)
			if err != nil {
				t.Fatalf("NormalizePURL(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("NormalizePURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
			// Canonicalisation must be a fixed point, or two ingests of the
			// same document produce two identities.
			again, err := NormalizePURL(got)
			if err != nil {
				t.Fatalf("re-normalising %q: %v", got, err)
			}
			if again != got {
				t.Errorf("NormalizePURL is not idempotent: %q then %q", got, again)
			}
		})
	}
}

func TestNormalizePURLRejects(t *testing.T) {
	for _, in := range []string{
		"",
		"   ",
		"left-pad",
		"npm/left-pad@1.3.0",
		"http://example.test/x",
		"pkg:npm",
		"pkg:/npm",
		"pkg:npm/",
		"pkg:NP M/left-pad",
		"pkg:1npm/left-pad",
		"pkg::left-pad",
	} {
		if got, err := NormalizePURL(in); err == nil {
			t.Errorf("NormalizePURL(%q) = %q, want an error", in, got)
		}
	}
}
