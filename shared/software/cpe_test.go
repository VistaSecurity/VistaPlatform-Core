package software

import "testing"

func TestNormalizeCPE23(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			// The shape NVD publishes, with unescaped periods in the version.
			// See the deviation note on NormalizeCPE: a validator that rejects
			// this rejects the entire published dictionary.
			name: "NVD-shaped formatted string",
			in:   "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*",
			want: "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*",
		},
		{
			name: "escaped punctuation survives",
			in:   `cpe:2.3:a:vendor:pro\:duct:1.0:*:*:*:*:*:*:*`,
			want: `cpe:2.3:a:vendor:pro\:duct:1.0:*:*:*:*:*:*:*`,
		},
		{
			name: "NA and ANY logical values",
			in:   "cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:x64:*",
			want: "cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:x64:*",
		},
		{
			name: "part is lowercased",
			in:   "cpe:2.3:A:openssl:openssl:3.0.13:*:*:*:*:*:*:*",
			want: "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*",
		},
		{
			name: "CPE prefix case folded",
			in:   "CPE:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*",
			want: "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*",
		},
		{
			name: "hardware part",
			in:   "cpe:2.3:h:cisco:catalyst_9300:-:*:*:*:*:*:*:*",
			want: "cpe:2.3:h:cisco:catalyst_9300:-:*:*:*:*:*:*:*",
		},
		{
			name: "single-character wildcard in a value",
			in:   "cpe:2.3:a:vendor:product:1.?:*:*:*:*:*:*:*",
			want: "cpe:2.3:a:vendor:product:1.?:*:*:*:*:*:*:*",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeCPE(tc.in)
			if err != nil {
				t.Fatalf("NormalizeCPE(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("NormalizeCPE(%q) = %q, want %q", tc.in, got, tc.want)
			}
			again, err := NormalizeCPE(got)
			if err != nil {
				t.Fatalf("re-normalising %q: %v", got, err)
			}
			if again != got {
				t.Errorf("NormalizeCPE is not idempotent: %q then %q", got, again)
			}
		})
	}
}

// TestNormalizeCPE22Conversion is the one that makes the two spellings a
// single catalogue row. SPDX defines both cpe22Type and cpe23Type external
// references and tools emit whichever their source had; storing both verbatim
// would give one product two rows and one vulnerability match.
func TestNormalizeCPE22Conversion(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "short URI pads the missing attributes with ANY",
			in:   "cpe:/a:openssl:openssl:3.0.13",
			want: "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*",
		},
		{
			name: "empty interior components become ANY, not blanks",
			in:   "cpe:/a:openssl:openssl::::",
			want: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
		},
		{
			name: "all seven components",
			in:   "cpe:/o:microsoft:windows_10:1607:sp1:pro:en-us",
			want: "cpe:2.3:o:microsoft:windows_10:1607:sp1:pro:en-us:*:*:*:*",
		},
		{
			name: "NA component stays NA",
			in:   "cpe:/h:cisco:catalyst_9300:-",
			want: "cpe:2.3:h:cisco:catalyst_9300:-:*:*:*:*:*:*:*",
		},
		{
			// The packed edition is the only place CPE 2.2 could carry
			// sw_edition/target_sw/target_hw/other. Left packed, the value is
			// an unmatched blob; unpacked, target_sw = windows is matchable.
			name: "packed extended edition unpacked into four attributes",
			in:   "cpe:/a:adobe:reader:9.0::~~pro~windows~x64~",
			want: "cpe:2.3:a:adobe:reader:9.0:*:*:*:pro:windows:x64:*",
		},
		{
			name: "percent-encoded punctuation is decoded and quoted",
			in:   "cpe:/a:vendor:pro%3Aduct:1.0",
			want: `cpe:2.3:a:vendor:pro\:duct:1.0:*:*:*:*:*:*:*`,
		},
		{
			name: "2.2 wildcard encodings decode as wildcards, not literals",
			in:   "cpe:/a:vendor:product:1.%02",
			want: "cpe:2.3:a:vendor:product:1.*:*:*:*:*:*:*:*",
		},
		{
			name: "2.2 single-character wildcard",
			in:   "cpe:/a:vendor:product:1.%01",
			want: "cpe:2.3:a:vendor:product:1.?:*:*:*:*:*:*:*",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeCPE(tc.in)
			if err != nil {
				t.Fatalf("NormalizeCPE(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("NormalizeCPE(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestNormalizeCPEConvergence: the point of converting rather than accepting
// both forms is that the two spellings of one product produce ONE identity.
func TestNormalizeCPEConvergence(t *testing.T) {
	from22, err := NormalizeCPE("cpe:/a:openssl:openssl:3.0.13")
	if err != nil {
		t.Fatal(err)
	}
	from23, err := NormalizeCPE("cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatal(err)
	}
	if from22 != from23 {
		t.Errorf("the 2.2 and 2.3 spellings of one product produced two identities:\n 2.2 → %q\n 2.3 → %q", from22, from23)
	}
}

func TestNormalizeCPERejects(t *testing.T) {
	for _, in := range []string{
		"",
		"   ",
		"openssl",
		"cpe:2.3",
		"cpe:2.3:a:openssl",
		"cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*",     // 12 fields
		"cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*:*", // 14 fields
		"cpe:2.3:x:openssl:openssl:3.0.13:*:*:*:*:*:*:*",   // bad part
		"cpe:2.3:a::openssl:3.0.13:*:*:*:*:*:*:*",          // blank attribute
		"cpe:2.2:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*",   // wrong spec version
		`cpe:2.3:a:vendor:pro duct:1.0:*:*:*:*:*:*:*`,      // unquoted space
		`cpe:2.3:a:vendor:product\:1.0:*:*:*:*:*:*:*`,      // escape eats a separator → 12 fields
		`cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*\`,      // dangling backslash
		"cpe:/a:vendor:product:1:2:3:4:5",                  // 8 URI components
		"cpe:/a:adobe:reader:9.0::~~pro~windows~",          // packed edition with 4 parts
		"cpe:/a:vendor:pro%zzduct:1.0",                     // bad percent escape
		"cpe:/a:vendor:product:1.%0",                       // truncated percent escape
		"cpe:/x:vendor:product:1.0",                        // bad part
	} {
		if got, err := NormalizeCPE(in); err == nil {
			t.Errorf("NormalizeCPE(%q) = %q, want an error", in, got)
		}
	}
}

func TestSplitEscaped(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"a:b:c", []string{"a", "b", "c"}},
		{`a\:b:c`, []string{`a\:b`, "c"}},
		{"", []string{""}},
		{":", []string{"", ""}},
		{`a\\:b`, []string{`a\\`, "b"}},
	}
	for _, tc := range tests {
		got := splitEscaped(tc.in, ':')
		if len(got) != len(tc.want) {
			t.Errorf("splitEscaped(%q) = %q, want %q", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitEscaped(%q) = %q, want %q", tc.in, got, tc.want)
				break
			}
		}
	}
}
