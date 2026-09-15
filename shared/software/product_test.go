package software

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/query/ast"
)

// TestProductIdentity pins the coalesce rule the `software_products` unique
// index implements, one row per branch of it.
//
// The last case is the one this test exists for. DATA_MODEL §4 first wrote the
// key as `name || '@' || version`, which is NULL when version is NULL — and in
// Postgres NULLs do not conflict, so every re-observation of an unversioned
// product would have inserted another row. The Go side has the same trap
// written differently: returning "" for a nameless-versionless product would
// collapse every such product onto one key. Both directions are asserted.
func TestProductIdentity(t *testing.T) {
	tests := []struct {
		name string
		in   Product
		want string
	}{
		{
			name: "purl wins over everything",
			in: Product{
				Name:    "OpenSSL",
				Version: "3.0.13",
				PURL:    "pkg:generic/openssl@3.0.13",
				CPE:     "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*",
			},
			want: "pkg:generic/openssl@3.0.13",
		},
		{
			name: "cpe wins when there is no purl",
			in: Product{
				Name:    "OpenSSL",
				Version: "3.0.13",
				CPE:     "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*",
			},
			want: "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*",
		},
		{
			name: "name@version when neither identifier is present",
			in:   Product{Name: "OpenSSL", Version: "3.0.13"},
			want: "OpenSSL@3.0.13",
		},
		{
			// THE regression. An unversioned product keeps a stable,
			// non-empty identity ending in '@'; anything else and the
			// catalogue either collapses or duplicates.
			name: "unversioned product keeps a non-empty identity",
			in:   Product{Name: "OpenSSL"},
			want: "OpenSSL@",
		},
		{
			name: "identity is computed on the NORMALISED fields",
			in:   Product{Name: "  OpenSSL  ", Version: " 3.0.13 "},
			want: "OpenSSL@3.0.13",
		},
		{
			// A CPE that will not survive normalisation must not be the key
			// here either, or the Go identity and the database identity
			// disagree and two rows appear for one product.
			name: "a dropped cpe does not become the identity",
			in:   Product{Name: "OpenSSL", Version: "3.0.13", CPE: "cpe:2.3:a:openssl"},
			want: "OpenSSL@3.0.13",
		},
		{
			name: "a dropped purl falls through to the cpe",
			in: Product{
				Name:    "OpenSSL",
				Version: "3.0.13",
				PURL:    "not-a-purl",
				CPE:     "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*",
			},
			want: "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*",
		},
		{
			name: "purl case variants converge on one identity",
			in:   Product{Name: "left-pad", PURL: "PKG:NPM/Left-Pad@1.3.0"},
			want: "pkg:npm/Left-Pad@1.3.0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.Identity(); got != tc.want {
				t.Errorf("Identity() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestProductIdentityNeverEmptyForANamedProduct is the invariant behind the
// table above, stated as a property rather than as cases: whatever else is
// missing, a product with a name has an identity.
func TestProductIdentityNeverEmptyForANamedProduct(t *testing.T) {
	for _, p := range []Product{
		{Name: "a"},
		{Name: "a", Version: ""},
		{Name: "a", PURL: "garbage"},
		{Name: "a", CPE: "garbage"},
		{Name: "a", PURL: "garbage", CPE: "garbage"},
	} {
		if got := p.Identity(); got == "" {
			t.Errorf("Identity() = \"\" for %#v — a NULL identity admits unlimited duplicates", p)
		}
	}
}

// TestProductVersionSortDelegates checks that VersionSort is the query
// language's key and not a second normalisation. A reimplementation here would
// make the writer and the `version < 3.0` translator disagree, and the
// predicate would return the wrong rows rather than fail.
func TestProductVersionSortDelegates(t *testing.T) {
	for _, v := range []string{"3.0.13", "1.1.1w", "1.0.0-rc1", "v2.1", "", "nightly"} {
		want, wantOK := ast.VersionSortKey(v)
		got, gotOK := Product{Version: v}.VersionSort()
		if got != want || gotOK != wantOK {
			t.Errorf("VersionSort(%q) = (%q, %v), ast.VersionSortKey = (%q, %v)", v, got, gotOK, want, wantOK)
		}
	}
}

// TestProductVersionSortOrders is the §5.5 claim applied to this type.
//
// The second pair is the one that matters: "1.9" sorts ABOVE "1.10" as text
// and below it as a version, so a column filled with the raw version string
// inverts every `version < …` predicate built on it. The assertion on the
// lexical order is deliberate — it fails loudly if the example ever stops
// demonstrating the inversion, rather than leaving a test that proves nothing.
func TestProductVersionSortOrders(t *testing.T) {
	ordered := [][2]string{
		{"1.1.1w", "3.0.2"},
		{"1.9", "1.10"},
		{"1.0.0-rc1", "1.0.0"},
		{"3.0", "3.0.2"},
	}
	for _, pair := range ordered {
		lower, ok := (Product{Version: pair[0]}).VersionSort()
		if !ok {
			t.Fatalf("%q produced no sort key", pair[0])
		}
		higher, ok := (Product{Version: pair[1]}).VersionSort()
		if !ok {
			t.Fatalf("%q produced no sort key", pair[1])
		}
		if lower >= higher {
			t.Errorf("sort key for %q (%q) is not below %q (%q)", pair[0], lower, pair[1], higher)
		}
	}

	if "1.9" <= "1.10" {
		t.Fatal("the premise of this test changed: 1.9 no longer sorts above 1.10 lexically, " +
			"so this test no longer demonstrates why version_sort exists")
	}
}

// TestProductVersionSortUnparseable: a version with no numeric component has
// NO key, which is what makes the column NULL and the comparison UNKNOWN.
// Returning the raw string instead would silently reintroduce lexical order.
func TestProductVersionSortUnparseable(t *testing.T) {
	for _, v := range []string{"", "latest", "nightly", "   "} {
		if key, ok := (Product{Version: v}).VersionSort(); ok {
			t.Errorf("VersionSort(%q) = (%q, true), want no key", v, key)
		}
	}
}

func TestProductNormalize(t *testing.T) {
	tests := []struct {
		name      string
		in        Product
		want      Product
		wantNotes int
	}{
		{
			name: "trims every field",
			in:   Product{Name: " a ", Vendor: " b ", Version: " 1 ", LicenseID: " MIT "},
			want: Product{Name: "a", Vendor: "b", Version: "1", LicenseID: "MIT"},
		},
		{
			name: "canonicalises the purl",
			in:   Product{Name: "x", PURL: "pkg://GitHub/VistaSecurity/VistaPlatform@v1"},
			want: Product{Name: "x", PURL: "pkg:github/vistasecurity/VistaPlatform@v1"},
		},
		{
			name: "converts a 2.2 cpe URI",
			in:   Product{Name: "x", CPE: "cpe:/a:openssl:openssl:3.0.13"},
			want: Product{Name: "x", CPE: "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*"},
		},
		{
			name:      "drops an unparseable purl and says so",
			in:        Product{Name: "x", PURL: "npm/left-pad"},
			want:      Product{Name: "x"},
			wantNotes: 1,
		},
		{
			name:      "drops an unparseable cpe and says so",
			in:        Product{Name: "x", CPE: "cpe:2.3:a:only:four:fields"},
			want:      Product{Name: "x"},
			wantNotes: 1,
		},
		{
			name:      "reports both drops",
			in:        Product{Name: "x", PURL: "nope", CPE: "nope"},
			want:      Product{Name: "x"},
			wantNotes: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, notes := tc.in.Normalize()
			if got != tc.want {
				t.Errorf("Normalize() = %#v, want %#v", got, tc.want)
			}
			if len(notes) != tc.wantNotes {
				t.Errorf("Normalize() notes = %v, want %d of them", notes, tc.wantNotes)
			}
			// Idempotence is what lets Identity() normalise internally
			// without changing the answer on an already-normalised product.
			again, againNotes := got.Normalize()
			if again != got {
				t.Errorf("Normalize() is not idempotent: %#v then %#v", got, again)
			}
			if len(againNotes) != 0 {
				t.Errorf("re-normalising a normalised product produced notes %v", againNotes)
			}
		})
	}
}

// TestNormalizeNotesDoNotEchoUnbounded: a note quotes the offending value, and
// an SBOM component field is attacker-supplied and can be megabytes long. The
// quote is truncated so one hostile field cannot blow the warning list up.
func TestNormalizeNotesDoNotEchoUnbounded(t *testing.T) {
	_, notes := Product{Name: "x", PURL: strings.Repeat("A", 10_000)}.Normalize()
	if len(notes) != 1 {
		t.Fatalf("notes = %v, want 1", notes)
	}
	if len(notes[0]) > 400 {
		t.Errorf("note is %d bytes; a note must not echo the whole field", len(notes[0]))
	}
}

func TestProductIdentifiable(t *testing.T) {
	if (Product{Name: "x"}).Identifiable() != true {
		t.Error("a named product is identifiable")
	}
	// A machine identifier is not a substitute for a name: the column is NOT
	// NULL, so this row cannot be written whatever else it carries.
	if (Product{PURL: "pkg:npm/left-pad@1.3.0"}).Identifiable() != false {
		t.Error("a nameless product must not claim to be identifiable")
	}
	if (Product{Name: "   "}).Identifiable() != false {
		t.Error("a whitespace name is not a name")
	}
}

func TestInstallValid(t *testing.T) {
	tests := []struct {
		name string
		in   Install
		want bool
	}{
		{"complete", Install{Product: "pkg:npm/x@1", Source: SourceImported}, true},
		{"no product identity", Install{Source: SourceImported}, false},
		{"blank product identity", Install{Product: "  ", Source: SourceImported}, false},
		{"no source kind", Install{Product: "pkg:npm/x@1"}, false},
		{"source kind outside the CHECK vocabulary", Install{Product: "pkg:npm/x@1", Source: "sbom"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.Valid(); got != tc.want {
				t.Errorf("Valid() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSourceKindsMatchIdentity is the drift guard for the copied vocabulary.
// This package spells the four provenance values itself so it stays
// stdlib-only for the cross-compiled agent; the TEST binary may import
// identity, so the copy is checked against the original rather than trusted.
func TestSourceKindsMatchIdentity(t *testing.T) {
	pairs := []struct {
		here  string
		there identity.SourceKind
	}{
		{SourceMeasured, identity.SourceMeasured},
		{SourceDeclared, identity.SourceDeclared},
		{SourceImported, identity.SourceImported},
		{SourceInferred, identity.SourceInferred},
	}
	for _, p := range pairs {
		if p.here != string(p.there) {
			t.Errorf("software constant %q does not match identity.SourceKind %q", p.here, p.there)
		}
		if !ValidSourceKind(p.here) {
			t.Errorf("ValidSourceKind(%q) = false", p.here)
		}
		if !p.there.Valid() {
			t.Errorf("identity.SourceKind(%q).Valid() = false", p.there)
		}
	}
	// The other direction: if identity grows a fifth value, this package must
	// grow it too. There is no enumeration to range over, so the count is
	// pinned by asserting the four we know are the only ones ValidSourceKind
	// accepts, and by the guard below.
	for _, s := range []string{"unknown", "sbom", "observed", ""} {
		if ValidSourceKind(s) {
			t.Errorf("ValidSourceKind(%q) = true; the vocabulary is four values", s)
		}
		if identity.SourceKind(s).Valid() {
			t.Errorf("identity.SourceKind(%q).Valid() = true — the vocabularies have drifted", s)
		}
	}
}

func TestErrorsAreSentinelWrapped(t *testing.T) {
	if _, err := NormalizePURL("nope"); !errors.Is(err, ErrInvalidPURL) {
		t.Errorf("NormalizePURL error %v does not wrap ErrInvalidPURL", err)
	}
	if _, err := NormalizeCPE("nope"); !errors.Is(err, ErrInvalidCPE) {
		t.Errorf("NormalizeCPE error %v does not wrap ErrInvalidCPE", err)
	}
}

// TestIdentityMatchesTheSQLUniqueExpression evaluates the `software_products`
// unique expression the way Postgres evaluates it — over NULLABLE columns —
// and requires [Product.Identity] to agree for every combination of present
// and absent fields.
//
// TestProductIdentity pins the branches; this pins the TRANSLATION between the
// two spellings of "absent". Go works on strings and spells absent as "";
// Postgres works on columns and spells it NULL, and `coalesce` skips only the
// second. That gap is where a Go identity and a database identity drift apart,
// and the drift is invisible from either side on its own.
//
// Nameless products are out of scope, deliberately: `software_products.name`
// is NOT NULL, the parser drops a component without one
// ([Product.Identifiable]), and FuzzParse asserts none is ever returned.
func TestIdentityMatchesTheSQLUniqueExpression(t *testing.T) {
	for _, p := range []Product{
		{Name: "OpenSSL", Version: "3.0.13", PURL: "pkg:generic/openssl@3.0.13", CPE: "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*"},
		{Name: "OpenSSL", Version: "3.0.13", PURL: "pkg:generic/openssl@3.0.13"},
		{Name: "OpenSSL", PURL: "pkg:generic/openssl"},
		{Name: "OpenSSL", Version: "3.0.13", CPE: "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*"},
		{Name: "OpenSSL", CPE: "cpe:2.3:a:openssl:openssl:-:*:*:*:*:*:*:*"},
		{Name: "OpenSSL", Version: "3.0.13"},
		// The case the inner coalesce exists for: no version at all.
		{Name: "OpenSSL"},
		{Name: "  OpenSSL  ", Version: " 3.0.13 "},
		// Identifiers that will not survive normalisation have to fall through
		// on BOTH sides, or one product is keyed two ways.
		{Name: "OpenSSL", Version: "3.0.13", PURL: "not-a-purl", CPE: "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*"},
		{Name: "OpenSSL", Version: "3.0.13", PURL: "not-a-purl", CPE: "not-a-cpe"},
		{Name: "OpenSSL", PURL: "not-a-purl", CPE: "not-a-cpe"},
	} {
		normalized, _ := p.Normalize()
		// What the writer puts in the row: the NORMALISED value, or NULL when
		// it is absent. Never '' — see TestIdentityWriterMustStoreNULLNotEmpty.
		sql := sqlUniqueKey(
			nullIfEmpty(normalized.PURL),
			nullIfEmpty(normalized.CPE),
			nullIfEmpty(normalized.Name),
			nullIfEmpty(normalized.Version),
		)
		if sql == nil {
			t.Errorf("the SQL expression is NULL for %#v, which admits unlimited duplicate rows", p)
			continue
		}
		if got := p.Identity(); got != *sql {
			t.Errorf("Identity() = %q but the unique expression evaluates to %q for %#v", got, *sql, p)
		}
	}
}

// TestIdentityWriterMustStoreNULLNotEmpty states, executably, the one way the
// Go identity and the database identity can still disagree. It is not a bug in
// this package; it is a rule the writer (workstream 2.6b) has to keep, and it
// is written down here because nothing in Go can observe a writer breaking it.
//
// `coalesce` skips NULL, not ”. A writer that stores the empty string for an
// absent purl keys EVERY purl-less product in the tenant on ”, so the second
// one collides with the first, while Identity() hands back a distinct
// name@version for each.
func TestIdentityWriterMustStoreNULLNotEmpty(t *testing.T) {
	alpha := Product{Name: "alpha", Version: "1"}
	beta := Product{Name: "beta", Version: "2"}

	if alpha.Identity() == beta.Identity() {
		t.Fatal("two different products share a Go identity; the rest of this test proves nothing")
	}

	// Written correctly — purl NULL — the two products keep two keys.
	withNULL := func(p Product) string {
		return *sqlUniqueKey(nil, nil, &p.Name, &p.Version)
	}
	if withNULL(alpha) == withNULL(beta) {
		t.Error("with a NULL purl the unique expression must fall through to name@version")
	}

	// Written wrongly — purl '' — they collapse onto one key, and the
	// catalogue loses a product on the second insert.
	empty := ""
	if *sqlUniqueKey(&empty, nil, &alpha.Name, &alpha.Version) != *sqlUniqueKey(&empty, nil, &beta.Name, &beta.Version) {
		t.Error("the premise of this test changed: '' no longer satisfies coalesce, " +
			"so the writer rule it documents is no longer load-bearing")
	}
}

// sqlUniqueKey evaluates
//
//	coalesce(purl, cpe, name || '@' || coalesce(version, ''))
//
// under SQL's NULL semantics: coalesce returns its first non-NULL argument,
// and `||` yields NULL when any operand is NULL. nil is NULL; a pointer to ""
// is the empty string, which SQL treats as a VALUE.
func sqlUniqueKey(purl, cpe, name, version *string) *string {
	switch {
	case purl != nil:
		return purl
	case cpe != nil:
		return cpe
	case name == nil:
		// `NULL || '@' || …` is NULL. Unreachable through the column, which is
		// NOT NULL; stated so the reader does not have to wonder.
		return nil
	}
	v := ""
	if version != nil {
		v = *version
	}
	key := *name + "@" + v
	return &key
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// TestNormalizeNotesStripControlCharacters: a note echoes the identifier it
// dropped, that identifier came out of an uploaded SBOM, and the note is
// rendered in a terminal and in a browser. An escape sequence must not survive
// the trip — the same rule describeByte applies one byte at a time.
func TestNormalizeNotesStripControlCharacters(t *testing.T) {
	_, notes := Product{Name: "x", PURL: "not-a-purl\x1b]0;pwned\x07 and\x00a\nnewline"}.Normalize()
	if len(notes) != 1 {
		t.Fatalf("notes = %v, want 1", notes)
	}
	for _, bad := range []struct{ ch, what string }{
		{"\x1b", "an ESC, which introduces an ANSI escape sequence"},
		{"\x07", "a BEL"},
		{"\x00", "a NUL"},
		{"\n", "a newline, which forges a second warning line"},
	} {
		if strings.Contains(notes[0], bad.ch) {
			t.Errorf("the note carries %s straight from the uploaded document: %q", bad.what, notes[0])
		}
	}
	// The inverse polarity: the readable part of the value must still be
	// there, or the note has stopped naming what it dropped.
	if !strings.Contains(notes[0], "not-a-purl") {
		t.Errorf("note = %q; stripping control characters must not eat the value itself", notes[0])
	}
}

// TestNormalizeNotesStayValidUTF8: the quoted value is truncated by BYTES, so
// a multi-byte character straddling the cut would otherwise leave half a rune
// in the message.
func TestNormalizeNotesStayValidUTF8(t *testing.T) {
	// The single leading ASCII byte is load-bearing: without it the two-byte
	// runes happen to land flush against the 120-byte cut and a byte-wise
	// truncation would pass this test by luck.
	_, notes := Product{Name: "x", PURL: "a" + strings.Repeat("é", 300)}.Normalize()
	if len(notes) != 1 {
		t.Fatalf("notes = %v, want 1", notes)
	}
	if !utf8.ValidString(notes[0]) {
		t.Errorf("note is not valid UTF-8: %q", notes[0])
	}
}
