package identity

import (
	"strings"
	"testing"
)

func TestIsConnectionSource(t *testing.T) {
	for _, tc := range []struct {
		src  Source
		want bool
	}{
		{Source{Kind: SourceImported, Ref: "cmdb:4f0c"}, true},
		{Source{Kind: SourceImported, Ref: "netbox:9a1e"}, true},
		{Source{Kind: SourceImported, Ref: SpreadsheetImportSourceRef}, false}, // a person's upload
		{Source{Kind: SourceImported, Ref: "sbom:upload-1"}, false},
		{Source{Kind: SourceImported, Ref: "sbom"}, false},
		{Source{Kind: SourceImported, Ref: "eol:endoflife.date"}, false},
		{Source{Kind: SourceMeasured, Ref: "cmdb:4f0c"}, false}, // not an import
		{Source{Kind: SourceDeclared, Ref: "netbox:9a1e"}, false},
		{Source{Kind: SourceImported, Ref: "xcmdb:1"}, false},
	} {
		if got := IsConnectionSource(tc.src); got != tc.want {
			t.Errorf("IsConnectionSource(%+v) = %v, want %v", tc.src, got, tc.want)
		}
	}
}

// The SQL form is generated from the same prefixes as the Go check: every
// prefix the Go check accepts appears in it, and nothing else does.
func TestConnectionSourceRefSQL_IsGeneratedFromThePrefixes(t *testing.T) {
	sql := ConnectionSourceRefSQL("h.source")
	for _, p := range connectionSourceRefPrefixes {
		if !strings.Contains(sql, "h.source LIKE '"+p+"%'") {
			t.Errorf("%s does not test prefix %q", sql, p)
		}
		if !IsConnectionSourceRef(p + "x") {
			t.Errorf("Go check rejects prefix %q", p)
		}
	}
	if n := strings.Count(sql, " LIKE "); n != len(connectionSourceRefPrefixes) {
		t.Errorf("%s has %d LIKE terms, want %d", sql, n, len(connectionSourceRefPrefixes))
	}
}
