package services

import (
	"strings"
	"testing"
)

// The external-connections search box ran `ILIKE '%' + term + '%'` with the
// term unescaped: a lone `%` matched every row and `_` any single character,
// and `_` is common in hostnames. This file pins the clause + pattern the
// service sends; the DB-backed twin
// (external_connections_search_like_integration_test.go) proves the rows that
// come back through the real List.
func TestExternalConnectionSearchClauseEscapesTheTerm(t *testing.T) {
	for _, tc := range []struct{ search, wantPattern string }{
		{"build_agent", `%build\_agent%`},
		{"100%", `%100\%%`},
		{"%", `%\%%`},
		{`a\b`, `%a\\b%`},
		{"example.com", `%example.com%`},
	} {
		clause, pattern := externalConnectionSearchClause(3, tc.search)
		if pattern != tc.wantPattern {
			t.Errorf("search %q: pattern = %q, want %q", tc.search, pattern, tc.wantPattern)
		}
		for _, col := range []string{"dest_hostname", "dest_ip::text"} {
			if !strings.Contains(clause, col+` ILIKE $3 ESCAPE '\'`) {
				t.Errorf("search %q: clause %q lacks `%s ILIKE $3 ESCAPE '\\'`", tc.search, clause, col)
			}
		}
	}
}
