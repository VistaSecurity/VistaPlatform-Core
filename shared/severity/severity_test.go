package severity

import (
	"fmt"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestStrictSeverityAndControlWeights(t *testing.T) {
	for _, tc := range []struct {
		value        string
		rank, weight int
	}{{"critical", 5, 4}, {"high", 4, 3}, {"medium", 3, 2}, {"low", 2, 1}, {"info", 1, 0}} {
		value, err := Parse(tc.value)
		if err != nil {
			t.Fatal(err)
		}
		rank, err := Rank(value)
		if err != nil || rank != tc.rank {
			t.Fatalf("rank %s=%d,%v", value, rank, err)
		}
		label, err := Label(value)
		if err != nil || label == "" {
			t.Fatal(value, err)
		}
		weight, err := ControlWeight(value)
		if tc.weight == 0 {
			if err == nil {
				t.Fatal("info accepted as control")
			}
		} else if err != nil || weight != tc.weight {
			t.Fatal(value, weight, err)
		}
	}
	for _, invalid := range []string{"Med", "Medium", "CRITICAL", " medium", "info ", "none", "", "unknown"} {
		if _, err := Parse(invalid); err == nil {
			t.Fatalf("accepted %q", invalid)
		}
		if _, err := Rank(Severity(invalid)); err == nil {
			t.Fatalf("rank accepted %q", invalid)
		}
		if _, err := Label(Severity(invalid)); err == nil {
			t.Fatalf("label accepted %q", invalid)
		}
		if _, err := ControlWeight(Severity(invalid)); err == nil {
			t.Fatalf("weight accepted %q", invalid)
		}
	}
}
func TestIntegration_RankSQLMatchesGo(t *testing.T) {
	db := testdb.Connect(t)
	for _, d := range Definitions() {
		var rank int
		if err := db.QueryRow("SELECT "+RankSQL("$1::text"), string(d.Value)).Scan(&rank); err != nil {
			t.Fatal(err)
		}
		want, _ := Rank(d.Value)
		if rank != want {
			t.Fatal(d.Value, rank, want)
		}
	}
	for _, invalid := range []any{"Med", "invalid", nil} {
		var rank *int
		if err := db.QueryRow("SELECT "+RankSQL("$1::text"), invalid).Scan(&rank); err != nil {
			t.Fatal(err)
		}
		if rank != nil {
			t.Fatal("invalid SQL rank", invalid, rank)
		}
	}
}
func TestRankSQLContainsOnlyCanonicalValues(t *testing.T) {
	sql := RankSQL("finding.severity")
	for _, d := range Definitions() {
		if !strings.Contains(sql, fmt.Sprintf("WHEN '%s' THEN %d", d.Value, d.Rank)) {
			t.Fatal(sql)
		}
	}
	if !strings.HasSuffix(sql, " ELSE NULL END") {
		t.Fatal(sql)
	}
}
