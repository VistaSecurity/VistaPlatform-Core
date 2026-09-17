package ratingsguard

import "testing"

func TestMutationFixtures(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		bad          bool
	}{
		{"generic score", "func band(score int) string {if score>=90{return \"Critical\"};if score>=70{return \"High\"};return \"Medium\"}", true},
		{"renamed and constants", "const cutoff=70; func band(x int) string {if x>=90{return severity.Critical};if x>=cutoff{return severity.High};return severity.Medium}", true},
		{"rank map", "var order=map[string]int{\"critical\":5,\"high\":4,\"medium\":3}", true},
		{"rank switch", "func rank(s string) int {switch s {case severity.Critical:return 5;case severity.High:return 4;case severity.Medium:return 3};return 0}", true},
		{"sql concat", "func rank(col string) string {return \"CASE \"+col+\" WHEN '\"+SeverityCritical+\"' THEN 5 WHEN '\"+SeverityHigh+\"' THEN 4 WHEN '\"+SeverityMedium+\"' THEN 3 END\"}", true},
		{"constructor", "var bands=ladder.FromRungs(C,H,M,L)", true},
		{"named boundaries", "const (vulnMediumScore=40;vulnHighScore=70;vulnCriticalScore=90)", true},
		{"band literal", "var band=riskbands.RiskBand{Label:\"Critical\",Min:90}", true},
		{"anonymous table", `var bands=[]struct{Label string; Min int}{{"Critical",90},{"High",70},{"Medium",40}}`, true},
		{"generic SQL grade", "var grade = `CASE WHEN score >=90 THEN 'critical' WHEN score>=70 THEN 'high' ELSE 'medium' END`", true},
		{"if ranks", `func rank(s string)int{if s=="critical"{return 5};if s=="high"{return 4};if s=="medium"{return 3};return 0}`, true},
		{"assigned ranks", `func rank(s string)int{r:=0;switch s{case "critical":r=5;case "high":r=4;case "medium":r=3};return r}`, true},
		{"zero score alone", "func known(x int) bool{return x>0}", false},
		{"delegated", "func rank(s severity.Severity)(int,error){return severity.Rank(s)}", false},
		{"percentage colour policy", "func color(p float64)string{if p>=90{return \"green\"};if p>=70{return \"amber\"};return \"red\"}", false},
		{"presentation palette", "var colors=map[string]string{\"critical\":\"red\",\"high\":\"orange\",\"medium\":\"amber\"}", false},
		{"comment", "// risk_score >= 70 WHEN 'critical' THEN 5\nfunc healthy()bool{return true}", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Inspect("fixture.go", []byte("package fixture\n"+tc.source))
			if err != nil {
				t.Fatal(err)
			}
			if (len(got) > 0) != tc.bad {
				t.Fatalf("violations=%v, want bad=%v", got, tc.bad)
			}
		})
	}
}
