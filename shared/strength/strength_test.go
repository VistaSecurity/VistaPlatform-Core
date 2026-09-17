package strength

import "testing"

func TestWeakest(t *testing.T) {
	for _, tc := range []struct {
		values   []string
		want     string
		complete bool
	}{
		{nil, "", false}, {[]string{"recommended", "weak"}, "weak", true}, {[]string{"strong", "acceptable"}, "acceptable", true},
		{[]string{"recommended", "strong"}, "strong", true}, {[]string{"recommended"}, "recommended", true},
		{[]string{"weak", ""}, "weak", false}, {[]string{"strong", "unknown"}, "strong", false},
	} {
		got, complete := Weakest(tc.values...)
		if got != tc.want || complete != tc.complete {
			t.Fatalf("%v = %q,%v", tc.values, got, complete)
		}
	}
}
