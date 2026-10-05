package services

import (
	"reflect"
	"testing"

	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// The request's names cross a service boundary. Only a single address takes
// them, the plan sanitizes whatever arrives, and a bad name drops itself, never
// the request.
func TestSNICandidatesForTarget(t *testing.T) {
	req := map[string][]string{
		"10.0.0.5":    {"a.example.test"},
		"app.test":    {"b.example.test"},
		"10.0.1.0/24": {"c.example.test"},
		" 10.0.0.6 ":  {"d.example.test"},
		"2001:db8::7": {"e.example.test"},
	}
	cases := []struct {
		target string
		want   []string
	}{
		{"10.0.0.5", []string{"a.example.test"}},
		{"10.0.0.6", []string{"d.example.test"}},
		{"2001:db8::7", []string{"e.example.test"}},
		{"app.test", nil},    // a hostname target presents its own name
		{"10.0.1.0/24", nil}, // a range names no one host
		{"10.0.0.99", nil},   // nothing supplied
	}
	for _, c := range cases {
		if got := sniCandidatesForTarget(req, c.target); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.target, got, c.want)
		}
	}
	if got := sniCandidatesForTarget(nil, "10.0.0.5"); got != nil {
		t.Errorf("no request names: got %q", got)
	}
}

func TestPlannedTargetKeepsOnlyValidBoundedNames(t *testing.T) {
	spec, err := shareddisc.ResolveJobRequest(shareddisc.JobRequestFields{ScanDepth: "quick"})
	if err != nil {
		t.Fatal(err)
	}
	req := map[string][]string{"10.0.0.5": {"bad name", "192.0.2.1", "a.example.test", "b.example.test", "c.example.test", "d.example.test"}}
	plan, err := shareddisc.BuildScanPlan(spec.Spec, nil, []shareddisc.PlanTargetInput{
		{Target: "10.0.0.5", Class: shareddisc.ClassPrivate, SNICandidates: sniCandidatesForTarget(req, "10.0.0.5")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a.example.test", "b.example.test", "c.example.test"}; !reflect.DeepEqual(plan.Targets[0].SNICandidates, want) {
		t.Fatalf("plan names = %q, want %q", plan.Targets[0].SNICandidates, want)
	}
}
