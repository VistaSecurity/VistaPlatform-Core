package services

import (
	"os"
	"regexp"
	"testing"
)

// The control-level readers must ask "is this finding suppressed?" through
// notSuppressedPredicate, which also honours an expired suppressed_until. A
// hand-written `workflow_status <> 'SUPPRESSED' OR ... IS NULL` keeps counting a
// lapsed suppression as still hiding the finding.
func TestControlReadersUseTheSharedSuppressionPredicate(t *testing.T) {
	hand := regexp.MustCompile(`workflow_status\s*(<>|!=)\s*'SUPPRESSED'\s+OR\s+\S*workflow_status\s+IS\s+NULL`)
	for _, f := range []string{
		"framework_score.go", "evaluation_service.go",
		"framework_context_service.go", "framework_license_service.go",
	} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if hand.Match(src) {
			t.Errorf("%s hand-writes the SUPPRESSED test; use notSuppressedPredicate(alias)", f)
		}
	}
}
