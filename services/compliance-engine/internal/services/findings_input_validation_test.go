package services

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Validation runs before any database access, so a zero-value service proves
// the refusals are input errors and not failures of the store.
func TestUpdateWorkflowStatus_RefusesBadInputAsInputErrors(t *testing.T) {
	svc := &FindingsService{}
	reason := "accepted"
	blank := "   "
	long := strings.Repeat("x", MaxSuppressionReasonLen+1)
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	cases := []struct {
		name   string
		status string
		reason *string
		until  *time.Time
		field  string
	}{
		{"unknown status", "BOGUS", nil, nil, "workflow_status"},
		{"lower-case status", "suppressed", &reason, &future, "workflow_status"},
		{"suppress without reason", "SUPPRESSED", nil, &future, "suppression_reason"},
		{"suppress with blank reason", "SUPPRESSED", &blank, &future, "suppression_reason"},
		{"suppress with huge reason", "SUPPRESSED", &long, &future, "suppression_reason"},
		{"suppress until the past", "SUPPRESSED", &reason, &past, "suppressed_until"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.UpdateWorkflowStatus(uuid.New(), uuid.New(), uuid.New(), tc.status, tc.reason, tc.until)
			ie, ok := AsInputError(err)
			if !ok || ie.Missing || ie.Field != tc.field {
				t.Fatalf("err = %v, want an InputError (not Missing) on %s", err, tc.field)
			}
		})
	}
}

// The predicate is what the open-finding readers splice in; pin its shape so
// the deadline guard cannot be dropped without a test noticing even where no
// database is available.
func TestOpenFindingPredicate_ReadsTheSuppressionDeadline(t *testing.T) {
	p := openFindingPredicate("f")
	for _, want := range []string{"f.detection_state = 'ACTIVE'", "f.workflow_status <> 'SUPPRESSED'", "f.suppressed_until <= NOW()"} {
		if !strings.Contains(p, want) {
			t.Errorf("openFindingPredicate(%q) lacks %q:\n%s", "f", want, p)
		}
	}
}
