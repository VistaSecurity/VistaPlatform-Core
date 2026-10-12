package services

// openFindingPredicate is the SQL fragment for "this finding is open": ACTIVE,
// and not under a suppression that is still in force.
//
// A suppression is in force while workflow_status = 'SUPPRESSED' AND its
// suppressed_until (when set) has not passed. The workflow_status column alone
// is not the truth: it only changes when something writes it, and a time-boxed
// suppression that has run out is reopened by the expiry sweep
// (FindingsService.ExpireSuppressions) up to one sweep interval later. Reading
// the deadline here as well means a control counts the finding again the moment
// the deadline passes, not at the next tick.
//
// alias is the findings table alias. The result is a parenthesised expression
// safe to AND into a WHERE clause. It contains no placeholders.
func openFindingPredicate(alias string) string {
	return "(" + alias + ".detection_state = 'ACTIVE'" +
		" AND " + notSuppressedPredicate(alias) + ")"
}

// notSuppressedPredicate is the suppression half of openFindingPredicate on its
// own, for readers that constrain detection_state separately.
func notSuppressedPredicate(alias string) string {
	return "(" + alias + ".workflow_status <> 'SUPPRESSED' OR " + alias + ".workflow_status IS NULL" +
		" OR (" + alias + ".suppressed_until IS NOT NULL AND " + alias + ".suppressed_until <= NOW()))"
}
