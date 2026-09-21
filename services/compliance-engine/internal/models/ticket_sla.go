package models

import "time"

// Default due dates by priority — the Go mirror of
// packages/primitives/src/tickets/sla.ts.
//
// Every ticket in the system had due_date = NULL before. Neither the
// findings path, the bulk-crypto path nor the alert path sent one, and there
// was no create form to type one into. The consequence was not a blank column:
// the work queue's Overdue / Due soon / "Keeping pace" cards read 0 / 0 / 100%
// permanently, and the hourly sweep for overdue and due-soon tickets — with
// its ticket_overdue and ticket_due_soon notifications — had no row it could
// ever act on. A whole layer, built on both sides, doing nothing.
//
// The numbers live in two languages because both create tickets: the UI fills
// the form, and CreateTicketFromAlert runs server-side with no UI involved.
// scripts/audit-ticket-categories.mjs compares the two maps and fails
// `make audit` if they diverge.

// DefaultSLADays is days-from-creation to the default due date, by priority.
//
// The shortest is 7 days, comfortably outside the fixed 3-day "due soon"
// window, so a freshly-filed ticket is never born already warning — a ticket
// that shows up amber the moment it is created teaches people to ignore the
// colour.
var DefaultSLADays = map[string]int{
	"critical": 7,
	"high":     14,
	"medium":   30,
	"low":      60,
}

// DueSoonDays is the window the due-date sweep treats as "due soon".
const DueSoonDays = 3

// DefaultDueDate returns the due date for a ticket of this priority.
//
// An unrecognised priority falls back to the medium window rather than to no
// due date: a ticket without one is invisible to every SLA view, which is the
// failure this mechanism exists to end.
func DefaultDueDate(priority string, from time.Time) time.Time {
	days, ok := DefaultSLADays[priority]
	if !ok {
		days = DefaultSLADays["medium"]
	}
	return from.AddDate(0, 0, days)
}

// DefaultDueDateRFC3339 is DefaultDueDate in the string form
// CreateTicketInput.DueDate expects.
func DefaultDueDateRFC3339(priority string, from time.Time) string {
	return DefaultDueDate(priority, from).Format(time.RFC3339)
}
