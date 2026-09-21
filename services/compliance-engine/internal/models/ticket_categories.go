package models

import "fmt"

// Ticket categories, statuses, priorities and severities — the write gate.
//
// These lists mirror the CHECK constraints on `public.tickets`. They exist in
// Go so an unknown value is a 400 that names the offending field, not a 500
// from a constraint violation surfacing as "failed to create ticket". The DB
// constraint stays the real backstop: this is the layer that explains.
//
// The same category list is spelled out in four places — the
// `tickets_category_check` constraint in `scripts/database/schema.sql`, here,
// the `TicketCategoryFilter` enum in
// `api/openapi/compliance-engine.openapi.yaml`, and
// `packages/primitives/src/tickets/categories.ts`.
// `scripts/audit-ticket-categories.mjs` reads all four and fails `make audit`
// on disagreement, so adding a category is four edits and the audit names the
// one you missed.

// TicketCategoriesWritable are the categories a new ticket may be filed under,
// in registry order.
var TicketCategoriesWritable = []string{
	"compliance",    // failed framework controls
	"crypto",        // weak cipher / protocol / key size
	"pqc",           // quantum-vulnerable crypto needing migration
	"certificate",   // cert lifecycle: expiry, revocation, chain
	"vulnerability", // known CVE on installed software
	"lifecycle",     // OS/software EOL, hardware end-of-support
	"inventory",     // CI hygiene: no owner/class/location, stale, duplicate
	"configuration", // insecure exposure: plaintext mgmt, default creds
	"drift",         // new issuer, unexpected protocol, port-profile change
	"operational",   // platform ops: sensor/agent offline, service down
	"general",       // manual, anything else
}

// TicketCategoriesLegacy are categories that exist on rows written before the
// per-producer split but are never written again.
//
// `remediation` is a verb, not a subject. Nearly every ticket is remediation
// work, which is how it came to hold weak crypto, quantum exposure,
// end-of-life software, configuration drift and CMDB hygiene in one
// undifferentiated bucket and made a category filter on the work queue
// meaningless. It remains legal in the DB CHECK so pre-split rows still read;
// it is rejected here so nothing writes another one.
var TicketCategoriesLegacy = []string{"remediation"}

var ticketStatuses = []string{"open", "in_progress", "resolved", "closed"}
var ticketSources = []string{"manual", "auto_finding", "auto_expiry", "external_sync", "remediation_queue"}
var ticketPriorities = []string{"low", "medium", "high", "critical"}
var ticketSeverities = []string{"low", "medium", "high", "critical"}

func oneOf(value string, allowed []string) bool {
	for _, a := range allowed {
		if a == value {
			return true
		}
	}
	return false
}

// invalidValue renders the offending value alongside what was allowed. The
// value is echoed back deliberately: "invalid category" alone sends the caller
// hunting through their own payload for which field the server disliked.
func invalidValue(field, value string, allowed []string) error {
	return fmt.Errorf("invalid %s %q: must be one of %v", field, value, allowed)
}

// ValidateTicketCategory accepts only a writable category. An empty string is
// NOT valid here — callers that permit a default resolve it before validating,
// so that "" can never reach the database as a literal.
func ValidateTicketCategory(category string) error {
	if oneOf(category, TicketCategoriesWritable) {
		return nil
	}
	if oneOf(category, TicketCategoriesLegacy) {
		return fmt.Errorf(
			"category %q is retired and cannot be used for new tickets: must be one of %v",
			category, TicketCategoriesWritable)
	}
	return invalidValue("category", category, TicketCategoriesWritable)
}

// ValidateTicketStatus checks a status value.
func ValidateTicketStatus(status string) error {
	if !oneOf(status, ticketStatuses) {
		return invalidValue("status", status, ticketStatuses)
	}
	return nil
}

// ValidateTicketPriority checks a priority value.
func ValidateTicketPriority(priority string) error {
	if !oneOf(priority, ticketPriorities) {
		return invalidValue("priority", priority, ticketPriorities)
	}
	return nil
}

// ValidateTicketSeverity checks a severity value. Severity is nullable on the
// table, so an empty string means "clear it" and is accepted.
func ValidateTicketSeverity(severity string) error {
	if severity == "" {
		return nil
	}
	if !oneOf(severity, ticketSeverities) {
		return invalidValue("severity", severity, ticketSeverities)
	}
	return nil
}

// ValidateTicketSource checks a source value.
func ValidateTicketSource(source string) error {
	if !oneOf(source, ticketSources) {
		return invalidValue("source", source, ticketSources)
	}
	return nil
}

// Ticket defaults. These are the values the row would otherwise take from the
// column DEFAULTs, restated here so that validation sees exactly what will be
// written rather than an empty string standing in for a default.
const (
	DefaultTicketCategory = "general"
	DefaultTicketPriority = "medium"
	DefaultTicketStatus   = "open"
	DefaultTicketSource   = "manual"
)

// ApplyDefaults fills the omitted closed-vocabulary fields on a create.
//
// It must run BEFORE Validate. The two are split deliberately: if validation
// also defaulted, an empty category would be indistinguishable from an absent
// one, and "" could reach the row as a literal whenever a caller mistakenly
// sent it. Defaulting first, validating second, means the value checked is the
// value written.
func (i *CreateTicketInput) ApplyDefaults() {
	if i.Category == "" {
		i.Category = DefaultTicketCategory
	}
	if i.Priority == "" {
		i.Priority = DefaultTicketPriority
	}
	if i.Source == nil || *i.Source == "" {
		src := DefaultTicketSource
		i.Source = &src
	}
}

// Validate checks every closed-vocabulary field on a create.
// It does NOT default anything — call ApplyDefaults first.
func (i *CreateTicketInput) Validate() error {
	if err := ValidateTicketCategory(i.Category); err != nil {
		return err
	}
	if err := ValidateTicketPriority(i.Priority); err != nil {
		return err
	}
	if i.Severity != nil {
		if err := ValidateTicketSeverity(*i.Severity); err != nil {
			return err
		}
	}
	if i.Source != nil {
		if err := ValidateTicketSource(*i.Source); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks every closed-vocabulary field present on an update. A nil
// pointer means "not being changed" and is skipped — validating an absent
// field would reject a request that changes nothing about it.
func (i *UpdateTicketInput) Validate() error {
	if i.Category != nil {
		if err := ValidateTicketCategory(*i.Category); err != nil {
			return err
		}
	}
	if i.Status != nil {
		if err := ValidateTicketStatus(*i.Status); err != nil {
			return err
		}
	}
	if i.Priority != nil {
		if err := ValidateTicketPriority(*i.Priority); err != nil {
			return err
		}
	}
	if i.Severity != nil {
		if err := ValidateTicketSeverity(*i.Severity); err != nil {
			return err
		}
	}
	return nil
}
