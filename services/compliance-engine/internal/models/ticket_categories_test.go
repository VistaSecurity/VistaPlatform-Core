package models

import "testing"

func TestValidateTicketCategory_AcceptsEveryWritableCategory(t *testing.T) {
	for _, c := range TicketCategoriesWritable {
		if err := ValidateTicketCategory(c); err != nil {
			t.Errorf("category %q should be accepted, got: %v", c, err)
		}
	}
}

func TestValidateTicketCategory_RejectsUnknown(t *testing.T) {
	// The whole point of validating in Go: without this the value reaches the
	// DB CHECK and the caller gets a 500 "failed to create ticket" naming no
	// field at all.
	err := ValidateTicketCategory("bogus")
	if err == nil {
		t.Fatal("an unknown category must be rejected")
	}
	// The offending value is echoed back so the caller does not have to guess
	// which field the server disliked.
	if got := err.Error(); !contains(got, `"bogus"`) {
		t.Errorf("error should name the offending value, got: %s", got)
	}
}

func TestValidateTicketCategory_RejectsRetiredCategoryWithItsOwnMessage(t *testing.T) {
	// `remediation` is still legal in the DB (pre-split rows satisfy the CHECK)
	// but must never be written again. A caller who tries deserves to be told
	// it is retired rather than that it does not exist.
	err := ValidateTicketCategory("remediation")
	if err == nil {
		t.Fatal("the retired category must be rejected for new tickets")
	}
	if !contains(err.Error(), "retired") {
		t.Errorf("error should say the category is retired, got: %s", err.Error())
	}
}

func TestValidateTicketCategory_RejectsEmpty(t *testing.T) {
	// Callers resolve their default BEFORE validating, so an empty category
	// here means nothing applied one — which would write "" to the row.
	if err := ValidateTicketCategory(""); err == nil {
		t.Fatal("an empty category must be rejected, not defaulted here")
	}
}

func TestTicketCategories_WritableAndLegacyDoNotOverlap(t *testing.T) {
	for _, w := range TicketCategoriesWritable {
		for _, l := range TicketCategoriesLegacy {
			if w == l {
				t.Errorf("%q is in both the writable and legacy lists", w)
			}
		}
	}
}

func TestValidateTicketSeverity_EmptyMeansClear(t *testing.T) {
	// severity is nullable on the table, so "" is how a caller clears it.
	// Rejecting it would make the field un-clearable from the drawer.
	if err := ValidateTicketSeverity(""); err != nil {
		t.Errorf("empty severity should be accepted as a clear, got: %v", err)
	}
	if err := ValidateTicketSeverity("bogus"); err == nil {
		t.Error("an unknown severity must be rejected")
	}
	for _, s := range []string{"low", "medium", "high", "critical"} {
		if err := ValidateTicketSeverity(s); err != nil {
			t.Errorf("severity %q should be accepted, got: %v", s, err)
		}
	}
}

func TestValidateTicketStatusAndPriority(t *testing.T) {
	for _, s := range []string{"open", "in_progress", "resolved", "closed"} {
		if err := ValidateTicketStatus(s); err != nil {
			t.Errorf("status %q should be accepted, got: %v", s, err)
		}
	}
	if err := ValidateTicketStatus("reopened"); err == nil {
		t.Error("an unknown status must be rejected")
	}
	// Unlike severity, status and priority are NOT NULL on the table, so an
	// empty string is an error rather than a clear.
	if err := ValidateTicketStatus(""); err == nil {
		t.Error("an empty status must be rejected")
	}
	if err := ValidateTicketPriority(""); err == nil {
		t.Error("an empty priority must be rejected")
	}
	if err := ValidateTicketPriority("urgent"); err == nil {
		t.Error("an unknown priority must be rejected")
	}
}

func TestUpdateTicketInput_Validate_SkipsAbsentFields(t *testing.T) {
	// A nil pointer means "not being changed". Validating an absent field
	// would reject an update that never touched it — e.g. a comment-only or
	// tags-only PUT.
	var empty UpdateTicketInput
	if err := empty.Validate(); err != nil {
		t.Errorf("an update that changes no closed-vocabulary field must pass, got: %v", err)
	}

	bad := "bogus"
	if err := (&UpdateTicketInput{Category: &bad}).Validate(); err == nil {
		t.Error("an invalid category on an update must be rejected")
	}
	if err := (&UpdateTicketInput{Status: &bad}).Validate(); err == nil {
		t.Error("an invalid status on an update must be rejected")
	}
	if err := (&UpdateTicketInput{Priority: &bad}).Validate(); err == nil {
		t.Error("an invalid priority on an update must be rejected")
	}
	if err := (&UpdateTicketInput{Severity: &bad}).Validate(); err == nil {
		t.Error("an invalid severity on an update must be rejected")
	}

	good := "pqc"
	if err := (&UpdateTicketInput{Category: &good}).Validate(); err != nil {
		t.Errorf("a valid category on an update must pass, got: %v", err)
	}
}

func TestCreateTicketInput_Validate(t *testing.T) {
	in := &CreateTicketInput{Category: "inventory", Priority: "high"}
	if err := in.Validate(); err != nil {
		t.Errorf("a valid create input must pass, got: %v", err)
	}

	in.Category = "remediation"
	if err := in.Validate(); err == nil {
		t.Error("a create with the retired category must be rejected")
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
