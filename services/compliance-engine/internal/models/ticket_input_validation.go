package models

import (
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

// Length ceilings for the free text a caller supplies on a ticket. Far above
// anything a person types, far below what a request body could otherwise store
// (the DB title column is varchar(500), so an over-long title was a 500).
const (
	MaxTicketTitleLen       = 200
	MaxTicketDescriptionLen = 20000
	MaxTicketCommentLen     = 10000
)

// ValidateTicketCommentContent bounds a ticket comment body.
func ValidateTicketCommentContent(content string) error {
	return checkLen("content", content, MaxTicketCommentLen)
}

func checkLen(field, v string, max int) error {
	if n := utf8.RuneCountInString(v); n > max {
		return fmt.Errorf("%s must be at most %d characters (got %d)", field, max, n)
	}
	return nil
}

// checkUUIDRef rejects a present-but-unparseable id. An empty string is treated
// as absent, matching how the service reads these fields. The ticket service
// used to drop an id it could not parse and create the ticket unlinked, so a
// typo'd finding_id answered 201 with nothing attached.
func checkUUIDRef(field string, v *string) error {
	if v == nil || *v == "" {
		return nil
	}
	if _, err := uuid.Parse(*v); err != nil {
		return fmt.Errorf("%s must be a UUID", field)
	}
	return nil
}

func checkRFC3339(field string, v *string) error {
	if v == nil || *v == "" {
		return nil
	}
	if _, err := time.Parse(time.RFC3339, *v); err != nil {
		return fmt.Errorf("%s must be an RFC 3339 timestamp", field)
	}
	return nil
}

func (i *CreateTicketInput) validateShape() error {
	if err := checkLen("title", i.Title, MaxTicketTitleLen); err != nil {
		return err
	}
	if i.Description != nil {
		if err := checkLen("description", *i.Description, MaxTicketDescriptionLen); err != nil {
			return err
		}
	}
	for _, r := range []struct {
		field string
		v     *string
	}{
		{"finding_id", i.FindingID},
		{"control_id", i.ControlID},
		{"asset_id", i.AssetID},
		{"certificate_id", i.CertificateID},
		{"crypto_implementation_id", i.CryptoImplementationID},
		{"assigned_to", i.AssignedTo},
	} {
		if err := checkUUIDRef(r.field, r.v); err != nil {
			return err
		}
	}
	return checkRFC3339("due_date", i.DueDate)
}

func (i *UpdateTicketInput) validateShape() error {
	if i.Description != nil {
		if err := checkLen("description", *i.Description, MaxTicketDescriptionLen); err != nil {
			return err
		}
	}
	if err := checkUUIDRef("assigned_to", i.AssignedTo); err != nil {
		return err
	}
	return checkRFC3339("due_date", i.DueDate)
}
