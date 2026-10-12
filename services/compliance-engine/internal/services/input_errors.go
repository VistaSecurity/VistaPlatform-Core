package services

import (
	"errors"
	"fmt"
)

// InputError is a refusal of the caller's input, as opposed to a failure of the
// service. Handlers map it to a 4xx; anything else that comes back is a 500.
//
// Missing separates the two ways input can be wrong. A value that is malformed
// or out of range (Missing=false) is a 400. A well-formed reference to a row
// that does not exist in the caller's tenant (Missing=true) is a 422: the
// request parsed, but names something the tenant does not have. The tenant
// boundary is deliberately not distinguishable from "no such row", so a UUID
// belonging to another tenant answers exactly like one that never existed.
type InputError struct {
	Field   string
	Message string
	Missing bool
}

func (e *InputError) Error() string {
	if e.Field == "" {
		return e.Message
	}
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// AsInputError reports whether err is (or wraps) an InputError.
func AsInputError(err error) (*InputError, bool) {
	var ie *InputError
	if errors.As(err, &ie) {
		return ie, true
	}
	return nil, false
}

func invalidInput(field, format string, args ...any) *InputError {
	return &InputError{Field: field, Message: fmt.Sprintf(format, args...)}
}

func missingReference(field string) *InputError {
	return &InputError{Field: field, Message: "does not exist in this tenant", Missing: true}
}

// MaxSuppressionReasonLen bounds the free-text reason on a suppression.
const MaxSuppressionReasonLen = 2000
