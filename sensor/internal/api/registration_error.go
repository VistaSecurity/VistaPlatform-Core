package api

import "net/http"

// RegistrationRejectedError means the control plane understood the registration
// request and refused it — a consumed or unknown key, a duplicate sensor id, a
// profile the platform will not accept.
//
// The distinction from an ordinary error is the whole point: a sensor should
// survive the control plane being down (retry until it comes back), but must
// NOT sit in a retry loop against a rejection that will be identical forever.
// Only a human with a fresh registration key can resolve one of these.
type RegistrationRejectedError struct {
	StatusCode int
	Body       string
	err        error
}

func (e *RegistrationRejectedError) Error() string { return e.err.Error() }
func (e *RegistrationRejectedError) Unwrap() error { return e.err }

// IsPermanentRegistrationStatus reports whether an HTTP status means retrying
// is pointless.
//
// 4xx is the client's fault and will not change on its own — except the three
// that explicitly mean "not now, try again": 408 Request Timeout, 425 Too Early
// and 429 Too Many Requests. Treating those as permanent would turn a
// rate-limited restart storm into a fleet of sensors that permanently gave up.
func IsPermanentRegistrationStatus(status int) bool {
	if status < 400 || status >= 500 {
		return false
	}
	switch status {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests:
		return false
	default:
		return true
	}
}
