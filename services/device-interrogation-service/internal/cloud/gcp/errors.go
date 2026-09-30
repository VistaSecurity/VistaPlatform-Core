package gcp

import (
	"errors"
	"net/http"
)

// ErrorDetail projects a GCP client error onto Google's own error code and
// message: the OAuth error of a refused token exchange, or the API's
// {"error":{"status","message"}}. ok is false for anything else.
func ErrorDetail(err error) (code, message string, status int, ok bool) {
	var tokenErr *TokenError
	if errors.As(err, &tokenErr) {
		message = tokenErr.Description
		if message == "" {
			message = http.StatusText(tokenErr.StatusCode)
		}
		return tokenErr.Code, message, tokenErr.StatusCode, true
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		message = apiErr.Message
		if message == "" {
			message = http.StatusText(apiErr.StatusCode)
		}
		return apiErr.Status, message, apiErr.StatusCode, true
	}
	return "", "", 0, false
}
