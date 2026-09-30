package gcp

import (
	"errors"
	"net/http"
	"testing"
)

func TestErrorDetail_TokenError(t *testing.T) {
	err := &TokenError{
		StatusCode:  http.StatusUnauthorized,
		Code:        "invalid_grant",
		Description: "Invalid JWT Signature.",
	}

	code, message, status, ok := ErrorDetail(err)
	if !ok {
		t.Fatal("TokenError was not recognized")
	}
	if code != "invalid_grant" {
		t.Errorf("code = %q, want invalid_grant", code)
	}
	if message != "Invalid JWT Signature." {
		t.Errorf("message = %q", message)
	}
	if status != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", status, http.StatusUnauthorized)
	}
}

func TestErrorDetail_TokenErrorFallsBackToHTTPStatusText(t *testing.T) {
	err := &TokenError{StatusCode: http.StatusUnauthorized, Code: "invalid_client"}

	code, message, status, ok := ErrorDetail(err)
	if !ok {
		t.Fatal("TokenError was not recognized")
	}
	if code != "invalid_client" {
		t.Errorf("code = %q, want invalid_client", code)
	}
	if message != http.StatusText(http.StatusUnauthorized) {
		t.Errorf("message = %q, want HTTP status text", message)
	}
	if status != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", status, http.StatusUnauthorized)
	}
}

func TestErrorDetail_APIError(t *testing.T) {
	err := &APIError{
		StatusCode: http.StatusForbidden,
		Status:     "PERMISSION_DENIED",
		Message:    "Permission denied on resource project/example.",
	}

	code, message, status, ok := ErrorDetail(err)
	if !ok {
		t.Fatal("APIError was not recognized")
	}
	if code != "PERMISSION_DENIED" {
		t.Errorf("code = %q, want PERMISSION_DENIED", code)
	}
	if message != "Permission denied on resource project/example." {
		t.Errorf("message = %q", message)
	}
	if status != http.StatusForbidden {
		t.Errorf("status = %d, want %d", status, http.StatusForbidden)
	}
}

func TestErrorDetail_APIErrorFallsBackToHTTPStatusText(t *testing.T) {
	err := &APIError{StatusCode: http.StatusTooManyRequests, Status: "RESOURCE_EXHAUSTED"}

	code, message, status, ok := ErrorDetail(err)
	if !ok {
		t.Fatal("APIError was not recognized")
	}
	if code != "RESOURCE_EXHAUSTED" {
		t.Errorf("code = %q, want RESOURCE_EXHAUSTED", code)
	}
	if message != http.StatusText(http.StatusTooManyRequests) {
		t.Errorf("message = %q, want HTTP status text", message)
	}
	if status != http.StatusTooManyRequests {
		t.Errorf("status = %d, want %d", status, http.StatusTooManyRequests)
	}
}

func TestErrorDetail_UnknownError(t *testing.T) {
	if code, message, status, ok := ErrorDetail(errors.New("dial tcp: no such host")); ok || code != "" || message != "" || status != 0 {
		t.Fatalf("plain error projected as GCP detail: code=%q message=%q status=%d ok=%v", code, message, status, ok)
	}
}
