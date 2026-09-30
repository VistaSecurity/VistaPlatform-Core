package azure

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

func azureErrorResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

func TestErrorDetail_AuthenticationFailedUsesOAuthError(t *testing.T) {
	err := &azidentity.AuthenticationFailedError{
		RawResponse: azureErrorResponse(http.StatusUnauthorized, `{
			"error": "invalid_client",
			"error_description": "client secret is invalid\nTrace ID: should-not-survive"
		}`),
	}

	code, message, status, ok := ErrorDetail(err)
	if !ok {
		t.Fatal("AuthenticationFailedError was not recognized")
	}
	if code != "invalid_client" {
		t.Errorf("code = %q, want invalid_client", code)
	}
	if message != "client secret is invalid" {
		t.Errorf("message = %q, want first actionable line only", message)
	}
	if strings.Contains(message, "Trace ID") {
		t.Errorf("trace metadata survived in message: %q", message)
	}
	if status != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", status, http.StatusUnauthorized)
	}
}

func TestErrorDetail_AuthenticationFailedWithoutBodyUsesDefaultCode(t *testing.T) {
	code, message, status, ok := ErrorDetail(&azidentity.AuthenticationFailedError{})
	if !ok {
		t.Fatal("AuthenticationFailedError was not recognized")
	}
	if code != "authentication_failed" {
		t.Errorf("code = %q, want authentication_failed", code)
	}
	if message != "" {
		t.Errorf("message = %q, want empty message when Azure provided none", message)
	}
	if status != 0 {
		t.Errorf("status = %d, want 0 when no response is attached", status)
	}
}

func TestErrorDetail_ResponseErrorUsesARMErrorBody(t *testing.T) {
	err := &azcore.ResponseError{
		StatusCode: http.StatusForbidden,
		RawResponse: azureErrorResponse(http.StatusForbidden, `{
			"error": {
				"code": "AuthorizationFailed",
				"message": "caller does not have authorization to perform Microsoft.Compute/virtualMachines/read"
			}
		}`),
	}

	code, message, status, ok := ErrorDetail(err)
	if !ok {
		t.Fatal("ResponseError was not recognized")
	}
	if code != "AuthorizationFailed" {
		t.Errorf("code = %q, want AuthorizationFailed", code)
	}
	if message != "caller does not have authorization to perform Microsoft.Compute/virtualMachines/read" {
		t.Errorf("message = %q", message)
	}
	if status != http.StatusForbidden {
		t.Errorf("status = %d, want %d", status, http.StatusForbidden)
	}
}

func TestErrorDetail_ResponseErrorFallsBackToHTTPStatusText(t *testing.T) {
	err := &azcore.ResponseError{
		ErrorCode:   "TooManyRequests",
		StatusCode:  http.StatusTooManyRequests,
		RawResponse: azureErrorResponse(http.StatusTooManyRequests, `{}`),
	}

	code, message, status, ok := ErrorDetail(err)
	if !ok {
		t.Fatal("ResponseError was not recognized")
	}
	if code != "TooManyRequests" {
		t.Errorf("code = %q, want TooManyRequests", code)
	}
	if message != http.StatusText(http.StatusTooManyRequests) {
		t.Errorf("message = %q, want HTTP status text", message)
	}
	if status != http.StatusTooManyRequests {
		t.Errorf("status = %d, want %d", status, http.StatusTooManyRequests)
	}
}

func TestErrorDetail_UnknownError(t *testing.T) {
	if code, message, status, ok := ErrorDetail(errors.New("dial tcp: connection refused")); ok || code != "" || message != "" || status != 0 {
		t.Fatalf("plain error projected as Azure detail: code=%q message=%q status=%d ok=%v", code, message, status, ok)
	}
}
