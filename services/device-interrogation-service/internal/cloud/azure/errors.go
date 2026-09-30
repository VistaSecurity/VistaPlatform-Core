package azure

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// ErrorDetail projects an Azure SDK error onto the provider's own error code
// and message: Microsoft Entra ID's OAuth error for a refused token, Azure
// Resource Manager's {"error":{"code","message"}} for a refused call. ok is
// false for anything else (a network error, a context deadline).
//
// The SDK's own Error() strings are multi-line dumps of the request and the
// whole response; this is the part a person can act on. Callers still
// sanitise and bound what they show.
func ErrorDetail(err error) (code, message string, status int, ok bool) {
	var authErr *azidentity.AuthenticationFailedError
	if errors.As(err, &authErr) {
		code = "authentication_failed"
		if authErr.RawResponse != nil {
			status = authErr.RawResponse.StatusCode
			if body, perr := runtime.Payload(authErr.RawResponse); perr == nil {
				var parsed struct {
					Error            string `json:"error"`
					ErrorDescription string `json:"error_description"`
				}
				if json.Unmarshal(body, &parsed) == nil {
					if parsed.Error != "" {
						code = parsed.Error
					}
					message = firstLine(parsed.ErrorDescription)
				}
			}
		}
		return code, message, status, true
	}
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		code, status = respErr.ErrorCode, respErr.StatusCode
		if respErr.RawResponse != nil {
			if body, perr := runtime.Payload(respErr.RawResponse); perr == nil {
				var parsed struct {
					Error struct {
						Code    string `json:"code"`
						Message string `json:"message"`
					} `json:"error"`
				}
				if json.Unmarshal(body, &parsed) == nil {
					if code == "" {
						code = parsed.Error.Code
					}
					message = parsed.Error.Message
				}
			}
		}
		if message == "" {
			message = http.StatusText(status)
		}
		return code, message, status, true
	}
	return "", "", 0, false
}

// firstLine keeps the first line of an AADSTS description; the rest is trace
// and correlation ids nobody acts on.
func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
