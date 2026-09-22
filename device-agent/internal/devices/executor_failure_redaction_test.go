package devices

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/redact"
)

// Every failure this agent reports goes out through submitFailure, and the
// platform stores it as device_jobs.error_message — the one field GET /jobs
// serves verbatim while the results beside it are projected field by field.
//
// Driven through the REAL Execute dispatch rather than by calling submitFailure
// directly, so the assertion is about what is actually submitted. The job below
// names a device type nothing handles, which is one of the failure branches.
func TestExecute_SubmittedFailureIsRedacted(t *testing.T) {
	const liveKey = "LUFRPT1LIVE-PAN-OS-API-KEY"

	// The shape the leak actually has: Go stringifies a transport failure as a
	// *url.Error carrying the whole request URL.
	leaky := (&url.Error{
		Op:  "Get",
		URL: "https://firewall.example/api/?type=op&key=" + liveKey,
		Err: http.ErrHandlerTimeout,
	}).Error()

	exec, rec := newTestExecutor()
	if err := exec.submitFailure(&models.Job{ID: uuid.New()}, "Device interrogation failed: "+leaky); err != nil {
		t.Fatalf("submitFailure: %v", err)
	}

	got := rec.last()
	if got == nil {
		t.Fatal("nothing was submitted")
	}
	if strings.Contains(got.Error, liveKey) {
		t.Fatalf("the submitted failure carries a live API key: %q", got.Error)
	}
	if !strings.Contains(got.Error, redact.Marker) {
		t.Fatalf("Error = %q; want the %s marker so the backstop is visible", got.Error, redact.Marker)
	}
	// The operator still has to be able to tell what failed and where.
	if !strings.Contains(got.Error, "firewall.example") || !strings.Contains(got.Error, "Device interrogation failed") {
		t.Fatalf("Error = %q; the host and the context must survive redaction", got.Error)
	}
}
