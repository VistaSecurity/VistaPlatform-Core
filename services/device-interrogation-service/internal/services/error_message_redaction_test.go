package services

import (
	"context"
	"database/sql/driver"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/redact"
)

// What lands in device_jobs.error_message, asserted on the BOUND PARAMETER of
// the real UPDATE rather than on the redactor in isolation.
//
// That distinction is the point. A redactor tested by itself proves only that
// the function works; it says nothing about whether the write goes through it.
// This drives JobQueueService.UpdateJobStatus — the one choke point every
// executor reaches — and reads the value the driver was handed. Delete the
// redactedErrorMessage call at the top of that function and this goes red.
func TestUpdateJobStatus_RedactsWhatLandsInErrorMessage(t *testing.T) {
	const liveKey = "LUFRPT1LIVE-PAN-OS-API-KEY"

	// The real shape of the leak: Go stringifies a transport failure as a
	// *url.Error carrying the whole request URL.
	transportErr := (&url.Error{
		Op:  "Get",
		URL: "https://firewall.example/api/?type=op&cmd=%3Cshow%3E&key=" + liveKey,
		Err: http.ErrHandlerTimeout,
	}).Error()
	if !strings.Contains(transportErr, liveKey) {
		t.Fatalf("fixture no longer carries the key (%q); the premise of this test is gone", transportErr)
	}

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	var bound []driver.Value
	mock.ExpectExec(`UPDATE device_jobs`).
		WithArgs(capture{&bound}, capture{&bound}, capture{&bound}, capture{&bound}, capture{&bound}).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// recordScheduleOutcome runs afterwards on the same handle and is non-fatal;
	// whatever it asks for may go unmatched without affecting the assertion.
	mock.MatchExpectationsInOrder(false)

	svc := NewJobQueueService(db, db, nil)
	if err := svc.UpdateJobStatus(context.Background(), uuid.New(), models.JobStatusFailed, nil, &transportErr); err != nil {
		t.Fatalf("UpdateJobStatus: %v", err)
	}

	stored := ""
	for _, v := range bound {
		if s, ok := v.(string); ok && strings.Contains(s, "firewall.example") {
			stored = s
		}
	}
	if stored == "" {
		t.Fatalf("the UPDATE did not bind the error message; bound = %v", bound)
	}
	if strings.Contains(stored, liveKey) {
		t.Fatalf("device_jobs.error_message would store a LIVE PAN-OS API key: %q", stored)
	}
	if !strings.Contains(stored, redact.Marker) {
		t.Fatalf("error_message = %q; want the %s marker, so a reader can see the backstop fired "+
			"rather than wondering where the URL went", stored, redact.Marker)
	}
	// The diagnostic value must survive: an operator still has to be able to
	// tell which device stopped answering. Over-redaction is the same bug
	// pointed the other way.
	if !strings.Contains(stored, "firewall.example") || !strings.Contains(stored, "type=op") {
		t.Fatalf("error_message = %q; the host and the operation must survive redaction", stored)
	}
}

// A nil error message must stay nil: SQL NULL means "no failure recorded", and
// an empty string on a completed job is a different claim.
func TestUpdateJobStatus_NilErrorMessageStaysNull(t *testing.T) {
	if got := redactedErrorMessage(nil); got != nil {
		t.Fatalf("redactedErrorMessage(nil) = %q, want nil", *got)
	}
}

// capture records the value sqlmock was handed and matches everything.
type capture struct{ into *[]driver.Value }

func (c capture) Match(v driver.Value) bool {
	*c.into = append(*c.into, v)
	return true
}
