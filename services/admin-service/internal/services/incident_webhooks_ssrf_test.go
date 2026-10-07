package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// Incident webhooks post to a stored, person-supplied URL. They must never
// reach loopback, the cloud metadata address or the platform's own network,
// whether the URL is rejected up front or the connection is refused at dial.

func incidentWebhookRows(url string) *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "name", "url", "secret", "events", "enabled", "headers",
		"timeout_seconds", "retry_attempts", "retry_backoff_ms", "created_at", "updated_at",
	}).AddRow(uuid.New(), "hook", url, "", []byte(`["incident.created"]`), true, []byte(`{}`),
		nil, 1, 1, time.Now(), time.Now())
}

// TestDeliverIncidentWebhook_RefusesInternalTargets drives the real entry point
// (config lookup, send, delivery record) and requires the receiver to see
// nothing and the failure to be recorded.
func TestDeliverIncidentWebhook_RefusesInternalTargets(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	for _, target := range []string{
		srv.URL, // http://127.0.0.1:<port>
		"http://169.254.169.254/latest/meta-data/",
		"http://[fd00:ec2::254]/latest/meta-data/",
	} {
		t.Run(target, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			svc, err := NewIncidentWebhookService(db, "")
			if err != nil {
				t.Fatal(err)
			}
			mock.ExpectQuery("FROM security_incident_webhooks").WillReturnRows(incidentWebhookRows(target))
			mock.ExpectExec("INSERT INTO security_incident_webhook_deliveries").
				WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), "failed", nil, nil,
					sqlmock.AnyArg(), 0, nil).
				WillReturnResult(sqlmock.NewResult(1, 1))

			if err := svc.DeliverIncidentWebhook(context.Background(), uuid.New(), "incident.created", map[string]string{"k": "v"}); err != nil {
				t.Fatalf("DeliverIncidentWebhook: %v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("the refused delivery was not recorded as failed: %v", err)
			}
		})
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("loopback receiver saw %d request(s)", got)
	}
}

// TestIncidentWebhookClient_RefusesLoopbackAtDial pins the connect-time guard
// itself, independent of the up-front URL check: a name that validates and then
// resolves internal (rebinding) or a redirect into an internal address reaches
// only the client.
func TestIncidentWebhookClient_RefusesLoopbackAtDial(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	// Control: the server is reachable by an unguarded client.
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	_ = resp.Body.Close()
	atomic.StoreInt32(&hits, 0)

	svc, err := NewIncidentWebhookService(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.httpClient.Post(srv.URL, "application/json", strings.NewReader("{}")); err == nil {
		t.Fatal("the incident webhook client connected to a loopback server")
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("loopback receiver saw %d request(s)", got)
	}
}
