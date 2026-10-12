package audit

import (
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

// The audit log is plain text on the host; an error that is a *url.Error
// carries the request URL, credential query parameters included.
//
// Mutation: change `redact.Text(err.Error())` back to `err.Error()` and this
// fails.
func TestLogInterrogation_RedactsTheError(t *testing.T) {
	dir := t.TempDir()
	al, err := NewAuditLogger(dir)
	if err != nil {
		t.Fatal(err)
	}
	leaky := &url.Error{Op: "Get", URL: "https://fw.example/api?user=a&password=hunter2-LIVE", Err: http.ErrHandlerTimeout}
	al.LogInterrogation("job-1", "10.0.0.1", "stub", "failure", nil, leaky)
	_ = al.Close()

	data, err := os.ReadFile(al.GetPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "hunter2-LIVE") {
		t.Fatalf("audit log holds a credential: %s", data)
	}
	if !strings.Contains(string(data), "fw.example") {
		t.Fatalf("redaction removed the host too: %s", data)
	}
}
