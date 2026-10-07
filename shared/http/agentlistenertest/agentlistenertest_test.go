package agentlistenertest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatMatchesRoute(t *testing.T) {
	cases := []struct {
		format, route string
		want          bool
	}{
		{"/api/v1/s/agents/%s/jobs", "/api/v1/s/agents/:id/jobs", true},
		{"/api/v1/s/agents/host-inventory", "/api/v1/s/agents/host-inventory", true},
		{"/api/v1/s/agents/host-inventory", "/api/v1/s/agents/:id", true},
		{"/api/v1/s/agents/%s/jobs", "/api/v1/s/agents/:id/results", false},
		{"/api/v1/s/agents/%s", "/api/v1/s/agents/host-inventory", false},
		{"/api/v1/s/agents/%s/jobs", "/api/v1/s/agents/:id", false},
		{"/api/v1/s/agents/%s", "/api/v1/s/agents/:id/jobs", false},
		{"/api/v1/s/files/a/b", "/api/v1/s/files/*rest", true},
		{"/api/v1/s/files", "/api/v1/s/files/*rest", false},
	}
	for _, tc := range cases {
		if got := FormatMatchesRoute(tc.format, tc.route); got != tc.want {
			t.Errorf("FormatMatchesRoute(%q, %q) = %v, want %v", tc.format, tc.route, got, tc.want)
		}
	}
}

// recTB records Errorf so the scanner's refusal can itself be tested.
type recTB struct {
	testing.TB
	errs []string
}

func (r *recTB) Helper() {}
func (r *recTB) Errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}

func writeGo(t *testing.T, dir, name, src string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestScanClientCalls(t *testing.T) {
	dir := t.TempDir()
	writeGo(t, dir, "client.go", `package c

import (
	"context"
	"fmt"
	"net/http"
)

type C struct{ baseURL, id string }

func (c *C) Heartbeat() {
	url := fmt.Sprintf("%s/api/v1/svc/agents/%s/heartbeat", c.baseURL, c.id)
	req, _ := http.NewRequest("POST", url, nil)
	_ = req
}

func (c *C) Jobs(ctx context.Context) {
	url := fmt.Sprintf("%s/api/v1/svc/agents/%s/jobs?limit=1", c.baseURL, c.id)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	_ = req
}

func (c *C) Other() {
	url := fmt.Sprintf("%s/api/v1/other-svc/x", c.baseURL)
	req, _ := http.NewRequest("GET", url, nil)
	_ = req
}
`)
	writeGo(t, dir, "client_test.go", `package c

const ignored = "/api/v1/svc/agents/test-only"
`)

	rec := &recTB{TB: t}
	calls := ScanClientCalls(rec, "/api/v1/svc/", dir)
	if len(rec.errs) != 0 {
		t.Fatalf("unexpected scanner errors: %v", rec.errs)
	}
	got := map[string]string{}
	for _, c := range calls {
		got[c.Func] = c.Method + " " + c.Format
	}
	want := map[string]string{
		"Heartbeat": "POST /api/v1/svc/agents/%s/heartbeat",
		"Jobs":      "GET /api/v1/svc/agents/%s/jobs",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("scanned %v, want %v", got, want)
	}

	// A call built some other way must be reported, not skipped.
	writeGo(t, dir, "odd.go", `package c

import "net/http"

func (c *C) Odd() {
	req, _ := http.NewRequest("POST", c.baseURL+"/api/v1/svc/agents/odd", nil)
	_ = req
}
`)
	rec = &recTB{TB: t}
	_ = ScanClientCalls(rec, "/api/v1/svc/", dir)
	if len(rec.errs) != 1 || !strings.Contains(rec.errs[0], "odd.go") {
		t.Fatalf("an unrecognised construction was not reported: %v", rec.errs)
	}
}
