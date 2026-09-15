package deviceinterrogation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The REST clients decoded straight from resp.Body into a json.Decoder, so the
// size of what reached our heap was the DEVICE's to choose. The Cisco collector
// has read its command output through a bound since this workstream; these two
// had none, and `ltm/pool?expandSubcollections=true` and
// `monitor/router/ipv4` are the largest responses either asks for.
//
// The bound errors rather than truncating, unlike Cisco's. A truncated CLI
// table is still a table and Cisco keeps the rows it read; a truncated JSON
// document is either a syntax error or — worse — a prefix that happens to
// parse, which would be a partial inventory presented as a complete one.
func TestBoundedBody_RefusesAnOversizeResponse(t *testing.T) {
	// Exactly at the bound is not a truncation.
	atLimit := strings.Repeat("x", maxAPIResponseBytes)
	if _, err := readBoundedBody(strings.NewReader(atLimit), "test"); err != nil {
		t.Errorf("a body exactly at the bound was rejected: %v", err)
	}

	over := strings.Repeat("x", maxAPIResponseBytes+1)
	body, err := readBoundedBody(strings.NewReader(over), "test")
	if err == nil {
		t.Fatalf("a body over the bound was accepted, returning %d bytes", len(body))
	}
	if !strings.Contains(err.Error(), "response bound") {
		t.Errorf("error does not say what happened: %v", err)
	}
	if body != nil {
		t.Errorf("a partial body was returned alongside the error: %d bytes", len(body))
	}

	// Inverse polarity: an ordinary document still decodes.
	var out struct {
		Name string `json:"name"`
	}
	if err := decodeBoundedJSON(strings.NewReader(`{"name":"port1"}`), "test", &out); err != nil {
		t.Fatalf("an ordinary document was rejected: %v", err)
	}
	if out.Name != "port1" {
		t.Errorf("decoded %+v", out)
	}
}

// Both clients must FAIL on an oversize response rather than return a prefix.
// A collector that decodes half a pool collection reports half a dependency
// graph and says nothing.
func TestF5AndFortinetClients_FailOnAnOversizeResponse(t *testing.T) {
	// A JSON array that never ends: valid-looking, and larger than the bound.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/mgmt/shared/authn/login") {
			_, _ = w.Write([]byte(`{"token":{"token":"FAKE-TOKEN"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"items":[`))
		filler := strings.Repeat(`{"name":"padding-entry-to-run-past-the-bound"},`, 4096)
		for written := 0; written < maxAPIResponseBytes+len(filler); written += len(filler) {
			if _, err := w.Write([]byte(filler)); err != nil {
				return
			}
		}
		_, _ = w.Write([]byte(`{"name":"last"}]}`))
	}))
	defer srv.Close()

	t.Run("f5", func(t *testing.T) {
		c := newF5Client(srv.URL, "admin", "admin", "", true)
		if _, err := f5GetCollection[f5Pool](context.Background(), c, "/mgmt/tm/ltm/pool"); err == nil {
			t.Error("an unbounded pool collection was decoded without complaint")
		} else if !strings.Contains(err.Error(), "response bound") {
			t.Errorf("failed for the wrong reason: %v", err)
		}
	})

	t.Run("fortinet", func(t *testing.T) {
		c := newFortinetClient(srv.URL, "admin", "admin", true)
		if _, err := c.getMonitorResults(context.Background(), "/api/v2/monitor/router/ipv4"); err == nil {
			t.Error("an unbounded routing table was decoded without complaint")
		} else if !strings.Contains(err.Error(), "response bound") {
			t.Errorf("failed for the wrong reason: %v", err)
		}
		if _, err := c.getResults(context.Background(), "/api/v2/cmdb/system/interface"); err == nil {
			t.Error("an unbounded cmdb collection was decoded without complaint")
		}
	})
}
