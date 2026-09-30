package handlers

// Platform integrations of type slack / pagerduty / datadog / splunk were
// dispatched by nothing, and their "test" only checked that a credential field
// was non-empty before reporting "Connection successful". The API now refuses to
// create or edit one (400, pointing at the notification channels / SIEM export
// page), and testing a row that already exists says so instead of lying.
//
// Create / update are refused before any database access, so those tests run
// with no database at all: reaching the DB with a nil handle would panic, which
// makes "the guard is missing" fail loudly rather than pass quietly. The test
// path has to load the row first, so it runs against the shared test database
// (skips without TEST_DATABASE_URL).

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const retiredTypesITMasterKey = "integration-test-master-key-32byt"

// integrationsTestRouter mounts the real handlers behind a stand-in for the auth
// middleware that only sets the user id the handlers read.
func integrationsTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	as := func(h gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			c.Set("userID", uuid.NewString())
			h(c)
		}
	}
	r.POST("/integrations", as(CreateIntegration()))
	r.PUT("/integrations/:id", as(UpdateIntegration()))
	r.POST("/integrations/:id/test", as(TestIntegration()))
	return r
}

func retiredTypesDo(r http.Handler, method, path string, body interface{}) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func retiredBody(typ string) map[string]interface{} {
	return map[string]interface{}{
		"integration_type": typ,
		"integration_name": "legacy " + typ,
		"provider":         "saas",
		"config":           map[string]interface{}{"api_key": "k", "webhook_url": "https://example.invalid/x"},
	}
}

func TestIntegrations_CreateAndUpdateRefuseRetiredTypes(t *testing.T) {
	// A nil service would panic on any DB access; the guard must answer first.
	InitializeIntegrationService(nil, nil, retiredTypesITMasterKey, logrus.New())
	r := integrationsTestRouter()

	cases := map[string]string{
		"slack":     "notification channels",
		"pagerduty": "notification channels",
		"datadog":   "SIEM export",
		"splunk":    "SIEM export",
	}
	for typ, pointer := range cases {
		for _, call := range []struct{ method, path string }{
			{http.MethodPost, "/integrations"},
			{http.MethodPut, "/integrations/" + uuid.NewString()},
		} {
			w := retiredTypesDo(r, call.method, call.path, retiredBody(typ))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("%s %s type=%s: status %d, want 400 (body %s)", call.method, call.path, typ, w.Code, w.Body.String())
			}
			var resp map[string]interface{}
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			msg, _ := resp["error"].(string)
			if !strings.Contains(msg, pointer) {
				t.Errorf("%s %s type=%s: error %q does not point at %q", call.method, call.path, typ, msg, pointer)
			}
			if resp["integration_type"] != typ {
				t.Errorf("%s %s type=%s: response does not name the type: %v", call.method, call.path, typ, resp)
			}
		}
	}
}

func TestIntegration_TestRefusesRetiredTypeAndRecordsNothing(t *testing.T) {
	db := testdb.Connect(t)
	InitializeIntegrationService(db, db, retiredTypesITMasterKey, logrus.New())
	r := integrationsTestRouter()

	for _, typ := range []string{"slack", "pagerduty", "datadog", "splunk"} {
		var id uuid.UUID
		err := db.QueryRowContext(context.Background(), `
			INSERT INTO platform_integrations (integration_type, integration_name, provider, config, status)
			VALUES ($1, $2, 'saas', '{}'::jsonb, 'configured')
			RETURNING id`, typ, "retired-type-test-"+uuid.NewString()).Scan(&id)
		if err != nil {
			t.Fatalf("insert %s row: %v", typ, err)
		}
		t.Cleanup(func() {
			_, _ = db.Exec(`DELETE FROM platform_integrations WHERE id = $1`, id)
		})

		w := retiredTypesDo(r, http.MethodPost, "/integrations/"+id.String()+"/test", nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: test status %d, want 400 (body %s)", typ, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "Connection successful") {
			t.Fatalf("%s: a retired type must never report a successful connection: %s", typ, w.Body.String())
		}

		// It must not stamp a successful test onto the row either.
		var lastOK, lastTested *string
		if err := db.QueryRow(`SELECT last_successful_connection_at::text, last_tested_at::text
			FROM platform_integrations WHERE id = $1`, id).Scan(&lastOK, &lastTested); err != nil {
			t.Fatalf("%s: read back: %v", typ, err)
		}
		if lastOK != nil || lastTested != nil {
			t.Errorf("%s: row was stamped tested (last_tested_at=%v last_successful_connection_at=%v)", typ, lastTested, lastOK)
		}
	}
}
