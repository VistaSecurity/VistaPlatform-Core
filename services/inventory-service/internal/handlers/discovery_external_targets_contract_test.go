package handlers

// POST /discovery/jobs, explicit external targets ( W5.13b), against the
// spec.
//
// This proxy is the route the browser calls. Two things must survive it
// unchanged or the feature is unreachable from the UI while every backend test
// stays green: the person's `external_targets_confirmed` flag on the way in,
// and cluster-sensor-service's target verdict — its code and its target lists
// — on the way out. The generic 4xx relay this proxy already had flattened
// every refusal into {"error":"validation_error"}, which would leave the
// confirmation dialog with nothing to list and nothing to branch on.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const externalJobBody = `{"targets":["93.184.216.34","https://www.example.com/"],"protocols":["TLS"],"ports":[443],"execution_mode":"auto"`

func TestContract_CreateDiscoveryJob_ForwardsTheConfirmation(t *testing.T) {
	sv := loadSpec(t)
	for _, confirmed := range []bool{false, true} {
		body := externalJobBody + `}`
		if confirmed {
			body = externalJobBody + `,"external_targets_confirmed":true}`
		}
		// The request the UI sends must be one the spec accepts:
		// CreateDiscoveryJobRequest is additionalProperties:false.
		sv.assertConforms(t, "CreateDiscoveryJobRequest", []byte(body))

		var forwarded map[string]interface{}
		engine, srv := newProxyEngine(t, func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&forwarded)
			w.WriteHeader(http.StatusInternalServerError)
		})
		postThrough(engine, body)
		srv.Close()
		if got, _ := forwarded["external_targets_confirmed"].(bool); got != confirmed {
			t.Fatalf("confirmed=%v: forwarded external_targets_confirmed=%v (%v)", confirmed, forwarded["external_targets_confirmed"], forwarded)
		}
	}
}

func TestContract_CreateDiscoveryJob_TargetVerdictsPassThrough(t *testing.T) {
	sv := loadSpec(t)
	for _, tc := range []struct {
		status int
		body   string
		code   string
		list   string
	}{
		{http.StatusUnprocessableEntity,
			`{"error":"external_targets_unconfirmed","message":"2 scan target(s) are outside your registered networks","external_targets":[{"target":"93.184.216.34","addresses":["93.184.216.34"]},{"target":"https://www.example.com/","addresses":["93.184.216.34"]}]}`,
			"external_targets_unconfirmed", "external_targets"},
		{http.StatusForbidden,
			`{"error":"external_targets_disabled","message":"the operator has turned it off","external_targets":[{"target":"93.184.216.34","addresses":["93.184.216.34"]}]}`,
			"external_targets_disabled", "external_targets"},
		{http.StatusBadRequest,
			`{"error":"targets_refused","message":"refused","refused_targets":[{"target":"169.254.169.254","reason":"link-local addresses include the cloud instance-metadata service (169.254.169.254)"}]}`,
			"targets_refused", "refused_targets"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			engine, srv := newProxyEngine(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			defer srv.Close()
			w := postThrough(engine, externalJobBody+`}`)
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tc.status, w.Body.String())
			}
			sv.assertConforms(t, "DiscoveryTargetVerdictError", w.Body.Bytes())
			var got map[string]interface{}
			_ = json.Unmarshal(w.Body.Bytes(), &got)
			if got["error"] != tc.code {
				t.Fatalf("error = %v, want the code %q passed through (not validation_error)", got["error"], tc.code)
			}
			if items, _ := got[tc.list].([]interface{}); len(items) == 0 {
				t.Fatalf("%s did not survive the proxy: %s", tc.list, w.Body.String())
			}
		})
	}
}

func TestContract_CreateDiscoveryJob_CreatedJobCarriesItsExternalTargets(t *testing.T) {
	sv := loadSpec(t)
	engine, srv := newProxyEngine(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"job":{"id":"6f1c2b9e-4d3a-4b8e-9c1d-2e3f4a5b6c7d","tenant_id":"t","status":"queued","execution_mode":"auto","created_at":"2026-09-24T12:00:00Z","updated_at":"2026-09-24T12:00:00Z","external_targets":[{"target":"https://www.example.com/","addresses":["93.184.216.34"]}]}}`))
	})
	defer srv.Close()
	w := postThrough(engine, externalJobBody+`,"external_targets_confirmed":true}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "DiscoveryJobResponse", w.Body.Bytes())
	if !strings.Contains(w.Body.String(), `"addresses":["93.184.216.34"]`) {
		t.Fatalf("created job lost its external targets: %s", w.Body.String())
	}
}
