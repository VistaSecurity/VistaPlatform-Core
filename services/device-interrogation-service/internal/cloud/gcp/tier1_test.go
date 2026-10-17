package gcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A Cloud Function's listing carries its environment variable VALUES; the
// projection keeps the names and nothing else (collect posture, never key
// material). MUTATION: decode the map into the struct as a value map and
// marshal it — the planted value appears and this goes red.
func TestListCloudFunctions_ProjectsEnvironmentNamesOnly(t *testing.T) {
	const planted = "PlantedGCPEnvValue-1199"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"functions": []any{map[string]any{
			"name":        "projects/p1/locations/europe-west4/functions/fn1",
			"state":       "ACTIVE",
			"buildConfig": map[string]any{"runtime": "go122", "entryPoint": "Handle"},
			"serviceConfig": map[string]any{
				"availableMemory": "512M", "serviceAccountEmail": "runner@p1.iam.gserviceaccount.com",
				"environmentVariables": map[string]string{"API_TOKEN": planted},
			},
		}}})
	}))
	t.Cleanup(srv.Close)
	c := &Client{projectID: "p1", httpClient: srv.Client(), apiBaseOverride: srv.URL, accessToken: "tok"}
	c.tokenExpiry = time.Now().Add(time.Hour)

	fns, err := c.ListCloudFunctions(context.Background())
	if err != nil || len(fns) != 1 {
		t.Fatalf("ListCloudFunctions = %+v, %v", fns, err)
	}
	f := fns[0]
	if f.Region != "europe-west4" || f.MemoryMB != 512 || f.EntryPoint != "Handle" || len(f.EnvironmentVarKeys) != 1 || f.EnvironmentVarKeys[0] != "API_TOKEN" {
		t.Errorf("projection = %+v", f)
	}
	b, _ := json.Marshal(fns)
	if strings.Contains(string(b), planted) {
		t.Fatal("the environment variable VALUE survived the projection")
	}
}
