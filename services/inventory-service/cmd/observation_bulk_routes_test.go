package main

// main.go must mount the bulk observation decision through
// observationBulkChain — the chain observation_bulk_routes_integration_test.go
// drives against a real database. A registration naming the bare handler would
// compile, pass every handler test, and let any authenticated tenant user
// confirm or dismiss two hundred observations at once.

import (
	"net/http"
	"strings"
	"testing"
)

func TestObservationBulkRouteIsMountedThroughTheGatedChain(t *testing.T) {
	for _, args := range registrationsOf(t, http.MethodPost, "/inventory-service/discovery/observations/bulk") {
		if !strings.Contains(args, "observationBulkChain(rawDB,") {
			t.Errorf("POST /discovery/observations/bulk is not mounted through observationBulkChain:\n%s", args)
		}
	}
}
