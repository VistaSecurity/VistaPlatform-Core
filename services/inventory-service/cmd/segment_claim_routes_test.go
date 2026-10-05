package main

// main.go must mount both claim routes through segmentClaimChain — the chain
// segment_claim_routes_integration_test.go drives against a real database. A
// registration that named the bare handler would compile, pass every handler
// test, and let any authenticated tenant user make a public range scannable.

import (
	"net/http"
	"strings"
	"testing"
)

func TestSegmentClaimRoutesAreMountedThroughTheGatedChain(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		for _, args := range registrationsOf(t, method, "/inventory-service/network-segments/:id/claim") {
			if !strings.Contains(args, "segmentClaimChain(rawDB,") {
				t.Errorf("%s /network-segments/:id/claim is not mounted through segmentClaimChain:\n%s", method, args)
			}
		}
	}
}
