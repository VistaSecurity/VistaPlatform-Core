package handlers

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The relationship routes deliberately follow the inventory house policy:
// reads are protected by the JWT/RLS group, while declarations and approval
// decisions are writes and therefore require assets.update.
//
// Handler contract tests stay green if cmd/main.go drops or adds one of these
// wrappers, so this pins the routing table itself, following the same source
// scan pattern used for the integrations gate.
func TestRelationshipRoutesKeepTheirReadWriteGates(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "cmd", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}

	route := regexp.MustCompile(`(?m)^\s*(?:api|apiv2)\.(GET|POST|DELETE)\("([^"]+)",\s*(.*relationshipHandler\.(ListAssetRelationships|GetNeighbourhood|GetImpact|ListRelationshipProposals|CreateAssetRelationship|DeleteAssetRelationship|AcceptRelationshipProposal|RejectRelationshipProposal)\).*)$`)
	matches := route.FindAllStringSubmatch(string(src), -1)
	if len(matches) != 16 {
		t.Fatalf("expected 16 relationship routes (v1 and v2 reads, writes, and proposal decisions), found %d: %v", len(matches), matches)
	}

	wantReads := map[string]int{
		"ListAssetRelationships":    2,
		"GetNeighbourhood":          2,
		"GetImpact":                 2,
		"ListRelationshipProposals": 2,
	}
	wantWrites := map[string]int{
		"CreateAssetRelationship":    2,
		"DeleteAssetRelationship":    2,
		"AcceptRelationshipProposal": 2,
		"RejectRelationshipProposal": 2,
	}
	gotReads := map[string]int{}
	gotWrites := map[string]int{}

	for _, m := range matches {
		method, path, args, handler := m[1], m[2], m[3], m[4]
		line := strings.TrimSpace(m[0])
		if _, ok := wantReads[handler]; ok {
			gotReads[handler]++
			if method != "GET" {
				t.Errorf("%s is registered as %s, want GET: %s", handler, method, line)
			}
			if strings.Contains(args, "RequireTenantPermission") {
				t.Errorf("GET %s reaches %s with a tenant-permission gate; relationship reads are JWT/RLS-scoped: %s", path, handler, line)
			}
			continue
		}

		if _, ok := wantWrites[handler]; ok {
			gotWrites[handler]++
			if method != "POST" && method != "DELETE" {
				t.Errorf("%s is registered as %s, want POST or DELETE: %s", handler, method, line)
			}
			if !strings.Contains(args, "RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate)") {
				t.Errorf("%s %s reaches %s without the assets.update gate: %s", method, path, handler, line)
			}
			continue
		}

		t.Errorf("unexpected relationship handler in route scan: %s", line)
	}

	for handler, want := range wantReads {
		if gotReads[handler] != want {
			t.Errorf("read handler %s registered %d times, want %d", handler, gotReads[handler], want)
		}
	}
	for handler, want := range wantWrites {
		if gotWrites[handler] != want {
			t.Errorf("write handler %s registered %d times, want %d", handler, gotWrites[handler], want)
		}
	}
}
