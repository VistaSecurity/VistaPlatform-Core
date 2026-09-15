package handlers

// The ask endpoint is gated on `assets.read`, and this file holds the gate in
// both halves — the middleware really refusing, and cmd/main.go really
// installing it — because either one alone is satisfiable while the hole is
// open.
//
// Why a gate at all, when the inventory LIST beside it carries none: reads on
// that group are JWT- and tenant-scoped by house policy, and this route reads
// the same rows. What it also does is spend the tenant's model budget on behalf
// of whoever called it, and it does so through a surface that composes several
// reads from one request. `assets.read` is the permission the MCP asset tools
// already declare for exactly those reads, so this is the same permission for
// the same rows rather than a new one invented here.
//
// The pattern is integrations_gate_test.go's, which is the pattern
// select_tier_gate_test.go established: drive the REAL middleware, then read the
// REAL routing table. Deleting the middleware from either route turns the second
// test red.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// TestAsk_RequiresAssetsRead proves the gate refuses a caller whose role does
// not carry assets.read, and that the handler behind it is never entered — so
// no question is asked, no model budget spent, and no row read.
func TestAsk_RequiresAssetsRead(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, tc := range []struct {
		name       string
		grant      bool
		wantStatus int
		wantCalled bool
	}{
		{name: "without assets.read", grant: false, wantStatus: http.StatusForbidden, wantCalled: false},
		{name: "with assets.read", grant: true, wantStatus: http.StatusOK, wantCalled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			r := gin.New()
			r.Use(func(c *gin.Context) {
				c.Set("userID", uuid.New())
				c.Set("tenantID", uuid.New())
			})
			r.POST("/api/v1/inventory-service/ask",
				sharedrbac.RequireTenantPermission(permissionDB(t, tc.grant), rbac.PermissionAssetsRead),
				func(c *gin.Context) {
					called = true
					c.JSON(http.StatusOK, gin.H{"query": "", "rows": []any{}})
				})

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/inventory-service/ask",
				strings.NewReader(`{"question":"anything"}`))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", w.Code, tc.wantStatus, w.Body.String())
			}
			if called != tc.wantCalled {
				t.Fatalf("handler called = %v, want %v", called, tc.wantCalled)
			}
			if !tc.grant && !strings.Contains(w.Body.String(), rbac.PermissionAssetsRead) {
				t.Fatalf("the 403 should name the required permission, got %s", w.Body.String())
			}
		})
	}
}

// TestAskRoutesAreGated pins the WIRING.
//
// The middleware test above stays green if someone drops the gate from a route,
// which is the failure found: a correct middleware, pinned in isolation,
// while the one line that actually closed the hole lived in the router. So read
// the routing table itself — every registration reaching askHandler.Ask must
// carry RequireTenantPermission(rawDB, rbac.PermissionAssetsRead).
//
// Mutation-proven: deleting the gate from either the v1 or the v2 registration
// fails this test.
func TestAskRoutesAreGated(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "cmd", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}

	route := regexp.MustCompile(`(?m)^.*\.POST\("([^"]*ask)",\s*(.*)askHandler\.Ask\).*$`)
	matches := route.FindAllStringSubmatch(string(src), -1)
	// Two: the v1 prefixed spelling and the v2 CMDB-aligned one. A count check
	// rather than "at least one", because a route added without the gate would
	// otherwise pass on the strength of the two that have it.
	if len(matches) != 2 {
		t.Fatalf("expected 2 ask routes (v1 and v2), found %d: %v", len(matches), matches)
	}
	for _, m := range matches {
		if !strings.Contains(m[2], "RequireTenantPermission(rawDB, rbac.PermissionAssetsRead)") {
			t.Errorf("POST %s reaches askHandler.Ask without the assets.read gate: %s",
				m[1], strings.TrimSpace(m[0]))
		}
	}
}

// TestAskRequestBudgetStaysWellUnderTheGenerativeWriteTimeout pins the
// relationship between two numbers that live in different packages:
// `askRequestBudget` here, and `seams.GenerativeWriteTimeout` — the API
// server's real `WriteTimeout`, wired in cmd/main.go and asserted there by
// TestAPIServerWriteTimeoutReadsTheSharedGenerativeConstant below.
//
// A gin handler runs to completion whether or not anyone is still listening.
// Once the API server's `WriteTimeout` has passed, the response write fails and
// the client gets a dropped connection with NO BODY — an answer nobody can read,
// composed at full cost, with the failure visible only as a transport error in
// a browser console. `askRequestBudget` exists to expire well before that, so
// the same failure arrives as a 503 with a sentence in it instead.
//
// Unlike the pre-`GenerativeWriteTimeout` version of this test, the two are not
// expected to sit close together: `seams.GenerativeWriteTimeout` is sized for
// the platform's slowest generative route (compliance-engine's author, a single
// 90s provider call), not for this one, so a wide gap here is correct, not
// wasted. What must never happen is the gap closing to nothing.
//
// Mutation-proven: raise askRequestBudget to within the margin of
// seams.GenerativeWriteTimeout (or past it), and this fails; restore it, and it
// passes again.
func TestAskRequestBudgetStaysWellUnderTheGenerativeWriteTimeout(t *testing.T) {
	// The write itself — headers, JSON body — needs some of the connection's
	// remaining life too; this is not a knife-edge budget like the old one.
	const margin = 30 * time.Second

	if askRequestBudget+margin > seams.GenerativeWriteTimeout {
		t.Errorf("askRequestBudget is %s, only %s inside seams.GenerativeWriteTimeout (%s): "+
			"a slow answer risks being cut off mid-write and reaching the client as a dropped "+
			"connection with no body instead of the 503 this budget exists to produce",
			askRequestBudget, seams.GenerativeWriteTimeout-askRequestBudget, seams.GenerativeWriteTimeout)
	}
}

// TestAPIServerWriteTimeoutReadsTheSharedGenerativeConstant reads the REAL
// main.go source (constructing the real http.Server isn't practical from a
// test — it needs live certs and a live DB) and checks two things at once:
//
//  1. The API server — both branches, mTLS and the plaintext fallback — sets
//     `WriteTimeout` from `seams.GenerativeWriteTimeout`, not a hard-coded
//     literal that could silently drift from the other two services' servers
//     or from `askRequestBudget`.
//  2. The plaintext `/health` server's `WriteTimeout` is untouched by that
//     change: it answers a static body, never calls a seam, and has no reason
//     to wait as long as the slowest generative route might.
//
// Mutation-proven: reverting either apiServer assignment to a numeric literal,
// or switching the health server onto the shared constant, fails this.
func TestAPIServerWriteTimeoutReadsTheSharedGenerativeConstant(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "cmd", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	text := string(src)

	apiCount := strings.Count(text, "apiServer.WriteTimeout = seams.GenerativeWriteTimeout") +
		strings.Count(text, "WriteTimeout:      seams.GenerativeWriteTimeout,")
	if apiCount != 2 {
		t.Errorf("expected exactly 2 apiServer WriteTimeout assignments wired to "+
			"seams.GenerativeWriteTimeout (the mTLS branch and the plaintext fallback), found %d",
			apiCount)
	}

	healthBlock := regexp.MustCompile(`(?s)healthServer\s*:=\s*&http\.Server\{.*?\n\t\}`).FindString(text)
	if healthBlock == "" {
		t.Fatal("could not find the healthServer struct literal in main.go — this guard cannot run")
	}
	if !strings.Contains(healthBlock, "WriteTimeout:      15 * time.Second,") {
		t.Errorf("healthServer no longer declares a plain 15s WriteTimeout literal — it should never "+
			"read seams.GenerativeWriteTimeout, which exists for generative routes it never serves:\n%s",
			healthBlock)
	}
	if strings.Contains(healthBlock, "GenerativeWriteTimeout") {
		t.Errorf("healthServer's block references GenerativeWriteTimeout — the plaintext health "+
			"server must keep its own short, independent timeout:\n%s", healthBlock)
	}
}

// The gate names a permission that exists. A typo'd constant would compile if
// it were a string literal and would refuse every caller forever; it is a
// constant precisely so it cannot be, and this states the expected value once so
// a rename shows up here rather than as a support ticket.
func TestAskGateNamesTheSamePermissionTheMCPAssetToolsDeclare(t *testing.T) {
	if rbac.PermissionAssetsRead != "assets.read" {
		t.Fatalf("PermissionAssetsRead = %q; the MCP asset tools declare \"assets.read\" for the same rows",
			rbac.PermissionAssetsRead)
	}
}
