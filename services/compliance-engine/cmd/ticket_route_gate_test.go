package main

// — filing a ticket is reporting, not triage.
//
// POST /tickets used to require compliance.update, which meant the only people
// who could REPORT a problem were the people who could already fix it. A
// `viewer` holds read across every operational resource and is therefore the
// person most likely to spot something — and could not raise it. Create is now
// ungated; edit, delete and comment stay gated so an unprivileged reporter can
// file a ticket and no more.
//
// This guards the WIRING. The route registrations live inline in main(), which
// has no extractable SetupRouter to drive with httptest the way
// auth-service's select_tier_gate_test.go does, so this reads the real
// registration lines out of the real source file. That is weaker than driving
// a router in two specific ways, stated here rather than left implied:
//
//   - it proves the middleware is NAMED on the route, not that it is effective
//     at runtime (a middleware that fails open would still satisfy it);
//   - it is coupled to the registrations staying one-per-line, which gofmt
//     keeps but nothing enforces. A reformatting breaks this loudly rather
//     than silently, which is the acceptable direction.
//
// What it does catch is the thing that actually happens: someone deleting the
// permission middleware from a mutating route, or re-adding it to create and
// quietly closing the reporting path again. Both polarities are mutation-
// tested.

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

const ticketGate = "RequireTenantPermission"

// routeLine returns the single registration line for `method path`, or "" when
// the route is not registered at all.
func routeLine(t *testing.T, src, method, path string) string {
	t.Helper()
	// e.g. compliance.POST("/tickets/:id/comments", ...)
	re := regexp.MustCompile(`(?m)^\s*compliance\.` + method + `\("` + regexp.QuoteMeta(path) + `",.*$`)
	matches := re.FindAllString(src, -1)
	if len(matches) == 0 {
		return ""
	}
	if len(matches) > 1 {
		t.Fatalf("%s %s is registered %d times — this guard reads one line per route", method, path, len(matches))
	}
	return matches[0]
}

func ticketRouterSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	return string(b)
}

func TestTicketRoutes_CreateIsNotPermissionGated(t *testing.T) {
	src := ticketRouterSource(t)

	line := routeLine(t, src, "POST", "/tickets")
	if line == "" {
		t.Fatal("POST /tickets is not registered — the reporting path is gone entirely")
	}
	if strings.Contains(line, ticketGate) {
		t.Errorf(
			"POST /tickets carries %s. Create is deliberately ungated so a viewer "+
				"can report a problem they cannot fix; re-gating it closes that path.\n  %s",
			ticketGate, strings.TrimSpace(line))
	}
}

func TestTicketRoutes_MutationsStayPermissionGated(t *testing.T) {
	src := ticketRouterSource(t)

	// Everything that CHANGES a ticket, as opposed to raising one. Opening
	// create must not have opened these by accident.
	for _, r := range []struct{ method, path string }{
		{"PUT", "/tickets/:id"},
		{"DELETE", "/tickets/:id"},
		{"POST", "/tickets/:id/comments"},
	} {
		line := routeLine(t, src, r.method, r.path)
		if line == "" {
			t.Errorf("%s %s is not registered", r.method, r.path)
			continue
		}
		if !strings.Contains(line, ticketGate) {
			t.Errorf(
				"%s %s has no %s. Triage stays gated on compliance.update even though "+
					"create is open.\n  %s",
				r.method, r.path, ticketGate, strings.TrimSpace(line))
		}
		if !strings.Contains(line, "PermissionComplianceUpdate") {
			t.Errorf("%s %s is gated on something other than compliance.update:\n  %s",
				r.method, r.path, strings.TrimSpace(line))
		}
	}
}

func TestTicketRoutes_ReadsAreNotGated(t *testing.T) {
	// Reads were always open to tenant members; this pins that opening create
	// did not come with an unrelated tightening of the read paths.
	for _, path := range []string{"/tickets", "/tickets/stats", "/tickets/progress", "/tickets/:id", "/tickets/:id/comments"} {
		line := routeLine(t, ticketRouterSource(t), "GET", path)
		if line == "" {
			t.Errorf("GET %s is not registered", path)
			continue
		}
		if strings.Contains(line, ticketGate) {
			t.Errorf("GET %s became permission-gated:\n  %s", path, strings.TrimSpace(line))
		}
	}
}

// The audit middleware must be reachable from handlers that write their own
// entry ( delete).
//
// This is the "fix compiles, passes its tests, does nothing in production"
// shape, and it is worth being precise about why a unit test could not catch
// it. audithelpers.ExtractAuditMiddleware reads the gin key "audit_middleware".
// Nothing in LogRequest sets that key — each service sets it itself, and
// compliance-engine did NOT. Delete the Set and:
//
//   - the handler still compiles (ExtractAuditMiddleware just returns false),
//   - the contract test still passes (it asserts the HTTP response),
//   - the delete still works,
//   - and every ticket.deleted entry is silently dropped.
//
// Seven services shipped revocation checks that were inert for exactly this
// class of reason. So the wiring gets its own assertion, against the real
// source.
func TestAuditMiddleware_IsReachableFromHandlers(t *testing.T) {
	src := ticketRouterSource(t)

	if !strings.Contains(src, `c.Set("audit_middleware", auditMiddleware)`) {
		t.Error(
			"cmd/main.go no longer puts the audit middleware in the gin context. " +
				"audithelpers.ExtractAuditMiddleware reads that key, so without it every " +
				"explicit audit entry — including ticket.deleted, the only surviving " +
				"record of a hard-deleted ticket — is silently skipped.")
	}

	// Order matters less than presence, but the Set must not sit behind the
	// Enabled short-circuit inside LogRequest: a handler needs the middleware
	// object whether or not THIS request is being logged.
	setIdx := strings.Index(src, `c.Set("audit_middleware", auditMiddleware)`)
	logIdx := strings.Index(src, "auditMiddleware.LogRequest()")
	if setIdx >= 0 && logIdx >= 0 && setIdx > logIdx {
		t.Error("the audit_middleware Set must be registered before LogRequest so handlers " +
			"can reach it on every request")
	}
}

func TestTicketRoutes_DeleteIsPermissionGatedAndRegistered(t *testing.T) {
	// Delete is the most destructive thing on a ticket and stays behind
	// compliance.update even though CREATE is open: reporting a problem and
	// destroying the record of one are not the same authority.
	line := routeLine(t, ticketRouterSource(t), "DELETE", "/tickets/:id")
	if line == "" {
		t.Fatal("DELETE /tickets/:id is not registered")
	}
	if !strings.Contains(line, ticketGate) {
		t.Errorf("DELETE /tickets/:id lost its permission gate:\n  %s", strings.TrimSpace(line))
	}
}
