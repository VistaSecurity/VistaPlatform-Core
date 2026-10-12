package main

// — the /mappings routes validated rule_id against compliance_rules, a
// table that is created but never seeded and has no writer, so every call
// failed with "compliance rule not found". No client ever called them. They
// were removed; this keeps them from coming back without the rule catalogue
// they depend on.
//
// Like ticket_route_gate_test.go this reads the registrations out of main.go
// (main() has no extractable router to drive).

import "testing"

func TestMappingsRoutesAreNotRegistered(t *testing.T) {
	src := ticketRouterSource(t)
	paths := []string{"/mappings", "/mappings/:id"}
	for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
		for _, p := range paths {
			if line := routeLine(t, src, method, p); line != "" {
				t.Errorf("%s %s is registered again: %s", method, p, line)
			}
		}
	}
}
