package handlers

// The pre-ADR-0014 rule/check/report path is gone and must stay gone.
//
// It was dead in every direction: `compliance_rules` is never seeded so the
// evaluation loop never reached its INSERT; none of the routes had a caller in
// either UI or any Go client; and `compliance_checks` had zero readers in the
// tree. Had it ever run it would have failed three ways at once — the INSERT
// named `checked_at` (the column is `created_at`), omitted `report_id uuid NOT
// NULL`, and bound a bare map into a jsonb column lib/pq cannot marshal — with
// the error discarded by `_ = WithTenantTx(...)`. Its evaluators also used two
// different vocabularies for the same outcome ("passed" when summarising,
// "pass" when writing a row) and joined `assets`, a relation that no longer
// exists.
//
// Compliance evaluation is the materialized-findings model (/findings,
// /evaluate, /summary). Anything that reintroduces the strings below is
// resurrecting the superseded path.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readSource(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func TestLegacyComplianceCheckRoutesAreNotRegistered(t *testing.T) {
	main := readSource(t, filepath.Join("..", "..", "cmd", "main.go"))

	// Each entry is a route registration, not a bare path, so the assertion
	// cannot be satisfied by a mention in a comment.
	for _, route := range []string{
		`compliance.GET("/rules"`,
		`compliance.GET("/rules/:id"`,
		`compliance.POST("/rules"`,
		`compliance.POST("/checks"`,
		`compliance.GET("/reports"`,
		`compliance.GET("/legacy/summary"`,
	} {
		if strings.Contains(main, route) {
			t.Errorf("legacy route re-registered: %s — the rule/check/report path is superseded by materialized findings", route)
		}
	}
}

func TestLegacyComplianceCheckTablesHaveNoWriters(t *testing.T) {
	root := filepath.Join("..", "..")
	var offenders []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		// This file names the strings it is hunting for.
		if strings.HasSuffix(path, "legacy_check_path_removed_test.go") {
			return nil
		}
		src := string(mustRead(t, path))
		// compliance_rules is deliberately absent from this list: MappingsService
		// still validates a rule id against it. That reader is itself orphaned
		// (no UI or client calls /mappings, and nothing can create a rule any
		// more) but retiring it is a separate decision.
		for _, frag := range []string{"INTO compliance_checks", "FROM compliance_checks", "INTO compliance_reports", "FROM compliance_reports", "UPDATE compliance_reports"} {
			if strings.Contains(src, frag) {
				offenders = append(offenders, path+": "+frag)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(offenders) > 0 {
		t.Errorf("legacy compliance_checks/rules/reports SQL is back:\n  %s", strings.Join(offenders, "\n  "))
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}
