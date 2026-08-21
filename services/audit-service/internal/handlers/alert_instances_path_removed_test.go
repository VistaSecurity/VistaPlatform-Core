package handlers

// The audit.alert_instances read/ack/resolve path is gone and must stay gone.
//
// Three routes — GET /alert-instances and POST /alert-instances/:id/{acknowledge,
// resolve} — read and updated audit.alert_instances, a table with no INSERT
// anywhere in the tree: not in Go, not in schema.sql, not in seed.sql. So the
// list route could only ever return an empty list and the two mutations could
// only ever report "not found". Neither UI called them and they were never in
// the OpenAPI spec. Confirmed live on a dev cluster: alert_instances
// held 0 rows while the working rail's `alerts` table held 21.
//
// This is the Triage defect ( / B-25) one layer down, and it was removed
// rather than given a producer for two reasons:
//
//  1. There is no engine to wire. audit.alert_rules is a rule *store* — CRUD
//     behind Settings → Alert Rules — and nothing in the tree evaluates those
//     rows. A producer would mean building an evaluator first.
//  2. Even then it would be a *second* stateful alert store beside the one that
//     already works, which is exactly what ADR-0006 rejected ("Do not create a
//     new alert store"). The same alert would carry two independent lifecycles:
//     acknowledge it in one place and it stays active in the other.
//
// Alert state belongs to the stateful rail — alerts.raise → compliance-engine's
// `alerts` table, surfaced at Remediation → Alerts. audit-service's in-memory
// rule engine (AlertService) already feeds it, tagged AlertSource "audit".
//
// If someone later builds the evaluator, the writer guard below fires. That is
// deliberate: reinstating the read routes is a decision to revisit ADR-0006,
// not a detail to slip in beside an INSERT.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readRepoSource(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// thisGuard is the one file allowed to name the strings it hunts for.
const thisGuard = "alert_instances_path_removed_test.go"

func TestAlertInstanceRoutesAreNotRegistered(t *testing.T) {
	main := readRepoSource(t, filepath.Join("..", "..", "cmd", "main.go"))

	// Each entry is a route registration with its handler, not a bare path, so
	// the assertion cannot be satisfied by the explanatory comment above it.
	for _, route := range []string{
		`api.GET("/audit-service/alert-instances", h.alertRule.GetAlertInstances)`,
		`h.alertRule.AcknowledgeAlert)`,
		`h.alertRule.ResolveAlert)`,
	} {
		if strings.Contains(main, route) {
			t.Errorf("alert-instances route re-registered: %s\n"+
				"audit.alert_instances has no writer; alert state belongs to the "+
				"alerts.raise rail (Remediation → Alerts). See ADR-0006.", route)
		}
	}

	// The neighbouring rule CRUD is live and must survive this removal — it
	// backs Settings → Alert Rules. Guards the deletion from over-reach.
	for _, keep := range []string{
		`api.GET("/audit-service/alert-rules", h.alertRule.GetAlertRules)`,
		`h.alertRule.CreateAlertRule)`,
		`h.alertRule.DeleteAlertRule)`,
	} {
		if !strings.Contains(main, keep) {
			t.Errorf("alert-rule CRUD route went missing: %s — Settings → Alert Rules depends on it", keep)
		}
	}
}

// TestAlertInstancesTableHasNoGoReferences pins the invariant in both
// directions: no writer (so a read path would be dishonest) and no reader (so
// nothing serves an empty list as though it were an answer).
func TestAlertInstancesTableHasNoGoReferences(t *testing.T) {
	root := filepath.Join("..", "..")
	var offenders []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, thisGuard) {
			return nil
		}
		src := readRepoSource(t, path)
		// SQL forms, not the bare table name: cmd/main.go carries a comment
		// explaining why these routes are gone, and that comment must not trip
		// the guard that enforces it.
		for _, frag := range []string{
			"FROM audit.alert_instances",
			"INTO audit.alert_instances",
			"UPDATE audit.alert_instances",
			"JOIN audit.alert_instances",
		} {
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
		t.Errorf("audit.alert_instances SQL is back in:\n  %s\n\n"+
			"A reader without a writer can only return empty. A writer means a "+
			"second alert store beside compliance-engine's `alerts` — revisit "+
			"ADR-0006 before adding either.", strings.Join(offenders, "\n  "))
	}
}

// TestAuditAlertsStillReachTheStatefulRail guards the other half of the
// decision. Removing the dead store is only correct while the live rail is
// there to carry audit alerts; if this publish disappears, audit alerts stop
// reaching the tenant entirely and the removal above needs revisiting.
func TestAuditAlertsStillReachTheStatefulRail(t *testing.T) {
	src := readRepoSource(t, filepath.Join("..", "services", "alert_service.go"))

	if !strings.Contains(src, "events.SubjectAlertsRaise") {
		t.Error("audit-service no longer publishes to the alerts.raise rail — " +
			"audit alerts now reach no persisted store at all")
	}
	if !strings.Contains(src, `AlertSource: "audit"`) {
		t.Error(`audit-service no longer tags notifications with AlertSource "audit"`)
	}
}
