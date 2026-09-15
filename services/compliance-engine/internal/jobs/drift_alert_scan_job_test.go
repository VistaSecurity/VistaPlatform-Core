package jobs

// The drift_detected ladder.
//
// Unlike the other two findings-driven types, drift has no scale of its own —
// no CVSS, no deadline — so the rung IS the finding's severity. What needs
// pinning is therefore different: not boundary arithmetic, but that the alert
// ladder can still EXPRESS every severity the drift producer can write, and
// that nothing in this file re-grades a finding the registry already graded.

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/alertcatalog"
	sharedfindings "github.com/vistasecurity/vistaplatform/shared/findings"
)

func driftFinding(kind, severity string) openFinding {
	return openFinding{
		id: uuid.New(), kind: kind,
		subjectType: "asset", subjectID: uuid.New(), subjectLabel: "web-01",
		severity: severity, score: 30,
		summary:  "web-01 started speaking telnet",
		evidence: map[string]any{"window_days": 14},
	}
}

// TestDriftLadderCoversEveryDriftKind is the cross-registry join. The findings
// registry fixes a severity per drift kind and the alert registry declares the
// ladder; a new kind graded `critical` against a ladder that stops at `medium`
// would silently open no alert at all, and the finding's own severity is the
// only grade there is to use.
func TestDriftLadderCoversEveryDriftKind(t *testing.T) {
	entry, ok := alertcatalog.Get("drift_detected")
	if !ok {
		t.Fatal("drift_detected is not in standards/alert-registry.yaml")
	}
	ladder := map[string]bool{}
	for _, r := range entry.Rungs {
		ladder[r.Severity] = true
	}

	seen := 0
	for _, k := range sharedfindings.All {
		if k.Producer != sharedfindings.ProducerDrift {
			continue
		}
		seen++
		if !ladder[k.DefaultSeverity] {
			t.Errorf("drift kind %q is graded %q, which the drift_detected ladder cannot express — "+
				"add the rung to standards/alert-registry.yaml or the kind opens no alert",
				k.Key, k.DefaultSeverity)
		}
		if _, crosses := driftRungFor(driftFinding(k.Key, k.DefaultSeverity)); !crosses {
			t.Errorf("a %q finding at its registry severity %q crosses no rung", k.Key, k.DefaultSeverity)
		}
	}
	if seen == 0 {
		t.Fatal("no drift kinds found in the findings registry — this test proves nothing")
	}
}

// TestDriftRungForIsTheFindingSeverity pins the one rule: the rung is the
// finding's grade, looked up, never re-derived.
func TestDriftRungForIsTheFindingSeverity(t *testing.T) {
	entry, _ := alertcatalog.Get("drift_detected")
	for want, severity := range map[int]string{0: "low", 1: "medium", 2: "high", 3: "critical"} {
		idx, ok := driftRungFor(driftFinding(sharedfindings.KindPortProfileChanged, severity))
		if !ok {
			t.Fatalf("severity %q crossed no rung", severity)
		}
		if idx != want {
			t.Errorf("severity %q mapped to rung %d, want %d", severity, idx, want)
		}
		if entry.Rungs[idx].Severity != severity {
			t.Errorf("rung %d carries severity %q, want %q — the alert would be graded differently from the finding",
				idx, entry.Rungs[idx].Severity, severity)
		}
	}
}

// TestDriftRungForRefusesAnUngradedFinding: a severity the ladder does not
// carry opens nothing rather than defaulting to a rung nobody chose. Same rule
// as the unscored CVE — a grade we do not have is not a grade of zero.
func TestDriftRungForRefusesAnUngradedFinding(t *testing.T) {
	for _, severity := range []string{"", "info", "catastrophic"} {
		if _, ok := driftRungFor(driftFinding(sharedfindings.KindNewIssuer, severity)); ok {
			t.Errorf("severity %q crossed a rung — the alert would claim a grade the finding does not carry", severity)
		}
	}
}

func TestSummarizeDrift(t *testing.T) {
	rung := alertcatalog.LadderRung{Threshold: "a change the drift producer graded medium", Severity: "medium"}

	// One finding: the alert says what the finding says.
	one := driftFinding(sharedfindings.KindUnexpectedProtocol, "medium")
	g := subjectGroup{subjectType: "asset", subjectID: one.subjectID, subjectLabel: "web-01",
		findings: []openFinding{one}, worst: one, crosses: true, rungIndex: 1}
	title, message, meta := summarizeDrift(g, rung)
	if !strings.Contains(title, "web-01") {
		t.Errorf("title %q does not name the subject", title)
	}
	if message != one.summary {
		t.Errorf("message = %q, want the finding's own summary %q — paraphrasing it makes the alert and the "+
			"Findings tab disagree about the same event", message, one.summary)
	}
	if meta["window_days"] != 14 {
		t.Errorf("window_days = %v, want 14 — a drift judgement is unreadable without the window it was made under", meta["window_days"])
	}
	if meta["worst_kind"] != sharedfindings.KindUnexpectedProtocol {
		t.Errorf("worst_kind = %v", meta["worst_kind"])
	}

	// Several findings: the count is stated and every kind is named.
	two := driftFinding(sharedfindings.KindPortProfileChanged, "low")
	two.subjectID = one.subjectID
	g.findings = []openFinding{one, two}
	_, message, meta = summarizeDrift(g, rung)
	if !strings.Contains(message, "2 drift findings") {
		t.Errorf("message %q does not say how many findings are open", message)
	}
	kinds, _ := meta["finding_kinds"].([]string)
	if len(kinds) != 2 {
		t.Fatalf("finding_kinds = %v, want both kinds", kinds)
	}

	// A subject with no label still yields a readable alert rather than a blank.
	g.subjectLabel = ""
	g.worst.summary = ""
	title, message, _ = summarizeDrift(g, rung)
	if strings.Contains(title, ": ") && strings.HasSuffix(title, ": ") {
		t.Errorf("title %q ends in an empty label", title)
	}
	if message == "" {
		t.Error("an unlabelled subject produced an empty message")
	}
}
