package producer

// Validation, which is the half of the writer that needs no database.
//
// Everything here is a refusal, and a refusal test is only worth having if the
// ACCEPT case is tested beside it: a validator that rejected everything would
// pass every "is it refused?" assertion below and stop the producers writing
// anything at all. So each group pins both polarities.

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/findings"
)

func newTestWriter(t *testing.T, key string) *Writer {
	t.Helper()
	w, err := New(key)
	if err != nil {
		t.Fatalf("New(%q): %v", key, err)
	}
	return w
}

func TestNew_RefusesAnUnregisteredProducer(t *testing.T) {
	if _, err := New("a-producer-nobody-registered"); err == nil {
		t.Fatal("New accepted an unregistered producer key; a typo would run a whole pass and report success")
	}
	for _, p := range findings.Producers {
		if _, err := New(p.Key); err != nil {
			t.Errorf("New(%q) refused a registered producer: %v", p.Key, err)
		}
	}
}

// A valid ladder finding, as the eol producer writes one.
func validLadderFinding(t *testing.T) Finding {
	t.Helper()
	r, err := Rung(findings.ProducerEOL, findings.KindOSEndOfLife, 1)
	if err != nil {
		t.Fatalf("Rung: %v", err)
	}
	return Finding{
		Kind:     findings.KindOSEndOfLife,
		Subject:  Subject{Type: findings.SubjectAsset, ID: uuid.New()},
		Severity: r.Severity,
		Score:    r.Score,
		Summary:  "Ubuntu 18.04 is past end of life",
		Evidence: map[string]any{"catalogue_id": "x"},
	}
}

func TestValidate_AcceptsARegistryShapedFinding(t *testing.T) {
	w := newTestWriter(t, findings.ProducerEOL)
	if err := w.validate(validLadderFinding(t)); err != nil {
		t.Fatalf("a finding built from the registry's own rung was refused: %v", err)
	}
}

func TestValidate_AcceptsEveryRungOfEveryLadderKind(t *testing.T) {
	// The inverse polarity of the rung check below: if the pairing rule were
	// wrong in the strict direction, a producer could not write ANY finding and
	// every "is it refused?" case would still pass.
	for _, k := range findings.All {
		if k.SeverityModel != "ladder" {
			continue
		}
		w := newTestWriter(t, k.Producer)
		for i, r := range k.Rungs {
			f := Finding{
				Kind:     k.Key,
				Subject:  Subject{Type: k.SubjectTypes[0], ID: uuid.New()},
				Severity: r.Severity,
				Score:    r.Score,
				Summary:  "rung " + k.Key,
			}
			if err := w.validate(f); err != nil {
				t.Errorf("%s/%s rung %d (%s, %d) was refused: %v", k.Producer, k.Key, i, r.Severity, r.Score, err)
			}
		}
	}
}

func TestValidate_RefusesAPairThatIsNotARung(t *testing.T) {
	w := newTestWriter(t, findings.ProducerEOL)
	f := validLadderFinding(t)
	f.Score = 55 // not one of os_end_of_life's 30 / 70 / 90
	err := w.validate(f)
	if err == nil {
		t.Fatal("a ladder kind accepted a computed severity/score pair; the registry is where those numbers live")
	}
	if !strings.Contains(err.Error(), "rung") {
		t.Errorf("error does not name the rule it enforced: %v", err)
	}
}

func TestValidate_RefusesAScoreOnAKindThatFeedsNoRisk(t *testing.T) {
	// hygiene/no_owner is feeds_risk: false. A number in `score` there would be
	// counted by nothing and believed by a reader — and "0 means NOT ASSESSED"
	// survives only while the kinds that assess nothing are the only 0s.
	w := newTestWriter(t, findings.ProducerHygiene)
	f := Finding{
		Kind:     findings.KindNoOwner,
		Subject:  Subject{Type: findings.SubjectAsset, ID: uuid.New()},
		Severity: SeverityLow,
		Summary:  "no owner",
	}
	if err := w.validate(f); err != nil {
		t.Fatalf("score 0 on a non-risk-feeding kind was refused: %v", err)
	}
	f.Score = 40
	if err := w.validate(f); err == nil {
		t.Fatal("a non-zero score was accepted on a kind whose feeds_risk is false")
	}
}

func TestValidate_RefusesOffLadderSeverity(t *testing.T) {
	w := newTestWriter(t, findings.ProducerEOL)
	// `Med` is the spelling the retired compliance_findings table used. It is
	// not on the registry ladder and findings_severity_check rejects it, so the
	// writer has to as well rather than letting the constraint be the error.
	for _, bad := range []string{"Med", "High", "", "severe"} {
		f := validLadderFinding(t)
		f.Severity = bad
		if err := w.validate(f); err == nil {
			t.Errorf("severity %q was accepted", bad)
		}
	}
}

func TestValidate_RefusesASubjectTypeTheKindForbids(t *testing.T) {
	w := newTestWriter(t, findings.ProducerEOL)
	f := validLadderFinding(t)
	// os_end_of_life is about an asset. A certificate cannot run an OS.
	f.Subject.Type = findings.SubjectCertificate
	if err := w.validate(f); err == nil {
		t.Fatal("a subject type outside the kind's subject_types was accepted")
	}
}

func TestValidate_RefusesAControlID(t *testing.T) {
	w := newTestWriter(t, findings.ProducerEOL)
	f := validLadderFinding(t)
	id := uuid.New()
	f.ControlID = &id
	err := w.validate(f)
	if err == nil {
		t.Fatal("a control id was accepted; it is part of the open-row identity and Sweep keys on control_id IS NULL, so such a row could never be resolved")
	}
	if !strings.Contains(err.Error(), "control_id") {
		t.Errorf("error does not name the column: %v", err)
	}
}

func TestValidate_RefusesAnEmptySummaryAndNilSubject(t *testing.T) {
	w := newTestWriter(t, findings.ProducerEOL)

	f := validLadderFinding(t)
	f.Summary = "  \t "
	if err := w.validate(f); err == nil {
		t.Error("a blank summary was accepted; it renders as a blank row")
	}

	f = validLadderFinding(t)
	f.Subject.ID = uuid.Nil
	if err := w.validate(f); err == nil {
		t.Error("the nil uuid was accepted as a subject")
	}
}

func TestValidate_RefusesAnUnknownSourceKind(t *testing.T) {
	w := newTestWriter(t, findings.ProducerEOL)
	f := validLadderFinding(t)
	f.SourceKind = "guessed"
	if err := w.validate(f); err == nil {
		t.Fatal("an unregistered source_kind was accepted")
	}
	for _, ok := range []string{"", SourceMeasured, SourceImported, SourceDeclared, SourceInferred} {
		f := validLadderFinding(t)
		f.SourceKind = ok
		if err := w.validate(f); err != nil {
			t.Errorf("source_kind %q was refused: %v", ok, err)
		}
	}
}

func TestRung_FailsWhenTheRegistryLadderShrinks(t *testing.T) {
	k, ok := findings.Get(findings.ProducerEOL, findings.KindOSEndOfLife)
	if !ok {
		t.Fatal("eol/os_end_of_life is not registered")
	}
	if _, err := Rung(findings.ProducerEOL, findings.KindOSEndOfLife, len(k.Rungs)); err == nil {
		t.Fatal("Rung returned a rung past the end of the ladder; a producer built against three rungs must fail loudly when the registry has two, not clamp")
	}
	if _, err := Rung(findings.ProducerEOL, findings.KindOSEndOfLife, -1); err == nil {
		t.Fatal("Rung accepted a negative index")
	}
}

func TestLadder_RefusesAFixedSeverityKind(t *testing.T) {
	if _, err := Ladder(findings.ProducerHygiene, findings.KindNoOwner); err == nil {
		t.Fatal("Ladder returned rungs for a fixed-severity kind; an empty slice would make a misreading of the registry a silent no-finding")
	}
	if _, err := Ladder(findings.ProducerEOL, findings.KindOSEndOfLife); err != nil {
		t.Fatalf("Ladder refused a real ladder kind: %v", err)
	}
}

func TestMarshalEvidence_NeverProducesNull(t *testing.T) {
	// `findings.evidence || EXCLUDED.evidence` yields NULL if either side is
	// NULL, so a producer writing no evidence would erase the row's whole
	// document. The column is NOT NULL with a `{}` default and this keeps it so.
	for _, in := range []map[string]any{nil, {}} {
		got, err := marshalEvidence(in)
		if err != nil {
			t.Fatalf("marshalEvidence(%v): %v", in, err)
		}
		if string(got) != "{}" {
			t.Errorf("marshalEvidence(%v) = %q, want {}", in, got)
		}
	}
	got, err := marshalEvidence(map[string]any{"cve": "CVE-2024-0001"})
	if err != nil || !strings.Contains(string(got), "CVE-2024-0001") {
		t.Errorf("marshalEvidence dropped the payload: %q, %v", got, err)
	}
}

func TestSeverityAtLeast(t *testing.T) {
	if !SeverityAtLeast(SeverityCritical, SeverityHigh) || !SeverityAtLeast(SeverityHigh, SeverityHigh) {
		t.Error("the ladder does not order worst-last")
	}
	if SeverityAtLeast(SeverityLow, SeverityHigh) {
		t.Error("low compared at or above high")
	}
}

// The conflict target in upsertSQL must be findings_open_subject_uniq spelled
// out: Postgres infers a partial index from the column list AND the predicate,
// so a drift here does not silently pick another index, it fails to find one.
// Pinning the text is cheaper than discovering that at runtime.
func TestUpsertSQL_NamesTheOpenSubjectIndexExactly(t *testing.T) {
	const want = "ON CONFLICT (tenant_id, producer, kind, subject_type, subject_id, control_id)\n" +
		"        WHERE detection_state <> 'ARCHIVED'"
	if !strings.Contains(upsertSQL, want) {
		t.Fatalf("upsertSQL's conflict target is not findings_open_subject_uniq's definition; want to find:\n%s", want)
	}
	// And the prior CTE has to use the same `<> ARCHIVED` predicate, or the
	// state it reports would not be the state the conflict resolved against.
	if !strings.Contains(upsertSQL, "AND detection_state <> 'ARCHIVED'") {
		t.Error("the prior CTE does not use the index's own predicate")
	}
}

// Sweep is the statement that can do the most damage if its scoping is wrong:
// without the producer and kind predicates it is a claim about every producer's
// findings. The integration suite proves the behaviour; this catches a deletion
// of the predicates in review.
func TestSweepSQL_IsScopedByProducerAndKind(t *testing.T) {
	for _, want := range []string{"AND producer = $2", "AND kind = $3", "AND control_id IS NULL", "AND detection_state = 'ACTIVE'"} {
		if !strings.Contains(sweepSQL, want) {
			t.Errorf("sweepSQL is missing %q — a sweep without it reaches rows this producer never wrote", want)
		}
	}
}
