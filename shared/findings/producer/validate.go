package producer

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/severity"
)

// The severity ladder, lowercase, as findings_severity_check spells it. Named
// here so a producer never types a bare string and a caller comparing against
// one cannot pick a spelling the CHECK rejects.
const (
	SeverityInfo     = string(severity.Info)
	SeverityLow      = string(severity.Low)
	SeverityMedium   = string(severity.Medium)
	SeverityHigh     = string(severity.High)
	SeverityCritical = string(severity.Critical)
)

// ValidSeverity reports whether s is one of the five stored severities.
func ValidSeverity(s string) bool { _, err := severity.Parse(s); return err == nil }

// SeverityAtLeast compares valid severities. This producer compatibility API
// preserves its historical zero-rank behavior for invalid inputs; writers still
// reject those inputs through ValidSeverity before persistence.
func SeverityAtLeast(a, b string) bool {
	ar, _ := severity.Rank(severity.Severity(a))
	br, _ := severity.Rank(severity.Severity(b))
	return ar >= br
}

// Source kinds, mirroring findings_source_kind_check.
const (
	SourceMeasured = "measured"
	SourceDeclared = "declared"
	SourceImported = "imported"
	SourceInferred = "inferred"
)

func validSourceKind(s string) bool {
	switch s {
	case SourceMeasured, SourceDeclared, SourceImported, SourceInferred:
		return true
	}
	return false
}

// Ladder returns a ladder kind's rungs, worst-last.
//
// It errors for a kind whose severity model is `fixed`, rather than returning
// an empty slice: a producer asking for rungs it has none of has misread the
// registry, and an empty slice would make that a silent no-finding rather than
// a loud mistake.
func Ladder(producerKey, kind string) ([]findings.Rung, error) {
	k, ok := findings.Get(producerKey, kind)
	if !ok {
		return nil, fmt.Errorf("producer: %q/%q is not in the findings registry", producerKey, kind)
	}
	if k.SeverityModel != "ladder" || len(k.Rungs) == 0 {
		return nil, fmt.Errorf("producer: %q/%q is a %s-severity kind and has no rungs", producerKey, kind, k.SeverityModel)
	}
	return k.Rungs, nil
}

// Rung returns one rung of a ladder kind by index, worst-last.
//
// The index is the producer's own reading of its measure — days past
// end-of-life, days unseen — and the producer owns that mapping because the
// registry's `threshold` is free text in the producer's units. What this
// enforces is that the index EXISTS: a producer built against a three-rung
// ladder that someone later trimmed to two fails here instead of silently
// clamping to the worst rung it still has.
func Rung(producerKey, kind string, i int) (findings.Rung, error) {
	rungs, err := Ladder(producerKey, kind)
	if err != nil {
		return findings.Rung{}, err
	}
	if i < 0 || i >= len(rungs) {
		return findings.Rung{}, fmt.Errorf(
			"producer: %q/%q has %d rungs, so rung %d does not exist — the registry ladder changed under this producer",
			producerKey, kind, len(rungs), i)
	}
	return rungs[i], nil
}

// Validate reports whether this writer would accept f.
//
// [Writer.Upsert] calls it anyway; this is the exported form, for a producer
// that wants to check what it has planned BEFORE opening the transaction that
// writes it. A pass that discovers a registry violation half way through its
// write phase loses every finding it had already upserted, and the violation is
// a programming error that a test can catch instead.
func (w *Writer) Validate(f Finding) error { return w.validate(f) }

// validate checks one finding against the registry before it reaches SQL.
//
// Everything here is a PROGRAMMING error, not a data error: a producer that
// writes an unregistered kind, a subject type its kind may not be about, or a
// score a non-risk-feeding kind must not carry, has a bug. They are returned as
// errors rather than corrected, because correcting them silently is how a
// producer comes to believe it is writing something it is not — the failure
// shape this repository keeps re-finding.
func (w *Writer) validate(f Finding) error {
	if err := findings.Validate(w.producer, f.Kind, f.Subject.Type); err != nil {
		return err
	}
	k, _ := findings.Get(w.producer, f.Kind)

	if f.Subject.ID == uuid.Nil {
		return fmt.Errorf("producer %s/%s: subject_id is the nil uuid", w.producer, f.Kind)
	}

	// findings_control_id_compliance_only_check, said in Go so the producer
	// gets the rule and not a constraint name. Refused rather than nulled:
	// control_id is part of the open-row identity, and a producer that believed
	// it was writing one finding per control would instead be writing one per
	// control that Sweep — which keys on `control_id IS NULL` — could never
	// reach again.
	if f.ControlID != nil {
		return fmt.Errorf(
			"producer %s/%s: control_id is the compliance producer's discriminator and must be nil here (findings_control_id_compliance_only_check)",
			w.producer, f.Kind)
	}
	if strings.TrimSpace(f.Summary) == "" {
		return fmt.Errorf("producer %s/%s: summary is empty — the findings table requires one and a blank renders as a blank row", w.producer, f.Kind)
	}
	if !ValidSeverity(f.Severity) {
		return fmt.Errorf("producer %s/%s: severity %q is not on the ladder %v", w.producer, f.Kind, f.Severity, []string{
			SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical})
	}
	if f.Score < 0 || f.Score > 100 {
		return fmt.Errorf("producer %s/%s: score %d is outside 0-100", w.producer, f.Kind, f.Score)
	}
	if f.SourceKind != "" && !validSourceKind(f.SourceKind) {
		return fmt.Errorf("producer %s/%s: source_kind %q is not one of measured/declared/imported/inferred", w.producer, f.Kind, f.SourceKind)
	}

	// feeds_risk false means the kind contributes nothing to the per-asset
	// rollup (ADR-0005 D4). Writing a number anyway would put a score in a
	// column the rollup ignores and a reader believes — and `0 means NOT
	// ASSESSED` only survives if the kinds that genuinely assess nothing are
	// the only ones carrying 0.
	if !k.FeedsRisk && f.Score != 0 {
		return fmt.Errorf(
			"producer %s/%s: score %d, but the registry sets feeds_risk false for this kind — a kind that feeds no risk must write 0",
			w.producer, f.Kind, f.Score)
	}

	// A ladder kind must write one of its own rungs, verbatim. The registry is
	// where the numbers live (and where they are revisited — see REGISTRIES.md
	// "Values chosen without a standard"); a producer that computed its own
	// pairing would make the YAML documentation of a decision taken elsewhere.
	if k.SeverityModel == "ladder" {
		for _, r := range k.Rungs {
			if r.Severity == f.Severity && r.Score == f.Score {
				return nil
			}
		}
		return fmt.Errorf(
			"producer %s/%s: (severity %q, score %d) is not one of the registry's rungs %v — a ladder kind writes a rung, not a computed pair",
			w.producer, f.Kind, f.Severity, f.Score, k.Rungs)
	}

	return nil
}
