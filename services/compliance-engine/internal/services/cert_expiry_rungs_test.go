package services

import (
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
)

// The three cert-expiry rungs exactly as scripts/database/seed.sql writes them
// into control_measurements for CE-NE-001 / CE-30-001 / CE-90-001.
//
// The operator states the PASS condition (evaluateThreshold returns the
// comparison, and a finding is raised when it is false), so each rung reads
// "the certificate still has at least this much validity left". Spelled as
// float64 because that is what encoding/json produces for a jsonb number, which
// is how these reach the evaluator in production — an int literal here would
// exercise a conversion the real path never takes.
var certExpiryRungs = map[string]map[string]interface{}{
	"not-expired": {"operator": ">", "value": float64(0)},
	"30-day":      {"operator": ">=", "value": float64(30)},
	"90-day":      {"operator": ">=", "value": float64(90)},
}

// TestCertExpiryRungsAreDistinct is the guard against the three cert-expiry
// frameworks collapsing into each other.
//
// Every band × every rung, stated as a full truth table rather than as spot
// checks, because the failure this pins was invisible precisely where the bands
// overlap: a certificate with 56 days left violates ONLY the 90-day rung, and
// every tenant that ever exercised these frameworks happened to also hold an
// expired certificate — which fails all three — so "the 90-day rung fires" and
// "only expiry fires" produced identical results everywhere anyone looked.
//
// Read the table: the 56-day row is the one that tells them apart.
func TestCertExpiryRungsAreDistinct(t *testing.T) {
	// Each row is one certificate's days-remaining and the rung verdicts it
	// must produce. true = the control PASSES for this certificate.
	bands := []struct {
		name          string
		daysRemaining int
		notExpired    bool
		thirtyDay     bool
		ninetyDay     bool
	}{
		{"expired 31 days ago", -31, false, false, false},
		{"expires today", 0, false, false, false},
		{"15 days left", 15, true, false, false},
		// The Bobco case. 56 days satisfies the 30-day rung and violates the
		// 90-day one; a rung ladder that has collapsed cannot produce this row.
		{"56 days left", 56, true, true, false},
		{"exactly 90 days left", 90, true, true, true},
		{"200 days left", 200, true, true, true},
	}

	evaluator := &RuleEvaluator{}
	measurementType := models.MeasurementType{Code: "cert_expiration_days", Name: "Certificate Expiration Days", DataType: "integer"}

	for _, band := range bands {
		for rung, wantPass := range map[string]bool{
			"not-expired": band.notExpired,
			"30-day":      band.thirtyDay,
			"90-day":      band.ninetyDay,
		} {
			t.Run(band.name+"/"+rung, func(t *testing.T) {
				measurement := models.ControlMeasurement{
					ID:            uuid.New(),
					ControlID:     uuid.New(),
					FrameworkType: "platform",
					RuleType:      "threshold",
					Predicate:     certExpiryRungs[rung],
				}
				value := MeasurementValue{
					Value:       band.daysRemaining,
					SubjectID:   uuid.New(),
					SubjectType: "certificate",
				}

				gotPass, severity := evaluator.evaluateMeasurement(value, measurement, measurementType, "low")
				if gotPass != wantPass {
					t.Errorf("cert with %d days remaining against the %s rung (%v): pass=%v, want pass=%v",
						band.daysRemaining, rung, certExpiryRungs[rung], gotPass, wantPass)
				}
				if severity != "low" {
					t.Errorf("severity = %q, want the control baseline %q", severity, "low")
				}
			})
		}
	}
}

// TestCertExpiryRungsSeparateTheSameCertificate states the collapse directly:
// one certificate, three rungs, three different verdicts. If any two rungs ever
// agree on 56 days, the ladder has folded and one of the frameworks is no longer
// measuring what its name says.
func TestCertExpiryRungsSeparateTheSameCertificate(t *testing.T) {
	evaluator := &RuleEvaluator{}
	measurementType := models.MeasurementType{Code: "cert_expiration_days", DataType: "integer"}
	value := MeasurementValue{Value: 56, SubjectID: uuid.New(), SubjectType: "certificate"}

	verdicts := map[string]bool{}
	for rung, predicate := range certExpiryRungs {
		pass, _ := evaluator.evaluateMeasurement(value,
			models.ControlMeasurement{RuleType: "threshold", Predicate: predicate}, measurementType, "low")
		verdicts[rung] = pass
	}

	if !verdicts["not-expired"] || !verdicts["30-day"] {
		t.Errorf("a certificate with 56 days left must PASS not-expired and 30-day, got %+v", verdicts)
	}
	if verdicts["90-day"] {
		t.Errorf("a certificate with 56 days left must FAIL the 90-day rung, got %+v — "+
			"the rungs have collapsed into an expired-vs-not check", verdicts)
	}
}
