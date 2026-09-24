package services

import (
	"errors"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/riskbands"
)

// Decision 12 (RC-38): marking an algorithm obsolete makes it grade Critical,
// and undoing it restores the score it had. These pin every branch of the pure
// planner; algorithm_obsolete_floor_integration_test.go drives the same rule
// through the real handler and a real Postgres.

func obsoletePtr(s string) *string { return &s }

func TestObsoleteRiskFloor_IsTheCriticalBandFromSharedRiskbands(t *testing.T) {
	want, ok := riskbands.RiskBandMin("Critical")
	if !ok {
		t.Fatal("shared/riskbands has no Critical band")
	}
	if got := ObsoleteRiskFloor(); got != want {
		t.Fatalf("ObsoleteRiskFloor() = %d, want the Critical band minimum %d", got, want)
	}
	if riskbands.GetRiskLevel(ObsoleteRiskFloor()) != "Critical" {
		t.Fatalf("a score at the floor must band Critical, got %s", riskbands.GetRiskLevel(ObsoleteRiskFloor()))
	}
	if riskbands.GetRiskLevel(ObsoleteRiskFloor()-1) == "Critical" {
		t.Fatal("the floor must be the LOWEST Critical score, not an arbitrary Critical one")
	}
}

func TestPlanObsoleteRisk(t *testing.T) {
	floor := ObsoleteRiskFloor()
	low, high := floor-50, floor+5
	explicit := floor - 20

	cases := []struct {
		name        string
		cur         obsoleteRiskState
		reqStatus   *string
		reqRisk     *int
		wantWrite   bool
		wantRisk    *int
		wantRecord  obsoleteRecordAction
		wantPrior   *int
		wantTrans   string
		wantErrIsFl bool
	}{
		{
			name:      "entering obsolete raises a low score to the floor and remembers it",
			cur:       obsoleteRiskState{Status: "current", RiskScore: &low},
			reqStatus: obsoletePtr("obsolete"),
			wantWrite: true, wantRisk: &floor, wantRecord: obsoleteRecordSet, wantPrior: &low,
			wantTrans: ObsoleteTransitionEntered,
		},
		{
			name:      "entering obsolete keeps a score already above the floor",
			cur:       obsoleteRiskState{Status: "deprecated", RiskScore: &high},
			reqStatus: obsoletePtr("obsolete"),
			wantWrite: true, wantRisk: &high, wantRecord: obsoleteRecordSet, wantPrior: &high,
			wantTrans: ObsoleteTransitionEntered,
		},
		{
			name:      "entering obsolete from unassessed grades Critical and remembers NULL",
			cur:       obsoleteRiskState{Status: "current"},
			reqStatus: obsoletePtr("obsolete"),
			wantWrite: true, wantRisk: &floor, wantRecord: obsoleteRecordSet, wantPrior: nil,
			wantTrans: ObsoleteTransitionEntered,
		},
		{
			name:      "entering obsolete with an explicit score remembers the explicit one",
			cur:       obsoleteRiskState{Status: "current", RiskScore: &low},
			reqStatus: obsoletePtr("obsolete"), reqRisk: &explicit,
			wantWrite: true, wantRisk: &floor, wantRecord: obsoleteRecordSet, wantPrior: &explicit,
			wantTrans: ObsoleteTransitionEntered,
		},
		{
			name:      "leaving obsolete restores the remembered score",
			cur:       obsoleteRiskState{Status: "obsolete", RiskScore: &floor, FloorApplied: true, PriorScore: &low},
			reqStatus: obsoletePtr("current"),
			wantWrite: true, wantRisk: &low, wantRecord: obsoleteRecordClear,
			wantTrans: ObsoleteTransitionRestored,
		},
		{
			name:      "leaving obsolete restores a remembered NULL (unassessed)",
			cur:       obsoleteRiskState{Status: "obsolete", RiskScore: &floor, FloorApplied: true},
			reqStatus: obsoletePtr("deprecated"),
			wantWrite: true, wantRisk: nil, wantRecord: obsoleteRecordClear,
			wantTrans: ObsoleteTransitionRestored,
		},
		{
			name:      "leaving obsolete with an explicit score uses it and spends the memory",
			cur:       obsoleteRiskState{Status: "obsolete", RiskScore: &floor, FloorApplied: true, PriorScore: &low},
			reqStatus: obsoletePtr("current"), reqRisk: &explicit,
			wantWrite: true, wantRisk: &explicit, wantRecord: obsoleteRecordClear,
			wantTrans: ObsoleteTransitionExplicit,
		},
		{
			name:      "leaving an obsolete row with nothing remembered (seeded) leaves its score",
			cur:       obsoleteRiskState{Status: "obsolete", RiskScore: &high},
			reqStatus: obsoletePtr("current"),
			wantTrans: ObsoleteTransitionLeftKept,
		},
		{
			name:        "staying obsolete refuses a score below the floor",
			cur:         obsoleteRiskState{Status: "obsolete", RiskScore: &floor, FloorApplied: true, PriorScore: &low},
			reqRisk:     &explicit,
			wantErrIsFl: true,
		},
		{
			name:    "staying obsolete accepts a score at or above the floor through the normal path",
			cur:     obsoleteRiskState{Status: "obsolete", RiskScore: &floor},
			reqRisk: &high,
		},
		{
			name:      "an edit that never touches obsolete changes nothing extra",
			cur:       obsoleteRiskState{Status: "current", RiskScore: &low},
			reqStatus: obsoletePtr("deprecated"), reqRisk: &explicit,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := planObsoleteRisk(tc.cur, tc.reqStatus, tc.reqRisk)
			if tc.wantErrIsFl {
				if !errors.Is(err, ErrObsoleteRiskBelowFloor) {
					t.Fatalf("err = %v, want ErrObsoleteRiskBelowFloor", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if plan.WriteRisk != tc.wantWrite {
				t.Fatalf("WriteRisk = %v, want %v", plan.WriteRisk, tc.wantWrite)
			}
			if !sameIntPtr(plan.Risk, tc.wantRisk) {
				t.Fatalf("Risk = %v, want %v", derefOrNil(plan.Risk), derefOrNil(tc.wantRisk))
			}
			if plan.Record != tc.wantRecord {
				t.Fatalf("Record = %v, want %v", plan.Record, tc.wantRecord)
			}
			if tc.wantRecord == obsoleteRecordSet && !sameIntPtr(plan.Prior, tc.wantPrior) {
				t.Fatalf("Prior = %v, want %v", derefOrNil(plan.Prior), derefOrNil(tc.wantPrior))
			}
			if plan.Transition != tc.wantTrans {
				t.Fatalf("Transition = %q, want %q", plan.Transition, tc.wantTrans)
			}
		})
	}
}

func TestPlanObsoleteRiskForCreate(t *testing.T) {
	floor := ObsoleteRiskFloor()
	plan := planObsoleteRiskForCreate(obsoletePtr("obsolete"), 12)
	if plan.Record != obsoleteRecordSet || plan.Risk == nil || *plan.Risk != floor || plan.Prior == nil || *plan.Prior != 12 {
		t.Fatalf("create as obsolete: %+v, want risk %d remembered 12", plan, floor)
	}
	if plan := planObsoleteRiskForCreate(nil, 12); plan.Record != obsoleteRecordKeep || plan.WriteRisk {
		t.Fatalf("create with default status must not touch the score: %+v", plan)
	}
}

func sameIntPtr(a, b *int) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func derefOrNil(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}
