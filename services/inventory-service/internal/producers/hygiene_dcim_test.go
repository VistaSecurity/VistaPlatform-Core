package producers

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/findings"
)

// Every DCIM kind's customer-facing guidance names the page the fix is made
// on — the finding is a worklist entry, and one that does not say where to go
// is a puzzle. Registered, asset-subject, feeds_risk false and score 0, like
// every hygiene kind.
func TestDCIMHygieneKindsNameTheirPage(t *testing.T) {
	pages := map[string]string{
		findings.KindNotRacked:         "Infrastructure → Racks",
		findings.KindNoRackPosition:    "Infrastructure → Racks",
		findings.KindPlannedCableStale: "Ports tab",
		findings.KindCableUnconfirmed:  "Ports tab",
		findings.KindInterfaceNoType:   "Interfaces tab",
		findings.KindDuplicateAddress:  "Infrastructure → Networks",
		findings.KindWarrantyExpired:   "Lifecycle card",
		findings.KindPastEndOfSupport:  "Lifecycle card",
		findings.KindEndOfSupportSoon:  "Lifecycle card",
	}
	for kind, page := range pages {
		k, ok := findings.Get(findings.ProducerHygiene, kind)
		if !ok {
			t.Errorf("%s is not a registered hygiene kind", kind)
			continue
		}
		if !strings.Contains(k.Guidance, page) {
			t.Errorf("%s guidance does not name %q: %s", kind, page, k.Guidance)
		}
		if k.FeedsRisk || k.Score != 0 {
			t.Errorf("%s: feeds_risk=%v score=%d; a hygiene kind never feeds risk", kind, k.FeedsRisk, k.Score)
		}
		if len(k.SubjectTypes) != 1 || k.SubjectTypes[0] != findings.SubjectAsset {
			t.Errorf("%s subject types %v, want [asset]: the IH controls count per asset", kind, k.SubjectTypes)
		}
	}
}

// The lifecycle kinds come from ComputeAssetLifecycle's states and nothing
// else: unknown raises nothing, past and within-12-months are exclusive.
func TestLifecycleHitsFollowComputeAssetLifecycle(t *testing.T) {
	today := time.Date(2026, 10, 20, 15, 0, 0, 0, time.UTC)
	d := func(y int, m time.Month, day int) *time.Time {
		v := time.Date(y, m, day, 0, 0, 0, 0, time.UTC)
		return &v
	}
	id := uuid.New()
	cases := []struct {
		name string
		in   services.LifecycleInputs
		want []string
	}{
		{"nothing recorded", services.LifecycleInputs{}, nil},
		{"warranty ended yesterday", services.LifecycleInputs{WarrantyEnd: d(2026, 10, 19)}, []string{findings.KindWarrantyExpired}},
		{"warranty ends today still covers today", services.LifecycleInputs{WarrantyEnd: d(2026, 10, 20)}, nil},
		{"device type past", services.LifecycleInputs{DeviceType: services.EOSCandidate{Declared: d(2025, 1, 1)}}, []string{findings.KindPastEndOfSupport}},
		{"platform catalogue within 12 months", services.LifecycleInputs{Platform: services.EOSCandidate{Catalogue: d(2027, 3, 1)}}, []string{findings.KindEndOfSupportSoon}},
		{"earlier of the two wins", services.LifecycleInputs{
			DeviceType: services.EOSCandidate{Declared: d(2031, 1, 1)},
			Platform:   services.EOSCandidate{Declared: d(2026, 1, 1)}}, []string{findings.KindPastEndOfSupport}},
		{"supported beyond 12 months", services.LifecycleInputs{DeviceType: services.EOSCandidate{Declared: d(2030, 1, 1)}}, nil},
		{"both", services.LifecycleInputs{WarrantyEnd: d(2020, 1, 1), DeviceType: services.EOSCandidate{Declared: d(2026, 12, 1)}},
			[]string{findings.KindWarrantyExpired, findings.KindEndOfSupportSoon}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lc := services.ComputeAssetLifecycle(c.in, today)
			w := ""
			if c.in.WarrantyEnd != nil {
				w = c.in.WarrantyEnd.Format("2006-01-02")
			}
			hits := lifecycleHits(id, w, lc)
			var got []string
			for _, h := range hits {
				got = append(got, h.kind)
				if h.assetID != id || h.detail == "" {
					t.Errorf("%s: hit %+v lacks its asset or detail", h.kind, h)
				}
			}
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Errorf("kinds %v, want %v (lifecycle %+v)", got, c.want, lc)
			}
		})
	}
	if models.EOSUnknown == models.EOSPastEOS {
		t.Fatal("unreachable: the state words collapsed")
	}
}

// One finding per asset, an exact count and a bounded list.
func TestAssetGroupsCountExactlyAndCapTheList(t *testing.T) {
	g := newAssetGroups()
	a, b := uuid.New(), uuid.New()
	for i := 0; i < dcimEvidenceCap+5; i++ {
		g.add(a, map[string]any{"i": i})
	}
	g.add(b, map[string]any{"i": 0})
	hits := g.hits(findings.KindInterfaceNoType, "interface", "interfaces", "interfaces")
	if len(hits) != 2 || hits[0].assetID != a || hits[1].assetID != b {
		t.Fatalf("hits %+v, want one per asset in read order", hits)
	}
	if hits[0].evidence["count"] != dcimEvidenceCap+5 || len(hits[0].evidence["interfaces"].([]map[string]any)) != dcimEvidenceCap ||
		hits[0].evidence["truncated"] != true {
		t.Errorf("capped evidence wrong: count=%v truncated=%v", hits[0].evidence["count"], hits[0].evidence["truncated"])
	}
	if hits[1].detail != "1 interface" || hits[1].evidence["truncated"] != false {
		t.Errorf("single hit detail %q truncated=%v", hits[1].detail, hits[1].evidence["truncated"])
	}
}
