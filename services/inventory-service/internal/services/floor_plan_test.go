package services

import (
	"errors"
	"math"
	"strings"
	"testing"
)

func fpF64(v float64) *float64 { return &v }
func fpStr(v string) *string   { return &v }

func fpNear(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// A rack's footprint in the plan's unit, from mm or in, with the default
// standing in for a side that is not recorded.
func TestRackFootprint(t *testing.T) {
	cases := []struct {
		name          string
		w, d          *float64
		unit          *string
		plan          string
		wantW, wantD  float64
		wantDefaulted bool
	}{
		{"mm to m", fpF64(600), fpF64(1200), fpStr("mm"), "m", 0.6, 1.2, false},
		{"in to ft", fpF64(24), fpF64(48), fpStr("in"), "ft", 2, 4, false},
		{"mm to ft", fpF64(304.8), fpF64(609.6), fpStr("mm"), "ft", 1, 2, false},
		{"in to m", fpF64(100), fpF64(10), fpStr("in"), "m", 2.54, 0.254, false},
		{"nothing recorded", nil, nil, nil, "m", 0.6, 1.0, true},
		{"depth missing", fpF64(800), nil, fpStr("mm"), "m", 0.8, 1.0, true},
		{"zero is not a size", fpF64(0), fpF64(1000), fpStr("mm"), "m", 0.6, 1.0, true},
	}
	for _, c := range cases {
		w, d, def := RackFootprint(c.w, c.d, c.unit, c.plan)
		if !fpNear(w, c.wantW) || !fpNear(d, c.wantD) || def != c.wantDefaulted {
			t.Errorf("%s: got %v x %v default=%v, want %v x %v default=%v", c.name, w, d, def, c.wantW, c.wantD, c.wantDefaulted)
		}
	}
}

// A quarter turn swaps the footprint's sides on the plan; a half turn does not.
func TestFloorExtentRotation(t *testing.T) {
	for _, c := range []struct {
		rot    int
		ex, ey float64
	}{{0, 0.6, 1.2}, {90, 1.2, 0.6}, {180, 0.6, 1.2}, {270, 1.2, 0.6}} {
		ex, ey := FloorExtent(0.6, 1.2, c.rot)
		if ex != c.ex || ey != c.ey {
			t.Errorf("rotation %d: extent %v x %v, want %v x %v", c.rot, ex, ey, c.ex, c.ey)
		}
	}
}

// The footprint, centred at (x, y) and turned, must lie inside the plan:
// touching an edge fits, crossing it by a hair does not, and a quarter turn
// moves which edges bind.
func TestFloorFitProblem(t *testing.T) {
	plan := FloorPlanSize{Width: 10, Depth: 8, Unit: "m"}
	fits := []struct {
		x, y float64
		rot  int
	}{
		{5, 4, 0}, {0.3, 0.6, 0}, {9.7, 7.4, 0}, {0.6, 0.3, 90}, {9.4, 7.7, 270}, {0.3, 0.6, 180},
	}
	for _, c := range fits {
		if p := FloorFitProblem(plan, c.x, c.y, 0.6, 1.2, c.rot); p != "" {
			t.Errorf("(%v, %v) rot %d should fit: %s", c.x, c.y, c.rot, p)
		}
	}
	misses := []struct {
		x, y float64
		rot  int
	}{
		{0.29, 0.6, 0}, {9.71, 4, 0}, {5, 0.59, 0}, {5, 7.41, 0},
		{0.3, 0.6, 90}, // unturned it fits; turned, its long side crosses the left edge
		{5, 7.75, 270}, // turned, 0.3 each side of y: 8.05 > 8
	}
	for _, c := range misses {
		if p := FloorFitProblem(plan, c.x, c.y, 0.6, 1.2, c.rot); p == "" {
			t.Errorf("(%v, %v) rot %d should not fit", c.x, c.y, c.rot)
		} else if !strings.Contains(p, "edge") {
			t.Errorf("(%v, %v) rot %d: problem %q does not name the edge", c.x, c.y, c.rot, p)
		}
	}
	if p := FloorFitProblem(FloorPlanSize{Width: 1, Depth: 1, Unit: "m"}, 0.5, 0.5, 0.6, 1.2, 0); !strings.Contains(p, "larger than the floor plan") {
		t.Errorf("a footprint bigger than the plan: %q", p)
	}
}

// A plan is all three of width, depth and unit, or none; sides are above 0
// and at most FloorPlanMaxSide; values round to the stored two decimals.
func TestValidateFloorPlanSize(t *testing.T) {
	if p, err := ValidateFloorPlanSize(nil, nil, nil); p != nil || err != nil {
		t.Errorf("none: %v %v", p, err)
	}
	if p, err := ValidateFloorPlanSize(nil, nil, fpStr("  ")); p != nil || err != nil {
		t.Errorf("blank unit alone is none: %v %v", p, err)
	}
	p, err := ValidateFloorPlanSize(fpF64(12.345), fpF64(8), fpStr("ft"))
	if err != nil || p == nil || p.Width != 12.35 || p.Depth != 8 || p.Unit != "ft" {
		t.Errorf("valid: %+v %v", p, err)
	}
	for name, in := range map[string][3]any{
		"width alone":  {fpF64(5), nil, nil},
		"no unit":      {fpF64(5), fpF64(5), nil},
		"bad unit":     {fpF64(5), fpF64(5), fpStr("yd")},
		"zero width":   {fpF64(0), fpF64(5), fpStr("m")},
		"negative":     {fpF64(5), fpF64(-1), fpStr("m")},
		"too large":    {fpF64(10000.01), fpF64(5), fpStr("m")},
		"rounds to 0":  {fpF64(0.001), fpF64(5), fpStr("m")},
		"missing deep": {fpF64(5), nil, fpStr("m")},
	} {
		w, _ := in[0].(*float64)
		d, _ := in[1].(*float64)
		u, _ := in[2].(*string)
		if _, err := ValidateFloorPlanSize(w, d, u); !errors.Is(err, ErrSiteInvalid) {
			t.Errorf("%s: err %v, want ErrSiteInvalid", name, err)
		}
	}
}
