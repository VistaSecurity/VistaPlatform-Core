package identity

import (
	"math"
	"strings"
	"testing"
)

func powerTestInt(n int) *int           { return &n }
func powerTestFloat(f float64) *float64 { return &f }

// NormalizeObservedPower keeps what the schema can hold and reports the rest:
// names bounded and unique, an outlet's power port only when the observation
// lists it, legs / states inside their lists, readings inside the columns'
// ranges (a misread is dropped, never clamped).
//
// Mutation: drop the portNames check → the dangling power port survives, red;
// accept a negative watt reading → red.
func TestNormalizeObservedPower(t *testing.T) {
	long := strings.Repeat("x", 65)
	ports, outlets, dropped := NormalizeObservedPower(
		[]ObservedPowerPort{
			{Name: " Input ", Number: 1, MeasuredDraw: powerTestInt(1230), MeasuredCurrent: powerTestFloat(5.456),
				Legs: []ObservedPowerLeg{{Leg: "a", MeasuredDraw: powerTestInt(400)}, {Leg: "A", MeasuredDraw: powerTestInt(1)}, {Leg: "N", MeasuredDraw: powerTestInt(9)}, {Leg: "B"}}},
			{Name: "Input"},
			{Name: long},
			{Name: "Bad", MeasuredDraw: powerTestInt(-5), MeasuredCurrent: powerTestFloat(math.NaN()), Number: 99999},
		},
		[]ObservedPowerOutlet{
			{Name: "Outlet 1", Number: 1, PowerPort: "Input", FeedLeg: "b", State: "ON", MeasuredDraw: powerTestInt(40)},
			{Name: "Outlet 2", PowerPort: "Elsewhere", FeedLeg: "Z", State: "faulty"},
			{Name: "Outlet 1"},
			{Name: ""},
		})
	if len(ports) != 2 || ports[0].Name != "Input" || ports[1].Name != "Bad" {
		t.Fatalf("ports %+v", ports)
	}
	p := ports[0]
	if *p.MeasuredCurrent != 5.46 || len(p.Legs) != 1 || p.Legs[0].Leg != "A" || *p.Legs[0].MeasuredDraw != 400 {
		t.Errorf("input %+v legs %+v", p, p.Legs)
	}
	if ports[1].MeasuredDraw != nil || ports[1].MeasuredCurrent != nil || ports[1].Number != 0 {
		t.Errorf("misreads kept: %+v", ports[1])
	}
	if len(outlets) != 2 {
		t.Fatalf("outlets %+v", outlets)
	}
	if o := outlets[0]; o.PowerPort != "Input" || o.FeedLeg != "B" || o.State != "on" || *o.MeasuredDraw != 40 {
		t.Errorf("outlet 1 %+v", o)
	}
	if o := outlets[1]; o.PowerPort != "" || o.FeedLeg != "" || o.State != "" {
		t.Errorf("outlet 2 kept what the schema cannot hold: %+v", o)
	}
	if len(dropped) != 2 {
		t.Errorf("dropped %v; want the over-long port and the unnamed outlet", dropped)
	}
}
