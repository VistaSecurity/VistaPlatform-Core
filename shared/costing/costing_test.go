package costing

import (
	"math"
	"slices"
	"testing"
	"time"
)

const epsilon = 1e-12

func closeTo(t *testing.T, got, want float64, what string) {
	t.Helper()
	if math.Abs(got-want) > epsilon {
		t.Fatalf("%s = %v, want %v", what, got, want)
	}
}

// TestCompute_TotalIsExactlyTheSumOfComponents is the invariant that ends the
// headline-vs-breakdown contradiction. Every read path renders TotalUSD as the
// headline and Components as the rows beneath it, so if this holds they cannot
// disagree.
func TestCompute_TotalIsExactlyTheSumOfComponents(t *testing.T) {
	cases := []struct {
		name string
		u    Usage
	}{
		{"all measured", Usage{
			Window:          720 * time.Hour,
			APICalls:        Int64(1_000_000),
			DatabaseQueries: Int64(2_500_000),
			NetworkBytes:    Int64(42 * bytesPerGB),
			StorageBytes:    Float64(3 * bytesPerGB),
		}},
		{"only api calls measured", Usage{
			Window:   24 * time.Hour,
			APICalls: Int64(17),
		}},
		{"nothing measured", Usage{Window: time.Hour}},
		{"measured zeroes", Usage{
			Window:          time.Hour,
			APICalls:        Int64(0),
			DatabaseQueries: Int64(0),
			NetworkBytes:    Int64(0),
			StorageBytes:    Float64(0),
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := Compute(tc.u, DefaultRates())

			var sum float64
			for _, v := range b.Components {
				sum += v
			}
			closeTo(t, b.TotalUSD, sum, "TotalUSD vs sum(Components)")
		})
	}
}

// TestCompute_UnitConversions pins the conversions the four superseded
// implementations got wrong: a per-GB rate must be applied to gigabytes, and a
// per-GB-month rate must be prorated by the window.
func TestCompute_UnitConversions(t *testing.T) {
	r := DefaultRates()

	t.Run("network is priced per GB, not per MB", func(t *testing.T) {
		b := Compute(Usage{NetworkBytes: Int64(bytesPerGB)}, r)
		closeTo(t, b.Components[ComponentNetwork], r.PerNetworkGB, "one GB of network")

		// The superseded formula divided by 1024^2 and would have produced
		// 1024x this. Guard the magnitude explicitly.
		wrong := float64(bytesPerGB) / (1024 * 1024) * r.PerNetworkGB
		if math.Abs(b.Components[ComponentNetwork]-wrong) < epsilon {
			t.Fatal("network cost still matches the per-MB formula")
		}
	})

	t.Run("storage is priced per GB-month and prorated", func(t *testing.T) {
		// One GB held for a full average month costs exactly the monthly rate.
		full := Compute(Usage{
			Window:       hoursPerMonth * time.Hour,
			StorageBytes: Float64(bytesPerGB),
		}, r)
		closeTo(t, full.Components[ComponentStorage], r.PerStorageGBMonth, "one GB for one month")

		// The same GB held for one hour costs 1/730th of that.
		hour := Compute(Usage{
			Window:       time.Hour,
			StorageBytes: Float64(bytesPerGB),
		}, r)
		closeTo(t, hour.Components[ComponentStorage], r.PerStorageGBMonth/hoursPerMonth, "one GB for one hour")

		if hour.Components[ComponentStorage] >= full.Components[ComponentStorage] {
			t.Fatal("a one-hour window is not cheaper than a one-month window: proration is not applied")
		}
	})

	t.Run("per-unit components scale linearly", func(t *testing.T) {
		b := Compute(Usage{APICalls: Int64(10_000), DatabaseQueries: Int64(10_000)}, r)
		closeTo(t, b.Components[ComponentAPICalls], 10_000*r.PerAPICall, "api calls")
		closeTo(t, b.Components[ComponentDatabase], 10_000*r.PerDatabaseQuery, "database")
	})
}

// TestCompute_NilIsNotMeasuredZeroIsAMeasurement is the honesty rule:
// an absent measurement must never be rendered as a confident number.
func TestCompute_NilIsNotMeasuredZeroIsAMeasurement(t *testing.T) {
	t.Run("nil input omits the component and names it", func(t *testing.T) {
		b := Compute(Usage{Window: time.Hour}, DefaultRates())

		for _, name := range []string{ComponentAPICalls, ComponentDatabase, ComponentStorage, ComponentNetwork} {
			if _, present := b.Components[name]; present {
				t.Fatalf("%s was priced despite having no measurement", name)
			}
			if !slices.Contains(b.NotMeasured, name) {
				t.Fatalf("%s is neither priced nor declared not-measured — it vanished silently", name)
			}
		}
		closeTo(t, b.TotalUSD, 0, "total with nothing measured")
	})

	t.Run("measured zero is priced, not hidden", func(t *testing.T) {
		b := Compute(Usage{Window: time.Hour, APICalls: Int64(0)}, DefaultRates())

		v, present := b.Components[ComponentAPICalls]
		if !present {
			t.Fatal("a measured zero was dropped: zero is an answer, absent is not")
		}
		closeTo(t, v, 0, "zero api calls")
		if slices.Contains(b.NotMeasured, ComponentAPICalls) {
			t.Fatal("a measured zero was reported as not measured")
		}
	})
}

// TestCompute_ComputeComponentIsNeverFabricated pins the deletion of the
// `compute: total * 0.3` fabrication and of the "AVG(cpu_percent) * rate"
// formula. There is no per-tenant CPU measurement on shared pods, so compute
// must always be declared unmeasured — whatever else is priced.
func TestCompute_ComputeComponentIsNeverFabricated(t *testing.T) {
	rich := Usage{
		Window:          720 * time.Hour,
		APICalls:        Int64(50_000_000),
		DatabaseQueries: Int64(50_000_000),
		NetworkBytes:    Int64(9_000 * bytesPerGB),
		StorageBytes:    Float64(4_000 * bytesPerGB),
	}
	b := Compute(rich, DefaultRates())

	if _, present := b.Components[ComponentCompute]; present {
		t.Fatal("compute was priced: there is no per-tenant CPU measurement to price")
	}
	if !slices.Contains(b.NotMeasured, ComponentCompute) {
		t.Fatal("compute is not declared not-measured")
	}

	// The retired fabrication was 30% of the total. Assert nothing in the
	// result equals it, so a reintroduction under any component name fails.
	fabricated := b.TotalUSD * 0.3
	for name, v := range b.Components {
		if math.Abs(v-fabricated) < epsilon && fabricated > epsilon {
			t.Fatalf("component %q equals 30%% of the total — the fabrication is back", name)
		}
	}
}

// TestCompute_StorageNeedsAWindow pins that an unprorateable storage figure is
// declared unmeasured rather than charged a whole month by accident.
func TestCompute_StorageNeedsAWindow(t *testing.T) {
	b := Compute(Usage{StorageBytes: Float64(bytesPerGB)}, DefaultRates())

	if _, present := b.Components[ComponentStorage]; present {
		t.Fatal("storage was priced with no window to prorate against")
	}
	if !slices.Contains(b.NotMeasured, ComponentStorage) {
		t.Fatal("windowless storage is not declared not-measured")
	}
}
