// Package costing is the single source of unit prices and the single costing
// formula for tenant resource usage.
//
// Before this package there were four independent implementations of "what
// does this tenant's usage cost": the resource-tracker persister, the
// resource-tracker repository, the admin cost-monitoring breakdown, and a
// platform rollup that fabricated compute as 30% of the total. They disagreed
// on unit conversion (a per-GB rate applied per MB is a 1024x error), on
// aggregation (SUM of a point-in-time gauge multiplies by the sample count),
// and on whether a component was billable at all. The user-visible symptom was
// a "Current period cost" headline and an itemised breakdown directly beneath
// it that differed by orders of magnitude.
//
// Two rules keep that from coming back:
//
//  1. Every read path computes its headline AND its itemisation from one
//     Compute call, so the two cannot diverge by construction.
//  2. An input that is not measured is nil, never zero. A component with no
//     measurement is absent from Components and named in NotMeasured. We do
//     not price a number we did not observe.
package costing

import "time"

// Component names. These are the keys of Breakdown.Components and the values
// in Breakdown.NotMeasured, so producers, consumers and tests share one
// vocabulary.
const (
	ComponentAPICalls = "api_calls"
	ComponentDatabase = "database"
	ComponentStorage  = "storage"
	ComponentNetwork  = "network"
	ComponentCompute  = "compute"
)

// bytesPerGB is 2^30 — the binary gigabyte, matching how the platform reports
// stored and transferred bytes elsewhere.
const bytesPerGB = 1024 * 1024 * 1024

// hoursPerMonth is the average month (8760 h / 12). Storage is rated per
// GB-month, so a window shorter than a month is prorated by this constant
// rather than charged a whole month's rate.
const hoursPerMonth = 730.0

// Rates are the platform's unit prices in USD.
//
// The unit is part of every field name on purpose: the defect this package
// replaces was a PerStorageGBMonth rate multiplied by a megabyte count.
type Rates struct {
	PerAPICall        float64 // USD per API call
	PerDatabaseQuery  float64 // USD per database query
	PerStorageGBMonth float64 // USD per GB stored for one month
	PerNetworkGB      float64 // USD per GB transferred
}

// DefaultRates returns the platform's standard unit prices. These are the same
// numbers the four superseded implementations used; only their application is
// corrected here.
func DefaultRates() Rates {
	return Rates{
		PerAPICall:        0.0001,
		PerDatabaseQuery:  0.00005,
		PerStorageGBMonth: 0.023,
		PerNetworkGB:      0.09,
	}
}

// Usage carries the measured inputs for exactly one costing window.
//
// A nil field means NOT MEASURED. A non-nil zero means "measured, and it was
// zero". Callers must preserve that distinction all the way from the query:
// COALESCE(SUM(x), 0) destroys it, which is how a tenant with no storage
// measurement at all came to be priced as though it stored a definite amount.
//
// Each field documents its aggregation, and there is exactly one per field:
//
//   - counters (API calls, queries, transferred bytes) are SUMMED over Window
//   - gauges (bytes currently stored) are AVERAGED over the samples in Window
type Usage struct {
	// Window is the period the aggregates cover. Required to price storage,
	// which is rated per GB-month; ignored by the per-unit components.
	Window time.Duration

	// APICalls is the SUM of API calls over Window.
	APICalls *int64
	// DatabaseQueries is the SUM of database queries over Window.
	DatabaseQueries *int64
	// NetworkBytes is the SUM of bytes transferred over Window.
	NetworkBytes *int64
	// StorageBytes is the MEAN of bytes stored across the samples in Window.
	// It is a gauge: summing it multiplies the answer by the sample count.
	StorageBytes *float64
}

// Breakdown is the result of pricing a Usage. Components holds only the
// components that were actually measured; NotMeasured names the rest, so a
// consumer can say "not measured" instead of showing a confident zero.
//
// TotalUSD is the sum of Components — that is, of the measured components
// only. It is deliberately NOT an estimate of the true total: a partial number
// that declares which parts are missing is honest; a whole number extrapolated
// from a fraction is not.
type Breakdown struct {
	Components  map[string]float64 `json:"components"`
	NotMeasured []string           `json:"not_measured"`
	TotalUSD    float64            `json:"total_usd"`
}

// Compute prices u at r.
//
// The compute component is ALWAYS reported as not measured. The platform runs
// shared service pods; there is no per-tenant pod whose CPU or memory can be
// read, and no agreed model for attributing shared infrastructure to a tenant.
// Until that product decision is made there is nothing here to price, and
// reporting a plausible constant instead would be a fabrication.
func Compute(u Usage, r Rates) Breakdown {
	b := Breakdown{Components: map[string]float64{}}

	add := func(name string, cost float64) {
		b.Components[name] = cost
		b.TotalUSD += cost
	}

	if u.APICalls != nil {
		add(ComponentAPICalls, float64(*u.APICalls)*r.PerAPICall)
	} else {
		b.NotMeasured = append(b.NotMeasured, ComponentAPICalls)
	}

	if u.DatabaseQueries != nil {
		add(ComponentDatabase, float64(*u.DatabaseQueries)*r.PerDatabaseQuery)
	} else {
		b.NotMeasured = append(b.NotMeasured, ComponentDatabase)
	}

	// Storage is rated per GB-month, so it needs both a quantity and a window.
	// A zero window cannot be prorated, so the component stays unmeasured
	// rather than silently collapsing to a whole month or to nothing.
	if u.StorageBytes != nil && u.Window > 0 {
		gb := *u.StorageBytes / bytesPerGB
		months := u.Window.Hours() / hoursPerMonth
		add(ComponentStorage, gb*r.PerStorageGBMonth*months)
	} else {
		b.NotMeasured = append(b.NotMeasured, ComponentStorage)
	}

	if u.NetworkBytes != nil {
		gb := float64(*u.NetworkBytes) / bytesPerGB
		add(ComponentNetwork, gb*r.PerNetworkGB)
	} else {
		b.NotMeasured = append(b.NotMeasured, ComponentNetwork)
	}

	// See the doc comment: compute is not attributable per tenant today.
	b.NotMeasured = append(b.NotMeasured, ComponentCompute)

	return b
}

// Int64 returns a pointer to v. It lets callers express "measured, and the
// value is v" without a local variable at every call site.
func Int64(v int64) *int64 { return &v }

// Float64 returns a pointer to v.
func Float64(v float64) *float64 { return &v }
