package pipelinetest

// The scheduled-cloud chain (integrations review W14).
//
// The same three hops as the vendor chain, for the platform worker's scheduled
// cloud discovery rather than a device interrogation: hop 1 runs the worker
// against a fake provider and records the sensor_discoveries rows of TWO runs
// of the same discovery; hop 2 runs ProcessBatch over each run's rows; hop 3
// replays each run's import requests into a tenant in ENFORCE identity
// admission. What it proves end to end is the thing the scheduled path could
// not do: an at-rest resource (a bucket, a database) becomes an asset of the
// right class on the first run, and the second run matches the same asset.
//
// It lives in its own directory beside the vendors and is not in [Vendors]:
// the vendor harness builds appliances and devices this chain has none of.

// CloudScheduledScenario is the chain's directory under the pipeline testdata.
const CloudScheduledScenario = "cloud-aws-scheduled"

// PlaceholderIntegrationID stands in for the cloud integration's id, which
// every cloud row carries.
const PlaceholderIntegrationID = "{{INTEGRATION_ID}}"

// CloudHop1Handoff is hop 1's golden: each run's rows, in a stable order.
type CloudHop1Handoff struct {
	Scenario string                 `json:"scenario"`
	Runs     [][]SensorDiscoveryRow `json:"runs"`
}

// CloudHop2Run is what ProcessBatch posted for one run's batch.
type CloudHop2Run struct {
	Imports      []ImportRequest `json:"imports"`
	Rows         []RowOutcome    `json:"rows"`
	ProcessError string          `json:"process_error"`
}

// CloudHop2Handoff is hop 2's golden and hop 3's input.
type CloudHop2Handoff struct {
	Scenario    string         `json:"scenario"`
	InputSHA256 string         `json:"input_sha256"`
	Runs        []CloudHop2Run `json:"runs"`
}
