package autoscan

import "github.com/google/uuid"

// MaxTargetsPerJob mirrors the 1000-target cap both CreateJob implementations
// enforce. Exceeding it is not a partial failure — the whole job is refused —
// so the planner chunks rather than discovering the limit at dispatch.
const MaxTargetsPerJob = 1000

// MaxJobsPerSweep bounds what ONE tenant's sweep may queue in one tick.
//
// This is the rate limit the product definition asks for, and it is expressed
// in jobs rather than hosts because a job is what the platform sensor executes
// one of at a time. Ten jobs of a thousand addresses is ten thousand hosts a
// tick — more than any sweep should ever need — while still being a number that
// cannot run away when a tenant imports a /16 and every row in it becomes an
// asset at once. What does not fit this tick is not lost: nothing was stamped,
// so the next tick selects it first (candidates are ordered oldest-scan-first).
const MaxJobsPerSweep = 10

// Batch is one dispatchable automatic job.
type Batch struct {
	// Addresses are the bare hosts the job probes — deduplicated, because
	// cluster-sensor writes one target row per input and the same address twice
	// is the same host scanned twice for nothing.
	Addresses []string
	// AssetIDs is every asset behind those addresses. Several assets can share
	// an address (one record per service on a box), and each of them must be
	// stamped by the job that actually probed it.
	AssetIDs []uuid.UUID
	// AssetsByAddress is the same set keyed by address, for a caller that
	// splits the batch across executors and must stamp each asset by
	// the job that actually probes its address.
	AssetsByAddress map[string][]uuid.UUID
}

// AssetsFor returns every asset behind the given addresses of this batch.
func (b Batch) AssetsFor(addresses []string) []uuid.UUID {
	var out []uuid.UUID
	for _, addr := range addresses {
		out = append(out, b.AssetsByAddress[addr]...)
	}
	return out
}

// PlanSweep turns the eligible targets into jobs.
//
// `inFlight` are addresses that already have an automatic job queued or
// running; they are dropped, which is what makes a burst of 300 new hosts, a
// restart mid-sweep and an ordinary tick that overlaps the previous one all
// converge on the same bounded set of jobs instead of stacking.
//
// Returns the batches and the number of targets that did not fit the sweep's
// cap, so the caller can say so rather than reporting a clean run.
func PlanSweep(targets []Target, inFlight map[string]bool, maxJobs, maxTargetsPerJob int) (batches []Batch, deferred int) {
	if maxJobs <= 0 {
		maxJobs = MaxJobsPerSweep
	}
	if maxTargetsPerJob <= 0 || maxTargetsPerJob > MaxTargetsPerJob {
		maxTargetsPerJob = MaxTargetsPerJob
	}

	var order []string
	byAddress := map[string][]uuid.UUID{}
	for _, t := range targets {
		if t.Address == "" || inFlight[t.Address] {
			continue
		}
		if _, seen := byAddress[t.Address]; !seen {
			order = append(order, t.Address)
		}
		byAddress[t.Address] = append(byAddress[t.Address], t.AssetID)
	}

	capacity := maxJobs * maxTargetsPerJob
	if len(order) > capacity {
		for _, addr := range order[capacity:] {
			deferred += len(byAddress[addr])
		}
		order = order[:capacity]
	}

	for start := 0; start < len(order); start += maxTargetsPerJob {
		end := start + maxTargetsPerJob
		if end > len(order) {
			end = len(order)
		}
		chunk := order[start:end]
		batch := Batch{Addresses: append([]string(nil), chunk...), AssetsByAddress: make(map[string][]uuid.UUID, len(chunk))}
		for _, addr := range chunk {
			batch.AssetIDs = append(batch.AssetIDs, byAddress[addr]...)
			batch.AssetsByAddress[addr] = byAddress[addr]
		}
		batches = append(batches, batch)
	}
	return batches, deferred
}
