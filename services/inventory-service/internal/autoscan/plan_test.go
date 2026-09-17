package autoscan

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
)

func targets(addresses ...string) []Target {
	out := make([]Target, 0, len(addresses))
	for _, a := range addresses {
		out = append(out, Target{AssetID: uuid.New(), Address: a})
	}
	return out
}

func TestPlanSweep(t *testing.T) {
	t.Run("one job for a handful of hosts", func(t *testing.T) {
		batches, deferred := PlanSweep(targets("10.0.0.1", "10.0.0.2", "10.0.0.3"), nil, 0, 0)
		if len(batches) != 1 {
			t.Fatalf("got %d batches, want 1", len(batches))
		}
		if len(batches[0].Addresses) != 3 || len(batches[0].AssetIDs) != 3 {
			t.Fatalf("batch = %+v, want 3 addresses and 3 assets", batches[0])
		}
		if deferred != 0 {
			t.Errorf("deferred = %d, want 0", deferred)
		}
	})

	t.Run("an address already being scanned is skipped", func(t *testing.T) {
		// The idempotency gate. Without it, a tick that fires while the previous
		// job is still running re-queues every one of its addresses.
		batches, _ := PlanSweep(
			targets("10.0.0.1", "10.0.0.2"),
			map[string]bool{"10.0.0.1": true},
			0, 0,
		)
		if len(batches) != 1 || len(batches[0].Addresses) != 1 || batches[0].Addresses[0] != "10.0.0.2" {
			t.Fatalf("batches = %+v, want only 10.0.0.2", batches)
		}
	})

	t.Run("every address in flight means no job at all", func(t *testing.T) {
		batches, deferred := PlanSweep(
			targets("10.0.0.1"),
			map[string]bool{"10.0.0.1": true},
			0, 0,
		)
		if len(batches) != 0 {
			t.Fatalf("batches = %+v, want none", batches)
		}
		// Nothing was deferred: the address is being scanned right now, which is
		// the outcome the sweep wanted.
		if deferred != 0 {
			t.Errorf("deferred = %d, want 0", deferred)
		}
	})

	t.Run("several assets on one address are one target and both stamped", func(t *testing.T) {
		// One record per service on a box is a real shape. Probing the host
		// twice would be waste; stamping only one of the assets would leave the
		// other permanently eligible.
		a, b := uuid.New(), uuid.New()
		batches, _ := PlanSweep([]Target{
			{AssetID: a, Address: "10.0.0.9"},
			{AssetID: b, Address: "10.0.0.9"},
		}, nil, 0, 0)
		if len(batches) != 1 {
			t.Fatalf("got %d batches, want 1", len(batches))
		}
		if len(batches[0].Addresses) != 1 {
			t.Errorf("addresses = %v, want one", batches[0].Addresses)
		}
		if len(batches[0].AssetIDs) != 2 {
			t.Errorf("assets = %v, want both", batches[0].AssetIDs)
		}
	})

	t.Run("chunks at the per-job target cap", func(t *testing.T) {
		var in []Target
		for i := 0; i < 2500; i++ {
			in = append(in, Target{AssetID: uuid.New(), Address: fmt.Sprintf("10.1.%d.%d", i/256, i%256)})
		}
		batches, deferred := PlanSweep(in, nil, 0, 0)
		if len(batches) != 3 {
			t.Fatalf("got %d batches, want 3 (1000+1000+500)", len(batches))
		}
		for i, b := range batches {
			if i < 2 && len(b.Addresses) != MaxTargetsPerJob {
				t.Errorf("batch %d has %d addresses, want %d", i, len(b.Addresses), MaxTargetsPerJob)
			}
		}
		if deferred != 0 {
			t.Errorf("deferred = %d, want 0 — 2500 fits inside the sweep cap", deferred)
		}
	})

	t.Run("a burst past the sweep cap is bounded and REPORTED", func(t *testing.T) {
		// "A burst of 300 new hosts from one sweep must coalesce into a bounded
		// number of jobs." With a cap of 2 jobs × 100 targets, 300 hosts must
		// produce 2 jobs and say that 100 were left for the next tick — a sweep
		// that silently dropped them would look like a clean run.
		var in []Target
		for i := 0; i < 300; i++ {
			in = append(in, Target{AssetID: uuid.New(), Address: fmt.Sprintf("10.2.0.%d", i)})
		}
		batches, deferred := PlanSweep(in, nil, 2, 100)
		if len(batches) != 2 {
			t.Fatalf("got %d batches, want 2", len(batches))
		}
		total := 0
		for _, b := range batches {
			total += len(b.Addresses)
		}
		if total != 200 {
			t.Errorf("dispatched %d addresses, want 200", total)
		}
		if deferred != 100 {
			t.Errorf("deferred = %d, want 100", deferred)
		}
	})

	t.Run("the cap counts ASSETS deferred, not addresses", func(t *testing.T) {
		// Two assets share the address that falls outside the cap, so the
		// deferred count is 2 — it is what the operator would see missing from
		// the inventory, and addresses are an implementation detail of the job.
		in := []Target{
			{AssetID: uuid.New(), Address: "10.3.0.1"},
			{AssetID: uuid.New(), Address: "10.3.0.2"},
			{AssetID: uuid.New(), Address: "10.3.0.2"},
		}
		batches, deferred := PlanSweep(in, nil, 1, 1)
		if len(batches) != 1 || len(batches[0].Addresses) != 1 {
			t.Fatalf("batches = %+v, want one job with one address", batches)
		}
		if deferred != 2 {
			t.Errorf("deferred = %d, want 2", deferred)
		}
	})

	t.Run("an empty address is never dispatched", func(t *testing.T) {
		batches, _ := PlanSweep([]Target{{AssetID: uuid.New(), Address: ""}}, nil, 0, 0)
		if len(batches) != 0 {
			t.Fatalf("batches = %+v, want none", batches)
		}
	})

	t.Run("nothing eligible means no job", func(t *testing.T) {
		batches, deferred := PlanSweep(nil, nil, 0, 0)
		if len(batches) != 0 || deferred != 0 {
			t.Fatalf("got %d batches / %d deferred, want 0/0", len(batches), deferred)
		}
	})
}

// A caller passing a per-job cap above what CreateJob accepts must not be able
// to build a job the dispatcher will refuse whole.
func TestPlanSweep_ClampsAnOversizedPerJobCap(t *testing.T) {
	var in []Target
	for i := 0; i < 1500; i++ {
		in = append(in, Target{AssetID: uuid.New(), Address: fmt.Sprintf("10.4.%d.%d", i/256, i%256)})
	}
	batches, _ := PlanSweep(in, nil, 5, 99999)
	if len(batches) != 2 {
		t.Fatalf("got %d batches, want 2 — the per-job cap must clamp to %d", len(batches), MaxTargetsPerJob)
	}
	if len(batches[0].Addresses) != MaxTargetsPerJob {
		t.Errorf("first batch has %d addresses, want %d", len(batches[0].Addresses), MaxTargetsPerJob)
	}
}
