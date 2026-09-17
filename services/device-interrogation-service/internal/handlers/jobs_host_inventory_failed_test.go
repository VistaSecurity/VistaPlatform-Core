package handlers

import (
	"strings"
	"testing"
)

// TestHostInventoryFromResults_SurfacesTheConsumersFatalError pins the dev-lab
// shape: a Windows device agent's first host inventory reached the consumer,
// which resolved the host, counted 91 listeners, and then died writing them
//. The consumer recorded the error as `processing.fatal` beside the
// counts it had assembled, the job row said `completed`, and the Job Logs line
// built from these counts read "91 listeners" — a success, for a host that
// was not in the inventory.
//
// The counts are still returned (they are true: that is what the consumer
// had), but `failed` travels with them so nothing rendering the block can
// mistake it for a materialised run.
func TestHostInventoryFromResults_SurfacesTheConsumersFatalError(t *testing.T) {
	const results = `{
	  "success": true,
	  "processing": {
	    "fatal": "host inventory: resolving xps16-bob: identity: upserting endpoints on ac7291da: identity/postgres: upsert endpoint fe80::1%6|64657|udp: pq: invalid input syntax for type inet",
	    "materialized": 0,
	    "host_inventory": {
	      "facts": 0, "endpoints": 91, "identifiers": 5,
	      "asset_created": false, "installs_active": 0, "installs_created": 0, "installs_removed": 0
	    }
	  }
	}`

	got := hostInventoryFromResults(results)
	if got == nil {
		t.Fatal("a run that reached the consumer must surface its block; got nil")
	}
	if got.Failed == "" {
		t.Fatal("Failed is empty for a run whose consumer recorded processing.fatal")
	}
	if !strings.Contains(got.Failed, "invalid input syntax for type inet") {
		t.Errorf("Failed = %q, want the consumer's error verbatim", got.Failed)
	}
	// The counts the consumer assembled before failing are kept, not zeroed:
	// they are what happened, and `failed` is what says how to read them.
	if got.Endpoints != 91 {
		t.Errorf("Endpoints = %d, want 91 (the counts are not erased by the failure)", got.Endpoints)
	}
	// installs_active without packages_enumerated is not a package count.
	if got.Packages != nil {
		t.Errorf("Packages = %d, want absent: the package step never ran", *got.Packages)
	}
}

func TestHostInventoryFromResults_MaterialisedRunHasNoFailure(t *testing.T) {
	const results = `{"processing": {"host_inventory": {"facts": 3, "endpoints": 12, "installs_active": 412, "packages_enumerated": 412}}}`
	got := hostInventoryFromResults(results)
	if got == nil {
		t.Fatal("nil for a materialised run")
	}
	if got.Failed != "" {
		t.Errorf("Failed = %q on a run with no processing.fatal", got.Failed)
	}
	if got.Packages == nil || *got.Packages != 412 {
		t.Errorf("Packages = %v, want 412", got.Packages)
	}
}

func TestHostInventoryFromResults_BlankFatalIsNotAFailure(t *testing.T) {
	// A consumer that writes the key with an empty value has not failed;
	// treating "" as a failure would flip every clean run to failed the day
	// the log started emitting the key unconditionally.
	got := hostInventoryFromResults(`{"processing": {"fatal": "  ", "host_inventory": {"facts": 1, "endpoints": 0}}}`)
	if got == nil || got.Failed != "" {
		t.Fatalf("got %+v, want a block with no failure", got)
	}
}
