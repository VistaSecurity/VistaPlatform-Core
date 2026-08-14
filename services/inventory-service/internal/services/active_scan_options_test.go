package services

import "testing"

// Active Scan was the only caller that ever set the result-sink probe option, and
// that option was the only thing that routed a job's findings into the ingestion
// queue — so every other discovery job's findings never reached inventory without
// a browser posting them back. cluster-sensor now mirrors every job
// unconditionally; the option is inert and must not come back, because a switch
// that no longer switches anything reads as if it still does.
func TestActiveScanJobOptions_CarriesNoResultSink(t *testing.T) {
	opts := activeScanJobOptions()

	if _, present := opts["result_sink"]; present {
		t.Fatal("Active Scan set result_sink again — routing to the ingestion queue is unconditional now, so this option would imply a choice that does not exist")
	}
	if opts["active_scan"] != true {
		t.Fatal("active_scan provenance flag missing — mirrored rows would be stamped as ordinary discovery-job findings")
	}
}
