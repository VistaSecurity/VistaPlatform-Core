package handlers

import (
	"encoding/json"
	"strings"
	"testing"
)

// Collection warnings reach the job detail as a typed list read out of the
// processing block (finding P-17), scrubbed again on the way out.

const storedWithWarnings = `{
  "success": true,
  "assets": [],
  "warnings": [{"collector":"fortinet","endpoint":"/api/v2/cmdb/system/interface","reason":"permission_denied","effect":"Configured interfaces and VLANs not collected"}],
  "processing": {
    "materialized": 3,
    "fully_materialized": true,
    "collection_warnings": [
      {"collector":"fortinet","endpoint":"/api/v2/cmdb/system/interface","reason":"permission_denied",
       "effect":"Configured interfaces and VLANs not collected","detail":"API returned status 403"},
      {"collector":"paloalto","endpoint":"/api/?type=op&key=LUFRPT1LIVEKEY","reason":"something_new",
       "effect":"ARP neighbours not collected",
       "detail":"Get \"https://198.51.100.7/api/?type=op&key=LUFRPT1LIVEKEY\": context deadline exceeded"}
    ]
  }
}`

func TestBuildJobResults_ServesCollectionWarningsTypedAndScrubbed(t *testing.T) {
	out := buildJobResults("job-1", "completed", storedWithWarnings)

	if out.CollectionWarningsUnreadable {
		t.Fatal("a readable warning list was reported unreadable")
	}
	if len(out.CollectionWarnings) != 2 {
		t.Fatalf("got %d collection warnings, want 2: %+v", len(out.CollectionWarnings), out.CollectionWarnings)
	}
	first := out.CollectionWarnings[0]
	if first.Collector != "fortinet" || first.Endpoint != "/api/v2/cmdb/system/interface" ||
		first.Reason != "permission_denied" || first.Effect != "Configured interfaces and VLANs not collected" {
		t.Errorf("the warning did not survive the projection intact: %+v", first)
	}

	second := out.CollectionWarnings[1]
	if second.Endpoint != "/api/" {
		t.Errorf("endpoint = %q; the query string must be stripped on the way out", second.Endpoint)
	}
	if second.Reason != "error" {
		t.Errorf("reason = %q; a value outside the closed set must be served as \"error\"", second.Reason)
	}

	blob, _ := json.Marshal(out)
	if strings.Contains(string(blob), "LUFRPT1LIVEKEY") {
		t.Errorf("an API key stored in a warning reached the client: %s", blob)
	}
	// Served once, typed — not a second time inside the untyped processing map.
	if _, dup := out.Processing["collection_warnings"]; dup {
		t.Error("collection_warnings is served twice: typed and inside processing")
	}
	if out.Processing["materialized"] == nil {
		t.Error("removing the duplicate cost the rest of the processing block")
	}
}

func TestBuildJobResults_NoWarningsMeansAbsentNotEmpty(t *testing.T) {
	out := buildJobResults("job-1", "completed", `{"success":true,"assets":[],"processing":{"materialized":0}}`)
	if out.CollectionWarnings != nil || out.CollectionWarningsUnreadable {
		t.Errorf("a run with no warnings reported %+v (unreadable=%v)", out.CollectionWarnings, out.CollectionWarningsUnreadable)
	}
	blob, _ := json.Marshal(out)
	if strings.Contains(string(blob), "collection_warnings") {
		t.Errorf("an empty warning list was serialised: %s", blob)
	}
}

// A list that is there but cannot be read must not render as "no warnings".
func TestBuildJobResults_UnreadableWarningsAreFlagged(t *testing.T) {
	out := buildJobResults("job-1", "completed", `{"success":true,"assets":[],"processing":{"collection_warnings":"not-a-list"}}`)
	if !out.CollectionWarningsUnreadable {
		t.Error("an unreadable warning list was reported as none")
	}
	if out.CollectionWarnings != nil {
		t.Errorf("warnings were invented from an unreadable list: %+v", out.CollectionWarnings)
	}
}
