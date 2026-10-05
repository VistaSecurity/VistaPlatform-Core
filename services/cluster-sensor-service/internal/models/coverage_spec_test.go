package models

// models.JobCoverage is what GET /discovery/jobs/{id} returns as `coverage`,
// forwarded verbatim by inventory-service, whose OpenAPI documents it as
// DiscoveryJobCoverage (additionalProperties: false, every key required).
// This service has no OpenAPI validator, so the link is pinned here: the
// type's JSON keys are exactly the schema's required list. Adding a field to
// either side without the other turns this red.

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func specRequired(t *testing.T, schema string) []string {
	t.Helper()
	_, here, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(here), "..", "..", "..", "..", "api", "openapi", "inventory-service.openapi.yaml")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open the spec: %v", err)
	}
	defer func() { _ = f.Close() }()
	var out []string
	in, inRequired := false, false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "    "+schema+":":
			in = true
		case in && strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "     "):
			return out // the next schema
		case in && line == "      required:":
			inRequired = true
		case in && inRequired && strings.HasPrefix(line, "      - "):
			out = append(out, strings.TrimPrefix(line, "      - "))
		case in && inRequired:
			inRequired = false
		}
	}
	return out
}

func TestJobCoverage_KeysMatchTheSpec(t *testing.T) {
	raw, err := json.Marshal(JobCoverage{})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	_ = json.Unmarshal(raw, &m)
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := specRequired(t, "DiscoveryJobCoverage")
	sort.Strings(want)
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Fatalf("JobCoverage JSON keys\n  %v\nspec DiscoveryJobCoverage required\n  %v", keys, want)
	}
}

// The grouped results (GET …/results?group=host) likewise: each type's
// always-present JSON keys are exactly its schema's required list.
func TestResultsByHost_KeysMatchTheSpec(t *testing.T) {
	for schema, v := range map[string]interface{}{
		"DiscoveryJobResultsByHost": DiscoveryResultsByHostResponse{},
		"DiscoveryHost":             DiscoveryHost{},
		"DiscoveryHostPort":         DiscoveryHostPort{},
		"DiscoveryHostUnit":         DiscoveryHostUnit{},
	} {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]interface{}
		_ = json.Unmarshal(raw, &m)
		var keys []string
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		want := specRequired(t, schema)
		sort.Strings(want)
		if strings.Join(keys, ",") != strings.Join(want, ",") {
			t.Errorf("%s: Go keys %v, spec required %v", schema, keys, want)
		}
	}
}
