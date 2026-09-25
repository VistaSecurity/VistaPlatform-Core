// Package pipelinetest is the harness behind the chained per-vendor pipeline
// tests (spec discovery-beyond-the-lab, slice W0.2).
//
// One interrogation crosses three services before a tenant sees it:
//
//	device output ──hop 1──▶ sensor_discoveries ──hop 2──▶ ingest payload ──hop 3──▶ inventory
//	(device-interrogation)    (discovery-processor)          (inventory-service)
//
// Go `internal` packages cannot be imported across service modules, so no one
// test can run all three. Instead each hop is a DB-integration test in its own
// module that runs the REAL code of that hop and hands its output to the next
// hop as a committed golden file under
// shared/deviceinterrogation/testdata/pipeline/<vendor>/. Hop N compares what it
// produced against its golden, and hop N+1 reads that same golden as its input.
// See testdata/pipeline/README.md for the chain and the regeneration order.
//
// This package holds only what every hop shares: the scenario and golden file
// formats, the regeneration flag, the chain (drift) check, the fake appliances
// the collectors talk to, and the knownGap assertion helper. It is imported
// only by tests.
package pipelinetest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// UpdateGolden rewrites a hop's golden from what the hop produced, instead of
// comparing against it. Regenerate in chain order (hop 1, then 2, then 3): each
// hop records the hash of the golden it read, so regenerating hop N without
// regenerating hop N+1 fails hop N+1's drift check.
var UpdateGolden = flag.Bool("update-golden", false,
	"rewrite the vendor pipeline goldens under shared/deviceinterrogation/testdata/pipeline from this run")

// Vendors is every vendor the chain covers, in the order the README lists
// them. UniFi is the baseline the others are measured against.
var Vendors = []string{"unifi", "cisco", "fortinet", "paloalto", "f5", "snmp"}

// Golden file names, one set per vendor directory.
const (
	ScenarioFile      = "scenario.json"
	Hop1HandoffFile   = "hop1_handoff.golden.json"
	Hop1ObservedFile  = "hop1_observations.golden.json"
	Hop2HandoffFile   = "hop2_handoff.golden.json"
	Hop3InventoryFile = "hop3_inventory.golden.json"
)

// Placeholders stand in for values that differ on every run (row ids, the
// tenant, the fake appliance's loopback listener) so a golden is stable. Each
// downstream hop substitutes them back with values of its own; see
// [Substitute].
const (
	PlaceholderDeviceAssetID = "{{DEVICE_ASSET_ID}}"
	PlaceholderApplianceIP   = "{{APPLIANCE_IP}}"
	PlaceholderAppliancePort = "{{APPLIANCE_PORT}}"
	PlaceholderSensorID      = "{{SENSOR_ID}}"
	PlaceholderTenantID      = "{{TENANT_ID}}"
	PlaceholderDeviceJobID   = "{{DEVICE_JOB_ID}}"
	// PlaceholderDiscoveryIDFormat names hop 1 row i by its index.
	PlaceholderDiscoveryIDFormat = "{{DISCOVERY_ID:%d}}"
	PlaceholderBatchID           = "{{BATCH_ID}}"
	PlaceholderTimestamp         = "{{TIMESTAMP}}"
)

// Dir resolves the pipeline testdata directory from a test's relative path to
// it and fails the test if it is not there. Each module's test states its own
// relative path (the goldens live in the shared module), so a moved directory
// fails loudly instead of every hop silently finding nothing.
func Dir(t testing.TB, relative string) string {
	t.Helper()
	abs, err := filepath.Abs(relative)
	if err != nil {
		t.Fatalf("pipeline dir %q: %v", relative, err)
	}
	if _, err := os.Stat(filepath.Join(abs, "README.md")); err != nil {
		t.Fatalf("pipeline dir %q has no README.md: %v", abs, err)
	}
	return abs
}

// Hash is the SHA-256 of a golden file's bytes, as recorded in the next hop's
// golden. Line endings are normalised so a checkout with autocrlf does not
// read as drift.
func Hash(t testing.TB, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("hash %s: %v", path, err)
	}
	sum := sha256.Sum256(bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n")))
	return hex.EncodeToString(sum[:])
}

// ReadJSON decodes a fixture or golden file.
func ReadJSON(t testing.TB, path string, into any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(into); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

// Marshal renders a golden: indented, map keys sorted (encoding/json sorts
// them), trailing newline, HTML characters left alone so a cipher string reads
// as the device printed it.
func Marshal(t testing.TB, v any) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		t.Fatalf("marshal golden: %v", err)
	}
	return buf.Bytes()
}

// CompareGolden compares got against the golden at path, or rewrites the
// golden when -update-golden is set. A mismatch names the first differing line
// and how to regenerate, because "golden mismatch" alone sends the reader to a
// 2,000-line diff.
func CompareGolden(t testing.TB, path string, got any) {
	t.Helper()
	gotBytes := Marshal(t, got)
	if *UpdateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, gotBytes, 0o644); err != nil {
			t.Fatalf("write golden %s: %v", path, err)
		}
		t.Logf("rewrote golden %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("golden %s missing (%v) — generate it with -update-golden", path, err)
	}
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if bytes.Equal(want, gotBytes) {
		return
	}
	t.Errorf("%s does not match this run.\n%s\n"+
		"If the change is intended, regenerate this hop with -update-golden and then every later hop "+
		"(see testdata/pipeline/README.md); the downstream drift check fails until you do.",
		path, firstDifference(string(want), string(gotBytes)))
}

// firstDifference renders the first differing line with a little context.
func firstDifference(want, got string) string {
	w := strings.Split(want, "\n")
	g := strings.Split(got, "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl == gl {
			continue
		}
		from := i - 3
		if from < 0 {
			from = 0
		}
		var b strings.Builder
		for j := from; j < i && j < len(g); j++ {
			fmt.Fprintf(&b, "   %5d  %s\n", j+1, g[j])
		}
		fmt.Fprintf(&b, "  -%5d  %s\n  +%5d  %s", i+1, wl, i+1, gl)
		return b.String()
	}
	return "(files differ only in trailing bytes)"
}

// CheckInput is the drift check: a golden that consumed another hop's golden
// records that golden's hash, and a hop that finds the hash stale refuses to
// compare anything else. Without it, regenerating hop 1 and forgetting hop 2
// would leave hop 2 comparing a fresh output against a golden built from the
// OLD input, and the failure would read as a hop-2 regression.
//
// Under -update-golden the recorded hash is simply what the new golden will
// say, so there is nothing to check.
func CheckInput(t testing.TB, recorded, inputPath string) {
	t.Helper()
	if *UpdateGolden {
		return
	}
	if actual := Hash(t, inputPath); recorded != actual {
		t.Fatalf("drift: this hop's golden was generated from a different %s "+
			"(recorded input_sha256 %s, file now hashes to %s). The upstream hop was regenerated "+
			"without this one — rerun this hop with -update-golden and review the diff.",
			filepath.Base(inputPath), short(recorded), short(actual))
	}
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// Canonical round-trips v through JSON so a golden compares the decoded shape
// (numbers as json.Number, maps as map[string]any) regardless of the Go types
// the hop produced it from.
func Canonical(t testing.TB, v any) any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("canonical marshal: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("canonical decode: %v", err)
	}
	return out
}

// Equal reports whether two values are equal after [Canonical].
func Equal(t testing.TB, a, b any) bool {
	t.Helper()
	return reflect.DeepEqual(Canonical(t, a), Canonical(t, b))
}
