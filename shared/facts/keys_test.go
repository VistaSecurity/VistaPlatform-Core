package facts

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var validTypes = map[string]bool{
	"string":  true,
	"integer": true,
	"boolean": true,
	"date":    true,
	"array":   true,
	"object":  true,
}

func TestRegistryIsNotEmpty(t *testing.T) {
	if len(All) == 0 {
		t.Fatal("no fact keys in the generated registry")
	}
	if len(Producers) == 0 {
		t.Fatal("no producers in the generated registry")
	}
}

// The keys ADR-0005 D2 and ADR-0004 name by hand. Losing one is a product
// decision; a YAML edit should not be able to do it quietly.
func TestNamedKeysArePresent(t *testing.T) {
	for _, want := range []string{
		KeyOSName, KeyOSVersion, KeyOSKernel, KeyOSEOLDate,
		KeyHWVendor, KeyHWModel, KeyHWSerial, KeyHWUUID, KeyHWFirmwareVersion,
		KeyNetUptimeSeconds, KeyNetInterfaces, KeyNetNeighbors, KeyNetVlans,
		KeyCloudProvider, KeyCloudAccountID, KeyCloudRegion, KeyCloudResourceID,
		KeyCloudVPCID, KeyCloudSubnetID, KeyCloudSecurityGroups,
		KeySWPackageCount, KeySvcListeningSockets,
		KeyEOLOSDate, KeyEOLHWDate,
		KeyMgmtProtocol, KeyMgmtPlaintext,
		KeyAgentID, KeyAgentMode,
	} {
		if _, ok := Get(want); !ok {
			t.Errorf("fact key %q is missing from the registry", want)
		}
	}
}

func TestKeysAreNamespacedAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, k := range All {
		if !strings.Contains(k.Key, ".") {
			t.Errorf("fact key %q is not namespaced", k.Key)
		}
		if seen[k.Key] {
			t.Errorf("duplicate fact key %q", k.Key)
		}
		seen[k.Key] = true
	}
}

func TestEveryKeyIsWellFormed(t *testing.T) {
	for _, k := range All {
		if !validTypes[k.Type] {
			t.Errorf("%s: invalid type %q", k.Key, k.Type)
		}
		if k.Description == "" {
			t.Errorf("%s: no description", k.Key)
		}
		if len(k.Producers) == 0 {
			t.Errorf("%s: no producers", k.Key)
		}
		for _, p := range k.Producers {
			if !slices.Contains(Producers, p) {
				t.Errorf("%s: producer %q is not in the producer vocabulary", k.Key, p)
			}
		}
		container := k.Type == "array" || k.Type == "object"
		if container && k.ItemSchema == "" {
			t.Errorf("%s: %s key has no item_schema", k.Key, k.Type)
		}
		if !container && k.ItemSchema != "" {
			t.Errorf("%s: scalar key carries an item_schema", k.Key)
		}
		if len(k.Enum) > 0 && container {
			t.Errorf("%s: container key carries an enum", k.Key)
		}
	}
}

// The fragments are shipped to the UI and the query language; a fragment that
// does not parse is worse than none, because a consumer will trust it.
func TestItemSchemasAreValidJSON(t *testing.T) {
	for _, k := range All {
		if k.ItemSchema == "" {
			continue
		}
		var into map[string]any
		if err := json.Unmarshal([]byte(k.ItemSchema), &into); err != nil {
			t.Errorf("%s: item_schema is not a JSON object: %v", k.Key, err)
			continue
		}
		if _, ok := into["type"]; !ok {
			t.Errorf("%s: item_schema has no `type`", k.Key)
		}
	}
}

func TestGet(t *testing.T) {
	k, ok := Get(KeyOSName)
	if !ok {
		t.Fatal("os.name is missing")
	}
	if k.Type != "string" {
		t.Errorf("os.name type is %q, want string", k.Type)
	}
	if _, ok := Get("os.favourite_colour"); ok {
		t.Error("Get accepted an unregistered key")
	}
}

func TestValidateValueRejectsUnknownKeys(t *testing.T) {
	err := ValidateValue("os.favourite_colour", "blue")
	if err == nil {
		t.Fatal("ValidateValue accepted an unregistered key")
	}
	if !strings.Contains(err.Error(), "unknown fact key") {
		t.Errorf("error %q does not say the key is unknown", err)
	}
}

// nil is the absence of a fact, not a fact whose value is nothing. Storing one
// would collapse "not collected" into "collected as empty".
func TestValidateValueRejectsNil(t *testing.T) {
	if err := ValidateValue(KeyOSName, nil); err == nil {
		t.Fatal("ValidateValue accepted a nil value")
	}
}

func TestValidateValue(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		value   any
		wantErr bool
	}{
		// string
		{name: "string ok", key: KeyOSName, value: "Ubuntu"},
		{name: "empty string is a value", key: KeyOSName, value: ""},
		{name: "string rejects int", key: KeyOSName, value: 22, wantErr: true},
		{name: "string rejects bool", key: KeyOSName, value: true, wantErr: true},

		// string with an enum
		{name: "enum ok", key: KeyAgentMode, value: "local"},
		{name: "enum ok remote", key: KeyAgentMode, value: "remote"},
		{name: "enum rejects unlisted", key: KeyAgentMode, value: "hybrid", wantErr: true},
		{name: "enum is case sensitive", key: KeyAgentMode, value: "Local", wantErr: true},
		{name: "provider enum ok", key: KeyCloudProvider, value: "aws"},
		{name: "provider enum rejects unlisted", key: KeyCloudProvider, value: "oracle", wantErr: true},

		// integer
		{name: "integer ok", key: KeyNetUptimeSeconds, value: 86400},
		{name: "integer ok int64", key: KeyNetUptimeSeconds, value: int64(86400)},
		{name: "integer ok whole float", key: KeyNetUptimeSeconds, value: float64(86400)},
		{name: "integer ok json.Number", key: KeyNetUptimeSeconds, value: json.Number("86400")},
		{name: "integer ok zero", key: KeySWPackageCount, value: 0},
		{name: "integer rejects fractional float", key: KeyNetUptimeSeconds, value: 86400.5, wantErr: true},
		{name: "integer rejects fractional json.Number", key: KeyNetUptimeSeconds, value: json.Number("1.5"), wantErr: true},
		{name: "integer rejects numeric string", key: KeyNetUptimeSeconds, value: "86400", wantErr: true},

		// boolean
		{name: "boolean true", key: KeyMgmtPlaintext, value: true},
		{name: "boolean false is an answer", key: KeyMgmtPlaintext, value: false},
		{name: "boolean rejects string", key: KeyMgmtPlaintext, value: "true", wantErr: true},
		{name: "boolean rejects int", key: KeyMgmtPlaintext, value: 1, wantErr: true},

		// date
		{name: "date ok YYYY-MM-DD", key: KeyEOLOSDate, value: "2027-04-30"},
		{name: "date ok RFC3339", key: KeyEOLOSDate, value: "2027-04-30T00:00:00Z"},
		{name: "date ok time.Time", key: KeyEOLOSDate, value: time.Now()},
		{name: "date rejects free text", key: KeyEOLOSDate, value: "April 2027", wantErr: true},
		{name: "date rejects US order", key: KeyEOLOSDate, value: "04/30/2027", wantErr: true},
		{name: "date rejects epoch int", key: KeyEOLOSDate, value: 1809043200, wantErr: true},

		// array
		{name: "array ok []any", key: KeyNetInterfaces, value: []any{map[string]any{"name": "eth0"}}},
		{name: "array ok empty", key: KeyNetInterfaces, value: []any{}},
		{name: "array ok typed slice", key: KeyCloudSecurityGroups, value: []map[string]string{{"id": "sg-1"}}},
		{name: "array rejects object", key: KeyNetInterfaces, value: map[string]any{"name": "eth0"}, wantErr: true},
		{name: "array rejects string", key: KeyNetInterfaces, value: "eth0", wantErr: true},
		{name: "array rejects raw bytes", key: KeyNetInterfaces, value: []byte("eth0"), wantErr: true},
		// A typed nil slice is not an untyped nil, so it slips past the nil
		// check at the top of ValidateValue — and it marshals to JSON `null`,
		// which is the empty fact that check exists to refuse.
		{name: "array rejects a typed nil slice", key: KeyNetInterfaces, value: []any(nil), wantErr: true},
		{name: "array rejects a nil typed slice", key: KeyCloudSecurityGroups, value: []map[string]string(nil), wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateValue(tc.key, tc.value)
			if tc.wantErr && err == nil {
				t.Fatalf("ValidateValue(%q, %#v) = nil, want error", tc.key, tc.value)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidateValue(%q, %#v) = %v, want nil", tc.key, tc.value, err)
			}
		})
	}
}

// Every array key must accept the shape a JSON decode produces, since that is
// how every fact actually arrives.
func TestEveryArrayKeyAcceptsADecodedJSONArray(t *testing.T) {
	for _, k := range All {
		if k.Type != "array" {
			continue
		}
		var decoded any
		if err := json.Unmarshal([]byte(`[{"a":1}]`), &decoded); err != nil {
			t.Fatalf("fixture failed to decode: %v", err)
		}
		if err := ValidateValue(k.Key, decoded); err != nil {
			t.Errorf("%s: rejected a decoded JSON array: %v", k.Key, err)
		}
	}
}

func TestValidateValueObject(t *testing.T) {
	// No object-typed key is registered yet, so exercise the branch through a
	// synthetic entry rather than leaving it untested until one appears.
	saved := byKey
	t.Cleanup(func() { byKey = saved })
	byKey = map[string]Key{"test.object": {Key: "test.object", Type: "object"}}

	for _, ok := range []any{
		map[string]any{"a": 1},
		map[string]string{"a": "b"},
		// Allocated but empty is a value ("nothing here"), unlike a nil map.
		map[string]any{},
		struct{ A int }{A: 1},
		&struct{ A int }{A: 1},
	} {
		if err := ValidateValue("test.object", ok); err != nil {
			t.Errorf("object rejected %#v: %v", ok, err)
		}
	}
	for _, bad := range []any{
		[]any{1},
		"a",
		42,
		time.Now(),
		map[int]string{1: "a"},
		// Typed nils marshal to JSON `null` — the empty fact ValidateValue's
		// nil check refuses, arriving in a non-nil interface.
		map[string]any(nil),
		(*struct{ A int })(nil),
	} {
		if err := ValidateValue("test.object", bad); err == nil {
			t.Errorf("object accepted %#v", bad)
		}
	}
}

func TestMayWrite(t *testing.T) {
	if !MayWrite(ProducerEnricher, KeyEOLOSDate) {
		t.Error("the enricher should be able to write the catalogue-resolved EOL date")
	}
	// eol.* is resolved by the platform, never asserted by a collector — that
	// is the whole reason os.eol_date and eol.os.date are separate keys.
	if MayWrite(ProducerSensor, KeyEOLOSDate) {
		t.Error("the sensor should not be able to write a catalogue-resolved fact")
	}
	if MayWrite("nobody", KeyOSName) {
		t.Error("MayWrite accepted an unregistered producer")
	}
	if MayWrite(ProducerDeviceAgent, "os.favourite_colour") {
		t.Error("MayWrite accepted an unregistered key")
	}
}

// Nothing at launch holds key material — we collect posture, never secrets.
// If this fails, a key that carries something sensitive has been added and the
// export, logging and AI-prompt paths need to learn to mask it.
func TestNoKeyIsRedactedYet(t *testing.T) {
	for _, k := range All {
		if k.Redact {
			t.Errorf("%s is marked redact: true — wire the masking path before landing it", k.Key)
		}
	}
}

// The drift audit `make audit` runs, executed here too so `go test ./...`
// catches a stale generated file without waiting for CI.
func TestGeneratedFilesMatchYAML(t *testing.T) {
	root := repoRoot(t)
	script := filepath.Join(root, "scripts", "generate-fact-keys.mjs")
	if _, err := os.Stat(script); err != nil {
		t.Skipf("generator not present (%v) — public tree or partial checkout", err)
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not on PATH")
	}
	cmd := exec.Command("node", script, "--check")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generator --check failed: %v\n%s", err, out)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skip("repo root (go.work) not found")
		}
		dir = parent
	}
}
