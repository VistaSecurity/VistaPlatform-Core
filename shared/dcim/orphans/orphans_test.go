package orphans

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

var (
	createTable = regexp.MustCompile(`^CREATE TABLE IF NOT EXISTS public\.(\w+) \(`)
	kindColumn  = regexp.MustCompile(`^\s+(\w+_kind) (?:text|character varying)`)
	uuidColumn  = regexp.MustCompile(`^\s+(\w+) uuid`)
)

// schemaPairs returns every "table.<x>_kind" in schema.sql that has a uuid
// "<x>_id" sibling in the same table: the shape of a polymorphic reference.
func schemaPairs(t *testing.T) map[string]string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(file), "..", "..", "..", "scripts", "database", "schema.sql")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open schema: %v", err)
	}
	defer func() { _ = f.Close() }()

	out := map[string]string{}
	var table string
	kinds := map[string]bool{}
	ids := map[string]bool{}
	flush := func() {
		for k := range kinds {
			if ids[strings.TrimSuffix(k, "_kind")+"_id"] {
				out[table+"."+k] = strings.TrimSuffix(k, "_kind") + "_id"
			}
		}
		kinds, ids = map[string]bool{}, map[string]bool{}
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if m := createTable.FindStringSubmatch(line); m != nil {
			table = m[1]
			continue
		}
		if table == "" {
			continue
		}
		// ");" ends a table; a partitioned one ends " ) PARTITION BY ...".
		if strings.HasPrefix(strings.TrimLeft(line, " "), ")") && len(line)-len(strings.TrimLeft(line, " ")) <= 1 {
			flush()
			table = ""
			continue
		}
		if m := kindColumn.FindStringSubmatch(line); m != nil {
			kinds[m[1]] = true
		}
		if m := uuidColumn.FindStringSubmatch(line); m != nil {
			ids[m[1]] = true
		}
	}
	return out
}

// Kind columns that are not references to an object of the DCIM kinds: the
// provenance of a value (`source_kind` and its prefixed forms) and the sibling
// uuid is a different thing.
func isProvenance(key string) bool {
	col := key[strings.Index(key, ".")+1:]
	return strings.HasSuffix(col, "source_kind")
}

// A (kind, id) pair in the schema that Registry does not classify would be
// left dangling when its object is deleted. Classify it: Delete, Null,
// Elsewhere or Retained.
func TestRegistryNamesEveryPolymorphicReference(t *testing.T) {
	pairs := schemaPairs(t)
	if len(pairs) < 15 {
		t.Fatalf("the schema scan found %d (kind, id) pairs; the parser is broken", len(pairs))
	}
	known := map[string]Ref{}
	for _, r := range Registry {
		if _, dup := known[r.Key()]; dup {
			t.Errorf("%s is in the registry twice", r.Key())
		}
		known[r.Key()] = r
	}
	for key, idCol := range pairs {
		if isProvenance(key) {
			continue
		}
		r, ok := known[key]
		if !ok {
			t.Errorf("%s (+ %s) is a polymorphic reference that orphans.Registry does not classify", key, idCol)
			continue
		}
		if r.IDCol != idCol {
			t.Errorf("%s: registry names id column %q, the schema has %q", key, r.IDCol, idCol)
		}
	}
	for key := range known {
		if _, ok := pairs[key]; !ok {
			t.Errorf("%s is in the registry but not in the schema", key)
		}
	}
}

func TestRegistryExplainsWhatItDoesNotSweep(t *testing.T) {
	for _, r := range Registry {
		switch r.Action {
		case Delete, Null:
			if r.Note != "" {
				t.Errorf("%s: a swept pair needs no note", r.Key())
			}
		case Elsewhere, Retained:
			if r.Note == "" {
				t.Errorf("%s: say why it is not swept here", r.Key())
			}
		default:
			t.Errorf("%s: unknown action %d", r.Key(), r.Action)
		}
	}
}

// Every kind a swept reference may carry must map to a table, or Sweep would
// skip it silently. The CHECKed kind lists are the registry's job to keep; this
// pins the kinds the sweep is known to meet.
func TestKindsMapToTables(t *testing.T) {
	for _, k := range []dcim.ObjectKind{
		dcim.ObjectKindAsset, dcim.ObjectKindInterface, dcim.ObjectKindSite, dcim.ObjectKindLocation,
		dcim.ObjectKindRegion, dcim.ObjectKindSiteGroup, dcim.ObjectKindRack, dcim.ObjectKindPrefix,
		dcim.ObjectKindVlan, dcim.ObjectKindModule, dcim.ObjectKindCluster, dcim.ObjectKindClusterGroup,
		dcim.ObjectKindProviderNetwork, dcim.ObjectKindFhrpGroup,
	} {
		if k.Table() == "" {
			t.Errorf("%s has no table", k)
		}
	}
}
