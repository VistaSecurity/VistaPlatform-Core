package tlsendpointtest

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/discovery"
)

// UpdateEnv, set to 1, makes CheckGolden (re)write the golden file instead of
// comparing against it. Goldens are recorded from the implementation being
// characterized; after that they change only through a named Exception.
const UpdateEnv = "UPDATE_TLS_ENDPOINT_GOLDEN"

// Dump renders v as a tree of maps and lists whose leaves are "type=value"
// strings, so a golden file pins Go types as well as values: a consumer that
// type-asserts `cert["subject_alternative_names"].([]string)` breaks just as
// surely on a type change as on a value change. Struct fields are keyed by Go
// field name. Strings found in tokens (Fixture.Tokens) are replaced by their
// token; loopback port numbers in strings are replaced by "PORT" and the
// verification time in an x509 expiry error by "NOW".
func Dump(v any, tokens map[string]string) any {
	return dump(reflect.ValueOf(v), tokens)
}

var (
	loopbackPort = regexp.MustCompile(`127\.0\.0\.1:\d+`)
	// x509 puts the verification time in an expiry error.
	currentTime = regexp.MustCompile(`current time \S+ is`)
)

func dump(v reflect.Value, tokens map[string]string) any {
	if !v.IsValid() {
		return "nil"
	}
	if v.Type() == reflect.TypeOf(time.Time{}) {
		return "time.Time=" + v.Interface().(time.Time).UTC().Format(time.RFC3339)
	}
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return "nil"
		}
		return dump(v.Elem(), tokens)
	case reflect.Pointer:
		if v.IsNil() {
			return fmt.Sprintf("%s=nil", v.Type())
		}
		return map[string]any{"*" + v.Type().Elem().String(): dump(v.Elem(), tokens)}
	case reflect.Map:
		if v.IsNil() {
			return fmt.Sprintf("%s=nil", v.Type())
		}
		out := map[string]any{}
		for _, k := range v.MapKeys() {
			out[fmt.Sprint(k.Interface())] = dump(v.MapIndex(k), tokens)
		}
		return map[string]any{v.Type().String(): out}
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			return fmt.Sprintf("%s=nil", v.Type())
		}
		out := make([]any, v.Len())
		for i := range out {
			out[i] = dump(v.Index(i), tokens)
		}
		return map[string]any{v.Type().String(): out}
	case reflect.Struct:
		out := map[string]any{}
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if !f.IsExported() {
				continue
			}
			out[f.Name] = dump(v.Field(i), tokens)
		}
		return map[string]any{v.Type().String(): out}
	case reflect.String:
		s := v.String()
		if tok, ok := tokens[s]; ok {
			s = tok
		}
		s = loopbackPort.ReplaceAllString(s, "127.0.0.1:PORT")
		s = currentTime.ReplaceAllString(s, "current time NOW is")
		return v.Type().String() + "=" + s
	default:
		return fmt.Sprintf("%s=%v", v.Type(), v.Interface())
	}
}

// Exception is one intended, explained difference between the recorded golden
// (the previous implementation) and the current output. Apply edits the golden
// tree in place and must report whether it changed anything: an exception that
// no longer applies is itself a failure, so a stale justification cannot
// linger.
type Exception struct {
	Name  string
	Why   string
	Apply func(golden map[string]any) bool
}

// CheckGolden compares got (a Dump) with the golden file at path after
// applying exceptions to the golden. With UpdateEnv=1 it writes got instead
// (exceptions are not applied: a golden always records an implementation
// verbatim).
func CheckGolden(t testing.TB, path string, got any, exceptions ...Exception) {
	t.Helper()
	gotJSON := canonicalJSON(t, got)
	if os.Getenv(UpdateEnv) == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, gotJSON, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (record it with %s=1 against the implementation being characterized)", path, err, UpdateEnv)
	}
	var golden map[string]any
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatalf("parse golden %s: %v", path, err)
	}
	for _, ex := range exceptions {
		if ex.Why == "" {
			t.Errorf("exception %q has no justification", ex.Name)
		}
		if !ex.Apply(golden) {
			t.Errorf("exception %q changed nothing in %s — it no longer describes a real difference; remove it", ex.Name, filepath.Base(path))
		}
	}
	want := canonicalJSON(t, golden)
	if string(want) != string(gotJSON) {
		t.Errorf("output differs from golden %s (after %d named exceptions):\n%s", filepath.Base(path), len(exceptions), lineDiff(string(want), string(gotJSON)))
	}
}

func canonicalJSON(t testing.TB, v any) []byte {
	t.Helper()
	// Round-trip through a generic tree so map keys sort the same way for a
	// freshly dumped value and a parsed golden.
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var generic any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatal(err)
	}
	out, err := json.MarshalIndent(generic, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

// lineDiff is a minimal "-want +got" listing of the lines only one side has.
func lineDiff(want, got string) string {
	count := func(s string) map[string]int {
		m := map[string]int{}
		for _, l := range strings.Split(s, "\n") {
			// A key that becomes or stops being the last in its object
			// gains or loses only a comma; that is not a difference.
			m[strings.TrimSuffix(l, ",")]++
		}
		return m
	}
	w, g := count(want), count(got)
	var lines []string
	for l, n := range w {
		for i := g[l]; i < n; i++ {
			lines = append(lines, "- "+l)
		}
	}
	for l, n := range g {
		for i := w[l]; i < n; i++ {
			lines = append(lines, "+ "+l)
		}
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// Node walks a Dump tree: each step is a map key (a type wrapper such as
// "map[string]interface {}" counts as a key). It returns the map holding the
// final key, and whether the path exists up to it.
func Node(tree map[string]any, path ...string) (map[string]any, bool) {
	cur := tree
	for _, p := range path {
		next, ok := cur[p].(map[string]any)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

// SetIfAbsent sets m[key] = dumped (a Dump leaf such as "bool=false") when key
// is absent, and reports whether it did.
func SetIfAbsent(m map[string]any, key, dumped string) bool {
	if m == nil {
		return false
	}
	if _, ok := m[key]; ok {
		return false
	}
	m[key] = dumped
	return true
}

// Leaf returns the value part of a Dump leaf ("string=TLS 1.2" → "TLS 1.2").
func Leaf(v any) string {
	s, _ := v.(string)
	if i := strings.IndexByte(s, '='); i >= 0 {
		return s[i+1:]
	}
	return s
}

// AddSharedProbeWireKeys adds, to a golden metadata map recorded from a
// private handshake, the four keys every shared TLS probe result carries in
// its metadata — derived from the version and cipher-suite NAMES the golden
// already holds, not copied from the new output:
//
//   - tls_version_raw / cipher_suite_raw: the numeric wire values (uint16)
//   - tls_fingerprint: "<version>-<suite>" in decimal
//   - negotiated_protocol: the ALPN protocol, "" (no fixture negotiates ALPN)
//
// It reports whether it added all four; a golden that already had any of them
// is not the shape this exception describes.
func AddSharedProbeWireKeys(meta map[string]any, versionName, cipherName string) bool {
	ver, ok := tlsVersionByName[versionName]
	if !ok {
		return false
	}
	suite, ok := cipherSuiteByName(cipherName)
	if !ok {
		return false
	}
	added := SetIfAbsent(meta, "tls_version_raw", fmt.Sprintf("uint16=%d", ver))
	added = SetIfAbsent(meta, "cipher_suite_raw", fmt.Sprintf("uint16=%d", suite)) && added
	added = SetIfAbsent(meta, "tls_fingerprint", fmt.Sprintf("string=%d-%d", ver, suite)) && added
	added = SetIfAbsent(meta, "negotiated_protocol", "string=") && added
	return added
}

var tlsVersionByName = map[string]uint16{
	"TLS 1.0": tls.VersionTLS10, "TLS 1.1": tls.VersionTLS11,
	"TLS 1.2": tls.VersionTLS12, "TLS 1.3": tls.VersionTLS13,
}

func cipherSuiteByName(name string) (uint16, bool) {
	for _, cs := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		if cs.Name == name {
			return cs.ID, true
		}
	}
	return 0, false
}

// AddQualityFlags adds, to a golden metadata map recorded from a handshake
// that computed no certificate quality flags, the flags the shared probe
// computes for sc's chain: shared/discovery.ClassifyCertificateFlags, refined
// for the two live-handshake SCT routes (no fixture delivers an SCT). It
// reports whether it added at least one flag and found none already present.
func AddQualityFlags(t testing.TB, meta map[string]any, sc Scenario) bool {
	t.Helper()
	chain := sc.PeerCertificates(t)
	flags := discovery.ClassifyCertificateFlags(chain[0], chain)
	var issuer *x509.Certificate
	if len(chain) > 1 {
		issuer = chain[1]
	}
	discovery.RefineSCTFlags(flags, nil, nil, issuer)
	if len(flags) == 0 {
		return false
	}
	for k, v := range flags {
		if !SetIfAbsent(meta, k, fmt.Sprintf("%T=%v", v, v)) {
			return false
		}
	}
	return true
}

// List walks to a Dump list (path ends at the list's type wrapper key).
func List(tree map[string]any, path ...string) ([]any, bool) {
	if len(path) == 0 {
		return nil, false
	}
	parent, ok := Node(tree, path[:len(path)-1]...)
	if !ok {
		return nil, false
	}
	l, ok := parent[path[len(path)-1]].([]any)
	return l, ok
}
