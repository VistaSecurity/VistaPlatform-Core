package paritytest

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
)

// Persisted is one row a path would hand to inventory: the sensor_discoveries
// columns ingestion reads (protocol, port, confidence, hostname) and its
// metadata AS INGESTION SEES IT — for the engine and the Platform Sensor the
// mirrored metadata (jobunits.MirrorMetadata of the finding's details); for the
// standalone sensor sensor-manager's envelope flattened the way
// discovery-processor flattens it (FlattenSensorEnvelope).
type Persisted struct {
	Protocol   string
	Port       int
	Confidence float64
	Hostname   string
	Metadata   map[string]any
}

// Fields is one finding normalized into a flat field namespace:
//
//	row.protocol, row.confidence, row.hostname   the columns
//	meta.<key>                                   every metadata key but "certificates"
//	cert[<i>].<key>                              every key of every certificate entry
//
// Values are canonical JSON, so a missing key, an empty string and a null are
// all distinguishable. A key one path writes and another does not therefore
// shows up as a difference on that key — key NAMES are compared, not just values.
type Fields map[string]string

// Absent is the value a Diff shows for a field one side does not have.
const Absent = "<absent>"

// volatile metadata keys: compared for presence only, never by value.
var volatile = map[string]string{
	"probe_timestamp": "<timestamp>",
	"job_id":          "<job id>",
}

// Normalize flattens one persisted row. Metadata is JSON round-tripped first,
// as it is on its way into Postgres, so numbers and nested types compare the
// same whichever path built them.
func Normalize(p Persisted) Fields {
	f := Fields{
		"row.protocol":   strconv.Quote(cryptoparse.NormalizeProtocol(p.Protocol)),
		"row.confidence": strconv.FormatFloat(p.Confidence, 'f', 2, 64),
		"row.hostname":   strconv.Quote(p.Hostname),
	}
	meta := roundTrip(p.Metadata)
	for k, v := range meta {
		if k == "certificates" {
			continue
		}
		if mask, ok := volatile[k]; ok {
			f["meta."+k] = mask
			continue
		}
		f["meta."+k] = canonical(v)
	}
	if certs, ok := meta["certificates"].([]any); ok {
		for i, c := range certs {
			entry, ok := c.(map[string]any)
			if !ok {
				f[fmt.Sprintf("cert[%d]", i)] = canonical(c)
				continue
			}
			for k, v := range entry {
				f[fmt.Sprintf("cert[%d].%s", i, k)] = canonical(v)
			}
		}
	} else if v, present := meta["certificates"]; present {
		f["meta.certificates"] = canonical(v)
	}
	return f
}

func roundTrip(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return map[string]any{"<unmarshalable>": err.Error()}
	}
	out := map[string]any{}
	_ = json.Unmarshal(b, &out)
	return out
}

func canonical(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("<%v>", err)
	}
	return string(b)
}

// Result is one path's findings on the fixture network: case → protocol →
// fields. Several findings on one port are told apart by their protocol.
type Result map[string]map[string]Fields

// Collect groups a path's rows by the fixture case on their port. A row on a
// port the fixture did not bind is a test failure: the path scanned something
// it was not asked to.
func Collect(t testing.TB, n *Network, rows []Persisted) Result {
	t.Helper()
	out := Result{}
	for _, r := range rows {
		c := n.CaseForPort(r.Port)
		if c == nil {
			t.Errorf("a finding on port %d, which the fixture did not bind", r.Port)
			continue
		}
		f := Normalize(r)
		proto := f["row.protocol"]
		if out[c.Name] == nil {
			out[c.Name] = map[string]Fields{}
		}
		if _, dup := out[c.Name][proto]; dup {
			// Two rows of one protocol on one port: keep both visible.
			proto += "#2"
		}
		out[c.Name][proto] = f
	}
	return out
}

// Difference is one field on which two sides disagree.
type Difference struct {
	Comparison string // "golden/<path>", e.g. "golden/engine"
	Case       string
	Protocol   string
	Field      string // "finding" when one side has no finding of this protocol
	Left       string
	Right      string
}

func presence(ok bool) string {
	if ok {
		return "present"
	}
	return Absent
}

func unionKeys[V any](a, b map[string]V) []string {
	seen := map[string]bool{}
	for k := range a {
		seen[k] = true
	}
	for k := range b {
		seen[k] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// CompareGolden diffs one path's result against the fixture's ground truth.
// Only the fields the golden names are compared — the truth the fixture
// controls. An open-endpoint finding (protocol "tcp": an open port nothing
// identified) is not a crypto finding and is not compared.
func CompareGolden(path string, n *Network, got Result) []Difference {
	comparison := "golden/" + path
	var out []Difference
	for _, c := range n.Cases {
		if c.Unavailable != "" {
			continue
		}
		want := Golden(c)
		have := map[string]Fields{}
		for proto, f := range got[c.Name] {
			if proto != strconv.Quote("tcp") {
				have[proto] = f
			}
		}
		for _, proto := range unionKeys(want, have) {
			wf, wok := want[proto]
			hf, hok := have[proto]
			if !wok || !hok {
				out = append(out, Difference{comparison, c.Name, proto, "finding", presence(wok), presence(hok)})
				continue
			}
			for _, field := range sortedKeys(wf) {
				hv, ok := hf[field]
				if !ok {
					hv = Absent
				}
				if wf[field] != hv {
					out = append(out, Difference{comparison, c.Name, proto, field, wf[field], hv})
				}
			}
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// CheckGaps fails t for every difference KnownGaps does not name, and for every
// gap of these comparisons that no longer occurs. A gap naming cases must occur
// on EACH of them that ran; a gap naming none must occur at least once.
func CheckGaps(t testing.TB, n *Network, comparisons []string, diffs []Difference) {
	t.Helper()
	ran := n.RanCases()
	inScope := map[string]bool{}
	for _, c := range comparisons {
		inScope[c] = true
	}
	for _, d := range diffs {
		if len(matchingGaps(d)) == 0 {
			t.Errorf("UNKNOWN difference (name it in paritytest.KnownGaps or fix the path): %s case=%s protocol=%s field=%s: %s vs %s",
				d.Comparison, d.Case, d.Protocol, d.Field, clip(d.Left), clip(d.Right))
		}
	}
	for _, g := range KnownGaps {
		if !inScope[g.Comparison] {
			continue
		}
		if len(g.Cases) == 0 {
			if !anyMatch(g, diffs, "") {
				t.Errorf("gap %q (%s, field %s) no longer occurs on any case: it has closed — remove it from KnownGaps", g.ID, g.Comparison, g.Field)
			}
			continue
		}
		for _, c := range g.Cases {
			if !ran[c] {
				continue
			}
			if !anyMatch(g, diffs, c) {
				t.Errorf("gap %q (%s, field %s) no longer occurs on case %s: it has closed there — remove the case (or the gap) from KnownGaps", g.ID, g.Comparison, g.Field, c)
			}
		}
	}
}

func matchingGaps(d Difference) []Gap {
	var out []Gap
	for _, g := range KnownGaps {
		if g.matches(d) {
			out = append(out, g)
		}
	}
	return out
}

func anyMatch(g Gap, diffs []Difference, onCase string) bool {
	for _, d := range diffs {
		if (onCase == "" || d.Case == onCase) && g.matches(d) {
			return true
		}
	}
	return false
}

func (g Gap) matches(d Difference) bool {
	if g.Comparison != d.Comparison {
		return false
	}
	if !fieldMatches(g.Field, d.Field) {
		return false
	}
	if len(g.Cases) == 0 {
		return true
	}
	for _, c := range g.Cases {
		if c == d.Case {
			return true
		}
	}
	return false
}

// fieldMatches matches a gap's field pattern, where "*" stands for any run of
// characters (so "cert[*].is_self_signed" covers every chain position).
func fieldMatches(pattern, field string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == field
	}
	if !strings.HasPrefix(field, parts[0]) {
		return false
	}
	rest := field[len(parts[0]):]
	for _, p := range parts[1 : len(parts)-1] {
		j := strings.Index(rest, p)
		if j < 0 {
			return false
		}
		rest = rest[j+len(p):]
	}
	return strings.HasSuffix(rest, parts[len(parts)-1])
}

// Report logs every difference as a markdown table row with the gap that
// explains it — the raw material of the difference list.
func Report(t testing.TB, diffs []Difference) {
	t.Helper()
	var b strings.Builder
	b.WriteString("\n| comparison | case | protocol | field | left | right | gap |\n|---|---|---|---|---|---|---|\n")
	for _, d := range diffs {
		ids := []string{}
		for _, g := range matchingGaps(d) {
			ids = append(ids, g.ID)
		}
		gap := strings.Join(ids, ", ")
		if gap == "" {
			gap = "**UNKNOWN**"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n", d.Comparison, d.Case, d.Protocol, d.Field, clip(d.Left), clip(d.Right), gap)
	}
	t.Log(b.String())
}

// LogResult logs a path's normalized fields per case, for reading the values
// behind a difference.
func LogResult(t testing.TB, path string, n *Network, r Result) {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "\n== %s ==\n", path)
	for _, c := range n.Cases {
		if c.Unavailable != "" {
			fmt.Fprintf(&b, "-- %s: NOT RUN (%s)\n", c.Name, c.Unavailable)
			continue
		}
		fmt.Fprintf(&b, "-- %s (port %d): %d finding(s)\n", c.Name, c.Port, len(r[c.Name]))
		for _, proto := range sortedKeys(r[c.Name]) {
			f := r[c.Name][proto]
			fmt.Fprintf(&b, "   [%s]\n", proto)
			for _, k := range sortedKeys(f) {
				fmt.Fprintf(&b, "     %s = %s\n", k, clip(f[k]))
			}
		}
	}
	t.Log(b.String())
}

func clip(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	if len(s) > 90 {
		return s[:87] + "..."
	}
	return s
}
