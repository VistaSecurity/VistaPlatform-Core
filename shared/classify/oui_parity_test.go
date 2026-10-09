package classify

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/ouiregistry"
)

// One manufacturer, one name, and the name is standards/oui/vendors.yaml's.
//
// MAC -> vendor has one owner on the platform: the IEEE registry compiled into
// shared/ouiregistry, canonicalised by standards/oui/vendors.yaml. The engine
// reports that canonical vendor for every MAC it resolves, so every OTHER place
// a vendor is named — the `oui_classes` keys the `oui_vendor` rules are derived
// from, and the `vendor:` of every hand-written rule — has to use the same
// spelling, or the two cancel in the vendor arbitration rather than agreeing
// (a Dell server seen by MAC and by sysObjectID came back with NO vendor while
// the two were spelled `Dell` and `Dell Inc.`).
//
// The generator enforces this at `make generate` time; this is the same
// property asserted over the generated table, with
// `vendors_outside_oui_table` as the only escape hatch.
func TestRuleVendors_AreCanonicalOrDeclaredOutside(t *testing.T) {
	outside := map[string]bool{}
	for _, v := range rulesYAML(t).VendorsOutside {
		if ouiregistry.IsCanonicalVendor(v) {
			t.Errorf("vendors_outside_oui_table lists %q, which IS a canonical vendor in standards/oui/vendors.yaml", v)
		}
		outside[v] = true
	}
	checked := 0
	for _, r := range generatedRules {
		if r.Vendor == "" {
			continue
		}
		checked++
		if !ouiregistry.IsCanonicalVendor(r.Vendor) && !outside[r.Vendor] {
			t.Errorf("%s rule %q names vendor %q, which is neither a canonical vendor in "+
				"standards/oui/vendors.yaml nor declared in vendors_outside_oui_table", r.Kind, r.Pattern, r.Vendor)
		}
	}
	if checked < 50 {
		t.Fatalf("only %d rules name a vendor; this test is not looking at the generated table", checked)
	}
}

// Every `oui_classes` key became exactly one `oui_vendor` rule, named by its
// CANONICAL spelling — the only spelling the engine matches an oui_vendor rule
// against — and the rule's vendor is its pattern.
func TestOUIVendorRules_AreTheOUIClassesMap(t *testing.T) {
	classes := rulesYAML(t).OUIClasses
	if len(classes) < 20 {
		t.Fatalf("only %d oui_classes entries read from the YAML", len(classes))
	}
	seen := map[string]bool{}
	for _, r := range generatedRules {
		if r.Kind != KindOUIVendor {
			continue
		}
		seen[r.Pattern] = true
		if !ouiregistry.IsCanonicalVendor(r.Pattern) {
			t.Errorf("oui_vendor rule %q is not a canonical vendor; it can never match", r.Pattern)
		}
		if r.Vendor != r.Pattern {
			t.Errorf("oui_vendor rule %q carries vendor %q", r.Pattern, r.Vendor)
		}
		want, ok := classes[r.Pattern]
		if !ok {
			t.Errorf("oui_vendor rule %q has no oui_classes entry; it was not derived from the map", r.Pattern)
			continue
		}
		if r.Class != want.Class || r.Confidence != want.Confidence {
			t.Errorf("oui_vendor rule %q = %s@%.2f, oui_classes says %s@%.2f",
				r.Pattern, r.Class, r.Confidence, want.Class, want.Confidence)
		}
	}
	for v := range classes {
		if !seen[v] {
			t.Errorf("oui_classes names %q but no oui_vendor rule was generated for it", v)
		}
	}
}

// Every shipped `oui_vendor` rule fires on a REAL assignment of its vendor.
//
// A rule whose pattern the registry never produces is a well-formed row that
// matches nothing, for ever, while nothing says so — the shape of a check that
// cannot fail. Driving each one through the engine with a MAC taken from the
// embedded registry is what proves the canonical-name wiring end to end.
func TestOUIVendorRules_EachMatchesARealAssignment(t *testing.T) {
	e := Default()
	n := 0
	for _, r := range generatedRules {
		if r.Kind != KindOUIVendor {
			continue
		}
		n++
		mac := firstMACOf(t, r.Pattern)
		got := e.Classify(t.Context(), ClassifyInput{MACs: []string{mac}})
		if got.Vendor != r.Pattern {
			t.Errorf("%s (%s): Vendor = %q", r.Pattern, mac, got.Vendor)
		}
		fired := false
		for _, m := range got.MatchedRules {
			if m.Kind == KindOUIVendor && m.Pattern == r.Pattern && m.Class == r.Class {
				fired = true
			}
		}
		if !fired {
			t.Errorf("oui_vendor rule %q did not fire on %s (matched %+v)", r.Pattern, mac, got.MatchedRules)
		}
	}
	if n == 0 {
		t.Fatal("no oui_vendor rules in the generated table")
	}
}

// Most manufacturers get a vendor and NO class, and that is the rule of thumb
// working rather than a gap to be filled in.
//
// A manufacturer selling servers, switches and printers under one IEEE
// assignment has no majority worth guessing at, so only a minority of the
// canonical vendors appear in `oui_classes`. If this ratio ever inverts,
// somebody has been filling in blanks, and the next thing to happen is a
// plausible wrong class getting bulk-approved.
func TestOUIVendorRules_AreAMinorityOfVendors(t *testing.T) {
	var classed int
	for _, r := range generatedRules {
		if r.Kind == KindOUIVendor && r.Class != "" {
			classed++
		}
	}
	all := len(ouiregistry.CanonicalVendors())
	if classed == 0 {
		t.Fatal("no oui_vendor rule proposes a class; the oui_classes map is not being applied")
	}
	if classed*2 >= all {
		t.Errorf("%d of %d canonical vendors carry a class — a wrong class is worse than none, "+
			"and this ratio says the blanks are being filled in", classed, all)
	}
}

// The CAPABILITY vocabularies have exactly one owner too: shared/hostobs'
// decoders, which turn a CDP or 802.1AB bitmask into names.
//
// A `cdp_capabilities` or `lldp_capability` rule is written in those words, and
// this is the same silent-failure shape as the banner contract one section over:
// a rule whose pattern names `wlan_acess_point` is a perfectly valid rule — the
// generator's regexp accepts it, the engine's validator accepts it, the CHECK
// accepts it, and it matches NOTHING for any device, for ever, while nothing
// anywhere says so. The classifier just quietly stops proposing `access_point`.
//
// Neither validator can catch it, because neither knows the vocabulary. This
// does, and it is the only thing that does.
//
// Mutation-checked: change one capability name in the YAML, run
// `make generate`, and this fails naming the rule.
func TestCapabilityRules_SpeakTheDecodersVocabulary(t *testing.T) {
	known := map[string]map[string]bool{
		KindCDPCapabilities: setOf(hostobs.CDPCapabilityNames()),
		KindLLDPCapability:  setOf(hostobs.LLDPCapabilityNames()),
	}
	seen := 0
	for _, r := range Default().Rules() {
		vocab, ok := known[r.Kind]
		if !ok {
			continue
		}
		seen++
		for _, name := range strings.Split(r.Pattern, ",") {
			if !vocab[name] {
				t.Errorf("%s rule %q names capability %q, which shared/hostobs' decoder never emits — "+
					"the rule can never match anything, and nothing would report that",
					r.Kind, r.Pattern, name)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no capability rules were checked; this test would then prove nothing")
	}
}

func setOf(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, v := range values {
		out[v] = true
	}
	return out
}

// ---- helpers ----------------------------------------------------------------

func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}

type rulesYAMLDoc struct {
	VendorsOutside []string `yaml:"vendors_outside_oui_table"`
	OUIClasses     map[string]struct {
		Class      string  `yaml:"class"`
		Confidence float64 `yaml:"confidence"`
	} `yaml:"oui_classes"`
}

func rulesYAML(t *testing.T) rulesYAMLDoc {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "standards", "classification-rules.yaml"))
	if err != nil {
		t.Fatalf("read classification-rules.yaml: %v", err)
	}
	var doc rulesYAMLDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse classification-rules.yaml: %v", err)
	}
	return doc
}

var (
	registryRowsOnce sync.Once
	registryRows     map[string]string // vendor -> first 24-bit prefix (or a longer one when it has none)
)

// firstMACOf returns a MAC, in colon form, that the embedded registry resolves
// to vendor, taken from shared/ouiregistry's own generated table — so the test
// exercises the registry the engine uses, not a hand-picked list that could
// drift from it.
func firstMACOf(t *testing.T, vendor string) string {
	t.Helper()
	registryRowsOnce.Do(func() {
		registryRows = map[string]string{}
		f, err := os.Open(filepath.Join(repoRoot(t), "shared", "ouiregistry", "registry_gen.tsv"))
		if err != nil {
			return
		}
		defer func() { _ = f.Close() }()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if line == "" || line[0] == '#' {
				continue
			}
			hex, v, ok := strings.Cut(line, "\t")
			if !ok {
				continue
			}
			if prev, have := registryRows[v]; !have || (len(prev) > 6 && len(hex) == 6) {
				registryRows[v] = hex
			}
		}
	})
	hex, ok := registryRows[vendor]
	if !ok {
		t.Fatalf("the embedded registry has no assignment resolving to %q", vendor)
	}
	full := (hex + "123456789ABC")[:12]
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(full[i : i+2])
	}
	mac := b.String()
	if got := ouiregistry.VendorForMAC(mac); got != vendor {
		t.Fatalf("constructed %s for %q but the registry resolves it to %q", mac, vendor, got)
	}
	return mac
}
