package registrycatalog

// The two catalogues, compared FIELD BY FIELD.
//
// There are two: the registry-derived one this package builds from
// standards/asset-classes.yaml, standards/fact-keys.yaml and schema.sql, and
// the static §4.3 one under testcatalog/ that the cross-language conformance
// fixtures resolve against. The static one is a spec fixture and is allowed to
// carry a SUBSET — it publishes a handful of representative `attr.` and `fact.`
// keys rather than all several hundred — but where the two publish the same
// field, they must mean the same thing.
//
// They did not, in eleven places, and every one of them had the same shape: a
// predicate the spec fixtures accepted and the product refused, or the other
// way round.
//
//   - `attr.os_version` typed NUMBER here and KEYWORD there, so
//     `attr.os_version < 3` was a documented example and an
//     `operator_not_allowed` in the running product.
//   - `attr.operating_system` and `attr.firmware_version`, TEXT vs KEYWORD.
//   - `attr.provider` missing `oci` and `other`.
//   - `attr.managed` and `fact.cve.max_cvss`, which are not a registered
//     attribute or fact key at all.
//   - `fact.eol.software.date`, for a key spelled `eol.sw.date`.
//   - `fact.os.version`, TEXT vs KEYWORD.
//   - `endpoint.protocol` and `crypto_configuration.protocol` five OT values
//     short, so `protocol:S7` was invalid in the fixture and stored in the
//     database.
//   - `crypto_configuration.strength` with no closed set on the static side, so
//     `strength:strng` validated and returned nothing.
//   - `identifier.kind` offering `mac`, which the column never holds.
//   - `observation.network.type` at two values instead of four (§14 B1).
//
// Every one is resolved in the registry's favour, which is the rule: the
// registry catalogue is derived from the schema and the standards files, and
// where the spec fixture disagrees with the schema it is the fixture that is
// wrong. This test is what stops a twelfth arriving.
//
// The named exceptions below are the differences that remain, each with a
// reason. A field that diverges for a reason belongs in that list, not in
// silence.

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog/testcatalog"
)

// knownDifferences are the fields the two catalogues deliberately differ on.
//
// Keyed `<target>.<field>`, valued with the reason. The list is asserted in
// BOTH directions: an entry naming a field that now AGREES is reported, so a
// resolved difference cannot sit here forever describing a state of the world
// that ended.
var knownDifferences = map[string]string{
	// Descriptions are autocomplete help text and carry no meaning a predicate
	// depends on. The registry catalogue writes them; the spec fixture does
	// not, and copying several hundred strings into a fixture would make it
	// harder to read for nothing.
	//
	// (Descriptions are not compared at all below — this entry exists to say
	// so, because a reader finding no description check will otherwise assume
	// one was forgotten.)
	"*.description": "descriptions are help text; the static catalogue carries none",
}

func TestBothCataloguesMeanTheSameThingByTheSameField(t *testing.T) {
	static := testcatalog.New()
	registry := newCatalog()

	seen := map[string]bool{}
	for _, target := range registry.Targets() {
		staticFields := map[string]catalog.FieldInfo{}
		for _, f := range static.Fields(target.Name) {
			staticFields[f.Name] = f
		}
		for _, rf := range registry.Fields(target.Name) {
			sf, ok := staticFields[rf.Name]
			if !ok {
				// The static catalogue is a documented SUBSET. A field it does
				// not publish is not a disagreement about meaning.
				continue
			}
			key := target.Name + "." + rf.Name
			seen[key] = true
			if _, exempt := knownDifferences[key]; exempt {
				continue
			}
			if sf.Type != rf.Type {
				t.Errorf("%s: type differs — registry %q, static %q.\n"+
					"One of them accepts an operator the other refuses, so the same "+
					"predicate is valid in the fixtures and rejected in the product "+
					"(or the reverse).", key, rf.Type, sf.Type)
			}
			if !sameValueSet(rf.Enum, sf.Enum) {
				t.Errorf("%s: closed value set differs —\n  registry %v\n  static   %v\n"+
					"A value only the static side has validates and then matches no row, "+
					"for ever; a value only the registry has is refused by the fixtures "+
					"while the database stores it.", key, sorted(rf.Enum), sorted(sf.Enum))
			}
		}
	}

	// A field the STATIC catalogue publishes and the registry does not is a
	// disagreement of the worst kind: the fixtures document a predicate the
	// product answers with `unknown_field`.
	for _, target := range static.Targets() {
		registryFields := map[string]bool{}
		for _, f := range registry.Fields(target.Name) {
			registryFields[f.Name] = true
		}
		for _, sf := range static.Fields(target.Name) {
			if registryFields[sf.Name] {
				continue
			}
			key := target.Name + "." + sf.Name
			if _, exempt := knownDifferences[key]; exempt {
				continue
			}
			t.Errorf("%s is published by the static catalogue and not by the registry one. "+
				"A conformance fixture may write it; the running product answers "+
				"unknown_field. Either register the key or stop publishing it.", key)
		}
	}

	for key := range knownDifferences {
		if strings.HasPrefix(key, "*.") {
			continue
		}
		if !seen[key] {
			t.Errorf("knownDifferences names %q, which the two catalogues no longer both "+
				"publish. An exemption that cannot fire is a comment pretending to be a "+
				"check — delete it.", key)
		}
	}
}

// The `attr.` and `fact.` keys the static catalogue DOES publish must every one
// of them be real.
//
// The subset rule above lets the fixture publish fewer keys; it must not let it
// publish keys that do not exist. `attr.managed` and `fact.cve.max_cvss` were
// both illustrative names nothing registers, so the §4.3 examples written
// against them documented a language the product does not speak.
func TestEveryStaticNamespacedKeyIsRegistered(t *testing.T) {
	static := testcatalog.New()
	registry := newCatalog()

	registryNames := map[string]bool{}
	for _, f := range registry.Fields("asset") {
		registryNames[f.Name] = true
	}
	for _, f := range static.Fields("asset") {
		if !strings.HasPrefix(f.Name, "attr.") && !strings.HasPrefix(f.Name, "fact.") {
			continue
		}
		if !registryNames[f.Name] {
			t.Errorf("the static catalogue publishes %q, which no registry declares. "+
				"standards/asset-classes.yaml and standards/fact-keys.yaml are the "+
				"vocabularies; a fixture key outside them is a predicate the product "+
				"answers with unknown_field.", f.Name)
		}
	}
}

func sameValueSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := sorted(a), sorted(b)
	for i := range x {
		if !strings.EqualFold(x[i], y[i]) {
			return false
		}
	}
	return true
}
