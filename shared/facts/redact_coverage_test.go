package facts_test

// The fact-key registry's `redact` flag, held against the redactor that would
// have to honour it.
//
// # What the flag promises, and what reads it
//
// `standards/fact-keys.yaml` requires every key to state `redact` explicitly:
// "whether the value must be masked in exports, logs and AI prompts … Nothing at
// launch is redacted, because nothing here is key material: we collect posture,
// never secrets. The flag exists so that a key which ever does carry something
// sensitive has to say so."
//
// Nothing reads it. The generator copies it into `facts.Key.Redact` and
// `keys.gen.ts`, and no Go or TypeScript file in the repository consults either.
// So the honest description of the flag today is not "the sensitive keys are
// masked" — it is "no key is sensitive yet, and if one became sensitive
// tomorrow the YAML would say so and nothing would happen".
//
// That is a fine place to be while every key is `false`, and a dangerous one to
// discover later. The failure would be silent in the worst direction: a key
// declared sensitive, stated as masked in the registry a reviewer reads, and
// crossing the AI provider boundary in clear. "Did not check, rendered as
// passed", one more time.
//
// # What this test does about it
//
// The provider boundary's redactor is NAME-based ([redact.IsSecretName]), so a
// key it would mask is a key whose leaf name looks secret. That gives a checkable
// rule that costs nothing today and fires the moment the flag stops being
// decorative: a fact key marked `redact: true` must be one the boundary redactor
// already catches. If it is not, the two disagree, and the YAML is the half that
// reads as a guarantee.
//
// The rule is stated as a function over ARBITRARY definitions rather than over
// [facts.All] alone, precisely so it cannot be vacuous: the synthetic cases below
// exercise both polarities on a registry where every real row is `false`.

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/redact"
)

// uncoveredSensitiveKeys returns the keys marked sensitive that the boundary
// redactor would NOT mask, by leaf name.
//
// The leaf is what matters: a fact travels to a prompt as a map entry, and the
// redactor judges the field name above the value. `sw.cpe` arrives as `cpe`,
// `net.interfaces` as `interfaces`. A namespaced key is never handed to the
// redactor whole.
func uncoveredSensitiveKeys(keys []facts.Key) []string {
	var out []string
	for _, k := range keys {
		if !k.Redact {
			continue
		}
		leaf := k.Key
		if i := strings.LastIndex(leaf, "."); i >= 0 {
			leaf = leaf[i+1:]
		}
		if !redact.IsSecretName(leaf) && !redact.IsSecretName(k.Key) {
			out = append(out, k.Key)
		}
	}
	return out
}

// The real registry. Today this passes by having nothing to examine, which is
// exactly why the polarity test below is not optional.
func TestFactKeys_SensitiveKeysAreCoveredByTheBoundaryRedactor(t *testing.T) {
	uncovered := uncoveredSensitiveKeys(facts.All)
	for _, key := range uncovered {
		t.Errorf("fact key %q is declared `redact: true` in standards/fact-keys.yaml, but "+
			"shared/redact would not mask it — so the value would reach an AI provider, an export "+
			"and a log in clear while the registry a reviewer reads says it is masked.\n"+
			"Fix it one of two ways: name the key so the redactor catches it (the fragment and "+
			"suffix lists are in shared/redact/redact.go), or add the name there deliberately.", key)
	}

	sensitive := 0
	for _, k := range facts.All {
		if k.Redact {
			sensitive++
		}
	}
	t.Logf("%d fact keys, %d declared sensitive", len(facts.All), sensitive)
}

// Both polarities of the rule itself, on synthetic definitions, because the real
// registry has no sensitive key and a check that examines nothing is worse than
// no check.
func TestFactKeys_TheCoverageRuleItselfWorks(t *testing.T) {
	cases := []struct {
		name      string
		keys      []facts.Key
		uncovered []string
	}{
		{
			name: "a sensitive key the redactor would miss is reported",
			keys: []facts.Key{{Key: "svc.community", Redact: false},
				{Key: "mgmt.banner_text", Redact: true}},
			uncovered: []string{"mgmt.banner_text"},
		},
		{
			name:      "a sensitive key the redactor catches by leaf name is not",
			keys:      []facts.Key{{Key: "mgmt.snmp_community", Redact: true}},
			uncovered: nil,
		},
		{
			name:      "a non-sensitive key is never reported, however it is named",
			keys:      []facts.Key{{Key: "mgmt.banner_text", Redact: false}},
			uncovered: nil,
		},
		{
			name: "posture keys stay posture: the rule must not demand they be masked",
			keys: []facts.Key{{Key: "tls.key_size", Redact: false},
				{Key: "ssh.public_key", Redact: false}},
			uncovered: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := uncoveredSensitiveKeys(tc.keys)
			if strings.Join(got, ",") != strings.Join(tc.uncovered, ",") {
				t.Errorf("uncovered = %v, want %v", got, tc.uncovered)
			}
		})
	}
}
