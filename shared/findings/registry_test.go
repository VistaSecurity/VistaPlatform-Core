package findings

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// allowedSubjectTypes is the ADR-0005 D3 vocabulary, written out by hand so
// that a mistaken addition to the YAML has to be made twice before it lands.
var allowedSubjectTypes = map[string]bool{
	"asset":                true,
	"endpoint":             true,
	"certificate":          true,
	"key":                  true,
	"crypto_configuration": true,
	"software_install":     true,
	"relationship":         true,
	"control":              true,
	"framework":            true,
}

var validSeverities = map[string]bool{
	"critical":       true,
	"high":           true,
	"medium":         true,
	"low":            true,
	"info":           true,
	"from-control":   true,
	"from-catalogue": true,
}

func TestRegistryIsNotEmpty(t *testing.T) {
	if len(Producers) == 0 {
		t.Fatal("no producers in the generated registry")
	}
	if len(All) == 0 {
		t.Fatal("no kinds in the generated registry")
	}
}

// The seven producers ADR-0005 D3 names, pinned by hand: dropping one is a
// product decision, not something a YAML edit should be able to do quietly.
func TestEveryADRProducerIsPresent(t *testing.T) {
	for _, want := range []string{
		ProducerCompliance, ProducerCrypto, ProducerEOL, ProducerVulnerability,
		ProducerConfiguration, ProducerHygiene, ProducerDrift,
	} {
		if _, ok := GetProducer(want); !ok {
			t.Errorf("producer %q from ADR-0005 D3 is missing from the registry", want)
		}
	}
}

func TestEveryKindBelongsToARegisteredProducer(t *testing.T) {
	for _, k := range All {
		if _, ok := GetProducer(k.Producer); !ok {
			t.Errorf("kind %q names producer %q, which is not registered", k.Key, k.Producer)
		}
	}
}

func TestKindKeysAreUniqueAcrossProducers(t *testing.T) {
	seen := map[string]string{}
	for _, k := range All {
		if prev, dup := seen[k.Key]; dup {
			t.Errorf("kind %q is declared by both %q and %q", k.Key, prev, k.Producer)
		}
		seen[k.Key] = k.Producer
	}
}

func TestEveryKindHasAValidSeverityModel(t *testing.T) {
	for _, k := range All {
		switch k.SeverityModel {
		case "fixed":
			if !validSeverities[k.DefaultSeverity] {
				t.Errorf("%s/%s: fixed kind has invalid default_severity %q", k.Producer, k.Key, k.DefaultSeverity)
			}
			if len(k.Rungs) != 0 {
				t.Errorf("%s/%s: fixed kind must not carry rungs", k.Producer, k.Key)
			}
		case "ladder":
			if k.DefaultSeverity != "" {
				t.Errorf("%s/%s: ladder kind must not carry a default_severity", k.Producer, k.Key)
			}
			if len(k.Rungs) < 2 {
				t.Errorf("%s/%s: ladder kind needs at least two rungs, got %d", k.Producer, k.Key, len(k.Rungs))
			}
			for _, r := range k.Rungs {
				if r.Threshold == "" {
					t.Errorf("%s/%s: rung with no threshold", k.Producer, k.Key)
				}
				if !validSeverities[r.Severity] {
					t.Errorf("%s/%s: rung %q has invalid severity %q", k.Producer, k.Key, r.Threshold, r.Severity)
				}
			}
		default:
			t.Errorf("%s/%s: unknown severity model %q", k.Producer, k.Key, k.SeverityModel)
		}
	}
}

func TestEverySubjectTypeIsFromTheAllowedSet(t *testing.T) {
	for _, s := range SubjectTypes {
		if !allowedSubjectTypes[s] {
			t.Errorf("registry subject type %q is not in the ADR-0005 D3 vocabulary", s)
		}
	}
	if len(SubjectTypes) != len(allowedSubjectTypes) {
		t.Errorf("registry declares %d subject types, ADR-0005 D3 names %d", len(SubjectTypes), len(allowedSubjectTypes))
	}
	for _, k := range All {
		if len(k.SubjectTypes) == 0 {
			t.Errorf("%s/%s: no subject types", k.Producer, k.Key)
		}
		for _, s := range k.SubjectTypes {
			if !allowedSubjectTypes[s] {
				t.Errorf("%s/%s: subject type %q is not in the allowed set", k.Producer, k.Key, s)
			}
		}
	}
}

func TestScoresAreWithinBounds(t *testing.T) {
	for _, k := range All {
		if k.Score < 0 || k.Score > 100 {
			t.Errorf("%s/%s: score %d out of bounds 0-100", k.Producer, k.Key, k.Score)
		}
		for _, r := range k.Rungs {
			if r.Score < 0 || r.Score > 100 {
				t.Errorf("%s/%s: rung %q score %d out of bounds 0-100", k.Producer, k.Key, r.Threshold, r.Score)
			}
		}
	}
}

// Hygiene is data quality, not security. ADR-0005 D4 is explicit that it
// contributes zero: a missing owner must never inflate a risk score.
func TestHygieneNeverFeedsRisk(t *testing.T) {
	for _, k := range All {
		if k.Producer != ProducerHygiene {
			continue
		}
		if k.FeedsRisk {
			t.Errorf("hygiene kind %q feeds risk; ADR-0005 D4 requires it not to", k.Key)
		}
		if FeedsRisk(k.Producer, k.Key) {
			t.Errorf("FeedsRisk(%q, %q) is true; ADR-0005 D4 requires hygiene to score 0", k.Producer, k.Key)
		}
	}
}

func TestKindsThatDoNotFeedRiskScoreZero(t *testing.T) {
	for _, k := range All {
		if k.FeedsRisk {
			continue
		}
		if k.Score != 0 {
			t.Errorf("%s/%s: does not feed risk but declares score %d", k.Producer, k.Key, k.Score)
		}
		for _, r := range k.Rungs {
			if r.Score != 0 {
				t.Errorf("%s/%s: does not feed risk but rung %q declares score %d", k.Producer, k.Key, r.Threshold, r.Score)
			}
		}
	}
}

// The catalogue is the single opinion on crypto risk (CLAUDE.md, "The
// catalogue drives risk scoring"). A literal score on a crypto kind would be
// the second opinion that guidance exists to prevent.
func TestCryptoScoresComeFromTheCatalogue(t *testing.T) {
	for _, k := range All {
		if k.Producer != ProducerCrypto || k.Key == KindPQCVulnerable {
			continue
		}
		if k.ScoreSource != "catalogue" {
			t.Errorf("crypto kind %q has score_source %q, want catalogue", k.Key, k.ScoreSource)
		}
	}
}

func TestVulnerabilityScoreIsCVSSx10(t *testing.T) {
	k, ok := Get(ProducerVulnerability, KindKnownVulnerability)
	if !ok {
		t.Fatal("vulnerability/known_vulnerability is missing")
	}
	if k.ScoreSource != "cvss_x10" {
		t.Errorf("score_source is %q, want cvss_x10 (the convention RiskBands is anchored to)", k.ScoreSource)
	}
}

func TestEveryTitleTemplateNamesItsSubject(t *testing.T) {
	for _, k := range All {
		if !strings.Contains(k.TitleTemplate, "{subject}") {
			t.Errorf("%s/%s: title template %q never names the subject", k.Producer, k.Key, k.TitleTemplate)
		}
		if k.Description == "" {
			t.Errorf("%s/%s: no description", k.Producer, k.Key)
		}
	}
}

func TestGet(t *testing.T) {
	k, ok := Get(ProducerEOL, KindOSEndOfLife)
	if !ok {
		t.Fatal("eol/os_end_of_life is missing")
	}
	if k.Producer != ProducerEOL || k.Key != KindOSEndOfLife {
		t.Errorf("Get returned %s/%s", k.Producer, k.Key)
	}
	if _, ok := Get(ProducerEOL, "not_a_kind"); ok {
		t.Error("Get accepted an unregistered kind")
	}
	// A kind that exists, but under a different producer, must not resolve.
	if _, ok := Get(ProducerHygiene, KindOSEndOfLife); ok {
		t.Error("Get resolved a kind under the wrong producer")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name                    string
		producer, kind, subject string
		wantErr                 bool
		wantErrContains         string
	}{
		{
			name:     "registered triple",
			producer: ProducerEOL, kind: KindOSEndOfLife, subject: SubjectAsset,
		},
		{
			name:     "unknown producer",
			producer: "telepathy", kind: KindOSEndOfLife, subject: SubjectAsset,
			wantErr: true, wantErrContains: "unknown producer",
		},
		{
			name:     "kind not emitted by this producer",
			producer: ProducerHygiene, kind: KindOSEndOfLife, subject: SubjectAsset,
			wantErr: true, wantErrContains: "does not emit kind",
		},
		{
			name:     "subject type the kind disallows",
			producer: ProducerEOL, kind: KindOSEndOfLife, subject: SubjectCertificate,
			wantErr: true, wantErrContains: "cannot be about subject type",
		},
		{
			name:     "subject type outside the vocabulary",
			producer: ProducerEOL, kind: KindOSEndOfLife, subject: "banana",
			wantErr: true, wantErrContains: "cannot be about subject type",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.producer, tc.kind, tc.subject)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Validate(%q, %q, %q) returned nil, want error", tc.producer, tc.kind, tc.subject)
				}
				if !strings.Contains(err.Error(), tc.wantErrContains) {
					t.Errorf("error %q does not mention %q", err, tc.wantErrContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate(%q, %q, %q) = %v, want nil", tc.producer, tc.kind, tc.subject, err)
			}
		})
	}
}

// Every registered triple must pass Validate — otherwise the registry declares
// something the enforcement point would reject.
func TestValidateAcceptsEveryRegisteredTriple(t *testing.T) {
	for _, k := range All {
		for _, s := range k.SubjectTypes {
			if err := Validate(k.Producer, k.Key, s); err != nil {
				t.Errorf("Validate(%q, %q, %q) = %v, want nil", k.Producer, k.Key, s, err)
			}
		}
	}
}

func TestFeedsRiskRejectsUnregisteredPairs(t *testing.T) {
	if FeedsRisk("telepathy", "hunch") {
		t.Error("FeedsRisk accepted an unregistered pair")
	}
	if !FeedsRisk(ProducerEOL, KindOSEndOfLife) {
		t.Error("eol/os_end_of_life should feed risk")
	}
}

// The drift audit `make audit` runs, executed here too so a `go test ./...`
// catches a stale generated file without waiting for CI.
func TestGeneratedFileMatchesYAML(t *testing.T) {
	root := repoRoot(t)
	script := filepath.Join(root, "scripts", "generate-findings-registry.mjs")
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

// Guidance is the remediator seam's null default (ADR-0008 D1): a deployment
// with no model configured answers "draft me a remediation plan" with exactly
// this string. A kind missing it therefore answers with nothing, which reads as
// "there is nothing to do about this" rather than as "nobody wrote this yet".
func TestEveryKindCarriesCustomerFacingGuidance(t *testing.T) {
	for _, k := range All {
		if strings.TrimSpace(k.Guidance) == "" {
			t.Errorf("%s/%s: no guidance — nothing answers a finding of this kind without a model", k.Producer, k.Key)
			continue
		}
		// Guidance and Description are written for different readers.
		// Description carries table names, workstream numbers and internal
		// history; Guidance goes in front of a tenant and into a prompt. A copy
		// of one into the other is the mistake that would leak the first.
		if strings.TrimSpace(k.Guidance) == strings.TrimSpace(k.Description) {
			t.Errorf("%s/%s: guidance is a copy of description", k.Producer, k.Key)
		}
	}
}

func TestGuidanceFor(t *testing.T) {
	got, ok := GuidanceFor(ProducerCrypto, KindWeakConfiguration)
	if !ok {
		t.Fatal("crypto/weak_configuration has no guidance")
	}
	if got == "" {
		t.Error("GuidanceFor returned an empty string for a registered kind")
	}

	// The false is the point: an unregistered pair must not answer with an
	// empty string that reads like "there is nothing to do".
	if _, ok := GuidanceFor(ProducerCrypto, "not_a_kind"); ok {
		t.Error("GuidanceFor resolved an unregistered kind")
	}
	if _, ok := GuidanceFor("not_a_producer", KindWeakConfiguration); ok {
		t.Error("GuidanceFor resolved a kind under an unknown producer")
	}
}
