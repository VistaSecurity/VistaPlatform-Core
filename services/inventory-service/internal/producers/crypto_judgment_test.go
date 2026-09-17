package producers

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/findings"
)

func producerIntPtr(value int) *int { return &value }

// Drive the real judge, not just the predicate: changing either emission gate
// back to score > 0 must fail both suppression and zero-score cases.
func TestCryptoJudge_StrengthIndependentOfScore(t *testing.T) {
	for _, tc := range []struct {
		name, strength string
		score          int
		want           string
	}{
		{"weak hidden below strong", "weak", 1, "uses weak cryptography"},
		{"weak tie", "weak", 90, "uses weak cryptography"},
		{"acceptable hidden below recommended", "acceptable", 1, "uses an algorithm rated acceptable"},
		{"acceptable tie", "acceptable", 90, "uses an algorithm rated acceptable"},
		{"strong nonzero", "strong", 10, ""},
		{"recommended nonzero", "recommended", 10, ""},
		{"unknown is not weak or strong", "", 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			high, other := 90, tc.score
			components, _ := json.Marshal([]configurationComponent{{Code: "HIGH", Role: "cipher_suite", Strength: "recommended", RiskScore: &high}, {Code: "OTHER", Role: "hash", Strength: tc.strength, RiskScore: &other}})
			cfg := configSubject{id: uuid.New(), assetID: uuid.New(), label: "endpoint", linked: 2, catalogueRisk: &high, components: components}
			cert := certSubject{id: uuid.New(), label: "certificate", assetIDs: []uuid.UUID{uuid.New()}, catalogue: []catalogueHit{{Code: "HIGH", Field: "public_key_algorithm", Strength: "strong", RiskScore: &high}, {Code: "OTHER", Field: "signature_algorithm", Strength: tc.strength, RiskScore: &other}}}
			plans, _ := (&CryptoProducer{}).judge([]configSubject{cfg}, []certSubject{cert}, nil, &CryptoRun{})
			emitted := 0
			for _, plan := range plans {
				if plan.retainOnly {
					continue
				}
				emitted++
				if tc.want == "" || !strings.Contains(plan.finding.Summary, tc.want) || plan.finding.Score != 90 {
					t.Errorf("finding=%+v", plan.finding)
				}
				if strings.Contains(plan.finding.Summary, "HIGH") {
					t.Errorf("numeric winner incorrectly chose title: %s", plan.finding.Summary)
				}
			}
			want := 0
			if tc.want != "" {
				want = 2
			}
			if emitted != want {
				t.Fatalf("emitted %d want %d", emitted, want)
			}
		})
	}
	for _, kind := range []string{findings.KindWeakConfiguration, findings.KindWeakCertificate} {
		t.Run(kind+" zero score", func(t *testing.T) {
			cfg := configSubject{id: uuid.New(), linked: 1, components: []byte(`[{"code":"WEAK","role":"hash","strength":"weak","risk_score":0}]`)}
			cert := certSubject{id: uuid.New(), catalogue: []catalogueHit{{Code: "WEAK", Strength: "weak", RiskScore: producerIntPtr(0)}}}
			plans, _ := (&CryptoProducer{}).judge([]configSubject{cfg}, []certSubject{cert}, nil, &CryptoRun{})
			for _, plan := range plans {
				if plan.finding.Kind == kind && !plan.retainOnly && plan.finding.Score == 0 && plan.finding.Severity == "info" {
					return
				}
			}
			t.Fatal("explicit weak zero-score catalogue judgment was suppressed")
		})
	}
}

func TestCryptoJudge_WeakNullCatalogueScoreRemainsUnscored(t *testing.T) {
	cfg := configSubject{id: uuid.New(), assetID: uuid.New(), linked: 1, components: []byte(`[{"code":"WEAK","role":"hash","strength":"weak","risk_score":null}]`)}
	cert := certSubject{id: uuid.New(), assetIDs: []uuid.UUID{uuid.New()}, keyBits: 256, catalogue: []catalogueHit{{Code: "WEAK", Field: "signature_algorithm", Strength: "weak"}}}
	plans, _ := (&CryptoProducer{}).judge([]configSubject{cfg}, []certSubject{cert}, nil, &CryptoRun{})
	if len(plans) != 2 {
		t.Fatalf("weak qualitative judgment was suppressed: %+v", plans)
	}
	for _, plan := range plans {
		if plan.retainOnly || (plan.finding.Kind != findings.KindWeakConfiguration && plan.finding.Kind != findings.KindWeakCertificate) {
			t.Fatalf("weak qualitative judgment was suppressed: %+v", plan)
		}
		ev := plan.finding.Evidence
		if _, exists := ev["catalogue_score"]; exists {
			t.Fatalf("null catalogue score was fabricated: %+v", ev)
		}
		if sources := ev["score_sources"].([]string); len(sources) != 0 {
			t.Fatalf("null catalogue score gained numeric provenance: %v", sources)
		}
		limitations := ev["assessment_limitations"].([]string)
		hasMissingScore := false
		for _, limitation := range limitations {
			hasMissingScore = hasMissingScore || strings.Contains(limitation, "no catalogue risk score")
		}
		if ev["reassessment_required"] != true || !hasMissingScore {
			t.Fatalf("missing-score limitation lost: %+v", ev)
		}
	}
}

func TestCryptoJudge_SizeHashExceptions(t *testing.T) {
	for _, tc := range []struct {
		name, key, hash string
		bits            int
		want            bool
	}{
		{"small RSA", "RSA", "", 1024, true}, {"small EC", "ECDSA", "", 192, true},
		{"healthy EC", "X25519", "", 256, false}, {"PQC size", "ML-KEM-768", "", 256, false},
		{"unknown family", "opaque", "", 256, false}, {"weak hash", "", "md5WithRSAEncryption", 0, true},
		{"deprecated hash", "", "SHA-1", 0, true}, {"healthy hash", "", "SHA-256", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := configSubject{keyAlg: tc.key, keyBits: tc.bits, hashAlg: tc.hash}
			cert := certSubject{keyAlg: tc.key, keyBits: tc.bits, sigAlg: tc.hash}
			plans, _ := (&CryptoProducer{}).judge([]configSubject{cfg}, []certSubject{cert}, nil, &CryptoRun{})
			n := 0
			for _, plan := range plans {
				if !plan.retainOnly {
					n++
					if !strings.Contains(plan.finding.Summary, "uses weak cryptography") || plan.finding.Score == 0 {
						t.Errorf("finding=%+v", plan.finding)
					}
				}
			}
			want := 0
			if tc.want {
				want = 2
			}
			if n != want {
				t.Fatalf("emitted=%d want=%d", n, want)
			}
		})
	}
}

func TestCryptoJudge_WeakPrecedesAcceptableAndUnknown(t *testing.T) {
	cfg := configSubject{components: []byte(`[
 {"code":"UNKNOWN","role":"signature","strength":"","risk_score":90},
 {"code":"ACCEPTABLE","role":"hash","strength":"acceptable","risk_score":70},
	 {"code":"WEAK","role":"key_exchange","strength":"weak","risk_score":0}]`), catalogueRisk: producerIntPtr(90), linked: 3}
	plans, _ := (&CryptoProducer{}).judge([]configSubject{cfg}, nil, nil, &CryptoRun{})
	if len(plans) != 1 || plans[0].retainOnly || !strings.Contains(plans[0].finding.Summary, "uses weak cryptography (WEAK") {
		t.Fatalf("plans=%+v", plans)
	}
	ev := plans[0].finding.Evidence
	if ev["reassessment_required"] != true || len(ev["assessment_limitations"].([]string)) != 1 {
		t.Fatalf("unknown component lost: %+v", ev)
	}
	sources := ev["score_sources"].([]string)
	if len(sources) != 1 || sources[0] != "UNKNOWN [signature]" {
		t.Fatalf("numeric sources=%v", sources)
	}
}
