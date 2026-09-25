package services

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

func kexComponent(code string, isPQC bool) models.CryptoComponentAssessment {
	return models.CryptoComponentAssessment{AlgorithmType: "key_exchange", Code: code, IsPQC: isPQC}
}

func otherComponent(role, code string) models.CryptoComponentAssessment {
	return models.CryptoComponentAssessment{AlgorithmType: role, Code: code}
}

// hintsOn returns the codes of the components carrying the hint, and the
// groups each one names.
func hintsOn(components []models.CryptoComponentAssessment) map[string][]string {
	out := map[string][]string{}
	for _, c := range components {
		if c.HybridKexAvailable != nil {
			out[c.Code] = c.HybridKexAvailable.Groups
		}
	}
	return out
}

func TestAnnotateHybridKexAvailability(t *testing.T) {
	tests := []struct {
		name       string
		components []models.CryptoComponentAssessment
		evidence   hybridKexEvidence
		want       map[string][]string
	}{
		{
			name:       "classical negotiated, hybrid supported, group known",
			components: []models.CryptoComponentAssessment{otherComponent("symmetric", "AES128-GCM"), kexComponent("X25519", false)},
			evidence:   hybridKexEvidence{Supported: true, Group: "X25519MLKEM768"},
			want:       map[string][]string{"X25519": {"X25519MLKEM768"}},
		},
		{
			name:       "classical negotiated, hybrid supported, group not recorded",
			components: []models.CryptoComponentAssessment{kexComponent("DH-ECP-256", false)},
			evidence:   hybridKexEvidence{Supported: true},
			want:       map[string][]string{"DH-ECP-256": {}},
		},
		{
			// A group name the probes would never write is not shown: the
			// hint names only what a handshake could have measured.
			name:       "recorded group is not a hybrid group",
			components: []models.CryptoComponentAssessment{kexComponent("X25519", false)},
			evidence:   hybridKexEvidence{Supported: true, Group: "X25519"},
			want:       map[string][]string{"X25519": {}},
		},
		{
			name:       "server refused the hybrid offer",
			components: []models.CryptoComponentAssessment{kexComponent("X25519", false)},
			evidence:   hybridKexEvidence{Supported: false},
			want:       map[string][]string{},
		},
		{
			// Absent is unknown, never true: evidence the ingest did not see
			// must not produce a hint.
			name:       "hybrid support unknown",
			components: []models.CryptoComponentAssessment{kexComponent("X25519", false)},
			evidence:   hybridKexEvidence{},
			want:       map[string][]string{},
		},
		{
			name:       "already negotiating hybrid",
			components: []models.CryptoComponentAssessment{kexComponent("X25519MLKEM768", true)},
			evidence:   hybridKexEvidence{Supported: true, Group: "X25519MLKEM768"},
			want:       map[string][]string{},
		},
		{
			// Any hybrid key exchange on the configuration means it is not
			// "negotiated classical" — no hint, rather than a hint that
			// contradicts the hybrid component beside it.
			name:       "classical and hybrid both linked",
			components: []models.CryptoComponentAssessment{kexComponent("X25519", false), kexComponent("X25519MLKEM768", true)},
			evidence:   hybridKexEvidence{Supported: true, Group: "X25519MLKEM768"},
			want:       map[string][]string{},
		},
		{
			// A family label derived from the cipher-suite name is not a
			// negotiated group, so the hint cannot say what was negotiated.
			name:       "key exchange is a suite-derived family label",
			components: []models.CryptoComponentAssessment{kexComponent("ECDHE", false)},
			evidence:   hybridKexEvidence{Supported: true, Group: "X25519MLKEM768"},
			want:       map[string][]string{},
		},
		{
			name:       "no key exchange resolved against the catalogue",
			components: []models.CryptoComponentAssessment{otherComponent("symmetric", "AES256-GCM")},
			evidence:   hybridKexEvidence{Supported: true, Group: "X25519MLKEM768"},
			want:       map[string][]string{},
		},
		{
			name:       "not on non-key-exchange components",
			components: []models.CryptoComponentAssessment{otherComponent("signature", "X25519"), kexComponent("X25519", false)},
			evidence:   hybridKexEvidence{Supported: true, Group: "X25519MLKEM768"},
			want:       map[string][]string{"X25519": {"X25519MLKEM768"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hintsOn(annotateHybridKexAvailability(tt.components, tt.evidence))
			if len(got) != len(tt.want) {
				t.Fatalf("hints = %v, want %v", got, tt.want)
			}
			for code, groups := range tt.want {
				g, ok := got[code]
				if !ok {
					t.Fatalf("no hint on %q; hints = %v", code, got)
				}
				if g == nil {
					t.Errorf("%q hint groups is nil, want a non-nil (possibly empty) list", code)
				}
				if len(g) != len(groups) || (len(g) > 0 && g[0] != groups[0]) {
					t.Errorf("%q hint groups = %v, want %v", code, g, groups)
				}
			}
			// Guidance only: the hint never moves the assessment.
			for _, c := range tt.components {
				if c.SetsScore || c.RiskScore != nil || c.RiskLevel != nil {
					t.Errorf("%q assessment changed: %+v", c.Code, c)
				}
			}
		})
	}
}
