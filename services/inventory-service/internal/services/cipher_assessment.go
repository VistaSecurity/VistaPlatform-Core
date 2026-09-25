package services

// Partial assessment of a cipher STRING ( W1.3, principle 2: unknown
// stays unknown).
//
// A cipher string such as "DEFAULT:!RC4" or "ALL:!aNULL" does not say which
// suites a device enables — that depends on its software version. Ingest can
// score what the string provably exposes, but the result is a LOWER BOUND:
// if it finds RC4, the configuration is at least that bad; if it finds nothing
// weak, that is not evidence of being clean. Stored as an assessed Low, the
// second case read as a verdict nobody reached.
//
// So a configuration whose cipher string is only partially resolved:
//   - carries raw_data.cipher_assessment = "partial" (and the unexpanded
//     tokens), where every reader can see it;
//   - keeps its ingest score when that score is Medium or worse — a known
//     component (a static-ECDH key exchange, an RSA-2048 one) has already
//     shown that much, and the unknown rest can only add to it. Below Medium
//     the score would be claiming "Low / Informational" for a set nobody
//     resolved, so it is stored as NULL: unassessed, not Low;
//   - carries a "Partially assessed" risk factor, and a limitation on its
//     crypto-risk judgment (cryptoassess.Judge).

import (
	"strings"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
	"github.com/vistasecurity/vistaplatform/shared/riskbands"
)

const (
	// cipherAssessmentKey is the raw_data flag: "partial" or "complete",
	// written whenever the configuration's cipher value is a cipher string.
	cipherAssessmentKey = "cipher_assessment"
	// cipherUnexpandedKey lists what could not be expanded when partial.
	cipherUnexpandedKey = "cipher_string_unexpanded"
)

// annotateCipherAssessment returns raw with the cipher-assessment flag set for
// a cipher-string value. It copies rather than mutating the finding's map, and
// it always writes the key for a string, so a re-observation that resolves
// fully overwrites an earlier "partial" (raw_data is merged on refresh).
func annotateCipherAssessment(raw models.JSONB, cipher *string) (models.JSONB, bool) {
	if cipher == nil || !cryptoparse.LooksLikeCipherString(*cipher) {
		return raw, false
	}
	out := make(models.JSONB, len(raw)+2)
	for k, v := range raw {
		out[k] = v
	}
	partial, unexpanded := cryptoparse.CipherStringAssessment(*cipher)
	if partial {
		out[cipherAssessmentKey] = "partial"
		out[cipherUnexpandedKey] = unexpanded
	} else {
		out[cipherAssessmentKey] = "complete"
		out[cipherUnexpandedKey] = []string{}
	}
	return out, partial
}

// partialAssessmentKeepsScore reports whether a score computed from a partial
// cipher assessment may stand: a partial string only stops a Low or
// Informational result being claimed as complete, so anything Medium or worse
// that known components support is kept. The band boundary comes from the
// shared ladder, never a literal.
func partialAssessmentKeepsScore(score int) bool {
	mediumMin, ok := riskbands.RiskBandMin("Medium")
	return ok && score >= mediumMin
}

// storedRiskScore is the score as persisted: nil when nothing was written.
func storedRiskScore(assessed bool, score int) *int {
	if !assessed {
		return nil
	}
	return &score
}

// partialCipherAssessmentFactor is the risk factor shown for a partially
// resolved cipher string.
func partialCipherAssessmentFactor(unexpanded []string) string {
	return "Partially assessed: the cipher string could not be fully resolved (" +
		strings.Join(unexpanded, ", ") + "); the enabled cipher set is unknown"
}
