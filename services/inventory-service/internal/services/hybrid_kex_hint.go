// Package services: the "supports hybrid, negotiated classical" hint.
//
// A TLS server can accept a hybrid post-quantum key exchange (X25519MLKEM768
// and its siblings) and still negotiate a classical one — because the client's
// offer, or the server's own group preference, put the classical group first.
// Such a configuration is correctly classed as needing PQC migration: what was
// negotiated is Shor-breakable. But the fix is a preference change on the
// server (or newer clients), not a migration project, and the user should be
// told so ( W1.9, owner decision Q11).
//
// The handshake sites record the evidence (shared/discovery.MeasureTLSKeyExchange:
// tls_supports_pqc_hybrid_kex, tls_pqc_hybrid_kex_group) and ingest stores it
// on the configuration's raw_data. This file turns it into guidance on the
// key-exchange component the "Why this score" panel already renders beside the
// catalogue's migration guidance. It changes no score, band or PQC category.
package services

import (
	"strings"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/discovery"
)

// hybridKexEvidenceSQL reads a configuration's hybrid-support evidence from
// raw_data. Comparing to the JSON literal true is deliberate: only a JSON
// boolean true is an answer. Absent (never asked), false (refused), and a
// string "true" (not something any producer writes) all read as not supported.
const hybridKexEvidenceSQL = `
	SELECT COALESCE(ci.raw_data -> '` + discovery.MetaTLSSupportsPQCHybridKex + `' = 'true'::jsonb, false),
	       COALESCE(ci.raw_data ->> '` + discovery.MetaTLSPQCHybridKexGroup + `', '')
	  FROM crypto_implementations ci
	 WHERE ci.id = $1
	   AND ci.tenant_id = $2
	   AND ci.deleted_at IS NULL
`

// hybridKexEvidence is what a configuration's raw_data proves about its
// server's hybrid post-quantum key-exchange support.
type hybridKexEvidence struct {
	// Supported is true only when a handshake proved the server accepts a
	// hybrid-only offer. False covers both "refused" and "never asked".
	Supported bool
	// Group is the hybrid group the server accepted, as recorded; validated
	// before it is shown.
	Group string
}

// annotateHybridKexAvailability sets HybridKexAvailable on each classical key
// exchange component when the evidence proves hybrid support.
//
// "Negotiated classical" is decided by the catalogue, not by string matching:
// the configuration's key_exchange components must all be is_pqc=false. Any
// hybrid key_exchange component means the configuration already negotiates
// post-quantum key exchange, and no hint is given. The component's code must
// also be a group a live handshake records (X25519, DH-ECP-256, ...): a family
// label such as "ECDHE", derived from a cipher-suite name, is not a negotiated
// group and the hint could not truthfully say what was negotiated.
//
// Nothing else on the component is touched — the hint is guidance, and the
// risk, band and PQC category stay exactly what the catalogue says.
func annotateHybridKexAvailability(components []models.CryptoComponentAssessment, ev hybridKexEvidence) []models.CryptoComponentAssessment {
	if !ev.Supported {
		return components
	}
	classical := make([]int, 0, 1)
	for i := range components {
		if components[i].AlgorithmType != "key_exchange" {
			continue
		}
		if components[i].IsPQC {
			return components
		}
		if discovery.IsTLSKeyExchangeGroupName(components[i].Code) {
			classical = append(classical, i)
		}
	}
	groups := []string{}
	if g := strings.TrimSpace(ev.Group); discovery.IsPQCHybridTLSGroupName(g) {
		groups = append(groups, g)
	}
	for _, i := range classical {
		components[i].HybridKexAvailable = &models.HybridKexAvailability{Groups: append([]string{}, groups...)}
	}
	return components
}
