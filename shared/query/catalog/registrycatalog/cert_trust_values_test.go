package registrycatalog

import (
	"testing"

	querysql "github.com/vistasecurity/vistaplatform/shared/query/sql"
)

// The asset's cert_trust enum is what the translator's expression can
// produce, and the certificate's trust_status enum is the six statuses that
// expression ranks. A value added to one side only would validate a predicate
// that can never match, or refuse one that can.
func TestCertTrustValues_MatchTheTranslatorExpression(t *testing.T) {
	assertSameSet(t, "asset cert_trust", certTrustAssetValues, querysql.CertTrustValues())
	assertSameSet(t, "certificate trust_status", certificateTrustStatusValues, querysql.CertTrustWorstLast)
}
