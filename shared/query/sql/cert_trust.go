package sql

import "strings"

// Certificate trust on the asset target: `cert_trust` is the WORST
// trust status among the certificates deployed on the asset.
//
// One expression, two readers: the query language's derived field
// (`cert_trust:untrusted`) and inventory-service's asset facet of the same
// name, so the rail's count and the list its click produces are the same
// predicate by construction.

// CertTrustWorstLast lists the six certificates.trust_status values from the
// least to the most concerning. An asset's value is the one latest in this
// list among its certificates.
var CertTrustWorstLast = []string{"public", "private_trusted", "incomplete", "self_signed", "untrusted", "distrusted"}

// Values an asset's cert_trust takes besides the six statuses.
const (
	// CertTrustUnevaluated: the asset has certificates, none evaluated yet.
	CertTrustUnevaluated = "unevaluated"
	// CertTrustNone: the asset has no certificate at all.
	CertTrustNone = "none"
)

// CertTrustValues is the closed value set of the asset's cert_trust.
func CertTrustValues() []string {
	return append(append([]string{}, CertTrustWorstLast...), CertTrustUnevaluated, CertTrustNone)
}

// AssetCertTrustSQL returns the scalar SQL for one asset's cert_trust. asset
// is the asset row's alias; alias makes the subquery's own aliases unique in
// the enclosing statement. The certificate reach is the asset/cert shape's
// (junction, configuration owned through its endpoint or directly), so
// `cert:(trust_status:x)` and `cert_trust:x` see the same certificates. The
// status words are code constants, written as literals.
func AssetCertTrustSQL(asset string, alias func(string) string) string {
	c, cic, ci, e := alias("ctc"), alias("ctcic"), alias("ctci"), alias("cte")
	quoted := make([]string, len(CertTrustWorstLast))
	for i, v := range CertTrustWorstLast {
		quoted[i] = "'" + v + "'"
	}
	arr := "(ARRAY[" + strings.Join(quoted, ", ") + "]::text[])"
	rank := "MAX(array_position(" + arr + ", " + c + ".trust_status::text))"
	return "(SELECT CASE WHEN COUNT(" + c + ".id) = 0 THEN '" + CertTrustNone + "'" +
		" WHEN " + rank + " IS NULL THEN '" + CertTrustUnevaluated + "'" +
		" ELSE " + arr + "[" + rank + "] END" +
		" FROM certificates " + c +
		" JOIN crypto_implementation_certificates " + cic + " ON " + cic + ".certificate_id = " + c + ".id" +
		" JOIN crypto_implementations " + ci + " ON " + ci + ".id = " + cic + ".crypto_implementation_id" +
		" LEFT JOIN asset_endpoints " + e + " ON " + e + ".id = " + ci + ".endpoint_id" +
		" WHERE " + configurationOwnedBy(ci, e, asset) + ")"
}
