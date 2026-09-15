// Package cryptoassess holds the crypto judgements that more than one package
// in inventory-service has to make, so they are made ONCE.
//
// Two of them, and both had exactly one home before:
//
//   - which junction roles contribute to a configuration's catalogue risk
//     (`catalogue_risk.go`), and
//   - how a configuration is classified for post-quantum vulnerability
//     (`pqc_readiness.go`).
//
// The `crypto` finding producer (workstream 3.2) has to make the same two
// judgements about the same rows, and it lives in `internal/producers`. Copying
// either one across the package boundary would recreate precisely the situation
// CLAUDE.md records for risk scoring: "two parallel, disagreeing opinions about
// how risky a given algorithm is — one curated and citable, one hardcoded and
// unattributed — and the unattributed one won."
//
// So the SQL and the lists live here, and both callers build their queries from
// them. `pqc_readiness.go`'s tenant aggregate and the producer's per-subject
// read are the SAME classification text with different projections over it,
// which is a property a test can assert (and does).
package cryptoassess

// CatalogueRiskRoles are the crypto_implementation_algorithms.algorithm_type
// values that contribute to a configuration's risk score.
//
// Unlike PQCComponentRoles below, risk DOES include the container rows: an
// obsolete protocol version is one of the strongest risk signals there is —
// TLS 1.0 carries catalogue risk 75, and RFC 8996 says it MUST NOT be used —
// and whole-suite entries carry their own assessment.
var CatalogueRiskRoles = []string{
	"protocol_version", "cipher_suite", "key_exchange", "signature", "symmetric", "hash",
}

// PQCComponentRoles are the junction roles that name a real cryptographic
// primitive.
//
// 'protocol_version' and 'cipher_suite' are deliberately EXCLUDED: ingest links
// those as container rows (a TLS version, a whole suite string) whose catalogue
// entries carry primitive 'other' or NULL. Counting them would mark essentially
// every configuration unclassified, since almost all of them link one.
var PQCComponentRoles = []string{"key_exchange", "signature", "symmetric", "hash"}

// QuantumVulnerablePrimitives are the CycloneDX primitives whose classical
// constructions Shor's algorithm breaks: public-key encryption, key
// establishment, and digital signatures.
//
// This is a DENYLIST on purpose. An allowlist of "quantum-safe" primitives
// silently treats everything it forgot as needing migration — against the
// shipped catalogue the previous {ae, hash, mac} allowlist misclassified 11
// algorithms, including plain AES128 and AES256. The set of Shor-breakable
// primitives is closed and small, so a denylist cannot rot the same way as the
// CycloneDX primitive enum grows.
//
// Authority: NIST IR 8547 names RSA, ECDSA, EdDSA, DH and ECDH as the
// quantum-vulnerable algorithms, deprecated after 2030 and disallowed after
// 2035. Symmetric ciphers and hashes are weakened (Grover) but not broken, and
// are not migration targets.
var QuantumVulnerablePrimitives = []string{"signature", "kem", "key-agree", "pke"}

// PQCClassCTE renders the two CTEs that classify configurations for
// post-quantum vulnerability, as a comma-terminated fragment to splice after a
// `WITH`.
//
// implSource is SQL selecting the configurations to classify, exposing at least
// `id` and `tenant_id`; rolesSQL and vulnSQL are the caller's own spellings of
// the two arrays (a bound placeholder, or a literal). They are the caller's
// because parameter numbering is the caller's, and a fragment that assumed $2
// and $3 would be usable by exactly one query.
//
// The output CTE `impl_class` has one row per configuration:
//
//	impl_id    the configuration
//	vulnerable ANY component is classical asymmetric  → needs PQC migration
//	has_pqc    ANY component is a PQC algorithm
//	known      how many components resolved to a real primitive
//	unknown    how many resolved to nothing, or to 'other'
//
// Precedence is the crux and it is deliberate: a configuration counts as
// vulnerable if ANY component is classical asymmetric, regardless of what else
// it uses. A TLS service with an RSA key exchange and an AES-GCM cipher is
// quantum-vulnerable — its session key can be recovered — even though its bulk
// cipher is fine.
func PQCClassCTE(implSource, rolesSQL, vulnSQL string) string {
	return `
impl_component AS (
    SELECT ci.id AS impl_id, a.is_pqc, a.primitive, a.code, cia.algorithm_type
      FROM (` + implSource + `) ci
      LEFT JOIN crypto_implementation_algorithms cia
             ON cia.crypto_implementation_id = ci.id
            AND cia.algorithm_type = ANY(` + rolesSQL + `)
      LEFT JOIN algorithms a ON a.id = cia.algorithm_id
),
impl_class AS (
    SELECT impl_id,
           COALESCE(bool_or(NOT COALESCE(is_pqc, false) AND primitive = ANY(` + vulnSQL + `)), false) AS vulnerable,
           COALESCE(bool_or(COALESCE(is_pqc, false)), false)                                          AS has_pqc,
           COUNT(*) FILTER (WHERE primitive IS NOT NULL AND primitive <> 'other')                      AS known,
           COUNT(*) FILTER (WHERE primitive IS NULL OR primitive = 'other')                            AS unknown,
           COALESCE(
               array_agg(DISTINCT code) FILTER (
                   WHERE code IS NOT NULL
                     AND NOT COALESCE(is_pqc, false)
                     AND primitive = ANY(` + vulnSQL + `)
               ),
               ARRAY[]::text[]
           ) AS vulnerable_codes
      FROM impl_component
     GROUP BY impl_id
)`
}
