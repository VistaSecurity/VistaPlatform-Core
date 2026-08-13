// Package services: post-quantum readiness classification.
//
// One classifier, used by BOTH PQC endpoints (/pqc/progress and /pqc/summary),
// so the two numbers the product reports about quantum readiness cannot
// disagree. They previously used unrelated logic over different columns.
package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
)

// pqcComponentRoles are the crypto_implementation_algorithms.algorithm_type
// values that name a real cryptographic component.
//
// 'protocol_version' and 'cipher_suite' are deliberately EXCLUDED: ingest links
// those as container rows (a TLS version, a whole suite string) whose catalogue
// entries carry primitive 'other' or NULL. Counting them would mark essentially
// every implementation unclassified, since almost all of them link one.
var pqcComponentRoles = []string{"key_exchange", "signature", "symmetric", "hash"}

// quantumVulnerablePrimitives are the CycloneDX primitives whose classical
// constructions Shor's algorithm breaks: public-key encryption, key
// establishment, and digital signatures.
//
// This is a DENYLIST on purpose. The previous implementation used an allowlist
// of "quantum-safe" primitives ({ae, hash, mac}) and therefore silently treated
// everything it forgot as needing migration — against the shipped catalogue that
// misclassified 11 algorithms, including plain AES128 and AES256
// (primitive 'block-cipher'), RC4 ('stream-cipher') and the SHAKE functions
// ('xof'). The set of Shor-breakable primitives is closed and small, so a
// denylist cannot rot the same way as the CycloneDX primitive enum grows.
//
// Authority: NIST IR 8547 (Transition to Post-Quantum Cryptography Standards)
// names RSA, ECDSA, EdDSA, DH and ECDH as the quantum-vulnerable algorithms,
// deprecated after 2030 and disallowed after 2035. Symmetric ciphers and hashes
// are weakened (Grover) but not broken, and are not migration targets.
var quantumVulnerablePrimitives = []string{"signature", "kem", "key-agree", "pke"}

// pqcCounts is a per-tenant classification of crypto implementations into four
// mutually exclusive, collectively exhaustive categories. Because they
// partition the population, NeedsMigration+PQCReady+SymmetricSafe+Unclassified
// == Total and any percentage derived from them is bounded by 100.
type pqcCounts struct {
	Total          int
	NeedsMigration int
	PQCReady       int
	SymmetricSafe  int
	Unclassified   int
}

// ReadyPercent is the share of implementations that need no PQC migration:
// those already using PQC, plus those using no asymmetric cryptography at all.
// Unclassified implementations count against readiness — an implementation we
// could not classify is not evidence of safety.
func (c pqcCounts) ReadyPercent() float64 {
	if c.Total <= 0 {
		return 0
	}
	return float64(c.PQCReady+c.SymmetricSafe) / float64(c.Total) * 100
}

// classifyTenantImplementationsPQC classifies every non-deleted crypto
// implementation for a tenant exactly once.
//
// Precedence is deliberate and is the crux of the fix: an implementation is
// counted as needing migration if ANY of its components is classical
// asymmetric, regardless of what else it uses. A TLS service with an RSA key
// exchange and an AES-GCM cipher is quantum-vulnerable — its session key can be
// recovered — even though its bulk cipher is fine. The previous implementation
// counted that AES component toward "symmetric safe" and reported the service
// as protected.
//
// It also summed per-algorithm-family counts over a per-implementation
// denominator, so one implementation contributed to several families at once
// and the readiness percentage could exceed 100%.
func classifyTenantImplementationsPQC(db *database.DB, tenantID uuid.UUID) (pqcCounts, error) {
	// INNER JOIN network_assets (na), scoped to asset_status = 'monitoring':
	// without it this classifier's Total counted every non-deleted
	// crypto_implementations row regardless of whether its asset still exists
	// or is still pending approval — a strictly broader population than
	// crypto-configurations' and risk/summary's total_crypto, which both
	// require a live, monitoring-status asset. That divergence is exactly what
	// let /pqc/progress's total_implementations disagree with the Dashboard's
	// "Configs" count and the Inventory Configuration lens total for the same
	// tenant (M-1). All three now share one definition: implementations on a
	// live, monitoring asset.
	const query = `
		WITH impl_component AS (
			SELECT ci.id AS impl_id, a.is_pqc, a.primitive
			  FROM crypto_implementations ci
			  INNER JOIN network_assets na ON na.id = ci.asset_id
			        AND na.deleted_at IS NULL AND na.asset_status = 'monitoring'
			  LEFT JOIN crypto_implementation_algorithms cia
			         ON cia.crypto_implementation_id = ci.id
			        AND cia.algorithm_type = ANY($2)
			  LEFT JOIN algorithms a ON a.id = cia.algorithm_id
			 WHERE ci.tenant_id = $1 AND ci.deleted_at IS NULL
		),
		impl_class AS (
			SELECT impl_id,
			       COALESCE(bool_or(NOT COALESCE(is_pqc, false) AND primitive = ANY($3)), false) AS vulnerable,
			       COALESCE(bool_or(COALESCE(is_pqc, false)), false)                             AS has_pqc,
			       COUNT(*) FILTER (WHERE primitive IS NOT NULL AND primitive <> 'other')        AS known,
			       COUNT(*) FILTER (WHERE primitive IS NULL OR primitive = 'other')              AS unknown
			  FROM impl_component
			 GROUP BY impl_id
		)
		SELECT
			COUNT(*)                                                                                  AS total,
			COUNT(*) FILTER (WHERE vulnerable)                                                        AS needs_migration,
			COUNT(*) FILTER (WHERE NOT vulnerable AND has_pqc)                                        AS pqc_ready,
			COUNT(*) FILTER (WHERE NOT vulnerable AND NOT has_pqc AND known > 0 AND unknown = 0)      AS symmetric_safe,
			COUNT(*) FILTER (WHERE NOT vulnerable AND NOT has_pqc AND (known = 0 OR unknown > 0))     AS unclassified
		  FROM impl_class
	`

	var c pqcCounts
	// RLS-scoped: crypto_implementations is a security_invoker view carrying the
	// tenant policy, so the tenant boundary holds even though algorithms and the
	// junction are global tables.
	err := database.WithTenantTx(context.Background(), db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(query, tenantID, pq.Array(pqcComponentRoles), pq.Array(quantumVulnerablePrimitives)).
			Scan(&c.Total, &c.NeedsMigration, &c.PQCReady, &c.SymmetricSafe, &c.Unclassified)
	})
	if err != nil {
		return pqcCounts{}, fmt.Errorf("failed to classify PQC readiness: %w", err)
	}
	return c, nil
}
