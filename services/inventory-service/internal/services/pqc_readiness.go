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

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/cryptoassess"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
)

// The component roles and the Shor-breakable primitive denylist moved to
// internal/cryptoassess, and these forward to them.
//
// They moved because the `crypto` finding producer classifies the SAME
// configurations against the SAME denylist, one package away, to decide whether
// to raise `crypto/pqc_vulnerable`. Two copies of a denylist is how one
// classification silently starts answering two different questions.
var pqcComponentRoles = cryptoassess.PQCComponentRoles

var quantumVulnerablePrimitives = cryptoassess.QuantumVulnerablePrimitives

// MonitoredConfigurationsSQL selects the configurations every tenant-wide
// crypto number is computed over: live configurations on a live, monitoring
// asset.
//
// It is a named constant because the population is the thing the numbers
// disagreed about. This classifier once counted every non-deleted
// crypto_implementations row regardless of whether its asset still existed or
// was still pending approval — a strictly broader set than crypto-configurations
// and risk/summary used — which is what let /pqc/progress's
// total_implementations disagree with the Dashboard's "Configs" count and the
// Inventory Configuration lens total for the same tenant (M-1).
const MonitoredConfigurationsSQL = `
    SELECT ci.id, ci.tenant_id
      FROM crypto_implementations ci
      INNER JOIN assets na ON na.tenant_id = ci.tenant_id AND na.id = ci.asset_id
            AND na.deleted_at IS NULL AND na.asset_status = 'monitoring'
     WHERE ci.tenant_id = $1 AND ci.deleted_at IS NULL`

// pqcPartitionSQL is the four-way partition over `impl_class`
// (cryptoassess.PQCClassCTE), as a SELECT-list fragment. It is the ONE place
// the categories and their precedence are spelled: the tenant-wide classifier
// below and the per-asset network map both select it, so a device's counts and
// the tenant's /pqc numbers cannot be two different partitions.
//
// Precedence: vulnerable first, then has_pqc, then fully-known symmetric; the
// rest is unclassified. Mutually exclusive and exhaustive by construction.
const pqcPartitionSQL = `COUNT(*) FILTER (WHERE vulnerable)                                                        AS needs_migration,
			COUNT(*) FILTER (WHERE NOT vulnerable AND has_pqc)                                        AS pqc_ready,
			COUNT(*) FILTER (WHERE NOT vulnerable AND NOT has_pqc AND known > 0 AND unknown = 0)      AS symmetric_safe,
			COUNT(*) FILTER (WHERE NOT vulnerable AND NOT has_pqc AND (known = 0 OR unknown > 0))     AS unclassified`

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
	// INNER JOIN assets (na), scoped to asset_status = 'monitoring':
	// without it this classifier's Total counted every non-deleted
	// crypto_implementations row regardless of whether its asset still exists
	// or is still pending approval — a strictly broader population than
	// crypto-configurations' and risk/summary's total_crypto, which both
	// require a live, monitoring-status asset. That divergence is exactly what
	// let /pqc/progress's total_implementations disagree with the Dashboard's
	// "Configs" count and the Inventory Configuration lens total for the same
	// tenant (M-1). All three now share one definition: implementations on a
	// live, monitoring asset.
	query := `
		WITH ` + cryptoassess.PQCClassCTE(MonitoredConfigurationsSQL, "$2", "$3") + `
		SELECT
			COUNT(*)                                                                                  AS total,
			` + pqcPartitionSQL + `
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
