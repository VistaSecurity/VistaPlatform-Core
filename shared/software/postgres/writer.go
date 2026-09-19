// Package postgres writes [software.Product] and [software.Install] values
// into `software_products` and `software_installs`.
//
// It exists because there are now TWO producers of the software inventory and
// only one correct way to write it. Workstream 2.6b shipped the SBOM upload
// (inventory-service) and 2.11b the host agent's package enumeration
// (device-interrogation-service), and the two run in different services, so
// "reuse the writer" could not mean "call the other service's method". Every
// rule below was learned once and must not be learned twice.
//
// # The NULL rule
//
//	ABSENT MEANS NULL, NEVER ''.
//
// `software_products` deduplicates on
// `coalesce(purl, cpe, name || '@' || coalesce(version, EMPTY))`. `coalesce`
// skips NULL and takes the empty string as a VALUE, so a writer that stores the
// empty string for a missing purl keys EVERY purl-less product in the tenant on
// that one string — the
// second one collides with the first — while [software.Product.Identity] hands
// back a distinct name@version for each of them. Nothing on the Go side can
// observe that happening, which is why [nullable] is the only way this package
// writes those columns.
//
// # The seam between the producers is `source_kind`
//
// An SBOM upload writes `imported` rows; an agent writes `measured` ones.
// [UpsertInstall] never DOWNGRADES a measured row to imported, and
// [MarkAbsentRemoved] only ever sweeps rows of the kind it is given. So an
// upload cannot mark an agent's measurement removed, and an agent cannot be
// mistaken for a build system's claim.
//
// # This package is NOT for the agent
//
// [software] itself is dependency-free because it is compiled into the
// cross-compiled agent binary. This sub-package takes database/sql and is
// imported only by services, exactly the way shared/identity/postgres sits
// beside shared/identity.
package postgres

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/software"
)

// Execer is the slice of a transaction this package needs.
//
// An interface rather than a concrete type because the two callers hold
// different ones: inventory-service runs on `*sqlx.Tx`, device-interrogation-
// service on `*sql.Tx`. Both satisfy this — sqlx.Tx embeds *sql.Tx and does not
// override either method — so neither has to convert, and neither gets its own
// copy of the SQL.
//
// It is a TRANSACTION rather than a pool, deliberately: every caller writes a
// whole inventory at once, and a half-written one is the failure shape this
// codebase keeps paying for — an asset showing a software list that looks
// complete with no way to tell which half is missing.
type Execer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// UpsertProduct writes the tenant catalogue row for one product and returns its
// id, and whether the row was created rather than matched.
//
// # ON CONFLICT does not touch an identity-bearing column
//
// `purl`, `cpe`, `version` and `name` are the inputs to the unique expression.
// Updating one of them on conflict would MOVE the row's identity: a row keyed
// on `openssl@3.0.13` that then acquires a purl is keyed on the purl from that
// moment on, so every later lookup of `openssl@3.0.13` misses it and creates a
// second row — or, worse, collides with a row that already holds that purl and
// raises a unique violation in the middle of an ingest. Enrichment is limited
// to the columns nothing is keyed on.
//
// `source_kind` is likewise left alone: a product first seen by a MEASUREMENT
// must not be downgraded to `imported` because a document mentioned it later.
//
// The product is normalised and its CPE lowercased before the identity is
// computed — see [FoldForWrite].
func UpsertProduct(
	ctx context.Context, tx Execer, tenantID uuid.UUID, p software.Product, sourceKind string,
) (id uuid.UUID, created bool, err error) {
	folded := FoldForWrite(p)
	versionSort, ok := folded.VersionSort()
	if !ok {
		// NULL, not the raw version. QUERY_LANGUAGE §5.5: a version with no
		// numeric component has no sort key, and every version comparison
		// against it evaluates UNKNOWN. A lexical fallback would put 1.10 below
		// 1.9 and invert every predicate built on the column.
		versionSort = ""
	}

	err = tx.QueryRowContext(ctx, `
		INSERT INTO software_products
			(tenant_id, name, vendor, version, version_sort, cpe, purl, license_id, source_kind)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (tenant_id, coalesce(purl, cpe, name || '@' || coalesce(version, '')))
		DO UPDATE SET
			vendor     = coalesce(software_products.vendor, excluded.vendor),
			license_id = coalesce(software_products.license_id, excluded.license_id),
			updated_at = now()
		RETURNING id, (xmax = 0)`,
		tenantID,
		folded.Name,
		nullable(folded.Vendor),
		nullable(folded.Version),
		nullable(versionSort),
		nullable(folded.CPE),
		nullable(folded.PURL),
		nullable(folded.LicenseID),
		sourceKind,
	).Scan(&id, &created)
	if err != nil {
		return uuid.Nil, false, err
	}
	return id, created, nil
}

// UpsertInstall records a product as present on an asset, and reports whether
// the row was created rather than refreshed.
//
// `installPath` is the filesystem location where the source knows one, and ""
// where it does not — an SBOM component has no install path, and neither does a
// package-database entry. The unique index coalesces NULL to the empty string
// precisely so repeated observations of a pathless install converge on one row
// instead of appending forever.
//
// `first_seen_at` is never updated: that is the whole point of having it beside
// `last_seen_at`. `status` returns to `active` because a product that reappears
// is present again — the row was marked `removed`, not deleted, so this is a
// state change rather than a resurrection.
func UpsertInstall(
	ctx context.Context, tx Execer,
	tenantID, assetID, productID uuid.UUID,
	installPath, sourceKind, sourceRef string,
) (created bool, err error) {
	return UpsertInstallAt(ctx, tx, tenantID, assetID, productID, installPath, sourceKind, sourceRef, time.Now().UTC())
}

// UpsertInstallAt preserves the measurement clock when a retained collection
// is materialized later. Older evidence cannot replace a newer installation.
func UpsertInstallAt(ctx context.Context, tx Execer, tenantID, assetID, productID uuid.UUID, installPath, sourceKind, sourceRef string, at time.Time) (created bool, err error) {
	err = tx.QueryRowContext(ctx, `
		INSERT INTO software_installs
			(tenant_id, asset_id, product_id, install_path, source_kind, source_ref, status, first_seen_at, last_seen_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'active', $8, $8)
		ON CONFLICT (tenant_id, asset_id, product_id, coalesce(install_path, ''))
		DO UPDATE SET
			last_seen_at = excluded.last_seen_at,
			status       = 'active',
			source_ref   = excluded.source_ref,
			-- A measured install is not downgraded to 'imported' because a
			-- document mentioned it. MarkAbsentRemoved is scoped the same way,
			-- so the two rules agree about which rows a source owns.
			source_kind  = CASE WHEN software_installs.source_kind = $7
			                    THEN software_installs.source_kind
			                    ELSE excluded.source_kind END,
			updated_at   = now()
		WHERE software_installs.last_seen_at <= excluded.last_seen_at
		RETURNING (xmax = 0)`,
		tenantID, assetID, productID, nullable(installPath), sourceKind, sourceRef,
		software.SourceMeasured, at,
	).Scan(&created)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return created, nil
}

// MarkAbsentRemoved marks every install on this asset, of this source kind,
// that the current run did not touch as `removed`, and returns how many.
//
// The test is `source_ref <> this run's` — every row the caller just wrote
// carries the new ref, so anything still holding an older one is absent from
// what was just observed. No array parameter and no second bookkeeping table.
//
// Two properties are deliberate and both are stated in the customer
// documentation, because both will surprise somebody:
//
//   - It is `removed`, never a DELETE. The row keeps its `first_seen_at`, so
//     "this library was here in March and is gone now" stays answerable, and a
//     later run that lists it again flips it back to `active`.
//   - A run REPLACES that source's picture for the asset. For an SBOM that
//     means a second document describing a different part of the same asset
//     marks the first document's rows removed; for a host agent it means the
//     newest package enumeration is the asset's measured software, which is
//     what a package database IS.
//
// Scoping by source kind is what keeps the two apart.
func MarkAbsentRemoved(
	ctx context.Context, tx Execer, tenantID, assetID uuid.UUID, sourceKind, sourceRef string,
) (int, error) {
	return MarkAbsentRemovedAt(ctx, tx, tenantID, assetID, sourceKind, sourceRef, time.Now().UTC())
}

// MarkAbsentRemovedAt cannot retire software observed after this snapshot.
func MarkAbsentRemovedAt(ctx context.Context, tx Execer, tenantID, assetID uuid.UUID, sourceKind, sourceRef string, at time.Time) (int, error) {
	res, err := tx.ExecContext(ctx, `
		UPDATE software_installs
		   SET status = 'removed', updated_at = now()
		 WHERE tenant_id = $1
		   AND asset_id = $2
		   AND source_kind = $3
		   AND status <> 'removed'
		   AND coalesce(source_ref, '') <> $4 AND last_seen_at <= $5`,
		tenantID, assetID, sourceKind, sourceRef, at)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// ActiveInstallCount is how many installs of one source kind are currently
// active on an asset.
//
// It is the number `sw.package_count` is written from, and it is deliberately
// NOT the count of things the source listed: those differ for good reasons — an
// excluded SBOM component, two packages sharing one purl, a subject that was
// already a component — and the fact's job is to say how many rows an inventory
// query would return.
func ActiveInstallCount(
	ctx context.Context, tx Execer, tenantID, assetID uuid.UUID, sourceKind string,
) (int, error) {
	var count int
	err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM software_installs
		 WHERE tenant_id = $1 AND asset_id = $2 AND status = 'active' AND source_kind = $3`,
		tenantID, assetID, sourceKind).Scan(&count)
	return count, err
}

// FoldForWrite normalises a product and lowercases its CPE.
//
// # Why the CPE is folded HERE and not in shared/software
//
// CPE 2.3 §5.3.2 makes attribute values case-INSENSITIVE, and NVD publishes its
// dictionary lowercase, so `cpe:2.3:a:OpenSSL:OpenSSL:3.0.13:…` and
// `cpe:2.3:a:openssl:openssl:3.0.13:…` are one product line and must be one
// catalogue row. software.NormalizeCPE deliberately does NOT fold them: it is
// also the validator a vulnerability feed's own strings pass through, and
// re-casing a value there would change a string something else matches on.
//
// The fold therefore belongs to the WRITER, where the column's uniqueness is
// decided — and it must happen BEFORE Identity() is computed, or the identity
// Go believes and the identity the unique index computes over the stored row
// would differ by case for exactly the products this exists to merge.
//
// Exported because callers deduplicate by identity before they write, and the
// identity they deduplicate on has to be the one the row will be keyed on.
func FoldForWrite(p software.Product) software.Product {
	n, _ := p.Normalize()
	n.CPE = strings.ToLower(n.CPE)
	return n
}

// nullable is the NULL-not-empty-string rule, in one place so no column can be
// written the other way by accident. See the package doc.
func nullable(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}
