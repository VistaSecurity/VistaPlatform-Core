package postgres

// Import-only provenance, stored on the asset (platform ADR-0002 D10, amended
//
//
// An asset whose ONLY claim to exist is a connection's import (a CMDB profile,
// a NetBox connection) is not a target for unattended active scanning unless
// that connection consents. Whether an asset is "import-only" used to be
// worked out on every check from its `created` history row and every
// identifier, fact and endpoint it carries; the planner and the dispatch guard
// asked that question once per target, and on a real inventory job creation
// took minutes. The answer is now a column, `assets.import_only_sources`:
//
//   - SET by CreateAsset when a connection creates the asset (the source that
//     the `created` history entry names), as a one-element array;
//   - CLEARED, permanently, the first time independent evidence is stored for
//     the asset: an identifier, fact or endpoint whose source_kind is
//     `measured` and whose source is not an active scan. A sensor, an agent or
//     an interrogation seeing the host is the evidence the import lacked; a
//     scan's own result is not, or consent withdrawn could never take effect
//     for an asset scanned while it held. [ClearImportOnlyIfVouched] decides
//     from the rows as stored, so the provenance precedence the writers apply
//     (an identifier the CMDB imported stays `imported` when a sensor
//     re-sights the same value) is honoured exactly as the derived rule did;
//   - CLEARED by a person's spreadsheet upload that lists the asset
//     ([ClearImportOnly]): an explicit list keeps it in scope;
//   - COMBINED on a merge ([MergeImportOnly]): the survivor is import-only only
//     if it AND every merged-in asset were, and then carries every creating
//     connection, so consent from either still counts.
//
// NULL means "not import-only". Writers never store an empty array.
//
// The column is the whole of "import-only". Consent is still read when a
// check runs (shared/autoscan ImportedWithoutConsentSQL), because a tenant
// turns it on and off at any time and the check must see the current answer.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// execer is the slice of *sql.Tx (and of sqlx's) these helpers need, so a
// service writing outside a Repository can call them on its own transaction.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// importOnlySourceRef is what CreateAsset stores for an asset created by src:
// the connection's source ref, or "" (stored as NULL) for every other source.
// It is exactly the source the `created` history entry records
// ([Repository.RecordHistory] trims the ref the same way).
func importOnlySourceRef(src identity.Source) string {
	if !identity.IsConnectionSource(src) {
		return ""
	}
	return strings.TrimSpace(src.Ref)
}

// vouches reports whether a row written with this provenance can be
// independent evidence: measured, and not by an active scan. It is only the
// cheap pre-check that decides whether [ClearImportOnlyIfVouched] needs to
// run; the clear itself reads the stored rows. kind is the effective kind, as
// written (sourceKindOr).
func vouches(kind, ref string) bool {
	ref = strings.TrimSpace(ref)
	return kind == string(identity.SourceMeasured) && ref != "scan" && !strings.HasPrefix(ref, "scan:")
}

// independentEvidenceSQL is TRUE when the asset aliased `a` carries an
// identifier, fact or endpoint measured by something other than an active
// scan. The upgrade backfill in scripts/database/schema.sql spells the same
// predicate (POST-MIGRATIONS "assets.import_only_sources").
const independentEvidenceSQL = `(
	EXISTS (SELECT 1 FROM public.asset_identifiers mi
	         WHERE mi.tenant_id = a.tenant_id AND mi.asset_id = a.id AND mi.source_kind = 'measured'
	           AND COALESCE(mi.source_ref, '') <> 'scan' AND COALESCE(mi.source_ref, '') NOT LIKE 'scan:%')
	OR EXISTS (SELECT 1 FROM public.asset_facts mf
	         WHERE mf.tenant_id = a.tenant_id AND mf.asset_id = a.id AND mf.source_kind = 'measured'
	           AND mf.source_ref <> 'scan' AND mf.source_ref NOT LIKE 'scan:%')
	OR EXISTS (SELECT 1 FROM public.asset_endpoints me
	         WHERE me.tenant_id = a.tenant_id AND me.asset_id = a.id AND me.source_kind = 'measured'
	           AND COALESCE(me.source_ref, '') <> 'scan' AND COALESCE(me.source_ref, '') NOT LIKE 'scan:%')
)`

// ClearImportOnlyIfVouched clears the asset's import-only state when it now
// carries independent evidence. Call it, on the writing transaction, after
// storing identifiers, facts or endpoints for an asset outside this
// Repository's own writers (which call it themselves). A no-op for every
// asset that is not import-only, which is nearly all of them: the UPDATE
// touches the one row by primary key and evaluates the evidence only for an
// import-only one.
func ClearImportOnlyIfVouched(ctx context.Context, tx execer, tenantID string, assetID uuid.UUID) error {
	if _, err := tx.ExecContext(ctx, `
		UPDATE public.assets a SET import_only_sources = NULL
		 WHERE a.tenant_id = $1 AND a.id = $2 AND a.import_only_sources IS NOT NULL
		   AND `+independentEvidenceSQL,
		tenantID, assetID); err != nil {
		return fmt.Errorf("identity/postgres: settle import-only state of %s: %w", assetID, err)
	}
	return nil
}

// ClearImportOnly clears the asset's import-only state unconditionally: a
// person's spreadsheet upload listed it, and a person's explicit list keeps an
// asset in scope whatever a connection said about it first.
func ClearImportOnly(ctx context.Context, tx execer, tenantID string, assetID uuid.UUID) error {
	if _, err := tx.ExecContext(ctx, `
		UPDATE public.assets SET import_only_sources = NULL
		 WHERE tenant_id = $1 AND id = $2 AND import_only_sources IS NOT NULL`,
		tenantID, assetID); err != nil {
		return fmt.Errorf("identity/postgres: clear import-only state of %s: %w", assetID, err)
	}
	return nil
}

// MergeImportOnly settles the survivor's import-only state after sources were
// merged into it. Call it after their identifiers, facts and endpoints have
// moved.
//
// The survivor stays import-only only if it AND every source were: an asset a
// person declared, a sensor found, or a spreadsheet listed is not "known only
// from a connection" because a connection also knew it. When all were, the
// survivor carries every creating connection, so consent from any of them
// still counts as it did before the merge. Evidence that moved with the
// sources is then read as for any other write.
func MergeImportOnly(ctx context.Context, tx execer, tenantID string, survivor uuid.UUID, sources []uuid.UUID) error {
	if len(sources) == 0 {
		return nil
	}
	ids := make([]string, 0, len(sources))
	for _, s := range sources {
		ids = append(ids, s.String())
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE public.assets s SET import_only_sources = CASE
		    WHEN EXISTS (SELECT 1 FROM public.assets l
		                  WHERE l.tenant_id = s.tenant_id AND l.id = ANY($3::uuid[])
		                    AND l.import_only_sources IS NULL)
		    THEN NULL
		    ELSE (SELECT array_agg(DISTINCT ref ORDER BY ref) FROM (
		            SELECT unnest(s.import_only_sources) AS ref
		            UNION ALL
		            SELECT unnest(l.import_only_sources) FROM public.assets l
		             WHERE l.tenant_id = s.tenant_id AND l.id = ANY($3::uuid[])) refs)
		    END
		 WHERE s.tenant_id = $1 AND s.id = $2 AND s.import_only_sources IS NOT NULL`,
		tenantID, survivor, pq.Array(ids)); err != nil {
		return fmt.Errorf("identity/postgres: merge import-only state into %s: %w", survivor, err)
	}
	return ClearImportOnlyIfVouched(ctx, tx, tenantID, survivor)
}
