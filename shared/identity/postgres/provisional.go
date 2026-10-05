package postgres

// The SQL half of provisional inventory ( D2/D3): the segment-eligibility
// question the engine asks before it invents an asset, the atomic identifier
// move that lets direct evidence take an address off a guess, and the
// retirement of a guess a move emptied.

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// ProvisionalScope implements [identity.ProvisionalScopeChecker]: may a
// provisional asset be created against this segment?
//
// Three conditions, and each rules out a way the answer to "which VLAN is this
// on" could be more than one thing:
//
//   - the segment is an ACTIVE `cidr` segment of this tenant. An `ip_range`,
//     `domain` or `cloud_vpc` segment is not a place an address unambiguously
//     lives, and a deactivated segment is one an operator has said to stop
//     using;
//   - no OTHER active cidr segment of the tenant overlaps it. Overlapping
//     segments mean the operator has drawn two answers over the same space,
//     and picking one for them is how an asset lands on the wrong VLAN and
//     duplicates something on the right one;
//   - it carries no `cloud_network_ref`. A CIDR is not unique in a cloud
//     account — two VPCs from one Terraform module both get 10.0.0.0/16 — so a
//     cloud segment cannot be identified from an address alone.
//
// The overlap test runs in Go rather than as `value::cidr && $2::cidr`, for the
// same reason [Repository.ScopeForAddress]'s containment test does: `value` is
// free text, and ONE malformed row would abort the whole query with a cast
// error. That would not merely refuse this segment — it would return an error
// from every Resolve in the tenant, which is a much worse failure than the one
// it was guarding.
func (r *Repository) ProvisionalScope(ctx context.Context, tenantID, segmentID string) (bool, string, error) {
	type seg struct {
		id         string
		prefix     netip.Prefix
		networkRef string
	}
	var (
		target  *seg
		others  []seg
		badKind bool
	)
	err := r.withTx(ctx, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT id::text, segment_type, value, coalesce(cloud_network_ref, '')
			  FROM public.network_segments
			 WHERE tenant_id = $1 AND is_active = true`, tenantID)
		if err != nil {
			return fmt.Errorf("identity/postgres: read network segments: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id, kind, value, networkRef string
			if err := rows.Scan(&id, &kind, &value, &networkRef); err != nil {
				return fmt.Errorf("identity/postgres: scan network segment: %w", err)
			}
			if kind != "cidr" {
				if id == segmentID {
					// Found, but not a kind an address lives in
					// unambiguously. Distinguished from "not found" so the
					// reason can be honest about which question failed.
					badKind = true
				}
				continue
			}
			p, perr := netip.ParsePrefix(strings.TrimSpace(value))
			if perr != nil {
				// A segment nobody can parse cannot overlap anything either.
				// Skipping it is the same decision ScopeForAddress makes.
				continue
			}
			s := seg{id: id, prefix: p.Masked(), networkRef: strings.TrimSpace(networkRef)}
			if id == segmentID {
				t := s
				target = &t
				continue
			}
			others = append(others, s)
		}
		return rows.Err()
	})
	if err != nil {
		return false, "", err
	}
	if target == nil || badKind {
		return false, identity.ReasonNetworkScopeUnresolved, nil
	}
	if target.networkRef != "" {
		return false, identity.ReasonOverlappingNetworkScope, nil
	}
	for _, other := range others {
		if other.prefix.Overlaps(target.prefix) {
			return false, identity.ReasonOverlappingNetworkScope, nil
		}
	}
	return true, "", nil
}

// ReassignIdentifier implements [identity.IdentifierReassigner]: it moves one
// identifier value from one asset to another in a single statement.
//
// One UPDATE, not a DELETE and an INSERT. The unique index of DATA_MODEL §2 is
// over (tenant, kind, value, scope), so a delete-then-insert is a window in
// which the value belongs to nobody — and if the insert fails, the identifier
// is gone from an inventory that had it.
//
// `asset_id = $from` in the WHERE clause is not belt and braces: the engine
// computed this move from an ownership lookup made earlier in the transaction,
// and a row that has since moved would otherwise be yanked from whoever owns it
// now. Zero rows is therefore an ERROR, not a no-op.
func (r *Repository) ReassignIdentifier(ctx context.Context, id identity.Identifier, from, to identity.AssetRef) error {
	if from.TenantID != to.TenantID {
		return fmt.Errorf("identity/postgres: ReassignIdentifier: %s and %s are in different tenants", from.ID, to.ID)
	}
	if from.ID == to.ID {
		return fmt.Errorf("identity/postgres: ReassignIdentifier: %s=%q is already %s's", id.Kind, id.Value, to.ID)
	}
	fromID, err := parseAsset(from.ID)
	if err != nil {
		return err
	}
	toID, err := parseAsset(to.ID)
	if err != nil {
		return err
	}
	return r.withTx(ctx, from.TenantID, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE public.asset_identifiers
			   SET asset_id = $3, updated_at = now()
			 WHERE tenant_id = $1 AND asset_id = $2
			   AND kind = $4 AND value = $5 AND coalesce(scope, '') = $6`,
			from.TenantID, fromID, toID, string(id.Kind), id.Value, id.Scope)
		if err != nil {
			return fmt.Errorf("identity/postgres: reassign %s=%q from %s to %s: %w",
				id.Kind, id.Value, from.ID, to.ID, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("%w: %s=%q is not %s's", identity.ErrIdentifierConflict, id.Kind, id.Value, from.ID)
		}
		// The moved row may be the independent evidence an import-only
		// asset lacked (import_only.go).
		return ClearImportOnlyIfVouched(ctx, tx, to.TenantID, toID)
	})
}

// ArchiveAsset implements [identity.AssetArchiver]: it retires a provisional
// asset a reassignment left with no identifier.
//
// `merged_into` is deliberately NOT written. Nothing was merged: the guess was
// about a thing that turned out not to be separate, and claiming a merge would
// send every reader of that asset to a row it was never part of.
func (r *Repository) ArchiveAsset(ctx context.Context, asset identity.AssetRef) error {
	assetID, err := parseAsset(asset.ID)
	if err != nil {
		return err
	}
	return r.withTx(ctx, asset.TenantID, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE public.assets SET asset_status = 'archived', updated_at = now()
			 WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`, asset.TenantID, assetID)
		if err != nil {
			return fmt.Errorf("identity/postgres: archiving %s: %w", asset.ID, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("%w: %s", identity.ErrAssetNotFound, asset.ID)
		}
		return nil
	})
}

// RetireIdentifier implements [identity.IdentifierRetirer]: the drift
// verdicts' "replace the key" and "release the old address" (owner Decision 4
// of). The row is deleted; the asset's timeline entry for the verdict is
// what records that it was there.
//
// `asset_id = $asset` in the WHERE clause, and zero rows an ERROR, for the
// reason [Repository.ReassignIdentifier] gives: the engine decided this from a
// summary read earlier in the transaction.
//
// Releasing an address the asset uses as its `primary_address` moves the
// primary to the freshest address the asset still holds (the drift path attaches
// the new one first), or clears it when none is left — a primary address the
// asset no longer answers at is the inventory telling the reader the old fact.
func (r *Repository) RetireIdentifier(ctx context.Context, asset identity.AssetRef, id identity.Identifier) error {
	assetID, err := parseAsset(asset.ID)
	if err != nil {
		return err
	}
	return r.withTx(ctx, asset.TenantID, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			DELETE FROM public.asset_identifiers
			 WHERE tenant_id = $1 AND asset_id = $2
			   AND kind = $3 AND value = $4 AND coalesce(scope, '') = $5`,
			asset.TenantID, assetID, string(id.Kind), id.Value, id.Scope)
		if err != nil {
			return fmt.Errorf("identity/postgres: retire %s=%q from %s: %w", id.Kind, id.Value, asset.ID, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("%w: %s=%q is not %s's", identity.ErrIdentifierConflict, id.Kind, id.Value, asset.ID)
		}
		if id.Kind != identity.KindIPAddress {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE public.assets a
			   SET primary_address = (
			         SELECT ai.value::inet FROM public.asset_identifiers ai
			          WHERE ai.tenant_id = a.tenant_id AND ai.asset_id = a.id AND ai.kind = 'ip_address'
			          ORDER BY ai.last_seen_at DESC NULLS LAST, ai.value
			          LIMIT 1),
			       updated_at = now()
			 WHERE a.tenant_id = $1 AND a.id = $2 AND a.primary_address = $3::text::inet`,
			asset.TenantID, assetID, id.Value); err != nil {
			return fmt.Errorf("identity/postgres: moving %s's primary address off %s: %w", asset.ID, id.Value, err)
		}
		return nil
	})
}

// DriftMaterial implements [identity.DriftMaterialReader]: the SHA-256
// fingerprints of the live leaf certificates the asset presents, and its
// listening ports.
//
// The certificates come by both links the product writes — the direct
// `crypto_implementations.certificate_id` and the `leaf`/`primary` rows of
// `crypto_implementation_certificates` — for the reason the drift finding
// producer reads both (inventory-service producers/drift.go readIssuers). An
// intermediate or root is the CA's identity, not this device's. Only the
// fingerprint leaves the query.
func (r *Repository) DriftMaterial(ctx context.Context, asset identity.AssetRef) (identity.StoredDriftMaterial, error) {
	assetID, err := parseAsset(asset.ID)
	if err != nil {
		return identity.StoredDriftMaterial{}, err
	}
	var out identity.StoredDriftMaterial
	err = r.withTx(ctx, asset.TenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT DISTINCT lower(c.fingerprint_sha256)
			  FROM public.crypto_implementations ci
			  JOIN public.certificates c ON c.tenant_id = ci.tenant_id AND c.id = ci.certificate_id
			 WHERE ci.tenant_id = $1 AND ci.asset_id = $2 AND ci.deleted_at IS NULL
			UNION
			SELECT DISTINCT lower(c.fingerprint_sha256)
			  FROM public.crypto_implementations ci
			  JOIN public.crypto_implementation_certificates cic ON cic.crypto_implementation_id = ci.id
			  JOIN public.certificates c ON c.tenant_id = ci.tenant_id AND c.id = cic.certificate_id
			 WHERE ci.tenant_id = $1 AND ci.asset_id = $2 AND ci.deleted_at IS NULL
			   AND cic.certificate_role IN ('leaf', 'primary')`, asset.TenantID, assetID)
		if err != nil {
			return fmt.Errorf("identity/postgres: read %s's certificates: %w", asset.ID, err)
		}
		for rows.Next() {
			var fp string
			if err := rows.Scan(&fp); err != nil {
				_ = rows.Close()
				return err
			}
			out.TLSCertFingerprints = append(out.TLSCertFingerprints, fp)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if err := rows.Err(); err != nil {
			return err
		}

		rows, err = tx.QueryContext(ctx, `
			SELECT DISTINCT port::text || '/' || lower(transport)
			  FROM public.asset_endpoints
			 WHERE tenant_id = $1 AND asset_id = $2 AND port IS NOT NULL AND port > 0
			 ORDER BY 1`, asset.TenantID, assetID)
		if err != nil {
			return fmt.Errorf("identity/postgres: read %s's ports: %w", asset.ID, err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var p string
			if err := rows.Scan(&p); err != nil {
				return err
			}
			out.Ports = append(out.Ports, p)
		}
		return rows.Err()
	})
	return out, err
}
