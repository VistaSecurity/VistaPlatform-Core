package services

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/ouiregistry"
)

// OUI vendor backfill: bring assets ingested before the platform resolved
// hw.vendor (or under an older registry snapshot) up to the registry's answer.
//
// Before the move, a host observation's vendor came from the sensor's own
// ~500-prefix table and was stored under the `sensor` / `platform-sensor`
// producer — or not at all, for every prefix that table lacked. Ingestion now
// writes the registry's answer for every new observation (oui_vendor.go), but an
// asset that is never observed again would keep the old answer, or none, for
// ever. This pass resolves each such asset's own mac_address identifiers
// through the registry and writes the `enricher` fact, under exactly the
// write-time precedence ingestion uses (applyRegistryVendorFact).

// ouiVendorBackfillBatch is how many assets one transaction covers. Small
// enough that a tenant with a large inventory never holds its fact rows locked
// for long; large enough that a pass is a handful of round trips.
const ouiVendorBackfillBatch = 500

// ouiVendorBackfillCandidatesSQL pages, by asset id, through the tenant's live
// assets that carry a mac_address identifier and hold NO hw.vendor fact from a
// device-identity source (anything but the passive sensors' and this lookup's
// own rows — see ouiVendorSourceRef). Those are left alone: the device, or a
// system of record, already named its own manufacturer.
const ouiVendorBackfillCandidatesSQL = `
	SELECT a.id, array_agg(DISTINCT i.value ORDER BY i.value)
	FROM assets a
	JOIN asset_identifiers i
	  ON i.tenant_id = a.tenant_id AND i.asset_id = a.id AND i.kind = 'mac_address'
	WHERE a.tenant_id = $1
	  AND a.deleted_at IS NULL
	  AND a.id > $2
	  AND NOT EXISTS (
	      SELECT 1 FROM asset_facts f
	      WHERE f.tenant_id = a.tenant_id AND f.asset_id = a.id AND f.key = $3
	        AND f.source_ref <> $4 AND NOT (f.source_ref = 'sensor' OR f.source_ref LIKE 'sensor:%'))
	GROUP BY a.id
	ORDER BY a.id
	LIMIT $5`

// registryVendorForMACs is the one vendor the registry gives for an asset's
// MACs, or "" when it gives none — or when two of them resolve to DIFFERENT
// vendors. Ambiguity is not an answer: an asset holding a Dell NIC's MAC and an
// Intel NIC's MAC has not told us which one is the chassis maker, and picking
// either is a guess the fact would then state as a lookup. A MAC the registry
// does not determine is no evidence either way and is skipped.
func registryVendorForMACs(macs []string) (vendor string, ambiguous bool) {
	for _, mac := range macs {
		v := ouiregistry.VendorForMAC(mac)
		if v == "" {
			continue
		}
		if vendor == "" {
			vendor = v
			continue
		}
		if v != vendor {
			return "", true
		}
	}
	return vendor, false
}

// BackfillRegistryVendors runs the OUI vendor backfill for one tenant and
// returns how many assets it wrote the fact for.
//
// Idempotent: a second run finds the same candidates and rewrites the same
// value (the upsert only moves observed_at forward), and an asset that gained a
// device-identity vendor in between is no longer a candidate. Each batch is its
// own tenant-scoped transaction (RLS through pgidentity.RunInTx, the session
// every identity write uses), so a failure part-way loses at most one batch and
// the next run picks it up. On success the snapshot it ran under is recorded in
// oui_vendor_backfill_state, which is what lets the worker skip the tenant until
// the registry changes.
func (s *AssetService) BackfillRegistryVendors(ctx context.Context, tenantID uuid.UUID) (int, error) {
	repo := pgidentity.New(s.db.DB.DB)
	tenant := tenantID.String()
	written := 0
	after := uuid.Nil
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		type candidate struct {
			id   uuid.UUID
			macs []string
		}
		var batch []candidate
		batchWritten := 0
		err := repo.RunInTx(ctx, tenant, func(bound *pgidentity.Repository) error {
			tx := bound.Tx()
			rows, err := tx.QueryContext(ctx, ouiVendorBackfillCandidatesSQL,
				tenantID, after, facts.KeyHWVendor, ouiVendorSourceRef, ouiVendorBackfillBatch)
			if err != nil {
				return fmt.Errorf("list backfill candidates: %w", err)
			}
			for rows.Next() {
				var c candidate
				if err := rows.Scan(&c.id, pq.Array(&c.macs)); err != nil {
					_ = rows.Close()
					return fmt.Errorf("scan backfill candidate: %w", err)
				}
				batch = append(batch, c)
			}
			if err := rows.Close(); err != nil {
				return err
			}
			if err := rows.Err(); err != nil {
				return err
			}
			now := time.Now().UTC()
			for _, c := range batch {
				vendor, ambiguous := registryVendorForMACs(c.macs)
				if ambiguous {
					slog.Debug("oui vendor backfill: MACs resolve to different vendors; writing nothing",
						"tenant", tenant, "asset", c.id, "macs", strings.Join(c.macs, ","))
					continue
				}
				if vendor == "" {
					continue
				}
				ok, err := applyRegistryVendorFact(ctx, bound, tx, identity.AssetRef{TenantID: tenant, ID: c.id.String()}, vendor, now)
				if err != nil {
					return fmt.Errorf("asset %s: %w", c.id, err)
				}
				if ok {
					batchWritten++
				}
			}
			return nil
		})
		if err != nil {
			return written, err
		}
		written += batchWritten
		if len(batch) < ouiVendorBackfillBatch {
			break
		}
		after = batch[len(batch)-1].id
	}

	err := repo.RunInTx(ctx, tenant, func(bound *pgidentity.Repository) error {
		_, err := bound.Tx().ExecContext(ctx, `
			INSERT INTO oui_vendor_backfill_state (tenant_id, snapshot_id, assets_written, completed_at)
			VALUES ($1, $2, $3, now())
			ON CONFLICT (tenant_id) DO UPDATE
			SET snapshot_id = EXCLUDED.snapshot_id,
			    assets_written = EXCLUDED.assets_written,
			    completed_at = EXCLUDED.completed_at`,
			tenantID, ouiregistry.SnapshotID(), written)
		return err
	})
	if err != nil {
		return written, fmt.Errorf("record backfill snapshot: %w", err)
	}
	return written, nil
}

// OUIVendorBackfillDueTenants lists the live tenants whose last completed
// backfill ran under a different registry snapshot than this binary carries, or
// never ran. It reads across tenants, so it takes the BYPASS connection — the
// same split every background worker here uses: enumerate with bypass, then do
// each tenant's reads and writes in its own RLS session.
func OUIVendorBackfillDueTenants(ctx context.Context, bypass *sql.DB) ([]uuid.UUID, error) {
	rows, err := bypass.QueryContext(ctx, `
		SELECT t.id
		FROM tenants t
		LEFT JOIN oui_vendor_backfill_state s ON s.tenant_id = t.id
		WHERE t.deleted_at IS NULL
		  AND s.snapshot_id IS DISTINCT FROM $1
		ORDER BY t.id`, ouiregistry.SnapshotID())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
