package services

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// PlatformReinterrogationKey is the device-metadata key that records an
// operator's consent for UNATTENDED platform re-interrogation (the
// rule): when identity enrichment needs fresh evidence from a device no agent
// interrogates, the platform may run that device's interrogation again without
// being asked only if this key holds platformExecutorValue. "A missing agent is
// not a platform fallback."
//
// Two places read it — the planner (ConfiguredSourceRefresh.plan) and the
// claim-time recheck (validateRefreshClaimTx) — and exactly one writes it:
// the explicit `platform_reinterrogation_allowed` field of the device create /
// update requests, through applyPlatformReinterrogation. A client's free-form
// `metadata` map cannot set or clear it (applyDeviceFields re-asserts the
// consent after every metadata merge): consent is a decision with its own field, its own audit record and its own
// permission gate, not a side effect of an arbitrary metadata write.
const PlatformReinterrogationKey = "identity_enrichment_executor"

const platformExecutorValue = "platform"

// reasonExecutorScopeUnknown is the enrichment reason the planner gives a
// platform-interrogated device that has not consented. It is the reason
// granting the consent re-opens.
const reasonExecutorScopeUnknown = "executor_scope_unknown"

// platformReinterrogationAllowed reads the consent off a device's metadata.
func platformReinterrogationAllowed(meta map[string]interface{}) bool {
	v, _ := meta[PlatformReinterrogationKey].(string)
	return v == platformExecutorValue
}

// readPlatformReinterrogation reads the stored consent, locking the asset row
// so the read-modify-write in applyDeviceFields cannot lose a concurrent flip.
func readPlatformReinterrogation(ctx context.Context, tx *sql.Tx, tenantID, assetID uuid.UUID) (bool, error) {
	var value sql.NullString
	err := tx.QueryRowContext(ctx, `
		SELECT metadata->`+"'"+deviceMetadataKey+"'"+`->>$3
		FROM public.assets WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
		tenantID, assetID, PlatformReinterrogationKey).Scan(&value)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read platform re-interrogation consent: %w", err)
	}
	return value.String == platformExecutorValue, nil
}

// writePlatformReinterrogation sets or removes the consent key inside the
// nested device metadata, leaving every other key there as it is.
func writePlatformReinterrogation(ctx context.Context, tx *sql.Tx, tenantID, assetID uuid.UUID, allowed bool) error {
	var err error
	if allowed {
		_, err = tx.ExecContext(ctx, `
			UPDATE public.assets
			SET metadata = jsonb_set(metadata, '{`+deviceMetadataKey+`}',
			      CASE WHEN jsonb_typeof(metadata->'`+deviceMetadataKey+`') = 'object' THEN metadata->'`+deviceMetadataKey+`' ELSE '{}'::jsonb END
			      || jsonb_build_object($3::text, $4::text), true),
			    updated_at = now()
			WHERE tenant_id = $1 AND id = $2`,
			tenantID, assetID, PlatformReinterrogationKey, platformExecutorValue)
	} else {
		_, err = tx.ExecContext(ctx, `
			UPDATE public.assets
			SET metadata = jsonb_set(metadata, '{`+deviceMetadataKey+`}', (metadata->'`+deviceMetadataKey+`') - $3::text),
			    updated_at = now()
			WHERE tenant_id = $1 AND id = $2
			  AND jsonb_typeof(metadata->'`+deviceMetadataKey+`') = 'object'
			  AND metadata->'`+deviceMetadataKey+`' ? $3::text`,
			tenantID, assetID, PlatformReinterrogationKey)
	}
	if err != nil {
		return fmt.Errorf("write platform re-interrogation consent: %w", err)
	}
	return nil
}

// reopenConsentBlockedEnrichment makes the enrichment work this device's
// missing consent blocked due NOW, so granting the consent takes effect on the
// next coordinator cycle instead of after a backoff of up to two hours.
//
// A blocked configured-source refresh is not terminal — the coordinator retries
// it (identityenrichment.Store.Finish backs off 1, 2, 4 … 128 minutes) and the
// planner re-plans it once its own five-minute receipt clock passes — so this
// moves clocks and nothing else: no state, no reason, no attempt count. The
// re-plan then decides afresh, under every other check the planner and the
// claim make.
//
// It touches only rows blocked for exactly this reason, and only for
// observations the planner would resolve to this device: linked to it, or
// produced by one of its interrogation jobs (by device-job id, or by the
// discovery job a platform run records on the device job).
func reopenConsentBlockedEnrichment(ctx context.Context, tx *sql.Tx, tenantID, assetID uuid.UUID) (int64, error) {
	res, err := tx.ExecContext(ctx, `
		WITH obs AS (
			SELECT o.id FROM public.identity_observations o
			WHERE o.tenant_id = $1 AND (o.asset_id = $2 OR (o.source_ref LIKE 'interrogation:%' AND EXISTS (
				SELECT 1 FROM public.device_jobs j
				WHERE j.tenant_id = $1 AND j.asset_id = $2 AND j.deleted_at IS NULL
				  AND (j.id::text = substr(o.source_ref, 15) OR j.parameters->>'discovery_job_id' = substr(o.source_ref, 15)))))
		), receipts AS (
			UPDATE public.identity_source_refreshes SET next_attempt_at = now(), updated_at = now()
			WHERE tenant_id = $1 AND state = 'blocked' AND reason = $3 AND observation_id IN (SELECT id FROM obs)
			RETURNING observation_id
		), jobs AS (
			UPDATE public.identity_enrichment_jobs SET next_attempt_at = now(), updated_at = now()
			WHERE tenant_id = $1 AND action = 'configured_source' AND state = 'blocked' AND reason = $3
			  AND observation_id IN (SELECT id FROM obs)
			RETURNING observation_id
		)
		UPDATE public.identity_observations SET next_attempt_at = now()
		WHERE tenant_id = $1 AND enrichment_reason = $3
		  AND id IN (SELECT observation_id FROM jobs UNION SELECT observation_id FROM receipts)`,
		tenantID, assetID, reasonExecutorScopeUnknown)
	if err != nil {
		return 0, fmt.Errorf("re-open consent-blocked enrichment: %w", err)
	}
	return res.RowsAffected()
}

// applyPlatformReinterrogation runs inside applyDeviceFields, after the
// free-form metadata merge. That merge REPLACES the nested device metadata
// wholesale — including any consent key the client slipped into it — so the
// consent is written explicitly afterwards: the requested value when the
// request names one, otherwise the prior value. An unrelated metadata edit
// therefore neither withdraws nor grants it.
func applyPlatformReinterrogation(ctx context.Context, tx *sql.Tx, tenantID, assetID uuid.UUID, requested *bool, prior bool) error {
	want := prior
	if requested != nil {
		want = *requested
	}
	if err := writePlatformReinterrogation(ctx, tx, tenantID, assetID, want); err != nil {
		return err
	}
	if want && !prior {
		if _, err := reopenConsentBlockedEnrichment(ctx, tx, tenantID, assetID); err != nil {
			return err
		}
	}
	return nil
}

// lastJobAgentSQL is the planner's own question — "who ran this device's most
// recent completed job?" — so the form hides the consent control for exactly
// the devices whose enrichment the planner would route to an agent.
const lastJobAgentSQL = `SELECT DISTINCT ON (asset_id) asset_id, agent_id IS NOT NULL
	FROM public.device_jobs
	WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[]) AND status = 'completed' AND deleted_at IS NULL
	ORDER BY asset_id, completed_at DESC`

// hydrateInterrogatedByAgent fills Device.InterrogatedByAgent for a page of
// devices in one query.
func (s *DeviceService) hydrateInterrogatedByAgent(ctx context.Context, tenantID uuid.UUID, devices []*models.Device) error {
	if len(devices) == 0 {
		return nil
	}
	byID := make(map[uuid.UUID]*models.Device, len(devices))
	ids := make([]string, 0, len(devices))
	for _, d := range devices {
		byID[d.ID] = d
		ids = append(ids, d.ID.String())
	}
	return shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, lastJobAgentSQL, tenantID, pgUUIDArrayLiteral(ids))
		if err != nil {
			return fmt.Errorf("read device executors: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id uuid.UUID
			var agent bool
			if err := rows.Scan(&id, &agent); err != nil {
				return fmt.Errorf("scan device executor: %w", err)
			}
			if d := byID[id]; d != nil {
				d.InterrogatedByAgent = agent
			}
		}
		return rows.Err()
	})
}
