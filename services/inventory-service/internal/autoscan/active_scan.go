package autoscan

// The person-initiated Active Scan's record of itself, and what finishes it.
//
// An Active Scan (and a stale-asset revalidation) marks the endpoints it is
// about to probe `last_scan_status = 'scanning'` and records, on the ASSET, the
// jobs that will probe them. Nothing in cluster-sensor-service writes back into
// inventory when a job ends, so without a second half those endpoints stayed
// `scanning` for good, and an asset with no endpoint at all could never leave
// Discovery → Active Scan however often it was scanned: a scan that found no
// listener had no endpoint to stamp. [Store.FinishActiveScans] is that second
// half. The automatic-scan worker runs it on every pass, beside
// StampCompletedScans and ClearUnstartedScanStamps, the same machinery the
// automatic scan already uses to close its own loop.
//
// The record lives in `assets.metadata` for the reason RecordScanned gives:
// no schema change, and the table already carries a document for exactly this
// kind of pipeline state. The keys:
//
//	last_active_scan_at          when the scan request was dispatched
//	last_active_scan_job_ids     every job that request created for this asset
//	                             (an asset with endpoints on two ports is two
//	                             jobs, because a job scans every port on every
//	                             target and Active Scan groups by port)
//	last_active_scan_status      scanning → completed | failed
//	last_active_scan_finished_at when FinishActiveScans settled it
//	last_scanned_at              the asset-level "this has been scanned" fact:
//	                             the completion time of the newest scan, active
//	                             or automatic, that finished and reached the
//	                             asset. A failed scan never writes it.
//
// `last_scanned_at` is what the query language's asset field `last_scanned`
// reads, and so what Discovery → Active Scan's unscanned_only predicate reads.

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// Metadata keys of the Active Scan record. Exported because the asset read
// projects them onto the API's `active_scan` field.
const (
	MetaActiveScanAt         = "last_active_scan_at"
	MetaActiveScanJobIDs     = "last_active_scan_job_ids"
	MetaActiveScanStatus     = "last_active_scan_status"
	MetaActiveScanFinishedAt = "last_active_scan_finished_at"
	// MetaLastScannedAt is the asset-level scan fact (see the package comment
	// above). The query language's asset field `last_scanned` reads it.
	MetaLastScannedAt = "last_scanned_at"
)

// manualOrigin is the options.origin cluster-sensor-service stamps on every job
// created with a person's credentials (discovery_handler.go: "Anything carrying
// a person's JWT is 'manual' by construction").
const manualOrigin = "manual"

// Active Scan record statuses.
const (
	ActiveScanScanning  = "scanning"
	ActiveScanCompleted = "completed"
	ActiveScanFailed    = "failed"
)

// RecordActiveScanTx records that jobID will scan the given assets on the
// given ports, as part of the scan request dispatched at requestAt. The caller
// holds a tenant transaction (database.WithTenantTx).
//
// The assets' live endpoints on those ports are marked `scanning`; their
// last_scanned_at is NOT written — that is a scan time, and the scan has not
// happened yet. FinishActiveScans writes it.
//
// One request can create several jobs for one asset (one per port list, and
// one per executor when routing splits a batch), so the job list is APPENDED
// to while the stored request time matches this request, and REPLACED when it
// does not: the record always names exactly the jobs of the newest request.
// requestAt is that request's marker, so the caller passes the same instant
// for every job of one request.
//
// Any previous result is cleared: the asset is `scanning` again until this
// request's jobs have all ended. `last_scanned_at` is deliberately kept — a
// rescan in flight does not make a scanned asset unscanned.
func RecordActiveScanTx(ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID, assetIDs []uuid.UUID, ports []int, jobID string, requestAt time.Time) error {
	if len(assetIDs) == 0 {
		return nil
	}
	marker := requestAt.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
		UPDATE asset_endpoints
		SET last_scan_status = '`+ActiveScanScanning+`',
		    updated_at       = now()
		WHERE tenant_id = $1 AND asset_id = ANY($2) AND port = ANY($3) AND status <> 'closed'`,
		tenantID, pq.Array(assetIDs), pq.Array(ports)); err != nil {
		return fmt.Errorf("mark endpoints scanning: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE assets
		SET metadata = (COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
		        '`+MetaActiveScanAt+`', $3::text,
		        '`+MetaActiveScanStatus+`', '`+ActiveScanScanning+`'::text,
		        '`+MetaActiveScanJobIDs+`', CASE
		            WHEN metadata ->> '`+MetaActiveScanAt+`' = $3::text
		             AND jsonb_typeof(metadata -> '`+MetaActiveScanJobIDs+`') = 'array'
		            THEN (metadata -> '`+MetaActiveScanJobIDs+`') || to_jsonb($4::text)
		            ELSE jsonb_build_array($4::text)
		        END)) - '`+MetaActiveScanFinishedAt+`',
		    updated_at = now()
		WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL`,
		tenantID, pq.Array(assetIDs), marker, jobID); err != nil {
		return fmt.Errorf("record the scan on its assets: %w", err)
	}
	return nil
}

// FinishedScans is what one FinishActiveScans pass settled.
type FinishedScans struct {
	// Assets is how many assets' scan records moved off `scanning`.
	Assets int
	// Endpoints is how many endpoints moved off `scanning`.
	Endpoints int
}

// activeScanJobIDsSQL is the asset's recorded job ids as uuid[], for a
// primary-key lookup on discovery_jobs. Only Active Scan writes the key, so a
// non-uuid element is corruption; it is skipped rather than cast, because a
// failed cast would abort the whole pass for every asset of the tenant.
func activeScanJobIDsSQL(asset string) string {
	return `ARRAY(SELECT x::uuid FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(` + asset + `.metadata -> '` + MetaActiveScanJobIDs + `') = 'array' THEN ` + asset + `.metadata -> '` + MetaActiveScanJobIDs + `' ELSE '[]'::jsonb END) AS x WHERE x ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')`
}

// targetReachedSQL is the condition that a job's target row was actually
// scanned, whatever the job's own outcome. A planned job (metadata ?
// 'scan_plan') settles each target from its units (jobunits.SettleTarget):
// `completed` once its host finished `done`, `failed` when the host could not
// be scanned, `cancelled` when the job was cancelled first — so a job that the
// stale-dispatch sweep failed AFTER this host was scanned still scanned it. A
// legacy job's platform executor sets `completed` per target too; an old
// tenant sensor reporting a legacy job may never move the row at all, so there
// a row that did not fail or get cancelled counts once the JOB completed.
const targetReachedSQL = `(t.status = 'completed' OR (j.status = 'completed' AND NOT (j.metadata ? 'scan_plan') AND t.status NOT IN ('failed', 'cancelled')))`

// targetScannedAtSQL is when a reached target was scanned: its own completion
// (SettleTarget, or the legacy executor) when recorded, else the job's.
const targetScannedAtSQL = `COALESCE(t.completed_at, j.completed_at, now())`

// lastScannedGuardSQL reads metadata.last_scanned_at as a timestamp, NULL when
// it is absent or not timestamp-shaped (the same guard the query language uses
// for a jsonb timestamp), so a corrupt value cannot abort the statement.
func lastScannedGuardSQL(asset string) string {
	v := asset + `.metadata ->> '` + MetaLastScannedAt + `'`
	return `(CASE WHEN ` + v + ` ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}([T ][0-9]{2}:[0-9]{2}(:[0-9]{2})?)?' THEN (` + v + `)::timestamptz END)`
}

// finishedAssetsCTE selects the assets whose Active Scan record is `scanning`
// and every recorded job of which has ended. A job that no longer exists counts
// as ended — it can never finish, and waiting for it would leave the record
// `scanning` for good, which is the bug this file exists to fix. A record with
// no job ids at all is ended too, and settles as failed.
var finishedAssetsCTE = `
	fin AS (
		SELECT a.id, a.tenant_id, a.primary_address, a.hostname, a.metadata,
		       ` + activeScanJobIDsSQL("a") + ` AS job_ids
		FROM assets a
		WHERE a.tenant_id = $1
		  AND a.deleted_at IS NULL
		  AND a.metadata ->> '` + MetaActiveScanStatus + `' = '` + ActiveScanScanning + `'
		  AND NOT EXISTS (
		        SELECT 1 FROM discovery_jobs j
		        WHERE j.tenant_id = a.tenant_id
		          AND j.id = ANY(` + activeScanJobIDsSQL("a") + `)
		          AND j.status NOT IN ('completed', 'failed', 'cancelled'))
	)`

// FinishActiveScans settles every person-initiated scan of the tenant whose
// jobs have all ended. It returns what it settled.
//
// For each such asset, every endpoint still `scanning` becomes:
//
//   - `completed`, with last_scanned_at = when its host was scanned, when one
//     of the asset's recorded jobs actually reached that endpoint: a target of
//     that job names the endpoint's address (or the asset's address or
//     hostname, which is what the scan used when the endpoint has none), lists
//     the endpoint's port, and was scanned (targetReachedSQL). Whether anything
//     ANSWERED does not matter — a closed port that was probed was scanned —
//     and neither does how the job ended: a job swept as failed after it had
//     scanned this host did scan it.
//   - `failed` otherwise: the job failed or was cancelled before scanning it,
//     or the host's unit failed, or no job covered it. last_scanned_at is left
//     exactly as it was — dispatch no longer writes it, so a scan that never
//     ran leaves no false scan time behind.
//
// The asset's record becomes `completed` (and `last_scanned_at` moves to the
// scan time) when a recorded job reached a target for the asset's address,
// hostname or any endpoint address; otherwise `failed`, which leaves
// `last_scanned_at` alone, so an asset whose only scan failed stays on the
// unscanned list.
//
// Endpoints still `scanning` from before this record existed — dispatched by
// an older build, with no job ids on the asset — are settled from the first
// person-initiated scan job created for their address and port after they were
// stamped, and marked `failed` after a day if no such job can be found.
// "Person-initiated" is how cluster-sensor-service records it: every job
// created with a person's credentials carries options.origin = "manual"
// (server-derived, discovery_handler.go); rows from builds before that carry
// no origin. `auto_scan` and `identity_enrichment` jobs are never matched.
//
// Idempotent: a settled record is no longer `scanning`, so a second pass
// matches nothing. Safe to run from any number of replicas.
func (s *Store) FinishActiveScans(ctx context.Context, tenantID uuid.UUID) (FinishedScans, error) {
	var out FinishedScans
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		// 1. Endpoints of the finished assets. The CTE computes each one's
		// completion time (NULL = not reached) before anything is written.
		res, err := tx.ExecContext(ctx, `
			WITH `+finishedAssetsCTE+`,
			res AS (
				SELECT e.id AS endpoint_id, (
					SELECT max(`+targetScannedAtSQL+`)
					FROM discovery_jobs j
					JOIN discovery_targets t ON t.job_id = j.id AND t.tenant_id = j.tenant_id
					WHERE j.tenant_id = a.tenant_id
					  AND j.id = ANY(a.job_ids)
					  AND t.input IN (host(e.address), host(a.primary_address), a.hostname)
					  AND e.port = ANY(t.ports)
					  AND `+targetReachedSQL+`
				) AS completed_at
				FROM asset_endpoints e
				JOIN fin a ON a.tenant_id = e.tenant_id AND a.id = e.asset_id
				WHERE e.tenant_id = $1 AND e.last_scan_status = '`+ActiveScanScanning+`'
			)
			UPDATE asset_endpoints e
			SET last_scan_status = CASE WHEN res.completed_at IS NOT NULL THEN '`+ActiveScanCompleted+`' ELSE '`+ActiveScanFailed+`' END,
			    last_scanned_at  = COALESCE(res.completed_at, e.last_scanned_at),
			    updated_at       = now()
			FROM res
			WHERE e.tenant_id = $1 AND e.id = res.endpoint_id`, tenantID)
		if err != nil {
			return fmt.Errorf("settle endpoints: %w", err)
		}
		n, _ := res.RowsAffected()
		out.Endpoints += int(n)

		// 2. The assets' own records. The job list is carried into the
		// UPDATE's WHERE so a scan re-dispatched while this ran (a new job
		// list) is not settled from the old one.
		res, err = tx.ExecContext(ctx, `
			WITH `+finishedAssetsCTE+`,
			res AS (
				SELECT a.id, a.metadata -> '`+MetaActiveScanJobIDs+`' AS recorded, (
					SELECT max(`+targetScannedAtSQL+`)
					FROM discovery_jobs j
					JOIN discovery_targets t ON t.job_id = j.id AND t.tenant_id = j.tenant_id
					WHERE j.tenant_id = a.tenant_id
					  AND j.id = ANY(a.job_ids)
					  AND (t.input = host(a.primary_address)
					       OR t.input = a.hostname
					       OR t.input IN (SELECT host(e.address) FROM asset_endpoints e
					                      WHERE e.tenant_id = a.tenant_id AND e.asset_id = a.id AND e.address IS NOT NULL))
					  AND `+targetReachedSQL+`
				) AS completed_at
				FROM fin a
			)
			UPDATE assets a
			SET metadata = CASE
			        WHEN res.completed_at IS NOT NULL THEN a.metadata || jsonb_build_object(
			            '`+MetaActiveScanStatus+`', '`+ActiveScanCompleted+`'::text,
			            '`+MetaActiveScanFinishedAt+`', to_jsonb(res.completed_at),
			            '`+MetaLastScannedAt+`', to_jsonb(GREATEST(res.completed_at, `+lastScannedGuardSQL("a")+`)))
			        ELSE a.metadata || jsonb_build_object(
			            '`+MetaActiveScanStatus+`', '`+ActiveScanFailed+`'::text,
			            '`+MetaActiveScanFinishedAt+`', to_jsonb(now()))
			    END,
			    updated_at = now()
			FROM res
			WHERE a.tenant_id = $1 AND a.id = res.id
			  AND a.metadata -> '`+MetaActiveScanJobIDs+`' IS NOT DISTINCT FROM res.recorded`, tenantID)
		if err != nil {
			return fmt.Errorf("settle assets: %w", err)
		}
		n, _ = res.RowsAffected()
		out.Assets += int(n)

		// 3. Endpoints stamped `scanning` by an older build, whose asset has no
		// job list to settle them from.
		res, err = tx.ExecContext(ctx, `
			WITH leg AS (
				SELECT e.id AS endpoint_id, m.job_status, m.completed_at, COALESCE(m.reached, false) AS reached
				FROM asset_endpoints e
				JOIN assets a ON a.tenant_id = e.tenant_id AND a.id = e.asset_id
				LEFT JOIN LATERAL (
					SELECT j.status AS job_status, `+targetScannedAtSQL+` AS completed_at,
					       `+targetReachedSQL+` AS reached
					FROM discovery_targets t
					JOIN discovery_jobs j ON j.id = t.job_id AND j.tenant_id = t.tenant_id
					WHERE t.tenant_id = e.tenant_id
					  AND t.input IN (host(e.address), host(a.primary_address), a.hostname)
					  AND e.port = ANY(t.ports)
					  AND j.metadata @> '{"options":{"active_scan":true}}'::jsonb
					  AND COALESCE(j.metadata -> 'options' ->> 'origin', '`+manualOrigin+`') = '`+manualOrigin+`'
					  AND e.last_scanned_at IS NOT NULL
					  AND j.created_at >= e.last_scanned_at - interval '5 minutes'
					ORDER BY j.created_at ASC
					LIMIT 1
				) m ON true
				WHERE e.tenant_id = $1
				  AND e.last_scan_status = '`+ActiveScanScanning+`'
				  AND a.deleted_at IS NULL
				  AND NOT COALESCE(a.metadata ? '`+MetaActiveScanJobIDs+`', false)
			)
			UPDATE asset_endpoints e
			SET last_scan_status = CASE WHEN leg.reached THEN '`+ActiveScanCompleted+`' ELSE '`+ActiveScanFailed+`' END,
			    last_scanned_at  = CASE WHEN leg.reached THEN leg.completed_at ELSE e.last_scanned_at END,
			    updated_at       = now()
			FROM leg
			WHERE e.tenant_id = $1 AND e.id = leg.endpoint_id
			  AND (leg.job_status IN ('completed', 'failed', 'cancelled')
			       OR (leg.job_status IS NULL AND (e.last_scanned_at IS NULL OR e.last_scanned_at < now() - interval '24 hours')))`, tenantID)
		if err != nil {
			return fmt.Errorf("settle endpoints stamped before the scan record existed: %w", err)
		}
		n, _ = res.RowsAffected()
		out.Endpoints += int(n)
		return nil
	})
	if err != nil {
		return FinishedScans{}, fmt.Errorf("finish active scans: %w", err)
	}
	return out, nil
}

// ActiveScanFromMetadata projects the record out of an asset's metadata onto
// the API's `active_scan` field, or nil when the asset has never been actively
// scanned (or the record is not one this build wrote).
func ActiveScanFromMetadata(meta map[string]interface{}) *models.AssetActiveScan {
	status, _ := meta[MetaActiveScanStatus].(string)
	switch status {
	case ActiveScanScanning, ActiveScanCompleted, ActiveScanFailed:
	default:
		return nil
	}
	rec := &models.AssetActiveScan{Status: status, JobIDs: []string{}}
	rec.StartedAt = metaTime(meta[MetaActiveScanAt])
	rec.FinishedAt = metaTime(meta[MetaActiveScanFinishedAt])
	if ids, ok := meta[MetaActiveScanJobIDs].([]interface{}); ok {
		for _, id := range ids {
			if s, ok := id.(string); ok && s != "" {
				rec.JobIDs = append(rec.JobIDs, s)
			}
		}
	}
	return rec
}

func metaTime(v interface{}) *time.Time {
	s, ok := v.(string)
	if !ok || s == "" {
		return nil
	}
	// Go writes RFC 3339; Postgres' to_jsonb(timestamptz) writes the same
	// shape with a "+00:00" offset, which RFC3339Nano also parses.
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return nil
	}
	return &t
}
