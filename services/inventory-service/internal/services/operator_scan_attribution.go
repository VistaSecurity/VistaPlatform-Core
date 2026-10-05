package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/autoscan"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// A person's Active Scan of a named asset attaches its result to that asset
// ( item 1, owner decision.
//
// The identity engine holds an active-scan observation of an address on a DHCP
// segment with no device binding (`dynamic_address_without_device_binding`):
// for a scan nobody asked for, the address may have moved to another device
// since the platform last saw it. When a PERSON pressed Scan on an asset, the
// platform itself chose the address from that asset's record, so the result
// belongs to it — unless the scan met a device that contradicts it, which the
// engine still checks (identity.Engine.WithOperatorScanRequest).
//
// The attribution comes only from rows the platform wrote, never from what a
// sensor or a finding says about itself. A finding qualifies when ALL of:
//
//  1. its job is a person-initiated Active Scan: the discovery_jobs row has a
//     `created_by` user, server-stamped `options.origin = "manual"` (the
//     origin cluster-sensor-service writes for a request carrying a person's
//     credentials, and strips from any other caller) and `options.active_scan`;
//     the finding was submitted by that job's executor; and the job is in the
//     asset's CURRENT Active Scan record (autoscan.RecordActiveScanTx), which
//     only CreateActiveScanJob / CreateRevalidationJob write;
//  2. the finding's address is the address that job targeted for that asset: a
//     target of the job, and the asset's primary address or one of its live
//     endpoints' addresses;
//  3. the asset is not deleted, denied or archived;
//
// and exactly one asset qualifies. The job id is read from the finding, but it
// only ever SELECTS among records the platform wrote: a forged id names a job
// that fails 1 or 2. Automatic scans (origin `auto_scan`), identity probes
// (`identity_enrichment`) and anything else no person asked for fail 1 and are
// resolved exactly as before.

// operatorScanFindingKey is the top-level key ingest adds to the retained
// payload of a receipt a person's scan request decided. The retained-evidence
// worker materialises a payload of an `operator_scan_request` observation only
// when it carries this key: the row may also hold receipts of automatic scans
// of the same address, before or after, and the person's attribution covers
// none of them. IngestFinding has no field of this name, so a finding cannot
// carry it in — json.Unmarshal into the struct drops unknown keys.
const operatorScanFindingKey = "operator_scan_job"

// operatorScanCandidate is what a finding says about the scan that produced
// it. Every value is checked against the platform's own rows before use.
type operatorScanCandidate struct {
	jobIDs  []string
	address string
	sensor  string
}

// operatorScanCandidateFor extracts the claim, or reports that the finding
// cannot be a person's Active Scan result at all: not an active scan, no
// address, no executor, or no job id.
func operatorScanCandidateFor(f IngestFinding, effectiveIP *string) (operatorScanCandidate, bool) {
	src := findingSource(f)
	if src.Mode != identity.ModeActive || (src.Ref != "scan" && !strings.HasPrefix(src.Ref, "scan:")) {
		return operatorScanCandidate{}, false
	}
	if effectiveIP == nil || f.SourceSensorID == nil {
		return operatorScanCandidate{}, false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(*effectiveIP))
	if err != nil {
		return operatorScanCandidate{}, false
	}
	sensor, err := uuid.Parse(strings.TrimSpace(*f.SourceSensorID))
	if err != nil || sensor == uuid.Nil {
		return operatorScanCandidate{}, false
	}
	c := operatorScanCandidate{address: addr.WithZone("").String(), sensor: sensor.String()}
	// job_id is stamped by the platform's mirror (jobunits.MirrorMetadata) and
	// by the tenant sensor's legacy executor; batch_id is the mirror row's
	// batch, which is the job for a planned job.
	for _, key := range []string{"job_id", "batch_id"} {
		v := strings.TrimSpace(rawDataString(f.RawData, key))
		id, err := uuid.Parse(v)
		if err != nil || id == uuid.Nil {
			continue
		}
		dup := false
		for _, have := range c.jobIDs {
			dup = dup || have == id.String()
		}
		if !dup {
			c.jobIDs = append(c.jobIDs, id.String())
		}
	}
	return c, len(c.jobIDs) > 0
}

// operatorScanRequestTx looks the claim up on the resolving transaction and
// returns the request it proves, or nil when it proves none.
func operatorScanRequestTx(ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID, c operatorScanCandidate) (*identity.OperatorScanRequest, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT a.id::text, j.id::text
		FROM discovery_jobs j
		JOIN assets a ON a.tenant_id = j.tenant_id
		WHERE j.tenant_id = $1 AND j.id::text = ANY($2)
		  AND `+operatorScanQualifiesSQL("$3", "$4")+`
		LIMIT 2`, tenantID, pq.Array(c.jobIDs), c.address, c.sensor)
	if err != nil {
		return nil, fmt.Errorf("look up the Active Scan that produced a finding: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var found []identity.OperatorScanRequest
	for rows.Next() {
		var asset, job string
		if err := rows.Scan(&asset, &job); err != nil {
			return nil, err
		}
		found = append(found, identity.OperatorScanRequest{
			Asset: identity.AssetRef{TenantID: tenantID.String(), ID: asset}, Address: c.address, JobID: job,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	switch len(found) {
	case 0:
		return nil, nil
	case 1:
		return &found[0], nil
	default:
		// Two assets in one request share the address. The request named
		// both, so it cannot say which one this answer is from.
		log.Printf("[AssetService] IngestFindings: Active Scan job(s) %v scanned %s for more than one asset; the result is not attributed to either", c.jobIDs, c.address)
		return nil, nil
	}
}

// operatorScanQualifiesSQL is conditions 1–3 of the comment at the top of this
// file over `discovery_jobs j` and `assets a` (same tenant), for the finding's
// address and executor sensor id given as SQL text expressions.
func operatorScanQualifiesSQL(address, sensor string) string {
	return `j.created_by IS NOT NULL
		  AND j.metadata -> 'options' ->> 'origin' = 'manual'
		  AND j.metadata @> '{"options":{"active_scan":true}}'::jsonb
		  AND ` + sensor + ` = COALESCE(j.assigned_sensor_id::text, (SELECT s.id::text FROM sensors s
		        WHERE s.tenant_id = j.tenant_id AND s.profile = 'discovery' AND 'system' = ANY(s.tags) ORDER BY s.id LIMIT 1))
		  AND EXISTS (SELECT 1 FROM discovery_targets t
		        WHERE t.tenant_id = j.tenant_id AND t.job_id = j.id AND t.input = ` + address + `)
		  AND a.deleted_at IS NULL AND a.asset_status NOT IN ('archived', 'denied')
		  AND jsonb_typeof(a.metadata -> '` + autoscan.MetaActiveScanJobIDs + `') = 'array'
		  AND a.metadata -> '` + autoscan.MetaActiveScanJobIDs + `' ? j.id::text
		  AND (host(a.primary_address) = ` + address + `
		       OR EXISTS (SELECT 1 FROM asset_endpoints e
		            WHERE e.tenant_id = a.tenant_id AND e.asset_id = a.id AND e.status <> 'closed' AND host(e.address) = ` + address + `))`
}

// operatorScanAttribution returns the resolving-transaction hook that supplies
// a finding's verified scan request, or nil when the finding cannot be one.
func operatorScanAttribution(tenantID uuid.UUID, f IngestFinding, effectiveIP *string) func(context.Context, *sqlx.Tx) (*identity.OperatorScanRequest, error) {
	c, ok := operatorScanCandidateFor(f, effectiveIP)
	if !ok {
		return nil
	}
	return func(ctx context.Context, tx *sqlx.Tx) (*identity.OperatorScanRequest, error) {
		req, err := operatorScanRequestTx(ctx, tx, tenantID, c)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return req, err
	}
}

// operatorScanPayload is the retained payload of one finding: the finding
// itself, plus [operatorScanFindingKey] when a person's scan request decided
// it.
func operatorScanPayload(f IngestFinding, job string) ([]byte, error) {
	raw, err := json.Marshal(f)
	if err != nil || job == "" {
		return raw, err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	marker, err := json.Marshal(job)
	if err != nil {
		return nil, err
	}
	doc[operatorScanFindingKey] = marker
	return json.Marshal(doc)
}
