// Package autoscan is inventory-service's half of automatic active scanning:
// reading and writing the tenant's policy, picking the assets a sweep is
// allowed to probe, and recording what the sweep did.
//
// The policy SHAPE, its defaults and the address rules live in
// shared/autoscan, because the settings endpoint and the background worker must
// agree about them exactly and a second copy of "24 hours" in either place is
// how a page ends up promising something the worker does not do. What lives
// here is everything that needs a database.
package autoscan

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	sharedautoscan "github.com/vistasecurity/vistaplatform/shared/autoscan"
)

// Policy is re-exported so callers do not have to import both packages for one
// struct.
type Policy = sharedautoscan.Policy

// State is what the last sweep did. It is the worker's record of its own run,
// and it lives under its OWN key in the settings document rather than inside
// the policy block: a tenant saving the policy page must not be able to rewrite
// the platform's account of what it did.
type State struct {
	LastSweepAt     *time.Time `json:"last_sweep_at,omitempty"`
	NextSweepAt     *time.Time `json:"next_sweep_at,omitempty"`
	LastSweepJobs   int        `json:"last_sweep_jobs"`
	LastSweepAssets int        `json:"last_sweep_assets"`
	// LastSweepRefusals counts, by reason, the assets the last sweep looked at
	// and would NOT scan — public addresses, carrier-grade NAT, the excluded
	// platform ranges, link-local and the rest. Recorded so the page can say
	// what was left out, because a tenant whose whole estate is in 100.64/10
	// otherwise sees "Automatic scanning: on" over a sweep that scans nothing.
	LastSweepRefusals map[sharedautoscan.Reason]int `json:"last_sweep_refusals,omitempty"`
}

// Target is one asset an automatic scan may probe.
type Target struct {
	AssetID uuid.UUID
	Address string
}

// Store reads and writes the policy, the state, and the eligible-asset set.
type Store struct {
	db *database.DB
}

func NewStore(db *database.DB) *Store { return &Store{db: db} }

// GetPolicy returns the tenant's policy, defaulted field-by-field for anything
// the settings document does not carry.
func (s *Store) GetPolicy(ctx context.Context, tenantID uuid.UUID) (Policy, error) {
	config, err := s.readConfig(ctx, tenantID)
	if err != nil {
		return sharedautoscan.DefaultPolicy(), err
	}
	policy := sharedautoscan.FromConfig(config)
	// The admission emergency stop also pauses automatic enrichment through
	// this older scheduler. Incoming evidence continues to be retained.
	if admission, ok := config["identity_admission"].(map[string]interface{}); ok && admission["mode"] == "paused" {
		policy.Enabled = false
	}
	return policy, nil
}

// GetState returns the worker's record of its last sweep.
func (s *Store) GetState(ctx context.Context, tenantID uuid.UUID) (State, error) {
	var out State
	config, err := s.readConfig(ctx, tenantID)
	if err != nil {
		return out, err
	}
	raw, ok := config[sharedautoscan.StateKey]
	if !ok {
		return out, nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return out, nil
	}
	// A state block written by a future build, or corrupted, must not fail the
	// settings page — the page's job is to show the policy, and "we have no
	// record of a sweep" is a truthful thing to show.
	_ = json.Unmarshal(encoded, &out)
	return out, nil
}

func (s *Store) readConfig(ctx context.Context, tenantID uuid.UUID) (map[string]interface{}, error) {
	var raw []byte
	// RLS-scoped read: tenant_admin_settings carries a tenant_isolation policy.
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		err := tx.QueryRowContext(ctx, `SELECT config FROM tenant_admin_settings WHERE tenant_id = $1`, tenantID).Scan(&raw)
		if err == sql.ErrNoRows {
			return nil
		}
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("read the tenant settings: %w", err)
	}
	config := map[string]interface{}{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &config); err != nil {
			return nil, fmt.Errorf("invalid tenant automatic-scan settings: %w", err)
		}
	}
	return config, nil
}

// SetPolicy writes the whole policy block, preserving every other key in the
// settings document, and returns the new `tenant_admin_settings.version`.
//
// The two-statement shape (seed-if-missing, then UPDATE) is the one
// driftsettings uses and for its reason: `log_tenant_admin_settings_change` is
// an AFTER UPDATE trigger, so a single upsert writes NO audit row for a tenant
// whose settings row does not exist yet — and the first time someone turns
// unattended scanning on or off is the change most worth recording.
func (s *Store) SetPolicy(ctx context.Context, tenantID, actorUserID uuid.UUID, policy Policy) (Policy, int, error) {
	normalized, err := sharedautoscan.Normalize(policy)
	if err != nil {
		return Policy{}, 0, err
	}
	blob, err := json.Marshal(sharedautoscan.ToConfig(normalized))
	if err != nil {
		return Policy{}, 0, fmt.Errorf("encode the policy: %w", err)
	}

	var version int
	err = database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		var actor any
		if actorUserID != uuid.Nil {
			actor = actorUserID
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO tenant_admin_settings (tenant_id, config, updated_by, created_at, updated_at)
			VALUES ($1, '{}'::jsonb, $2, NOW(), NOW())
			ON CONFLICT (tenant_id) DO NOTHING`, tenantID, actor); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `
			UPDATE tenant_admin_settings
			SET config = COALESCE(config, '{}'::jsonb) || jsonb_build_object($2::text, $3::jsonb),
			    version = tenant_admin_settings.version + 1,
			    updated_by = $4,
			    updated_at = NOW()
			WHERE tenant_id = $1
			RETURNING version`,
			tenantID, sharedautoscan.ConfigKey, blob, actor).Scan(&version)
	})
	if err != nil {
		return Policy{}, 0, fmt.Errorf("save the automatic-scan policy: %w", err)
	}
	return normalized, version, nil
}

// SetState records what a sweep did.
//
// It deliberately does NOT bump `version` or touch `updated_by`: the version is
// the tenant's settings version and the audit trigger reads it, so a background
// pass bumping it on every tick would bury the tenant's own changes in machine
// noise.
func (s *Store) SetState(ctx context.Context, tenantID uuid.UUID, state State) error {
	blob, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO tenant_admin_settings (tenant_id, config, created_at, updated_at)
			VALUES ($1, '{}'::jsonb, NOW(), NOW())
			ON CONFLICT (tenant_id) DO NOTHING`, tenantID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `
			UPDATE tenant_admin_settings
			SET config = COALESCE(config, '{}'::jsonb) || jsonb_build_object($2::text, $3::jsonb)
			WHERE tenant_id = $1`,
			tenantID, sharedautoscan.StateKey, blob)
		return err
	})
}

// cutoffArg renders an optional cutoff for the query. A typed nil rather than
// an untyped one, so the ::timestamptz cast in the CASE has something to cast.
func cutoffArg(cutoff *time.Time) interface{} {
	if cutoff == nil {
		return nil
	}
	return *cutoff
}

// candidateLimit caps how many asset rows one sweep reads per tenant. A sweep
// that had to page through a million-row inventory before it could dispatch
// anything would be a sweep that never dispatched anything; the rows it does
// not reach this tick are the OLDEST-scanned ones, so they come first next tick.
const candidateLimit = 20000

// EligibleTargets returns the assets whose last automatic scan is older than
// the policy's interval (or which have never had one), restricted to addresses
// an automatic scan is allowed to probe.
//
// `excluded` are the platform's own addresses. Approval state is deliberately
// NOT part of the filter beyond the two terminal states: a `pending_approval`
// asset is still a host on the tenant's network, and refusing to scan it would
// mean the inventory the approval decision is made from is the thin one.
//
// `denied` and `archived` ARE excluded — those are a decision that the thing is
// not part of the inventory, and continuing to probe it daily would be the
// platform disagreeing with the tenant on a schedule.
func (s *Store) EligibleTargets(ctx context.Context, tenantID uuid.UUID, policy Policy, now time.Time, excluded []netip.Prefix) ([]Target, map[sharedautoscan.Reason]int, error) {
	cutoff := now.Add(-time.Duration(policy.RescanIntervalHours) * time.Hour)
	return s.scannableAssets(ctx, tenantID, &cutoff, excluded)
}

// InScope counts every asset automatic scanning COVERS, whether or not it is
// due right now. It is what the settings page shows beside the policy, and it
// answers the question a tenant actually asks of an unattended capability:
// "what is this doing on my behalf?"
//
// It is the eligibility rule with the interval dropped, computed from the same
// function, so the number on the page can never describe a different set from
// the one the worker scans.
func (s *Store) InScope(ctx context.Context, tenantID uuid.UUID, excluded []netip.Prefix) (int, error) {
	targets, _, err := s.scannableAssets(ctx, tenantID, nil, excluded)
	if err != nil {
		return 0, err
	}
	return len(targets), nil
}

// scannableAssets is the one eligibility rule. `cutoff` nil means "ignore the
// rescan interval".
func (s *Store) scannableAssets(ctx context.Context, tenantID uuid.UUID, cutoff *time.Time, excluded []netip.Prefix) ([]Target, map[sharedautoscan.Reason]int, error) {
	config, err := s.readConfig(ctx, tenantID)
	if err != nil {
		return nil, nil, err
	}
	restrictions, err := sharedautoscan.RestrictionsFromConfig(config)
	if err != nil {
		return nil, nil, err
	}
	if restrictions.Paused {
		return nil, map[sharedautoscan.Reason]int{}, nil
	}
	excluded = append(append([]netip.Prefix(nil), excluded...), restrictions.Excluded...)
	protectedClasses := []string{}
	for _, class := range assetclass.All {
		if restrictions.ProtectsAsset(uuid.Nil, class.Key) {
			protectedClasses = append(protectedClasses, class.Key)
		}
	}
	protectedIDs := []string{}
	for id := range restrictions.SensitiveAssetIDs {
		protectedIDs = append(protectedIDs, id.String())
	}
	segments, err := s.segmentPrefixes(ctx, tenantID)
	if err != nil {
		return nil, nil, err
	}

	type row struct {
		id        uuid.UUID
		address   string
		protected bool
	}
	var rows []row
	err = database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		var sensitiveSegments []string
		if err := tx.SelectContext(ctx, &sensitiveSegments, `SELECT value FROM network_segments WHERE tenant_id=$1 AND is_active AND segment_type='cidr' AND (COALESCE(metadata->>'sensitive','false')='true' OR COALESCE(metadata->>'active_probes_disabled','false')='true')`, tenantID); err != nil {
			return err
		}
		excluded = append(excluded, sharedautoscan.ParsePrefixes(sensitiveSegments)...)
		// The CASE — rather than an OR chain — is what keeps a malformed stored
		// timestamp from erroring the whole query: Postgres may reorder the arms
		// of an OR and evaluate the cast anyway, while CASE is evaluated in
		// order. An unparseable stamp is treated as "never scanned", which errs
		// toward scanning rather than toward silently skipping an asset forever.
		q, err := tx.QueryContext(ctx, `
			SELECT a.id, host(a.primary_address), EXISTS(
       SELECT 1 FROM assets protected WHERE protected.tenant_id=a.tenant_id
       AND (protected.id=ANY($4::uuid[]) OR protected.class_key=ANY($5::text[]) OR protected.class_key LIKE '%industrial%' OR protected.class_key LIKE '%medical%' OR protected.class_key LIKE 'ot\_%' ESCAPE '\')
       AND (protected.primary_address=a.primary_address OR EXISTS(SELECT 1 FROM asset_endpoints e WHERE e.tenant_id=protected.tenant_id AND e.asset_id=protected.id AND e.address=a.primary_address)))
   FROM assets a
			WHERE a.tenant_id = $1
			  AND a.deleted_at IS NULL
			  AND a.primary_address IS NOT NULL
			  AND a.asset_status NOT IN ('denied', 'archived')
			  AND a.asset_ownership <> 'third_party'
			  AND COALESCE(a.stale_status, '') <> 'archived'
			  AND CASE
			        WHEN $2::timestamptz IS NULL THEN true
			        WHEN a.metadata ->> 'last_auto_scan_at' ~ '^\d{4}-\d{2}-\d{2}T'
			          THEN (a.metadata ->> 'last_auto_scan_at')::timestamptz < $2::timestamptz
			        ELSE true
			      END
			ORDER BY a.metadata ->> 'last_auto_scan_at' NULLS FIRST, a.last_seen_at DESC
			LIMIT $3`, tenantID, cutoffArg(cutoff), candidateLimit, pq.Array(protectedIDs), pq.Array(protectedClasses))
		if err != nil {
			return err
		}
		defer func() { _ = q.Close() }()
		for q.Next() {
			var r row
			var addr sql.NullString
			if err := q.Scan(&r.id, &addr, &r.protected); err != nil {
				return err
			}
			r.address = addr.String
			rows = append(rows, r)
		}
		return q.Err()
	})
	if err != nil {
		return nil, nil, fmt.Errorf("select automatic-scan candidates: %w", err)
	}

	refusals := map[sharedautoscan.Reason]int{}
	var targets []Target
	for _, r := range rows {
		if r.protected {
			refusals[sharedautoscan.ReasonExcluded]++
			continue
		}
		addr, reason, ok := sharedautoscan.ParseTarget(r.address)
		if !ok {
			refusals[reason]++
			continue
		}
		allowed, reason := sharedautoscan.Classify(addr, segments, excluded)
		if !allowed {
			refusals[reason]++
			continue
		}
		targets = append(targets, Target{AssetID: r.id, Address: addr.String()})
	}
	return targets, refusals, nil
}

// AutomaticSegmentTypes are the `network_segments.network_type` values that put
// an address in scope for an UNATTENDED scan.
//
// `public` is deliberately absent. A tenant can register a public segment, and
// it is a perfectly good thing to scan when a person asks — but the Active
// Scanning page tells them "public addresses and third-party systems are never
// probed", and a registered public segment is exactly how that sentence becomes
// false without anyone noticing. The segment rule exists to let a tenant say
// "this range is mine"; `network_type: public` says the opposite about what is
// on it. The manual Discover wizard and Active Scan are unchanged.
var AutomaticSegmentTypes = map[string]bool{"private": true, "vpn": true, "cloud": true}

// Segment is one registered network segment, as the eligibility rule sees it.
type Segment struct {
	Value       string `db:"value"`
	NetworkType string `db:"network_type"`
}

// AutomaticSegmentPrefixes is the decision: which of a tenant's registered
// segments put an address in scope for an unattended scan.
//
// The filter lives in Go rather than in the WHERE clause so it is one
// expression with a table test behind it, including the case that matters — a
// registered `public` segment, which is a real thing a tenant can create and
// the one way the page's promise silently becomes false.
func AutomaticSegmentPrefixes(segments []Segment) []netip.Prefix {
	var values []string
	for _, seg := range segments {
		if !AutomaticSegmentTypes[strings.ToLower(strings.TrimSpace(seg.NetworkType))] {
			continue
		}
		values = append(values, seg.Value)
	}
	return sharedautoscan.ParsePrefixes(values)
}

// segmentPrefixes returns the CIDRs of the tenant's ACTIVE registered network
// segments that an automatic scan may treat as theirs. Only the `cidr`-shaped
// values describe addresses; a segment can equally be a domain or a VPC id, and
// ParsePrefixes drops those.
func (s *Store) segmentPrefixes(ctx context.Context, tenantID uuid.UUID) ([]netip.Prefix, error) {
	var segments []Segment
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.SelectContext(ctx, &segments, `
			SELECT value, network_type FROM network_segments
			WHERE tenant_id = $1 AND COALESCE(is_active, true) = true`, tenantID)
	})
	if err != nil {
		return nil, fmt.Errorf("read the tenant's network segments: %w", err)
	}
	return AutomaticSegmentPrefixes(segments), nil
}

// AddressesWithScanInFlight returns the target inputs that already have an
// automatic job queued or running.
//
// This is the idempotency gate. Without it a burst of observations, a restart
// mid-sweep, or simply a sweep tick that fires while the previous job is still
// running would each queue the same address again — and a host being probed
// several times over for one observation is exactly the unattended-scanner
// failure mode a tenant would notice in their own logs before we did.
func (s *Store) AddressesWithScanInFlight(ctx context.Context, tenantID uuid.UUID) (map[string]bool, error) {
	out := map[string]bool{}
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		q, err := tx.QueryContext(ctx, `
			SELECT DISTINCT t.input
			FROM discovery_targets t
			JOIN discovery_jobs j ON j.id = t.job_id AND j.tenant_id = t.tenant_id
			WHERE t.tenant_id = $1
			  AND j.status IN ('queued', 'awaiting_sensor', 'running', 'in_progress', 'processing')
			  AND j.metadata @> $2::jsonb`, tenantID, originFilterJSON)
		if err != nil {
			return err
		}
		defer func() { _ = q.Close() }()
		for q.Next() {
			var input string
			if err := q.Scan(&input); err != nil {
				return err
			}
			out[input] = true
		}
		return q.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("read in-flight automatic scans: %w", err)
	}
	return out, nil
}

// Origin is the marker an automatic job carries so every later reader — the
// idempotency gate, the settings page's recent-runs list, a support engineer
// with psql — can tell a scan nobody asked for from one somebody did.
//
// It rides in the job's `options`, which cluster-sensor-service stores verbatim
// under `metadata.options`. That needs no new column and no request-shape
// change, and `idx_discovery_jobs_metadata` is a GIN index, so the containment
// query below uses it.
const Origin = "auto_scan"

const originFilterJSON = `{"options":{"origin":"` + Origin + `"}}`

// JobOptions is what an automatic scan puts in a discovery job's options.
//
// `active_scan` is carried for the same reason the on-demand Active Scan
// carries it: it stamps provenance (discovery_source) on the rows the job
// mirrors into sensor_discoveries. It does not gate the mirror.
func JobOptions() map[string]interface{} {
	return map[string]interface{}{
		"active_scan": true,
		"origin":      Origin,
	}
}

// RecentJob is one automatic run, for the settings page's read-only summary.
type RecentJob struct {
	ID          string     `json:"id"`
	Status      string     `json:"status"`
	TargetCount int        `json:"target_count"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	// Executor is "platform" or "sensor"; ExecutorName names the tenant sensor
	// a `sensors` job was handed to. The dispatch timestamps and the
	// failure reason are what the settings page's run list renders the
	// state from — this list is where automatic scans are visible.
	Executor              string     `json:"executor"`
	ExecutorName          *string    `json:"executor_name,omitempty"`
	ExecutorLastHeartbeat *time.Time `json:"executor_last_heartbeat,omitempty"`
	DispatchedAt          *time.Time `json:"dispatched_at,omitempty"`
	PickedUpAt            *time.Time `json:"picked_up_at,omitempty"`
	ErrorMessage          *string    `json:"error_message,omitempty"`
}

// RecentJobs returns the tenant's most recent automatic scans.
//
// This is the whole reachability story for the worker: a capability that acts
// unasked and reports nowhere is indistinguishable from a bug. Discovery jobs
// have no listing page of their own (Discovery → Discovery Jobs lists
// device-interrogation runs), so the Active Scanning settings page is where a
// tenant sees that the platform is in fact scanning for them — and, since
//from WHICH sensor and in what state.
func (s *Store) RecentJobs(ctx context.Context, tenantID uuid.UUID, limit int) ([]RecentJob, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	var out []RecentJob
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		q, err := tx.QueryContext(ctx, `
			SELECT j.id, j.status, j.created_at, j.completed_at,
			       (SELECT COUNT(DISTINCT t.input) FROM discovery_targets t WHERE t.job_id = j.id AND t.tenant_id = j.tenant_id),
			       j.execution_mode, s.name, s.last_heartbeat, j.dispatched_at, c.delivered_at, j.error_message
			FROM discovery_jobs j
			LEFT JOIN sensors s ON s.id = j.assigned_sensor_id
			LEFT JOIN LATERAL (
				SELECT c.delivered_at FROM sensor_commands c
				WHERE c.command_type = 'discovery_job' AND c.payload ->> 'job_id' = j.id::text
				ORDER BY c.created_at DESC LIMIT 1
			) c ON true
			WHERE j.tenant_id = $1 AND j.metadata @> $2::jsonb
			ORDER BY j.created_at DESC
			LIMIT $3`, tenantID, originFilterJSON, limit)
		if err != nil {
			return err
		}
		defer func() { _ = q.Close() }()
		for q.Next() {
			var r RecentJob
			var completed, beat, dispatched, pickedUp sql.NullTime
			var mode string
			var sensorName, errMsg sql.NullString
			if err := q.Scan(&r.ID, &r.Status, &r.CreatedAt, &completed, &r.TargetCount, &mode, &sensorName, &beat, &dispatched, &pickedUp, &errMsg); err != nil {
				return err
			}
			if completed.Valid {
				t := completed.Time
				r.CompletedAt = &t
			}
			r.Executor = "platform"
			if strings.EqualFold(strings.TrimSpace(mode), "sensors") {
				r.Executor = "sensor"
			}
			if sensorName.Valid {
				name := sensorName.String
				r.ExecutorName = &name
			}
			if beat.Valid {
				t := beat.Time
				r.ExecutorLastHeartbeat = &t
			}
			if dispatched.Valid {
				t := dispatched.Time
				r.DispatchedAt = &t
			}
			if pickedUp.Valid {
				t := pickedUp.Time
				r.PickedUpAt = &t
			}
			if errMsg.Valid && errMsg.String != "" {
				msg := errMsg.String
				r.ErrorMessage = &msg
			}
			out = append(out, r)
		}
		return q.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("read recent automatic scans: %w", err)
	}
	return out, nil
}

// RecordScanned stamps the assets a dispatched job covers.
//
// The stamp goes in `assets.metadata` rather than a new column: the interval
// logic and the page summary are the only readers, the table is partitioned and
// already carries a metadata document for exactly this kind of pipeline state,
// and a column would be a schema change the product definition does not need.
//
// It is written at ENQUEUE time, not on the result. A job that dispatches and
// then fails still means the address was probed, and re-stamping only on
// success would have a permanently-failing host re-queued on every single tick.
func (s *Store) RecordScanned(ctx context.Context, tenantID uuid.UUID, assetIDs []uuid.UUID, jobID string, at time.Time) error {
	if len(assetIDs) == 0 {
		return nil
	}
	stamp, err := json.Marshal(map[string]string{
		"last_auto_scan_at":     at.UTC().Format(time.RFC3339Nano),
		"last_auto_scan_job_id": jobID,
	})
	if err != nil {
		return err
	}
	return database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE assets
			SET metadata = COALESCE(metadata, '{}'::jsonb) || $3::jsonb,
			    updated_at = now()
			WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL`,
			tenantID, pq.Array(assetIDs), stamp)
		return err
	})
}

// StampCompletedScans stamps `asset_endpoints.last_scanned_at` for every
// endpoint an automatic scan actually reached, once the job that reached it has
// completed. It returns how many endpoints it stamped.
//
// The manual Active Scan stamps at DISPATCH (revalidation_service.go): a person
// asked for that scan, and the optimistic stamp is what takes the asset off the
// coverage list they are looking at. An automatic scan stamps at COMPLETION,
// and only where the job wrote a finding for that endpoint — a sweep that
// stamped every target it queued would retire hosts from the manual coverage
// list on the strength of a connect attempt that may never have answered.
//
// Two gates, both the owner's decision:
//   - the asset must be `monitoring`. A `pending_approval` asset's findings are
//     deferred until approval, so "scanned" would overclaim; it stays on the
//     manual coverage list until someone approves it or scans it themselves.
//   - the finding must be for the endpoint's own (address, port). The job's
//     target list says what was attempted; discovery_findings says what
//     answered.
//
// The asset's `last_auto_scan_job_id` (written by RecordScanned) is what ties
// an endpoint to the job that probed it, so only the most recent automatic job
// per asset is ever consulted. Idempotent: an endpoint already stamped at or
// after that job's completion is left alone, so the sweep calls this on every
// pass.
func (s *Store) StampCompletedScans(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var stamped int64
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE asset_endpoints e
			SET last_scanned_at  = j.completed_at,
			    last_scan_status = 'completed',
			    updated_at       = now()
			FROM assets a
			JOIN discovery_jobs j
			  ON j.tenant_id = a.tenant_id
			 AND j.id::text = a.metadata ->> 'last_auto_scan_job_id'
			WHERE e.tenant_id = $1
			  AND a.tenant_id = e.tenant_id AND a.id = e.asset_id
			  AND a.deleted_at IS NULL
			  AND a.asset_status = 'monitoring'
			  AND j.status = 'completed'
			  AND j.completed_at IS NOT NULL
			  AND j.metadata @> $2::jsonb
			  AND e.address IS NOT NULL AND e.port IS NOT NULL
			  AND (e.last_scanned_at IS NULL OR e.last_scanned_at < j.completed_at)
			  AND EXISTS (
			        SELECT 1 FROM discovery_findings f
			        WHERE f.tenant_id = j.tenant_id AND f.job_id = j.id
			          AND f.resolved_ip IS NOT NULL
			          AND host(f.resolved_ip) = host(e.address) AND f.port = e.port)`,
			tenantID, originFilterJSON)
		if err != nil {
			return err
		}
		stamped, err = res.RowsAffected()
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("stamp completed automatic scans: %w", err)
	}
	return int(stamped), nil
}

// ClearUnstartedScanStamps removes the "last automatically scanned" stamp from
// assets whose recorded job failed WITHOUT EVER STARTING. It returns how many
// assets it un-stamped.
//
// [RecordScanned] stamps at enqueue, deliberately: "a job that dispatches and
// then fails still means the address was probed, and re-stamping only on
// success would have a permanently-failing host re-queued on every single
// tick." That reasoning holds for a job that ran and got nothing back — an
// unanswered probe is still a probe.
//
// It does NOT hold when the job never ran at all. A sensor that refuses the
// command ("Unknown command type: discovery_job") or never collects it before
// the command expires leaves every target untouched; cluster-sensor-service
// says so in the job's own error_message, which ends "nothing was scanned".
// The stamp written at enqueue then claims a probe that never happened, and
// the asset is skipped for a full rescan interval on the strength of it. That
// is the exact shape CLAUDE.md warns about: something reporting success while
// doing nothing.
//
// The discriminator is `started_at`, not the message text. A sensor that
// collected the job sets it (sensor-manager's discovery_job_service.go fills
// `started_at = COALESCE(started_at, command.delivered_at)` when the sensor
// reports back), and the platform executor sets it on the `running`
// transition. A job that is `failed` with `started_at IS NULL` is one nothing
// ever began. Reading the structured column rather than grepping the human
// sentence is what keeps this from breaking the next time the wording changes.
//
// Only the job the asset's stamp actually NAMES is consulted
// (`last_auto_scan_job_id`), so a later successful sweep's stamp is never
// undone by an older failure. Idempotent — the sweep calls it on every pass,
// and an asset whose stamp has already been cleared no longer matches.
func (s *Store) ClearUnstartedScanStamps(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var cleared int64
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE assets a
			SET metadata   = a.metadata - 'last_auto_scan_at' - 'last_auto_scan_job_id',
			    updated_at = now()
			FROM discovery_jobs j
			WHERE a.tenant_id = $1
			  AND a.deleted_at IS NULL
			  AND j.tenant_id = a.tenant_id
			  AND j.id::text = a.metadata ->> 'last_auto_scan_job_id'
			  AND j.status = 'failed'
			  AND j.started_at IS NULL
			  AND j.metadata @> $2::jsonb`,
			tenantID, originFilterJSON)
		if err != nil {
			return err
		}
		cleared, err = res.RowsAffected()
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("clear stamps for automatic scans that never started: %w", err)
	}
	return int(cleared), nil
}
