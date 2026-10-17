package services

// Cloud disappearance as a lifecycle event (asset-inventory ADR-0009 D6, DCIM
// BUILD_PLAN row 4.6).
//
// Staleness is otherwise tenant-wide by `last_seen_at`: a terminated instance
// simply stops being re-observed and ages out on the same clock as a laptop
// that went home. For cloud resources the provider's own listing is a much
// sharper instrument, and this sweep reads it:
//
//   - every cloud resource a listing returns carries `cloud.listing` (which
//     listing, `<resource_type>@<region>`) and `cloud.last_enumerated_at`;
//   - the account asset carries `cloud.enumeration_coverage`: when each
//     listing last COMPLETED (device-interrogation-service, cloud_lifecycle.go);
//   - a resource whose listing completed AFTER it was last returned is absent,
//     and moves `monitoring → stale` once it has been absent longer than its
//     class's window: one day for instances, functions and clusters (they come
//     and go by the hour), the tenant's stale policy for buckets, zones, key
//     stores and the rest;
//   - a provider-reported terminal state (`terminated`, `deleting`, a key
//     pending deletion) moves it straight away, with the state as the reason.
//
// What it never does: delete anything, or read a failed or partial listing as
// evidence of absence (such a listing records no coverage). Archive follows the
// existing lifecycle policy. A resource that is listed again is returned to
// active.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/facts"
)

// cloudEphemeralWindow is the absence window for classes that come and go by
// the hour (ADR-0009 D6: "instances and functions: hours-to-a-day").
const cloudEphemeralWindow = 24 * time.Hour

// cloudEphemeralClasses are the classes on the short clock.
var cloudEphemeralClasses = map[string]bool{
	"compute_instance":    true,
	"serverless_function": true,
	"container_cluster":   true,
}

// cloudTerminalStates are the provider states that mean "this resource is
// going or gone" (normalised: lower case, cloud_lifecycle.go in
// device-interrogation-service). GCP's TERMINATED is recorded as `stopped`
// there and so is not here.
var cloudTerminalStates = map[string]bool{
	"terminated":       true,
	"shutting-down":    true,
	"deleting":         true,
	"deleted":          true,
	"pending_deletion": true,
}

// CloudStaleWindow is the absence window for a class: one day for the
// ephemeral classes, the tenant's stale-warning days otherwise.
func CloudStaleWindow(classKey string, staleWarningDays int) time.Duration {
	if cloudEphemeralClasses[classKey] {
		return cloudEphemeralWindow
	}
	if staleWarningDays <= 0 {
		staleWarningDays = 30
	}
	return time.Duration(staleWarningDays) * 24 * time.Hour
}

// cloudLifecycleRow is one cloud resource's lifecycle evidence.
type cloudLifecycleRow struct {
	ID          uuid.UUID
	ClassKey    string
	StaleStatus string
	Listing     string
	LastListed  time.Time
	State       string
	Coverage    map[string]time.Time
}

// CloudLifecycleVerdict is what the sweep decided for one resource.
type CloudLifecycleVerdict struct {
	AssetID uuid.UUID `json:"asset_id"`
	// Action is "stale" or "restored".
	Action string `json:"action"`
	Reason string `json:"reason"`
}

// decideCloudLifecycle is the rule, pure: given one resource's evidence, the
// class window and the clock, stale it, restore it, or leave it.
func decideCloudLifecycle(r cloudLifecycleRow, window time.Duration, now time.Time) (CloudLifecycleVerdict, bool) {
	v := CloudLifecycleVerdict{AssetID: r.ID}
	stale := r.StaleStatus == "stale"
	if cloudTerminalStates[r.State] {
		if stale {
			return v, false
		}
		v.Action, v.Reason = "stale", "provider_state:"+r.State
		return v, true
	}
	covered, ok := r.Coverage[r.Listing]
	if !ok || r.LastListed.IsZero() {
		// The listing never completed: nothing is known about absence.
		return v, false
	}
	absent := covered.After(r.LastListed)
	switch {
	case absent && !stale && now.Sub(r.LastListed) >= window:
		v.Action, v.Reason = "stale", "absent_from_listing:"+r.Listing
		return v, true
	case !absent && stale:
		v.Action, v.Reason = "restored", "listed_again:"+r.Listing
		return v, true
	}
	return v, false
}

// cloudLifecycleBatch caps one sweep, like staleDetectionBatch.
const cloudLifecycleBatch = 5000

// SweepCloudDisappearance applies the D6 rule to one tenant's cloud
// resources and returns what it changed.
func (s *AssetLifecycleService) SweepCloudDisappearance(ctx context.Context, tenantID uuid.UUID, now time.Time) ([]CloudLifecycleVerdict, error) {
	policy, err := s.GetLifecyclePolicy(tenantID)
	if err != nil {
		return nil, err
	}
	var out []CloudLifecycleVerdict
	err = database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := loadCloudLifecycleRows(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		var staleIDs, restoredIDs []uuid.UUID
		for _, r := range rows {
			v, act := decideCloudLifecycle(r, CloudStaleWindow(r.ClassKey, policy.StaleWarningDays), now)
			if !act {
				continue
			}
			out = append(out, v)
			if v.Action == "stale" {
				staleIDs = append(staleIDs, v.AssetID)
			} else {
				restoredIDs = append(restoredIDs, v.AssetID)
			}
		}
		if len(staleIDs) > 0 {
			if _, err := tx.ExecContext(ctx, `UPDATE assets SET stale_status = 'stale', updated_at = NOW()
				WHERE tenant_id = $1 AND id = ANY($2)`, tenantID, pq.Array(staleIDs)); err != nil {
				return fmt.Errorf("mark cloud resources stale: %w", err)
			}
		}
		if len(restoredIDs) > 0 {
			if _, err := tx.ExecContext(ctx, `UPDATE assets SET stale_status = NULL, updated_at = NOW()
				WHERE tenant_id = $1 AND id = ANY($2) AND stale_status = 'stale'`, tenantID, pq.Array(restoredIDs)); err != nil {
				return fmt.Errorf("restore re-listed cloud resources: %w", err)
			}
		}
		// The reason is the point (ADR-0009 D6: "provider terminal states
		// recorded as the reason"), so it goes on the asset's timeline in the
		// same transaction as the move.
		for _, v := range out {
			status := any("stale")
			if v.Action == "restored" {
				status = nil
			}
			changes, _ := json.Marshal(map[string]any{"stale_status": status, "reason": v.Reason, "source_kind": "measured"})
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO asset_history (asset_id, tenant_id, source, action, changes_json)
				VALUES ($1, $2, 'lifecycle', 'updated', $3::jsonb)`, v.AssetID, tenantID, string(changes)); err != nil {
				return fmt.Errorf("record cloud lifecycle history: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// loadCloudLifecycleRows reads every monitored cloud resource that carries
// listing evidence, with its account's coverage (through the `hosted_on` edge
// to the account asset).
func loadCloudLifecycleRows(ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID) ([]cloudLifecycleRow, error) {
	q, err := tx.QueryContext(ctx, `
		SELECT a.id, a.class_key, COALESCE(a.stale_status, ''),
		       lst.value, enum.value, st.value, cov.value
		  FROM assets a
		  JOIN LATERAL (SELECT f.value FROM asset_facts f
		                 WHERE f.tenant_id = a.tenant_id AND f.asset_id = a.id AND f.key = $2
		                 ORDER BY f.observed_at DESC LIMIT 1) lst ON true
		  JOIN LATERAL (SELECT f.value FROM asset_facts f
		                 WHERE f.tenant_id = a.tenant_id AND f.asset_id = a.id AND f.key = $3
		                 ORDER BY f.observed_at DESC LIMIT 1) enum ON true
		  LEFT JOIN LATERAL (SELECT f.value FROM asset_facts f
		                 WHERE f.tenant_id = a.tenant_id AND f.asset_id = a.id AND f.key = $4
		                 ORDER BY f.observed_at DESC LIMIT 1) st ON true
		  LEFT JOIN LATERAL (SELECT f.value FROM asset_relationships r
		                       JOIN asset_facts f ON f.tenant_id = r.tenant_id AND f.asset_id = r.to_asset_id AND f.key = $5
		                      WHERE r.tenant_id = a.tenant_id AND r.from_asset_id = a.id AND r.type = 'hosted_on'
		                        AND r.status <> 'rejected'
		                      ORDER BY f.observed_at DESC LIMIT 1) cov ON true
		 WHERE a.tenant_id = $1
		   AND a.deleted_at IS NULL
		   AND a.asset_status = 'monitoring'
		   AND a.class_path LIKE 'cloud_resource.%'
		   AND COALESCE(a.stale_status, '') IN ('', 'active', 'stale')
		 ORDER BY a.id
		 LIMIT `+fmt.Sprint(cloudLifecycleBatch),
		tenantID, facts.KeyCloudListing, facts.KeyCloudLastEnumeratedAt, facts.KeyCloudProviderState, facts.KeyCloudEnumerationCoverage)
	if err != nil {
		return nil, fmt.Errorf("read cloud lifecycle evidence: %w", err)
	}
	defer func() { _ = q.Close() }()
	var out []cloudLifecycleRow
	for q.Next() {
		var (
			r               cloudLifecycleRow
			listing, last   []byte
			state, coverage []byte
		)
		if err := q.Scan(&r.ID, &r.ClassKey, &r.StaleStatus, &listing, &last, &state, &coverage); err != nil {
			return nil, err
		}
		r.Listing = jsonString(listing)
		r.LastListed = parseFactTime(jsonString(last))
		r.State = strings.ToLower(jsonString(state))
		r.Coverage = map[string]time.Time{}
		var cov map[string]string
		if len(coverage) > 0 && json.Unmarshal(coverage, &cov) == nil {
			for k, v := range cov {
				if t := parseFactTime(v); !t.IsZero() {
					r.Coverage[k] = t
				}
			}
		}
		out = append(out, r)
	}
	return out, q.Err()
}

func jsonString(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

func parseFactTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
