package dispatchguard

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// Re-authorization of a PERSON's protocols x ports scan handed to a sensor.
//
// A scan-plan job is re-judged unit by unit when it is dispatched, and an
// automatic or identity-enrichment payload is re-judged by AuthorizeProbe at
// dispatch and again when the sensor collects it. The legacy shape a person
// started (a sensor that cannot run a plan) was judged once, when the job was
// created, and never again: a retry days later, a segment withdrawn or an
// exclusion added in between, were not honoured. This is the check that closes
// that, run at dispatch, at pickup and on a retry.
//
// It judges exactly what the creation-time check judged for a tenant sensor:
// every address a target names must be inside the tenant's registered networks
// or private space and outside every exclusion. A tenant sensor is never handed
// targets outside them (CreateJob refuses to create such a job), so there is no
// consent to look up here.

// IsLegacyManualPayload reports whether p is a person-started protocols x ports
// payload: no scan plan, not an automatic scan and not an identity-enrichment
// probe (those are judged by AuthorizeProbe).
func IsLegacyManualPayload(p sensordispatch.Payload) bool {
	if p.Plan != nil || IsAutomaticScan(p.Options) {
		return false
	}
	_, enrichment := p.Options["identity_enrichment_request_id"]
	return !enrichment
}

// AuthorizeLegacyManualTargets judges every target of a legacy manual payload
// against the tenant's CURRENT scope, inside the caller's transaction, and
// returns the targets that are still authorized and, with reasons, those that
// are not. The caller decides what to do with a partial answer.
//
// A hostname target is judged on the addresses recorded when it was authorized
// (the job's pinned_addresses) — the sensor resolves names on its own network,
// so these are the only addresses the platform ever vouched for. A name with no
// recorded addresses cannot be re-checked and is refused.
func AuthorizeLegacyManualTargets(tx Queryer, payload sensordispatch.Payload, sensor uuid.UUID) (kept []string, refused []RefusedTarget, err error) {
	refuseAll := func(reason string) ([]string, []RefusedTarget, error) {
		out := make([]RefusedTarget, 0, len(payload.Targets))
		for _, t := range payload.Targets {
			out = append(out, RefusedTarget{Target: t, Reason: reason})
		}
		return nil, out, nil
	}
	jobID, perr := uuid.Parse(payload.JobID)
	if _, terr := uuid.Parse(payload.TenantID); perr != nil || terr != nil {
		return refuseAll("the command does not name a valid job and tenant")
	}
	var pinsRaw []byte
	if e := tx.QueryRow(`SELECT COALESCE(metadata->'pinned_addresses','{}'::jsonb) FROM discovery_jobs WHERE id=$1 AND tenant_id=$2`,
		jobID, payload.TenantID).Scan(&pinsRaw); e != nil {
		if errors.Is(e, sql.ErrNoRows) {
			return refuseAll("the job no longer exists")
		}
		return nil, nil, e
	}
	pins := map[string][]string{}
	if e := json.Unmarshal(pinsRaw, &pins); e != nil {
		pins = map[string][]string{}
	}
	scope, err := LoadTargetScope(tx, payload.TenantID)
	if err != nil {
		return nil, nil, err
	}
	// A platform collector carries the cluster's own ranges as exclusions too.
	// An unknown sensor is judged as the stricter of the two.
	var platform bool
	if e := tx.QueryRow(`SELECT `+platformCollectorSQL+` FROM sensors s WHERE s.id=$1`, sensor).Scan(&platform); e != nil {
		if !errors.Is(e, sql.ErrNoRows) {
			return nil, nil, e
		}
		platform = true
	}
	if platform {
		scope = scope.ForPlatformSensor()
	}
	reason := func(e error) string { return strings.TrimPrefix(e.Error(), ErrDenied.Error()+": ") }
	for _, target := range payload.Targets {
		mt, e := ParseManualTarget(target)
		if e != nil {
			refused = append(refused, RefusedTarget{Target: target, Reason: reason(e)})
			continue
		}
		judged := []string{mt.Input}
		if mt.Host != "" {
			if judged = pins[target]; len(judged) == 0 {
				refused = append(refused, RefusedTarget{Target: target, Reason: "the addresses this name was authorized on were not recorded, so it cannot be re-checked"})
				continue
			}
		}
		ok := true
		for _, addr := range judged {
			if e := scope.Authorize(addr); e != nil {
				refused = append(refused, RefusedTarget{Target: target, Reason: reason(e)})
				ok = false
				break
			}
		}
		if ok {
			kept = append(kept, target)
		}
	}
	return kept, refused, nil
}

// Execer is what RecordDroppedTargets writes through; *sql.Tx and *sqlx.Tx
// both satisfy it.
type Execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// RecordDroppedTargets makes a dropped target visible to the person who started
// the scan: its target row reads failed with the reason, and the job carries a
// note naming every target that was not scanned. Run it in the same transaction
// that hands the remaining targets to the sensor, so the note and the command
// cannot disagree.
func RecordDroppedTargets(tx Execer, jobID string, refused []RefusedTarget) error {
	if len(refused) == 0 {
		return nil
	}
	parts := make([]string, 0, len(refused))
	for _, r := range refused {
		if _, err := tx.Exec(`
			UPDATE discovery_targets SET status='failed', error_message=$3, completed_at=NOW(), updated_at=NOW()
			WHERE job_id=$1 AND input=$2 AND status='pending'`, jobID, r.Target, "not scanned: "+r.Reason); err != nil {
			return err
		}
		parts = append(parts, r.Target+" ("+r.Reason+")")
	}
	note := "Not scanned, no longer authorized: " + strings.Join(parts, "; ")
	_, err := tx.Exec(`UPDATE discovery_jobs SET metadata = jsonb_set(COALESCE(metadata,'{}'::jsonb), '{note}', to_jsonb($2::text)) WHERE id=$1`, jobID, note)
	return err
}
