package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
)

// The processing log records what happened to each discovered asset AFTER the
// agent handed its results back — the stage of the pipeline that turns a raw
// result into a discovery finding and a sensor_discovery row.
//
// It exists because that stage used to report only to stdout. When every
// finding insert failed on a NOT NULL violation, the job still reported
// "completed · 12 assets" (a count parsed straight out of the raw results blob)
// while nothing at all reached inventory. Nobody could see that from the UI.
// Persisting the per-asset outcome is what makes "the job succeeded" and "the
// data landed" two separately checkable claims.

// Processing stages, in pipeline order.
const (
	StageDiscoveryTarget  = "discovery_target"
	StageDiscoveryFinding = "discovery_finding"
	StageSensorDiscovery  = "sensor_discovery"
)

// Step outcomes.
const (
	StepOK      = "ok"
	StepFailed  = "failed"
	StepSkipped = "skipped"
)

// ProcessingStep is one (asset, stage) outcome.
type ProcessingStep struct {
	Target string `json:"target"`
	Stage  string `json:"stage"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// ProcessingLog accumulates steps during result processing and renders the
// summary the UI shows. The zero value is ready to use.
type ProcessingLog struct {
	AssetsReceived int
	DiscoveryJobID string
	steps          []ProcessingStep
}

func (p *ProcessingLog) record(target, stage, status, detail string) {
	if p == nil {
		return
	}
	p.steps = append(p.steps, ProcessingStep{Target: target, Stage: stage, Status: status, Detail: detail})
}

func (p *ProcessingLog) ok(target, stage string) { p.record(target, stage, StepOK, "") }

func (p *ProcessingLog) fail(target, stage string, err error) {
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	p.record(target, stage, StepFailed, detail)
}

func (p *ProcessingLog) skip(target, stage, reason string) {
	p.record(target, stage, StepSkipped, reason)
}

// counts returns per-stage ok/failed/skipped tallies.
func (p *ProcessingLog) counts(stage string) (ok, failed, skipped int) {
	for _, s := range p.steps {
		if s.Stage != stage {
			continue
		}
		switch s.Status {
		case StepOK:
			ok++
		case StepFailed:
			failed++
		case StepSkipped:
			skipped++
		}
	}
	return ok, failed, skipped
}

// distinctErrors collapses repeated identical failures into one entry with a
// count. Twelve copies of the same constraint violation is one bug, not twelve.
func (p *ProcessingLog) distinctErrors() []map[string]interface{} {
	type key struct{ stage, detail string }
	seen := map[key]int{}
	for _, s := range p.steps {
		if s.Status != StepFailed {
			continue
		}
		seen[key{s.Stage, s.Detail}]++
	}
	out := make([]map[string]interface{}, 0, len(seen))
	for k, n := range seen {
		out = append(out, map[string]interface{}{
			"stage":   k.stage,
			"message": k.detail,
			"count":   n,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i]["stage"].(string) != out[j]["stage"].(string) {
			return out[i]["stage"].(string) < out[j]["stage"].(string)
		}
		return out[i]["message"].(string) < out[j]["message"].(string)
	})
	return out
}

// Summary is the persisted shape, read back by GET /jobs/{id}/results.
//
// materialized is the honest headline: how many assets actually became a
// discovery finding. It is deliberately NOT the same number as the asset count
// parsed from the raw results, so a pipeline failure can no longer hide behind
// "12 assets discovered".
func (p *ProcessingLog) Summary() map[string]interface{} {
	findingsOK, findingsFailed, _ := p.counts(StageDiscoveryFinding)
	discOK, discFailed, discSkipped := p.counts(StageSensorDiscovery)
	targetsOK, targetsFailed, _ := p.counts(StageDiscoveryTarget)

	return map[string]interface{}{
		"assets_received":        p.AssetsReceived,
		"discovery_job_id":       p.DiscoveryJobID,
		"targets_created":        targetsOK,
		"targets_failed":         targetsFailed,
		"findings_created":       findingsOK,
		"findings_failed":        findingsFailed,
		"discoveries_written":    discOK,
		"discoveries_failed":     discFailed,
		"discoveries_skipped":    discSkipped,
		"materialized":           findingsOK,
		"fully_materialized":     findingsFailed == 0 && discFailed == 0 && targetsFailed == 0,
		"errors":                 p.distinctErrors(),
		"steps":                  p.steps,
		"processing_finished_at": time.Now().UTC().Format(time.RFC3339),
	}
}

// persist merges the summary into device_jobs.results under a "processing" key.
//
// A merge rather than a rewrite: results holds the agent's payload and this adds
// our post-processing verdict beside it. Runs on the bypass handle for the same
// reason the rest of this finalize path does — it is keyed by job id and carries
// no tenant in context.
func (p *ProcessingLog) persist(ctx context.Context, bypassDB *sql.DB, jobID uuid.UUID) error {
	summaryJSON, err := json.Marshal(p.Summary())
	if err != nil {
		return fmt.Errorf("failed to marshal processing summary: %w", err)
	}
	_, err = bypassDB.ExecContext(ctx, `
		UPDATE device_jobs
		SET results = jsonb_set(COALESCE(results, '{}'::jsonb), '{processing}', $1::jsonb, true),
		    updated_at = now()
		WHERE id = $2`, string(summaryJSON), jobID)
	if err != nil {
		return fmt.Errorf("failed to persist processing summary: %w", err)
	}
	return nil
}
