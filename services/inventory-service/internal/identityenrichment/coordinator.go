package identityenrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/google/uuid"
)

type Coordinator struct {
	Store    *Store
	Backend  Backend
	Enabled  bool
	Excluded []netip.Prefix
	Now      func() time.Time
}

// Sweep never holds a data transaction while talking to a collector. The job
// lease handles competing workers; durable request IDs handle process crashes.
func (c *Coordinator) Sweep(ctx context.Context, tenant uuid.UUID) error {
	if !c.Enabled {
		return nil
	}
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now()
	}
	policy, err := c.Store.Policy(ctx, tenant)
	if err != nil {
		return err
	}
	// D5. Materialization runs on ADMISSION mode alone, before and
	// independently of enrichment: it re-reads evidence the platform already
	// holds under a rule that changed after that evidence was stored, and
	// nothing about it touches the tenant's network. `paused` and `disabled`
	// still create nothing — a paused tenant has asked for exactly that.
	if policy.AdmissionMode == "enforce" {
		if err := c.materialize(ctx, tenant, now); err != nil {
			return err
		}
	}
	if !policy.Active() {
		return nil
	}
	observations, err := c.Store.Candidates(ctx, tenant, now)
	if err != nil {
		return err
	}
	for _, o := range observations {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Re-read policy before each observation; pausing leaves all evidence and
		// queued work intact and never falls back to permissive asset creation.
		policy, err = c.Store.Policy(ctx, tenant)
		if err != nil {
			return err
		}
		if !policy.Active() {
			return nil
		}
		if err := c.enrich(ctx, tenant, o, policy, now); err != nil {
			return err
		}
	}
	return nil
}

// materialize re-resolves one bounded batch of retained observations that never
// produced an asset ( D5).
//
// Bounded and restartable rather than a one-off backfill script: the rule that
// decides whether an observation becomes a provisional item depends on tenant
// state that keeps moving (segments are drawn, overlaps are resolved), so
// "re-read them once at deploy" would fix the rows that happened to be ready
// that minute and leave the rest retained for ever. Running it every sweep
// costs one indexed read per tenant per minute when there is nothing to do.
func (c *Coordinator) materialize(ctx context.Context, tenant uuid.UUID, now time.Time) error {
	candidates, err := c.Store.MaterializationCandidates(ctx, tenant, now)
	if err != nil {
		return err
	}
	for _, o := range candidates {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := c.Backend.Materialize(ctx, tenant, o); err != nil {
			return err
		}
	}
	return nil
}

func (c *Coordinator) enrich(ctx context.Context, tenant uuid.UUID, o Observation, p Policy, now time.Time) error {
	o.Cycle = strconv.FormatInt(now.Unix()/int64(time.Duration(p.Scan.RescanIntervalHours)*time.Hour/time.Second), 10)
	source, err := c.Store.Ensure(ctx, tenant, o, Plan{Action: "configured_source", Executor: "configured_sources"}, now)
	if err != nil {
		return err
	}
	// A source request may finish after the next scheduled window starts.
	// Its downstream work stays in that source's cohort rather than claiming
	// that the new cycle completed a source stage it never ran.
	o.Cycle = source.Plan.Cycle
	source, err = c.advance(ctx, source, o, now)
	if err != nil {
		return err
	}
	if source.State != "completed" {
		return nil
	}
	currentPolicy, err := c.Store.Policy(ctx, tenant)
	if err != nil {
		return err
	}
	if !currentPolicy.Active() {
		return nil
	}
	p = currentPolicy
	if err := c.Backend.Reevaluate(ctx, tenant, o); err != nil {
		return err
	}
	// Re-read the observation after source results have traversed normal intake;
	// a new established link or conflict supersedes a queued weak-name question.
	current, err := c.Store.Observation(ctx, tenant, o.ID)
	if err != nil {
		return err
	}
	current.Cycle = o.Cycle
	o = current
	if o.State == "conflict" || o.State == "dismissed" || o.State == "expired" {
		return nil
	}
	if o.State == "linked" {
		return c.Store.Summary(ctx, tenant, o.ID, "completed", "evidence_linked_existing_asset_enrichment_applies", now, now.Add(time.Duration(p.Scan.RescanIntervalHours)*time.Hour))
	}
	scope, excluded, err := c.Store.Scope(ctx, tenant, o, now)
	if err != nil {
		return err
	}
	excluded = append(excluded, c.Excluded...)
	plan, reason := NetworkPlan(o, p, scope, nil, excluded)
	if reason != "" {
		return c.Store.Summary(ctx, tenant, o.ID, "blocked", reason, now, now.Add(15*time.Minute))
	}
	if plan.Action == "dns" {
		dns, err := c.Store.Ensure(ctx, tenant, o, plan, now)
		if err != nil {
			return err
		}
		dns, err = c.advance(ctx, dns, o, now)
		if err != nil {
			return err
		}
		if dns.State != "completed" {
			return nil
		}
		var result struct {
			Addresses []string `json:"addresses"`
		}
		if err := json.Unmarshal(dns.Result, &result); err != nil {
			return fmt.Errorf("invalid retained DNS result: %w", err)
		}
		plan, reason = NetworkPlan(o, p, scope, result.Addresses, excluded)
		if reason != "" || plan.Action != "probe" {
			return c.Store.Summary(ctx, tenant, o.ID, "completed", "dns_did_not_provide_authorized_address", now, now.Add(time.Duration(p.Scan.RescanIntervalHours)*time.Hour))
		}
	}
	job, err := c.Store.Ensure(ctx, tenant, o, plan, now)
	if err != nil {
		return err
	}
	job, err = c.advance(ctx, job, o, now)
	if err != nil {
		return err
	}
	if job.State == "completed" {
		if err := c.Backend.Reevaluate(ctx, tenant, o); err != nil {
			return err
		}
		return c.Store.Summary(ctx, tenant, o.ID, "completed", "authorized_probe_completed_identity_requires_corroboration", now, now.Add(time.Duration(p.Scan.RescanIntervalHours)*time.Hour))
	}
	return nil
}

func (c *Coordinator) advance(ctx context.Context, j Job, o Observation, now time.Time) (Job, error) {
	if j.State == "completed" {
		return j, nil
	}
	claimed, lease, ok, err := c.Store.Claim(ctx, j, now)
	if err != nil || !ok {
		return j, err
	}
	j = claimed
	policy, err := c.Store.Policy(ctx, j.TenantID)
	var result Result
	if err != nil {
		result = Result{State: "failed", Reason: "policy_read_failed", RemoteID: j.RemoteID}
	} else if !policy.Active() {
		result = Result{State: "waiting", Reason: "admission_or_enrichment_paused", RemoteID: j.RemoteID}
	} else if j.RemoteID != "" {
		result, err = c.Backend.Poll(ctx, j, o)
	} else {
		if j.Plan.Action != "configured_source" {
			scope, exclusions, scopeErr := c.Store.Scope(ctx, j.TenantID, o, now)
			if scopeErr != nil {
				err = scopeErr
			} else {
				authorized, reason := NetworkPlan(o, policy, scope, j.Plan.Addresses, append(exclusions, c.Excluded...))
				authorized.Cycle = j.Plan.Cycle
				expected, _ := json.Marshal(j.Plan)
				actual, _ := json.Marshal(authorized)
				if reason != "" || string(actual) != string(expected) {
					result = Result{State: "blocked", Reason: "authorization_changed_before_dispatch"}
				} else {
					result, err = c.Backend.Dispatch(ctx, j, o)
				}
			}
		} else {
			result, err = c.Backend.Dispatch(ctx, j, o)
		}
	}
	if err != nil {
		result = Result{State: "failed", Reason: "retryable_dispatch_or_result_failure", RemoteID: j.RemoteID}
	}
	if finishErr := c.Store.Finish(ctx, j, lease, result, now); finishErr != nil {
		return j, finishErr
	}
	j.State = result.State
	j.Reason = result.Reason
	j.RemoteID = result.RemoteID
	j.Result = result.Data
	return j, nil
}
