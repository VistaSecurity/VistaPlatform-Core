package services

// The rule-merge executor ( Phase 4, owner decisions D1 + D4).
//
// The identification engine may NOT merge two existing assets inside Resolve
// (guard rail 2). When the same-device rule holds for a conflict it opens the
// proposal as always and stamps it `rule_verdict: same_device`, with the
// evidence. This worker is where that verdict becomes a merge: every 30
// seconds it picks the stamped proposals up, re-evaluates the rule on the
// records as they are NOW, and merges through exactly the audited path a
// person's "Merge" click takes — MergeProposalService.PreviewMerge then
// ExecuteMerge — with no user (`actor_user_id` NULL) and `decided_by: rule` in
// the audit and on the proposal ([DecidedByRule] is the storage contract the
// Approvals "Merged automatically" list reads).
//
// One code path whichever service opened the proposal: device-interrogation's
// controller inventory stamps verdicts too, and they are merged here, where the
// merge service lives.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/identitysettings"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

const (
	// EnvRuleMergeWorkerEnabled is the operator's kill switch for the whole
	// deployment. Unset or anything but "false" means ON — the product default
	// (D1). The TENANT's lever is Settings → Identification rules.
	EnvRuleMergeWorkerEnabled = "IDENTITY_RULE_MERGE_WORKER_ENABLED"

	// RuleMergeInterval is how often the executor looks for verdicts.
	RuleMergeInterval = 30 * time.Second

	// ruleMergeTenantBatch and ruleMergeTickBatch bound one tick: at most this
	// many proposals per tenant, and in all. A backlog drains over several
	// ticks rather than holding merge locks for minutes.
	ruleMergeTenantBatch = 20
	ruleMergeTickBatch   = 100

	// ruleMergeAdvisoryLockKey is the fixed key a tick takes so that, with two
	// replicas, only one executes verdicts at a time. Hand-picked, greppable,
	// and distinct from every other advisory-lock key in the platform
	// (inventory-service's auto-scan sweep uses …_0001).
	ruleMergeAdvisoryLockKey int64 = 0x7641_5343_0000_0002

	// ruleMergeReasonPrefix starts every rule merge's audit reason.
	ruleMergeReasonPrefix = "rule: " + identity.RuleVerdictSameDevice + " — "
)

// ruleMergeTenantFilter, when set, limits which tenants a pass visits. Nil in
// production. It exists for the integration tests alone: they share one
// database with every other package's tests, and an executor started by one
// test must not merge another test's proposals. It is not an option of
// StartRuleMergeExecutor, so the wiring test still drives the exact
// registration production runs.
var ruleMergeTenantFilter atomic.Pointer[func(uuid.UUID) bool]

// errRuleNoLongerHolds is returned by the in-merge re-check when the records
// changed between the executor's look and the merge's locks.
var errRuleNoLongerHolds = errors.New("the same-device rule no longer holds on the current records")

// RuleMergeWorkerEnabled reads the kill switch.
func RuleMergeWorkerEnabled() bool {
	return !strings.EqualFold(strings.TrimSpace(os.Getenv(EnvRuleMergeWorkerEnabled)), "false")
}

// RuleMergeExecutor merges the proposals the same-device rule is sure about.
type RuleMergeExecutor struct {
	db       *database.DB
	bypass   *sql.DB
	merges   *MergeProposalService
	interval time.Duration
}

// NewRuleMergeExecutor builds the executor. `bypass` is the RLS-bypass handle,
// used ONLY to enumerate the tenants that have verdicts waiting (and for the
// cross-replica lock); every read and write about a tenant's records runs on a
// tenant-scoped transaction.
func NewRuleMergeExecutor(db *database.DB, bypass *sql.DB, merges *MergeProposalService) *RuleMergeExecutor {
	return &RuleMergeExecutor{db: db, bypass: bypass, merges: merges, interval: RuleMergeInterval}
}

// StartRuleMergeExecutor is the executor's registration: the one call
// cmd/main.go makes. It reads the kill switch and, unless the operator turned
// the worker off, starts it. Returns the running executor, or nil when off.
//
// A function rather than two lines in main so the wiring test drives exactly
// what production starts (TestIntegration_RuleMergeExecutor_MergesAndAudits),
// and a source guard pins that main still calls it.
func StartRuleMergeExecutor(ctx context.Context, db *database.DB, bypass *sql.DB, merges *MergeProposalService) *RuleMergeExecutor {
	if !RuleMergeWorkerEnabled() {
		log.Printf("[RuleMerge] executor DISABLED (%s=false): same-device verdicts stay pending for a person", EnvRuleMergeWorkerEnabled)
		return nil
	}
	x := NewRuleMergeExecutor(db, bypass, merges)
	go x.Run(ctx)
	log.Printf("[RuleMerge] executor started (every %s)", x.interval)
	return x
}

// Run executes a pass immediately and then every interval until ctx ends.
func (x *RuleMergeExecutor) Run(ctx context.Context) {
	ticker := time.NewTicker(x.interval)
	defer ticker.Stop()
	for {
		if _, err := x.RunOnce(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[RuleMerge] pass: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// RunOnce is one tick: every tenant with a verdict waiting, a bounded batch
// each. It returns how many proposals were merged. A failure on one proposal
// is logged and does not stop the others.
func (x *RuleMergeExecutor) RunOnce(ctx context.Context) (int, error) {
	release, ok, err := x.tryLock(ctx)
	if err != nil {
		return 0, fmt.Errorf("take the rule-merge lock: %w", err)
	}
	if !ok {
		// Another replica is executing verdicts; it will reach these too.
		return 0, nil
	}
	defer release()

	tenants, err := x.tenantsWithVerdicts(ctx)
	if err != nil {
		return 0, err
	}
	merged, budget := 0, ruleMergeTickBatch
	for _, tenant := range tenants {
		if ctx.Err() != nil || budget <= 0 {
			break
		}
		if keep := ruleMergeTenantFilter.Load(); keep != nil && !(*keep)(tenant) {
			continue
		}
		limit := min(ruleMergeTenantBatch, budget)
		n, seen, err := x.ExecuteTenant(ctx, tenant, limit)
		merged += n
		budget -= seen
		if err != nil {
			log.Printf("[RuleMerge] tenant %s: %v", tenant, err)
		}
	}
	return merged, nil
}

// ExecuteTenant handles up to `limit` of one tenant's stamped proposals,
// oldest first. It returns how many it merged and how many it looked at.
func (x *RuleMergeExecutor) ExecuteTenant(ctx context.Context, tenant uuid.UUID, limit int) (merged, seen int, err error) {
	ids, err := x.pendingVerdicts(ctx, tenant, limit)
	if err != nil {
		return 0, 0, err
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			break
		}
		seen++
		ok, err := x.executeProposal(ctx, tenant, id)
		if err != nil {
			log.Printf("[RuleMerge] tenant %s proposal %s: %v", tenant, id, err)
			continue
		}
		if ok {
			merged++
		}
	}
	return merged, seen, nil
}

// ruleMergePlan is what the executor decided to do with one proposal.
type ruleMergePlan struct {
	survivor uuid.UUID
	pair     [2]uuid.UUID
	sources  []uuid.UUID
	evidence []string
}

// executeProposal takes one stamped proposal from verdict to merge — or back to
// an ordinary question for a person. It returns true when it merged.
func (x *RuleMergeExecutor) executeProposal(ctx context.Context, tenant, proposalID uuid.UUID) (bool, error) {
	plan, err := x.plan(ctx, tenant, proposalID)
	if err != nil || plan == nil {
		return false, err
	}
	return x.mergePlanned(ctx, tenant, proposalID, plan)
}

// mergePlanned executes a plan through the audited merge path. The rule is
// re-checked once more inside the merge transaction: the records may have
// changed since the plan was made, and the merge must act on what is true
// under its own locks.
func (x *RuleMergeExecutor) mergePlanned(ctx context.Context, tenant, proposalID uuid.UUID, plan *ruleMergePlan) (bool, error) {
	selection := MergeSelection{SourceAssetIDs: plan.sources, SurvivorAssetID: plan.survivor}
	first, err := x.merges.PreviewMerge(ctx, tenant, proposalID, selection)
	if err != nil {
		return false, x.refused(ctx, tenant, proposalID, err)
	}
	selection.FieldResolutions = ruleFieldResolutions(first, plan.survivor)
	// The revision covers the field resolutions, so the preview the merge is
	// executed against is the one that carries them.
	preview, err := x.merges.PreviewMerge(ctx, tenant, proposalID, selection)
	if err != nil {
		return false, x.refused(ctx, tenant, proposalID, err)
	}

	decision := &ruleMergeDecision{
		recheck: func(ctx context.Context, tx *sqlx.Tx) ([]string, error) {
			repo, err := pgidentity.Bind(x.db.DB.DB, tx.Tx, tenant.String())
			if err != nil {
				return nil, err
			}
			row, ok, err := readRuleProposal(ctx, tx.Tx, tenant, proposalID, false)
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, errRuleNoLongerHolds
			}
			holds, evidence, pair, err := evaluateSameDevice(ctx, tx.Tx, repo, tenant, row)
			if err != nil {
				return nil, err
			}
			if !holds || !samePair(pair, plan.pair) {
				return nil, errRuleNoLongerHolds
			}
			return evidence, nil
		},
	}
	// The reason is the evidence the plan established; the in-merge re-check
	// replaces the evidence the audit and the proposal record with what held
	// under the merge's own locks.
	if _, err := x.merges.ExecuteMerge(ctx, tenant, proposalID, uuid.Nil, MergeExecutionRequest{
		MergeSelection: selection,
		Revision:       preview.Revision,
		Reason:         ruleMergeReason(plan.evidence),
		rule:           decision,
	}); err != nil {
		return false, x.refused(ctx, tenant, proposalID, err)
	}
	return true, nil
}

// plan re-reads the proposal and both records in ONE tenant transaction and
// decides: merge (a plan), or hand the question back to a person (the verdict
// is cleared and nil is returned), or leave it (nil, nil — another replica or
// a person got there first).
func (x *RuleMergeExecutor) plan(ctx context.Context, tenant, proposalID uuid.UUID) (*ruleMergePlan, error) {
	var plan *ruleMergePlan
	err := pgidentity.New(x.db.DB.DB).RunInTx(ctx, tenant.String(), func(repo *pgidentity.Repository) error {
		tx := repo.Tx()
		row, ok, err := readRuleProposal(ctx, tx, tenant, proposalID, true)
		if err != nil || !ok {
			return err
		}

		// The tenant's switch, read now: turning it off stops verdicts that
		// were stamped while it was on, and the proposal becomes the ordinary
		// question it would have been.
		on, err := identitysettings.ReadAutoMergeExisting(ctx, tx, tenant)
		if err != nil {
			return err
		}
		if !on {
			return clearRuleVerdict(ctx, tx, tenant, proposalID, "rule merges are turned off for this tenant")
		}

		holds, evidence, pair, err := evaluateSameDevice(ctx, tx, repo, tenant, row)
		if err != nil {
			return err
		}
		if !holds {
			return clearRuleVerdict(ctx, tx, tenant, proposalID, "the same-device rule no longer holds on the current records")
		}

		survivor, err := chooseRuleSurvivor(ctx, tx, tenant, pair)
		if err != nil {
			return err
		}
		p := &ruleMergePlan{survivor: survivor, pair: pair, evidence: evidence}
		for _, id := range pair {
			if id != survivor {
				p.sources = append(p.sources, id)
			}
		}
		// The asset the linking sighting was created as, when it carried
		// identifiers nobody owned: it is that same sighting, so it goes into
		// the survivor with the other record. Left behind it would keep the
		// proposal open against a pending shard of the device.
		if obs, err := uuid.Parse(row.ObservationAssetID); err == nil && obs != pair[0] && obs != pair[1] {
			live, err := assetIsLive(ctx, tx, tenant, obs)
			if err != nil {
				return err
			}
			if live {
				p.sources = append(p.sources, obs)
			}
		}
		plan = p
		return nil
	})
	return plan, err
}

// refused decides what a failed preview or merge means for the verdict.
//
// A preview that changed under us is a race with ingest or another reviewer:
// leave the verdict, the next tick re-evaluates from scratch. Anything else —
// the rule failing its in-merge re-check, a kept-separate decision, a merge the
// service refuses — hands the question back to a person, so a proposal can
// never be retried forever.
func (x *RuleMergeExecutor) refused(ctx context.Context, tenant, proposalID uuid.UUID, cause error) error {
	if errors.Is(cause, ErrMergePreviewChanged) || errors.Is(cause, ErrMergeProposalChanged) {
		return fmt.Errorf("records changed during the merge; retrying next pass: %w", cause)
	}
	reason := "the merge was refused: " + cause.Error()
	switch {
	case errors.Is(cause, errRuleNoLongerHolds):
		reason = "the same-device rule no longer holds on the current records"
	case errors.Is(cause, ErrMergeKeptSeparate):
		reason = "a reviewer kept these records separate"
	}
	if err := database.WithTenantTx(ctx, x.db, tenant, func(tx *sqlx.Tx) error {
		return clearRuleVerdict(ctx, tx.Tx, tenant, proposalID, reason)
	}); err != nil {
		return errors.Join(cause, err)
	}
	if errors.Is(cause, errRuleNoLongerHolds) || errors.Is(cause, ErrMergeKeptSeparate) {
		return nil
	}
	return fmt.Errorf("verdict handed back to a person: %w", cause)
}

// ruleProposalRow is the stored proposal, as much of it as the rule reads.
type ruleProposalRow struct {
	Source             string                  `json:"-"`
	SourceKind         string                  `json:"source_kind"`
	ObservationAssetID string                  `json:"observation_asset_id"`
	Candidates         []ruleProposalCandidate `json:"candidates"`
}

type ruleProposalCandidate struct {
	AssetID            string                `json:"asset_id"`
	MatchedIdentifiers []identity.Identifier `json:"matched_identifiers"`
}

// ruleVerdictPendingSQL selects a PENDING merge proposal carrying a same-device
// verdict. It repeats idx_asset_history_pending_merge_proposal's predicate so
// the planner can walk that partial index (pending proposals only) instead of
// the whole history.
const ruleVerdictPendingSQL = `action = 'merge_proposed'
	AND changes_json ? 'fingerprint'
	AND COALESCE(changes_json ->> 'status', 'pending') = 'pending'
	AND changes_json ->> 'kind' = 'merge_proposal'
	AND changes_json ->> 'rule_verdict' = '` + identity.RuleVerdictSameDevice + `'`

// readRuleProposal reads a pending, stamped proposal. With `claim` the row is
// locked FOR UPDATE SKIP LOCKED: a proposal another transaction holds is
// skipped (false), not waited for.
func readRuleProposal(ctx context.Context, tx *sql.Tx, tenant, proposalID uuid.UUID, claim bool) (ruleProposalRow, bool, error) {
	q := `SELECT source, changes_json FROM asset_history WHERE tenant_id = $1 AND id = $2 AND ` + ruleVerdictPendingSQL
	if claim {
		q += ` FOR UPDATE SKIP LOCKED`
	}
	var (
		row ruleProposalRow
		raw []byte
	)
	err := tx.QueryRowContext(ctx, q, tenant, proposalID).Scan(&row.Source, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return row, false, nil
	}
	if err != nil {
		return row, false, fmt.Errorf("read the stamped proposal: %w", err)
	}
	if err := json.Unmarshal(raw, &row); err != nil {
		return row, false, fmt.Errorf("decode the stamped proposal: %w", err)
	}
	return row, true, nil
}

// evaluateSameDevice re-evaluates identity.SameDeviceVerdict for a stored
// proposal on the records as they are now:
//
//   - the candidates' summaries are re-read (status, segment, identifiers);
//   - a deleted record is not live;
//   - an identifier the sighting matched to a candidate counts only if that
//     candidate STILL holds it — a MAC that has since moved is no longer a
//     link between these two records;
//   - any `kept_separate` decision about the live pair stops it.
//
// The sighting's directness is not re-derived: a verdict is only ever stamped
// for a direct or authoritative sighting, and what a sighting was does not
// change. It returns the two live records the verdict is about.
func evaluateSameDevice(ctx context.Context, tx *sql.Tx, repo *pgidentity.Repository, tenant uuid.UUID, row ruleProposalRow) (bool, []string, [2]uuid.UUID, error) {
	var pair [2]uuid.UUID
	ids := make([]string, 0, len(row.Candidates))
	for _, c := range row.Candidates {
		ids = append(ids, c.AssetID)
	}
	loaded, err := repo.LoadSummaries(ctx, tenant.String(), ids)
	if err != nil {
		return false, nil, pair, fmt.Errorf("load the candidates: %w", err)
	}
	deleted, err := deletedAssets(ctx, tx, tenant, ids)
	if err != nil {
		return false, nil, pair, err
	}
	summaries := make(map[string]identity.AssetSummary, len(loaded))
	for _, s := range loaded {
		if !deleted[s.Ref.ID] {
			summaries[s.Ref.ID] = s
		}
	}

	candidates := make([]identity.MergeCandidate, 0, len(row.Candidates))
	var live []string
	for _, c := range row.Candidates {
		s, ok := summaries[c.AssetID]
		held := map[string]bool{}
		if ok {
			for _, h := range s.Identifiers {
				held[h.Key()] = true
			}
			if s.Status != identity.StatusArchived && s.Status != identity.StatusDenied {
				live = append(live, c.AssetID)
			}
		}
		var still []identity.Identifier
		for _, m := range c.MatchedIdentifiers {
			n, err := m.Normalized()
			if err != nil {
				continue
			}
			// Normalized keeps the per-observation context the stored
			// evidence carries — the generic mark (condition 8) and a derived
			// identifier's provenance (condition 3 counts a derived MAC and no
			// other derived kind); TestIntegration_RuleMergeExecutor_DerivedMACLinks
			// pins the provenance end to end.
			if held[n.Key()] {
				still = append(still, n)
			}
		}
		candidates = append(candidates, identity.MergeCandidate{
			Ref:                identity.AssetRef{TenantID: tenant.String(), ID: c.AssetID},
			MatchedIdentifiers: still,
		})
	}

	kept := false
	if len(live) >= 2 {
		if d, ok, err := repo.LastKeptSeparate(ctx, tenant.String(), live); err != nil {
			return false, nil, pair, fmt.Errorf("read decision memory: %w", err)
		} else if ok && d.Covers(live) {
			kept = true
		}
	}

	obs := identity.Observation{
		TenantID: tenant.String(),
		Source:   identity.Source{Kind: identity.SourceKind(row.SourceKind), Ref: row.Source},
	}
	holds, evidence := identity.SameDeviceVerdict(obs, candidates, summaries, identity.SameDeviceLink{Direct: true, KeptSeparate: kept})
	if !holds {
		return false, nil, pair, nil
	}
	if len(live) != 2 {
		// SameDeviceVerdict's condition 1 already requires this; restated so
		// the pair below can never be built from anything else.
		return false, nil, pair, nil
	}
	for i, id := range live {
		u, err := uuid.Parse(id)
		if err != nil {
			return false, nil, pair, nil
		}
		pair[i] = u
	}
	return true, evidence, pair, nil
}

func samePair(a, b [2]uuid.UUID) bool {
	return (a[0] == b[0] && a[1] == b[1]) || (a[0] == b[1] && a[1] == b[0])
}

func deletedAssets(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, ids []string) (map[string]bool, error) {
	out := map[string]bool{}
	valid := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, err := uuid.Parse(id); err == nil {
			valid = append(valid, id)
		}
	}
	if len(valid) == 0 {
		return out, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT id::text FROM assets WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND deleted_at IS NOT NULL`, tenant, pq.Array(valid))
	if err != nil {
		return nil, fmt.Errorf("read deleted candidates: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

func assetIsLive(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID) (bool, error) {
	var live bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM assets lc WHERE lc.tenant_id = $1 AND lc.id = $2 AND `+mergeLiveAssetSQL+`)`, tenant, id).Scan(&live)
	if err != nil {
		return false, fmt.Errorf("read the observation asset: %w", err)
	}
	return live, nil
}

// ruleSurvivorFacts is what the survivor choice reads about one record.
type ruleSurvivorFacts struct {
	ID              uuid.UUID
	Status          string
	Declared        bool
	Provisional     bool
	FirstDiscovered sql.NullTime
	IdentifierCount int
}

// chooseRuleSurvivor reads the two records and picks the one the merge keeps.
func chooseRuleSurvivor(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, pair [2]uuid.UUID) (uuid.UUID, error) {
	// "Declared" is how a record a person made is marked on each path that
	// makes one. The Devices form and manual create both resolve through the
	// engine with Source{declared, manual}, which stamps class_source_kind
	// 'declared', metadata.name_source_kind 'declared' and source_kind
	// 'declared' on every identifier — there is no `metadata.source = manual`.
	// An operator-confirmed identity and a declaration_id are the same claim
	// made through identity confirmation.
	rows, err := tx.QueryContext(ctx, `
		SELECT a.id, a.asset_status,
		       (a.class_source_kind = 'declared'
		        OR a.metadata ->> 'name_source_kind' = 'declared'
		        OR a.identity_status = 'operator_confirmed'
		        OR EXISTS (SELECT 1 FROM asset_identifiers i
		                    WHERE i.tenant_id = a.tenant_id AND i.asset_id = a.id
		                      AND (i.source_kind = 'declared' OR i.kind = 'declaration_id'))) AS declared,
		       (a.identity_status = 'provisional') AS provisional,
		       a.first_discovered_at,
		       (SELECT count(*) FROM asset_identifiers i WHERE i.tenant_id = a.tenant_id AND i.asset_id = a.id)
		  FROM assets a
		 WHERE a.tenant_id = $1 AND a.id = ANY($2::uuid[])`,
		tenant, pq.Array([]string{pair[0].String(), pair[1].String()}))
	if err != nil {
		return uuid.Nil, fmt.Errorf("read the records to choose a survivor: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var facts []ruleSurvivorFacts
	for rows.Next() {
		var f ruleSurvivorFacts
		if err := rows.Scan(&f.ID, &f.Status, &f.Declared, &f.Provisional, &f.FirstDiscovered, &f.IdentifierCount); err != nil {
			return uuid.Nil, err
		}
		facts = append(facts, f)
	}
	if err := rows.Err(); err != nil {
		return uuid.Nil, err
	}
	if len(facts) != 2 {
		return uuid.Nil, errRuleNoLongerHolds
	}
	return ruleMergeSurvivor(facts), nil
}

// ruleMergeSurvivor orders two records and returns the one the merge keeps:
//
//  1. a record in service (`monitoring`) over one awaiting approval — the
//     survivor's approval status is what the merged record keeps, and merging
//     an approved device into a pending one would take it out of the
//     inventory on the rule's say-so;
//  2. a record a person made (D4: declared records are the preferred survivor);
//  3. an established identity over a provisional one;
//  4. the one first discovered earlier;
//  5. the one with more identifiers;
//  6. the lower id, so the answer never depends on row order.
//
// Declared FIELD values win whichever record survives: ruleFieldResolutions
// resolves every declared conflict to the declared value (guard rail 5).
func ruleMergeSurvivor(facts []ruleSurvivorFacts) uuid.UUID {
	sorted := append([]ruleSurvivorFacts(nil), facts...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if am, bm := a.Status == identity.StatusMonitoring, b.Status == identity.StatusMonitoring; am != bm {
			return am
		}
		if a.Declared != b.Declared {
			return a.Declared
		}
		if a.Provisional != b.Provisional {
			return !a.Provisional
		}
		switch {
		case a.FirstDiscovered.Valid && !b.FirstDiscovered.Valid:
			return true
		case !a.FirstDiscovered.Valid && b.FirstDiscovered.Valid:
			return false
		case a.FirstDiscovered.Valid && !a.FirstDiscovered.Time.Equal(b.FirstDiscovered.Time):
			return a.FirstDiscovered.Time.Before(b.FirstDiscovered.Time)
		}
		if a.IdentifierCount != b.IdentifierCount {
			return a.IdentifierCount > b.IdentifierCount
		}
		return a.ID.String() < b.ID.String()
	})
	return sorted[0].ID
}

// ruleFieldResolutions answers every conflict the merge preview says needs a
// decision. The survivor's value is kept when it is declared (or when nothing
// competing is); a DECLARED value on another record beats a measured one on the
// survivor — declared values are never overwritten by measured ones (guard
// rail 5, D4).
func ruleFieldResolutions(preview *AssetMergePreview, survivor uuid.UUID) map[string]uuid.UUID {
	out := map[string]uuid.UUID{}
	for _, c := range preview.Conflicts {
		if !c.RequiresResolution {
			continue
		}
		var choice uuid.UUID
		survivorDeclared, survivorHasValue := false, false
		var firstDeclared uuid.UUID
		for _, v := range c.Values {
			if v.AssetID == survivor {
				survivorHasValue = true
				survivorDeclared = v.Declared
			} else if v.Declared && firstDeclared == uuid.Nil {
				firstDeclared = v.AssetID
			}
		}
		switch {
		case survivorHasValue && (survivorDeclared || firstDeclared == uuid.Nil):
			choice = survivor
		case firstDeclared != uuid.Nil:
			choice = firstDeclared
		case len(c.Values) > 0:
			choice = c.Values[0].AssetID
		default:
			choice = survivor
		}
		out[c.Field] = choice
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ruleMergeReason is the audit reason: the rule's name and its evidence,
// within ExecuteMerge's 2000-character limit.
func ruleMergeReason(evidence []string) string {
	reason := ruleMergeReasonPrefix + strings.Join(evidence, "; ")
	if len(evidence) == 0 {
		reason = ruleMergeReasonPrefix + "the same-device rule held"
	}
	const max = 2000
	if len(reason) <= max {
		return reason
	}
	cut := max - len("…")
	for cut > 0 && !utf8.RuneStart(reason[cut]) {
		cut--
	}
	return reason[:cut] + "…"
}

// clearRuleVerdict hands a stamped proposal back to a person: the verdict and
// its evidence are removed, a note says why and when, and the proposal stays
// pending — exactly the ordinary question it would have been without the rule.
func clearRuleVerdict(ctx context.Context, tx *sql.Tx, tenant, proposalID uuid.UUID, reason string) error {
	_, err := tx.ExecContext(ctx, `
		UPDATE asset_history
		   SET changes_json = (changes_json - 'rule_verdict' - 'rule_evidence')
		                      || jsonb_build_object('rule_verdict_cleared', $3::text,
		                                            'rule_verdict_cleared_at', $4::text)
		 WHERE tenant_id = $1 AND id = $2 AND `+ruleVerdictPendingSQL,
		tenant, proposalID, reason, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("clear the rule verdict: %w", err)
	}
	return nil
}

// pendingVerdicts lists one tenant's stamped proposals, oldest first.
func (x *RuleMergeExecutor) pendingVerdicts(ctx context.Context, tenant uuid.UUID, limit int) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	err := database.WithTenantTx(ctx, x.db, tenant, func(tx *sqlx.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT id FROM asset_history
			 WHERE tenant_id = $1 AND `+ruleVerdictPendingSQL+`
			 ORDER BY created_at, seq
			 LIMIT $2`, tenant, limit)
		if err != nil {
			return fmt.Errorf("list stamped proposals: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	return ids, err
}

// tenantsWithVerdicts enumerates, through the bypass handle, the live tenants
// that have a stamped proposal waiting. Cross-tenant enumeration only: nothing
// about any tenant's records is read here.
func (x *RuleMergeExecutor) tenantsWithVerdicts(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := x.bypass.QueryContext(ctx, `
		SELECT DISTINCT h.tenant_id
		  FROM asset_history h
		  JOIN tenants t ON t.id = h.tenant_id
		 WHERE t.deleted_at IS NULL AND `+strings.ReplaceAll(ruleVerdictPendingSQL, "changes_json", "h.changes_json")+`
		 ORDER BY h.tenant_id`)
	if err != nil {
		return nil, fmt.Errorf("enumerate tenants with verdicts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var tenants []uuid.UUID
	for rows.Next() {
		var t uuid.UUID
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		tenants = append(tenants, t)
	}
	return tenants, rows.Err()
}

// tryLock takes the cross-replica session lock on its own connection, or
// reports that another replica holds it. Released on the same connection: a
// session lock belongs to its session.
func (x *RuleMergeExecutor) tryLock(ctx context.Context) (func(), bool, error) {
	if x.bypass == nil {
		return func() {}, true, nil
	}
	conn, err := x.bypass.Conn(ctx)
	if err != nil {
		return nil, false, err
	}
	var got bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, ruleMergeAdvisoryLockKey).Scan(&got); err != nil {
		_ = conn.Close()
		return nil, false, err
	}
	if !got {
		_ = conn.Close()
		return nil, false, nil
	}
	return func() {
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, ruleMergeAdvisoryLockKey)
		_ = conn.Close()
	}, true, nil
}
