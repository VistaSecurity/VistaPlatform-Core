// Package services: merge proposals — the Approvals surface for ADR-0002 D3's
// third outcome.
package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// A merge proposal is an `asset_history` row, not a table.
//
// The identification engine writes it with action `merge_proposed` and
// `changes_json.kind = "merge_proposal"` (see shared/identity/postgres). There
// is no proposals table in phase 1 and inventing one here would be a second
// home for a decision the history already records — the proposal, its outcome,
// and the merge itself are all entries in the same timeline, which is what a
// reviewer six months later actually needs to read.
//
// Two things a proposal is NOT:
//
//   - It is not an auto-merge. The engine never merges on its own; even an
//     auto-ACCEPTED proposal (a matcher scored the top candidate above the
//     tenant's threshold) still leaves the remaining candidates for a human.
//   - It is not the ordinary approval queue. Accepting a proposal merges two
//     assets; keeping them separate leaves the observation asset exactly where
//     it was, still pending ordinary approval. Deciding the proposal is not
//     deciding the asset.

// MergeProposalStatus values stored in changes_json.status.
const (
	mergeStatusPending      = "pending"
	mergeStatusMerged       = "merged"
	mergeStatusKeptSeparate = "kept_separate"
)

// MergeCandidateView is one candidate, decorated for display.
type MergeCandidateView struct {
	AssetID     uuid.UUID `json:"asset_id"`
	DisplayName string    `json:"display_name,omitempty"`
	Hostname    *string   `json:"hostname,omitempty"`
	ClassKey    string    `json:"class_key,omitempty"`
	ClassLabel  string    `json:"class_label,omitempty"`
	AssetStatus string    `json:"asset_status,omitempty"`
	// Deleted marks a candidate the reviewer can no longer merge into: it was
	// soft-deleted, or merged away by an earlier proposal. Shown rather than
	// dropped, because a proposal that silently loses a candidate reads as if
	// it only ever had one.
	Deleted bool `json:"deleted"`
	// MatchedIdentifiers is the EVIDENCE — the observation's identifiers that
	// resolved to this asset. A proposal listing candidates with no reason can
	// only be rubber-stamped.
	MatchedIdentifiers []map[string]any `json:"matched_identifiers"`
	Score              float64          `json:"score"`
	Reason             string           `json:"reason,omitempty"`
	// Explanation is the score's working: the signals that moved it, strongest
	// first. A score with no working can only be rubber-stamped, which is the
	// same failure as a candidate with no matched identifiers — so the two
	// travel together.
	Explanation []MergeScoreFactor `json:"explanation,omitempty"`
}

// MergeScoreFactor is one signal behind a candidate's score.
//
// It names a COMPARISON, never a value: "a one-per-asset identifier matches" is
// the evidence, and the serial itself is on `matched_identifiers` where the
// reviewer is already looking at it under the tenant's own access control.
type MergeScoreFactor struct {
	Feature      string  `json:"feature"`
	Label        string  `json:"label"`
	Value        float64 `json:"value"`
	Weight       float64 `json:"weight"`
	Contribution float64 `json:"contribution"`
}

// MergeProposalView is one pending proposal as the Approvals queue shows it.
type MergeProposalView struct {
	ID                 uuid.UUID            `json:"id"`
	TenantID           uuid.UUID            `json:"tenant_id"`
	Status             string               `json:"status"`
	Reason             string               `json:"reason,omitempty"`
	Source             string               `json:"source"`
	SourceKind         string               `json:"source_kind,omitempty"`
	ProposedAt         time.Time            `json:"proposed_at"`
	ObservationAssetID *uuid.UUID           `json:"observation_asset_id,omitempty"`
	Observation        *MergeCandidateView  `json:"observation,omitempty"`
	Candidates         []MergeCandidateView `json:"candidates"`
	// ModelID and SourceRef name the matcher that RANKED the candidates,
	// whether or not it accepted anything. Empty when nothing scored them.
	ModelID           string     `json:"model_id,omitempty"`
	SourceRef         string     `json:"source_ref,omitempty"`
	AutoAccepted      bool       `json:"auto_accepted,omitempty"`
	AcceptedAssetID   *uuid.UUID `json:"accepted_asset_id,omitempty"`
	AcceptedScore     float64    `json:"accepted_score,omitempty"`
	AcceptedModelID   string     `json:"accepted_model_id,omitempty"`
	AcceptedSourceRef string     `json:"accepted_source_ref,omitempty"`
	// ResolvedAt and ResolvedBy are stamped when a human decides the proposal.
	// On an auto-accepted row they stay empty until somebody settles the
	// REMAINING candidates, which is what makes "merged by the matcher, not yet
	// reviewed" a state the Approvals page can show.
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
	ResolvedBy string     `json:"resolved_by,omitempty"`
}

// ErrMergeProposalNotFound is returned for an id that names no pending proposal
// in this tenant.
var ErrMergeProposalNotFound = errors.New("merge proposal not found")

// ErrMergeProposalResolved is returned when a proposal has already been decided.
// It is distinct from not-found so a second click on a stale page can say what
// happened rather than claiming the row never existed.
var ErrMergeProposalResolved = errors.New("merge proposal has already been decided")

// ErrMergeCandidateNotInProposal is returned when the chosen survivor is not one
// of the proposal's candidates. Accepting an arbitrary asset id would let the
// API merge two assets a reviewer never saw compared.
var ErrMergeCandidateNotInProposal = errors.New("the chosen asset is not a candidate of this proposal")

// ErrMergeObservationMissing means the proposal has no source record to merge.
var ErrMergeObservationMissing = errors.New("this proposal has no observation asset to merge")

// ErrMergeSurvivorArchived is returned when the chosen survivor is archived or
// soft-deleted — most often because an EARLIER proposal already merged it away.
// Merging into a tombstone buries the observation behind a pointer to somewhere
// else.
var ErrMergeSurvivorArchived = errors.New("the chosen survivor is archived; pick a live candidate")

var ErrMergeProposalChanged = errors.New("merge candidates changed; refresh the proposal")

// MergeProposalService reads and decides merge proposals.
type MergeProposalService struct {
	db     *database.DB
	events *EventPublisherService
}

// NewMergeProposalService constructs the service.
func NewMergeProposalService(db *database.DB) *MergeProposalService {
	return &MergeProposalService{db: db}
}

// SetEventPublisher wires the lifecycle publisher, so an accepted merge emits
// `inventory.lifecycle.asset.merged`. Optional: without it the merge still
// happens and is still recorded in history — a downstream cache just learns
// about it on its next read instead of immediately.
func (s *MergeProposalService) SetEventPublisher(p *EventPublisherService) {
	s.events = p
}

// MergeProposalPageSize is the default page of pending proposals, and
// MergeProposalMaxPageSize the ceiling a caller may ask for. The ceiling is the
// whole reason `total` exists: a page that stops at 200 and a caller that reads
// `len(proposals)` as the count would report "200 awaiting review" on a tenant
// with a thousand, which is the failure C6 names.
const (
	MergeProposalPageSize    = 50
	MergeProposalMaxPageSize = 200
)

// ListPending returns one page of the pending merge proposals for a tenant,
// newest first, with every candidate decorated with its display name and class,
// and the TOTAL number of pending proposals the page was cut from.
//
// The total is counted over the same predicate in the same transaction, so a
// page and its count can never describe two different worlds.
//
// Three reads, not N+1: one COUNT, one over asset_history for the proposals,
// one over `assets` for every candidate id any of them names. A proposal has
// two or three candidates and a page has fifty proposals, so the per-candidate
// form would be a hundred and fifty round trips for one screen.
func (s *MergeProposalService) ListPending(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]MergeProposalView, int, error) {
	limit, offset = ClampMergeProposalPage(limit, offset)
	var (
		views []MergeProposalView
		total int
	)
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		if err := tx.QueryRowContext(ctx, `
			SELECT count(*)
			FROM asset_history
			WHERE tenant_id = $1
			  AND action = $2
			  AND changes_json->>'kind' = 'merge_proposal'
			  AND COALESCE(changes_json->>'status', 'pending') = 'pending'`,
			tenantID, string(identity.ActionMergeProposed)).Scan(&total); err != nil {
			return fmt.Errorf("count merge proposals: %w", err)
		}
		rows, err := tx.QueryContext(ctx, `
			SELECT id, asset_id, source, changes_json::text, created_at
			FROM asset_history
			WHERE tenant_id = $1
			  AND action = $2
			  AND changes_json->>'kind' = 'merge_proposal'
			  AND COALESCE(changes_json->>'status', 'pending') = 'pending'
			ORDER BY created_at DESC, seq DESC
			LIMIT $3 OFFSET $4`,
			tenantID, string(identity.ActionMergeProposed), limit, offset)
		if err != nil {
			return fmt.Errorf("query merge proposals: %w", err)
		}
		defer func() { _ = rows.Close() }()

		var ids []uuid.UUID
		for rows.Next() {
			v, candidateIDs, e := scanMergeProposal(rows, tenantID)
			if e != nil {
				return e
			}
			views = append(views, *v)
			ids = append(ids, candidateIDs...)
			// The observation asset is decorated too — it is the left-hand card
			// of the comparison, and a reviewer choosing between two things has
			// to be able to read both of them.
			if v.ObservationAssetID != nil {
				ids = append(ids, *v.ObservationAssetID)
			}
			if v.AcceptedAssetID != nil {
				ids = append(ids, *v.AcceptedAssetID)
			}
		}
		if e := rows.Err(); e != nil {
			return e
		}
		_ = rows.Close()

		decor, e := loadMergeDecorations(ctx, tx, tenantID, ids)
		if e != nil {
			return e
		}
		for i := range views {
			decorateMergeProposal(&views[i], decor)
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	if views == nil {
		views = []MergeProposalView{}
	}
	return views, total, nil
}

// AutoAcceptedWindowDays is how far back [MergeProposalService.ListAutoAccepted]
// looks: thirty days.
//
// Long enough that a tenant who checks monthly sees everything the matcher did;
// short enough that the list stays a REVIEW and not an archive. The full record
// is in `asset_history` either way — this is the surface that makes a merge
// nobody approved visible to somebody, which is the reachability half of
// workstream 4.6.
const AutoAcceptedWindowDays = 30

// ListAutoAccepted returns the merges the MATCHER made on the tenant's behalf
// in the last [AutoAcceptedWindowDays] days, newest first.
//
// # Why this exists at all
//
// A tenant who sets an auto-accept threshold above zero is telling the platform
// it may merge two assets without asking. That is a real capability and the one
// thing on the identification path with no human in it — so it must be VISIBLE
// to a human afterwards, on the page where they already review identity
// decisions, with the score and the model's reasons beside it. A capability
// that acts unasked and reports nowhere is indistinguishable from a bug.
//
// It reads the SAME rows ListPending reads — an auto-accepted proposal is an
// `asset_history` row like any other — filtered on `auto_accepted` rather than
// on status, because an auto-accepted proposal is still pending as far as its
// REMAINING candidates are concerned. Both a pending and a resolved one are
// included: the question this list answers is "what did the matcher do", and a
// reviewer having since decided the leftovers does not unmake the merge.
func (s *MergeProposalService) ListAutoAccepted(ctx context.Context, tenantID uuid.UUID, limit int) ([]MergeProposalView, error) {
	if limit <= 0 || limit > MergeProposalMaxPageSize {
		limit = MergeProposalPageSize
	}
	var views []MergeProposalView
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT id, asset_id, source, changes_json::text, created_at
			FROM asset_history
			WHERE tenant_id = $1
			  AND action = $2
			  AND changes_json->>'kind' = 'merge_proposal'
			  AND (changes_json->>'auto_accepted')::boolean IS TRUE
			  AND created_at >= now() - make_interval(days => $3)
			ORDER BY created_at DESC, seq DESC
			LIMIT $4`,
			tenantID, string(identity.ActionMergeProposed), AutoAcceptedWindowDays, limit)
		if err != nil {
			return fmt.Errorf("query auto-accepted merges: %w", err)
		}
		defer func() { _ = rows.Close() }()

		var ids []uuid.UUID
		for rows.Next() {
			v, candidateIDs, e := scanMergeProposal(rows, tenantID)
			if e != nil {
				return e
			}
			views = append(views, *v)
			ids = append(ids, candidateIDs...)
			if v.AcceptedAssetID != nil {
				ids = append(ids, *v.AcceptedAssetID)
			}
			if v.ObservationAssetID != nil {
				ids = append(ids, *v.ObservationAssetID)
			}
		}
		if e := rows.Err(); e != nil {
			return e
		}
		_ = rows.Close()

		decor, e := loadMergeDecorations(ctx, tx, tenantID, ids)
		if e != nil {
			return e
		}
		for i := range views {
			decorateMergeProposal(&views[i], decor)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if views == nil {
		views = []MergeProposalView{}
	}
	return views, nil
}

// ClampMergeProposalPage normalises a caller's page request. It is exported so
// the handler can echo the page the server actually used rather than the one
// the caller asked for.
//
// A limit outside (0, MergeProposalMaxPageSize] falls back to the default
// rather than 400ing: the parameter is a convenience on a read, and a caller
// asking for a thousand wants "as many as you'll give me", not an error. A
// negative offset is zero — there is nothing before the first row.
func ClampMergeProposalPage(limit, offset int) (int, int) {
	if limit <= 0 || limit > MergeProposalMaxPageSize {
		limit = MergeProposalPageSize
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// Accept merges the proposal into `survivorID`.
//
// Everything that belongs to the observation asset moves to the survivor —
// endpoints, identifiers, crypto configurations, facts, software installs,
// relationships (both directions), and the observation's own history, so the
// merged asset's timeline includes what happened before the merge rather than
// starting at it. The observation asset is then ARCHIVED, not
// deleted: a foreign key elsewhere may still name it, and a dangling reference
// that resolves to "merged into X" is a better answer than one that 404s.
//
// Two history entries are written, one on each side: `merged_into` on the
// observation and `merged_from` on the survivor. Recording it only on the
// survivor would leave the observation's timeline ending mid-sentence.
//
// All of it is ONE transaction. A merge that moved the endpoints and then
// failed before archiving the source would leave two assets both claiming the
// same sockets, with no way to tell which was the survivor.
func (s *MergeProposalService) Accept(ctx context.Context, tenantID, proposalID, survivorID, actorUserID uuid.UUID) (*MergeProposalView, error) {
	var view *MergeProposalView
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		var candidates []uuid.UUID
		var err error
		view, candidates, err = readProposal(ctx, tx, tenantID, proposalID, false)
		if err != nil {
			return err
		}
		if view.ObservationAssetID == nil {
			return ErrMergeObservationMissing
		}
		found := false
		for _, candidate := range candidates {
			if candidate == survivorID {
				found = true
			}
		}
		if !found || *view.ObservationAssetID == survivorID {
			return ErrMergeCandidateNotInProposal
		}
		for _, id := range []uuid.UUID{*view.ObservationAssetID, survivorID} {
			var live bool
			if err := tx.QueryRowContext(ctx, `SELECT asset_status<>'archived' AND deleted_at IS NULL AND NULLIF(metadata->>'merged_into','') IS NULL FROM assets WHERE tenant_id=$1 AND id=$2`, tenantID, id).Scan(&live); err != nil {
				return err
			}
			if !live {
				if id == survivorID {
					return ErrMergeSurvivorArchived
				}
				return ErrMergeProposalChanged
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	selection := MergeSelection{SourceAssetIDs: []uuid.UUID{*view.ObservationAssetID}, SurvivorAssetID: survivorID}
	preview, err := s.PreviewMerge(ctx, tenantID, proposalID, selection)
	if err != nil {
		if errors.Is(err, ErrMergePreviewChanged) {
			return nil, ErrMergeProposalChanged
		}
		return nil, err
	}
	if _, err := s.ExecuteMerge(ctx, tenantID, proposalID, actorUserID, MergeExecutionRequest{MergeSelection: selection, Revision: preview.Revision, Reason: "Operator accepted the observation-to-asset merge proposal"}); err != nil {
		if errors.Is(err, ErrMergePreviewChanged) {
			return nil, ErrMergeProposalChanged
		}
		return nil, err
	}
	view.Status = mergeStatusMerged
	view.AcceptedAssetID = &survivorID
	return view, nil
}

// KeepSeparate records that a reviewer looked and decided these are different
// things.
//
// The observation asset is deliberately left `pending_approval`: the reviewer
// answered "this is not that", not "this belongs in inventory". Promoting it
// here would turn one decision into two, and the second one would be ours.
func (s *MergeProposalService) KeepSeparate(ctx context.Context, tenantID, proposalID, actorUserID uuid.UUID) (*MergeProposalView, error) {
	var result *MergeProposalView
	err := pgidentity.WithAssetLifecycleWriteLocks(ctx, s.db.DB.DB, tenantID, nil, func() error {
		var err error
		result, err = s.keepSeparate(ctx, tenantID, proposalID, actorUserID)
		return err
	})
	return result, err
}

func (s *MergeProposalService) keepSeparate(ctx context.Context, tenantID, proposalID, actorUserID uuid.UUID) (*MergeProposalView, error) {
	var view *MergeProposalView
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		v, _, err := lockProposal(ctx, tx, tenantID, proposalID)
		if err != nil {
			return err
		}
		// The proposal ROW records the outcome — it is an asset_history entry
		// with action `merge_proposed`, and stamping `status: kept_separate`,
		// `resolved_by` and `resolved_at` onto it puts the decision in the
		// observation's timeline where the proposal already is.
		//
		// No SECOND entry: `merge_rejected` is not one of the eleven values
		// `asset_history_action_check` carries, and widening a CHECK to record
		// something the timeline already says would be a schema change buying
		// nothing. Accept is different — `merged_into` / `merged_from` ARE in
		// the list, and they have to be, because they appear on the SURVIVOR's
		// timeline where no proposal row exists.
		if err := resolveProposal(ctx, tx, tenantID, proposalID, mergeStatusKeptSeparate, uuid.Nil, actorUserID); err != nil {
			return err
		}
		v.Status = mergeStatusKeptSeparate
		view = v
		return nil
	})
	if err != nil {
		return nil, err
	}
	return view, nil
}

// ------------------------------------------------------------- internals --

// lockProposal reads one proposal FOR UPDATE so two reviewers clicking at once
// cannot both merge it. Without the lock the second merge would find the
// observation already archived and move nothing, reporting success.
func lockProposal(ctx context.Context, tx *sqlx.Tx, tenantID, proposalID uuid.UUID) (*MergeProposalView, []uuid.UUID, error) {
	return readProposal(ctx, tx, tenantID, proposalID, true)
}

func readProposal(ctx context.Context, tx *sqlx.Tx, tenantID, proposalID uuid.UUID, lock bool) (*MergeProposalView, []uuid.UUID, error) {
	query := `
		SELECT id, asset_id, source, changes_json::text, created_at
		FROM asset_history
		WHERE tenant_id = $1 AND id = $2 AND action = $3
		  AND changes_json->>'kind' = 'merge_proposal'`
	if lock {
		query += ` FOR UPDATE`
	}
	rows, err := tx.QueryContext(ctx, query,
		tenantID, proposalID, string(identity.ActionMergeProposed))
	if err != nil {
		return nil, nil, fmt.Errorf("lock merge proposal: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		if e := rows.Err(); e != nil {
			return nil, nil, e
		}
		return nil, nil, ErrMergeProposalNotFound
	}
	v, candidates, err := scanMergeProposal(rows, tenantID)
	if err != nil {
		return nil, nil, err
	}
	if v.Status != mergeStatusPending {
		return nil, nil, ErrMergeProposalResolved
	}
	return v, candidates, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanMergeProposal(rows rowScanner, tenantID uuid.UUID) (*MergeProposalView, []uuid.UUID, error) {
	var (
		id        uuid.UUID
		subjectID uuid.UUID
		source    string
		payload   string
		createdAt time.Time
	)
	if err := rows.Scan(&id, &subjectID, &source, &payload, &createdAt); err != nil {
		return nil, nil, fmt.Errorf("scan merge proposal: %w", err)
	}
	var body struct {
		Status             string  `json:"status"`
		Reason             string  `json:"reason"`
		SourceKind         string  `json:"source_kind"`
		ObservationAssetID string  `json:"observation_asset_id"`
		ModelID            string  `json:"model_id"`
		SourceRef          string  `json:"source_ref"`
		AutoAccepted       bool    `json:"auto_accepted"`
		AcceptedAssetID    string  `json:"accepted_asset_id"`
		AcceptedScore      float64 `json:"accepted_score"`
		AcceptedModelID    string  `json:"accepted_model_id"`
		AcceptedSourceRef  string  `json:"accepted_source_ref"`
		ResolvedAt         string  `json:"resolved_at"`
		ResolvedBy         string  `json:"resolved_by"`
		Candidates         []struct {
			AssetID            string             `json:"asset_id"`
			MatchedIdentifiers []map[string]any   `json:"matched_identifiers"`
			Score              float64            `json:"score"`
			Reason             string             `json:"reason"`
			Explanation        []MergeScoreFactor `json:"explanation"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal([]byte(payload), &body); err != nil {
		return nil, nil, fmt.Errorf("decode merge proposal %s: %w", id, err)
	}

	v := &MergeProposalView{
		ID:                id,
		TenantID:          tenantID,
		Status:            orDefault(body.Status, mergeStatusPending),
		Reason:            body.Reason,
		Source:            source,
		SourceKind:        body.SourceKind,
		ProposedAt:        createdAt,
		ModelID:           body.ModelID,
		SourceRef:         body.SourceRef,
		AutoAccepted:      body.AutoAccepted,
		AcceptedScore:     body.AcceptedScore,
		AcceptedModelID:   body.AcceptedModelID,
		AcceptedSourceRef: body.AcceptedSourceRef,
		ResolvedBy:        body.ResolvedBy,
		Candidates:        []MergeCandidateView{},
	}
	if body.ResolvedAt != "" {
		if t, err := time.Parse(time.RFC3339, body.ResolvedAt); err == nil {
			v.ResolvedAt = &t
		}
	}
	if obs, err := uuid.Parse(body.ObservationAssetID); err == nil {
		v.ObservationAssetID = &obs
	}
	if acc, err := uuid.Parse(body.AcceptedAssetID); err == nil {
		v.AcceptedAssetID = &acc
	}
	for _, c := range body.Candidates {
		cid, err := uuid.Parse(c.AssetID)
		if err != nil {
			// A candidate whose id does not parse is a corrupt row, not a
			// missing one. Skipping it keeps the rest of the proposal
			// reviewable; including a card nothing can be merged into would
			// not.
			continue
		}
		matched := c.MatchedIdentifiers
		if matched == nil {
			matched = []map[string]any{}
		}
		v.Candidates = append(v.Candidates, MergeCandidateView{
			AssetID:            cid,
			MatchedIdentifiers: matched,
			Score:              c.Score,
			Reason:             c.Reason,
			Explanation:        c.Explanation,
		})
	}
	candidateIDs := make([]uuid.UUID, 0, len(v.Candidates))
	for _, c := range v.Candidates {
		candidateIDs = append(candidateIDs, c.AssetID)
	}
	return v, candidateIDs, nil
}

type mergeDecoration struct {
	DisplayName string
	Hostname    *string
	ClassKey    string
	AssetStatus string
	Deleted     bool
}

// loadMergeDecorations is the second read: display name, class and status for
// every asset any proposal on the page names.
func loadMergeDecorations(ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]mergeDecoration, error) {
	out := map[uuid.UUID]mergeDecoration{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT id, COALESCE(display_name, hostname, host(primary_address), id::text) AS display_name,
		       hostname, class_key, asset_status, (deleted_at IS NOT NULL) AS deleted
		FROM assets
		WHERE tenant_id = $1 AND id = ANY($2::uuid[])`,
		tenantID, pq.Array(uuidStrings(ids)))
	if err != nil {
		return nil, fmt.Errorf("decorate merge candidates: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id uuid.UUID
		var d mergeDecoration
		if err := rows.Scan(&id, &d.DisplayName, &d.Hostname, &d.ClassKey, &d.AssetStatus, &d.Deleted); err != nil {
			return nil, fmt.Errorf("scan merge candidate: %w", err)
		}
		out[id] = d
	}
	return out, rows.Err()
}

func decorateMergeProposal(v *MergeProposalView, decor map[uuid.UUID]mergeDecoration) {
	apply := func(c *MergeCandidateView) {
		d, ok := decor[c.AssetID]
		if !ok {
			// The asset is gone entirely. Say so rather than rendering a blank
			// card that reads as an unnamed thing.
			c.Deleted = true
			c.DisplayName = c.AssetID.String()
			return
		}
		c.DisplayName = d.DisplayName
		c.Hostname = d.Hostname
		c.ClassKey = d.ClassKey
		c.ClassLabel = classLabelForPath(d.ClassKey)
		c.AssetStatus = d.AssetStatus
		c.Deleted = d.Deleted
	}
	for i := range v.Candidates {
		apply(&v.Candidates[i])
	}
	if v.ObservationAssetID != nil {
		obs := MergeCandidateView{AssetID: *v.ObservationAssetID, MatchedIdentifiers: []map[string]any{}}
		apply(&obs)
		v.Observation = &obs
	}
}

// assetReferrers and endpointReferrers are every column outside the asset's own
// children that names an asset or an endpoint by foreign key.
//
// They are spelled out here, and TestMergeMovesEveryForeignKeyToAssets reads
// the same list out of `schema.sql` and fails if the two disagree. A comment
// claiming the list is complete is worth nothing — it was complete once, and
// five tables were added under it.
//
// The asset's OWN children (asset_endpoints, asset_identifiers, asset_facts,
// asset_management, asset_credentials, asset_relationships, asset_history,
// software_installs) are not here: each needs a collision rule of its own and
// is moved by name above.
type fkRef struct{ table, column string }

var (
	assetReferrers = []fkRef{
		{"identity_observations", "asset_id"},
		// The class timeline follows the asset. A merge is two records of one
		// thing becoming one, so the classes the duplicate was believed to be
		// are part of the survivor's history — and the FK is ON DELETE CASCADE,
		// so leaving the rows behind would DELETE them with the source row
		// rather than merely stranding them.
		{"asset_class_history", "asset_id"},
		{"ssh_keys", "asset_id"},
		{"external_connections", "source_asset_id"},
		{"device_jobs", "asset_id"},
		{"database_encryption_states", "asset_id"},
		{"crypto_applications", "asset_id"},
	}
	endpointReferrers = []fkRef{
		{"crypto_implementations", "endpoint_id"},
		{"external_connections", "source_endpoint_id"},
		{"ssh_keys", "endpoint_id"},
	}
)

// moveAssetChildren re-parents everything the observation asset owns onto the
// survivor.
//
// # Collisions are the normal case, not the edge case
//
// Both `asset_endpoints` and `asset_identifiers` carry a unique identity index
// scoped by asset. A merge is precisely when two assets are believed to be the
// same thing, so the two very often carry THE SAME endpoint and THE SAME
// identifier — that overlap is usually WHY the proposal was opened. A bare
// `UPDATE … SET asset_id` therefore hits a duplicate-key violation on the
// commonest merge there is.
//
// The rule for a collision is the same on both tables: the survivor's row wins,
// and the source's observation timestamps are folded into it so nothing about
// when the thing was seen is lost. Then the source row goes.
func moveAssetChildren(ctx context.Context, tx *sqlx.Tx, tenantID, from, to uuid.UUID, managementSelected ...bool) error {
	if err := moveMergePolymorphicChildren(ctx, tx, tenantID, from, to); err != nil {
		return err
	}

	// Endpoints first, and in four steps, because crypto configurations point
	// at endpoint ids: a configuration on a source endpoint that is about to be
	// deleted has to be re-pointed at the survivor's equivalent BEFORE the row
	// goes, or the FK takes the configuration with it.
	//
	// `endpointIdentityJoin` is the unique index's key, spelled once.
	const endpointIdentityJoin = `
		dst.tenant_id = $1 AND dst.asset_id = $3
		  AND coalesce(dst.address::text, '') = coalesce(src.address::text, '')
		  AND coalesce(dst.fqdn, '')          = coalesce(src.fqdn, '')
		  AND coalesce(dst.port, -1)          = coalesce(src.port, -1)
		  AND dst.transport                   = src.transport`

	// 1. Re-point EVERY row that names an endpoint the survivor already has.
	//
	// All three of these FKs are ON DELETE SET NULL, which is why this step is
	// not optional and why getting it wrong is silent: step 3 deletes the
	// duplicate endpoints, and any row still pointing at one has its
	// endpoint_id quietly set to NULL. Only `crypto_implementations` was
	// handled here, so merging two assets that shared a socket unlinked the
	// SSH host keys and the external connections observed on it — no error, no
	// log line, just columns that used to say which endpoint and now say
	// nothing.
	//
	// The list is pinned by TestMergeMovesEveryForeignKeyToAssets, which reads
	// the FKs out of schema.sql rather than trusting this comment.
	for _, ref := range endpointReferrers {
		if _, err := tx.ExecContext(ctx, `
			UPDATE `+ref.table+` r SET `+ref.column+` = dst.id
			  FROM asset_endpoints src, asset_endpoints dst
			 WHERE r.tenant_id = $1 AND r.`+ref.column+` = src.id
			   AND src.tenant_id = $1 AND src.asset_id = $2
			   AND `+endpointIdentityJoin,
			tenantID, from, to); err != nil {
			return fmt.Errorf("merge: re-point %s.%s at the surviving endpoint: %w", ref.table, ref.column, err)
		}
	}

	// 2. Fold the duplicate's observation window into the survivor's row, so a
	//    merge never makes an endpoint look newer or shorter-lived than it was.
	if _, err := tx.ExecContext(ctx, `
		UPDATE asset_endpoints dst
		   SET status = CASE WHEN `+preferNewerMergeState+` THEN src.status ELSE dst.status END,
               source_kind = CASE WHEN `+preferNewerMergeState+` THEN src.source_kind ELSE dst.source_kind END,
               source_ref = CASE WHEN `+preferNewerMergeState+` THEN src.source_ref ELSE dst.source_ref END,
               last_scan_status = CASE WHEN src.last_scanned_at > dst.last_scanned_at OR dst.last_scanned_at IS NULL THEN src.last_scan_status ELSE dst.last_scan_status END,
               last_scanned_at = GREATEST(dst.last_scanned_at, src.last_scanned_at),
               first_seen_at = LEAST(dst.first_seen_at, src.first_seen_at),
		       last_seen_at  = GREATEST(dst.last_seen_at, src.last_seen_at),
		       updated_at    = now()
		  FROM asset_endpoints src
		 WHERE src.tenant_id = $1 AND src.asset_id = $2
		   AND `+endpointIdentityJoin,
		tenantID, from, to); err != nil {
		return fmt.Errorf("merge: fold endpoint observation windows: %w", err)
	}

	// 3. Drop the duplicates.
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM asset_endpoints src
		 WHERE src.tenant_id = $1 AND src.asset_id = $2
		   AND EXISTS (SELECT 1 FROM asset_endpoints dst WHERE `+endpointIdentityJoin+`)`,
		tenantID, from, to); err != nil {
		return fmt.Errorf("merge: drop duplicate endpoints: %w", err)
	}

	// 4. Move what is left — the endpoints only the source had.
	if _, err := tx.ExecContext(ctx, `
		UPDATE asset_endpoints SET asset_id = $3, updated_at = now()
		 WHERE tenant_id = $1 AND asset_id = $2`,
		tenantID, from, to); err != nil {
		return fmt.Errorf("merge: move endpoints: %w", err)
	}

	steps := []struct {
		what string
		sql  string
	}{
		{"crypto configurations", `UPDATE crypto_implementations SET asset_id = $3, updated_at = now()
		                WHERE tenant_id = $1 AND asset_id = $2`},
		{"management", `UPDATE asset_management SET asset_id = $3, updated_at = now()
		                WHERE tenant_id = $1 AND asset_id = $2
		                  AND NOT EXISTS (SELECT 1 FROM asset_management m2
		                                   WHERE m2.tenant_id = $1 AND m2.asset_id = $3)`},
		// asset_credentials is keyed (tenant_id, asset_id) like asset_management
		// and moves under the same rule: the survivor's row wins, because two
		// credentials for one thing is not a thing.
		{"credentials", `UPDATE asset_credentials SET asset_id = $3, updated_at = now()
		                WHERE tenant_id = $1 AND asset_id = $2
		                  AND NOT EXISTS (SELECT 1 FROM asset_credentials c2
		                                   WHERE c2.tenant_id = $1 AND c2.asset_id = $3)`},
		{"history", `UPDATE asset_history SET asset_id = $3
		                WHERE tenant_id = $1 AND asset_id = $2`},

		// Facts. Unique per (tenant, asset, key, source_ref), so the survivor's
		// row for a key one producer wrote wins and the duplicate goes. The
		// survivor's row is NOT touched: a fact carries the value AND when it
		// was observed, and moving the source's observed_at onto the survivor's
		// value would claim a measurement that never happened.
		{"facts", `DELETE FROM asset_facts src
		                WHERE src.tenant_id = $1 AND src.asset_id = $2
		                  AND EXISTS (SELECT 1 FROM asset_facts dst
		                               WHERE dst.tenant_id = $1 AND dst.asset_id = $3
		                                 AND dst.key = src.key AND dst.source_ref = src.source_ref)`},
		{"remaining facts", `UPDATE asset_facts SET asset_id = $3, updated_at = now()
		                WHERE tenant_id = $1 AND asset_id = $2`},

		// Software installs. Unique per (tenant, asset, product, path); fold the
		// observation window as the endpoints do, then drop and move.
		{"software install windows", `UPDATE software_installs dst
		                   SET status = CASE WHEN ` + preferNewerMergeState + ` THEN src.status ELSE dst.status END,
                           source_kind = CASE WHEN ` + preferNewerMergeState + ` THEN src.source_kind ELSE dst.source_kind END,
                           source_ref = CASE WHEN ` + preferNewerMergeState + ` THEN src.source_ref ELSE dst.source_ref END,
                           first_seen_at = LEAST(dst.first_seen_at, src.first_seen_at),
		                       last_seen_at  = GREATEST(dst.last_seen_at, src.last_seen_at),
		                       updated_at    = now()
		                  FROM software_installs src
		                 WHERE src.tenant_id = $1 AND src.asset_id = $2
		                   AND dst.tenant_id = $1 AND dst.asset_id = $3
		                   AND dst.product_id = src.product_id
		                   AND coalesce(dst.install_path, '') = coalesce(src.install_path, '')`},
		{"duplicate software installs", `DELETE FROM software_installs src
		                WHERE src.tenant_id = $1 AND src.asset_id = $2
		                  AND EXISTS (SELECT 1 FROM software_installs dst
		                               WHERE dst.tenant_id = $1 AND dst.asset_id = $3
		                                 AND dst.product_id = src.product_id
		                                 AND coalesce(dst.install_path, '') = coalesce(src.install_path, ''))`},
		{"software installs", `UPDATE software_installs SET asset_id = $3, updated_at = now()
		                WHERE tenant_id = $1 AND asset_id = $2`},

		// Producer coverage (ADR-0005 D4). A producer that examined the source
		// examined the very subjects the survivor now owns, so the survivor
		// inherits the claim — and without it the survivor can end up SCORED by
		// an inherited finding while its risk_assessed_by stays empty, which
		// every reader spells "not assessed" and the facet rail's band counters
		// skip entirely.
		//
		// Unique per (tenant, asset, producer), so a plain UPDATE collides
		// whenever both assets were assessed by the same producer — which is the
		// commonest case, since a merge proposal is opened about two records of
		// one thing. Insert-on-conflict with the LATER timestamp winning: an
		// inherited claim must never make the survivor's coverage look staler
		// than it already was.
		{"producer coverage", `WITH moved AS (
		                    DELETE FROM producer_assessments
		                     WHERE tenant_id = $1 AND asset_id = $2
		                 RETURNING tenant_id, producer, assessed_at
		                )
		                INSERT INTO producer_assessments (tenant_id, asset_id, producer, assessed_at)
		                SELECT tenant_id, $3, producer, assessed_at FROM moved
		                ON CONFLICT (tenant_id, asset_id, producer)
		                DO UPDATE SET assessed_at = GREATEST(producer_assessments.assessed_at, EXCLUDED.assessed_at)`},
	}

	// Every OTHER table that names an asset. These five carry ON DELETE SET
	// NULL foreign keys, so nothing broke when they were left behind — the rows
	// simply went on pointing at an archived tombstone, and the survivor showed
	// no SSH keys, no external connections, no interrogation jobs and no
	// disk-encryption state for hardware it had just absorbed. A merge that
	// loses half the evidence is worse than no merge, because it looks
	// finished.
	//
	// None of their unique keys includes asset_id, so a plain UPDATE cannot
	// collide the way endpoints and identifiers do.
	for _, ref := range assetReferrers {
		steps = append(steps, struct {
			what string
			sql  string
		}{
			ref.table + "." + ref.column,
			`UPDATE ` + ref.table + ` SET ` + ref.column + ` = $3 WHERE tenant_id = $1 AND ` + ref.column + ` = $2`,
		})
	}
	for _, step := range steps {
		// Paired profile selection includes deliberate absences. A later
		// source must not fill a missing URL/credential from a different pair.
		if len(managementSelected) > 0 && managementSelected[0] && (step.what == "management" || step.what == "credentials") {
			continue
		}
		if _, err := tx.ExecContext(ctx, step.sql, tenantID, from, to); err != nil {
			return fmt.Errorf("merge: move %s: %w", step.what, err)
		}
	}

	if err := moveAssetEdges(ctx, tx, tenantID, from, to); err != nil {
		return err
	}

	// Identifiers: fold the observation window of the ones the survivor already
	// carries, move the ones it does not, drop the rest. Same rule as endpoints,
	// and for the same reason — a shared identifier is usually why these two
	// assets are being merged at all.
	if _, err := tx.ExecContext(ctx, `
		UPDATE asset_identifiers dst
		   SET first_seen_at = LEAST(dst.first_seen_at, src.first_seen_at),
		       last_seen_at  = GREATEST(dst.last_seen_at, src.last_seen_at),
		       updated_at    = now()
		  FROM asset_identifiers src
		 WHERE src.tenant_id = $1 AND src.asset_id = $2
		   AND dst.tenant_id = $1 AND dst.asset_id = $3
		   AND dst.kind = src.kind AND dst.value = src.value
		   AND dst.scope IS NOT DISTINCT FROM src.scope`,
		tenantID, from, to); err != nil {
		return fmt.Errorf("merge: fold identifier observation windows: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE asset_identifiers src SET asset_id = $3
		 WHERE src.tenant_id = $1 AND src.asset_id = $2
		   AND NOT EXISTS (
			SELECT 1 FROM asset_identifiers dst
			 WHERE dst.tenant_id = $1 AND dst.asset_id = $3
			   AND dst.kind = src.kind AND dst.value = src.value
			   AND dst.scope IS NOT DISTINCT FROM src.scope)`,
		tenantID, from, to); err != nil {
		return fmt.Errorf("merge: move identifiers: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM asset_identifiers WHERE tenant_id = $1 AND asset_id = $2`,
		tenantID, from); err != nil {
		return fmt.Errorf("merge: drop duplicate identifiers: %w", err)
	}
	return nil
}

// moveAssetEdges re-points the observation's relationships onto the survivor,
// in BOTH directions.
//
// Edges are the one child where "move it" is not enough on its own, for three
// reasons the table states outright:
//
//   - `asset_relationships_no_self_edge_check` forbids from = to. An edge
//     BETWEEN the two assets being merged becomes exactly that, and re-pointing
//     it would abort the whole merge transaction. It is also the one edge a
//     merge makes meaningless: the two ends were one thing all along.
//   - `asset_relationships_edge_uniq` is (tenant, from, to, type), so the
//     survivor and the observation very often hold the SAME edge — the shared
//     neighbour is frequently the evidence the proposal was opened on.
//   - An edge is directional, so both ends have to be checked; moving only
//     `from_asset_id` would strand every edge that pointed AT the observation.
//
// The collision rule is the one the endpoints and identifiers use: the
// survivor's row wins and the source's observation window is folded into it, so
// nothing about when the relationship was seen is lost — and the survivor's
// `status` survives, because a rejected edge is a human decision that an
// unrelated merge must not undo.
func moveAssetEdges(ctx context.Context, tx *sqlx.Tx, tenantID, from, to uuid.UUID) error {
	// 1. The edge between the two merged assets, if there is one. It cannot
	//    survive the merge in any form.
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM asset_relationships
		 WHERE tenant_id = $1
		   AND ((from_asset_id = $2 AND to_asset_id = $3)
		     OR (from_asset_id = $3 AND to_asset_id = $2))`,
		tenantID, from, to); err != nil {
		return fmt.Errorf("merge: drop the edge between the merged assets: %w", err)
	}

	// 2 and 3, once per direction. `mine` is the column that would become the
	// survivor's; `theirs` is the far end, which has to match for two edges to
	// be the same edge.
	for _, d := range []struct{ mine, theirs string }{
		{"from_asset_id", "to_asset_id"},
		{"to_asset_id", "from_asset_id"},
	} {
		match := `dst.tenant_id = $1 AND dst.` + d.mine + ` = $3
			  AND dst.` + d.theirs + ` = src.` + d.theirs + `
			  AND dst.type = src.type`
		if _, err := tx.ExecContext(ctx, `
			UPDATE asset_relationships dst
			   SET first_seen_at      = LEAST(dst.first_seen_at, src.first_seen_at),
			       last_seen_at       = GREATEST(dst.last_seen_at, src.last_seen_at),
			       observation_count  = dst.observation_count + src.observation_count,
			       updated_at         = now()
			  FROM asset_relationships src
			 WHERE src.tenant_id = $1 AND src.`+d.mine+` = $2
			   AND `+match,
			tenantID, from, to); err != nil {
			return fmt.Errorf("merge: fold %s edges: %w", d.mine, err)
		}
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM asset_relationships src
			 WHERE src.tenant_id = $1 AND src.`+d.mine+` = $2
			   AND EXISTS (SELECT 1 FROM asset_relationships dst WHERE `+match+`)`,
			tenantID, from, to); err != nil {
			return fmt.Errorf("merge: drop duplicate %s edges: %w", d.mine, err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE asset_relationships SET `+d.mine+` = $3, updated_at = now()
			 WHERE tenant_id = $1 AND `+d.mine+` = $2`,
			tenantID, from, to); err != nil {
			return fmt.Errorf("merge: move %s edges: %w", d.mine, err)
		}
	}
	return nil
}

func writeMergeHistory(ctx context.Context, tx *sqlx.Tx, tenantID, assetID, actor uuid.UUID, action string, changes map[string]any) error {
	payload, err := json.Marshal(changes)
	if err != nil {
		return fmt.Errorf("marshal %s history: %w", action, err)
	}
	var actorArg any
	if actor != uuid.Nil {
		actorArg = actor
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO asset_history (asset_id, tenant_id, actor_user_id, source, action, changes_json)
		VALUES ($1, $2, $3, 'manual', $4, $5::jsonb)`,
		assetID, tenantID, actorArg, action, payload); err != nil {
		return fmt.Errorf("record %s: %w", action, err)
	}
	return nil
}

// resolveProposal stamps the outcome onto the proposal row itself, so the
// Approvals queue stops returning it and the history says who decided and how.
func resolveProposal(ctx context.Context, tx *sqlx.Tx, tenantID, proposalID uuid.UUID, status string, survivor, actor uuid.UUID) error {
	patch := map[string]any{
		"status":      status,
		"resolved_at": time.Now().UTC().Format(time.RFC3339),
	}
	if survivor != uuid.Nil {
		patch["merged_into"] = survivor.String()
	}
	if actor != uuid.Nil {
		patch["resolved_by"] = actor.String()
	}
	payload, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("marshal proposal resolution: %w", err)
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE asset_history
		   SET changes_json = changes_json || $3::jsonb
		 WHERE tenant_id = $1 AND id = $2`,
		tenantID, proposalID, payload)
	if err != nil {
		return fmt.Errorf("resolve merge proposal: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrMergeProposalNotFound
	}
	return nil
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
