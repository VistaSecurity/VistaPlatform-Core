// Package services: class proposals — the Approvals surface for a class the
// rules argued about an asset that already has one (workstream 2.10b).
package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/assetclasshistory"
	"github.com/vistasecurity/vistaplatform/shared/classify"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// A class proposal is an `asset_history` row, not a table.
//
// Same decision as the merge proposals next door, for the same reasons. The
// proposal, the decision and the class change it caused are three entries in one
// timeline, which is what somebody reading an asset's history six months later
// actually needs; a `class_proposals` table would be a second home for a
// decision the history already records, and a second queue is how half the
// proposals in a product end up unread.
//
// The row carries `action = 'class_proposed'` and
// `changes_json.kind = 'class_proposal'`. A partial unique index keeps one
// PENDING proposal per (tenant, asset, proposed class), so a printer that
// advertises `_ipp._tcp` on every coalescing window asks the question once
// rather than a hundred times a day.
//
// Two things a class proposal is NOT:
//
//   - It is not how a NEW asset gets a class. A discovery the rules classify is
//     created WITH that class, `class_source_kind: rule`, and lands in
//     `pending_approval` like any other; approving the asset approves the class.
//     Raising a proposal as well would ask the same question twice and let a
//     reviewer answer it two ways.
//   - It is not a class change. Accepting one sets the class; until then the
//     asset is exactly what it was.

// ClassProposalView is one pending proposal as the Approvals queue shows it.
type ClassProposalView struct {
	ID       uuid.UUID `json:"id"`
	TenantID uuid.UUID `json:"tenant_id"`
	AssetID  uuid.UUID `json:"asset_id"`
	Status   string    `json:"status"`
	Source   string    `json:"source"`

	// ProposedClassKey is the class the rules argued, empty when they
	// contradicted each other. ProposedClassLabel is its display name, so the
	// queue does not have to hold a copy of the taxonomy.
	ProposedClassKey   string `json:"proposed_class_key"`
	ProposedClassLabel string `json:"proposed_class_label,omitempty"`

	// CurrentClassKey is what the asset is classed as now. A proposal is a
	// COMPARISON — "we think this is a printer, it is currently an unknown
	// host" — and one half of it is not reviewable.
	CurrentClassKey   string `json:"current_class_key,omitempty"`
	CurrentClassLabel string `json:"current_class_label,omitempty"`
	CurrentSourceKind string `json:"current_class_source_kind,omitempty"`

	// ConflictingClasses are the classes that tied when the rules disagreed,
	// with their labels. A reviewer either picks one or rejects the lot; the
	// disagreement itself is a curation bug and this is what names it.
	ConflictingClasses []ClassOption `json:"conflicting_classes,omitempty"`

	// MatchedRules is the argument: the pattern, the confidence and the
	// citation per rule, as they stood when the proposal was raised.
	MatchedRules []classify.RuleRef `json:"matched_rules,omitempty"`
	RuleIDs      []string           `json:"rule_ids,omitempty"`
	Confidence   float64            `json:"confidence,omitempty"`

	// ProposedClassSourceKind is the provenance an acceptance will stamp:
	// `rule` for a class the curated table argued, `inferred` for one the
	// learned classifier proposed (workstream 4.2). A reviewer reads it as how
	// much to trust the row, and it is the field that says the two are not the
	// same kind of claim.
	ProposedClassSourceKind string `json:"proposed_class_source_kind,omitempty"`

	// ProposedClassSourceRef is the `class_source_ref` an acceptance writes —
	// `rule:<id>` or `model:<id>`. Server-side plumbing rather than part of the
	// response: a reviewer already has `rule_ids` and `model_id`, which is the
	// same information in the shape the row renders, and a second spelling on
	// the wire is a second thing for a client to get right.
	ProposedClassSourceRef string `json:"-"`

	// ModelID, ModelProbability and ModelReasons are the learned classifier's
	// argument — the weights that proposed it, the calibrated probability, and
	// the top feature contributions. Empty for a rule-derived proposal, which
	// is what the row reads to decide whether to say "Rule" or "Model".
	//
	// A reason names a FEATURE and the evidence that set it — a vendor, a port,
	// a banner token, an advertised service. Never a hostname or an address:
	// the model's whole input carries neither.
	ModelID          string                 `json:"model_id,omitempty"`
	ModelProbability float64                `json:"model_probability,omitempty"`
	ModelReasons     []classify.ModelReason `json:"model_reasons,omitempty"`

	ProposedAt time.Time `json:"proposed_at"`

	// Asset decoration. The reviewer is on Approvals with no asset around them,
	// and "something might be a printer" is not a reviewable sentence.
	AssetName    string `json:"asset_display_name,omitempty"`
	AssetHost    string `json:"asset_hostname,omitempty"`
	AssetAddress string `json:"asset_primary_address,omitempty"`
	AssetStatus  string `json:"asset_status,omitempty"`

	// AcceptedClassKey is set once a proposal is accepted, which is not always
	// ProposedClassKey: a conflict proposal offers a choice.
	AcceptedClassKey string `json:"accepted_class_key,omitempty"`
}

// ClassOption is a class a reviewer may choose, with its label.
type ClassOption struct {
	Key   string `json:"key"`
	Label string `json:"label,omitempty"`
}

// Errors the handler maps onto status codes.
var (
	// ErrClassProposalNotFound names no pending proposal in this tenant.
	ErrClassProposalNotFound = errors.New("class proposal not found")

	// ErrClassProposalDecided is distinct from not-found so a second click on a
	// stale page can say what happened rather than claiming the row never
	// existed.
	ErrClassProposalDecided = errors.New("class proposal has already been decided")

	// ErrClassNotInProposal is returned when the chosen class is not one this
	// proposal offered. Accepting an arbitrary class key would let the API
	// reclassify an asset as something no rule ever argued for — which is the
	// fabricated fact the whole table exists to avoid, arriving through the
	// approval path instead of the classifier.
	ErrClassNotInProposal = errors.New("the chosen class is not one this proposal offers")

	// ErrClassProposalNeedsChoice is returned when a conflict proposal is
	// accepted with no class named. The rules disagreed; the API must not pick
	// for the reviewer.
	ErrClassProposalNeedsChoice = errors.New("this proposal has no single class — choose one of the conflicting classes")
)

// ClassProposalService reads and decides class proposals.
type ClassProposalService struct {
	db *database.DB
}

// NewClassProposalService constructs the service.
func NewClassProposalService(db *database.DB) *ClassProposalService {
	return &ClassProposalService{db: db}
}

// ClassProposalPageSize is the default page, ClassProposalMaxPageSize the
// ceiling. The ceiling is why `total` exists: a page that stops at 200 and a
// caller reading len() as the count would tell a tenant with a thousand
// proposals that it has 200.
const (
	ClassProposalPageSize    = 50
	ClassProposalMaxPageSize = 200
)

// ClampClassProposalPage normalises a caller's page request. Exported so the
// handler can echo the page the server actually used rather than the one the
// caller asked for.
func ClampClassProposalPage(limit, offset int) (int, int) {
	if limit <= 0 || limit > ClassProposalMaxPageSize {
		limit = ClassProposalPageSize
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

const classProposalPredicate = `
	tenant_id = $1
	AND action = 'class_proposed'
	AND changes_json->>'kind' = 'class_proposal'
	AND COALESCE(changes_json->>'status', 'pending') = 'pending'`

// ListPending returns one page of pending class proposals, newest first, and
// the TOTAL the page was cut from.
//
// Two reads plus one decoration read, not N+1: one COUNT, one over
// asset_history, one over `assets` for every asset any of them names.
func (s *ClassProposalService) ListPending(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]ClassProposalView, int, error) {
	limit, offset = ClampClassProposalPage(limit, offset)

	var (
		views []ClassProposalView
		total int
	)
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		if err := tx.QueryRowContext(ctx,
			`SELECT count(*) FROM asset_history WHERE `+classProposalPredicate, tenantID).Scan(&total); err != nil {
			return fmt.Errorf("count class proposals: %w", err)
		}
		rows, err := tx.QueryContext(ctx, `
			SELECT id, asset_id, source, changes_json::text, created_at
			  FROM asset_history
			 WHERE `+classProposalPredicate+`
			 ORDER BY created_at DESC, seq DESC
			 LIMIT $2 OFFSET $3`, tenantID, limit, offset)
		if err != nil {
			return fmt.Errorf("query class proposals: %w", err)
		}
		defer func() { _ = rows.Close() }()

		var assetIDs []uuid.UUID
		for rows.Next() {
			v, err := scanClassProposal(rows, tenantID)
			if err != nil {
				return err
			}
			views = append(views, *v)
			assetIDs = append(assetIDs, v.AssetID)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		_ = rows.Close()

		decor, err := loadClassProposalAssets(ctx, tx, tenantID, assetIDs)
		if err != nil {
			return err
		}
		for i := range views {
			decorateClassProposal(&views[i], decor[views[i].AssetID])
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	if views == nil {
		views = []ClassProposalView{}
	}
	return views, total, nil
}

// Decide accepts or rejects one proposal.
//
// ACCEPTING writes the class onto the asset with `class_source_kind: rule` and
// a `class_source_ref` naming the rule that argued it, and stamps the proposal
// `accepted`. The reviewer's own id goes on the history row rather than into
// the source ref: the RULE decided what the class is, a person decided to take
// it, and collapsing the two would lose which rule to go and fix if it turns out
// wrong.
//
// REJECTING leaves the asset exactly as it was and writes a `class_rejected`
// row. That row is load-bearing rather than decorative: it is what the intake
// checks before proposing the same class again, and without it a printer that
// advertises `_ipp._tcp` every coalescing window would refill the queue with a
// question already answered.
//
// One transaction, SELECT ... FOR UPDATE first: two reviewers on the same stale
// page must not both get a 200 for opposite answers.
func (s *ClassProposalService) Decide(
	ctx context.Context, tenantID, proposalID, actorUserID uuid.UUID, accept bool, chosenClass string,
) (*ClassProposalView, error) {
	var view *ClassProposalView
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		row := tx.QueryRowContext(ctx, `
			SELECT id, asset_id, source, changes_json::text, created_at
			  FROM asset_history
			 WHERE tenant_id = $1 AND id = $2
			   AND action = 'class_proposed'
			   AND changes_json->>'kind' = 'class_proposal'
			 FOR UPDATE`, tenantID, proposalID)
		v, err := scanClassProposal(row, tenantID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrClassProposalNotFound
		}
		if err != nil {
			return err
		}
		if v.Status != classProposalPending {
			return fmt.Errorf("%w: it is %s", ErrClassProposalDecided, v.Status)
		}

		status := classProposalRejected
		action := identity.ActionClassRejected
		chosen := ""
		if accept {
			chosen, err = chooseProposedClass(*v, chosenClass)
			if err != nil {
				return err
			}
			status, action = classProposalAccepted, identity.ActionClassAccepted
			kind, ref := classSourceOfProposal(*v)
			if err := applyProposedClass(ctx, tx, tenantID, v.AssetID, chosen, kind, ref); err != nil {
				return err
			}
			// The class MOVED, so the class-history record owes a row — on
			// this transaction, beside the UPDATE that moved it. Written here
			// rather than inside applyProposedClass because only this scope
			// knows the reviewer and the argument they were shown.
			if err := assetclasshistory.Record(ctx, tx, tenantID, v.AssetID, assetclasshistory.Entry{
				From:   v.CurrentClassKey,
				To:     chosen,
				Source: assetclasshistory.SourceProposal,
				Actor:  actorUserID,
				Evidence: map[string]any{
					"proposal_id":       proposalID.String(),
					"class_source_kind": kind,
					"class_source_ref":  ref,
					"rule_ids":          v.RuleIDs,
					"model_id":          v.ModelID,
					"model_probability": v.ModelProbability,
					"confidence":        v.Confidence,
				},
			}); err != nil {
				return err
			}
		}

		// The proposal row keeps its `class_proposed` action and gains a
		// status: the queue's predicate reads the status, and rewriting the
		// action would lose the row that says a proposal was ever raised.
		if _, err := tx.ExecContext(ctx, `
			UPDATE asset_history
			   SET changes_json = changes_json
			       || jsonb_build_object('status', $3::text)
			       || CASE WHEN $4::text = '' THEN '{}'::jsonb
			               ELSE jsonb_build_object('accepted_class_key', $4::text) END
			 WHERE tenant_id = $1 AND id = $2`, tenantID, proposalID, status, chosen); err != nil {
			return fmt.Errorf("stamp class proposal: %w", err)
		}

		// And the decision itself, as its own entry. The `class_rejected` row
		// is what the intake reads; the `class_accepted` row is what the
		// timeline reads.
		decision := classProposalChanges{
			Kind:               classProposalKind,
			ProposedClassKey:   v.ProposedClassKey,
			CurrentClassKey:    v.CurrentClassKey,
			ConflictingClasses: optionKeys(v.ConflictingClasses),
			RuleIDs:            v.RuleIDs,
			Confidence:         v.Confidence,
			Status:             status,
			AcceptedClassKey:   chosen,
			// The producer travels onto the decision row too. A
			// `class_rejected` row is what intake reads before re-proposing the
			// same class, and the timeline entry a person reads six months
			// later has to say whether a rule or a model was the thing that got
			// it wrong.
			SourceKind:       v.ProposedClassSourceKind,
			SourceRef:        v.ProposedClassSourceRef,
			ModelID:          v.ModelID,
			ModelProbability: v.ModelProbability,
			ModelReasons:     v.ModelReasons,
		}
		payload, err := decision.JSON()
		if err != nil {
			return fmt.Errorf("encode class decision: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO asset_history (tenant_id, asset_id, actor_user_id, source, action, changes_json)
			VALUES ($1, $2, $3, 'approvals', $4, $5::jsonb)`,
			tenantID, v.AssetID, nullActor(actorUserID), string(action), string(payload)); err != nil {
			return fmt.Errorf("record the class decision: %w", err)
		}

		v.Status = status
		v.AcceptedClassKey = chosen
		view = v
		return nil
	})
	if err != nil {
		return nil, err
	}
	return view, nil
}

// chooseProposedClass decides WHICH class an acceptance applies.
//
// The allowed set is the proposed class plus any class the rules conflicted
// over, and nothing else. An arbitrary class key would let the approval path
// reclassify an asset as something no rule argued for — the fabricated fact the
// rule table exists to prevent, arriving through a different door.
func chooseProposedClass(v ClassProposalView, chosen string) (string, error) {
	chosen = strings.TrimSpace(chosen)
	allowed := optionKeys(v.ConflictingClasses)
	if v.ProposedClassKey != "" {
		allowed = append([]string{v.ProposedClassKey}, allowed...)
	}
	if chosen == "" {
		if v.ProposedClassKey == "" {
			return "", fmt.Errorf("%w: %s", ErrClassProposalNeedsChoice, strings.Join(allowed, ", "))
		}
		return v.ProposedClassKey, nil
	}
	for _, k := range allowed {
		if k == chosen {
			return chosen, nil
		}
	}
	return "", fmt.Errorf("%w: it offers %s", ErrClassNotInProposal, strings.Join(allowed, ", "))
}

// applyProposedClass writes the accepted class onto the asset.
//
// class_path moves with class_key, because the denormalised ancestry is what
// every class facet and prefix filter reads; leaving it behind would put the
// asset under its old branch in every list while its badge said otherwise.
//
// sourceKind is a PARAMETER rather than the literal `rule` it used to be. Since
// workstream 4.2 there are two producers of class proposals, and a class the
// learned classifier proposed is `inferred` with a `model:<id>` ref — ADR-0008
// D4.2's "something a model proposed". Both spellings satisfy the database's
// CHECK constraint, so writing `rule` for a model's answer would fail nowhere
// and be wrong on the one column a reviewer audits.
func applyProposedClass(ctx context.Context, tx *sqlx.Tx, tenantID, assetID uuid.UUID, classKey, sourceKind, sourceRef string) error {
	// classPathForKey falls back to the key itself for a tenant leaf subclass,
	// whose path is a runtime row (ADR-0002 D2). The column is an FK by value to
	// asset_classes, which refuses a key naming nothing at all, so the loud
	// failure happens in the right place rather than here.
	path := classPathForKey(classKey)
	res, err := tx.ExecContext(ctx, `
		UPDATE assets
		   SET class_key = $3,
		       class_path = $4,
		       class_source_kind = $5,
		       class_source_ref = NULLIF($6, ''),
		       updated_at = NOW()
		 WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`,
		tenantID, assetID, classKey, path, sourceKind, sourceRef)
	if err != nil {
		return fmt.Errorf("apply the accepted class: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// The asset was deleted between the page render and the click. Not an
		// error the reviewer caused, and not something to report as success.
		return fmt.Errorf("%w: its asset is gone", ErrClassProposalNotFound)
	}
	return nil
}

// classSourceOfProposal is the `class_source_kind` and `class_source_ref` an
// accepted proposal stamps onto the asset.
//
// The proposal's own recorded provenance wins when it has one: it was written
// when the proposal was raised, which is the provenance the reviewer was
// SHOWN, and re-deriving it at acceptance would read whatever the rules and the
// weights say now — possibly a different producer entirely, after a retrain or
// a rule edit while the row sat in the queue.
//
// The fallback re-derives the rule ref the old way, for the rows written before
// workstream 4.2 recorded it. Those are all rule-derived, so `rule` is the right
// kind for them and not a guess.
//
// The FIRST rule, not the best: RuleIDs and MatchedRules both arrive
// highest-confidence first from the engine, so position is the ranking.
func classSourceOfProposal(v ClassProposalView) (kind, ref string) {
	if v.ProposedClassSourceKind != "" && v.ProposedClassSourceRef != "" {
		return v.ProposedClassSourceKind, v.ProposedClassSourceRef
	}
	if v.ModelID != "" {
		return string(identity.ClassSourceInferred), "model:" + v.ModelID
	}
	return string(identity.ClassSourceRule), legacyRuleRefOfProposal(v)
}

func legacyRuleRefOfProposal(v ClassProposalView) string {
	if len(v.RuleIDs) > 0 {
		return "rule:" + v.RuleIDs[0]
	}
	if len(v.MatchedRules) > 0 {
		// A rule from the COMPILED-IN table has no id — that is the fallback
		// engine, and a class it argued has no curated row to point at — so the
		// ref names the kind and pattern instead, which is still something a
		// reviewer can search the console for.
		if r := v.MatchedRules[0]; r.ID != "" {
			return "rule:" + r.ID
		}
		return "rule:" + v.MatchedRules[0].Kind + ":" + v.MatchedRules[0].Pattern
	}
	return "rule"
}

// --------------------------------------------------------------- plumbing --

func scanClassProposal(row rowScanner, tenantID uuid.UUID) (*ClassProposalView, error) {
	var (
		id, assetID uuid.UUID
		source      string
		payload     string
		createdAt   sql.NullTime
	)
	if err := row.Scan(&id, &assetID, &source, &payload, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("scan class proposal: %w", err)
	}
	var c classProposalChanges
	if err := json.Unmarshal([]byte(payload), &c); err != nil {
		return nil, fmt.Errorf("decode class proposal %s: %w", id, err)
	}
	v := &ClassProposalView{
		ID:                      id,
		TenantID:                tenantID,
		AssetID:                 assetID,
		Source:                  source,
		Status:                  firstNonEmpty(c.Status, classProposalPending),
		ProposedClassKey:        c.ProposedClassKey,
		ProposedClassLabel:      classLabelOf(c.ProposedClassKey),
		CurrentClassKey:         c.CurrentClassKey,
		CurrentClassLabel:       classLabelOf(c.CurrentClassKey),
		CurrentSourceKind:       c.CurrentSourceKind,
		MatchedRules:            c.MatchedRules,
		RuleIDs:                 c.RuleIDs,
		Confidence:              c.Confidence,
		AcceptedClassKey:        c.AcceptedClassKey,
		ProposedClassSourceKind: c.SourceKind,
		ProposedClassSourceRef:  c.SourceRef,
		ModelID:                 c.ModelID,
		ModelProbability:        c.ModelProbability,
		ModelReasons:            c.ModelReasons,
	}
	for _, k := range c.ConflictingClasses {
		v.ConflictingClasses = append(v.ConflictingClasses, ClassOption{Key: k, Label: classLabelOf(k)})
	}
	if createdAt.Valid {
		v.ProposedAt = createdAt.Time
	}
	return v, nil
}

// classProposalAsset is the decoration one asset contributes.
type classProposalAsset struct {
	DisplayName string
	Hostname    string
	Address     string
	Status      string
}

func loadClassProposalAssets(ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]classProposalAsset, error) {
	out := map[uuid.UUID]classProposalAsset{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT id, COALESCE(display_name, ''), COALESCE(hostname, ''),
		       COALESCE(host(primary_address), ''), asset_status
		  FROM assets
		 WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND deleted_at IS NULL`,
		tenantID, pq.Array(uuidStrings(ids)))
	if err != nil {
		return nil, fmt.Errorf("decorate class proposals: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id uuid.UUID
		var a classProposalAsset
		if err := rows.Scan(&id, &a.DisplayName, &a.Hostname, &a.Address, &a.Status); err != nil {
			return nil, fmt.Errorf("scan class-proposal decoration: %w", err)
		}
		out[id] = a
	}
	return out, rows.Err()
}

func decorateClassProposal(v *ClassProposalView, a classProposalAsset) {
	v.AssetName, v.AssetHost, v.AssetAddress, v.AssetStatus = a.DisplayName, a.Hostname, a.Address, a.Status
}

func classLabelOf(key string) string {
	if key == "" {
		return ""
	}
	if c, ok := assetclass.Get(key); ok {
		return c.Label
	}
	return key
}

func optionKeys(opts []ClassOption) []string {
	if len(opts) == 0 {
		return nil
	}
	out := make([]string, 0, len(opts))
	for _, o := range opts {
		out = append(out, o.Key)
	}
	return out
}

func nullActor(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}
