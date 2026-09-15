// Package classproposal is what an intake owes the CLASS of the asset it just
// resolved: a proposal, or nothing.
//
// # Why it is shared
//
// Workstream 2.10b built this inside inventory-service, where the three intake
// paths that classify live. device-interrogation-service classifies too — an
// interrogated peer described only by a chassis MAC is exactly the case the
// curated rule table exists for — but it had no proposal writer, so a class the
// rules or the model decided for an EXISTING peer was computed and then
// dropped on the floor (BUILD_PLAN 4.2/2.10b, stated as a scope limit).
//
// Giving it one meant either a second copy of these rules or one home for them.
// A second copy is the worse half: the four "write nothing" cases below are the
// difference between a queue a reviewer reads and a queue that re-asks a
// question they already answered, and rules like that do not stay identical in
// two files. So they live here and both services call [Record].
//
// # What this never does
//
// It never turns `unknown` into a guess. The engine answers Unknown when the
// rules do not decide, INCLUDING when they decide two, and this package
// forwards that verbatim — the asset stays `unknown_host` and, for the
// two-answer case, a proposal names the classes that disagreed so the CATALOGUE
// can be fixed rather than the asset guessed at.
//
// It never sets a class on an existing asset. ADR-0008 D3 sends a machine's
// proposal through Approvals, and ADR-0002 D5 forbids the auto-decide; a rule
// that changed its mind six months after somebody approved a class would be a
// silent rewrite of the inventory.
package classproposal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/classify"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

const (
	// Kind is the `changes_json.kind` discriminator, matching the
	// `merge_proposal` convention: one action can carry more than one shape of
	// row over time, and a reader that assumed otherwise is how a queue starts
	// showing rows it cannot render.
	Kind = "class_proposal"

	// StatusPending is a proposal nobody has decided yet. Absent means pending
	// — the partial unique index coalesces the two.
	StatusPending = "pending"

	// StatusAccepted and StatusRejected are what a reviewer's decision stamps.
	StatusAccepted = "accepted"
	StatusRejected = "rejected"
)

// Tx is the transaction [Record] runs on.
//
// An interface rather than a concrete handle because the two services hold
// different ones: inventory-service's intake speaks *sqlx.Tx and
// device-interrogation-service's identity repository hands out a raw *sql.Tx.
// Both satisfy this.
//
// It MUST be the transaction the asset was resolved on. A proposal committed
// against an asset whose creation rolled back is a queue item pointing at
// nothing.
type Tx interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// Changes is the `changes_json` payload of a class proposal, shared by the
// writer here and the reader in inventory-service so the two cannot disagree
// about a key name.
type Changes struct {
	// Kind is the discriminator. See [Kind].
	Kind string `json:"kind"`

	// ProposedClassKey is the class the rules argued, or "" when they
	// contradicted each other. The key is always PRESENT, because the partial
	// unique index keys on it and `changes_json ? 'proposed_class_key'` is what
	// decides whether a row is in that index at all.
	ProposedClassKey string `json:"proposed_class_key"`

	// CurrentClassKey is what the asset is classed as now, so the proposal
	// reads as a comparison rather than as an assertion.
	CurrentClassKey   string `json:"current_class_key,omitempty"`
	CurrentSourceKind string `json:"current_class_source_kind,omitempty"`

	// ConflictingClasses are the classes that tied when the rules disagreed.
	// A reviewer picks one, or rejects the lot; the disagreement itself is a
	// curation bug and this is what names it.
	ConflictingClasses []string `json:"conflicting_classes,omitempty"`

	// ConflictKey identifies WHICH disagreement this is: the conflicting
	// classes, sorted and joined. It is the dedupe key for a conflict proposal,
	// the way ProposedClassKey is for a class one.
	//
	// A conflict names no class, so both ends of a conflict proposal used to
	// key on the same empty string — and the partial unique index therefore
	// allowed ONE pending conflict per asset, whatever it was about. An asset
	// the catalogue argued over twice showed the reviewer the first
	// disagreement and swallowed the second. This is what tells them apart.
	//
	// SORTED, so `printer|switch` and `switch|printer` are one question: the
	// engine returns the tied classes in the order they scored, and a rule edit
	// that changes only the order does not change the disagreement.
	ConflictKey string `json:"conflict_key,omitempty"`

	// RuleIDs are the rules behind the proposal, highest confidence first.
	RuleIDs []string `json:"rule_ids,omitempty"`

	// MatchedRules is the full argument — pattern, confidence and citation per
	// rule, as they were when the proposal was raised. A copy rather than a
	// pointer for the same reason classify.RuleRef is one: a reviewer asking
	// "why does this say switch" needs what the rule said AT THE TIME.
	MatchedRules []classify.RuleRef `json:"matched_rules,omitempty"`

	Confidence float64 `json:"confidence,omitempty"`

	// Status is `pending` until somebody decides, then `accepted` or
	// `rejected`. Absent means pending — the partial index coalesces the two
	// with COALESCE, so an older row with no status still counts.
	Status string `json:"status,omitempty"`

	// AcceptedClassKey records WHICH class a reviewer took, which is not always
	// ProposedClassKey: a conflict proposal offers a choice.
	AcceptedClassKey string `json:"accepted_class_key,omitempty"`

	// SourceKind and SourceRef are the provenance an ACCEPTANCE will stamp onto
	// the asset: `rule` + `rule:<id>` for a class the curated table argued,
	// `inferred` + `model:<id>` for one the learned classifier proposed
	// (workstream 4.2).
	//
	// Recorded on the proposal rather than re-derived at acceptance, because
	// the two are separated by however long the queue takes: the rules can be
	// edited and the model retrained in between, and the provenance a reviewer
	// was shown is the provenance the asset should carry.
	//
	// Absent means `rule`, which is what every row written before 4.2 is.
	SourceKind string `json:"class_source_kind,omitempty"`
	SourceRef  string `json:"class_source_ref,omitempty"`

	// ModelID, ModelProbability and ModelReasons are the learned classifier's
	// half of the argument: which weights proposed it, the calibrated
	// probability, and the top feature contributions behind it.
	//
	// ModelReasons names FEATURES, never raw values — a banner token or a
	// vendor is fine, a hostname is not. The model's whole input is
	// classify.ClassifyInput, which carries neither a hostname nor an address.
	ModelID          string                 `json:"model_id,omitempty"`
	ModelProbability float64                `json:"model_probability,omitempty"`
	ModelReasons     []classify.ModelReason `json:"model_reasons,omitempty"`
}

// JSON encodes the payload.
func (c Changes) JSON() ([]byte, error) { return json.Marshal(c) }

// Source is the `asset_history.source` a proposal is written under, and what
// the Approvals source facet reads to say who is asking.
//
// Both start `classifier:`, which is what the facet keys on, so a model
// proposal lands under "Proposed by classifier" beside a rule one rather than
// falling through to "Discovered" — which would tell a reviewer a sensor said
// so. The half after the colon is what distinguishes the two producers.
func Source(prop classify.ClassProposal) string {
	if prop.ModelID != "" {
		return "classifier:model"
	}
	return "classifier:rules"
}

// Provenance is the class_source_kind and class_source_ref an acceptance of this
// proposal will write.
//
// `rule` and `inferred` are NOT interchangeable. A class argued from a curated
// rule is deterministic and cites a source; a class a model proposed is
// ADR-0008 D4.2's "something a model proposed" and is priced accordingly. Both
// would pass every database constraint, so nothing but this function stands
// between the two on the one field a reviewer uses to audit a class.
func Provenance(prop classify.ClassProposal) (kind, ref string) {
	if prop.ModelID != "" {
		return string(identity.ClassSourceInferred), "model:" + prop.ModelID
	}
	return string(identity.ClassSourceRule), TopRuleRef(prop)
}

// TopRuleRef is what `class_source_ref` records for a rule-derived class: the
// id of the highest-confidence rule that argued the class the engine chose.
//
// The id and not the pattern, because the id is what Catalog ▸ Classification
// rules edits and what survives an edit to the pattern. A rule from the
// COMPILED-IN table has no id — that is the fallback engine, and a class it
// argued honestly has no curated row to point at — so the ref falls back to
// naming the kind and pattern, which is still something a reviewer can search
// for.
func TopRuleRef(prop classify.ClassProposal) string {
	for _, r := range prop.MatchedRules {
		if r.Class != prop.Class {
			continue
		}
		if r.ID != "" {
			return "rule:" + r.ID
		}
		return "rule:" + r.Kind + ":" + r.Pattern
	}
	return "rule"
}

// RuleIDsOf lists the matched rules that argued for `class`, highest confidence
// first. Only the ones that argued for it: a proposal that cited every rule that
// happened to match would include the ones whose class LOST, which is evidence
// for a different answer.
func RuleIDsOf(prop classify.ClassProposal, class string) []string {
	var out []string
	for _, r := range prop.MatchedRules {
		if class != "" && r.Class != class {
			continue
		}
		if r.ID != "" {
			out = append(out, r.ID)
		}
	}
	return out
}

// IsFallbackClassHint reports whether a hint is really "no opinion".
//
// `unknown_host` and `external` are what the intake builders write when they
// have none; treating either as an opinion would mean the rules never got to
// answer at all.
func IsFallbackClassHint(hint string) bool {
	switch strings.TrimSpace(hint) {
	case "", string(assetclass.KeyUnknownHost), string(assetclass.KeyExternal):
		return true
	default:
		return false
	}
}

// Apply puts a RULE's answer onto an observation about to be resolved, and
// reports whether it did.
//
// It only fills a hint the builder did not already have. A class the intake path
// itself established — a cloud collector reading the provider's own resource
// type through shared/assetclass, a user picking one in the class picker, a
// vendor collector that read the device's own model string — is a better answer
// than a rule's, and overwriting it would be the classifier arguing with a
// measurement.
//
// # A MODEL's answer is never applied here
//
// Workstream 4.2 chained the learned classifier beneath the rules, and a class
// it proposed carries `ModelID`. That class does NOT go onto the observation, on
// a new asset or an existing one: it goes to Approvals as a proposal, every
// time, and [Record] is what raises it. A rule is deterministic and cites a
// source, so creating an asset with its class and letting the asset's own
// approval cover it is honest; a model is neither, so the same shortcut would
// mean a machine's guess entering the inventory with nobody having read it —
// which is exactly what ADR-0008 D3 forbids.
func Apply(obs *identity.Observation, prop classify.ClassProposal) bool {
	if obs == nil || prop.Class == "" || prop.ModelID != "" || !IsFallbackClassHint(obs.ClassHint) {
		return false
	}
	obs.ClassHint = prop.Class
	obs.ClassProvenance = identity.ClassProvenance{
		Kind:       identity.ClassSourceRule,
		Ref:        TopRuleRef(prop),
		Confidence: prop.Confidence,
	}
	return true
}

// Record writes whatever a resolution owes the class: a proposal, or nothing.
//
// It runs on the ENGINE's transaction, so a proposal and the asset it is about
// land together or not at all.
//
// Four cases, and three of them write nothing:
//
//  1. The asset was CREATED and the RULES decided. The class is already on it,
//     with `rule` provenance, and the asset is in Approvals — approving it
//     approves the class. Proposing it as well would ask one question twice and
//     let a reviewer answer it two ways.
//  2. The rules decided nothing and did not conflict. There is nothing to
//     propose; `unknown_host` is the answer and it is a true one.
//  3. The asset's class is DECLARED. A person said what this is, and a rule does
//     not reopen that at any confidence — ADR-0008 D4.2's rule, applied to the
//     class column.
//  4. Otherwise — an existing asset whose class is a fallback, or was itself
//     rule- or measurement-derived and now differs, or a conflict — a proposal.
//
// Case 1 is deliberately narrower than it reads: it covers a class a RULE
// argued, not a class the MODEL proposed (workstream 4.2). A model's answer
// never reaches the asset at creation — [Apply] declines to set it — so there is
// nothing for the asset's own approval to cover, and skipping the proposal here
// would drop the model's answer on the floor. The two halves have to agree,
// which is why deleting either one fails
// TestIntegration_ClassifierModel_NeverSetsAClassOnANewAsset.
func Record(
	ctx context.Context, tx Tx, tenantID, assetID uuid.UUID,
	outcome identity.Outcome, prop classify.ClassProposal,
) error {
	if prop.Class == "" && !prop.Conflict {
		return nil
	}
	if outcome == identity.OutcomeCreated && !prop.Conflict && prop.ModelID == "" {
		return nil
	}

	current, sourceKind, err := CurrentClassOf(ctx, tx, tenantID, assetID)
	if err != nil {
		return err
	}
	if current == "" {
		// The asset is gone (soft-deleted between resolution and here), or was
		// never written — the contested path resolves to no asset at all. There
		// is nothing to propose about.
		return nil
	}
	if sourceKind == string(identity.ClassSourceDeclared) {
		return nil
	}
	if prop.Class != "" && prop.Class == current {
		// The rules agree with what the asset already says. Silence is right:
		// a proposal to change nothing is queue noise a reviewer has to read in
		// order to discover it was pointless.
		return nil
	}
	if prop.Class == "" && classIn(prop.ConflictingClasses, current) {
		// A CONFLICT proposes no class, so the check above cannot see that the
		// question has already been answered — and a conflict is exactly the
		// case where the evidence never changes, because the disagreement is in
		// the CATALOGUE. Without this, a reviewer who settles "printer or
		// network device?" by choosing one is asked the same thing on the next
		// coalescing window, for ever: the accepted proposal has dropped out of
		// the partial unique index, and `class_rejected` — the other
		// suppression — was never written, because they accepted.
		//
		// The asset already IS one of the classes being argued over, whoever
		// put it there. There is nothing left to propose until the catalogue
		// changes its mind about a class the asset does not hold.
		return nil
	}

	rejected, err := rejectedBefore(ctx, tx, tenantID, assetID, prop.Class)
	if err != nil {
		return err
	}
	if rejected {
		// Somebody has already said no to exactly this. Re-proposing it on the
		// next observation of unchanged evidence is how a queue becomes
		// unreadable, and it is why the `class_rejected` row survives at all.
		return nil
	}

	provenanceKind, provenanceRef := Provenance(prop)
	changes := Changes{
		Kind:               Kind,
		ProposedClassKey:   prop.Class,
		CurrentClassKey:    current,
		CurrentSourceKind:  sourceKind,
		ConflictingClasses: prop.ConflictingClasses,
		ConflictKey:        ConflictKeyOf(prop),
		RuleIDs:            RuleIDsOf(prop, prop.Class),
		MatchedRules:       prop.MatchedRules,
		Confidence:         prop.Confidence,
		Status:             StatusPending,
		SourceKind:         provenanceKind,
		SourceRef:          provenanceRef,
		ModelID:            prop.ModelID,
		ModelProbability:   prop.ModelProbability,
		ModelReasons:       prop.ModelReasons,
	}
	payload, err := changes.JSON()
	if err != nil {
		return fmt.Errorf("encode class proposal: %w", err)
	}

	// ON CONFLICT DO NOTHING against the partial unique index. The same
	// evidence arrives on every coalescing window, and a second proposal for
	// one question is not an error — it is the same question.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO asset_history (tenant_id, asset_id, source, action, changes_json)
		VALUES ($1, $2, $3, 'class_proposed', $4::jsonb)
		ON CONFLICT DO NOTHING`,
		tenantID, assetID, Source(prop), string(payload)); err != nil {
		return fmt.Errorf("record class proposal: %w", err)
	}
	return nil
}

// ConflictKeyOf is the dedupe key for a CONFLICT proposal: the tied classes,
// sorted and joined with a byte a class key cannot contain (keys are
// lower_snake_case). Empty for a proposal that names a class — that one keys on
// the class itself.
//
// A COPY is sorted rather than the proposal's own slice: ConflictingClasses is
// the reviewer-facing list and arrives in the order the classes SCORED, which
// is information, and sorting it in place would quietly reorder what the
// Approvals row shows.
func ConflictKeyOf(prop classify.ClassProposal) string {
	if prop.Class != "" || len(prop.ConflictingClasses) == 0 {
		return ""
	}
	sorted := append([]string(nil), prop.ConflictingClasses...)
	sort.Strings(sorted)
	return strings.Join(sorted, "|")
}

// classIn reports whether key is one of the classes a conflict named. A helper
// rather than slices.Contains inline, so the call site reads as the question it
// is asking.
func classIn(classes []string, key string) bool {
	if key == "" {
		return false
	}
	for _, c := range classes {
		if c == key {
			return true
		}
	}
	return false
}

// CurrentClassOf reads what an asset is classed as now, and how that was
// decided. Empty class means the asset is not there.
func CurrentClassOf(ctx context.Context, tx Tx, tenantID, assetID uuid.UUID) (string, string, error) {
	var class, kind string
	err := tx.QueryRowContext(ctx, `
		SELECT class_key, COALESCE(class_source_kind, '')
		  FROM assets
		 WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`, tenantID, assetID).Scan(&class, &kind)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("read the asset's current class: %w", err)
	}
	return class, kind, nil
}

// rejectedBefore reports whether a reviewer has already rejected this exact
// class for this asset.
//
// It reads the `class_rejected` rows rather than the stamped proposals, because
// the partial unique index covers only the PENDING ones — deliberately, since an
// index that also covered the decided ones could never record a second decision.
func rejectedBefore(ctx context.Context, tx Tx, tenantID, assetID uuid.UUID, classKey string) (bool, error) {
	var exists bool
	err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM asset_history
			 WHERE tenant_id = $1 AND asset_id = $2
			   AND action = 'class_rejected'
			   AND changes_json->>'proposed_class_key' = $3)`,
		tenantID, assetID, classKey).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check for a rejected class proposal: %w", err)
	}
	return exists, nil
}
