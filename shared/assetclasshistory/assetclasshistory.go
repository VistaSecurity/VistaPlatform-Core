// Package assetclasshistory records every class an asset has held.
//
// # Why it exists
//
// An asset's class lives in ONE mutable column. Change it and the previous
// answer is gone: a printer that becomes a multifunction device has always been
// a multifunction device, as far as anything reading the database can tell.
//
// That is not a cosmetic loss. Class is an INPUT to most of the platform — the
// producers pick which findings apply by it, the approval rules match on it,
// the compliance measurements scope by it — and every one of them writes a
// conclusion that was true of the class the asset held at the time. When the
// class moves and nothing says so, the stale conclusions are indistinguishable
// from current ones, and the first question anybody asks about a surprising
// finding ("was this thing reclassified?") has no answer anywhere.
//
// # Why `asset_history` is not already this
//
// `asset_history` carries a `created` row whose `changes_json` happens to
// mention `class_key`, and carried nothing at all for the two paths that CHANGE
// a class — the proposal acceptance and the manual edit both wrote the column
// and moved on. Reconstructing a timeline from it would mean parsing a
// free-shaped jsonb blob per action kind, and a consumer that has to parse
// somebody else's blob is a consumer that breaks the next time the blob's
// author adds a field.
//
// # What this package is not
//
// It is not an authority. Nothing reads `asset_class_history` to decide what an
// asset IS — `assets.class_key` is that, and always will be. This is the record
// of how it got there, written beside the change, in the change's own
// transaction.
//
// It is also not a place for evidence with a body: the `evidence` map takes the
// argument's IDENTIFIERS — rule ids, a model id and its probability, the
// proposal id — and never a hostname, an address, a credential or a command
// transcript. The call sites build it from the class proposal's own recorded
// fields, which carry none of those by construction.
package assetclasshistory

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// The mechanisms by which a class can move. A closed set, matching the
// `asset_class_history_source_check` constraint, because a consumer branches on
// it: "a person said so" and "a rule argued it" are not the same claim.
const (
	// SourceProposal is a reviewer accepting a class proposal in Approvals.
	// The class came from a rule or the model; the DECISION came from a person,
	// and `actor_user_id` names them.
	SourceProposal = "proposal"

	// SourceManual is somebody editing the asset directly. `class_source_kind`
	// on the asset becomes `declared`, which outranks every machine.
	SourceManual = "manual"

	// SourceImport is a connector or a spreadsheet stating the class.
	SourceImport = "import"

	// SourceClassifier is the intake path: an asset created with a class the
	// rules argued or a collector measured. It is the only source that produces
	// a row with no `from_class_key`, because there was no previous class.
	SourceClassifier = "classifier"
)

// Tx is the transaction a record is written on.
//
// An interface rather than a concrete handle for the same reason
// classproposal.Tx is one: the call sites hold three different types
// (*sqlx.Tx, *sql.Tx, and the identity repository's own). It MUST be the
// transaction that changed the class — a history row committed beside a change
// that rolled back is a record of something that did not happen.
type Tx interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// Entry is one transition.
type Entry struct {
	// From is the class the asset held. Empty means it held none, which is only
	// true on creation.
	From string
	// To is the class it now holds. Required.
	To string
	// Source is one of the constants above.
	Source string
	// Actor is the person who caused it, or uuid.Nil for a machine. Nil means
	// "no person", never "person unknown": every path with a session passes
	// one, and the paths that do not are machine paths.
	Actor uuid.UUID
	// Evidence is the argument, as identifiers. Never key material, never a
	// transcript, never a hostname. Nil is fine.
	Evidence map[string]any
}

// Record writes one transition, or nothing.
//
// Nothing when the class did not move. A "change" from a class to itself is not
// a change, and the table's whole value is that every row in it means something
// moved — the database refuses such a row too (`asset_class_history_moves_check`),
// so this is the readable half of a rule that is also structural.
//
// An empty To is an error rather than a silent skip: a caller that lost the new
// class has a bug, and swallowing it here would make the history quietly
// incomplete, which is the failure mode this package exists to end.
func Record(ctx context.Context, tx Tx, tenantID, assetID uuid.UUID, e Entry) error {
	from := strings.TrimSpace(e.From)
	to := strings.TrimSpace(e.To)
	if to == "" {
		return fmt.Errorf("assetclasshistory: refusing to record a move to no class at all")
	}
	if from == to {
		return nil
	}
	if !validSource(e.Source) {
		return fmt.Errorf("assetclasshistory: %q is not a class-change source", e.Source)
	}

	evidence := []byte("{}")
	if pruned := pruneEmpty(e.Evidence); len(pruned) > 0 {
		encoded, err := json.Marshal(pruned)
		if err != nil {
			return fmt.Errorf("assetclasshistory: encode evidence: %w", err)
		}
		evidence = encoded
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO asset_class_history
		    (tenant_id, asset_id, from_class_key, to_class_key, source, actor_user_id, evidence)
		VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6, $7::jsonb)`,
		tenantID, assetID, from, to, e.Source, nullUUID(e.Actor), string(evidence)); err != nil {
		return fmt.Errorf("assetclasshistory: record the class change: %w", err)
	}
	return nil
}

// pruneEmpty drops the entries a caller could not fill.
//
// The evidence map is built by call sites that do not know which PRODUCER the
// class came from: a rule-derived proposal has no model id or probability, and
// a model-derived one has no rule ids. Writing those as `""` and `0` would not
// be an absence, it would be a claim — "the model scored this at 0.0" — on a
// row whose only purpose is to be read later by somebody asking why.
//
// A boolean `false` is kept, and so is a zero that arrives as an int rather
// than a float: `false` is an answer, and demoting it is the jq `//` mistake.
// Only the forms that actually mean "nothing to say here" are dropped.
func pruneEmpty(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch typed := v.(type) {
		case nil:
			continue
		case string:
			if strings.TrimSpace(typed) == "" {
				continue
			}
		case float64:
			if typed == 0 {
				continue
			}
		case []string:
			if len(typed) == 0 {
				continue
			}
		}
		out[k] = v
	}
	return out
}

func validSource(s string) bool {
	switch s {
	case SourceProposal, SourceManual, SourceImport, SourceClassifier:
		return true
	default:
		return false
	}
}

// nullUUID turns the zero uuid into a NULL. A machine has no actor, and
// `00000000-0000-0000-0000-000000000000` in a column an FK will one day point
// at is a user id that names nobody.
func nullUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

// SourceForClassProvenance maps an asset's `class_source_kind` onto the
// mechanism that produced it, for the CREATE path — the one place where the
// history row is written from the asset's provenance rather than from a call
// site that knows what it is doing.
//
// `declared` is a person (the declared-class paths are the manual edit and the
// class picker), `imported` is a connector or a spreadsheet, and everything
// else — `measured`, `rule`, `inferred` — is the intake classifying. Anything
// unrecognised is `classifier` too: an asset appearing with a class it did not
// get from a person or an import got it from the intake, whatever the column
// spells.
func SourceForClassProvenance(classSourceKind string) string {
	switch strings.TrimSpace(strings.ToLower(classSourceKind)) {
	case "declared":
		return SourceManual
	case "imported":
		return SourceImport
	default:
		return SourceClassifier
	}
}
