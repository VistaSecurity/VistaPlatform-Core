package producer

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/redact"
)

// HistoryTable is where a finding's state transitions are recorded.
//
// The name is compliance-flavoured because the table predates the one-table
// move (workstream 3.1), which re-pointed its `finding_id` foreign key at
// `findings` and left the name alone. It is the findings history table for
// every producer; renaming it is a schema change with no behavioural payoff,
// and naming it once here stops six producers each hard-coding the surprise.
const HistoryTable = "compliance_finding_history"

// Subject is what a finding is about: a type from the registry's vocabulary and
// the id of the row of that type.
type Subject struct {
	Type string
	ID   uuid.UUID
}

// Finding is one condition a producer currently observes.
//
// The producer key is NOT here — it belongs to the [Writer], so a producer
// physically cannot write another producer's rows by filling in a struct field.
type Finding struct {
	// Kind is one of this producer's registered kinds.
	Kind string

	// Subject names the object measured. SubjectLabel is the display name to
	// stamp alongside it — a FALLBACK for a reader whose join finds nothing
	// because the row has since been archived, not the display path. Leave it
	// empty when nothing names the subject; empty is stored as NULL, because
	// "" would satisfy a `subject_label IS NOT NULL` check and then render as a
	// blank.
	Subject      Subject
	SubjectLabel string

	// Severity is one of the five stored severities; Score is its 0-100
	// contribution to the per-asset risk rollup. For a ladder kind the pair
	// must be one of the registry's rungs verbatim (see [Rung]); for a kind
	// whose feeds_risk is false, Score must be 0.
	Severity string
	Score    int

	// Summary is the one line a person reads first. The registry's
	// title_template is the shape; the producer substitutes and passes the
	// result here.
	Summary string

	// Evidence is the citation and the detail behind the judgement. It is
	// merged into whatever the row already carries rather than replacing it —
	// see [Writer.Upsert].
	Evidence map[string]any

	// SourceKind defaults to `measured`. A producer reading a mirrored
	// catalogue writes `imported`; one that asked a model writes `inferred`
	// (and owes the provenance ADR-0005 D2 requires alongside).
	SourceKind string

	// ControlID is the compliance producer's discriminator, and this writer
	// REFUSES a non-nil one.
	//
	// The field is here to state the rule rather than to offer the option.
	// `control_id` is part of the open-row identity and
	// findings_control_id_compliance_only_check confines it to producer =
	// 'compliance', so every producer this package serves leaves it NULL — and
	// because they all do, [Writer.Resolve] and [Writer.Sweep] can key on
	// `control_id IS NULL` and mean exactly the rows [Writer.Upsert] wrote. A
	// writer that accepted a control id on Upsert but ignored it on Sweep would
	// be the asymmetry that leaves rows nothing ever resolves.
	ControlID *uuid.UUID
}

// Result is what one [Writer.Upsert] did.
type Result struct {
	// ID is the finding's row id, whether it was created or reused.
	ID uuid.UUID
	// Created is true only for a genuine INSERT. A row reached through ON
	// CONFLICT is an update even on the first pass that raced another writer.
	Created bool
	// Reactivated is true when the row was INACTIVE and this pass brought it
	// back. The row is reused, not replaced, which is the whole reason the
	// unique index is keyed on `<> ARCHIVED` rather than `= ACTIVE`.
	Reactivated bool
	// PriorState is the detection_state the row held before this call, or ""
	// when there was no row.
	PriorState string
}

// Detection states, mirroring findings_detection_state_check.
const (
	StateActive   = "ACTIVE"
	StateInactive = "INACTIVE"
	StateArchived = "ARCHIVED"
)

// Writer writes one producer's findings.
//
// Construct it once per producer with [New]; it holds no connection and no
// state beyond the producer key and a clock, so it is safe to share.
type Writer struct {
	producer string
	// now is the clock, overridable in tests. Every timestamp one call writes
	// comes from ONE reading of it, so a finding's first_seen, last_seen and
	// history row cannot disagree by a few microseconds.
	now func() time.Time
}

// New builds the writer for a registered producer.
//
// An unregistered key is an error here rather than at the first write: a
// producer whose key is a typo would otherwise run a whole pass, write rows
// nothing reads, and report success.
func New(producerKey string) (*Writer, error) {
	if _, ok := findings.GetProducer(producerKey); !ok {
		return nil, fmt.Errorf("producer: %q is not in standards/findings-registry.yaml", producerKey)
	}
	return &Writer{producer: producerKey, now: time.Now}, nil
}

// Key is the producer this writer writes as.
func (w *Writer) Key() string { return w.producer }

// WithClock returns a copy of the writer using clock for its timestamps. For
// tests that need to place a finding's history at a known instant.
func (w *Writer) WithClock(clock func() time.Time) *Writer {
	cp := *w
	cp.now = clock
	return &cp
}

// upsertSQL is the whole lifecycle in one statement.
//
// # The `prior` CTE
//
// A plain SELECT in the same statement as the INSERT, so it is evaluated
// against the statement's snapshot and cannot see the insert the other CTE
// performs. It is how the call learns the state the row held BEFORE the write —
// which RETURNING cannot tell it, because RETURNING sees the new row. That
// state is what decides whether a history row is owed and whether this was a
// resurfacing, and reading it in a separate round trip would open a window in
// which another writer changed it.
//
// # The conflict target
//
// `(tenant_id, producer, kind, subject_type, subject_id, control_id) WHERE
// detection_state <> 'ARCHIVED'` is `findings_open_subject_uniq` spelled out.
// It must stay character-for-character the index's definition: Postgres matches
// a partial-index conflict target by inferring the index from the column list
// AND the predicate, so a drift here does not pick a different index — it fails
// to find one, and the statement errors. (That is the good direction. The bad
// one is omitting the WHERE, which would match no index at all.)
//
// # detection_state on conflict
//
// Written as the literal 'ACTIVE' rather than EXCLUDED's value: Upsert's whole
// meaning is "the producer still sees this", so there is no call shape where
// the answer is anything else. Resolve and Sweep are how a row leaves ACTIVE.
//
// # workflow_status and SUPPRESSED
//
// A resurfacing resets the human status to NEW so it comes back into the
// triage queue — UNLESS somebody suppressed it, which is a standing decision
// about the condition and not about one episode of it. Re-raising a suppressed
// finding on every nightly pass would make suppression mean nothing.
//
// # evidence
//
// `findings.evidence || EXCLUDED.evidence` — a shallow object merge where the
// incoming run wins per key. Idempotent by construction ((a||b)||b == a||b), so
// a converged re-run writes byte-identical evidence. The merge rather than a
// replace because the evidence object is SHARED SPACE: the compliance
// reconcile's crypto_implementation_ids, and anything a later surface annotates
// a finding with, live in the same document, and a producer restating its own
// keys has no business erasing somebody else's. A producer is expected to
// restate its WHOLE evidence each run — a key it stops writing is not removed.
const upsertSQL = `
WITH prior AS (
    SELECT id, detection_state
    FROM findings
    WHERE tenant_id = $1
      AND producer = $2
      AND kind = $3
      AND subject_type = $4
      AND subject_id = $5
      AND control_id IS NULL
      AND detection_state <> 'ARCHIVED'
),
ins AS (
    INSERT INTO findings (
        id, tenant_id, producer, kind, subject_type, subject_id, subject_label,
        control_id, severity, score, summary, evidence, source_kind,
        detection_state, workflow_status, occurrence_count,
        first_seen, last_seen, last_evaluated_at, created_at, updated_at
    ) VALUES (
        $6, $1, $2, $3, $4, $5, NULLIF($7, ''),
        NULL, $8, $9, $10, $11::jsonb, $12,
        'ACTIVE', 'NEW', 1,
        $13, $13, $13, $13, $13
    )
    ON CONFLICT (tenant_id, producer, kind, subject_type, subject_id, control_id)
        WHERE detection_state <> 'ARCHIVED'
    DO UPDATE SET
        subject_label     = COALESCE(EXCLUDED.subject_label, findings.subject_label),
        severity          = EXCLUDED.severity,
        score             = EXCLUDED.score,
        summary           = EXCLUDED.summary,
        evidence          = findings.evidence || EXCLUDED.evidence,
        source_kind       = EXCLUDED.source_kind,
        detection_state   = 'ACTIVE',
        workflow_status   = CASE
            WHEN findings.detection_state = 'INACTIVE' AND findings.workflow_status <> 'SUPPRESSED'
            THEN 'NEW' ELSE findings.workflow_status END,
        resurfaced_at     = CASE
            WHEN findings.detection_state = 'INACTIVE'
            THEN EXCLUDED.last_seen ELSE findings.resurfaced_at END,
        occurrence_count  = findings.occurrence_count + 1,
        last_seen         = EXCLUDED.last_seen,
        last_evaluated_at = EXCLUDED.last_evaluated_at,
        updated_at        = EXCLUDED.updated_at
    RETURNING id, (xmax = 0) AS inserted
)
SELECT ins.id, ins.inserted, COALESCE(prior.detection_state, '')
FROM ins LEFT JOIN prior ON true`

// Upsert records that this producer currently observes f.
//
// It creates the finding, or reuses the open row that already exists for the
// same (producer, kind, subject, control) — bumping occurrence_count, moving
// last_seen, merging evidence, and bringing an INACTIVE row back to ACTIVE with
// resurfaced_at stamped. There is never a second open row; the partial unique
// index enforces that and this statement is written against it.
//
// tx must already be scoped to tenantID's RLS session (database.WithTenantTx).
// The explicit tenant_id predicate is belt and braces, not a substitute.
func (w *Writer) Upsert(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, f Finding) (Result, error) {
	if tx == nil {
		return Result{}, fmt.Errorf("producer %s: Upsert needs a transaction", w.producer)
	}
	if tenantID == uuid.Nil {
		return Result{}, fmt.Errorf("producer %s: refusing to write a finding for the nil tenant", w.producer)
	}
	if err := w.validate(f); err != nil {
		return Result{}, err
	}

	evidence, err := marshalEvidence(f.Evidence)
	if err != nil {
		return Result{}, fmt.Errorf("producer %s/%s: %w", w.producer, f.Kind, err)
	}
	sourceKind := f.SourceKind
	if sourceKind == "" {
		sourceKind = SourceMeasured
	}

	now := w.now().UTC()
	var out Result
	err = tx.QueryRowContext(ctx, upsertSQL,
		tenantID, w.producer, f.Kind, f.Subject.Type, f.Subject.ID,
		uuid.New(), f.SubjectLabel,
		f.Severity, f.Score, f.Summary, evidence, sourceKind, now,
	).Scan(&out.ID, &out.Created, &out.PriorState)
	if err != nil {
		return Result{}, fmt.Errorf("producer %s/%s: upsert finding: %w", w.producer, f.Kind, err)
	}
	out.Reactivated = out.PriorState == StateInactive

	switch {
	case out.Created:
		w.history(ctx, tx, out.ID, "detection_state", "", StateActive, "Detected by the "+w.producer+" producer")
	case out.Reactivated:
		w.history(ctx, tx, out.ID, "detection_state", StateInactive, StateActive, "Condition returned")
	}
	return out, nil
}

// resolveSQL flips one open row to INACTIVE.
//
// Scoped to `detection_state = 'ACTIVE'` and not to `<> 'ARCHIVED'`: an already
// INACTIVE row needs no write, and touching it would move updated_at — which is
// the timestamp a reader uses to answer "when did this stop being detected",
// since the table has no resolved_at column. Re-resolving would therefore keep
// pushing that answer forward for a condition that went away weeks ago.
const resolveSQL = `
UPDATE findings
SET detection_state   = 'INACTIVE',
    last_evaluated_at = $6,
    updated_at        = $6
WHERE tenant_id = $1
  AND producer = $2
  AND kind = $3
  AND subject_type = $4
  AND subject_id = $5
  AND control_id IS NULL
  AND detection_state = 'ACTIVE'
RETURNING id`

// Resolve records that this producer no longer observes the condition on one
// subject: the row goes INACTIVE and keeps everything else.
//
// The row is NOT deleted and its workflow_status is NOT set to RESOLVED.
// Deleting would throw away occurrence_count and first_seen, which exist to
// carry the history across episodes; closing the workflow status is a PERSON's
// decision about whether anybody dealt with it, and a producer asserting it
// would sign off findings on a human's behalf. (compliance-engine's
// AutoCloseInactiveFindings closes its own producer's rows after a grace
// period, which is a policy, not a detection.)
//
// When did it resolve? `updated_at` on an INACTIVE row, and the history row
// this writes. There is deliberately no `resolved_at` column: it would be
// `updated_at` under another name for every row that has one, and NULL for
// every row that does not.
//
// Returns false when there was no ACTIVE row to resolve, which is not an error
// — a producer sweeping a subject it never raised anything for is the normal
// case.
func (w *Writer) Resolve(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, kind string, s Subject) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("producer %s: Resolve needs a transaction", w.producer)
	}
	if _, ok := findings.Get(w.producer, kind); !ok {
		return false, fmt.Errorf("producer: %q does not emit kind %q", w.producer, kind)
	}
	now := w.now().UTC()

	var id uuid.UUID
	err := tx.QueryRowContext(ctx, resolveSQL,
		tenantID, w.producer, kind, s.Type, s.ID, now).Scan(&id)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("producer %s/%s: resolve finding: %w", w.producer, kind, err)
	}
	w.history(ctx, tx, id, "detection_state", StateActive, StateInactive, "No longer detected")
	return true, nil
}

// sweepSQL inactivates every ACTIVE row of ONE producer and ONE kind whose
// subject is not in the seen set.
//
// The producer and kind predicates are the load-bearing part. A sweep is a
// producer saying "this is everything I see"; without them it would be a claim
// about every producer's findings, and the eol producer's nightly pass would
// quietly inactivate the compliance producer's violations. `NOT EXISTS` over
// an unnest rather than `NOT IN`, because `NOT IN` against an empty array is
// fine but `NOT IN` against anything carrying a NULL is silently false for
// every row — and the two spellings look identical at review.
const sweepSQL = `
UPDATE findings
SET detection_state   = 'INACTIVE',
    last_evaluated_at = $4,
    updated_at        = $4
WHERE tenant_id = $1
  AND producer = $2
  AND kind = $3
  AND control_id IS NULL
  AND detection_state = 'ACTIVE'
  AND NOT EXISTS (
      SELECT 1 FROM unnest($5::text[], $6::uuid[]) AS s(subject_type, subject_id)
      WHERE s.subject_type = findings.subject_type
        AND s.subject_id = findings.subject_id
  )
RETURNING id`

// Sweep inactivates everything this producer no longer asserts for one kind.
//
// A producer's run is a FULL STATEMENT of what it currently sees: whatever it
// Upserted this pass is `seen`, and every other ACTIVE row of the same
// (producer, kind) is a condition that has gone away. Passing an EMPTY seen set
// therefore inactivates all of them, which is correct and is also why this must
// only be called after a pass that COMPLETED. A run that failed half way
// through has not made a full statement about anything, and sweeping on its
// partial answer would inactivate live findings and re-raise them tomorrow —
// resetting workflow status, re-notifying, and making the history unreadable.
//
// Returns how many rows it inactivated.
func (w *Writer) Sweep(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, kind string, seen []Subject) (int, error) {
	if tx == nil {
		return 0, fmt.Errorf("producer %s: Sweep needs a transaction", w.producer)
	}
	if _, ok := findings.Get(w.producer, kind); !ok {
		return 0, fmt.Errorf("producer: %q does not emit kind %q", w.producer, kind)
	}

	types := make([]string, 0, len(seen))
	ids := make([]string, 0, len(seen))
	for _, s := range seen {
		types = append(types, s.Type)
		ids = append(ids, s.ID.String())
	}

	now := w.now().UTC()
	rows, err := tx.QueryContext(ctx, sweepSQL,
		tenantID, w.producer, kind, now, pq.Array(types), pq.Array(ids))
	if err != nil {
		return 0, fmt.Errorf("producer %s/%s: sweep findings: %w", w.producer, kind, err)
	}
	var swept []uuid.UUID
	func() {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id uuid.UUID
			if scanErr := rows.Scan(&id); scanErr != nil {
				err = scanErr
				return
			}
			swept = append(swept, id)
		}
		err = rows.Err()
	}()
	if err != nil {
		return 0, fmt.Errorf("producer %s/%s: sweep findings: %w", w.producer, kind, err)
	}

	for _, id := range swept {
		w.history(ctx, tx, id, "detection_state", StateActive, StateInactive, "No longer detected")
	}
	return len(swept), nil
}

// history records one state change.
//
// Best-effort: the history is an audit trail BESIDE the finding, and failing
// the producer's whole transaction because the trail could not be appended
// would lose the finding as well as its history.
//
// # The SAVEPOINT is what makes "best-effort" true
//
// Ignoring an error inside a transaction does not undo it. Postgres aborts the
// whole transaction on any failed statement, so a swallowed failure here poisons
// the caller's tx: every subsequent Upsert in the same pass comes back
// `current transaction is aborted` / `could not complete operation in a failed
// transaction`, the run dies, and the error names a statement that has nothing
// to do with the cause. That is the shape of a comment asserting a guarantee
// the code does not provide — this package's own contract suite hit it under
// cross-binary lock contention before the savepoint existed.
//
// So the INSERT runs inside a savepoint and a failure rolls back to it, leaving
// the transaction usable. The error still reaches historyErrorSink, because a
// bookkeeping failure that is only swallowed is the kind nobody finds.
func (w *Writer) history(ctx context.Context, tx *sql.Tx, findingID uuid.UUID, field, oldValue, newValue, reason string) {
	const savepoint = "vp_finding_history"
	if _, err := tx.ExecContext(ctx, "SAVEPOINT "+savepoint); err != nil {
		// The transaction is already unusable; there is nothing to protect and
		// nothing this can do about it. The caller's next statement reports it.
		w.reportHistoryError(findingID, err)
		return
	}

	_, err := tx.ExecContext(ctx, `
		INSERT INTO `+HistoryTable+` (finding_id, changed_by, changed_at, field_name, old_value, new_value, change_reason)
		VALUES ($1, NULL, $2, $3, $4, $5, $6)`,
		findingID, w.now().UTC(), field, oldValue, newValue, reason)
	if err != nil {
		if _, rbErr := tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT "+savepoint); rbErr != nil {
			w.reportHistoryError(findingID, rbErr)
		}
		w.reportHistoryError(findingID, err)
		return
	}
	// Released rather than left open: a savepoint per history row would pile up
	// across a pass over thousands of subjects, and each one holds resources
	// until the transaction ends.
	if _, err := tx.ExecContext(ctx, "RELEASE SAVEPOINT "+savepoint); err != nil {
		w.reportHistoryError(findingID, err)
	}
}

func (w *Writer) reportHistoryError(findingID uuid.UUID, err error) {
	if historyErrorSink != nil {
		historyErrorSink(w.producer, findingID, err)
	}
}

// historyErrorSink is where a failed history append is reported. A package
// variable rather than a direct log call so a test can observe it; nil means
// discard, which is the production default because the caller's logger is the
// one with the run's context on it.
var historyErrorSink func(producerKey string, findingID uuid.UUID, err error)

// SetHistoryErrorSink installs the reporter for failed history appends. Pass
// nil to discard. Not safe to call concurrently with a write.
func SetHistoryErrorSink(f func(producerKey string, findingID uuid.UUID, err error)) {
	historyErrorSink = f
}

// marshalEvidence renders the evidence object, with the rail's two backstops
// applied on the way: redaction (security review X.5, X5-06) and the size cap
// (evidence_cap.go).
//
// Redaction first, capping second. The cap can drop a key, and a key that is
// dropped is a key whose value was never asked whether it was a credential —
// which would be a hole in the redaction backstop opened by the size of the
// document rather than by its content.
//
// A nil map becomes `{}` rather than SQL NULL: the column is NOT NULL with a
// `{}` default, and the merge `findings.evidence || EXCLUDED.evidence` yields
// NULL if either side is NULL — which would erase an existing row's whole
// evidence document the first time a producer wrote a finding with none.
func marshalEvidence(e map[string]any) ([]byte, error) {
	if len(e) == 0 {
		return []byte("{}"), nil
	}
	capped := capEvidence(redactEvidence(e))
	raw, err := json.Marshal(capped)
	if err != nil {
		return nil, fmt.Errorf("evidence is not JSON: %w", err)
	}
	raw, err = capEvidenceBytes(capped, raw)
	if err != nil {
		return nil, fmt.Errorf("evidence is not JSON: %w", err)
	}
	return raw, nil
}

// redactEvidence is this rail's backstop: the layer that exists because layer 1
// depends on a human remembering.
//
// Every other rail in this codebase has one — Registry.Get wraps each
// interrogator in deviceinterrogation.Sanitize, the host-inventory intake
// re-sanitises, the AI boundary redacts — and `findings.evidence` is a jsonb
// the UI renders and the remediator seam reads, written verbatim by six
// producers built in parallel. Nothing leaks through it today: every key in use
// is an explicitly named, platform-derived value. The point is the NEXT
// producer, which is who a backstop is for.
//
// # Two rules, and one rule deliberately not applied
//
//  1. A key this package has NAMED as a credential is masked:
//     redact.IsExplicitSecretName. A producer writing evidence["password"] has
//     a programming error, and the value does not reach the database.
//  2. PEM private-key blocks inside string values are masked
//     (redact.TextPEM). That is the package's one value-shaped rule, and it
//     over-redacts nothing: CERTIFICATE and PUBLIC KEY blocks pass through
//     untouched, and a private key in a finding's evidence is never the answer.
//
// What is NOT applied is redact.Map, and the difference is the whole design.
// Map uses IsSecretName, whose catch-all is `strings.HasSuffix(name, "key")` —
// and the drift producer's evidence carries `observation_key`, the finding's
// own identity and the thing a re-run matches on, while class evidence carries
// `class_key`. Masking either would break a producer silently, which is the
// over-strict polarity of exactly the bug this backstop is for. Those two are
// safe here by CONSTRUCTION rather than by an allowlist: no named fragment is a
// substring of them, so no list has to be kept in step as producers are added.
//
// Mask rather than refuse. Refusing would lose a whole pass over thousands of
// subjects because one producer named one key badly, and the masked value is
// still a finding a person can act on.
func redactEvidence(e map[string]any) map[string]any {
	out := make(map[string]any, len(e))
	for k, v := range e {
		if redact.IsExplicitSecretName(k) {
			out[k] = redact.Marker
			continue
		}
		out[k] = redactEvidenceValue(v)
	}
	return out
}

// redactEvidenceValue walks a value with the same two rules. Nested maps are
// walked by key, because `baseline` and `observed` are maps and a credential
// one level down is still a credential.
func redactEvidenceValue(v any) any {
	switch t := v.(type) {
	case string:
		return redact.TextPEM(t)
	case map[string]any:
		return redactEvidence(t)
	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = redactEvidenceValue(item)
		}
		return out
	default:
		return v
	}
}
