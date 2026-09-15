// Package producertest is the contract suite every finding producer runs.
//
// The lifecycle rules in [producer] are not visible in a producer's own unit
// tests — they live in one SQL statement and a partial unique index, and the
// ways they go wrong (a second open row, a resurfacing that loses its history,
// a sweep that reaches another producer's rows) all look like success from the
// calling side. So each producer runs this suite against a real Postgres with
// its OWN producer key and kinds, and what it proves is that THAT producer's
// rows obey the contract — not that some example producer does.
//
// Usage, from a producer's `*_integration_test.go`:
//
//	func TestIntegration_EOLProducer_WriterContract(t *testing.T) {
//	    owner := testdb.Connect(t)
//	    app := testdb.ConnectAsAppRole(t, owner)
//	    producertest.Run(t, producertest.Config{
//	        DB:          app,
//	        Owner:       owner,
//	        Producer:    findings.ProducerEOL,
//	        Kind:        findings.KindOSEndOfLife,
//	        OtherKind:   findings.KindHardwareEndOfSupport,
//	        SubjectType: findings.SubjectAsset,
//	    })
//	}
//
// The suite writes only `findings` and `compliance_finding_history` rows for
// the tenant it is given, and uses random uuids as subject ids — `subject_id`
// carries no foreign key, deliberately, because a finding's subject may be any
// of nine kinds of row.
package producertest

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Config names the producer under test.
type Config struct {
	// DB is an RLS-subject handle (testdb.ConnectAsAppRole), because the
	// contract includes "every statement works under the tenant's RLS session".
	// Running the suite on the owner or bypass role would prove less than it
	// looks like it proves.
	DB *sql.DB

	// Owner is the owner handle, used ONLY to mint a throwaway tenant per case.
	//
	// Per case, not per suite: several cases here end by leaving rows ACTIVE,
	// and Sweep with nothing seen inactivates every ACTIVE row of its
	// (producer, kind) — which is the behaviour under test. Sharing one tenant
	// makes each case's result depend on which ones ran before it, and the
	// sweep cases then measure the suite rather than the writer.
	Owner *sql.DB

	// Producer is the key under test.
	Producer string

	// Kind is the producer's primary kind — the one the lifecycle cases are
	// written against. A LADDER kind where the producer has one, because a
	// ladder also exercises the registry-rung half of validation with this
	// producer's real numbers; a fixed kind is fine where it does not.
	Kind string

	// OtherKind is a SECOND kind of the same producer. It is what proves Sweep
	// is scoped by kind as well as by producer — the failure it guards against
	// is a nightly OS-lifecycle pass inactivating the same producer's hardware
	// findings. Leave empty only for a producer that genuinely has one kind, in
	// which case that case SKIPS rather than being faked against a kind the
	// producer does not emit.
	OtherKind string

	// SubjectType is a subject type both kinds allow.
	SubjectType string

	// tenantID is minted per case by Run.
	tenantID uuid.UUID
}

// Run executes the whole contract suite.
func Run(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.DB == nil || cfg.Owner == nil || cfg.Producer == "" || cfg.Kind == "" || cfg.SubjectType == "" {
		t.Fatalf("producertest: incomplete Config %+v", cfg)
	}
	if err := findings.Validate(cfg.Producer, cfg.Kind, cfg.SubjectType); err != nil {
		t.Fatalf("producertest: Config does not describe a registered finding: %v", err)
	}

	// Watch the history appends. They are best-effort by design — the trail is
	// beside the finding, not the finding — but "best effort" has to mean the
	// error was NOTICED, and a bookkeeping failure that is only swallowed is
	// the kind nobody finds. Installed for the whole suite so any case that
	// provokes one fails loudly instead of surfacing three statements later as
	// "could not complete operation in a failed transaction".
	producer.SetHistoryErrorSink(func(producerKey string, findingID uuid.UUID, err error) {
		// Not the cross-binary race, though: this suite runs against a database
		// shared with every other package binary of the same `go test ./...`,
		// and a deadlock with one of their schema applies says nothing about
		// the writer. The savepoint means the pass survives it either way; what
		// this sink is for is a history append that is genuinely broken.
		if testdb.IsTransientRace(err) {
			t.Logf("producer %s: history append for %s hit a cross-binary race (contained): %v", producerKey, findingID, err)
			return
		}
		t.Errorf("producer %s: appending history for finding %s failed: %v", producerKey, findingID, err)
	})
	t.Cleanup(func() { producer.SetHistoryErrorSink(nil) })

	cases := []struct {
		name string
		fn   func(*testing.T, Config)
	}{
		{"CreatesThenReusesOneOpenRow", createsThenReuses},
		{"ResolveThenReturnReusesTheSameRow", resolveThenReturn},
		{"SuppressionSurvivesAResurfacing", suppressionSurvives},
		{"SecondOpenRowIsImpossible", secondOpenRowImpossible},
		{"ArchivedRowDoesNotBlockAFreshOne", archivedDoesNotBlock},
		{"EvidenceMergeIsIdempotent", evidenceMergeIdempotent},
		{"SweepTouchesOnlyThisProducerAndKind", sweepScoping},
		{"SweepWithNothingSeenInactivatesAll", sweepEmpty},
		{"ValidationRefusesOffRegistryWrites", validationRefusals},
		{"WritesAreTenantScoped", tenantScoped},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A fresh tenant per case. testdb.NewTenant registers a CASCADE
			// delete, so nothing this case writes survives into the next.
			c := cfg
			c.tenantID = testdb.NewTenant(t, cfg.Owner)
			tc.fn(t, c)
		})
	}
}

// --- the cases --------------------------------------------------------------

func createsThenReuses(t *testing.T, cfg Config) {
	w := newWriter(t, cfg.Producer)
	subject := cfg.subject()

	first := mustUpsert(t, cfg, w, cfg.finding(t, cfg.Kind, subject, 0))
	if !first.Created {
		t.Fatalf("first Upsert reported Created=false; the row did not exist")
	}
	if first.Reactivated || first.PriorState != "" {
		t.Errorf("first Upsert: Reactivated=%v PriorState=%q, want false/\"\"", first.Reactivated, first.PriorState)
	}
	// Read first_seen BEFORE the second pass. Comparing the column to itself
	// after the fact is a check that cannot fail.
	firstSeen := cfg.load(t, first.ID).firstSeen

	second := mustUpsert(t, cfg, w, cfg.finding(t, cfg.Kind, subject, 0))
	if second.Created {
		t.Errorf("second Upsert reported Created=true — it inserted a second row instead of reusing the first")
	}
	if second.ID != first.ID {
		t.Fatalf("second Upsert returned id %s, want the first row %s", second.ID, first.ID)
	}
	if second.PriorState != producer.StateActive {
		t.Errorf("second Upsert PriorState=%q, want ACTIVE", second.PriorState)
	}

	row := cfg.load(t, first.ID)
	if row.occurrence != 2 {
		t.Errorf("occurrence_count=%d after two passes, want 2 — the column that carries how often this was seen", row.occurrence)
	}
	if !row.firstSeen.Equal(firstSeen) {
		t.Errorf("first_seen moved on the second pass (%v → %v); it must record the first episode", firstSeen, row.firstSeen)
	}
	if n := cfg.countOpen(t, cfg.Producer, cfg.Kind, subject); n != 1 {
		t.Fatalf("%d open rows for one (producer, kind, subject), want exactly 1", n)
	}
	if n := cfg.countHistory(t, first.ID); n != 1 {
		t.Errorf("%d history rows after create + no-change re-observation, want 1 (the creation)", n)
	}
}

func resolveThenReturn(t *testing.T, cfg Config) {
	w := newWriter(t, cfg.Producer)
	subject := cfg.subject()

	created := mustUpsert(t, cfg, w, cfg.finding(t, cfg.Kind, subject, 0))

	var resolved bool
	cfg.tx(t, func(tx *sql.Tx) error {
		var err error
		resolved, err = w.Resolve(context.Background(), tx, cfg.tenantID, cfg.Kind, subject)
		return err
	})
	if !resolved {
		t.Fatalf("Resolve reported nothing to resolve, but the finding was just written")
	}
	if got := cfg.load(t, created.ID); got.state != producer.StateInactive {
		t.Fatalf("detection_state=%q after Resolve, want INACTIVE", got.state)
	}

	// Resolving twice is a no-op, and must not move updated_at: with no
	// resolved_at column, updated_at on an INACTIVE row IS when it stopped
	// being detected.
	before := cfg.load(t, created.ID).updatedAt
	cfg.tx(t, func(tx *sql.Tx) error {
		again, err := w.Resolve(context.Background(), tx, cfg.tenantID, cfg.Kind, subject)
		if again {
			t.Errorf("Resolve reported a second resolution of an already-INACTIVE row")
		}
		return err
	})
	if after := cfg.load(t, created.ID).updatedAt; !after.Equal(before) {
		t.Errorf("updated_at moved on a no-op Resolve (%v → %v) — that timestamp is the answer to \"when did this stop\"", before, after)
	}

	back := mustUpsert(t, cfg, w, cfg.finding(t, cfg.Kind, subject, 0))
	if back.ID != created.ID {
		t.Fatalf("the returning condition got a NEW row %s instead of reusing %s — occurrence_count and first_seen would each describe one episode", back.ID, created.ID)
	}
	if !back.Reactivated || back.PriorState != producer.StateInactive {
		t.Errorf("Upsert after Resolve: Reactivated=%v PriorState=%q, want true/INACTIVE", back.Reactivated, back.PriorState)
	}
	row := cfg.load(t, created.ID)
	if row.state != producer.StateActive {
		t.Errorf("detection_state=%q after the condition returned, want ACTIVE", row.state)
	}
	if !row.resurfacedAt.Valid {
		t.Errorf("resurfaced_at is NULL after a resurfacing")
	}
	// Two OBSERVATIONS: the pass that created it and the pass that saw it come
	// back. Resolve is not an observation — the condition was absent, which is
	// the opposite of being seen — so it must not bump the count.
	if row.occurrence != 2 {
		t.Errorf("occurrence_count=%d, want 2 (created, then seen again when it returned)", row.occurrence)
	}
	if row.workflow != "NEW" {
		t.Errorf("workflow_status=%q after a resurfacing, want NEW — it has to come back into the triage queue", row.workflow)
	}
}

func suppressionSurvives(t *testing.T, cfg Config) {
	w := newWriter(t, cfg.Producer)
	subject := cfg.subject()
	created := mustUpsert(t, cfg, w, cfg.finding(t, cfg.Kind, subject, 0))

	cfg.exec(t, `UPDATE findings SET workflow_status = 'SUPPRESSED' WHERE id = $1 AND tenant_id = $2`, created.ID, cfg.tenantID)
	cfg.tx(t, func(tx *sql.Tx) error {
		_, err := w.Resolve(context.Background(), tx, cfg.tenantID, cfg.Kind, subject)
		return err
	})
	mustUpsert(t, cfg, w, cfg.finding(t, cfg.Kind, subject, 0))

	if got := cfg.load(t, created.ID).workflow; got != "SUPPRESSED" {
		t.Errorf("workflow_status=%q after a suppressed finding resurfaced, want SUPPRESSED — suppression is a standing decision about the condition, not about one episode", got)
	}
}

func secondOpenRowImpossible(t *testing.T, cfg Config) {
	w := newWriter(t, cfg.Producer)
	subject := cfg.subject()
	mustUpsert(t, cfg, w, cfg.finding(t, cfg.Kind, subject, 0))

	// Straight past the writer, which is the point: the guarantee is the
	// database's, not the Go code's.
	//
	// INSIDE the tenant's RLS session, and asserting the SQLSTATE. Both halves
	// are the fix for a check that could not fail: run outside a session,
	// `app.tenant_id` is unset, so findings_tenant_isolation's WITH CHECK
	// compares tenant_id against NULL and the row is refused BEFORE the unique
	// index is ever consulted — "an error came back" was satisfied with
	// findings_open_subject_uniq dropped entirely. A bare `err != nil` proves
	// only that something said no; the question is WHICH thing.
	var err error
	_ = shareddatabase.WithTenantTx(context.Background(), cfg.DB, cfg.tenantID, func(tx *sql.Tx) error {
		_, err = tx.ExecContext(context.Background(), `
			INSERT INTO findings (tenant_id, producer, kind, subject_type, subject_id, severity, score, summary)
			VALUES ($1, $2, $3, $4, $5, 'low', 0, 'a second open row')`,
			cfg.tenantID, cfg.Producer, cfg.Kind, cfg.SubjectType, subject.ID)
		// Swallowed: the INSERT is EXPECTED to fail, and returning the error
		// would only make WithTenantTx roll back, which it does anyway.
		return nil
	})
	if err == nil {
		t.Fatalf("a second OPEN row for one (producer, kind, subject) was accepted — findings_open_subject_uniq is not doing its job")
	}
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) || string(pqErr.Code) != uniqueViolation {
		t.Fatalf("the second open row was refused by %v, not by a unique-index violation — "+
			"the guarantee under test is findings_open_subject_uniq, and an error from anything else "+
			"(RLS, a CHECK, a missing column) would pass this case with that index dropped", err)
	}
	if !strings.Contains(pqErr.Constraint, "findings_open_subject_uniq") {
		t.Errorf("unique violation on %q, want findings_open_subject_uniq", pqErr.Constraint)
	}
}

// uniqueViolation is SQLSTATE 23505.
const uniqueViolation = "23505"

func archivedDoesNotBlock(t *testing.T, cfg Config) {
	w := newWriter(t, cfg.Producer)
	subject := cfg.subject()
	old := mustUpsert(t, cfg, w, cfg.finding(t, cfg.Kind, subject, 0))

	cfg.exec(t, `UPDATE findings SET detection_state = 'ARCHIVED' WHERE id = $1 AND tenant_id = $2`, old.ID, cfg.tenantID)

	fresh := mustUpsert(t, cfg, w, cfg.finding(t, cfg.Kind, subject, 0))
	if fresh.ID == old.ID {
		t.Fatalf("the ARCHIVED row was reused; ARCHIVED is the soft-delete state and a retired row must not block a fresh one")
	}
	if !fresh.Created {
		t.Errorf("Created=false — the fresh finding should have been an INSERT")
	}
}

func evidenceMergeIdempotent(t *testing.T, cfg Config) {
	w := newWriter(t, cfg.Producer)
	subject := cfg.subject()

	f := cfg.finding(t, cfg.Kind, subject, 0)
	f.Evidence = map[string]any{"first": "a"}
	res := mustUpsert(t, cfg, w, f)

	f.Evidence = map[string]any{"second": "b"}
	mustUpsert(t, cfg, w, f)
	after := cfg.evidence(t, res.ID)
	if after["first"] != "a" || after["second"] != "b" {
		t.Fatalf("evidence after a second producer's keys = %v, want both keys — the merge is a shallow union, not a replace", after)
	}

	mustUpsert(t, cfg, w, f)
	again := cfg.evidence(t, res.ID)
	if !sameJSON(after, again) {
		t.Errorf("a converged re-run rewrote evidence: %v → %v; the merge must be idempotent", after, again)
	}
}

func sweepScoping(t *testing.T, cfg Config) {
	if cfg.OtherKind == "" {
		t.Skip("producer has one kind; the cross-kind half of the sweep contract cannot be exercised")
	}
	w := newWriter(t, cfg.Producer)
	kept, swept := cfg.subject(), cfg.subject()

	keptRes := mustUpsert(t, cfg, w, cfg.finding(t, cfg.Kind, kept, 0))
	sweptRes := mustUpsert(t, cfg, w, cfg.finding(t, cfg.Kind, swept, 0))
	otherKindRes := mustUpsert(t, cfg, w, cfg.finding(t, cfg.OtherKind, swept, 0))
	foreignID := cfg.foreignProducerFinding(t, swept)

	var n int
	cfg.tx(t, func(tx *sql.Tx) error {
		var err error
		n, err = w.Sweep(context.Background(), tx, cfg.tenantID, cfg.Kind, []producer.Subject{kept})
		return err
	})
	if n != 1 {
		t.Errorf("Sweep inactivated %d rows, want 1", n)
	}
	if got := cfg.load(t, keptRes.ID).state; got != producer.StateActive {
		t.Errorf("the subject the producer still sees is %q, want ACTIVE", got)
	}
	if got := cfg.load(t, sweptRes.ID).state; got != producer.StateInactive {
		t.Errorf("the subject the producer no longer asserts is %q, want INACTIVE", got)
	}
	if got := cfg.load(t, otherKindRes.ID).state; got != producer.StateActive {
		t.Errorf("a %s/%s finding was swept by a %s sweep (%q) — Sweep must be scoped by kind", cfg.Producer, cfg.OtherKind, cfg.Kind, got)
	}
	if got := cfg.load(t, foreignID).state; got != producer.StateActive {
		t.Errorf("another PRODUCER's finding was swept (%q) — a producer's full statement is about its own rows only", got)
	}
}

func sweepEmpty(t *testing.T, cfg Config) {
	w := newWriter(t, cfg.Producer)
	a, b := cfg.subject(), cfg.subject()
	ra := mustUpsert(t, cfg, w, cfg.finding(t, cfg.Kind, a, 0))
	rb := mustUpsert(t, cfg, w, cfg.finding(t, cfg.Kind, b, 0))

	cfg.tx(t, func(tx *sql.Tx) error {
		_, err := w.Sweep(context.Background(), tx, cfg.tenantID, cfg.Kind, nil)
		return err
	})
	for _, id := range []uuid.UUID{ra.ID, rb.ID} {
		if got := cfg.load(t, id).state; got != producer.StateInactive {
			t.Errorf("finding %s is %q after a sweep that saw nothing, want INACTIVE", id, got)
		}
	}
}

func validationRefusals(t *testing.T, cfg Config) {
	w := newWriter(t, cfg.Producer)
	subject := cfg.subject()
	k, _ := findings.Get(cfg.Producer, cfg.Kind)

	control := uuid.New()
	cases := []struct {
		name string
		f    producer.Finding
	}{
		{"unregistered kind", mutate(cfg.finding(t, cfg.Kind, subject, 0), func(f *producer.Finding) {
			f.Kind = "a_kind_nobody_registered"
		})},
		{"subject type the kind forbids", mutate(cfg.finding(t, cfg.Kind, subject, 0), func(f *producer.Finding) {
			f.Subject.Type = forbiddenSubject(k)
		})},
		{"a control id", mutate(cfg.finding(t, cfg.Kind, subject, 0), func(f *producer.Finding) {
			f.ControlID = &control
		})},
		{"off-ladder severity", mutate(cfg.finding(t, cfg.Kind, subject, 0), func(f *producer.Finding) {
			f.Severity = "Med"
		})},

		{"empty summary", mutate(cfg.finding(t, cfg.Kind, subject, 0), func(f *producer.Finding) {
			f.Summary = "   "
		})},
		{"nil subject id", mutate(cfg.finding(t, cfg.Kind, subject, 0), func(f *producer.Finding) {
			f.Subject.ID = uuid.Nil
		})},
	}
	// A LADDER kind has one more rule: the (severity, score) pair must be one
	// of the registry's rungs verbatim. It is skipped for a fixed kind, which
	// has no rungs to be off — asserting it there would test the registry, not
	// the writer.
	if k.SeverityModel == "ladder" {
		cases = append(cases, struct {
			name string
			f    producer.Finding
		}{"a severity/score pair that is not a rung", mutate(cfg.finding(t, cfg.Kind, subject, 0), func(f *producer.Finding) {
			f.Score = offRungScore(k)
		})})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := shareddatabase.WithTenantTx(context.Background(), cfg.DB, cfg.tenantID, func(tx *sql.Tx) error {
				_, upErr := w.Upsert(context.Background(), tx, cfg.tenantID, tc.f)
				return upErr
			})
			if err == nil {
				t.Fatalf("Upsert accepted %s; a write off the registry has to be refused, not corrected", tc.name)
			}
		})
	}
}

func tenantScoped(t *testing.T, cfg Config) {
	w := newWriter(t, cfg.Producer)
	subject := cfg.subject()
	res := mustUpsert(t, cfg, w, cfg.finding(t, cfg.Kind, subject, 0))

	other := uuid.New()
	// A sweep run in ANOTHER tenant's session must not reach this row, whether
	// RLS or the explicit tenant_id predicate is what stops it. Both are
	// supposed to.
	err := shareddatabase.WithTenantTx(context.Background(), cfg.DB, other, func(tx *sql.Tx) error {
		_, sweepErr := w.Sweep(context.Background(), tx, other, cfg.Kind, nil)
		return sweepErr
	})
	if err != nil {
		t.Fatalf("sweep in a foreign tenant session: %v", err)
	}
	if got := cfg.load(t, res.ID).state; got != producer.StateActive {
		t.Errorf("another tenant's sweep inactivated this tenant's finding (%q)", got)
	}
}

// --- helpers ----------------------------------------------------------------

type storedRow struct {
	state        string
	workflow     string
	occurrence   int
	firstSeen    time.Time
	updatedAt    time.Time
	resurfacedAt sql.NullTime
}

func newWriter(t *testing.T, key string) *producer.Writer {
	t.Helper()
	w, err := producer.New(key)
	if err != nil {
		t.Fatalf("producer.New(%q): %v", key, err)
	}
	return w
}

func (c Config) subject() producer.Subject {
	return producer.Subject{Type: c.SubjectType, ID: uuid.New()}
}

// finding builds a valid finding of `kind` at ladder rung `rung`.
//
// For a fixed-severity kind the rung index is ignored and the registry's
// declared severity/score are used — a fixed kind with `from-catalogue` as its
// default resolves to `medium`/0, which is a legal pair for a feeds_risk kind
// and the only one available without a catalogue.
func (c Config) finding(t *testing.T, kind string, s producer.Subject, rung int) producer.Finding {
	t.Helper()
	k, ok := findings.Get(c.Producer, kind)
	if !ok {
		t.Fatalf("producertest: %s/%s is not registered", c.Producer, kind)
	}
	f := producer.Finding{
		Kind:         kind,
		Subject:      s,
		SubjectLabel: "producertest-" + s.ID.String()[:8],
		Summary:      "producertest " + c.Producer + "/" + kind,
		Evidence:     map[string]any{},
	}
	if k.SeverityModel == "ladder" {
		r, err := producer.Rung(c.Producer, kind, rung)
		if err != nil {
			t.Fatalf("producertest: %v", err)
		}
		f.Severity, f.Score = r.Severity, r.Score
		return f
	}
	f.Severity = k.DefaultSeverity
	if !producer.ValidSeverity(f.Severity) {
		// `from-catalogue` / `from-control` are resolved at evaluation time;
		// the suite has no catalogue, so it writes the middle of the ladder.
		f.Severity = producer.SeverityMedium
	}
	f.Score = k.Score
	if !k.FeedsRisk {
		f.Score = 0
	}
	return f
}

func mustUpsert(t *testing.T, cfg Config, w *producer.Writer, f producer.Finding) producer.Result {
	t.Helper()
	var out producer.Result
	cfg.tx(t, func(tx *sql.Tx) error {
		var err error
		out, err = w.Upsert(context.Background(), tx, cfg.tenantID, f)
		return err
	})
	return out
}

// tx runs fn in the tenant's RLS transaction.
//
// Through testdb.RetryTransient, because this suite runs in whichever package
// its producer lives in, alongside other binaries of the same `go test ./...`
// that apply schema.sql. A concurrent ACCESS EXCLUSIVE DDL sweep deadlocks
// against these multi-table statements, and the victim is whoever was
// mid-statement. Only that class retries; a real lifecycle failure is
// deterministic and still fails.
func (c Config) tx(t *testing.T, fn func(*sql.Tx) error) {
	t.Helper()
	testdb.RetryTransient(t, func() error {
		return shareddatabase.WithTenantTx(context.Background(), c.DB, c.tenantID, fn)
	})
}

func (c Config) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	c.tx(t, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(), q, args...)
		return err
	})
}

func (c Config) load(t *testing.T, id uuid.UUID) storedRow {
	t.Helper()
	var r storedRow
	c.tx(t, func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(), `
			SELECT detection_state, workflow_status, occurrence_count, first_seen, updated_at, resurfaced_at
			FROM findings WHERE id = $1 AND tenant_id = $2`, id, c.tenantID).
			Scan(&r.state, &r.workflow, &r.occurrence, &r.firstSeen, &r.updatedAt, &r.resurfacedAt)
	})
	return r
}

func (c Config) countOpen(t *testing.T, producerKey, kind string, s producer.Subject) int {
	t.Helper()
	var n int
	c.tx(t, func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(), `
			SELECT count(*) FROM findings
			WHERE tenant_id = $1 AND producer = $2 AND kind = $3
			  AND subject_type = $4 AND subject_id = $5
			  AND detection_state <> 'ARCHIVED'`,
			c.tenantID, producerKey, kind, s.Type, s.ID).Scan(&n)
	})
	return n
}

func (c Config) countHistory(t *testing.T, id uuid.UUID) int {
	t.Helper()
	var n int
	c.tx(t, func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(),
			`SELECT count(*) FROM `+producer.HistoryTable+` WHERE finding_id = $1`, id).Scan(&n)
	})
	return n
}

func (c Config) evidence(t *testing.T, id uuid.UUID) map[string]any {
	t.Helper()
	var raw []byte
	c.tx(t, func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(),
			`SELECT evidence FROM findings WHERE id = $1 AND tenant_id = $2`, id, c.tenantID).Scan(&raw)
	})
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("producertest: evidence is not an object: %v", err)
	}
	return out
}

// foreignProducerFinding writes one row for a DIFFERENT registered producer, so
// the sweep case can assert it survives. Inserted directly rather than through
// a second Writer because the point is only that the row exists.
func (c Config) foreignProducerFinding(t *testing.T, s producer.Subject) uuid.UUID {
	t.Helper()
	foreign, kind := "", ""
	for _, k := range findings.All {
		if k.Producer == c.Producer {
			continue
		}
		for _, st := range k.SubjectTypes {
			if st == c.SubjectType {
				foreign, kind = k.Producer, k.Key
				break
			}
		}
		if foreign != "" {
			break
		}
	}
	if foreign == "" {
		t.Skipf("producertest: no other producer emits a %s-subject kind to test sweep isolation against", c.SubjectType)
	}
	id := uuid.New()
	c.exec(t, `
		INSERT INTO findings (id, tenant_id, producer, kind, subject_type, subject_id, severity, score, summary)
		VALUES ($1, $2, $3, $4, $5, $6, 'low', 0, 'another producer''s finding')`,
		id, c.tenantID, foreign, kind, c.SubjectType, s.ID)
	return id
}

func mutate(f producer.Finding, fn func(*producer.Finding)) producer.Finding {
	fn(&f)
	return f
}

// forbiddenSubject returns a subject type this kind may NOT be about.
func forbiddenSubject(k findings.Kind) string {
	allowed := map[string]bool{}
	for _, s := range k.SubjectTypes {
		allowed[s] = true
	}
	for _, s := range findings.SubjectTypes {
		if !allowed[s] {
			return s
		}
	}
	return "not_a_subject_type"
}

// offRungScore returns a score that pairs with no rung of this ladder.
func offRungScore(k findings.Kind) int {
	used := map[int]bool{}
	for _, r := range k.Rungs {
		used[r.Score] = true
	}
	for n := 1; n <= 100; n++ {
		if !used[n] {
			return n
		}
	}
	return 0
}

func sameJSON(a, b map[string]any) bool {
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(ja) == string(jb)
}
