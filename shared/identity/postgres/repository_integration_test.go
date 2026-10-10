package postgres_test

// The SQL half of the identification engine, against a real Postgres.
//
// Skips without TEST_DATABASE_URL; runs in `make test-integration-db` and in
// the nightly. The bulk of it is identitytest.RunRepositoryContract — the same
// assertions the in-memory implementation runs, because two implementations of
// one storage contract tested by two different suites is how they drift.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/identitytest"
	pgrepo "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_PostgresIdentityRepository_Contract(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)

	identitytest.RunRepositoryContract(t, func() identity.Repository {
		return newContractRepo(t, admin)
	})
}

// TestIntegration_PostgresIdentityRepository_Intake runs identity.Intake over
// the SQL store: SegmentSnapshot must agree with ScopeForAddress row
// for row, and segment posture must read as what the one-statement precedence
// rule in segment_posture.go STORED — which only a real database can say,
// because the precedence lives in SQL.
//
// Mutation check: swap the `operator` and `measured` WHEN branches of
// postureUpdateSQL's effective-source CASE and the "operator=static must
// outrank measured=dynamic" step fails.
func TestIntegration_PostgresIdentityRepository_Intake(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)

	identitytest.RunIntakeContract(t, func() identity.Repository {
		return newContractRepo(t, admin)
	})
}

// TestIntegration_PostgresIdentityRepository_SingletonGuard runs the engine's
// singleton rule against real SQL.
//
// It is not redundant with the in-memory run. The guard reads the matched
// asset's identifiers back through LoadSummaries, and the SQL implementation
// loads them with a second query against `asset_identifiers` — a store that
// returned the asset row without its identifiers would make the guard pass
// everything, silently, and only a real database can say it does not.
func TestIntegration_PostgresIdentityRepository_SingletonGuard(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)

	identitytest.RunSingletonGuardContract(t, func() identity.Repository {
		return newContractRepo(t, admin)
	})
}

// TestIntegration_PostgresIdentityRepository_PinnedAddress runs's
// pinned-address rule against real SQL. Not redundant with the in-memory run:
// the rule reads the owner's `address_assignment` back through LoadSummaries,
// and the upsert decides whether a declaration ever sets it.
func TestIntegration_PostgresIdentityRepository_PinnedAddress(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)

	identitytest.RunPinnedAddressContract(t, func() identity.Repository {
		return newContractRepo(t, admin)
	})
}

// TestIntegration_PostgresIdentityRepository_LeaseFreshAddress runs the
// lease-fresh address contract (leasefresh.go) against real SQL: the
// confirmation goes through the attach upsert's GREATEST and comes back
// through LoadSummaries' device_confirmed_at.
func TestIntegration_PostgresIdentityRepository_LeaseFreshAddress(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)

	identitytest.RunLeaseFreshAddressContract(t, func() identity.Repository {
		return newContractRepo(t, admin)
	})
}

// TestIntegration_PostgresIdentityRepository_ClaimedAddress runs's
// claimed-address rule against real SQL: the move goes through the store's
// ReassignIdentifier under the unique index, the pin through the upsert's
// address_assignment rule, and the holder's status through LoadSummaries.
func TestIntegration_PostgresIdentityRepository_ClaimedAddress(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)

	identitytest.RunClaimedAddressContract(t, func() identity.Repository {
		return newContractRepo(t, admin)
	})
}

// TestIntegration_PostgresIdentityRepository_UnknownHostSerial runs ADR-0002
// D3's erratum against real SQL.
//
// Not redundant with the in-memory run for the same reason the singleton guard
// is not: the precedence walk asks the store who owns a serial
// (`FindByIdentifier`), and the class assertion reads `class_key` back through
// LoadSummaries. A SQL store that scoped either query differently would pass
// in memory and match nothing — or everything — here.
func TestIntegration_PostgresIdentityRepository_UnknownHostSerial(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)

	identitytest.RunUnknownHostSerialContract(t, func() identity.Repository {
		return newContractRepo(t, admin)
	})
}

// TestIntegration_PostgresIdentityRepository_ResolveIsAtomic is the reason
// RunInTx and Engine.WithRepository exist.
//
// One Resolve makes up to five writes. Half of them landing is not a partial
// success: the NEXT observation matches the asset that was created and never
// reaches the conflict path again, so the missing merge proposal is missing
// forever. The test drives a real conflict, then fails the unit of work, and
// asserts the database is exactly as it was.
//
// Mutation check: take the RunInTx wrapper away (call engine.Resolve on an
// unbound repository and drop the returned error) and this fails — the asset
// and its history rows survive.
func TestIntegration_PostgresIdentityRepository_ResolveIsAtomic(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin).String()
	ctx := context.Background()

	repo := pgrepo.New(admin)
	engine, err := identity.New(identity.Config{Repo: repo})
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}

	// Two assets, one identifier each, so a third observation carrying both
	// resolves to two different assets: ADR-0002 D3's outcome three.
	seed := func(serial, mac string) {
		t.Helper()
		err := repo.RunInTx(ctx, tenant, func(r *pgrepo.Repository) error {
			_, err := engine.WithRepository(r).Resolve(ctx, observation(tenant, serial, mac))
			return err
		})
		if err != nil {
			t.Fatalf("seeding %s/%s: %v", serial, mac, err)
		}
	}
	seed("SN-ATOMIC-A", "")
	seed("", "aa:bb:cc:00:00:01")

	before := counts(t, admin, tenant)

	sentinel := errors.New("caller failed after Resolve")
	var res identity.Resolution
	err = repo.RunInTx(ctx, tenant, func(r *pgrepo.Repository) error {
		var rErr error
		res, rErr = engine.WithRepository(r).Resolve(ctx, observation(tenant, "SN-ATOMIC-A", "aa:bb:cc:00:00:01"))
		if rErr != nil {
			return rErr
		}
		if res.Outcome != identity.OutcomeConflict {
			return fmt.Errorf("outcome = %s, want conflict", res.Outcome)
		}
		if res.Proposal.ID == "" {
			return errors.New("a conflict opened no merge proposal")
		}
		// Everything above succeeded. Fail the unit of work anyway: that is
		// what an ingest batch aborting one finding later looks like.
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("RunInTx returned %v, want the sentinel — the conflict path itself did not complete", err)
	}

	after := counts(t, admin, tenant)
	if after != before {
		t.Errorf("a rolled-back Resolve left rows behind:\n  before %+v\n  after  %+v\n"+
			"Resolve's writes for one observation must be one transaction — a pending asset "+
			"created without its merge proposal is never proposed again, because the next "+
			"observation matches the asset instead of conflicting.", before, after)
	}
}

// TestIntegration_PostgresIdentityRepository_ConflictDoesNotAbortTheTransaction
// pins the savepoint. An identifier already owned by another asset must come
// back as ErrIdentifierConflict with the surrounding transaction still usable;
// without the savepoint the failed statement poisons it and every later write
// in the same unit of work fails with "current transaction is aborted".
func TestIntegration_PostgresIdentityRepository_ConflictDoesNotAbortTheTransaction(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin).String()
	ctx := context.Background()
	repo := pgrepo.New(admin)

	var second identity.AssetRef
	err := repo.RunInTx(ctx, tenant, func(r *pgrepo.Repository) error {
		taken := identity.Identifier{Kind: identity.KindSerialNumber, Value: "SN-TAKEN", Confidence: 1}
		first, err := r.CreateAsset(ctx, tenant, newAsset("host-1", taken))
		if err != nil {
			return fmt.Errorf("first create: %w", err)
		}
		if first.ID == "" {
			return errors.New("first create returned no id")
		}
		if _, err := r.CreateAsset(ctx, tenant, newAsset("host-2", taken)); !errors.Is(err, identity.ErrIdentifierConflict) {
			return fmt.Errorf("second create: err = %v, want ErrIdentifierConflict", err)
		}
		// The transaction must still work.
		second, err = r.CreateAsset(ctx, tenant, newAsset("host-3",
			identity.Identifier{Kind: identity.KindSerialNumber, Value: "SN-FREE", Confidence: 1}))
		if err != nil {
			return fmt.Errorf("create after a conflict: %w", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("RunInTx: %v", err)
	}
	owners, err := repo.FindByIdentifier(ctx, tenant, identity.KindSerialNumber, "SN-FREE", "")
	if err != nil || len(owners) != 1 || owners[0].ID != second.ID {
		t.Fatalf("the write after the conflict did not commit: %+v (err %v)", owners, err)
	}
}

// TestIntegration_PostgresIdentityRepository_RefusesAnotherTenant pins the bound
// repository's tenant guard. The bound transaction has already set
// app.tenant_id, so a write for a different tenant either fails an RLS check
// with an opaque error or — on the owner connection, where RLS is dormant —
// succeeds against the wrong tenant. It has to be refused outright.
func TestIntegration_PostgresIdentityRepository_RefusesAnotherTenant(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	mine := testdb.NewTenant(t, admin).String()
	theirs := testdb.NewTenant(t, admin).String()
	ctx := context.Background()

	repo := pgrepo.New(admin)
	err := repo.RunInTx(ctx, mine, func(r *pgrepo.Repository) error {
		if _, err := r.CreateAsset(ctx, theirs, newAsset("intruder")); err == nil {
			return errors.New("a repository bound to one tenant wrote to another")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := admin.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id = $1`, theirs).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d rows landed in the other tenant", n)
	}
}

// TestIntegration_PostgresIdentityRepository_HistoryOrderSurvivesOneTransaction
// is the regression for ordering by created_at.
//
// The engine writes `created` then `merge_proposed` for one observation inside
// ONE transaction, so both rows carry the same now() — the transaction
// timestamp. Ordering on it returns them in whatever order the plan produces,
// which tells the story backwards half the time.
func TestIntegration_PostgresIdentityRepository_HistoryOrderSurvivesOneTransaction(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin).String()
	ctx := context.Background()
	repo := pgrepo.New(admin)

	want := []identity.HistoryAction{
		identity.ActionCreated,
		identity.ActionUpdated,
		identity.ActionMergeProposed,
		identity.ActionUpdated,
	}
	var ref identity.AssetRef
	err := repo.RunInTx(ctx, tenant, func(r *pgrepo.Repository) error {
		var err error
		ref, err = r.CreateAsset(ctx, tenant, newAsset("history-host"))
		if err != nil {
			return err
		}
		at := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC) // identical on every entry
		for i, action := range want {
			if err := r.RecordHistory(ctx, identity.HistoryEntry{
				TenantID: tenant, AssetID: ref.ID, Action: action,
				Source:  identity.Source{Kind: identity.SourceMeasured, Ref: "contract"},
				Changes: map[string]any{"n": i}, At: at,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("RunInTx: %v", err)
	}

	got := repo.HistoryFor(ref)
	if len(got) != len(want) {
		t.Fatalf("%d history entries, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Action != w {
			t.Fatalf("history[%d] = %s, want %s — entries written in one transaction share created_at, "+
				"so only the append counter can order them", i, got[i].Action, w)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// TestIntegration_OpenMergeProposal_OnePairIsOnePendingRow is A3 through
// the real engine and real SQL: two sightings of the same contested pair that
// carry DIFFERENT identifiers leave ONE pending proposal row, whose candidates
// carry the union of what both sightings matched.
//
// Mutation check: put the matched identifier keys back into
// identity.MergeProposalFingerprint and this sees two pending rows; replace the
// fold in OpenMergeProposal with the old whole-payload overwrite and candidate
// b loses the MAC the first sighting matched.
func TestIntegration_OpenMergeProposal_OnePairIsOnePendingRow(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin).String()
	ctx := context.Background()
	repo := pgrepo.New(admin)
	engine, err := identity.New(identity.Config{Repo: repo})
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}

	serial := identity.Identifier{Kind: identity.KindSerialNumber, Value: "SN-FOLD-A", Confidence: 1}
	mac := identity.Identifier{Kind: identity.KindMACAddress, Value: "aa:bb:cc:00:00:31", Confidence: 1}
	host := identity.Identifier{Kind: identity.KindHostname, Value: "fold-b", Scope: identity.ScopeTenantDefault, Confidence: 1}
	a, err := repo.CreateAsset(ctx, tenant, newAsset("fold-a", serial))
	if err != nil {
		t.Fatalf("CreateAsset(a): %v", err)
	}
	b, err := repo.CreateAsset(ctx, tenant, newAsset("fold-b", mac, host))
	if err != nil {
		t.Fatalf("CreateAsset(b): %v", err)
	}

	firstAt := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	laterAt := firstAt.Add(4 * time.Hour)
	resolve := func(at time.Time, ids ...identity.Identifier) identity.Resolution {
		t.Helper()
		o := observation(tenant, "", "")
		o.ObservedAt = at
		o.Identifiers = ids
		var res identity.Resolution
		if err := repo.RunInTx(ctx, tenant, func(r *pgrepo.Repository) error {
			var rErr error
			res, rErr = engine.WithRepository(r).Resolve(ctx, o)
			return rErr
		}); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		return res
	}
	// The serial says a, and b's hostname (first) or b's MAC (second) says b:
	// a cross-kind conflict with nothing left to attach, each time with
	// DIFFERENT evidence for b. Neither sighting alone carries both.
	first := resolve(firstAt, serial, host)
	second := resolve(laterAt, serial, mac)
	if first.Outcome != identity.OutcomeConflict || second.Outcome != identity.OutcomeConflict {
		t.Fatalf("outcomes %s / %s, want conflict / conflict", first.Outcome, second.Outcome)
	}
	if second.Proposal.ID != first.Proposal.ID || !second.Proposal.Reused {
		t.Errorf("second sighting got proposal %s (reused %v), want %s reused", second.Proposal.ID, second.Proposal.Reused, first.Proposal.ID)
	}

	var pending int
	if err := admin.QueryRow(`
		SELECT count(*) FROM public.asset_history
		 WHERE tenant_id = $1 AND action = 'merge_proposed'
		   AND changes_json ->> 'kind' = 'merge_proposal'
		   AND COALESCE(changes_json ->> 'status', 'pending') = 'pending'`, tenant).Scan(&pending); err != nil {
		t.Fatalf("count pending proposals: %v", err)
	}
	if pending != 1 {
		t.Fatalf("%d pending proposal rows for one pair, want 1 — a sighting carrying one more identifier is "+
			"more evidence for the same question, not a new question", pending)
	}

	var (
		raw       []byte
		createdAt time.Time
	)
	if err := admin.QueryRow(`
		SELECT changes_json, created_at FROM public.asset_history
		 WHERE tenant_id = $1 AND id = $2`, tenant, first.Proposal.ID).Scan(&raw, &createdAt); err != nil {
		t.Fatalf("read the proposal: %v", err)
	}
	var row struct {
		Candidates []struct {
			AssetID string `json:"asset_id"`
			Matched []struct {
				Kind  string `json:"kind"`
				Value string `json:"value"`
			} `json:"matched_identifiers"`
		} `json:"candidates"`
		LatestEvidenceAt time.Time `json:"latest_evidence_at"`
	}
	if err := json.Unmarshal(raw, &row); err != nil {
		t.Fatalf("decode the proposal: %v", err)
	}
	matched := map[string]map[string]bool{}
	for _, c := range row.Candidates {
		matched[c.AssetID] = map[string]bool{}
		for _, m := range c.Matched {
			matched[c.AssetID][m.Kind+"="+m.Value] = true
		}
	}
	if len(matched) != 2 || !matched[a.ID]["serial_number=SN-FOLD-A"] {
		t.Errorf("candidates = %v, want a (%s) matched by its serial", matched, a.ID)
	}
	if !matched[b.ID]["mac_address=aa:bb:cc:00:00:31"] || !matched[b.ID]["hostname=fold-b"] {
		t.Errorf("candidate b (%s) matched %v, want the union of both sightings: its MAC and its hostname", b.ID, matched[b.ID])
	}
	if !createdAt.Equal(firstAt) {
		t.Errorf("created_at = %s, want the first sighting's time %s: a fold must not move when the question was asked", createdAt, firstAt)
	}
	if !row.LatestEvidenceAt.Equal(laterAt) {
		t.Errorf("latest_evidence_at = %s, want the later sighting's time %s", row.LatestEvidenceAt, laterAt)
	}
}

func observation(tenant, serial, mac string) identity.Observation {
	o := identity.Observation{
		TenantID:   tenant,
		ClassHint:  "server",
		Source:     identity.Source{Kind: identity.SourceMeasured, Ref: "sensor", Mode: identity.ModePassive},
		ObservedAt: time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC),
		Confidence: 0.9,
	}
	if serial != "" {
		o.Identifiers = append(o.Identifiers, identity.Identifier{Kind: identity.KindSerialNumber, Value: serial, Confidence: 1})
	}
	if mac != "" {
		o.Identifiers = append(o.Identifiers, identity.Identifier{Kind: identity.KindMACAddress, Value: mac, Confidence: 1})
	}
	return o
}

func newAsset(name string, ids ...identity.Identifier) identity.NewAsset {
	return identity.NewAsset{
		ClassKey:        "server",
		ClassSourceKind: identity.ClassSourceMeasured,
		DisplayName:     name,
		Status:          identity.StatusPendingApproval,
		Source:          identity.Source{Kind: identity.SourceMeasured, Ref: "contract"},
		Identifiers:     ids,
	}
}

type rowCounts struct{ Assets, Endpoints, Identifiers, History int }

func counts(t *testing.T, db *sql.DB, tenant string) rowCounts {
	t.Helper()
	var c rowCounts
	err := db.QueryRow(`
		SELECT (SELECT count(*) FROM assets            WHERE tenant_id = $1),
		       (SELECT count(*) FROM asset_endpoints   WHERE tenant_id = $1),
		       (SELECT count(*) FROM asset_identifiers WHERE tenant_id = $1),
		       (SELECT count(*) FROM asset_history     WHERE tenant_id = $1)`, tenant).
		Scan(&c.Assets, &c.Endpoints, &c.Identifiers, &c.History)
	if err != nil {
		t.Fatalf("counting rows: %v", err)
	}
	return c
}

// contractRepo adapts the Postgres repository to identitytest's vocabulary.
//
// The contract addresses tenants by NAME ("tenant-a") and pokes at asset ids
// that were never created ("no-such-asset", "gone"), because it was written
// against a store with no schema. Postgres has uuid columns and a foreign key
// to `tenants`. Rather than loosening the production repository to accept
// whatever a test hands it — which would mean a typo'd tenant id silently
// becoming a new tenant — the translation lives here: a logical name gets a
// real throwaway tenant on first use, and an id that is not a uuid gets one
// that provably names no row.
//
// Everything it delegates is the real thing: the SQL, the uniqueness, the
// errors and the ordering are all the repository's.
type contractRepo struct {
	t     *testing.T
	db    *sql.DB
	inner *pgrepo.Repository

	mu      sync.Mutex
	tenants map[string]string // logical name -> tenant uuid
	back    map[string]string // tenant uuid -> logical name
	ghosts  map[string]string // non-uuid asset id -> a uuid that names no row

	// segments maps a written network_segments id back to the logical scope
	// name the contract used, so ScopeForAddress can be asserted on in the
	// contract's own vocabulary.
	segments map[string]string
}

func newContractRepo(t *testing.T, db *sql.DB) *contractRepo {
	return &contractRepo{
		t: t, db: db, inner: pgrepo.New(db),
		tenants:  map[string]string{},
		back:     map[string]string{},
		ghosts:   map[string]string{},
		segments: map[string]string{},
	}
}

var _ identity.Repository = (*contractRepo)(nil)
var _ identitytest.LastSeenReader = (*contractRepo)(nil)
var _ identitytest.HistoryReader = (*contractRepo)(nil)
var _ identitytest.SegmentWriter = (*contractRepo)(nil)
var _ identity.ProvisionalScopeChecker = (*contractRepo)(nil)
var _ identity.IdentifierReassigner = (*contractRepo)(nil)
var _ identity.AssetArchiver = (*contractRepo)(nil)

func (c *contractRepo) tenantID(name string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if id, ok := c.tenants[name]; ok {
		return id
	}
	id := testdb.NewTenant(c.t, c.db).String()
	c.tenants[name] = id
	c.back[id] = name
	return id
}

func (c *contractRepo) logicalTenant(id string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if name, ok := c.back[id]; ok {
		return name
	}
	return id
}

func (c *contractRepo) assetID(id string) string {
	if _, err := uuid.Parse(strings.TrimSpace(id)); err == nil {
		return id
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if g, ok := c.ghosts[id]; ok {
		return g
	}
	g := uuid.New().String()
	c.ghosts[id] = g
	return g
}

func (c *contractRepo) ref(in identity.AssetRef) identity.AssetRef {
	return identity.AssetRef{TenantID: c.tenantID(in.TenantID), ID: c.assetID(in.ID)}
}

func (c *contractRepo) out(in identity.AssetRef) identity.AssetRef {
	return identity.AssetRef{TenantID: c.logicalTenant(in.TenantID), ID: in.ID}
}

func (c *contractRepo) FindByIdentifier(ctx context.Context, tenantID string, kind identity.Kind, value, scope string) ([]identity.AssetRef, error) {
	refs, err := c.inner.FindByIdentifier(ctx, c.tenantID(tenantID), kind, value, scope)
	for i := range refs {
		refs[i] = c.out(refs[i])
	}
	return refs, err
}

func (c *contractRepo) LoadSummaries(ctx context.Context, tenantID string, ids []string) ([]identity.AssetSummary, error) {
	real := make([]string, 0, len(ids))
	for _, id := range ids {
		real = append(real, c.assetID(id))
	}
	sums, err := c.inner.LoadSummaries(ctx, c.tenantID(tenantID), real)
	for i := range sums {
		sums[i].Ref = c.out(sums[i].Ref)
	}
	return sums, err
}

func (c *contractRepo) CreateAsset(ctx context.Context, tenantID string, a identity.NewAsset) (identity.AssetRef, error) {
	ref, err := c.inner.CreateAsset(ctx, c.tenantID(tenantID), a)
	if err != nil {
		return identity.AssetRef{}, err
	}
	return c.out(ref), nil
}

func (c *contractRepo) AttachIdentifiers(ctx context.Context, asset identity.AssetRef, ids []identity.Identifier) (int, error) {
	return c.inner.AttachIdentifiers(ctx, c.ref(asset), ids)
}

func (c *contractRepo) UpsertEndpoints(ctx context.Context, asset identity.AssetRef, eps []identity.EndpointObservation) (int, error) {
	return c.inner.UpsertEndpoints(ctx, c.ref(asset), eps)
}

func (c *contractRepo) ReconcileSourceEndpoints(ctx context.Context, asset identity.AssetRef, sourcePrefix string, observed []identity.EndpointObservation, at time.Time) ([]string, error) {
	return c.inner.ReconcileSourceEndpoints(ctx, c.ref(asset), sourcePrefix, observed, at)
}

func (c *contractRepo) HistoryHasChange(ctx context.Context, asset identity.AssetRef, action identity.HistoryAction, subset map[string]any) (bool, error) {
	return c.inner.HistoryHasChange(ctx, c.ref(asset), action, subset)
}

func (c *contractRepo) Touch(ctx context.Context, asset identity.AssetRef, seenAt time.Time) error {
	return c.inner.Touch(ctx, c.ref(asset), seenAt)
}

func (c *contractRepo) PromoteNames(ctx context.Context, asset identity.AssetRef, hostname, displayName, sourceKind string) error {
	return c.inner.PromoteNames(ctx, c.ref(asset), hostname, displayName, sourceKind)
}

func (c *contractRepo) RecordHistory(ctx context.Context, e identity.HistoryEntry) error {
	e.TenantID = c.tenantID(e.TenantID)
	e.AssetID = c.assetID(e.AssetID)
	return c.inner.RecordHistory(ctx, e)
}

func (c *contractRepo) OpenMergeProposal(ctx context.Context, tenantID string, p identity.MergeProposal) (identity.ProposalRef, error) {
	// An EMPTY observation asset is the floor path — the proposal that creates
	// nothing — and must stay empty. Running it through assetID would mint a
	// ghost uuid for the key "" and the insert would then fail on an asset that
	// was never created.
	if p.ObservationAssetID != "" {
		p.ObservationAssetID = c.assetID(p.ObservationAssetID)
	}
	for i := range p.Candidates {
		p.Candidates[i].Ref = c.ref(p.Candidates[i].Ref)
	}
	ref, err := c.inner.OpenMergeProposal(ctx, c.tenantID(tenantID), p)
	if err != nil {
		return identity.ProposalRef{}, err
	}
	return identity.ProposalRef{TenantID: c.logicalTenant(ref.TenantID), ID: ref.ID, Reused: ref.Reused}, nil
}

func (c *contractRepo) LastKeptSeparate(ctx context.Context, tenantID string, assetIDs []string) (identity.PriorDecision, bool, error) {
	mapped := make([]string, 0, len(assetIDs))
	for _, id := range assetIDs {
		mapped = append(mapped, c.assetID(id))
	}
	return c.inner.LastKeptSeparate(ctx, c.tenantID(tenantID), mapped)
}

func (c *contractRepo) AddressAnnounced(ctx context.Context, holder identity.AssetRef, address string) (bool, error) {
	return c.inner.AddressAnnounced(ctx, c.ref(holder), address)
}

func (c *contractRepo) IdentifierLastSeen(ctx context.Context, tenantID string, id identity.Identifier) (time.Time, bool, error) {
	return c.inner.IdentifierLastSeen(ctx, c.tenantID(tenantID), id)
}

func (c *contractRepo) RecordAnnouncement(ctx context.Context, announcer, holder identity.AssetRef, a identity.Announcement) error {
	return c.inner.RecordAnnouncement(ctx, c.ref(announcer), c.ref(holder), a)
}

// ResolveProposal is identitytest.ProposalResolver: the patch the approvals
// path (inventory-service's MergeProposalService.resolveProposal) applies to a
// proposal row, written out here so a change to that shape fails this contract
// loudly rather than being silently followed.
func (c *contractRepo) ResolveProposal(ref identity.ProposalRef, status, actor string, at time.Time) error {
	patch := map[string]any{
		"status":      status,
		"resolved_at": at.UTC().Format(time.RFC3339),
	}
	if actor != "" {
		patch["resolved_by"] = actor
	}
	payload, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	res, err := c.db.Exec(`
		UPDATE public.asset_history
		   SET changes_json = changes_json || $3::jsonb
		 WHERE tenant_id = $1 AND id = $2 AND action = 'merge_proposed'`,
		c.tenantID(ref.TenantID), ref.ID, payload)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("ResolveProposal: %d rows matched proposal %s, want 1", n, ref.ID)
	}
	return nil
}

// PendingProposal is identitytest.ProposalReader, decoded here from the row
// rather than through the package's own reader, so the contract asserts what
// the Approvals surface would read and not this package's opinion of it.
func (c *contractRepo) PendingProposal(ref identity.ProposalRef) (identity.MergeProposal, bool) {
	var (
		raw       []byte
		createdAt time.Time
	)
	err := c.db.QueryRow(`
		SELECT changes_json, created_at FROM public.asset_history
		 WHERE tenant_id = $1 AND id = $2 AND action = 'merge_proposed'
		   AND COALESCE(changes_json ->> 'status', 'pending') = 'pending'`,
		c.tenantID(ref.TenantID), ref.ID).Scan(&raw, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return identity.MergeProposal{}, false
	}
	if err != nil {
		c.t.Fatalf("read proposal %s: %v", ref.ID, err)
	}
	var row struct {
		Candidates []struct {
			AssetID string `json:"asset_id"`
			Matched []struct {
				Kind  string `json:"kind"`
				Value string `json:"value"`
				Scope string `json:"scope"`
			} `json:"matched_identifiers"`
			Score  float64 `json:"score"`
			Reason string  `json:"reason"`
		} `json:"candidates"`
		CandidateSnapshots []struct {
			AssetID string `json:"asset_id"`
			rowMatcherSide
		} `json:"candidate_snapshots"`
		LatestEvidenceAt       *time.Time      `json:"latest_evidence_at"`
		PairScore              float64         `json:"pair_score"`
		PairAssetIDs           []string        `json:"pair_asset_ids"`
		PairReason             string          `json:"pair_reason"`
		ObservationIdentifiers []rowIdentifier `json:"observation_identifiers"`
		ObservationContext     *rowMatcherSide `json:"observation_context"`
	}
	if err := json.Unmarshal(raw, &row); err != nil {
		c.t.Fatalf("decode proposal %s: %v", ref.ID, err)
	}
	out := identity.MergeProposal{
		ProposedAt:   createdAt,
		PairScore:    row.PairScore,
		PairAssetIDs: row.PairAssetIDs,
		PairReason:   row.PairReason,
		// The Phase 5 keys are read with this file's own types, the spelling
		// scripts/export-merge-decisions.sql reads, not the package decoder.
		ObservationContext: row.ObservationContext.side(),
	}
	for _, id := range row.ObservationIdentifiers {
		out.ObservationIdentifiers = append(out.ObservationIdentifiers, id.identifier())
	}
	if row.LatestEvidenceAt != nil {
		out.LatestEvidenceAt = *row.LatestEvidenceAt
	}
	snapshots := map[string]*identity.MatcherSide{}
	for i := range row.CandidateSnapshots {
		snapshots[row.CandidateSnapshots[i].AssetID] = row.CandidateSnapshots[i].side()
	}
	for _, cand := range row.Candidates {
		mc := identity.MergeCandidate{
			Ref:      identity.AssetRef{TenantID: ref.TenantID, ID: cand.AssetID},
			Score:    cand.Score,
			Reason:   cand.Reason,
			Snapshot: snapshots[cand.AssetID],
		}
		for _, m := range cand.Matched {
			mc.MatchedIdentifiers = append(mc.MatchedIdentifiers, identity.Identifier{
				Kind: identity.Kind(m.Kind), Value: m.Value, Scope: m.Scope,
			})
		}
		out.Candidates = append(out.Candidates, mc)
	}
	return out, true
}

// rowIdentifier and rowMatcherSide read the Phase 5 keys of a proposal
// row independently of the package's own decoder.
type rowIdentifier struct {
	Kind    string `json:"kind"`
	Value   string `json:"value"`
	Scope   string `json:"scope"`
	Derived bool   `json:"derived"`
	Generic bool   `json:"generic"`
}

func (r rowIdentifier) identifier() identity.Identifier {
	id := identity.Identifier{Kind: identity.Kind(r.Kind), Value: r.Value, Scope: r.Scope, Generic: r.Generic}
	if r.Derived {
		id.Source.Kind = identity.SourceInferred
	}
	return id
}

type rowMatcherSide struct {
	Name        string          `json:"name"`
	Class       string          `json:"class"`
	Segment     string          `json:"segment"`
	Vendor      string          `json:"vendor"`
	Model       string          `json:"model"`
	SourceKind  string          `json:"source_kind"`
	SeenAt      *time.Time      `json:"seen_at"`
	Identifiers []rowIdentifier `json:"identifiers"`
}

func (r *rowMatcherSide) side() *identity.MatcherSide {
	if r == nil {
		return nil
	}
	out := &identity.MatcherSide{Name: r.Name, Class: r.Class, Segment: r.Segment, Vendor: r.Vendor, Model: r.Model, SourceKind: r.SourceKind}
	if r.SeenAt != nil {
		out.SeenAt = *r.SeenAt
	}
	for _, id := range r.Identifiers {
		out.Identifiers = append(out.Identifiers, id.identifier())
	}
	return out
}

// Announcements is identitytest.AnnouncementReader, read straight from
// asset_relationships so the contract asserts the row and not this package's
// own reading of it.
func (c *contractRepo) Announcements(ref identity.AssetRef) []identity.AnnouncementRecord {
	in := c.ref(ref)
	rows, err := c.db.Query(`
		SELECT from_asset_id, to_asset_id, attributes, observation_count, last_seen_at
		  FROM public.asset_relationships
		 WHERE tenant_id = $1 AND type = 'hosted_on'
		   AND attributes ? 'floating_address'
		   AND (from_asset_id = $2 OR to_asset_id = $2)
		 ORDER BY first_seen_at`, in.TenantID, in.ID)
	if err != nil {
		c.t.Fatalf("read announcements: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []identity.AnnouncementRecord
	for rows.Next() {
		var (
			from, to uuid.UUID
			raw      []byte
			count    int
			lastSeen time.Time
		)
		if err := rows.Scan(&from, &to, &raw, &count, &lastSeen); err != nil {
			c.t.Fatalf("scan announcement: %v", err)
		}
		var attrs struct {
			Floating struct {
				MACs       []string `json:"macs"`
				Addresses  []string `json:"addresses"`
				Gratuitous bool     `json:"gratuitous_arp"`
			} `json:"floating_address"`
		}
		if err := json.Unmarshal(raw, &attrs); err != nil {
			c.t.Fatalf("decode announcement attributes: %v", err)
		}
		out = append(out, identity.AnnouncementRecord{
			// The edge is holder → announcer (the VIP's asset is hosted_on
			// the node), so `to` is the announcer.
			Announcer: identity.AssetRef{TenantID: ref.TenantID, ID: to.String()},
			Holder:    identity.AssetRef{TenantID: ref.TenantID, ID: from.String()},
			Latest: identity.Announcement{
				MACs: attrs.Floating.MACs, Addresses: attrs.Floating.Addresses,
				Gratuitous: attrs.Floating.Gratuitous, At: lastSeen.UTC(),
			},
			Count: count,
		})
	}
	return out
}

func (c *contractRepo) ScopeForAddress(ctx context.Context, tenantID string, addr netip.Addr, cloudNetworkRef string) (string, bool, error) {
	scope, dynamic, err := c.inner.ScopeForAddress(ctx, c.tenantID(tenantID), addr, cloudNetworkRef)
	if err != nil {
		return "", false, err
	}
	// The contract works in logical scope names; the SQL side returns the
	// segment's uuid. Map it back so both implementations can be held to the
	// same assertions.
	if name, ok := c.segmentName(scope); ok {
		return name, dynamic, nil
	}
	return scope, dynamic, nil
}

// SegmentSnapshot maps the real snapshot back into the contract's logical
// vocabulary — tenant name, scope names — the same way ScopeForAddress does.
func (c *contractRepo) SegmentSnapshot(ctx context.Context, tenantID string) (identity.SegmentSnapshot, error) {
	snap, err := c.inner.SegmentSnapshot(ctx, c.tenantID(tenantID))
	if err != nil {
		return identity.SegmentSnapshot{}, err
	}
	snap.TenantID = tenantID
	for i := range snap.Segments {
		if name, ok := c.segmentName(snap.Segments[i].ID); ok {
			snap.Segments[i].ID = name
		}
	}
	return snap, nil
}

// AddDomainSegment implements identitytest.DomainSegmentWriter with a real
// `domain` row.
func (c *contractRepo) AddDomainSegment(tenantID, pattern, scope string) error {
	var id string
	err := c.db.QueryRow(`
		INSERT INTO public.network_segments
			(tenant_id, name, segment_type, value, network_type, environment, is_active, metadata)
		VALUES ($1, $2, 'domain', $3, 'private', 'production', true, '{}'::jsonb)
		RETURNING id::text`, c.tenantID(tenantID), scope, pattern).Scan(&id)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.segments[id] = scope
	return nil
}

// StateSegmentPosture implements identitytest.SegmentPostureWriter through the
// product's own posture writer, so the contract reads back what the deployed
// precedence rule stored.
func (c *contractRepo) StateSegmentPosture(tenantID, scope, source string, dynamic *bool) error {
	id := c.segmentIDFor(scope)
	tid := c.tenantID(tenantID)
	ctx := context.Background()
	var err error
	if dynamic == nil {
		_, err = pgrepo.ClearSegmentPosture(ctx, c.db, tid, id, pgrepo.PostureSource(source))
	} else {
		_, err = pgrepo.RecordSegmentPosture(ctx, c.db, tid, id, pgrepo.PostureSource(source), *dynamic, pgrepo.PostureEvidence{})
	}
	return err
}

// AddSegment implements identitytest.SegmentWriter: it writes a real
// network_segments row, so the SQL ScopeForAddress is exercised against the
// table it actually reads rather than a stub.
func (c *contractRepo) AddSegment(tenantID, cidr, scope string, dynamic bool) error {
	return c.AddCloudSegment(tenantID, cidr, scope, dynamic, "")
}

// AddCloudSegment implements identitytest.CloudSegmentWriter: the same row with
// a `cloud_network_ref`, which is what lets two segments share one CIDR.
//
// A NULL is written for the LAN case rather than an empty string, because that
// is what the column actually holds for an operator-drawn segment and the
// unique index keys on `coalesce(cloud_network_ref, ”)`. Writing ” here would
// test a shape production never produces.
func (c *contractRepo) AddCloudSegment(tenantID, cidr, scope string, dynamic bool, networkRef string) error {
	tid := c.tenantID(tenantID)
	var ref any
	if strings.TrimSpace(networkRef) != "" {
		ref = networkRef
	}
	var id string
	err := c.db.QueryRow(`
		INSERT INTO public.network_segments
			(tenant_id, name, segment_type, value, network_type, environment, is_active, metadata, cloud_network_ref)
		VALUES ($1, $2, 'cidr', $3, 'private', 'production', true, jsonb_build_object('dynamic', $4::boolean), $5)
		RETURNING id::text`, tid, scope, cidr, dynamic, ref).Scan(&id)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.segments[id] = scope
	return nil
}

func (c *contractRepo) segmentName(id string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	name, ok := c.segments[id]
	return name, ok
}

// ProvisionalScope, ReassignIdentifier and ArchiveAsset are the D2/D3
// capabilities, delegated to the real repository.
//
// The eligibility answer is DERIVED from `network_segments` here, so this
// adapter deliberately does NOT implement identitytest.ProvisionalScopeWriter:
// the contract's configurable subtest skips, and the derivation itself is
// pinned by TestIntegration_ProvisionalScope below against real rows. What the
// contract still holds this implementation to is the default — a segment
// nobody configured answers no — which is the polarity that matters.
func (c *contractRepo) ProvisionalScope(ctx context.Context, tenantID, segmentID string) (bool, string, error) {
	// The contract names segments logically; a name it never registered has no
	// row, and assetID mints a uuid that provably names none.
	real := segmentID
	if _, err := uuid.Parse(strings.TrimSpace(segmentID)); err != nil {
		real = c.segmentIDFor(segmentID)
	}
	return c.inner.ProvisionalScope(ctx, c.tenantID(tenantID), real)
}

func (c *contractRepo) segmentIDFor(name string) string {
	c.mu.Lock()
	for id, scope := range c.segments {
		if scope == name {
			c.mu.Unlock()
			return id
		}
	}
	c.mu.Unlock()
	return c.assetID(name)
}

func (c *contractRepo) ReassignIdentifier(ctx context.Context, id identity.Identifier, from, to identity.AssetRef) error {
	return c.inner.ReassignIdentifier(ctx, id, c.ref(from), c.ref(to))
}

func (c *contractRepo) ArchiveAsset(ctx context.Context, asset identity.AssetRef) error {
	return c.inner.ArchiveAsset(ctx, c.ref(asset))
}

func (c *contractRepo) RetireIdentifier(ctx context.Context, asset identity.AssetRef, id identity.Identifier) error {
	return c.inner.RetireIdentifier(ctx, c.ref(asset), id)
}

func (c *contractRepo) DriftMaterial(ctx context.Context, asset identity.AssetRef) (identity.StoredDriftMaterial, error) {
	return c.inner.DriftMaterial(ctx, c.ref(asset))
}

func (c *contractRepo) LastSeen(ref identity.AssetRef) time.Time {
	return c.inner.LastSeen(c.ref(ref))
}

func (c *contractRepo) HistoryFor(ref identity.AssetRef) []identity.HistoryEntry {
	entries := c.inner.HistoryFor(c.ref(ref))
	for i := range entries {
		entries[i].TenantID = c.logicalTenant(entries[i].TenantID)
	}
	return entries
}

func (c *contractRepo) Endpoints(ref identity.AssetRef) []identity.EndpointObservation {
	return c.inner.Endpoints(c.ref(ref))
}

// TestIntegration_PostgresIdentityRepository_ZonedLinkLocalEndpoint is the
// regression for the Windows host-inventory failure.
//
// A host agent reports its listening sockets as the host sees them, and a
// socket bound to an IPv6 link-local address carries a zone: `%6` on Windows
// (the interface index), `%eth0` on Linux. netip parses that; Postgres `inet`
// rejects it with 22P02. The value therefore passed nullInet's validation and
// failed at the cast — and because the endpoints of one host go in as a batch,
// one zoned socket failed the whole statement and the entire host inventory
// was rejected as unmaterialisable.
//
// This has to be an integration test: the unit test on nullInet pins what the
// function RETURNS, and the whole bug was that Go's opinion of a valid address
// is not the database's. Only a real inet column can say so.
//
// Mutation check: return `s` unchanged from nullInet's ParseAddr branch (its
// behaviour before the fix) and this fails with 22P02.
func TestIntegration_PostgresIdentityRepository_ZonedLinkLocalEndpoint(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin).String()
	ctx := context.Background()

	repo := pgrepo.New(admin)
	ref, err := repo.CreateAsset(ctx, tenant, newAsset("zoned-endpoint-host",
		identity.Identifier{Kind: identity.KindSerialNumber, Value: "SN-ZONED-1", Confidence: 1}))
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}

	// Two endpoints in ONE call, the zoned one first, so a statement that
	// aborts on it takes the ordinary one with it — which is what made the
	// whole report unmaterialisable rather than one socket.
	eps := []identity.EndpointObservation{
		{Address: "fe80::dd63:32d5:6809:dde3%6", Port: 64657, Transport: "udp",
			Source: identity.Source{Kind: identity.SourceMeasured, Ref: "host-inventory"}},
		{Address: "192.0.2.10", Port: 443, Transport: "tcp",
			Source: identity.Source{Kind: identity.SourceMeasured, Ref: "host-inventory"}},
	}
	if _, err := repo.UpsertEndpoints(ctx, ref, eps); err != nil {
		t.Fatalf("UpsertEndpoints with a zoned link-local address: %v\n"+
			"A host's own socket table is where zoned addresses come from; rejecting the "+
			"batch loses every endpoint on the host, not just this one.", err)
	}

	var stored string
	err = admin.QueryRowContext(ctx, `
		SELECT host(address) FROM public.asset_endpoints
		 WHERE tenant_id = $1 AND asset_id = $2 AND port = 64657`, tenant, ref.ID).Scan(&stored)
	if err != nil {
		t.Fatalf("reading the zoned endpoint back: %v", err)
	}
	if stored != "fe80::dd63:32d5:6809:dde3" {
		t.Errorf("stored address = %q, want the address with its zone stripped", stored)
	}

	var total int
	if err := admin.QueryRowContext(ctx, `
		SELECT count(*) FROM public.asset_endpoints
		 WHERE tenant_id = $1 AND asset_id = $2`, tenant, ref.ID).Scan(&total); err != nil {
		t.Fatalf("counting endpoints: %v", err)
	}
	if total != 2 {
		t.Errorf("endpoint count = %d, want 2 — the ordinary endpoint in the batch must survive", total)
	}
}

// TestIntegration_SourceRankSQLMatchesGo holds the identifier upsert's SQL
// rank ladder to identity.SourceRank for every source kind the column
// accepts, evaluated by Postgres rather than compared as text: the upsert and
// the in-memory store must order provenance identically, or the contract
// passes one and not the other.
func TestIntegration_SourceRankSQLMatchesGo(t *testing.T) {
	db := testdb.Connect(t)
	for _, k := range []identity.SourceKind{identity.SourceDeclared, identity.SourceMeasured, identity.SourceImported, identity.SourceInferred} {
		var got int
		if err := db.QueryRow(`SELECT `+pgrepo.SourceRankSQL("$1::text"), string(k)).Scan(&got); err != nil {
			t.Fatalf("rank(%s): %v", k, err)
		}
		if want := identity.SourceRank(k); got != want {
			t.Errorf("SQL rank(%s) = %d, Go = %d", k, got, want)
		}
	}
}
