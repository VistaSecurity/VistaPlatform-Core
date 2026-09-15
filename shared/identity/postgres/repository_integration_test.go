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

func (c *contractRepo) AttachIdentifiers(ctx context.Context, asset identity.AssetRef, ids []identity.Identifier) error {
	return c.inner.AttachIdentifiers(ctx, c.ref(asset), ids)
}

func (c *contractRepo) UpsertEndpoints(ctx context.Context, asset identity.AssetRef, eps []identity.EndpointObservation) error {
	return c.inner.UpsertEndpoints(ctx, c.ref(asset), eps)
}

func (c *contractRepo) Touch(ctx context.Context, asset identity.AssetRef, seenAt time.Time) error {
	return c.inner.Touch(ctx, c.ref(asset), seenAt)
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
	return identity.ProposalRef{TenantID: c.logicalTenant(ref.TenantID), ID: ref.ID}, nil
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
