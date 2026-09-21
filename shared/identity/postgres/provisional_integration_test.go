package postgres_test

// The SQL half of provisional inventory ( D1–D3) against a real Postgres.
//
// These cannot be unit tests. `ProvisionalScope` is a question about rows in
// `network_segments` and an overlap between two CIDRs; `ReassignIdentifier`
// rests on the unique index of DATA_MODEL §2 holding across a single UPDATE;
// and the allowance rule is a `count(*)` with a predicate that only a database
// can be wrong about. An in-memory fake agreeing with all three proves that the
// fake agrees with itself.
//
// Skips without TEST_DATABASE_URL; runs in `make test-integration-db` and in
// the nightly.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgrepo "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// addSegment writes a `network_segments` row and returns its id.
func addSegment(t *testing.T, tenant, name, cidr, networkRef string, active bool) string {
	t.Helper()
	db := testdb.Connect(t)
	var ref any
	if strings.TrimSpace(networkRef) != "" {
		ref = networkRef
	}
	var id string
	err := db.QueryRow(`
		INSERT INTO public.network_segments
			(tenant_id, name, segment_type, value, network_type, environment, is_active, cloud_network_ref)
		VALUES ($1, $2, 'cidr', $3, 'private', 'production', $4, $5)
		RETURNING id::text`, tenant, name, cidr, active, ref).Scan(&id)
	if err != nil {
		t.Fatalf("inserting segment %s: %v", name, err)
	}
	return id
}

// TestIntegration_ProvisionalScope pins the derivation of D2.4 against
// real segment rows: which segment is somewhere an asset may be invented.
//
// Both polarities. A rule that only ever says no would pass a suite that only
// ever asks about bad segments, and would then mean no provisional asset is
// ever created on any cluster — a feature that silently does nothing.
func TestIntegration_ProvisionalScope(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin).String()
	repo := pgrepo.New(admin)
	ctx := context.Background()

	clean := addSegment(t, tenant, "prov-clean", "10.60.1.0/24", "", true)
	inactive := addSegment(t, tenant, "prov-inactive", "10.60.2.0/24", "", false)
	cloud := addSegment(t, tenant, "prov-cloud", "10.60.3.0/24", "vpc-abc", true)
	overlapped := addSegment(t, tenant, "prov-overlapped", "10.60.4.0/24", "", true)
	addSegment(t, tenant, "prov-overlapper", "10.60.4.128/25", "", true)

	// A segment of ANOTHER tenant covering the same space must not make this
	// tenant's segment ambiguous: every lookup is tenant-scoped under RLS, and
	// two customers using 10.60.1.0/24 is the normal case, not a conflict.
	otherTenant := testdb.NewTenant(t, admin).String()
	addSegment(t, otherTenant, "prov-elsewhere", "10.60.1.0/24", "", true)

	tests := []struct {
		name       string
		segment    string
		wantOK     bool
		wantReason string
	}{
		{"active cidr, nothing overlapping", clean, true, ""},
		{"inactive", inactive, false, identity.ReasonNetworkScopeUnresolved},
		{"unknown segment", "00000000-0000-0000-0000-000000000000", false, identity.ReasonNetworkScopeUnresolved},
		{"cloud network ref", cloud, false, identity.ReasonOverlappingNetworkScope},
		{"overlapped by a narrower segment", overlapped, false, identity.ReasonOverlappingNetworkScope},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, reason, err := repo.ProvisionalScope(ctx, tenant, tt.segment)
			if err != nil {
				t.Fatalf("ProvisionalScope: %v", err)
			}
			if ok != tt.wantOK {
				t.Errorf("eligible = %v, want %v", ok, tt.wantOK)
			}
			if reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}

	// A segment whose `value` is not a CIDR at all must not take the whole
	// tenant's answer down with it: one malformed row used to be enough to
	// make every lookup in the tenant return an error.
	if _, err := admin.Exec(`
		INSERT INTO public.network_segments
			(tenant_id, name, segment_type, value, network_type, environment, is_active)
		VALUES ($1, 'prov-garbage', 'cidr', 'not-a-cidr', 'private', 'production', true)`, tenant); err != nil {
		t.Fatalf("inserting the malformed segment: %v", err)
	}
	ok, _, err := repo.ProvisionalScope(ctx, tenant, clean)
	if err != nil {
		t.Fatalf("ProvisionalScope with one unparseable segment in the tenant: %v\n"+
			"`value` is free text; one bad row must not answer for every address in the tenant.", err)
	}
	if !ok {
		t.Error("an unparseable segment made a clean one ineligible")
	}
}

// TestIntegration_ProvisionalReassignIdentifier is the atomic move of D3.
func TestIntegration_ProvisionalReassignIdentifier(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin).String()
	repo := pgrepo.New(admin)
	ctx := context.Background()

	addr := identity.Identifier{Kind: identity.KindIPAddress, Value: "10.61.0.50", Scope: "seg-b", Confidence: 1,
		Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:a"}}
	from, err := repo.CreateAsset(ctx, tenant, provisionalAsset("printer.local", addr,
		identity.Identifier{Kind: identity.KindHostname, Value: "printer.local", Scope: "seg-b", Confidence: 1,
			Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:a"}}))
	if err != nil {
		t.Fatalf("CreateAsset(from): %v", err)
	}
	to, err := repo.CreateAsset(ctx, tenant, newAsset("scanner.local",
		identity.Identifier{Kind: identity.KindMACAddress, Value: "02:00:00:61:00:01", Confidence: 1}))
	if err != nil {
		t.Fatalf("CreateAsset(to): %v", err)
	}

	// The wrong owner first: a store that simply always moves would pass a
	// suite that only ever asked it the easy question.
	if err := repo.ReassignIdentifier(ctx, addr, to, from); err == nil {
		t.Error("a move whose `from` does not own the identifier was accepted")
	}
	owners, err := repo.FindByIdentifier(ctx, tenant, addr.Kind, addr.Value, addr.Scope)
	if err != nil || len(owners) != 1 || owners[0].ID != from.ID {
		t.Fatalf("owners = %+v (err %v) after a refused move, want %s", owners, err, from.ID)
	}

	if err := repo.ReassignIdentifier(ctx, addr, from, to); err != nil {
		t.Fatalf("ReassignIdentifier: %v", err)
	}
	var rows int
	if err := admin.QueryRow(`SELECT count(*) FROM public.asset_identifiers
		WHERE tenant_id=$1 AND kind='ip_address' AND value=$2`, tenant, addr.Value).Scan(&rows); err != nil {
		t.Fatalf("counting identifier rows: %v", err)
	}
	if rows != 1 {
		t.Fatalf("%d asset_identifiers rows for %s, want exactly 1 — a move must be one UPDATE, not "+
			"a delete and an insert with a window in between", rows, addr.Value)
	}
	owners, err = repo.FindByIdentifier(ctx, tenant, addr.Kind, addr.Value, addr.Scope)
	if err != nil || len(owners) != 1 || owners[0].ID != to.ID {
		t.Fatalf("owners = %+v (err %v), want %s", owners, err, to.ID)
	}

	if err := repo.ArchiveAsset(ctx, from); err != nil {
		t.Fatalf("ArchiveAsset: %v", err)
	}
	var status, mergedInto string
	if err := admin.QueryRow(`SELECT asset_status, coalesce(metadata->>'merged_into','')
		FROM public.assets WHERE tenant_id=$1 AND id=$2`, tenant, from.ID).Scan(&status, &mergedInto); err != nil {
		t.Fatalf("reading the archived asset: %v", err)
	}
	if status != identity.StatusArchived {
		t.Errorf("asset_status = %q, want archived", status)
	}
	if mergedInto != "" {
		t.Errorf("merged_into = %q; nothing was merged, and claiming one sends every reader of that "+
			"asset to a row it was never part of", mergedInto)
	}
}

// TestIntegration_ProvisionalPromotionAndAllowance is D1: a guess does
// not spend a customer's paid inventory, and promoting one does.
func TestIntegration_ProvisionalPromotionAndAllowance(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin).String()
	repo := pgrepo.New(admin)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	// One asset of allowance for the whole tenant.
	if _, err := admin.Exec(`INSERT INTO tenant_entitlements(tenant_id,item_id,override_value,reason)
		SELECT $1,id,'{"quantity":1}'::jsonb,'provisional allowance regression'
		  FROM billable_items WHERE key='max_assets'`, tenant); err != nil {
		t.Fatalf("setting max_assets: %v", err)
	}

	provisional := func(name, host string) identity.AssetRef {
		t.Helper()
		ref, err := repo.CreateAsset(ctx, tenant, provisionalAsset(name,
			identity.Identifier{Kind: identity.KindHostname, Value: host, Scope: "seg-b", Confidence: 1,
				Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:a"}}))
		if err != nil {
			t.Fatalf("CreateAsset(%s): %v", name, err)
		}
		return ref
	}
	first := provisional("printer.local", "printer.local")
	second := provisional("plotter.local", "plotter.local")

	// Three provisional assets would exhaust an allowance of one if they
	// counted. They must not.
	_ = provisional("scanner.local", "scanner.local")
	allowed := mustAllowance(t, repo, tenant)
	if !allowed {
		t.Fatalf("the allowance is exhausted by three PROVISIONAL assets with a limit of 1; a chatty " +
			"mDNS reflector would then block the creation of assets that are real (#1898 D1)")
	}

	obsFor := func(host string) string {
		t.Helper()
		obs := identity.Observation{
			TenantID:   tenant,
			Source:     identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:vlan-b"},
			ObservedAt: now,
			Identifiers: []identity.Identifier{
				{Kind: identity.KindHostname, Value: host, Scope: "seg-b", Confidence: 1},
			},
		}
		id, err := repo.StoreObservation(ctx, obs, identity.AssessAdmission(obs))
		if err != nil {
			t.Fatalf("StoreObservation(%s): %v", host, err)
		}
		return id
	}
	firstObs, secondObs := obsFor("printer.local"), obsFor("plotter.local")

	// The first promotion fits inside the allowance of one.
	if err := repo.RunInTx(ctx, tenant, func(bound *pgrepo.Repository) error {
		return bound.LinkObservation(ctx, tenant, firstObs, first.ID, identity.IdentityEstablished)
	}); err != nil {
		t.Fatalf("LinkObservation(first): %v", err)
	}
	if got := identityStatusOf(t, tenant, first.ID); got != string(identity.IdentityEstablished) {
		t.Fatalf("identity_status = %q after promotion, want established", got)
	}
	var promoted int
	if err := admin.QueryRow(`SELECT count(*) FROM public.asset_history
		WHERE tenant_id=$1 AND asset_id=$2 AND action='updated'
		  AND changes_json->>'kind'='identity_status'
		  AND changes_json->>'from'='provisional'`, tenant, first.ID).Scan(&promoted); err != nil {
		t.Fatalf("reading the promotion history: %v", err)
	}
	if promoted != 1 {
		t.Errorf("promotion history rows = %d, want 1 recording from=provisional", promoted)
	}

	// The second does not: one established asset now exists and the limit is
	// one. The evidence still lands, the asset stays provisional, and the
	// tenant is told why.
	if err := repo.RunInTx(ctx, tenant, func(bound *pgrepo.Repository) error {
		return bound.LinkObservation(ctx, tenant, secondObs, second.ID, identity.IdentityEstablished)
	}); err != nil {
		t.Fatalf("LinkObservation(second): %v", err)
	}
	if got := identityStatusOf(t, tenant, second.ID); got != string(identity.IdentityProvisional) {
		t.Errorf("identity_status = %q with the allowance exhausted, want it still provisional", got)
	}
	var state string
	var reasons []string
	if err := admin.QueryRow(`SELECT state, admission_reasons FROM public.identity_observations
		WHERE tenant_id=$1 AND id=$2`, tenant, secondObs).Scan(&state, pq.Array(&reasons)); err != nil {
		t.Fatalf("reading the refused observation: %v", err)
	}
	if state != "linked" {
		t.Errorf("observation state = %q, want linked — losing the evidence would make an exhausted "+
			"allowance look like a discovery that never happened", state)
	}
	found := false
	for _, r := range reasons {
		found = found || r == identity.ReasonAssetAllowanceExhausted
	}
	if !found {
		t.Errorf("admission_reasons = %v, want it to include %q", reasons, identity.ReasonAssetAllowanceExhausted)
	}
}

// TestIntegration_ProvisionalFinishObservationStates pins how the two new
// outcomes leave the evidence row ( D2/D3).
//
// A provisional asset is a guess, so the observation stays `unresolved` and
// enrichment keeps working on it. Supporting evidence for an ESTABLISHED asset
// is resolved, because there is nothing left to find out.
func TestIntegration_ProvisionalFinishObservationStates(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin).String()
	repo := pgrepo.New(admin)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	guess, err := repo.CreateAsset(ctx, tenant, provisionalAsset("printer.local",
		identity.Identifier{Kind: identity.KindHostname, Value: "printer.local", Scope: "seg-b", Confidence: 1,
			Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:a"}}))
	if err != nil {
		t.Fatalf("CreateAsset(provisional): %v", err)
	}
	met, err := repo.CreateAsset(ctx, tenant, newAsset("scanner.local",
		identity.Identifier{Kind: identity.KindMACAddress, Value: "02:00:00:62:00:01", Confidence: 1}))
	if err != nil {
		t.Fatalf("CreateAsset(established): %v", err)
	}
	if _, err := admin.Exec(`UPDATE public.assets SET identity_status='established'
		WHERE tenant_id=$1 AND id=$2`, tenant, met.ID); err != nil {
		t.Fatalf("establishing the second asset: %v", err)
	}

	finish := func(host string, outcome identity.Outcome, asset identity.AssetRef) string {
		t.Helper()
		obs := identity.Observation{
			TenantID:   tenant,
			Source:     identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:vlan-a"},
			ObservedAt: now,
			Admission:  identity.AdmissionEvidence{Relayed: true},
			Identifiers: []identity.Identifier{
				{Kind: identity.KindHostname, Value: host, Scope: "seg-b", Confidence: 1},
			},
		}
		decision := identity.AssessAdmission(obs)
		id, err := repo.StoreObservation(ctx, obs, decision)
		if err != nil {
			t.Fatalf("StoreObservation(%s): %v", host, err)
		}
		res := identity.Resolution{Outcome: outcome, Asset: asset}
		if err := repo.FinishObservation(ctx, obs, id, res, decision, true); err != nil {
			t.Fatalf("FinishObservation(%s): %v", outcome, err)
		}
		return id
	}

	cases := []struct {
		name      string
		host      string
		outcome   identity.Outcome
		asset     identity.AssetRef
		wantState string
	}{
		{"provisional", "printer.local", identity.OutcomeProvisional, guess, "unresolved"},
		{"supporting on a provisional asset", "printer-2.local", identity.OutcomeSupporting, guess, "unresolved"},
		{"supporting on an established asset", "scanner.local", identity.OutcomeSupporting, met, "linked"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := finish(tc.host, tc.outcome, tc.asset)
			var state, assetID string
			if err := admin.QueryRow(`SELECT state, coalesce(asset_id::text,'')
				FROM public.identity_observations WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&state, &assetID); err != nil {
				t.Fatalf("reading the observation: %v", err)
			}
			if assetID != tc.asset.ID {
				t.Errorf("asset_id = %q, want %q", assetID, tc.asset.ID)
			}
			if state != tc.wantState {
				t.Errorf("state = %q, want %q", state, tc.wantState)
			}
		})
	}
}

func provisionalAsset(name string, ids ...identity.Identifier) identity.NewAsset {
	a := newAsset(name, ids...)
	a.IdentityStatus = string(identity.IdentityProvisional)
	return a
}

func mustAllowance(t *testing.T, repo *pgrepo.Repository, tenant string) bool {
	t.Helper()
	ctx := context.Background()
	var allowed bool
	if err := repo.RunInTx(ctx, tenant, func(bound *pgrepo.Repository) error {
		var err error
		allowed, err = bound.CheckAdmissionAllowance(ctx, tenant)
		return err
	}); err != nil {
		t.Fatalf("CheckAdmissionAllowance: %v", err)
	}
	return allowed
}

func identityStatusOf(t *testing.T, tenant, assetID string) string {
	t.Helper()
	db := testdb.Connect(t)
	var status string
	if err := db.QueryRow(`SELECT identity_status FROM public.assets
		WHERE tenant_id=$1 AND id=$2`, tenant, assetID).Scan(&status); err != nil {
		t.Fatalf("reading identity_status: %v", err)
	}
	return status
}

// TestIntegration_ProvisionalNotEligibleKeepsTheAdmissionReason drives a real
// refusal through the engine and asserts that BOTH reasons survive on the
// evidence row.
//
// `FinishObservation` used to REPLACE `admission_reasons` with the resolution's
// single reason. That was tolerable while `asset_allowance_exhausted` was the
// only value it ever wrote; the provisional refusals of D2 would
// otherwise overwrite `unverified_relayed_advertisement` — the sentence the UI
// uses to explain why an advert could not establish anything — with a segment
// complaint, leaving the tenant reading a reason that does not answer the
// question they asked.
func TestIntegration_ProvisionalNotEligibleKeepsTheAdmissionReason(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin).String()
	ctx := context.Background()

	if _, err := admin.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config)
		VALUES($1,'{"identity_admission":{"mode":"enforce"}}')
		ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant); err != nil {
		t.Fatalf("enabling enforce mode: %v", err)
	}

	// A segment two active segments cover: real, placeable, and not somewhere
	// an asset may be invented (ReasonOverlappingNetworkScope).
	segment := addSegment(t, tenant, "prov-refuse", "10.62.0.0/24", "", true)
	addSegment(t, tenant, "prov-refuse-overlap", "10.62.0.128/25", "", true)

	repo := pgrepo.New(admin)
	engine, err := identity.New(identity.Config{Repo: repo, AdmissionEnabled: true, ProvisionalInventory: true})
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}

	obs := identity.Observation{
		TenantID:   tenant,
		Source:     identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:vlan-a", Mode: identity.ModePassive},
		ObservedAt: time.Now().UTC().Truncate(time.Microsecond),
		Admission:  identity.AdmissionEvidence{Relayed: true},
		Identifiers: []identity.Identifier{
			{Kind: identity.KindHostname, Value: "printer.local", Scope: segment, Confidence: 1},
			{Kind: identity.KindIPAddress, Value: "10.62.0.50", Scope: segment, Confidence: 1},
		},
	}
	obs.Network.SegmentID = segment

	var res identity.Resolution
	if err := repo.RunInTx(ctx, tenant, func(bound *pgrepo.Repository) error {
		var rErr error
		res, rErr = engine.WithRepository(bound).Resolve(ctx, obs)
		return rErr
	}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Outcome != identity.OutcomeUnresolved || !res.Asset.Zero() {
		t.Fatalf("outcome = %s on %s, want unresolved with no asset — an overlapped segment is not "+
			"somewhere an asset may be invented", res.Outcome, res.Asset.ID)
	}
	if res.AdmissionReason != identity.ReasonOverlappingNetworkScope {
		t.Fatalf("AdmissionReason = %q, want %q", res.AdmissionReason, identity.ReasonOverlappingNetworkScope)
	}

	var reasons []string
	var state, enrichment string
	if err := admin.QueryRow(`SELECT admission_reasons, state, enrichment_state
		FROM public.identity_observations WHERE tenant_id=$1 AND id=$2`,
		tenant, res.ObservationID).Scan(pq.Array(&reasons), &state, &enrichment); err != nil {
		t.Fatalf("reading the refused observation: %v", err)
	}
	for _, want := range []string{"unverified_relayed_advertisement", identity.ReasonOverlappingNetworkScope} {
		found := false
		for _, got := range reasons {
			found = found || got == want
		}
		if !found {
			t.Errorf("admission_reasons = %v, want it to include %q — a resolution reason is a SECOND "+
				"fact about this evidence, not a correction of the admission decision", reasons, want)
		}
	}
	if enrichment != "blocked" {
		t.Errorf("enrichment_state = %q, want blocked", enrichment)
	}

	// And the append is idempotent: the same advert delivered again must not
	// grow the array.
	if err := repo.RunInTx(ctx, tenant, func(bound *pgrepo.Repository) error {
		_, rErr := engine.WithRepository(bound).Resolve(ctx, obs)
		return rErr
	}); err != nil {
		t.Fatalf("Resolve (replay): %v", err)
	}
	var again []string
	if err := admin.QueryRow(`SELECT admission_reasons FROM public.identity_observations
		WHERE tenant_id=$1 AND id=$2`, tenant, res.ObservationID).Scan(pq.Array(&again)); err != nil {
		t.Fatalf("re-reading the refused observation: %v", err)
	}
	if len(again) != len(reasons) {
		t.Errorf("admission_reasons = %v after a replay, want the same %v — append-if-absent, not append",
			again, reasons)
	}
}
