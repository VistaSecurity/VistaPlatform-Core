package services

// The tenant's auto-accept threshold reaches THIS service's identity engines
// (workstream 4.6a).
//
// # Why this is its own test, in this package
//
// inventory-service has the same test for its own engine, shared/identity's
// engine_test.go proves the engine honours a threshold it is handed, and
// identification_settings_integration_test.go proves the number round-trips
// through `tenant_admin_settings`. None of those says anything about
// device-interrogation-service, which is the point of 4.6a: until it, these two
// engines were hard-wired to zero and a tenant who set 95% got auto-accepted
// merges on the discovery path and never on the interrogation one.
//
// Deleting `engine.WithAutoAcceptThreshold(threshold)` from either
// DeviceService.resolveObservation or ObservationSink.resolveObservationWith
// leaves every other suite green, the build fine, and the setting silently
// inert here again. That is's shape — "a unit test proves the code path
// exists; nothing in it proves the dependency is wired".
//
// # Why the threshold is derived rather than fixed
//
// The score comes from the shipped weights, so a hard-coded 0.6 would become a
// retrain's problem rather than a wiring test. So: run the identical conflict on
// two tenants. The first has the default threshold and reports the score the
// real model gave; the second is set just below THAT score and must accept. The
// assertion survives any retrain that keeps the pair separable at all, and it
// fails loudly if the model stops scoring the pair (which would make the test
// prove nothing).
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/identityaudit"
	"github.com/vistasecurity/vistaplatform/shared/identity/identitysettings"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// captureAudit is an identityaudit.Logger that keeps what it was handed.
//
// The real one POSTs to audit-service, which no integration test has. Capturing
// is also the only way to assert on the event's CONTENT — `actor = matcher`, the
// score, the proposal — which is the half of the record that makes it useful.
type captureAudit struct {
	mu   sync.Mutex
	reqs []*auditmiddleware.ActivityLogRequest
}

func (c *captureAudit) LogActivity(_ context.Context, req *auditmiddleware.ActivityLogRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reqs = append(c.reqs, req)
	return nil
}

func (c *captureAudit) all() []*auditmiddleware.ActivityLogRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*auditmiddleware.ActivityLogRequest, len(c.reqs))
	copy(out, c.reqs)
	return out
}

func (c *captureAudit) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reqs = nil
}

// installCaptureAudit points this package's auto-accept audit at a capture and
// restores whatever was there afterwards.
func installCaptureAudit(t *testing.T) *captureAudit {
	t.Helper()
	cap := &captureAudit{}
	SetAutoAcceptAuditLogger(cap)
	t.Cleanup(func() { SetAutoAcceptAuditLogger(nil) })
	return cap
}

// writeAutoAcceptThreshold stores the tenant's setting the way the settings API
// does.
//
// It writes through the SHARED key constants
// ([identitysettings.Key] / [identitysettings.AutoAcceptThresholdKey]) rather
// than literal strings, because those are exactly what inventory-service's
// IdentificationSettingsService writes to and what the reader under test reads
// from. A test that spelled the path itself would still pass if the product's
// two halves started disagreeing about it, which is the one thing the shared
// constants exist to prevent.
//
// The `||` before the jsonb_set is not decoration: jsonb_set creates only the
// LAST element of its path, so without it a tenant whose config has no
// `identity` block silently keeps its old value and the statement reports
// success.
func writeAutoAcceptThreshold(t *testing.T, db *sql.DB, tenant uuid.UUID, threshold float64) {
	t.Helper()
	if _, err := db.Exec(`
		INSERT INTO tenant_admin_settings (tenant_id, config, created_at, updated_at)
		VALUES ($1, '{}'::jsonb, NOW(), NOW())
		ON CONFLICT (tenant_id) DO NOTHING`, tenant); err != nil {
		t.Fatalf("seed tenant_admin_settings: %v", err)
	}
	if _, err := db.Exec(`
		UPDATE tenant_admin_settings
		   SET config = jsonb_set(
		           COALESCE(config, '{}'::jsonb)
		             || jsonb_build_object($2::text, COALESCE(config -> $2::text, '{}'::jsonb)),
		           ARRAY[$2::text, $3::text], to_jsonb($4::numeric), true),
		       version = version + 1,
		       updated_at = NOW()
		 WHERE tenant_id = $1`,
		tenant, identitysettings.Key, identitysettings.AutoAcceptThresholdKey, threshold); err != nil {
		t.Fatalf("write the auto-accept threshold: %v", err)
	}
}

// stageDeviceConflict builds the two assets an observation will be contested
// between and returns the request that will contest them.
//
// Both are promoted to `monitoring`, because the auto-accept guard refuses to
// merge into anything still in Approvals. `run` distinguishes one staging from
// the next WITHIN a tenant: the second call would otherwise re-observe the first
// call's serial and MATCH it, which is correct behaviour and useless as a
// fixture.
func stageDeviceConflict(t *testing.T, svc *DeviceService, db *sql.DB, tenant uuid.UUID, run string) models.CreateDeviceRequest {
	t.Helper()
	ctx := context.Background()
	serial := "SN-DIS-AUTOACCEPT-" + run
	host := "dis-autoaccept-" + run

	serialOnly, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "cisco_ios", SerialNumber: &serial,
	})
	if err != nil {
		t.Fatalf("stage the serial-only device: %v", err)
	}
	hostOnly, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "cisco_ios", Hostname: &host,
	})
	if err != nil {
		t.Fatalf("stage the hostname-only device: %v", err)
	}
	if serialOnly.ID == hostOnly.ID {
		t.Fatal("the two staged devices resolved to ONE asset; the fixture is not contested and proves nothing")
	}
	promoteAssetToMonitoring(t, db, tenant, serialOnly.ID)
	promoteAssetToMonitoring(t, db, tenant, hostOnly.ID)

	// Carries BOTH, so the precedence walk decides one asset by serial and finds
	// another by hostname: ADR-0002 D3's cross-kind conflict.
	return models.CreateDeviceRequest{DeviceType: "cisco_ios", Hostname: &host, SerialNumber: &serial}
}

// createContestedDevice runs CreateDevice over a request every identifier of
// which is already owned, and tolerates the refusal.
//
// The refusal IS the answer when nothing is auto-accepted: the identity floor
// created no asset, so there is nothing to configure and the operator is sent to
// the merge proposal instead (ErrDeviceIdentityContested). An auto-accept turns
// the same call into a success — the observation goes into the winner — which is
// exactly the difference these tests are measuring, so the error is reported
// rather than asserted on here and the auto-merged COUNT is what decides.
func createContestedDevice(t *testing.T, svc *DeviceService, tenant uuid.UUID, req models.CreateDeviceRequest) (*models.Device, error) {
	t.Helper()
	dev, err := svc.CreateDevice(context.Background(), tenant, req)
	if err != nil && !errors.Is(err, ErrDeviceIdentityContested) {
		t.Fatalf("create the contested device: %v", err)
	}
	return dev, err
}

func promoteAssetToMonitoring(t *testing.T, db *sql.DB, tenant uuid.UUID, assetID uuid.UUID) {
	t.Helper()
	if _, err := db.Exec(
		`UPDATE assets SET asset_status = 'monitoring' WHERE tenant_id = $1 AND id = $2`,
		tenant, assetID); err != nil {
		t.Fatalf("promote %s to monitoring: %v", assetID, err)
	}
}

// autoAcceptedHistoryCount counts the `asset_history` rows an auto-accepted
// merge leaves, using the EXACT predicate Approvals'
// "Auto-merged by the matcher (last 30 days)" list runs
// (inventory-service MergeProposalService.ListAutoAccepted).
//
// Spelled out rather than imported because the two services are separate Go
// modules. It is the predicate that matters, and every clause of it is written
// by shared/identity's acceptMerge — which is why a merge this service accepts
// appears on that list with no change to inventory-service or the frontend.
// TestIntegration_AutoMergedList_CoversEveryEngine in inventory-service drives
// the real query over rows the shared engine wrote.
func autoAcceptedHistoryCount(t *testing.T, db *sql.DB, tenant uuid.UUID) int {
	t.Helper()
	var n int
	err := db.QueryRow(`
		SELECT count(*) FROM asset_history
		 WHERE tenant_id = $1
		   AND action = $2
		   AND changes_json->>'kind' = 'merge_proposal'
		   AND (changes_json->>'auto_accepted')::boolean IS TRUE
		   AND created_at >= now() - make_interval(days => 30)`,
		tenant, string(identity.ActionMergeProposed)).Scan(&n)
	if err != nil {
		t.Fatalf("count auto-merged history rows: %v", err)
	}
	return n
}

// ---------------------------------------------------------------------------
// the tests
// ---------------------------------------------------------------------------

// TestIntegration_DeviceService_AutoAcceptThresholdReachesTheEngine drives
// CreateDevice — the REAL path an operator's device takes — and proves the
// tenant's threshold governs it.
func TestIntegration_DeviceService_AutoAcceptThresholdReachesTheEngine(t *testing.T) {
	raw := testdb.Connect(t)
	db := raw
	audit := installCaptureAudit(t)
	svc := NewDeviceService(raw)
	ctx := context.Background()

	// ── the control: the default threshold never accepts ────────────────────
	def := testdb.NewTenant(t, raw)
	defReq := stageDeviceConflict(t, svc, db, def, "a")
	if _, err := createContestedDevice(t, svc, def, defReq); err == nil {
		t.Fatal("a tenant that has set NOTHING had its contested device accepted rather than refused; " +
			"with no threshold the identity floor creates nothing and the operator is sent to Approvals")
	}
	if n := autoAcceptedHistoryCount(t, db, def); n != 0 {
		t.Fatalf("a tenant that has set NOTHING auto-accepted %d merge(s): the default threshold is zero "+
			"and zero means never, so the threshold in force is not this tenant's", n)
	}
	if got := len(audit.all()); got != 0 {
		t.Fatalf("%d audit events for a tenant that auto-accepted nothing", got)
	}

	// The score the shipped model gave this pair, read off the proposal the
	// conflict left. The accepting half below is asserted against it, so a
	// retrain moves the test with the model instead of breaking it.
	score := topProposalScore(t, db, def)
	t.Logf("the shipped model scored the top candidate %.4f", score)
	if score < 0.1 {
		t.Fatalf("the top candidate scored %.4f: nothing is scoring this pair, so this test cannot distinguish "+
			"a wired threshold from an unwired one", score)
	}

	// ── the subject: a threshold the tenant set, at or below that score ─────
	//
	// Floored to a hundredth, which is the granularity the UI offers anyway, so
	// the stored value is one a tenant could actually have chosen.
	threshold := math.Floor(score*100) / 100
	if threshold <= 0 {
		t.Fatalf("derived threshold %v is not above zero", threshold)
	}

	set := testdb.NewTenant(t, raw)
	writeAutoAcceptThreshold(t, db, set, threshold)
	audit.reset()

	setReq := stageDeviceConflict(t, svc, db, set, "a")
	setDev, err := svc.CreateDevice(ctx, set, setReq)
	if err != nil {
		t.Fatalf("create the contested device on the threshold-%v tenant: %v — an auto-accept puts the "+
			"observation into the winning asset, so the call must SUCCEED", threshold, err)
	}
	if setDev == nil {
		t.Fatal("the auto-accepted create returned no device")
	}
	if n := autoAcceptedHistoryCount(t, db, set); n != 1 {
		t.Fatalf("a tenant whose stored threshold is %v got %d auto-accepted merges on a candidate scoring %.4f, want 1: "+
			"the setting is not reaching this service's engine", threshold, n, score)
	}

	// ── the audit event ─────────────────────────────────────────────────────
	events := audit.all()
	if len(events) != 1 {
		t.Fatalf("%d audit events for one auto-accepted merge, want 1", len(events))
	}
	ev := events[0]
	if ev.EventType != identityaudit.EventType {
		t.Errorf("event_type = %q, want %q", ev.EventType, identityaudit.EventType)
	}
	if ev.Action != identityaudit.Action {
		t.Errorf("action = %q, want %q", ev.Action, identityaudit.Action)
	}
	if got, _ := ev.Metadata["actor"].(string); got != identityaudit.ActorMatcher {
		t.Errorf("actor = %q, want %q — a person did not do this and naming one would be false", got, identityaudit.ActorMatcher)
	}
	if !ev.RequiresAttention {
		t.Error("an auto-accepted merge is reversible only by hand today; it must be flagged for attention")
	}
	if id, _ := ev.Metadata["proposal_id"].(string); id == "" {
		t.Error("the audit event names no proposal; the evidence is what a human reviews afterwards")
	}
	if s, _ := ev.Metadata["score"].(float64); s < threshold {
		t.Errorf("audit score %v is below the threshold %v that licensed the merge", s, threshold)
	}
	if ev.TenantID == nil || *ev.TenantID != set {
		t.Errorf("audit tenant = %v, want %v", ev.TenantID, set)
	}

	// ── and it is PER TENANT, read fresh ────────────────────────────────────
	//
	// The default tenant must still be at zero after the other one wrote a
	// threshold. A cached or process-wide threshold passes everything above and
	// fails here, which is the failure worth naming: one tenant's permission to
	// auto-merge applied to another tenant's inventory.
	againReq := stageDeviceConflict(t, svc, db, def, "b")
	_, _ = createContestedDevice(t, svc, def, againReq)
	if n := autoAcceptedHistoryCount(t, db, def); n != 0 {
		t.Fatalf("the default-threshold tenant auto-accepted %d merge(s) after ANOTHER tenant set a threshold", n)
	}

	// Turning it back off takes effect on the very next observation, with no
	// restart. "A config change that silently did not take effect" is the
	// failure this repo keeps hitting, and it is the reason the read is
	// uncached.
	writeAutoAcceptThreshold(t, db, set, 0)
	offReq := stageDeviceConflict(t, svc, db, set, "b")
	if _, err := createContestedDevice(t, svc, set, offReq); err == nil {
		t.Fatal("still auto-accepting after the tenant set the threshold back to zero")
	}
	if n := autoAcceptedHistoryCount(t, db, set); n != 1 {
		t.Fatalf("auto-merged count is %d after the tenant set the threshold back to zero, want the 1 from before: "+
			"the change did not take effect on the next observation", n)
	}
}

// TestIntegration_DeviceService_AutoAcceptFences drives the four conditions of
// ADR-0002 D3 through THIS service's wiring, one at a time.
//
// They are [identity.Engine]'s guards and are unit-tested there. What this adds
// is that the engine device-interrogation-service hands an observation to is the
// one carrying them: a future edit here that resolved through a differently
// configured engine, or that passed a threshold of 1.0 by mistake, would leave
// shared/identity's suite green.
//
// MUTATION: delete any one of the four conditions from
// shared/identity/engine.go's autoAcceptable and the matching sub-test below
// goes red.
func TestIntegration_DeviceService_AutoAcceptFences(t *testing.T) {
	raw := testdb.Connect(t)
	db := raw
	installCaptureAudit(t)
	svc := NewDeviceService(raw)
	ctx := context.Background()

	// The score this fixture attracts, measured once on a throwaway tenant, so
	// each fence below can be set just under it — the only setting at which
	// "this fence stopped it" is distinguishable from "the score was too low".
	probe := testdb.NewTenant(t, raw)
	probeReq := stageDeviceConflict(t, svc, db, probe, "p")
	_, _ = createContestedDevice(t, svc, probe, probeReq)
	score := topProposalScore(t, db, probe)
	if score < 0.1 {
		t.Fatalf("the top candidate scored %.4f; nothing is scoring this pair and no fence test could be meaningful", score)
	}
	below := math.Floor(score*100) / 100
	if below <= 0 {
		t.Fatalf("derived threshold %v is not above zero", below)
	}

	t.Run("fence 1: a threshold of zero means never", func(t *testing.T) {
		tenant := testdb.NewTenant(t, raw)
		// Deliberately NOT written at all: zero is what a tenant who has never
		// decided gets, and "has not decided" must read as no.
		req := stageDeviceConflict(t, svc, db, tenant, "f1")
		_, _ = createContestedDevice(t, svc, tenant, req)
		if n := autoAcceptedHistoryCount(t, db, tenant); n != 0 {
			t.Fatalf("%d auto-accepted merges at threshold zero", n)
		}
	})

	t.Run("fence 2: a score below the threshold does not accept", func(t *testing.T) {
		tenant := testdb.NewTenant(t, raw)
		// Just ABOVE what this pair scores. The tenant has turned auto-accept
		// on; the model simply is not confident enough, and that is a different
		// answer from "off".
		above := math.Min(1, math.Ceil(score*100)/100+0.01)
		writeAutoAcceptThreshold(t, db, tenant, above)
		req := stageDeviceConflict(t, svc, db, tenant, "f2")
		_, _ = createContestedDevice(t, svc, tenant, req)
		if n := autoAcceptedHistoryCount(t, db, tenant); n != 0 {
			t.Fatalf("%d auto-accepted merges at threshold %v over a pair scoring %.4f", n, above, score)
		}
	})

	t.Run("fence 3: a singleton disagreement is categorical", func(t *testing.T) {
		// This fence needs a DIFFERENT fixture from the other three — a
		// cross-kind conflict whose candidates hold a singleton the observation
		// contradicts — and therefore its own threshold. `below` above is
		// derived from the two-identifier fixture and is not necessarily under
		// what this three-identifier one scores; setting it too high would make
		// the sub-test pass because the SCORE was short, which is fence 2's job
		// and proves nothing about this one.
		//
		// So: measure this fixture on a throwaway tenant, then run it again
		// under a threshold at or below what it actually scored.
		probe := testdb.NewTenant(t, raw)
		stageFence3(t, svc, db, probe, "p")
		s3score := topProposalScore(t, db, probe)
		// Expect a LOW score, and derive a correspondingly low threshold. The
		// matcher is right that a serial disagreement is evidence against a
		// merge, so this pair scores near the floor — which makes the tenant
		// whose threshold sits under it a MAXIMALLY permissive one, and that is
		// exactly the tenant this fence has to hold for. It is still a value the
		// API accepts and stores; the settings card's 70/80/90/95/99 steps are a
		// convenience, not the range.
		t.Logf("the singleton fixture scored %.4f", s3score)
		if s3score < 0.01 {
			t.Fatalf("the singleton fixture scored %.4f: nothing is scoring it, so no threshold at the stored "+
				"granularity could reach it and this sub-test would pass for the wrong reason", s3score)
		}
		s3threshold := math.Floor(s3score*100) / 100
		if s3threshold <= 0 {
			t.Fatalf("derived threshold %v is not above zero", s3threshold)
		}

		tenant := testdb.NewTenant(t, raw)
		writeAutoAcceptThreshold(t, db, tenant, s3threshold)
		stageFence3(t, svc, db, tenant, "f3")
		if n := autoAcceptedHistoryCount(t, db, tenant); n != 0 {
			t.Fatalf("%d auto-accepted merges over a SERIAL disagreement at threshold %v (the pair scores %.4f): "+
				"two different serials are two different machines, whatever a matcher scores the pair",
				n, s3threshold, s3score)
		}
	})

	// Not one of the four, and worth its own case: a singleton disagreement
	// against a MATCHED asset never reaches the auto-accept at all.
	//
	// resolveSingletonConflict goes straight to conflictOutcome without
	// consulting the threshold — "a tenant's auto-accept says a high enough
	// score may settle an AMBIGUITY; a singleton disagreement is not an
	// ambiguity". Wiring this service's engines to the tenant's threshold must
	// not have opened that door, and nothing else here would notice if it had.
	t.Run("a singleton disagreement never offers the threshold", func(t *testing.T) {
		tenant := testdb.NewTenant(t, raw)
		writeAutoAcceptThreshold(t, db, tenant, below)

		serial, other, host := "SN-DIS-SINGLE-A", "SN-DIS-SINGLE-B", "dis-single"
		owner, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
			DeviceType: "cisco_ios", Hostname: &host, SerialNumber: &serial,
		})
		if err != nil {
			t.Fatalf("stage the owner: %v", err)
		}
		promoteAssetToMonitoring(t, db, tenant, owner.ID)

		_, _ = createContestedDevice(t, svc, tenant, models.CreateDeviceRequest{
			DeviceType: "cisco_ios", Hostname: &host, SerialNumber: &other,
		})
		if n := autoAcceptedHistoryCount(t, db, tenant); n != 0 {
			t.Fatalf("%d auto-accepted merges over a serial that disagrees with the MATCHED asset at threshold %v", n, below)
		}
	})

	t.Run("fence 4: a candidate still awaiting approval is never merged into", func(t *testing.T) {
		tenant := testdb.NewTenant(t, raw)
		writeAutoAcceptThreshold(t, db, tenant, below)

		// The same fixture as the accepting case, except the candidates are left
		// in `pending_approval` — which is what CreateDevice leaves them in.
		// Admitting an asset to the inventory and merging two assets are two
		// decisions, and the threshold licenses only the second.
		serial, host := "SN-DIS-FENCE4", "dis-fence4"
		if _, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
			DeviceType: "cisco_ios", SerialNumber: &serial,
		}); err != nil {
			t.Fatalf("stage the serial-only device: %v", err)
		}
		if _, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
			DeviceType: "cisco_ios", Hostname: &host,
		}); err != nil {
			t.Fatalf("stage the hostname-only device: %v", err)
		}
		_, _ = createContestedDevice(t, svc, tenant, models.CreateDeviceRequest{
			DeviceType: "cisco_ios", Hostname: &host, SerialNumber: &serial,
		})
		if n := autoAcceptedHistoryCount(t, db, tenant); n != 0 {
			t.Fatalf("%d auto-accepted merges into a candidate still in Approvals at threshold %v", n, below)
		}
	})
}

// TestIntegration_DeviceService_AFailedWriteAutoAcceptsNothing: an observation
// whose transaction rolls back leaves no merge, no history and NO AUDIT EVENT.
//
// The audit call sits after the commit deliberately, and the failure it prevents
// is a record of something that did not happen: an `asset.merge.auto_accepted`
// event naming an asset that never absorbed the sighting, which a reviewer would
// then go looking for and not find.
//
// The lever is the `after` callback, which is the real one — every caller of
// resolveObservation passes one (CreateDevice writes the management row there),
// and returning an error from it is how this service undoes an observation.
//
// MUTATION: move identityaudit.LogAutoAcceptedMerge inside the RunInTx closure
// and this goes red while every other test here stays green.
func TestIntegration_DeviceService_AFailedWriteAutoAcceptsNothing(t *testing.T) {
	raw := testdb.Connect(t)
	db := raw
	audit := installCaptureAudit(t)
	svc := NewDeviceService(raw)
	ctx := context.Background()

	// A tenant whose threshold WOULD accept, so the only thing stopping the
	// audit event is the rollback.
	probe := testdb.NewTenant(t, raw)
	_, _ = createContestedDevice(t, svc, probe, stageDeviceConflict(t, svc, db, probe, "p"))
	score := topProposalScore(t, db, probe)
	if score < 0.1 {
		t.Fatalf("the fixture scored %.4f; nothing would have been auto-accepted anyway and this proves nothing", score)
	}
	tenant := testdb.NewTenant(t, raw)
	writeAutoAcceptThreshold(t, db, tenant, math.Floor(score*100)/100)
	audit.reset()

	req := stageDeviceConflict(t, svc, db, tenant, "w")
	obs, err := svc.deviceObservation(ctx, tenant, deviceObservationInput{
		DeviceType:   req.DeviceType,
		Hostname:     derefStr(req.Hostname),
		SerialNumber: derefStr(req.SerialNumber),
		Source:       declaredSource(),
		ObservedAt:   time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("build the observation: %v", err)
	}

	boom := errors.New("the caller's own write failed")
	var accepted bool
	_, err = svc.resolveObservation(ctx, obs, func(_ *pgidentity.Repository, res identity.Resolution) error {
		accepted = res.AutoAccepted
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the callback's error", err)
	}
	if !accepted {
		t.Fatal("the engine did not auto-accept, so the rollback is not what this test is measuring; " +
			"the threshold or the fixture has drifted")
	}
	if n := len(audit.all()); n != 0 {
		t.Fatalf("%d audit events for a merge that rolled back: the record announces something that did not happen", n)
	}
	if n := autoAcceptedHistoryCount(t, db, tenant); n != 0 {
		t.Fatalf("%d auto-merged history rows survived a rolled-back observation", n)
	}
}

// TestIntegration_DeviceService_AnUnusableTenantIDResolvesNothing: an
// observation whose tenant id is not a tenant id is refused, and writes nothing
// at all — no asset, no history row, no audit event.
//
// # What this does NOT pin, and why the name says so
//
// It does not reach the threshold read. `RunInTx` parses the tenant id before
// it opens a transaction, so an unparseable one is refused there and the read
// never happens: delete the whole `ReadAutoAcceptThresholdFor` call from
// resolveObservation and this test stays GREEN. It was called
// "...UnreadableThresholdResolvesNothing", which claimed a guard it does not
// carry — the shape this file exists to stop.
//
// The reader's own three-valued contract — "we could not check" must not render
// as "the answer is no" — is pinned in shared/identity/identitysettings, where
// a closed handle makes the read genuinely fail, and swallowing it there turns
// TestReadAutoAcceptThreshold_AFailedReadIsAnError red. That a DB-level read
// failure PROPAGATES out of this service's transaction is not separately
// reachable: there is no tenant id that parses for RunInTx and fails for the
// reader, and no row content that makes the query error (a `config` whose
// `identity` is a scalar or an array yields SQL NULL, not a fault).
func TestIntegration_DeviceService_AnUnusableTenantIDResolvesNothing(t *testing.T) {
	raw := testdb.Connect(t)
	db := raw
	audit := installCaptureAudit(t)
	svc := NewDeviceService(raw)
	tenant := testdb.NewTenant(t, raw)

	obs, err := svc.deviceObservation(context.Background(), tenant, deviceObservationInput{
		DeviceType: "cisco_ios", Hostname: "dis-badtenant", Source: declaredSource(), ObservedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("build the observation: %v", err)
	}
	obs.TenantID = "not-a-uuid"

	if _, err := svc.resolveObservation(context.Background(), obs, nil); err == nil {
		t.Fatal("an observation whose threshold could not be read was resolved anyway")
	}
	if n := len(audit.all()); n != 0 {
		t.Fatalf("%d audit events for an observation that never resolved", n)
	}
	var rows int
	if err := db.QueryRow(`SELECT count(*) FROM asset_history WHERE tenant_id = $1`, tenant).Scan(&rows); err != nil {
		t.Fatalf("count history: %v", err)
	}
	if rows != 0 {
		t.Fatalf("%d history rows written by a refused observation", rows)
	}
}

// topProposalScore reads the score off the newest merge proposal a tenant has.
//
// The proposal is the engine's own record of what the matcher said, so reading
// it back is how this test learns the score without re-implementing the model or
// pinning a number a retrain will move.
func topProposalScore(t *testing.T, db *sql.DB, tenant uuid.UUID) float64 {
	t.Helper()
	var payload string
	err := db.QueryRow(`
		SELECT changes_json::text FROM asset_history
		 WHERE tenant_id = $1 AND changes_json->>'kind' = 'merge_proposal'
		 ORDER BY created_at DESC, seq DESC LIMIT 1`, tenant).Scan(&payload)
	if err != nil {
		t.Fatalf("read the newest merge proposal: %v", err)
	}
	var body struct {
		Candidates []struct {
			Score float64 `json:"score"`
		} `json:"candidates"`
		Score float64 `json:"score"`
	}
	if err := json.Unmarshal([]byte(payload), &body); err != nil {
		t.Fatalf("decode the proposal: %v", err)
	}
	best := body.Score
	for _, c := range body.Candidates {
		if c.Score > best {
			best = c.Score
		}
	}
	return best
}

// stageFence3 builds the singleton-disagreement fixture and observes it.
//
//	asset A: serial S1 + hostname H
//	asset B: serial S3 + address I
//	observed: serial S2 + hostname H + address I
//
// S2 is owned by nobody, so the precedence walk falls through to the weak
// kinds: the hostname decides A, the address finds B, and the engine ranks the
// two — which is the only shape that reaches the auto-accept at all (a
// singleton disagreement against a single MATCHED asset goes to
// resolveSingletonConflict, which never offers the threshold).
//
// BOTH candidates hold a serial that is not S2, deliberately: a fixture where
// only one of them disagreed would pass or fail on which one the matcher ranked
// top, rather than on the guard.
func stageFence3(t *testing.T, svc *DeviceService, db *sql.DB, tenant uuid.UUID, run string) {
	t.Helper()
	ctx := context.Background()
	s1, s2, s3 := "SN-DIS-FENCE3-A-"+run, "SN-DIS-FENCE3-OBSERVED-"+run, "SN-DIS-FENCE3-B-"+run
	host, addr := "dis-fence3-"+run, "198.51.100.37"

	a, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "cisco_ios", Hostname: &host, SerialNumber: &s1,
	})
	if err != nil {
		t.Fatalf("stage candidate A: %v", err)
	}
	b, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "cisco_ios", IPAddress: &addr, SerialNumber: &s3,
	})
	if err != nil {
		t.Fatalf("stage candidate B: %v", err)
	}
	if a.ID == b.ID {
		t.Fatal("the two candidates resolved to ONE asset; the fixture is not a cross-kind conflict")
	}
	promoteAssetToMonitoring(t, db, tenant, a.ID)
	promoteAssetToMonitoring(t, db, tenant, b.ID)

	_, _ = createContestedDevice(t, svc, tenant, models.CreateDeviceRequest{
		DeviceType: "cisco_ios", Hostname: &host, IPAddress: &addr, SerialNumber: &s2,
	})
}
