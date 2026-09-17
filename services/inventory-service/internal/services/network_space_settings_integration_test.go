package services

// `tenant_admin_settings.config` is ONE jsonb document that six features share,
// each owning a top-level key: `network_spaces` here, and `drift`, `identity`,
// `ai`, `discovery_auto_scan` and `onboarding_required` elsewhere. These tests
// hold SaveNetworkSpaces to the contract the other five already keep — write
// your key, leave every other byte alone, and record the first save.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db). Takes the schema share lock for the reason
// asset_approval_sharelock_test.go documents.

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/driftsettings"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// siblingConfig is what the OTHER owners of this row have written, as they
// would have written it.
//
// `last_seen_epoch_ns` is not decoration. It is an int64 with more than 15
// significant digits, which is the value class a Go-side read-modify-write
// silently destroys: `json.Unmarshal` into map[string]any decodes every number
// as float64, and re-marshalling emits the nearest representable double
// (…456800, not …456789). jsonb stores numbers as `numeric` and compares them
// exactly, so the equality assertion below sees the difference. Without a value
// of this shape the test passes against the broken writer, because every small
// number survives the round trip unchanged.
const siblingConfig = `{
  "drift": {"baseline_days": 45},
  "identity": {"auto_accept_threshold": 0.9, "last_seen_epoch_ns": 1758153600123456789},
  "discovery_auto_scan": {"enabled": false, "cadence": "weekly"},
  "onboarding_required": true
}`

func newNetworkSpaceSettingsFixture(t *testing.T) (*NetworkSpaceService, *database.DB, uuid.UUID, uuid.UUID) {
	t.Helper()
	db, tenantID := getTestDBAndTenant(t)
	testdb.HoldSchemaShareLock(t, db.DB.DB) // see asset_approval_sharelock_test.go
	return NewNetworkSpaceService(db), db, tenantID, seedTestUser(t, db, tenantID)
}

func seedSiblingKeys(t *testing.T, db *database.DB, tenantID uuid.UUID) {
	t.Helper()
	err := database.WithTenantTx(context.Background(), db, tenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(`
			INSERT INTO tenant_admin_settings (tenant_id, config, version, created_at, updated_at)
			VALUES ($1, $2::jsonb, 1, NOW(), NOW())
			ON CONFLICT (tenant_id) DO UPDATE SET config = EXCLUDED.config`, tenantID, siblingConfig)
		return e
	})
	if err != nil {
		t.Fatalf("seed sibling keys: %v", err)
	}
}

func readConfig(t *testing.T, db *database.DB, tenantID uuid.UUID) map[string]any {
	t.Helper()
	var raw []byte
	err := database.WithTenantTx(context.Background(), db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`SELECT config FROM tenant_admin_settings WHERE tenant_id = $1`, tenantID).Scan(&raw)
	})
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	return out
}

// siblingsIntact asks POSTGRES whether everything except `network_spaces` still
// equals what was seeded, rather than comparing in Go — a Go comparison would
// decode both sides through the same float64 lossy step that the bug uses, and
// would therefore agree with itself.
func siblingsIntact(t *testing.T, db *database.DB, tenantID uuid.UUID) (bool, string) {
	t.Helper()
	var equal bool
	var stored string
	err := database.WithTenantTx(context.Background(), db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`
			SELECT (config - 'network_spaces') = $2::jsonb, (config - 'network_spaces')::text
			FROM tenant_admin_settings WHERE tenant_id = $1`, tenantID, siblingConfig).Scan(&equal, &stored)
	})
	if err != nil {
		t.Fatalf("compare siblings: %v", err)
	}
	return equal, stored
}

func sampleSpaces(t *testing.T) []models.NetworkSpace {
	t.Helper()
	return []models.NetworkSpace{{
		ID:          uuid.New().String(),
		Type:        "cidr",
		Value:       "192.168.100.0/24",
		NetworkType: "private",
		Description: "Development network",
		IsActive:    true,
		Tags:        map[string]interface{}{"environment": "dev"},
	}}
}

// The write must merge into the shared document, not replace it.
//
// The pre-fix writer SELECTed the whole config into a Go map, set its own key
// and wrote the WHOLE map back. That is a full-document replace dressed up as
// an update: every sibling key makes a lossy round trip through
// map[string]any on every network-spaces save, whether or not anybody is
// writing concurrently.
func TestIntegration_NetworkSpaces_PreserveOtherKeys(t *testing.T) {
	svc, db, tenantID, userID := newNetworkSpaceSettingsFixture(t)
	seedSiblingKeys(t, db, tenantID)

	if err := svc.SaveNetworkSpaces(tenantID, userID, sampleSpaces(t)); err != nil {
		t.Fatalf("SaveNetworkSpaces: %v", err)
	}

	if ok, stored := siblingsIntact(t, db, tenantID); !ok {
		t.Errorf("the network-spaces save rewrote its co-tenants of this row.\n got: %s\nwant: %s", stored, siblingConfig)
	}

	// And the key it owns actually landed.
	config := readConfig(t, db, tenantID)
	spaces, ok := config["network_spaces"].([]any)
	if !ok || len(spaces) != 1 {
		t.Fatalf("network_spaces did not land: %#v", config["network_spaces"])
	}
}

// Same claim on the path that CREATES the row: the merge must not depend on the
// settings row already existing.
func TestIntegration_NetworkSpaces_FirstSaveOnEmptyRowStillMerges(t *testing.T) {
	svc, db, tenantID, userID := newNetworkSpaceSettingsFixture(t)

	// No settings row at all.
	if err := svc.SaveNetworkSpaces(tenantID, userID, sampleSpaces(t)); err != nil {
		t.Fatalf("SaveNetworkSpaces on a tenant with no settings row: %v", err)
	}
	config := readConfig(t, db, tenantID)
	if _, ok := config["network_spaces"].([]any); !ok {
		t.Fatalf("network_spaces did not land on a fresh row: %#v", config)
	}

	// A sibling written afterwards, then a second save, must both survive.
	if _, err := driftsettings.NewService(db).Set(context.Background(), tenantID, userID, 60); err != nil {
		t.Fatalf("drift Set: %v", err)
	}
	if err := svc.SaveNetworkSpaces(tenantID, userID, sampleSpaces(t)); err != nil {
		t.Fatalf("second SaveNetworkSpaces: %v", err)
	}
	config = readConfig(t, db, tenantID)
	drift, ok := config["drift"].(map[string]any)
	if !ok || drift["baseline_days"] != float64(60) {
		t.Errorf("the drift window written between the two saves was erased: %#v", config["drift"])
	}
}

// The FIRST save is audited.
//
// `log_tenant_admin_settings_change` is an AFTER **UPDATE** trigger reading
// OLD.config/OLD.version, so it cannot fire on an INSERT. The pre-fix writer
// INSERTed when no row existed, so the first time a tenant defined their
// network spaces — the change most worth having a record of — nothing was
// written to tenant_admin_settings_audit, and "nobody changed it" and "we
// didn't record it" are indistinguishable afterwards.
//
// Both saves are asserted: a fix that audited only the second would pass a
// second-save assertion on its own.
func TestIntegration_NetworkSpaces_FirstSaveIsAudited(t *testing.T) {
	svc, db, tenantID, userID := newNetworkSpaceSettingsFixture(t)

	auditRows := func() int {
		t.Helper()
		var n int
		err := database.WithTenantTx(context.Background(), db, tenantID, func(tx *sqlx.Tx) error {
			return tx.QueryRow(
				`SELECT count(*) FROM tenant_admin_settings_audit WHERE tenant_id = $1`, tenantID).Scan(&n)
		})
		if err != nil {
			t.Fatalf("count audit rows: %v", err)
		}
		return n
	}

	if got := auditRows(); got != 0 {
		t.Fatalf("the fixture already has %d audit rows", got)
	}
	if err := svc.SaveNetworkSpaces(tenantID, userID, sampleSpaces(t)); err != nil {
		t.Fatalf("first SaveNetworkSpaces: %v", err)
	}
	if got := auditRows(); got != 1 {
		t.Fatalf("%d audit rows after the FIRST save, want 1 — an INSERT does not fire an AFTER UPDATE trigger", got)
	}
	if err := svc.SaveNetworkSpaces(tenantID, userID, sampleSpaces(t)); err != nil {
		t.Fatalf("second SaveNetworkSpaces: %v", err)
	}
	if got := auditRows(); got != 2 {
		t.Errorf("%d audit rows after the second save, want 2", got)
	}
}

// A sibling writer committing WHILE a network-spaces save is in flight must not
// lose its change, and must not make the save fail either.
//
// The pre-fix writer read the document and the version in one statement and
// wrote the whole document back in another. Between those two statements a
// drift or identity write can commit; the stale full-document write then either
// erases it or, because of the `AND version = $4` guard, aborts the save with
// "settings were modified by another process, please retry" — a guard that
// protected nothing a user could see, since the version it compared against was
// read microseconds earlier inside the same transaction rather than when the
// browser loaded the page. Merging in the UPDATE itself removes the window
// instead of reporting it.
func TestIntegration_NetworkSpaces_ConcurrentSiblingWriteSurvives(t *testing.T) {
	svc, db, tenantID, userID := newNetworkSpaceSettingsFixture(t)
	seedSiblingKeys(t, db, tenantID)
	drift := driftsettings.NewService(db)
	ctx := context.Background()

	const rounds = 24
	errs := make(chan error, rounds*2)
	var wg sync.WaitGroup
	for i := 0; i < rounds; i++ {
		days := driftsettings.MinBaselineDays + i
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := svc.SaveNetworkSpaces(tenantID, userID, sampleSpaces(t)); err != nil {
				errs <- fmt.Errorf("SaveNetworkSpaces: %w", err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := drift.Set(ctx, tenantID, userID, days); err != nil {
				errs <- fmt.Errorf("drift Set(%d): %w", days, err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("a concurrent write failed: %v", err)
	}

	// Whatever order they landed in, BOTH keys must be present: a full-document
	// write that won the race would have dropped whichever drift value it never
	// saw, leaving the key at its seeded value or gone entirely.
	config := readConfig(t, db, tenantID)
	driftBlock, ok := config["drift"].(map[string]any)
	if !ok {
		t.Fatalf("the drift key was erased by a concurrent network-spaces save: %#v", config)
	}
	days, ok := driftBlock["baseline_days"].(float64)
	if !ok || int(days) == 45 {
		t.Errorf("baseline_days is %#v — the seeded 45 survived every one of the %d concurrent drift writes, "+
			"so a network-spaces save overwrote them", driftBlock["baseline_days"], rounds)
	}
	if _, ok := config["network_spaces"].([]any); !ok {
		t.Errorf("network_spaces was lost: %#v", config)
	}
	if _, ok := config["identity"].(map[string]any); !ok {
		t.Errorf("the identity key was erased: %#v", config)
	}
}
