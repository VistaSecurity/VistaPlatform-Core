package entitlements

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// The licence step's decision table, DB-free so it runs on every PR.
//
// Rows: the four licence states an install can be in. Columns: the four states
// a tenant's own rows can be in. Every cell is asserted for an edition-gated
// boolean AND for a capacity (numeric) item, because the step treats them
// differently and a bug in one would not show in the other.
//
// Mutations this table was run against (each turns at least one cell red):
//   - drop the `!active ||` from the gated deny  → expired/no-licence cells grant
//   - drop the Enterprise `SourceOverride` return → "enterprise × override off" grants
//   - make MSP take the Enterprise branch         → "msp × nothing" grants, "msp × tier" unlimited
//   - drop the Enterprise numeric rewrite         → "enterprise × tier/nothing" quantity stays 5
//   - EditionCovers(Enterprise, billing_portal)   → see TestApplyLicense_EnterpriseDoesNotCoverMSPItems

const (
	gatedBool = "custom_policies" // EditionEnterprise
	capItem   = "max_sensors"     // Core, numeric_cap
)

type tenantRows int

const (
	rowsNothing tenantRows = iota
	rowsTierGrant
	rowsOverrideOn
	rowsOverrideOff
)

func (r tenantRows) String() string {
	return [...]string{"nothing", "tier grant", "override on", "override off"}[r]
}

// resolvedBool is what the SQL half of the resolver hands the licence step for
// a gated boolean in each tenant-row state.
func resolvedBool(key string, r tenantRows) *EffectiveEntitlement {
	exp := time.Now().Add(time.Hour)
	switch r {
	case rowsTierGrant:
		return ent(key, KindBoolean, `{"enabled": true}`, SourceTier, nil)
	case rowsOverrideOn:
		return ent(key, KindBoolean, `{"enabled": true}`, SourceOverride, &exp)
	case rowsOverrideOff:
		return ent(key, KindBoolean, `{"enabled": false}`, SourceOverride, &exp)
	default:
		return ent(key, KindBoolean, `{"enabled": false}`, SourceDefault, nil)
	}
}

// resolvedQty is the same for a capacity item. "override off" is a cap the
// platform admin set on one tenant; "override on" is a raised cap.
func resolvedQty(r tenantRows) *EffectiveEntitlement {
	switch r {
	case rowsTierGrant:
		return ent(capItem, KindNumericCap, `{"quantity": 5}`, SourceTier, nil)
	case rowsOverrideOn:
		return ent(capItem, KindNumericCap, `{"quantity": 500}`, SourceOverride, nil)
	case rowsOverrideOff:
		return ent(capItem, KindNumericCap, `{"quantity": 0}`, SourceOverride, nil)
	default:
		return ent(capItem, KindNumericCap, `{"quantity": 0}`, SourceDefault, nil)
	}
}

func ent(key string, kind Kind, value string, src Source, exp *time.Time) *EffectiveEntitlement {
	return &EffectiveEntitlement{
		Item:      BillableItem{ID: uuid.New(), Key: key, Kind: kind},
		Value:     json.RawMessage(value),
		Source:    src,
		ExpiresAt: exp,
	}
}

func licenceStates(now time.Time) map[string]*License {
	return map[string]*License{
		"no licence": nil,
		"expired":    {Edition: EditionEnterprise, ExpiresAt: now.Add(-time.Minute)},
		"enterprise": {Edition: EditionEnterprise, ExpiresAt: now.Add(24 * time.Hour)},
		"msp":        {Edition: EditionMSP, ExpiresAt: now.Add(24 * time.Hour)},
	}
}

func TestApplyLicense_GatedBooleanMatrix(t *testing.T) {
	now := time.Now()
	type want struct {
		enabled bool
		source  Source
	}
	cases := map[string]map[tenantRows]want{
		// No valid licence: nothing a tenant row says can switch it on.
		"no licence": {
			rowsNothing:     {false, SourceEdition},
			rowsTierGrant:   {false, SourceEdition},
			rowsOverrideOn:  {false, SourceEdition},
			rowsOverrideOff: {false, SourceEdition},
		},
		"expired": {
			rowsNothing:     {false, SourceEdition},
			rowsTierGrant:   {false, SourceEdition},
			rowsOverrideOn:  {false, SourceEdition},
			rowsOverrideOff: {false, SourceEdition},
		},
		// Enterprise: on for everyone, unless switched off per tenant. Tiers
		// play no part.
		"enterprise": {
			rowsNothing:     {true, SourceEdition},
			rowsTierGrant:   {true, SourceEdition},
			rowsOverrideOn:  {true, SourceOverride},
			rowsOverrideOff: {false, SourceOverride},
		},
		// MSP: the tenant's plan and exceptions decide, unchanged.
		"msp": {
			rowsNothing:     {false, SourceDefault},
			rowsTierGrant:   {true, SourceTier},
			rowsOverrideOn:  {true, SourceOverride},
			rowsOverrideOff: {false, SourceOverride},
		},
	}
	for licName, lic := range licenceStates(now) {
		for rows, w := range cases[licName] {
			t.Run(fmt.Sprintf("%s × %s", licName, rows), func(t *testing.T) {
				e := resolvedBool(gatedBool, rows)
				applyLicense(e, lic, now)
				got, ok := e.BooleanValue()
				if !ok {
					t.Fatalf("value %s is not a boolean shape", e.Value)
				}
				if got != w.enabled || e.Source != w.source {
					t.Fatalf("enabled=%v source=%q, want enabled=%v source=%q", got, e.Source, w.enabled, w.source)
				}
				if e.Source == SourceEdition && e.ExpiresAt != nil {
					t.Error("an edition-decided value kept the override's expiry — the UI would show a trial end on it")
				}
			})
		}
	}
}

func TestApplyLicense_QuantityMatrix(t *testing.T) {
	now := time.Now()
	type want struct {
		qty    *int // nil = unlimited
		source Source
	}
	five, fiveHundred, zero := 5, 500, 0
	unchanged := map[tenantRows]want{
		rowsNothing:     {&zero, SourceDefault},
		rowsTierGrant:   {&five, SourceTier},
		rowsOverrideOn:  {&fiveHundred, SourceOverride},
		rowsOverrideOff: {&zero, SourceOverride},
	}
	cases := map[string]map[tenantRows]want{
		// Capacity is not edition-gated: Core and an expired licence keep the
		// tenant's plan, exactly as before this model.
		"no licence": unchanged,
		"expired":    unchanged,
		// Enterprise capacity is unlimited unless a tenant override caps it.
		"enterprise": {
			rowsNothing:     {nil, SourceEdition},
			rowsTierGrant:   {nil, SourceEdition},
			rowsOverrideOn:  {&fiveHundred, SourceOverride},
			rowsOverrideOff: {&zero, SourceOverride},
		},
		"msp": unchanged,
	}
	for licName, lic := range licenceStates(now) {
		for rows, w := range cases[licName] {
			t.Run(fmt.Sprintf("%s × %s", licName, rows), func(t *testing.T) {
				e := resolvedQty(rows)
				applyLicense(e, lic, now)
				got, ok := e.QuantityValue()
				if !ok {
					t.Fatalf("value %s is not a quantity shape", e.Value)
				}
				if (got == nil) != (w.qty == nil) || (got != nil && *got != *w.qty) || e.Source != w.source {
					t.Fatalf("quantity=%s source=%q, want quantity=%s source=%q", fmtQty(got), e.Source, fmtQty(w.qty), w.source)
				}
			})
		}
	}
}

func fmtQty(q *int) string {
	if q == nil {
		return "unlimited"
	}
	return fmt.Sprint(*q)
}

// billing_portal is MSP-only. An Enterprise licence must not switch it on for
// anyone — not by default, not from a tier, not from an override.
func TestApplyLicense_EnterpriseDoesNotCoverMSPItems(t *testing.T) {
	now := time.Now()
	ent := &License{Edition: EditionEnterprise, ExpiresAt: now.Add(time.Hour)}
	msp := &License{Edition: EditionMSP, ExpiresAt: now.Add(time.Hour)}
	for _, rows := range []tenantRows{rowsNothing, rowsTierGrant, rowsOverrideOn} {
		e := resolvedBool("billing_portal", rows)
		applyLicense(e, ent, now)
		if on, _ := e.BooleanValue(); on {
			t.Errorf("enterprise × %s: billing_portal enabled — an Enterprise licence does not cover it", rows)
		}
	}
	// And the MSP licence does cover it, per plan.
	e := resolvedBool("billing_portal", rowsTierGrant)
	applyLicense(e, msp, now)
	if on, _ := e.BooleanValue(); !on {
		t.Error("msp × tier grant: billing_portal disabled — an MSP plan must be able to grant it")
	}
}

// A licence naming an edition this build does not know grants nothing. The
// schema's CHECK keeps such a row out, but the resolver must not depend on it.
func TestApplyLicense_UnknownEditionIsCore(t *testing.T) {
	now := time.Now()
	for _, ed := range []Edition{EditionCore, "platinum", ""} {
		e := resolvedBool(gatedBool, rowsTierGrant)
		applyLicense(e, &License{Edition: ed, ExpiresAt: now.Add(time.Hour)}, now)
		if on, _ := e.BooleanValue(); on {
			t.Errorf("licence edition %q enabled a gated capability", ed)
		}
	}
}

func TestLicenseActive_ExpiryBoundary(t *testing.T) {
	now := time.Now()
	l := &License{Edition: EditionMSP, ExpiresAt: now}
	if l.Active(now) {
		t.Error("a licence is active at its exact expiry instant; it must lapse AT expires_at")
	}
	if !l.Active(now.Add(-time.Nanosecond)) {
		t.Error("a licence is inactive just before its expiry")
	}
	var none *License
	if none.Active(now) {
		t.Error("a nil licence is active")
	}
}

// The cache: one query per TTL, a flush forces a re-read, errors are not
// cached. Driven through sqlmock so the query count is observable.
func TestLoadLicense_CachesAndFlushes(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	FlushLicenseCache()
	t.Cleanup(FlushLicenseCache)

	q := regexp.QuoteMeta(selectLicenseSQL)
	exp := time.Now().Add(time.Hour)
	mock.ExpectQuery(q).WillReturnRows(sqlmock.NewRows([]string{"edition", "expires_at", "licensee"}).AddRow("msp", exp, "Acme MSP"))

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		lic, err := LoadLicense(ctx, db)
		if err != nil || lic == nil || lic.Edition != EditionMSP {
			t.Fatalf("load %d: lic=%+v err=%v", i, lic, err)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expected ONE query for three loads within the TTL: %v", err)
	}

	// Flush → re-read; a missing row is Core (nil, nil) and is cached too.
	FlushLicenseCache()
	mock.ExpectQuery(q).WillReturnRows(sqlmock.NewRows([]string{"edition", "expires_at", "licensee"}))
	lic, err := LoadLicense(ctx, db)
	if err != nil || lic != nil {
		t.Fatalf("after flush with no row: lic=%+v err=%v, want nil, nil", lic, err)
	}

	// An error is returned and NOT cached: the next load queries again.
	FlushLicenseCache()
	mock.ExpectQuery(q).WillReturnError(errors.New("connection refused"))
	if _, err := LoadLicense(ctx, db); err == nil {
		t.Fatal("a failed licence read returned no error — gates would treat it as Core silently")
	}
	mock.ExpectQuery(q).WillReturnRows(sqlmock.NewRows([]string{"edition", "expires_at", "licensee"}).AddRow("enterprise", exp, "Acme Corp"))
	// An Enterprise licence also reads the platform retention cap.
	mock.ExpectQuery(regexp.QuoteMeta(selectRetentionSQL)).WithArgs(RetentionSettingKey).
		WillReturnRows(sqlmock.NewRows([]string{"setting_value"}).AddRow([]byte("730")))
	lic, err = LoadLicense(ctx, db)
	if err != nil || lic == nil || lic.Edition != EditionEnterprise {
		t.Fatalf("load after an error: lic=%+v err=%v — the error was cached", lic, err)
	}
	if lic.Licensee != "Acme Corp" || lic.RetentionMaxDays == nil || *lic.RetentionMaxDays != 730 {
		t.Fatalf("Enterprise licence = %+v, want licensee Acme Corp and a 730-day retention cap", lic)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// Concurrent loads must be safe (run with -race).
func TestLoadLicense_ConcurrentUse(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	mock.MatchExpectationsInOrder(false)
	FlushLicenseCache()
	t.Cleanup(FlushLicenseCache)
	for i := 0; i < 16; i++ {
		mock.ExpectQuery(regexp.QuoteMeta(selectLicenseSQL)).
			WillReturnRows(sqlmock.NewRows([]string{"edition", "expires_at", "licensee"}).AddRow("msp", time.Now().Add(time.Hour), ""))
	}
	done := make(chan struct{})
	for i := 0; i < 16; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 20; j++ {
				if j%7 == 0 {
					FlushLicenseCache()
				}
				_, _ = LoadLicense(context.Background(), db)
			}
		}()
	}
	for i := 0; i < 16; i++ {
		<-done
	}
}
