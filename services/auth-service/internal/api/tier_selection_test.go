package api

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// The pattern must carry EVERY predicate the query relies on for safety.
// sqlmock matches it as an UNANCHORED regexp, so a pattern that stops early
// matches whether or not the remaining clauses are present — which is how the
// `price_cents = 0` guard sat here completely unpinned: these tests stub the DB
// answer, so they prove "if no row comes back we reject", never "a paid tier
// produces no row". Dropping the clause from the query changed no test.
//
// Extend this pattern whenever the query grows a predicate, and pair it with
// the real-Postgres test in select_tier_gate_integration_test.go, which proves
// the behaviour rather than the text.
const selfServiceTierQueryPattern = `SELECT 1\s+FROM subscription_tiers\s+WHERE id = \$1\s+AND is_active = true\s+AND COALESCE\(is_custom, false\) = false\s+AND owner_tenant_id IS NULL\s+AND COALESCE\(is_trial, false\) = true\s+AND COALESCE\(price_cents, 0\) = 0`

func TestValidateSelfServiceTierSelectionAllowsFreePublicTrialTier(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	tierID := uuid.New()
	mock.ExpectQuery(selfServiceTierQueryPattern).
		WithArgs(tierID).
		WillReturnRows(sqlmock.NewRows([]string{"?column?"}).AddRow(1))

	if err := validateSelfServiceTierSelection(context.Background(), db, tierID); err != nil {
		t.Fatalf("validateSelfServiceTierSelection() = %v, want nil", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func TestValidateSelfServiceTierSelectionRejectsPaidPublicTier(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	tierID := uuid.New()
	mock.ExpectQuery(selfServiceTierQueryPattern).
		WithArgs(tierID).
		WillReturnError(sql.ErrNoRows)

	err = validateSelfServiceTierSelection(context.Background(), db, tierID)
	if !errors.Is(err, errTierNotSelfSelectable) {
		t.Fatalf("validateSelfServiceTierSelection() = %v, want errTierNotSelfSelectable", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func TestValidateSelfServiceTierSelectionRejectsZeroPriceNonTrialTier(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	tierID := uuid.New()
	mock.ExpectQuery(selfServiceTierQueryPattern).
		WithArgs(tierID).
		WillReturnError(sql.ErrNoRows)

	err = validateSelfServiceTierSelection(context.Background(), db, tierID)
	if !errors.Is(err, errTierNotSelfSelectable) {
		t.Fatalf("validateSelfServiceTierSelection() = %v, want errTierNotSelfSelectable", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func TestValidateSelfServiceTierSelectionRejectsPrivateOrInactiveTier(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	tierID := uuid.New()
	mock.ExpectQuery(selfServiceTierQueryPattern).
		WithArgs(tierID).
		WillReturnError(sql.ErrNoRows)

	err = validateSelfServiceTierSelection(context.Background(), db, tierID)
	if !errors.Is(err, errTierNotSelfSelectable) {
		t.Fatalf("validateSelfServiceTierSelection() = %v, want errTierNotSelfSelectable", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func TestListActiveTiersFiltersCatalogToTrialOrPricedStripePlans(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectQuery(`(?s)FROM subscription_tiers.*WHERE is_active = true.*AND COALESCE\(is_custom, false\) = false\s+AND owner_tenant_id IS NULL\s+AND \(COALESCE\(is_trial, false\) = true OR \(billing_method = 'stripe' AND COALESCE\(price_cents, 0\) > 0\)\)`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "display_name", "max_sensors", "max_assets", "max_users",
			"retention_days", "price_cents", "annual_price_cents", "billing_interval",
			"features", "limits", "is_active",
		}).AddRow(
			uuid.New(), "free", "Free", 1, 50, -1,
			7, 0, 0, "monthly", []byte(`{}`), []byte(`{}`), true,
		))

	tiers, err := newBillingRepo(db).ListActiveTiers(context.Background())
	if err != nil {
		t.Fatalf("ListActiveTiers() error = %v", err)
	}
	if len(tiers) != 1 || tiers[0].Name != "free" {
		t.Fatalf("ListActiveTiers() = %+v, want only free tier", tiers)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}
