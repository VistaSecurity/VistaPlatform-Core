package api

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

const selfServiceTierQueryPattern = `SELECT 1\s+FROM subscription_tiers\s+WHERE id = \$1\s+AND is_active = true\s+AND COALESCE\(is_custom, false\) = false\s+AND owner_tenant_id IS NULL\s+AND COALESCE\(is_trial, false\) = true`

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
