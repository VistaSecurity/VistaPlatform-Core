// Package driftsettings holds the one number the `drift` producer is
// configured by: how far back its baseline window reaches (workstream 4.7,
// ADR-0005 D3).
//
// It lives in `tenant_admin_settings.config` under the `drift` key, beside
// `identity`, `capability_policy` and `network_spaces`, because that is where
// this platform's tenant-admin settings live and a second home for one number
// would be a second thing to back up, migrate and reason about. The table
// carries an audit trigger (`log_tenant_admin_settings_change`), so a change to
// the window is recorded with who made it.
//
// # Its own package, not a member of internal/services
//
// The reader is called from the PRODUCER, which lives in internal/producers and
// holds a plain `*sql.Tx`; the writer is called from a handler, which holds the
// service's sqlx pool. Putting the constants in internal/services would make
// the producers package import the whole service layer for three strings, and
// copying them into the producer is how the two spellings of one key drift
// apart. One small package, two importers, one definition of the key.
package driftsettings

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
)

// SettingsKey is the key inside `tenant_admin_settings.config` this block lives
// under.
const SettingsKey = "drift"

// BaselineDaysKey is the field inside it.
const BaselineDaysKey = "baseline_days"

// DefaultBaselineDays is the window a tenant who has never touched the setting
// gets.
//
// Thirty days: long enough that a monthly patch window, a quarterly-ish
// certificate rotation and an ordinary maintenance weekend are all INSIDE the
// baseline by the time the next one comes round, and short enough that "this is
// new" still means something a person can remember doing.
const DefaultBaselineDays = 30

// The bounds the window may be set to.
//
// Both ends are real limits rather than decoration. Below a week, a fortnightly
// scan schedule makes every scan look like drift — the previous observation of
// the same thing has already fallen out of the baseline, so the thing reads as
// new every time. Beyond a year the "baseline" stops describing anything
// current: a port opened eleven months ago is not news, and a tenant who wants
// that answer wants inventory history, not a drift finding.
const (
	MinBaselineDays = 7
	MaxBaselineDays = 365
)

// ErrInvalidBaselineDays is returned for a window outside the bounds.
var ErrInvalidBaselineDays = fmt.Errorf("the drift baseline window must be between %d and %d days",
	MinBaselineDays, MaxBaselineDays)

// Settings is the tenant's drift configuration as the Settings page reads and
// writes it.
type Settings struct {
	// BaselineDays is how far back the baseline reaches. Everything first
	// observed inside the window is a candidate for drift; everything older is
	// the baseline it is compared against.
	BaselineDays int `json:"baseline_days"`

	// Version is `tenant_admin_settings.version` after the write, echoed so a
	// caller can see its change landed.
	Version int `json:"version,omitempty"`
}

// Service reads and writes them.
type Service struct {
	db *database.DB
}

// NewService constructs the service.
func NewService(db *database.DB) *Service { return &Service{db: db} }

// Get returns the tenant's settings, or the default when they have never been
// written.
func (s *Service) Get(ctx context.Context, tenantID uuid.UUID) (Settings, error) {
	out := Settings{BaselineDays: DefaultBaselineDays}
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		days, err := ReadBaselineDaysTx(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		out.BaselineDays = days
		return nil
	})
	if err != nil {
		return Settings{}, err
	}
	return out, nil
}

// Set writes the window, preserving every other key in the config.
//
// A value outside the bounds is REFUSED rather than clamped, for the same
// reason the auto-accept threshold is: storing a number the tenant did not ask
// for, on a setting that decides what the platform reports as a change, is
// worse than telling them the number was wrong.
func (s *Service) Set(ctx context.Context, tenantID, actorUserID uuid.UUID, days int) (Settings, error) {
	if days < MinBaselineDays || days > MaxBaselineDays {
		return Settings{}, fmt.Errorf("%w (got %d)", ErrInvalidBaselineDays, days)
	}
	var version int
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		var actor any
		if actorUserID != uuid.Nil {
			actor = actorUserID
		}

		// Two statements, not one upsert, and the `||` before the jsonb_set is
		// not redundant. Both are the lessons of the identification settings
		// beside this one (workstream 4.6):
		//
		//   - `log_tenant_admin_settings_change` is an AFTER **UPDATE** trigger
		//     reading OLD.config/OLD.version, so it cannot fire on an INSERT. A
		//     single `INSERT … ON CONFLICT DO UPDATE` writes NO audit row for a
		//     tenant who has no settings row yet — and the first save is the one
		//     worth recording. So: seed the row if missing (a no-op if not),
		//     then UPDATE, which always fires because `version` always moves.
		//   - `jsonb_set(doc, ARRAY['drift','baseline_days'], …,
		//     create_if_missing => true)` creates only the LAST element of the
		//     path. With `drift` absent the whole call returns its input
		//     UNCHANGED and reports success — the "a rewrite that matches
		//     nothing returns its input and says nothing" shape. The
		//     concatenation ensures `drift` exists first, carrying forward
		//     whatever it already held.
		//
		// Both statements run inside the one WithTenantTx, so a concurrent
		// writer cannot land between them.
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO tenant_admin_settings (tenant_id, config, updated_by, created_at, updated_at)
			VALUES ($1, '{}'::jsonb, $2, NOW(), NOW())
			ON CONFLICT (tenant_id) DO NOTHING`,
			tenantID, actor); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `
			UPDATE tenant_admin_settings
			SET config = jsonb_set(
			        COALESCE(tenant_admin_settings.config, '{}'::jsonb)
			          || jsonb_build_object($2::text,
			               COALESCE(tenant_admin_settings.config -> $2::text, '{}'::jsonb)),
			        ARRAY[$2::text, $3::text],
			        to_jsonb($4::int),
			        true),
			    version = tenant_admin_settings.version + 1,
			    updated_by = $5,
			    updated_at = NOW()
			WHERE tenant_id = $1
			RETURNING version`,
			tenantID, SettingsKey, BaselineDaysKey, days, actor).Scan(&version)
	})
	if err != nil {
		return Settings{}, fmt.Errorf("save the drift settings: %w", err)
	}
	return Settings{BaselineDays: days, Version: version}, nil
}

// RowQuerier is the one method [ReadBaselineDaysTx] needs. Both `*sql.Tx` (the
// producer's) and `*sqlx.Tx` (the service's) satisfy it, which is what lets the
// pass and the settings page read the value through the same function instead of
// through two queries that agree until one is edited.
type RowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// ReadBaselineDaysTx reads the window on an existing tenant-scoped transaction.
//
// A tenant with no settings row, no `drift` block, or a value that is not an
// integer inside the bounds gets [DefaultBaselineDays]. Every one of those is
// "nobody has told us otherwise", and a corrupt value must not silently become
// a one-day window that reports the entire inventory as drift.
//
// Read PER PASS and never cached: the producer runs nightly, the setting is
// edited in a browser, and a cached window would keep answering with the old
// one until the service restarted.
func ReadBaselineDaysTx(ctx context.Context, q RowQuerier, tenantID uuid.UUID) (int, error) {
	var raw []byte
	err := q.QueryRowContext(ctx, `
		SELECT config -> $2 ->> $3
		FROM tenant_admin_settings
		WHERE tenant_id = $1`,
		tenantID, SettingsKey, BaselineDaysKey).Scan(&raw)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return DefaultBaselineDays, nil
	case err != nil:
		return DefaultBaselineDays, fmt.Errorf("read the drift baseline window: %w", err)
	case len(raw) == 0:
		return DefaultBaselineDays, nil
	}
	var days int
	if err := json.Unmarshal(raw, &days); err != nil {
		return DefaultBaselineDays, nil
	}
	if days < MinBaselineDays || days > MaxBaselineDays {
		return DefaultBaselineDays, nil
	}
	return days, nil
}
