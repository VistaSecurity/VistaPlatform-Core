package services

// The tenant's identification settings — today, one number: the learned
// matcher's auto-accept threshold (workstream 4.6, ADR-0002 D3).
//
// It lives in `tenant_admin_settings.config` under the `identity` key, beside
// `discovery_auto_scan` and `network_spaces`, because that is where this
// platform's tenant-admin settings live and a second home for one number would
// be a second thing to back up, migrate and reason about. The table carries an
// audit trigger (`log_tenant_admin_settings_change`), so a change to the
// threshold is already recorded with who made it — which matters more here than
// for most settings: this is the one number that lets the platform merge two
// assets without asking.

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity/identitysettings"
)

// The key names, the default and the invalid-value error are shared/identity's
// (`shared/identity/identitysettings`), not this package's, and these are
// aliases rather than copies.
//
// The reader moved there for workstream 4.6a: device-interrogation-service's
// two identification engines have to read the SAME setting from the SAME key,
// and a second spelling of `identity.auto_accept_threshold` would be a silent
// divergence on the one setting that decides whether the platform may merge two
// assets unasked. The WRITER stays here — it is the settings API and it owns the
// first-save audit dance below.
const (
	IdentitySettingsKey        = identitysettings.Key
	AutoAcceptThresholdKey     = identitysettings.AutoAcceptThresholdKey
	DefaultAutoAcceptThreshold = identitysettings.DefaultAutoAcceptThreshold
)

// ErrInvalidAutoAcceptThreshold is returned for a threshold outside 0..1.
var ErrInvalidAutoAcceptThreshold = identitysettings.ErrInvalidAutoAcceptThreshold

// IdentificationSettings is the tenant's identification configuration as the
// Settings page reads and writes it.
type IdentificationSettings struct {
	// AutoAcceptThreshold is the matcher score at or above which the engine may
	// accept a merge proposal on the tenant's behalf. 0 means never.
	AutoAcceptThreshold float64 `json:"auto_accept_threshold"`

	// MatcherModelID names the model that will do the scoring, so the page can
	// say what the threshold is a threshold ON. Empty when no matcher is
	// configured, in which case nothing is ever scored and the threshold cannot
	// fire whatever it is set to — which the page says rather than leaving the
	// control looking live.
	MatcherModelID string `json:"matcher_model_id,omitempty"`

	// Version is `tenant_admin_settings.version` after the write, echoed so a
	// caller can see its change landed.
	Version int `json:"version,omitempty"`
}

// IdentificationSettingsService reads and writes them.
type IdentificationSettingsService struct {
	db *database.DB
}

// NewIdentificationSettingsService constructs the service.
func NewIdentificationSettingsService(db *database.DB) *IdentificationSettingsService {
	return &IdentificationSettingsService{db: db}
}

// Get returns the tenant's settings, or the defaults when they have never been
// written.
func (s *IdentificationSettingsService) Get(ctx context.Context, tenantID uuid.UUID) (IdentificationSettings, error) {
	out := IdentificationSettings{AutoAcceptThreshold: DefaultAutoAcceptThreshold}
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		threshold, err := identitysettings.ReadAutoAcceptThreshold(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		out.AutoAcceptThreshold = threshold
		return nil
	})
	if err != nil {
		return IdentificationSettings{}, err
	}
	return out, nil
}

// Set writes the threshold, preserving every other key in the config.
//
// A value outside 0..1 is REFUSED rather than clamped. Clamping 1.5 to 1 would
// store a threshold the tenant did not ask for on the one setting that decides
// whether the platform may merge two assets unasked, and "we rounded your
// number" is not an acceptable answer there.
func (s *IdentificationSettingsService) Set(ctx context.Context, tenantID, actorUserID uuid.UUID, threshold float64) (IdentificationSettings, error) {
	if threshold < 0 || threshold > 1 {
		return IdentificationSettings{}, fmt.Errorf("%w (got %v)", ErrInvalidAutoAcceptThreshold, threshold)
	}
	var version int
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		// Read-modify-write inside ONE transaction. `config` is a single jsonb
		// document several features share (discovery_auto_scan, network_spaces,
		// onboarding_required), so a read outside the transaction and a write
		// inside it would drop whichever of them changed in between.
		//
		// The merge is done in SQL rather than in Go, so a concurrent writer to a
		// DIFFERENT key cannot be clobbered by this one re-serialising a
		// document it read a moment ago.
		//
		// The `||` before the jsonb_set is NOT redundant, and leaving it out is
		// a silent no-op. `jsonb_set(doc, ARRAY['identity','auto_accept_threshold'], …,
		// create_if_missing => true)` creates only the LAST element of the path:
		// if `identity` is absent, the whole call returns its input unchanged
		// and reports success. That is the "a rewrite that matches nothing
		// returns its input and says nothing" shape — the threshold simply never
		// landed, on exactly the tenants who had OTHER settings and no identity
		// block, which is every tenant who has ever touched a setting.
		// TestIntegration_IdentificationSettings_PreserveOtherKeys is what
		// caught it and is what keeps it caught.
		//
		// The concatenation ensures `identity` exists first, carrying forward
		// whatever it already held (COALESCE of the existing object, not an
		// empty one — otherwise this would clobber future keys under it).
		var actor any
		if actorUserID != uuid.Nil {
			actor = actorUserID
		}

		// # Why this is two statements and not one upsert
		//
		// `log_tenant_admin_settings_change` is an AFTER **UPDATE** trigger that
		// reads OLD.config/OLD.version (and `version_before` is NOT NULL), so it
		// cannot fire on an INSERT. A single `INSERT … ON CONFLICT DO UPDATE`
		// therefore writes NO audit row for a tenant who has no settings row yet
		// — and the first save is precisely the one worth recording here: it is
		// the save that first grants the platform permission to merge two of
		// this tenant's assets without asking. "Nothing was recorded" and
		// "nobody changed it" would be indistinguishable afterwards.
		//
		// So: seed the row if it is missing (a no-op if it is not), then UPDATE,
		// which always fires the trigger because `version` always moves. The
		// seeded `{}` is what `config_before` honestly says for a tenant who had
		// no settings. Same gap, same fix as shared/ai's SetTenantAIControls.
		// TestIntegration_IdentificationSettings_FirstSaveIsAudited pins it.
		//
		// Both statements run inside the one WithTenantTx, so a concurrent
		// writer cannot land between them and the pair is atomic.
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
			        to_jsonb($4::numeric),
			        true),
			    version = tenant_admin_settings.version + 1,
			    updated_by = $5,
			    updated_at = NOW()
			WHERE tenant_id = $1
			RETURNING version`,
			tenantID, IdentitySettingsKey, AutoAcceptThresholdKey, threshold, actor).Scan(&version)
	})
	if err != nil {
		return IdentificationSettings{}, fmt.Errorf("save the identification settings: %w", err)
	}
	return IdentificationSettings{AutoAcceptThreshold: threshold, Version: version}, nil
}
