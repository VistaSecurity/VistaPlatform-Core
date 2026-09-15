package ai

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// The tenant's own controls over the AI assistant, and the ONE helper every
// generative seam call site reads them through.
//
// Two decisions belong to the tenant rather than to the operator (ADR-0008 D4.7
// for the second, and the plain fact that the first is their data for the
// first):
//
//   - assistant_disabled — a kill switch. The deployment may have a provider
//     configured and every seam live; a tenant that turns this on has no
//     generative call made on its behalf, by any seam, at all.
//   - record_questions — the D4.7 opt-in. "Prompts themselves are not stored
//     unless the tenant opts in." Off by default, and off means the audit trail
//     carries the prompt HASH and the platform's own derived artefacts (a
//     canonical query, an outcome, a count) and not a word the user typed.
//
// # Where they live, and why not in a new table
//
// `tenant_admin_settings.config` is the tenant's settings blob — one jsonb row
// per tenant, audited by the `log_tenant_admin_settings_change` trigger, RLS
// isolated, already carrying `onboarding_required` and `email_config`. These
// two booleans go under the `ai` key of that object. A new table would have
// bought a second audit trigger, a second RLS policy and a second migration for
// two booleans.
//
// Read and write both live HERE rather than in the service that serves the
// settings page, so the shape of `config->'ai'` has exactly one owner. A reader
// in shared/ and a writer in auth-service is two spellings of the same
// key waiting to disagree.
//
// # How a call site uses them
//
// Once, at the top of a request that is about to reach a generative seam:
//
//	allowed, err := ai.TenantAllows(ctx, db, tenantID)   // or TenantAIControls for both
//	if err != nil { /* log; decide; see "Failure is not permission" below */ }
//	if !allowed { /* answer without a model — see the call site's own rule */ }
//	ctx = ai.WithTenantControls(ctx, controls)
//
// The stamp on the context is not decoration. [WithAudit] reads it, so the
// kill switch is enforced a second time at the provider boundary — the same
// defence-in-depth shape as the providers re-checking `req.IsSanitized()` after
// `Boundary` already guaranteed it. A seam added tomorrow that forgets the
// call-site check is still refused, provided its caller stamped the context;
// and a caller that has a tenant id and a database handle has no reason not to.
//
// # Failure is not permission
//
// A read that errors returns `allowed = false`. A settings read that cannot be
// completed is not evidence that the tenant said yes, and the direction to be
// wrong in is the one that sends nothing anywhere. Call sites log and fall back
// to their deterministic path, which every generative seam has by construction
// (ADR-0008: AI-native, never AI-dependent) — so failing closed here costs a
// narrative, not a page.

// TenantControls is the pair of tenant-owned switches, in the shape they are
// stored in and the shape the settings API returns.
type TenantControls struct {
	// AssistantDisabled turns every generative seam off for this tenant.
	// Classical seams (matcher, classifier, drift detector) are unaffected:
	// they run in-process, send nothing anywhere, and are not what this switch
	// is about.
	AssistantDisabled bool `json:"assistant_disabled"`

	// RecordQuestions is the D4.7 opt-in for storing the text a user typed in
	// the audit trail. Off by default.
	RecordQuestions bool `json:"record_questions"`
}

// TenantControlsConfigKey is the key under `tenant_admin_settings.config` these
// controls live at. Exported so a test can assert the reader and the writer
// agree rather than checking two string literals by eye.
const TenantControlsConfigKey = "ai"

// TenantAIControls reads both controls for one tenant.
//
// A tenant with no settings row, or a row with no `ai` key, gets the zero value
// — assistant enabled, questions not recorded — which is the documented default
// and not a guess: a tenant that has never opened the page has made neither
// decision, and the defaults are what the product does absent one.
//
// The read is RLS-scoped through [shareddatabase.WithTenantTx], like every
// other read of this table. A plain-pool query would return nothing once the
// service RLS role is on, silently, which is the shape the v0.5.0 sweep found
// across the codebase.
func TenantAIControls(ctx context.Context, db *sql.DB, tenantID uuid.UUID) (TenantControls, error) {
	var out TenantControls
	if db == nil {
		return out, errors.New("ai: tenant controls: no database handle")
	}
	if tenantID == uuid.Nil {
		// A platform-scope generative call (a platform admin drafting into the
		// shared framework catalogue, the nightly EOL gap pass) is not made on
		// behalf of a tenant and has no tenant controls to consult. Saying so
		// is better than scoping an RLS transaction to the nil tenant, which
		// WithTenantTx refuses anyway.
		return out, ErrNoTenantScope
	}

	var raw []byte
	err := shareddatabase.WithTenantTx(ctx, db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT config -> $2
			FROM tenant_admin_settings
			WHERE tenant_id = $1
		`, tenantID, TenantControlsConfigKey).Scan(&raw)
	})
	if errors.Is(err, sql.ErrNoRows) {
		// No settings row at all. The tenant has made no decision; the defaults
		// stand. Not an error.
		return out, nil
	}
	if err != nil {
		return TenantControls{}, fmt.Errorf("ai: read tenant AI controls: %w", err)
	}
	if len(raw) == 0 {
		// Row exists, `ai` key absent — `config -> 'ai'` scans as SQL NULL.
		return out, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return TenantControls{}, fmt.Errorf("ai: decode tenant AI controls: %w", err)
	}
	return out, nil
}

// ErrNoTenantScope is returned by [TenantAIControls] and [TenantAllows] for the
// nil tenant.
//
// It is its own error rather than a nil-tenant zero value because the two are
// different facts: "this tenant has not disabled the assistant" and "this call
// is not being made for a tenant" would otherwise be the same answer, and a
// platform-scope caller that started passing uuid.Nil by accident would look
// exactly like a permitted tenant.
var ErrNoTenantScope = errors.New("ai: no tenant in scope for the AI controls")

// TenantAllows reports whether a generative seam may run for this tenant.
//
// It is the single predicate every generative call site asks, and it fails
// closed: any error — no row is not an error, but a broken connection is —
// answers false.
//
// It deliberately returns the error as well. A call site that cannot tell "the
// tenant turned it off" from "the settings read failed" would tell a user the
// wrong thing about their own configuration, so the sentence a user sees is
// chosen by the caller from the error, not from the bool.
func TenantAllows(ctx context.Context, db *sql.DB, tenantID uuid.UUID) (bool, error) {
	tc, err := TenantAIControls(ctx, db, tenantID)
	if err != nil {
		return false, err
	}
	return !tc.AssistantDisabled, nil
}

// SetTenantAIControls writes both controls for one tenant, preserving every
// other key in the settings blob.
//
// The `||` merge is what keeps `onboarding_required` and `email_config` alive
// across a save from the AI page, and the `version` bump is what the
// `log_tenant_admin_settings_change` trigger records the change against.
// updatedBy is the acting user, and the trigger writes it into the audit row.
//
// # Why this is two statements and not one upsert
//
// `log_tenant_admin_settings_change` is an AFTER **UPDATE** trigger and reads
// `OLD.config` / `OLD.version`, so it cannot fire on an INSERT and could not be
// made to without a rewrite. A single `INSERT … ON CONFLICT DO UPDATE` therefore
// writes NO audit row for a tenant that has no settings row yet — and the first
// save is precisely the one worth recording: it is the save that turns the
// assistant off, or opts the organization in to storing the text its people
// type. "Nothing was recorded" and "nobody changed it" would look identical in
// the audit trail.
//
// So: seed the row if it is missing (no-op if it is not), then UPDATE. The
// second statement always fires the trigger, because `version` always moves.
// The seeded row's `{}` is what `config_before` honestly says for a tenant that
// had no settings.
//
// Both statements run inside the one [shareddatabase.WithTenantTx], so a
// concurrent writer cannot land between them and the pair is atomic.
func SetTenantAIControls(ctx context.Context, db *sql.DB, tenantID, updatedBy uuid.UUID, tc TenantControls) error {
	if db == nil {
		return errors.New("ai: tenant controls: no database handle")
	}
	if tenantID == uuid.Nil {
		return ErrNoTenantScope
	}
	blob, err := json.Marshal(tc)
	if err != nil {
		return fmt.Errorf("ai: encode tenant AI controls: %w", err)
	}
	return shareddatabase.WithTenantTx(ctx, db, tenantID, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO tenant_admin_settings (tenant_id, config, updated_by, updated_at)
			VALUES ($1, '{}'::jsonb, $2, NOW())
			ON CONFLICT (tenant_id) DO NOTHING
		`, tenantID, updatedBy); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `
			UPDATE tenant_admin_settings SET
				config = tenant_admin_settings.config || jsonb_build_object($3::text, $2::jsonb),
				version = tenant_admin_settings.version + 1,
				updated_by = $4,
				updated_at = NOW()
			WHERE tenant_id = $1
		`, tenantID, string(blob), TenantControlsConfigKey, updatedBy)
		return err
	})
}

// ── The context carrier ────────────────────────────────────────────────────

type tenantControlsKey struct{}

// WithTenantControls stamps a tenant's resolved controls on a context, so the
// provider boundary can enforce them without a second database read on a path
// that has neither a handle nor a tenant id ([Request] carries neither, by
// design — ADR-0008 D6).
//
// Stamp it at the call site that already read them. Both of this package's
// readers treat an unstamped context as "no decision recorded", which is the
// only answer available and is why the call-site check is the primary
// enforcement and this is the second lock rather than the first.
func WithTenantControls(ctx context.Context, tc TenantControls) context.Context {
	return context.WithValue(ctx, tenantControlsKey{}, tc)
}

// TenantControlsFrom returns the controls stamped on ctx, or the zero value.
func TenantControlsFrom(ctx context.Context) TenantControls {
	tc, _ := ctx.Value(tenantControlsKey{}).(TenantControls)
	return tc
}

// RecordQuestionsAllowed reports whether the tenant this call is being made for
// has opted in to having the text they typed stored in the audit trail.
//
// It is the single predicate for D4.7's opt-in, consulted by [WithAudit] for
// the per-call record and by the grounded query seam for its own grounding
// record. False for an unstamped context, which is the default and the safe
// direction: a call site that forgot to stamp records no prompt text, rather
// than recording it on a tenant's behalf without having asked.
func RecordQuestionsAllowed(ctx context.Context) bool {
	return TenantControlsFrom(ctx).RecordQuestions
}
