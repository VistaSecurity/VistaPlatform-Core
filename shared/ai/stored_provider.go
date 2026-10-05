package ai

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

// A provider configured in the database rather than the environment.
//
// # Three places a provider can come from
//
//   - a TENANT's own, connected from Settings → AI assistant and stored in that
//     tenant's settings row;
//   - the PLATFORM default, set by a platform administrator in admin-ui and
//     stored in platform_settings;
//   - the ENVIRONMENT (`AI_PROVIDER` and friends), set by whoever installs the
//     chart.
//
// [Resolver] picks between them. This file is the first two: the shape they are
// stored in, the cipher for the credential, and the readers and writers.
//
// # The credential
//
// [ProviderConfig] has no key field and still has none. What is stored is
// ciphertext under the deployment's ENCRYPTION_MASTER_KEY, plus the last four
// characters so a settings page can show which key is connected without ever
// being able to show the key. The plaintext exists only inside
// [KeyCipher.Open], called by the config's key source at the moment of use.

// StoredProvider is the persisted shape, for a tenant and for the platform
// default alike.
type StoredProvider struct {
	// Kind is "anthropic" or "openai_compat". "none" is not stored: no
	// provider is the absence of a row, not a row saying so.
	Kind string `json:"kind"`

	// BaseURL is the endpoint. Optional for anthropic, required for
	// openai_compat.
	BaseURL string `json:"base_url,omitempty"`

	// Model is the model id. Optional for anthropic, required for
	// openai_compat.
	Model string `json:"model,omitempty"`

	// AllowPrivateEndpoints is honoured for the PLATFORM default only, where
	// the person setting it is the operator. For a tenant it is never read:
	// whether tenants may point the platform at a private address is one
	// operator switch ([PlatformAISettings.TenantPrivateEndpointsAllowed]), and
	// a tenant's row cannot grant it to itself whatever it contains.
	AllowPrivateEndpoints bool `json:"allow_private_endpoints,omitempty"`

	// APIKeyEnc is the credential as [KeyCipher.Seal] wrote it. Empty means no
	// credential, which is legitimate for openai_compat.
	APIKeyEnc string `json:"api_key_enc,omitempty"`

	// APIKeyHint is the last four characters of the key, for display.
	APIKeyHint string `json:"api_key_hint,omitempty"`
}

// Host returns the endpoint's host for display, or "" when the base URL is
// empty or unparseable. A settings page shows the host and never the full URL:
// the path and any query are the part that can carry something nobody meant to
// put on a screen.
func (s StoredProvider) Host() string {
	raw := strings.TrimSpace(s.BaseURL)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// SameEndpoint reports whether two stored configurations would send a
// credential to the same place: same kind, same base URL.
//
// It is the rule for reusing a stored key on a save that did not supply one.
// Without it, anyone who may edit the settings could repoint the base URL at a
// host of their own and have the platform deliver a key they were never shown.
// A changed endpoint needs the key typed again.
func (s StoredProvider) SameEndpoint(other StoredProvider) bool {
	return NormalizeKind(s.Kind) == NormalizeKind(other.Kind) &&
		strings.TrimRight(strings.TrimSpace(s.BaseURL), "/") == strings.TrimRight(strings.TrimSpace(other.BaseURL), "/")
}

// ── The credential cipher ──────────────────────────────────────────────────

// keyEncPrefix marks a stored value as ciphertext from the shared AES-256-GCM
// envelope. Same convention as the CMDB connection credentials: a value with
// the prefix MUST decrypt, so a wrong master key surfaces as an error rather
// than as ciphertext sent to a provider as a bearer token.
const keyEncPrefix = "enc:v1:"

// ErrNoMasterKey is returned when a credential has to be sealed or opened and
// this process has no ENCRYPTION_MASTER_KEY.
//
// There is deliberately no plaintext fallback. A deployment without the master
// key cannot store a provider credential at all, and says so — the alternative
// is an API key in a settings row in clear, which is the thing the key-less
// [ProviderConfig] exists to make impossible.
var ErrNoMasterKey = errors.New("ai: this deployment has no ENCRYPTION_MASTER_KEY, so a provider credential cannot be stored or read")

// KeyCipher seals and opens provider credentials.
type KeyCipher struct {
	enc *encryption.Service
}

// NewKeyCipher builds a cipher from a master key. An empty key yields a cipher
// that refuses every operation with [ErrNoMasterKey] rather than a nil one, so
// a caller holding it cannot panic and cannot store plaintext.
func NewKeyCipher(masterKey string) *KeyCipher {
	if strings.TrimSpace(masterKey) == "" {
		return &KeyCipher{}
	}
	enc, err := encryption.NewService(masterKey)
	if err != nil {
		return &KeyCipher{}
	}
	return &KeyCipher{enc: enc}
}

// KeyCipherFromEnv reads ENCRYPTION_MASTER_KEY.
func KeyCipherFromEnv() *KeyCipher {
	return NewKeyCipher(os.Getenv("ENCRYPTION_MASTER_KEY"))
}

// Usable reports whether this cipher has a master key.
func (k *KeyCipher) Usable() bool { return k != nil && k.enc != nil }

// Seal encrypts a credential and returns the stored form and its display hint.
// An empty credential seals to two empty strings: no key is a real answer for
// an endpoint that needs none, and it needs no master key to say.
func (k *KeyCipher) Seal(plain string) (stored, hint string, err error) {
	plain = strings.TrimSpace(plain)
	if plain == "" {
		return "", "", nil
	}
	if !k.Usable() {
		return "", "", ErrNoMasterKey
	}
	ct, err := k.enc.Encrypt(plain)
	if err != nil {
		return "", "", fmt.Errorf("ai: seal provider credential: %w", err)
	}
	return keyEncPrefix + ct, keyHint(plain), nil
}

// Open decrypts a stored credential. A value without the ciphertext prefix is
// refused: nothing in this package ever writes one, so it is a row someone
// edited by hand, and sending it on as a key would be guessing.
func (k *KeyCipher) Open(stored string) (string, error) {
	if stored == "" {
		return "", nil
	}
	if !strings.HasPrefix(stored, keyEncPrefix) {
		return "", errors.New("ai: stored provider credential is not in the encrypted form")
	}
	if !k.Usable() {
		return "", ErrNoMasterKey
	}
	plain, err := k.enc.Decrypt(strings.TrimPrefix(stored, keyEncPrefix))
	if err != nil {
		return "", fmt.Errorf("ai: open provider credential (was ENCRYPTION_MASTER_KEY changed?): %w", err)
	}
	return plain, nil
}

// keyHint is the last four characters, and nothing for a key too short for
// four characters to be a small fraction of it.
func keyHint(plain string) string {
	if len(plain) < 12 {
		return ""
	}
	return plain[len(plain)-4:]
}

// ── A tenant's own provider ────────────────────────────────────────────────

// TenantProviderConfigKey is the key under `tenant_admin_settings.config` a
// tenant's provider lives at.
//
// A sibling of [TenantControlsConfigKey], not a child of it:
// [SetTenantAIControls] replaces the whole `ai` object on every save of the two
// switches, so a provider stored inside it would be erased by toggling
// "record the questions we send".
const TenantProviderConfigKey = "ai_provider"

// TenantProvider reads a tenant's own provider, or nil when it has none.
// RLS-scoped, like every read of this table.
func TenantProvider(ctx context.Context, db *sql.DB, tenantID uuid.UUID) (*StoredProvider, error) {
	if db == nil {
		return nil, errors.New("ai: tenant provider: no database handle")
	}
	if tenantID == uuid.Nil {
		return nil, ErrNoTenantScope
	}
	var raw []byte
	err := shareddatabase.WithTenantTx(ctx, db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT config -> $2
			FROM tenant_admin_settings
			WHERE tenant_id = $1
		`, tenantID, TenantProviderConfigKey).Scan(&raw)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ai: read tenant provider: %w", err)
	}
	return decodeStoredProvider(raw)
}

// SetTenantProvider stores a tenant's provider, preserving every other key in
// the settings blob. Seed-then-UPDATE for the reason [SetTenantAIControls]
// gives: the audit trigger is AFTER UPDATE, and the first save is the one most
// worth recording.
//
// AllowPrivateEndpoints is cleared before the write. It is never read for a
// tenant either, but a row that does not contain it cannot be misread by
// whatever is written next.
func SetTenantProvider(ctx context.Context, db *sql.DB, tenantID, updatedBy uuid.UUID, sp StoredProvider) error {
	if db == nil {
		return errors.New("ai: tenant provider: no database handle")
	}
	if tenantID == uuid.Nil {
		return ErrNoTenantScope
	}
	sp.Kind = NormalizeKind(sp.Kind)
	sp.AllowPrivateEndpoints = false
	blob, err := json.Marshal(sp)
	if err != nil {
		return fmt.Errorf("ai: encode tenant provider: %w", err)
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
		`, tenantID, string(blob), TenantProviderConfigKey, updatedBy)
		return err
	})
}

// DeleteTenantProvider removes a tenant's provider and its credential. A tenant
// with none is not an error.
func DeleteTenantProvider(ctx context.Context, db *sql.DB, tenantID, updatedBy uuid.UUID) error {
	if db == nil {
		return errors.New("ai: tenant provider: no database handle")
	}
	if tenantID == uuid.Nil {
		return ErrNoTenantScope
	}
	return shareddatabase.WithTenantTx(ctx, db, tenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE tenant_admin_settings SET
				config = tenant_admin_settings.config - $2::text,
				version = tenant_admin_settings.version + 1,
				updated_by = $3,
				updated_at = NOW()
			WHERE tenant_id = $1 AND tenant_admin_settings.config ? $2::text
		`, tenantID, TenantProviderConfigKey, updatedBy)
		return err
	})
}

func decodeStoredProvider(raw []byte) (*StoredProvider, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var sp StoredProvider
	if err := json.Unmarshal(raw, &sp); err != nil {
		return nil, fmt.Errorf("ai: decode stored provider: %w", err)
	}
	sp.Kind = NormalizeKind(sp.Kind)
	if sp.Kind == "" || sp.Kind == ProviderNone {
		return nil, nil
	}
	return &sp, nil
}

// ── The platform's settings ────────────────────────────────────────────────

// The platform_settings keys. All three share the `ai.` prefix, which is what
// the table's write guard matches: they decide where every tenant's prompts go
// and what address space a tenant may aim the platform at, so only a platform
// administrator's connection may change them.
const (
	PlatformProviderSettingKey               = "ai.provider"
	PlatformTenantProvidersAllowedSettingKey = "ai.tenant_providers_allowed"
	PlatformTenantPrivateEndpointsSettingKey = "ai.tenant_private_endpoints_allowed"
)

// PlatformAISettings is what a platform administrator has decided.
type PlatformAISettings struct {
	// Provider is the default for every tenant, or nil when none is set here
	// (the environment may still name one).
	Provider *StoredProvider

	// TenantProvidersAllowed is whether tenants may connect their own provider
	// at all. Default TRUE: absent a decision, an organization running the
	// platform for itself has no reason to stop its own teams. A plan that does
	// not include the capability is a separate gate, applied by the caller.
	TenantProvidersAllowed bool

	// TenantPrivateEndpointsAllowed is whether a TENANT's endpoint may be on a
	// loopback, private or link-local address. Default FALSE, and the default
	// is the important half: a tenant-typed private address is exactly what the
	// outbound guard exists to refuse.
	TenantPrivateEndpointsAllowed bool
}

// ReadPlatformAISettings reads all three in one round trip. Missing rows are
// the defaults, not errors.
func ReadPlatformAISettings(ctx context.Context, db *sql.DB) (PlatformAISettings, error) {
	out := PlatformAISettings{TenantProvidersAllowed: true}
	if db == nil {
		return out, errors.New("ai: platform AI settings: no database handle")
	}
	rows, err := db.QueryContext(ctx, `
		SELECT setting_key, setting_value
		FROM platform_settings
		WHERE setting_key = ANY($1)
	`, pq.Array([]string{
		PlatformProviderSettingKey,
		PlatformTenantProvidersAllowedSettingKey,
		PlatformTenantPrivateEndpointsSettingKey,
	}))
	if err != nil {
		return PlatformAISettings{}, fmt.Errorf("ai: read platform AI settings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var key string
		var raw []byte
		if err := rows.Scan(&key, &raw); err != nil {
			return PlatformAISettings{}, fmt.Errorf("ai: read platform AI settings: %w", err)
		}
		switch key {
		case PlatformProviderSettingKey:
			sp, err := decodeStoredProvider(raw)
			if err != nil {
				return PlatformAISettings{}, err
			}
			out.Provider = sp
		case PlatformTenantProvidersAllowedSettingKey:
			if err := json.Unmarshal(raw, &out.TenantProvidersAllowed); err != nil {
				return PlatformAISettings{}, fmt.Errorf("ai: decode %s: %w", key, err)
			}
		case PlatformTenantPrivateEndpointsSettingKey:
			if err := json.Unmarshal(raw, &out.TenantPrivateEndpointsAllowed); err != nil {
				return PlatformAISettings{}, fmt.Errorf("ai: decode %s: %w", key, err)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return PlatformAISettings{}, fmt.Errorf("ai: read platform AI settings: %w", err)
	}
	return out, nil
}

// SetPlatformProvider stores the platform default. db must be a connection the
// platform_settings write guard accepts — the platform administrator's pool,
// not a tenant-scoped one. updatedBy is a platform user, or uuid.Nil.
func SetPlatformProvider(ctx context.Context, db *sql.DB, updatedBy uuid.UUID, sp StoredProvider) error {
	sp.Kind = NormalizeKind(sp.Kind)
	blob, err := json.Marshal(sp)
	if err != nil {
		return fmt.Errorf("ai: encode platform provider: %w", err)
	}
	return upsertPlatformSetting(ctx, db, updatedBy, PlatformProviderSettingKey, blob,
		"Default AI model provider for every tenant (admin-ui → Settings → AI assistant)")
}

// DeletePlatformProvider removes the platform default.
func DeletePlatformProvider(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("ai: platform AI settings: no database handle")
	}
	_, err := db.ExecContext(ctx, `DELETE FROM platform_settings WHERE setting_key = $1`, PlatformProviderSettingKey)
	return err
}

// SetPlatformTenantSwitches stores the two switches that govern tenants.
func SetPlatformTenantSwitches(ctx context.Context, db *sql.DB, updatedBy uuid.UUID, providersAllowed, privateEndpointsAllowed bool) error {
	if err := upsertPlatformSetting(ctx, db, updatedBy, PlatformTenantProvidersAllowedSettingKey,
		boolJSON(providersAllowed), "Whether tenants may connect their own AI model provider"); err != nil {
		return err
	}
	return upsertPlatformSetting(ctx, db, updatedBy, PlatformTenantPrivateEndpointsSettingKey,
		boolJSON(privateEndpointsAllowed), "Whether a tenant's AI model endpoint may be on a private or in-cluster address")
}

func boolJSON(b bool) []byte {
	if b {
		return []byte("true")
	}
	return []byte("false")
}

func upsertPlatformSetting(ctx context.Context, db *sql.DB, updatedBy uuid.UUID, key string, value []byte, description string) error {
	if db == nil {
		return errors.New("ai: platform AI settings: no database handle")
	}
	var by interface{}
	if updatedBy != uuid.Nil {
		by = updatedBy
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO platform_settings (setting_key, setting_value, description, updated_by)
		VALUES ($1, $2::jsonb, $3, $4)
		ON CONFLICT (setting_key) DO UPDATE SET
			setting_value = EXCLUDED.setting_value,
			updated_by = EXCLUDED.updated_by,
			updated_at = NOW()
	`, key, string(value), description, by)
	if err != nil {
		return fmt.Errorf("ai: write platform setting %s: %w", key, err)
	}
	return nil
}
