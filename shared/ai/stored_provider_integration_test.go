package ai_test

// Stored providers against a real Postgres: the write guard on the platform's
// rows, RLS on a tenant's, and the resolver end to end over both.
//
// Three things here cannot be shown with a mock:
//
//   - The platform_settings write guard. The `ai.*` rows decide where every
//     tenant's prompts are sent; the tenant-scoped application role must be
//     able to READ them (every service does) and must not be able to write
//     them, directly or by renaming another row onto the key.
//   - That saving the two tenant switches does not erase the tenant's provider.
//     They share one settings row, and the switches' writer replaces its own
//     key wholesale — which is why the provider lives under a sibling key.
//   - That one tenant cannot read, and so cannot be served by, another
//     tenant's provider, under the role services actually connect as.
//
// Scratch database: it writes global settings. Skips without TEST_DATABASE_URL.

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/ai"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func isInsufficientPrivilege(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "42501"
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

func newUser(t *testing.T, owner *sql.DB, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	mustExec(t, owner, `
		INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name)
		VALUES ($1, $2, $3, 'x', 'It', 'User')`, id, tenantID, id.String()+"@example.test")
	return id
}

func TestIntegration_AISettings_PlatformRowsWritableOnlyByBypassOrOwner(t *testing.T) {
	owner := testdb.ScratchDatabase(t)
	app := testdb.ConnectScratchAsAppRole(t, owner)
	bypass := testdb.ConnectScratchAsBypassRole(t, owner)
	ctx := context.Background()

	rows := func() int {
		t.Helper()
		var n int
		if err := owner.QueryRow(`SELECT count(*) FROM platform_settings WHERE setting_key LIKE 'ai.%'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	refused := func(what string, err error) {
		t.Helper()
		if !isInsufficientPrivilege(err) {
			t.Errorf("crypto_app %s: err = %v, want insufficient_privilege (42501)", what, err)
		}
	}

	sp := ai.StoredProvider{Kind: "openai_compat", BaseURL: "https://attacker.example/v1", Model: "m"}

	// The application role can create none of the three — through the package's
	// own writers, which is the path an injected or mistaken call would take.
	refused("SetPlatformProvider", ai.SetPlatformProvider(ctx, app, uuid.Nil, sp))
	refused("SetPlatformTenantSwitches", ai.SetPlatformTenantSwitches(ctx, app, uuid.Nil, true, true))
	if n := rows(); n != 0 {
		t.Fatalf("crypto_app created %d ai.* row(s)", n)
	}

	// The platform administrator's pool can.
	good := ai.StoredProvider{Kind: "openai_compat", BaseURL: "https://llm.example/v1", Model: "m"}
	if err := ai.SetPlatformProvider(ctx, bypass, uuid.Nil, good); err != nil {
		t.Fatalf("bypass SetPlatformProvider: %v", err)
	}
	if err := ai.SetPlatformTenantSwitches(ctx, bypass, uuid.Nil, false, false); err != nil {
		t.Fatalf("bypass SetPlatformTenantSwitches: %v", err)
	}

	// Once they exist, the application role can neither change, remove nor
	// rename them — nor rename something else ONTO one.
	refused("overwrite", ai.SetPlatformProvider(ctx, app, uuid.Nil, sp))
	refused("flip the switches", ai.SetPlatformTenantSwitches(ctx, app, uuid.Nil, true, true))
	refused("DeletePlatformProvider", ai.DeletePlatformProvider(ctx, app))
	_, err := app.Exec(`UPDATE platform_settings SET setting_key = 'parked' WHERE setting_key = $1`, ai.PlatformProviderSettingKey)
	refused("rename away", err)
	mustExec(t, app, `INSERT INTO platform_settings (setting_key, setting_value) VALUES ('it.decoy', '{"kind":"openai_compat","base_url":"https://attacker.example"}'::jsonb)`)
	mustExec(t, bypass, `DELETE FROM platform_settings WHERE setting_key = $1`, ai.PlatformTenantPrivateEndpointsSettingKey)
	_, err = app.Exec(`UPDATE platform_settings SET setting_key = $1 WHERE setting_key = 'it.decoy'`, ai.PlatformTenantPrivateEndpointsSettingKey)
	refused("rename to", err)

	// It still READS them — every service resolves a provider on this pool —
	// and what it reads is what the administrator wrote, untouched.
	got, err := ai.ReadPlatformAISettings(ctx, app)
	if err != nil {
		t.Fatalf("crypto_app read: %v", err)
	}
	if got.Provider == nil || got.Provider.BaseURL != "https://llm.example/v1" {
		t.Fatalf("provider read back as %+v, want the administrator's", got.Provider)
	}
	if got.TenantProvidersAllowed || got.TenantPrivateEndpointsAllowed {
		t.Fatalf("switches read back as %t/%t, want false/false", got.TenantProvidersAllowed, got.TenantPrivateEndpointsAllowed)
	}

	// And the guard is not a blanket: an unrelated key is still the app's to
	// write (it.decoy above went in on the app pool).
	mustExec(t, app, `UPDATE platform_settings SET setting_value = '2'::jsonb WHERE setting_key = 'it.decoy'`)
}

// Defaults with no rows at all: tenants may connect their own, and may not use
// a private address. The second default is the one that matters.
func TestIntegration_AISettings_DefaultsWithNoRows(t *testing.T) {
	owner := testdb.ScratchDatabase(t)
	got, err := ai.ReadPlatformAISettings(context.Background(), owner)
	if err != nil {
		t.Fatal(err)
	}
	if got.Provider != nil || !got.TenantProvidersAllowed || got.TenantPrivateEndpointsAllowed {
		t.Fatalf("defaults = %+v, want no provider, tenants allowed, private endpoints NOT allowed", got)
	}
}

func TestIntegration_AISettings_TenantProviderRoundTripSurvivesTheSwitches(t *testing.T) {
	owner := testdb.ScratchDatabase(t)
	app := testdb.ConnectScratchAsAppRole(t, owner)
	ctx := context.Background()

	a, b := testdb.NewTenant(t, owner), testdb.NewTenant(t, owner)
	userA := newUser(t, owner, a)

	sp := ai.StoredProvider{
		Kind: "openai_compat", BaseURL: "https://a.example/v1", Model: "m",
		APIKeyEnc: "enc:v1:abc", APIKeyHint: "1234",
		AllowPrivateEndpoints: true, // a tenant's row must never keep this
	}
	if err := ai.SetTenantProvider(ctx, app, a, userA, sp); err != nil {
		t.Fatalf("SetTenantProvider: %v", err)
	}

	got, err := ai.TenantProvider(ctx, app, a)
	if err != nil || got == nil {
		t.Fatalf("TenantProvider(a) = %+v, %v", got, err)
	}
	if got.BaseURL != sp.BaseURL || got.APIKeyEnc != sp.APIKeyEnc || got.APIKeyHint != "1234" {
		t.Fatalf("read back %+v", got)
	}
	if got.AllowPrivateEndpoints {
		t.Fatal("a tenant's stored provider kept allow_private_endpoints")
	}

	// RLS: tenant B sees nothing of A's.
	if other, err := ai.TenantProvider(ctx, app, b); err != nil || other != nil {
		t.Fatalf("TenantProvider(b) = %+v, %v; want nil", other, err)
	}

	// Saving the two switches must not erase the provider, and saving the
	// provider must not erase the switches.
	if err := ai.SetTenantAIControls(ctx, app, a, userA, ai.TenantControls{RecordQuestions: true}); err != nil {
		t.Fatalf("SetTenantAIControls: %v", err)
	}
	if got, err := ai.TenantProvider(ctx, app, a); err != nil || got == nil {
		t.Fatalf("after saving the switches the provider is %+v, %v — it was erased", got, err)
	}
	sp.Model = "m2"
	if err := ai.SetTenantProvider(ctx, app, a, userA, sp); err != nil {
		t.Fatal(err)
	}
	if tc, err := ai.TenantAIControls(ctx, app, a); err != nil || !tc.RecordQuestions {
		t.Fatalf("after saving the provider the switches are %+v, %v — they were erased", tc, err)
	}

	// The settings-audit trigger recorded each change against the actor.
	var audited int
	if err := owner.QueryRow(`SELECT count(*) FROM tenant_admin_settings_audit WHERE tenant_id = $1 AND changed_by = $2`, a, userA).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited < 3 {
		t.Fatalf("%d audit row(s) for three settings changes", audited)
	}

	// Disconnect removes the provider and leaves the switches.
	if err := ai.DeleteTenantProvider(ctx, app, a, userA); err != nil {
		t.Fatal(err)
	}
	if got, err := ai.TenantProvider(ctx, app, a); err != nil || got != nil {
		t.Fatalf("after disconnect the provider is %+v, %v", got, err)
	}
	if tc, err := ai.TenantAIControls(ctx, app, a); err != nil || !tc.RecordQuestions {
		t.Fatalf("disconnect erased the switches: %+v, %v", tc, err)
	}
	// Disconnecting again is not an error.
	if err := ai.DeleteTenantProvider(ctx, app, a, userA); err != nil {
		t.Fatalf("second disconnect: %v", err)
	}
}

// itKind is a provider kind registered once for this test binary. Its
// instances record what they were sent, keyed by the base URL they were built
// for.
const itKind = "it-recording"

var (
	itOnce  sync.Once
	itMu    sync.Mutex
	itMocks = map[string]*ai.MockProvider{}
)

func registerITKind(t *testing.T) {
	t.Helper()
	itOnce.Do(func() {
		if err := ai.RegisterProvider(itKind, func(cfg ai.ProviderConfig) (ai.Provider, error) {
			itMu.Lock()
			defer itMu.Unlock()
			m := &ai.MockProvider{ProviderName: cfg.BaseURL}
			itMocks[cfg.BaseURL] = m
			return m, nil
		}); err != nil {
			t.Fatalf("register: %v", err)
		}
	})
}

func itRequests(baseURL string) int {
	itMu.Lock()
	defer itMu.Unlock()
	if m := itMocks[baseURL]; m != nil {
		return len(m.Requests())
	}
	return 0
}

// The whole path over a real database, as the role services connect as: two
// tenants with their own providers, a platform default, and a third tenant with
// nothing. Each prompt reaches exactly the endpoint it should, and a
// platform-scope call reaches the platform's whatever tenants have stored.
func TestIntegration_AIResolver_EachTenantReachesOnlyItsOwnProvider(t *testing.T) {
	owner := testdb.ScratchDatabase(t)
	app := testdb.ConnectScratchAsAppRole(t, owner)
	bypass := testdb.ConnectScratchAsBypassRole(t, owner)
	ctx := context.Background()
	registerITKind(t)
	t.Setenv("AI_PROVIDER", "")

	a, b, c := testdb.NewTenant(t, owner), testdb.NewTenant(t, owner), testdb.NewTenant(t, owner)
	userA, userB := newUser(t, owner, a), newUser(t, owner, b)
	cipher := ai.NewKeyCipher("it-master-key")

	seal := func(key string) (string, string) {
		enc, hint, err := cipher.Seal(key)
		if err != nil {
			t.Fatal(err)
		}
		return enc, hint
	}
	encA, hintA := seal("key-of-tenant-a-0001")
	encB, hintB := seal("key-of-tenant-b-0002")
	if err := ai.SetTenantProvider(ctx, app, a, userA, ai.StoredProvider{Kind: itKind, BaseURL: "https://it-a.example", APIKeyEnc: encA, APIKeyHint: hintA}); err != nil {
		t.Fatal(err)
	}
	if err := ai.SetTenantProvider(ctx, app, b, userB, ai.StoredProvider{Kind: itKind, BaseURL: "https://it-b.example", APIKeyEnc: encB, APIKeyHint: hintB}); err != nil {
		t.Fatal(err)
	}
	if err := ai.SetPlatformProvider(ctx, bypass, uuid.Nil, ai.StoredProvider{Kind: itKind, BaseURL: "https://it-platform.example"}); err != nil {
		t.Fatal(err)
	}

	resolver := ai.NewResolver(app, cipher, func(context.Context, uuid.UUID) (bool, error) { return true, nil })
	routed := resolver.Routed(ai.SinkFunc(func(context.Context, ai.AuditRecord) {}))
	req := ai.Request{Seam: ai.SeamQuery, Invoker: "it", Messages: []ai.Message{{Role: "user", Content: "hi"}}}

	for _, scope := range []struct {
		name string
		ctx  context.Context
	}{
		{"tenant a", ai.WithTenantScope(ctx, a)},
		{"tenant b", ai.WithTenantScope(ctx, b)},
		{"tenant c (none of its own)", ai.WithTenantScope(ctx, c)},
		{"platform", ctx},
	} {
		if _, err := routed.Complete(scope.ctx, req); err != nil {
			t.Fatalf("%s: %v", scope.name, err)
		}
	}

	for base, want := range map[string]int{
		"https://it-a.example":        1,
		"https://it-b.example":        1,
		"https://it-platform.example": 2, // tenant c, and the platform's own call
	} {
		if got := itRequests(base); got != want {
			t.Errorf("%s received %d prompt(s), want %d", base, got, want)
		}
	}

	// The operator turns tenant providers off: A and B are now served by the
	// platform's, and their own endpoints receive nothing further.
	if err := ai.SetPlatformTenantSwitches(ctx, bypass, uuid.Nil, false, false); err != nil {
		t.Fatal(err)
	}
	for _, id := range []uuid.UUID{a, b} {
		res, err := resolver.ForTenant(ctx, id)
		if err != nil || res.Source != ai.SourcePlatform {
			t.Fatalf("with tenant providers off: source=%s err=%v, want platform", res.Source, err)
		}
		if _, err := routed.Complete(ai.WithTenantScope(ctx, id), req); err != nil {
			t.Fatal(err)
		}
	}
	if got := itRequests("https://it-a.example") + itRequests("https://it-b.example"); got != 2 {
		t.Errorf("tenant endpoints received %d prompt(s) in total, want 2 — one went out after the operator switched tenant providers off", got)
	}
	if got := itRequests("https://it-platform.example"); got != 4 {
		t.Errorf("platform endpoint received %d prompt(s), want 4", got)
	}
}
