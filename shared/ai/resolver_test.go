package ai

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// fakeStore is the resolver's view of the database.
type fakeStore struct {
	platform    PlatformAISettings
	platformErr error
	tenants     map[uuid.UUID]*StoredProvider
	tenantErr   error

	mu          sync.Mutex
	tenantReads int
}

func (f *fakeStore) Platform(context.Context) (PlatformAISettings, error) {
	return f.platform, f.platformErr
}

func (f *fakeStore) Tenant(_ context.Context, id uuid.UUID) (*StoredProvider, error) {
	f.mu.Lock()
	f.tenantReads++
	f.mu.Unlock()
	if f.tenantErr != nil {
		return nil, f.tenantErr
	}
	return f.tenants[id], nil
}

// recordingFactory registers a provider kind whose instances are mocks named
// after the base URL they were built for, and remembers every config it saw —
// so a test can assert WHICH configuration answered and what the factory was
// told about private endpoints and the credential.
type recordingFactory struct {
	mu      sync.Mutex
	configs []ProviderConfig
	keys    []string
	mocks   map[string]*MockProvider
}

func (f *recordingFactory) build(cfg ProviderConfig) (Provider, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.configs = append(f.configs, cfg)
	f.keys = append(f.keys, cfg.APIKey())
	if f.mocks == nil {
		f.mocks = map[string]*MockProvider{}
	}
	m := &MockProvider{ProviderName: cfg.BaseURL}
	f.mocks[cfg.BaseURL] = m
	return m, nil
}

func (f *recordingFactory) mock(baseURL string) *MockProvider {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mocks[baseURL]
}

const testKind = "openai_compat"

// newTestResolver builds a resolver over a fake store with testKind registered
// to a recording factory. envBase, when set, makes the environment name a
// provider at that base URL.
func newTestResolver(t *testing.T, store *fakeStore, gate TenantGate, envBase string) (*Resolver, *recordingFactory, *KeyCipher) {
	t.Helper()
	withEmptyRegistry(t)
	factory := &recordingFactory{}
	if err := RegisterProvider(testKind, factory.build); err != nil {
		t.Fatalf("register: %v", err)
	}
	for _, name := range []string{"AI_PROVIDER", "AI_BASE_URL", "AI_MODEL", "AI_API_KEY_ENV", "AI_ALLOW_PRIVATE_ENDPOINTS"} {
		t.Setenv(name, "")
	}
	if envBase != "" {
		t.Setenv("AI_PROVIDER", testKind)
		t.Setenv("AI_BASE_URL", envBase)
	}
	cipher := NewKeyCipher("test-master-key")
	return NewResolverOver(store, cipher, gate), factory, cipher
}

func allowAll(context.Context, uuid.UUID) (bool, error)  { return true, nil }
func allowNone(context.Context, uuid.UUID) (bool, error) { return false, nil }

func stored(t *testing.T, cipher *KeyCipher, baseURL, key string) *StoredProvider {
	t.Helper()
	enc, hint, err := cipher.Seal(key)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return &StoredProvider{Kind: testKind, BaseURL: baseURL, Model: "m", APIKeyEnc: enc, APIKeyHint: hint}
}

func TestResolver_OrderIsTenantThenPlatformThenEnvironmentThenNone(t *testing.T) {
	tenant := uuid.New()
	ctx := context.Background()

	t.Run("tenant's own wins", func(t *testing.T) {
		store := &fakeStore{platform: PlatformAISettings{TenantProvidersAllowed: true}}
		r, _, cipher := newTestResolver(t, store, allowAll, "https://env.example")
		store.platform.Provider = stored(t, cipher, "https://platform.example", "pk-platform-000000")
		store.tenants = map[uuid.UUID]*StoredProvider{tenant: stored(t, cipher, "https://tenant.example", "tk-tenant-0000000")}

		res, err := r.ForTenant(ctx, tenant)
		if err != nil || res.Err != nil {
			t.Fatalf("err=%v res.Err=%v", err, res.Err)
		}
		if res.Source != SourceTenant || res.Provider.Name() != "https://tenant.example" {
			t.Fatalf("source=%s provider=%s, want the tenant's", res.Source, res.Provider.Name())
		}
		if res.TenantStored == nil || !res.Permission.Allowed() {
			t.Fatalf("TenantStored=%v allowed=%t, want stored and allowed", res.TenantStored, res.Permission.Allowed())
		}
	})

	t.Run("no tenant provider: the platform default, over the environment", func(t *testing.T) {
		store := &fakeStore{platform: PlatformAISettings{TenantProvidersAllowed: true}}
		r, _, cipher := newTestResolver(t, store, allowAll, "https://env.example")
		store.platform.Provider = stored(t, cipher, "https://platform.example", "pk-platform-000000")

		res, err := r.ForTenant(ctx, tenant)
		if err != nil || res.Source != SourcePlatform || res.Provider.Name() != "https://platform.example" {
			t.Fatalf("err=%v source=%s provider=%s, want the platform default", err, res.Source, res.Provider.Name())
		}
		if res.TenantStored != nil {
			t.Fatal("TenantStored must be nil for a tenant with nothing stored")
		}
	})

	t.Run("neither: the environment", func(t *testing.T) {
		store := &fakeStore{platform: PlatformAISettings{TenantProvidersAllowed: true}}
		r, _, _ := newTestResolver(t, store, allowAll, "https://env.example")

		res, err := r.ForTenant(ctx, tenant)
		if err != nil || res.Source != SourceEnvironment || res.Provider.Name() != "https://env.example" {
			t.Fatalf("err=%v source=%s provider=%s, want the environment's", err, res.Source, res.Provider.Name())
		}
	})

	t.Run("nothing anywhere: none", func(t *testing.T) {
		store := &fakeStore{platform: PlatformAISettings{TenantProvidersAllowed: true}}
		r, _, _ := newTestResolver(t, store, allowAll, "")

		res, err := r.ForTenant(ctx, tenant)
		if err != nil || res.Source != SourceNone || res.Provider.Available() {
			t.Fatalf("err=%v source=%s available=%t, want none", err, res.Source, res.Provider.Available())
		}
	})
}

// A tenant that may no longer bring its own provider is served by the default.
// Both ways of saying no are covered: the platform switch and the plan gate.
func TestResolver_ATenantNotPermittedItsOwnProviderGetsTheDefault(t *testing.T) {
	tenant := uuid.New()
	cases := []struct {
		name            string
		platformAllowed bool
		gate            TenantGate
	}{
		{"platform switch off", false, allowAll},
		{"plan does not include it", true, allowNone},
		{"no gate wired", true, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeStore{platform: PlatformAISettings{TenantProvidersAllowed: tc.platformAllowed}}
			r, _, cipher := newTestResolver(t, store, tc.gate, "")
			store.platform.Provider = stored(t, cipher, "https://platform.example", "pk-platform-000000")
			store.tenants = map[uuid.UUID]*StoredProvider{tenant: stored(t, cipher, "https://tenant.example", "tk-tenant-0000000")}

			res, err := r.ForTenant(context.Background(), tenant)
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if res.Source != SourcePlatform || res.Provider.Name() != "https://platform.example" {
				t.Fatalf("source=%s provider=%s, want the platform default", res.Source, res.Provider.Name())
			}
			if res.TenantStored == nil || res.Permission.Allowed() {
				t.Fatalf("TenantStored=%v allowed=%t, want stored and not allowed", res.TenantStored, res.Permission.Allowed())
			}
		})
	}
}

// The property the feature turns on: a configured provider that cannot be
// built must NOT quietly become the next one down. A tenant that connected its
// own endpoint and whose key will not decrypt gets no model — not the
// platform's, which it did not choose.
func TestResolver_ABrokenTenantProviderDoesNotFallThroughToTheDefault(t *testing.T) {
	tenant := uuid.New()
	store := &fakeStore{platform: PlatformAISettings{TenantProvidersAllowed: true}}
	r, _, cipher := newTestResolver(t, store, allowAll, "https://env.example")
	store.platform.Provider = stored(t, cipher, "https://platform.example", "pk-platform-000000")

	// Sealed under a DIFFERENT master key: the row is well-formed and will not
	// open here, which is what a rotated ENCRYPTION_MASTER_KEY looks like.
	foreign := stored(t, NewKeyCipher("some-other-master-key"), "https://tenant.example", "tk-tenant-0000000")
	store.tenants = map[uuid.UUID]*StoredProvider{tenant: foreign}

	res, err := r.ForTenant(context.Background(), tenant)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if res.Source != SourceTenant {
		t.Fatalf("source = %s, want tenant — the level that was chosen, even though it failed", res.Source)
	}
	if res.Err == nil {
		t.Fatal("res.Err is nil; a key that will not decrypt must be reported")
	}
	if res.Provider.Available() {
		t.Fatalf("provider %q is available; a broken tenant provider must resolve to none, not to the default", res.Provider.Name())
	}
}

// When the plan gate cannot be read and the tenant HAS a provider, neither
// answer is safe to guess, so there is no provider and the error is returned.
func TestResolver_AnUnreadableGateWithATenantProviderFailsClosed(t *testing.T) {
	tenant := uuid.New()
	gateErr := errors.New("entitlements unavailable")
	store := &fakeStore{platform: PlatformAISettings{TenantProvidersAllowed: true}}
	r, _, cipher := newTestResolver(t, store, func(context.Context, uuid.UUID) (bool, error) { return false, gateErr }, "")
	store.platform.Provider = stored(t, cipher, "https://platform.example", "pk-platform-000000")
	store.tenants = map[uuid.UUID]*StoredProvider{tenant: stored(t, cipher, "https://tenant.example", "tk-tenant-0000000")}

	res, err := r.ForTenant(context.Background(), tenant)
	if !errors.Is(err, gateErr) {
		t.Fatalf("err = %v, want the gate's error", err)
	}
	if res.Provider.Available() {
		t.Fatalf("provider %q answered; an undetermined gate must yield none", res.Provider.Name())
	}
}

func TestResolver_SettingsReadFailuresFailClosed(t *testing.T) {
	tenant := uuid.New()
	boom := errors.New("connection reset")

	for name, store := range map[string]*fakeStore{
		"platform read": {platformErr: boom},
		"tenant read":   {platform: PlatformAISettings{TenantProvidersAllowed: true}, tenantErr: boom},
	} {
		t.Run(name, func(t *testing.T) {
			r, _, _ := newTestResolver(t, store, allowAll, "https://env.example")
			res, err := r.ForTenant(context.Background(), tenant)
			if !errors.Is(err, boom) {
				t.Fatalf("err = %v, want the read error", err)
			}
			if res.Provider.Available() {
				t.Fatal("a failed settings read must not resolve to a usable provider — not even the environment's")
			}
		})
	}
}

// A platform-scope call must never reach a tenant's provider. The assertion is
// structural: the tenant store is not even read.
func TestResolver_APlatformCallNeverReadsATenantsProvider(t *testing.T) {
	tenant := uuid.New()
	store := &fakeStore{platform: PlatformAISettings{TenantProvidersAllowed: true}}
	r, _, cipher := newTestResolver(t, store, allowAll, "https://env.example")
	store.tenants = map[uuid.UUID]*StoredProvider{tenant: stored(t, cipher, "https://tenant.example", "tk-tenant-0000000")}

	res, err := r.ForPlatform(context.Background())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if res.Source != SourceEnvironment || res.Provider.Name() != "https://env.example" {
		t.Fatalf("source=%s provider=%s, want the environment's", res.Source, res.Provider.Name())
	}
	if store.tenantReads != 0 {
		t.Fatalf("the tenant store was read %d times on a platform-scope resolution", store.tenantReads)
	}
}

// What a tenant's row says about private endpoints is never read. Only the
// operator's switch decides, in both directions.
func TestResolver_OnlyTheOperatorSwitchGrantsATenantAPrivateEndpoint(t *testing.T) {
	tenant := uuid.New()
	for _, operatorAllows := range []bool{false, true} {
		store := &fakeStore{platform: PlatformAISettings{TenantProvidersAllowed: true, TenantPrivateEndpointsAllowed: operatorAllows}}
		r, factory, cipher := newTestResolver(t, store, allowAll, "")
		sp := stored(t, cipher, "http://10.0.0.5:11434/v1", "")
		sp.AllowPrivateEndpoints = true // the tenant's row claims it; must be ignored
		store.tenants = map[uuid.UUID]*StoredProvider{tenant: sp}

		if _, err := r.ForTenant(context.Background(), tenant); err != nil {
			t.Fatalf("err = %v", err)
		}
		if len(factory.configs) != 1 {
			t.Fatalf("factory saw %d configs, want 1", len(factory.configs))
		}
		if got := factory.configs[0].AllowPrivateEndpoints; got != operatorAllows {
			t.Fatalf("operator switch %t: factory was told AllowPrivateEndpoints=%t", operatorAllows, got)
		}
	}
}

// A stored configuration must never pick up the deployment's credential from
// the environment: that would deliver the operator's key to an endpoint a
// tenant typed.
func TestStoredConfig_NeverReadsTheEnvironmentsCredential(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-operator-secret")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-operator-secret")

	tenant := uuid.New()
	store := &fakeStore{platform: PlatformAISettings{TenantProvidersAllowed: true}}
	r, factory, cipher := newTestResolver(t, store, allowAll, "")
	store.tenants = map[uuid.UUID]*StoredProvider{tenant: stored(t, cipher, "https://tenant.example", "")} // no key stored

	if _, err := r.ForTenant(context.Background(), tenant); err != nil {
		t.Fatalf("err = %v", err)
	}
	if got := factory.keys[0]; got != "" {
		t.Fatalf("a keyless stored provider resolved the credential %q from the environment", got)
	}

	// And the stored key, when there is one, is what the factory sees.
	store.tenants[tenant] = stored(t, cipher, "https://tenant2.example", "tk-tenant-own-key-1234")
	if _, err := r.ForTenant(context.Background(), tenant); err != nil {
		t.Fatalf("err = %v", err)
	}
	if got := factory.keys[1]; got != "tk-tenant-own-key-1234" {
		t.Fatalf("stored key resolved as %q", got)
	}
}

// The config a stored provider is built from still cannot carry a credential
// through a marshal or a log line.
func TestStoredConfig_TheCredentialIsInNeitherTheJSONNorTheString(t *testing.T) {
	cfg := ProviderConfig{Kind: testKind, BaseURL: "https://x.example"}.WithDefaults().
		WithKeySource(func() string { return "sk-very-secret-value" })
	if cfg.APIKey() != "sk-very-secret-value" {
		t.Fatal("key source not consulted")
	}
	blob, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"json": string(blob), "String()": cfg.String()} {
		if strings.Contains(text, "sk-very-secret-value") {
			t.Fatalf("%s carries the credential: %s", name, text)
		}
	}
}

// ── The routed provider ────────────────────────────────────────────────────

func routedRequest() Request {
	return Request{Seam: SeamQuery, Invoker: "user-1", Messages: []Message{{Role: "user", Content: "hello"}}}
}

// Two tenants, two providers, and a platform default. Each tenant's prompt
// reaches its own endpoint and nobody else's; a call with no tenant on the
// context reaches the platform's. This is the cross-tenant property, asserted
// on what each mock actually received.
func TestRouted_EachScopeReachesOnlyItsOwnProvider(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	store := &fakeStore{platform: PlatformAISettings{TenantProvidersAllowed: true}}
	r, factory, cipher := newTestResolver(t, store, allowAll, "")
	store.platform.Provider = stored(t, cipher, "https://platform.example", "pk-platform-000000")
	store.tenants = map[uuid.UUID]*StoredProvider{
		a: stored(t, cipher, "https://a.example", "tk-a-000000000000"),
		b: stored(t, cipher, "https://b.example", "tk-b-000000000000"),
	}

	var records []AuditRecord
	var mu sync.Mutex
	routed := r.Routed(SinkFunc(func(_ context.Context, rec AuditRecord) {
		mu.Lock()
		records = append(records, rec)
		mu.Unlock()
	}))

	ctx := context.Background()
	for _, scope := range []context.Context{WithTenantScope(ctx, a), WithTenantScope(ctx, b), WithTenantScope(ctx, a), ctx} {
		if _, err := routed.Complete(scope, routedRequest()); err != nil {
			t.Fatalf("complete: %v", err)
		}
	}

	want := map[string]int{"https://a.example": 2, "https://b.example": 1, "https://platform.example": 1}
	for base, n := range want {
		m := factory.mock(base)
		if m == nil {
			t.Fatalf("no provider was built for %s", base)
		}
		if got := len(m.Requests()); got != n {
			t.Fatalf("%s received %d requests, want %d", base, got, n)
		}
	}

	// The audit trail names the provider that actually received each prompt,
	// not the router.
	var names []string
	for _, rec := range records {
		names = append(names, rec.Provider)
	}
	if got := strings.Join(names, ","); got != "https://a.example,https://b.example,https://a.example,https://platform.example" {
		t.Fatalf("audit providers = %s", got)
	}
}

// The tenant kill switch still beats every provider, the tenant's own included.
func TestRouted_TheTenantKillSwitchWinsOverTheTenantsOwnProvider(t *testing.T) {
	tenant := uuid.New()
	store := &fakeStore{platform: PlatformAISettings{TenantProvidersAllowed: true}}
	r, factory, cipher := newTestResolver(t, store, allowAll, "")
	store.tenants = map[uuid.UUID]*StoredProvider{tenant: stored(t, cipher, "https://tenant.example", "tk-tenant-0000000")}

	routed := r.Routed(SinkFunc(func(context.Context, AuditRecord) {}))
	ctx := WithTenantScope(context.Background(), tenant)
	ctx = WithTenantControls(ctx, TenantControls{AssistantDisabled: true})

	_, err := routed.Complete(ctx, routedRequest())
	if !errors.Is(err, ErrTenantDisabled) {
		t.Fatalf("err = %v, want ErrTenantDisabled", err)
	}
	if m := factory.mock("https://tenant.example"); m != nil && len(m.Requests()) != 0 {
		t.Fatal("a prompt reached the tenant's provider with the assistant turned off")
	}
}

func TestRouted_AvailabilityIsPerScope(t *testing.T) {
	with, without := uuid.New(), uuid.New()
	store := &fakeStore{platform: PlatformAISettings{TenantProvidersAllowed: true}}
	r, _, cipher := newTestResolver(t, store, allowAll, "")
	store.tenants = map[uuid.UUID]*StoredProvider{with: stored(t, cipher, "https://tenant.example", "tk-tenant-0000000")}

	routed := r.Routed(nil)
	ctx := context.Background()

	if !routed.Available() {
		t.Fatal("Available() is false though this build has a provider kind registered")
	}
	if !AvailableFor(WithTenantScope(ctx, with), routed) {
		t.Fatal("the tenant with a provider is reported unavailable")
	}
	if AvailableFor(WithTenantScope(ctx, without), routed) {
		t.Fatal("the tenant with no provider is reported available")
	}
	if AvailableFor(ctx, routed) {
		t.Fatal("platform scope is reported available with nothing configured for it")
	}

	// And a build with no provider kinds at all is never available.
	withEmptyRegistry(t)
	if routed.Available() {
		t.Fatal("Available() is true in a build that registered no provider kind")
	}
}

// A scope with no provider gets ErrUnavailable and leaves no audit record:
// nothing was sent, so there is no call to record.
func TestRouted_NoProviderIsUnavailableAndUnrecorded(t *testing.T) {
	store := &fakeStore{platform: PlatformAISettings{TenantProvidersAllowed: true}}
	r, _, _ := newTestResolver(t, store, allowAll, "")

	records := 0
	routed := r.Routed(SinkFunc(func(context.Context, AuditRecord) { records++ }))
	_, err := routed.Complete(WithTenantScope(context.Background(), uuid.New()), routedRequest())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if records != 0 {
		t.Fatalf("%d audit record(s) written for a call that was never made", records)
	}
}

// ── The credential cipher ──────────────────────────────────────────────────

func TestKeyCipher_SealsOpensAndRefuses(t *testing.T) {
	c := NewKeyCipher("master")
	enc, hint, err := c.Seal("sk-ant-abcdefghijkl")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, keyEncPrefix) || strings.Contains(enc, "abcdefgh") {
		t.Fatalf("stored form %q is not prefixed ciphertext", enc)
	}
	if hint != "ijkl" {
		t.Fatalf("hint = %q", hint)
	}
	plain, err := c.Open(enc)
	if err != nil || plain != "sk-ant-abcdefghijkl" {
		t.Fatalf("open = %q, %v", plain, err)
	}

	// A short key gives no hint: four characters would be most of it.
	if _, hint, _ := c.Seal("short"); hint != "" {
		t.Fatalf("hint for a short key = %q, want none", hint)
	}

	// No key is a real answer and needs no master key.
	none := NewKeyCipher("")
	if enc, hint, err := none.Seal(""); enc != "" || hint != "" || err != nil {
		t.Fatalf("sealing nothing = %q %q %v", enc, hint, err)
	}
	// But a real key without a master key is refused, never stored in clear.
	if _, _, err := none.Seal("sk-real"); !errors.Is(err, ErrNoMasterKey) {
		t.Fatalf("seal without a master key: err = %v, want ErrNoMasterKey", err)
	}
	if _, err := none.Open(enc); !errors.Is(err, ErrNoMasterKey) {
		t.Fatalf("open without a master key: err = %v, want ErrNoMasterKey", err)
	}

	// Something not in the encrypted form is refused rather than sent as a key.
	if _, err := c.Open("sk-pasted-into-the-row-by-hand"); err == nil {
		t.Fatal("a plaintext value in the stored slot was opened")
	}
	// A different master key fails loudly.
	if _, err := NewKeyCipher("other").Open(enc); err == nil {
		t.Fatal("ciphertext opened under the wrong master key")
	}
}

func TestStoredProvider_SameEndpointAndHost(t *testing.T) {
	base := StoredProvider{Kind: "openai_compat", BaseURL: "https://llm.example/v1"}
	if !base.SameEndpoint(StoredProvider{Kind: "openai-compatible", BaseURL: "https://llm.example/v1/"}) {
		t.Fatal("a spelling variant and a trailing slash made the endpoint look different")
	}
	if base.SameEndpoint(StoredProvider{Kind: "openai_compat", BaseURL: "https://evil.example/v1"}) {
		t.Fatal("a different host is the same endpoint")
	}
	if base.SameEndpoint(StoredProvider{Kind: "anthropic", BaseURL: "https://llm.example/v1"}) {
		t.Fatal("a different kind is the same endpoint")
	}
	if got := (StoredProvider{BaseURL: "https://llm.example:8443/v1?x=1"}).Host(); got != "llm.example:8443" {
		t.Fatalf("Host() = %q", got)
	}
}

// A generative call for a tenant with nothing stored must not pay for an
// entitlement lookup; a settings page always gets the answer.
func TestResolver_ThePlanGateIsAskedOnlyWhenTheAnswerDependsOnIt(t *testing.T) {
	tenant := uuid.New()
	calls := 0
	gate := func(context.Context, uuid.UUID) (bool, error) { calls++; return true, nil }
	store := &fakeStore{platform: PlatformAISettings{TenantProvidersAllowed: true}}
	r, _, cipher := newTestResolver(t, store, gate, "")

	if _, err := r.ForTenant(context.Background(), tenant); err != nil || calls != 0 {
		t.Fatalf("ForTenant with nothing stored: err=%v gate calls=%d, want 0", err, calls)
	}
	res, err := r.DescribeTenant(context.Background(), tenant)
	if err != nil || calls != 1 || !res.Permission.PlanAllows {
		t.Fatalf("DescribeTenant: err=%v gate calls=%d planAllows=%t", err, calls, res.Permission.PlanAllows)
	}

	store.tenants = map[uuid.UUID]*StoredProvider{tenant: stored(t, cipher, "https://tenant.example", "tk-tenant-0000000")}
	if _, err := r.ForTenant(context.Background(), tenant); err != nil || calls != 2 {
		t.Fatalf("ForTenant with a provider stored: err=%v gate calls=%d, want 2", err, calls)
	}
}
