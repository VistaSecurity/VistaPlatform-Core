package ai

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// Which provider answers for whom.
//
// # The order
//
//	a tenant's call:    the tenant's own  →  the platform default  →  the environment  →  none
//	a platform's call:                       the platform default  →  the environment  →  none
//
// A tenant's own provider is used only for that tenant's calls, and only while
// the tenant is permitted to have one. A platform-scope call — a platform
// administrator drafting into the shared catalogue, the nightly catalogue gap
// pass — never resolves a tenant's provider, whichever tenants have one: that
// would send data that belongs to nobody in particular to an endpoint one
// tenant chose, on that tenant's key.
//
// # A configured provider that cannot be built does NOT fall through
//
// If a tenant connected a provider and it cannot be constructed — the stored
// key will not decrypt, the endpoint is now refused — the answer is no
// provider, with the reason. Falling through to the platform default would
// send that tenant's prompts to an endpoint they did not choose, silently, at
// the exact moment they believed their own was in use. The same holds one
// level down: a broken platform default does not quietly become the
// environment's.
//
// What DOES fall through is permission. A tenant whose plan or platform no
// longer lets it bring its own provider is served by the default, and its
// settings page says which provider is answering.

// Source says where the provider in effect came from.
type Source string

// The sources, in the order they are consulted.
const (
	SourceTenant      Source = "tenant"
	SourcePlatform    Source = "platform"
	SourceEnvironment Source = "environment"
	SourceNone        Source = "none"
)

// Resolution is the provider in effect for one scope, and why.
type Resolution struct {
	// Provider is never nil. It is [NoneProvider] when nothing is configured
	// or what is configured could not be built.
	Provider Provider

	// Config is the configuration Provider was built from. It carries no
	// credential.
	Config ProviderConfig

	// Source is where it came from. [SourceNone] when nothing is configured
	// anywhere; otherwise the level that was CHOSEN, even when Err says it
	// could not be built.
	Source Source

	// Err is why the chosen source yielded no usable provider, or nil.
	Err error

	// TenantStored is the provider the tenant has stored, in effect or not.
	// Nil when it has none, and always nil for a platform resolution.
	TenantStored *StoredProvider

	// Permission is what the tenant is permitted. PlanAllows is filled in only
	// when it was needed (see [Resolver.ForTenant]) or asked for
	// ([Resolver.DescribeTenant]). Zero for a platform resolution.
	Permission TenantPermission
}

// TenantGate answers whether a tenant's plan lets it connect its own provider.
// It is a function rather than an import so this package does not depend on
// the entitlements resolver; services pass one built from it.
type TenantGate func(ctx context.Context, tenantID uuid.UUID) (bool, error)

// Resolver resolves the provider for a scope. Build one per process with
// [NewResolver] and share it.
type Resolver struct {
	store  ProviderStore
	cipher *KeyCipher
	gate   TenantGate

	env         ProviderConfig
	envProvider Provider
	envErr      error

	mu    sync.Mutex
	built map[string]builtProvider
}

// ProviderStore is where stored configurations are read from. Production reads
// the database; the indirection exists so the resolution ORDER — which is the
// part that can be wrong in a way that sends a prompt to the wrong place — can
// be tested without one.
type ProviderStore interface {
	Platform(ctx context.Context) (PlatformAISettings, error)
	Tenant(ctx context.Context, tenantID uuid.UUID) (*StoredProvider, error)
}

type dbProviderStore struct{ db *sql.DB }

func (s dbProviderStore) Platform(ctx context.Context) (PlatformAISettings, error) {
	return ReadPlatformAISettings(ctx, s.db)
}

func (s dbProviderStore) Tenant(ctx context.Context, tenantID uuid.UUID) (*StoredProvider, error) {
	return TenantProvider(ctx, s.db, tenantID)
}

type builtProvider struct {
	provider Provider
	config   ProviderConfig
	err      error
}

// maxBuiltProviders bounds the construction cache. It is keyed by
// configuration, so it grows with distinct tenant configurations rather than
// with requests; past the bound it is simply emptied.
const maxBuiltProviders = 512

// NewResolver reads the environment's provider once — it cannot change under a
// running process, and [NewFromEnv] logs a warning for a misconfiguration that
// should be said once rather than per request — and returns a resolver over
// db.
//
// A nil gate denies every tenant its own provider, and says so here rather than
// never: a service that forgot to pass one would otherwise ignore every
// tenant's configuration with no signal anywhere.
func NewResolver(db *sql.DB, cipher *KeyCipher, gate TenantGate) *Resolver {
	if cipher == nil {
		cipher = &KeyCipher{}
	}
	if gate == nil {
		logrus.Warn("ai: resolver built without a tenant gate; tenants' own providers will NOT be used")
	}
	r := &Resolver{cipher: cipher, gate: gate, built: map[string]builtProvider{}}
	if db != nil {
		r.store = dbProviderStore{db: db}
	}
	r.env = ProviderConfigFromEnv()
	r.envProvider, r.envErr = NewFromEnv()
	return r
}

// NewResolverOver is [NewResolver] over an explicit store, for a test that
// drives a handler or a seam through the real resolver without a database.
func NewResolverOver(store ProviderStore, cipher *KeyCipher, gate TenantGate) *Resolver {
	r := NewResolver(nil, cipher, gate)
	r.store = store
	return r
}

// Environment returns the provider the environment names and the error from
// constructing it, exactly as [NewFromEnv] reported them at startup.
func (r *Resolver) Environment() (Provider, ProviderConfig, error) {
	return r.envProvider, r.env, r.envErr
}

// ForTenant resolves the provider for one tenant's calls.
//
// An error return means the answer could not be determined — a settings read
// failed — and the Resolution then carries [NoneProvider]. That is the
// fail-closed direction: a read that did not complete is not evidence about
// where this tenant's prompts may go.
//
// It asks the plan gate only when the answer depends on it — when the tenant
// has a provider stored — so a tenant with none costs a generative call two
// small reads and no entitlement lookup.
func (r *Resolver) ForTenant(ctx context.Context, tenantID uuid.UUID) (Resolution, error) {
	return r.forTenant(ctx, tenantID, false)
}

// DescribeTenant is [Resolver.ForTenant] for a settings page: the same
// resolution, with [Resolution.Permission] always filled in, because the page
// has to say whether the tenant MAY connect a provider even when it has not.
func (r *Resolver) DescribeTenant(ctx context.Context, tenantID uuid.UUID) (Resolution, error) {
	return r.forTenant(ctx, tenantID, true)
}

func (r *Resolver) forTenant(ctx context.Context, tenantID uuid.UUID, describe bool) (Resolution, error) {
	none := Resolution{Provider: NoneProvider{}, Source: SourceNone}
	if tenantID == uuid.Nil {
		return none, ErrNoTenantScope
	}
	if r.store == nil {
		// No database: nothing stored can be read, and the environment is all
		// there is. A service wired without a pool is a dev shape, not an
		// outage.
		return r.fromEnvironment(), nil
	}

	platform, err := r.store.Platform(ctx)
	if err != nil {
		return none, err
	}
	stored, err := r.store.Tenant(ctx, tenantID)
	if err != nil {
		return none, err
	}

	perm := TenantPermission{
		PlatformAllows:   platform.TenantProvidersAllowed,
		PrivateEndpoints: platform.TenantPrivateEndpointsAllowed,
	}
	if r.gate != nil && (describe || (stored != nil && perm.PlatformAllows)) {
		perm.PlanAllows, err = r.gate(ctx, tenantID)
		if err != nil {
			// With a provider stored, neither answer is safe to guess: using it
			// might breach the plan, and using the default might send prompts
			// where the tenant did not intend. Without one, only a settings
			// page asked, and it must not report a guess either.
			none.TenantStored = stored
			return none, fmt.Errorf("ai: whether tenant %s may use its own provider could not be determined: %w", tenantID, err)
		}
	}

	var res Resolution
	if stored != nil && perm.Allowed() {
		res = r.build(*stored, perm.PrivateEndpoints, SourceTenant)
	} else {
		res = r.forPlatform(platform)
	}
	res.TenantStored = stored
	res.Permission = perm
	return res, nil
}

// TenantPermission is what a tenant is permitted regarding a provider of its
// own, split by who decided — because the sentence a settings page shows is
// different for "your plan does not include this" and "whoever runs this
// deployment has switched it off".
type TenantPermission struct {
	// PlatformAllows is the platform administrator's switch.
	PlatformAllows bool
	// PlanAllows is the tenant's entitlement.
	PlanAllows bool
	// PrivateEndpoints is whether a tenant's endpoint may be on a private
	// address.
	PrivateEndpoints bool
}

// Allowed reports whether the tenant may connect and use its own provider.
func (p TenantPermission) Allowed() bool { return p.PlatformAllows && p.PlanAllows }

// Cipher returns the credential cipher this resolver opens stored keys with,
// so the handler that seals a key uses the same one.
func (r *Resolver) Cipher() *KeyCipher { return r.cipher }

// ForPlatform resolves the provider for a call made on no tenant's behalf.
func (r *Resolver) ForPlatform(ctx context.Context) (Resolution, error) {
	if r.store == nil {
		return r.fromEnvironment(), nil
	}
	platform, err := r.store.Platform(ctx)
	if err != nil {
		return Resolution{Provider: NoneProvider{}, Source: SourceNone}, err
	}
	return r.forPlatform(platform), nil
}

func (r *Resolver) forPlatform(platform PlatformAISettings) Resolution {
	if platform.Provider != nil {
		return r.build(*platform.Provider, platform.Provider.AllowPrivateEndpoints, SourcePlatform)
	}
	return r.fromEnvironment()
}

func (r *Resolver) fromEnvironment() Resolution {
	if r.env.Kind == "" || r.env.Kind == ProviderNone {
		return Resolution{Provider: NoneProvider{}, Config: r.env, Source: SourceNone}
	}
	return Resolution{Provider: r.envProvider, Config: r.env, Source: SourceEnvironment, Err: r.envErr}
}

// build constructs (or reuses) the provider for a stored configuration.
func (r *Resolver) build(sp StoredProvider, allowPrivate bool, source Source) Resolution {
	key := fingerprint(sp, allowPrivate)

	r.mu.Lock()
	cached, ok := r.built[key]
	r.mu.Unlock()
	if !ok {
		cached = r.construct(sp, allowPrivate)
		r.mu.Lock()
		if len(r.built) >= maxBuiltProviders {
			r.built = map[string]builtProvider{}
		}
		r.built[key] = cached
		r.mu.Unlock()
	}
	return Resolution{Provider: cached.provider, Config: cached.config, Source: source, Err: cached.err}
}

func (r *Resolver) construct(sp StoredProvider, allowPrivate bool) builtProvider {
	cfg := configFor(sp, allowPrivate)

	// Open the credential once, now, so a key that will not decrypt is reported
	// as that rather than surfacing later as a provider rejecting an empty
	// token. The plaintext is not kept: the key source opens it again at the
	// moment of use.
	if _, err := r.cipher.Open(sp.APIKeyEnc); err != nil {
		return builtProvider{provider: NoneProvider{}, config: cfg, err: err}
	}
	cipher, stored := r.cipher, sp.APIKeyEnc
	cfg = cfg.WithKeySource(func() string {
		plain, err := cipher.Open(stored)
		if err != nil {
			return ""
		}
		return plain
	})

	p, err := New(cfg)
	return builtProvider{provider: p, config: cfg, err: err}
}

// BuildUnsaved constructs a provider from a configuration that has not been
// stored, with its credential in hand. It is what "Test connection" and
// save-time validation use, and it is never cached: the point is to try
// exactly what the form holds.
func BuildUnsaved(sp StoredProvider, plainKey string, allowPrivate bool) (Provider, error) {
	cfg := configFor(sp, allowPrivate).WithKeySource(func() string { return plainKey })
	return New(cfg)
}

func configFor(sp StoredProvider, allowPrivate bool) ProviderConfig {
	return ProviderConfig{
		Kind:                  sp.Kind,
		BaseURL:               sp.BaseURL,
		Model:                 sp.Model,
		AllowPrivateEndpoints: allowPrivate,
	}.WithDefaults()
}

func fingerprint(sp StoredProvider, allowPrivate bool) string {
	blob, _ := json.Marshal(struct {
		SP           StoredProvider
		AllowPrivate bool
	}{sp, allowPrivate})
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:])
}

// ── Scope on the context ───────────────────────────────────────────────────

type tenantScopeKey struct{}

// WithTenantScope records which tenant a generative call is being made for, so
// the routed provider can resolve that tenant's provider. Stamp it where the
// tenant's controls are stamped ([WithTenantControls]).
//
// An unstamped context is a platform-scope call and resolves the platform's
// provider. That is the safe direction for a call site that forgot: it can
// never reach a tenant's provider, its own or anyone else's.
func WithTenantScope(ctx context.Context, tenantID uuid.UUID) context.Context {
	if tenantID == uuid.Nil {
		return ctx
	}
	return context.WithValue(ctx, tenantScopeKey{}, tenantID)
}

// TenantScopeFrom returns the tenant stamped on ctx.
func TenantScopeFrom(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(tenantScopeKey{}).(uuid.UUID)
	return id, ok && id != uuid.Nil
}

// ── The routed provider ────────────────────────────────────────────────────

// Routed returns a [Provider] that resolves, per call, the provider for the
// scope stamped on the context, and sends the request through [Boundary]
// around it.
//
// It replaces `ai.Boundary(provider, sink)` at a seam's wiring: the seam holds
// one Provider for the life of the process, as before, and which model that
// reaches is decided when a request arrives. Redaction and audit wrap the
// RESOLVED provider, so the audit record names the provider that actually
// received the prompt.
func (r *Resolver) Routed(sink AuditSink) Provider {
	return routedProvider{resolver: r, sink: sink}
}

// RoutedName is what the routed provider calls itself in a startup log line.
// An audit record never carries it — those name the resolved provider.
const RoutedName = "routed"

type routedProvider struct {
	resolver *Resolver
	sink     AuditSink
}

func (p routedProvider) Name() string { return RoutedName }

// Available reports whether this BUILD can reach a model for anyone: whether
// any provider kind is registered. It is asked once, at wiring, to decide
// whether a generative implementation is selected at all, and it cannot depend
// on configuration any more — a tenant may connect a provider a minute after
// the process started. Whether one answers for a particular request is
// [AvailableFor].
func (p routedProvider) Available() bool { return len(RegisteredProviders()) > 0 }

// AvailableFor reports whether a provider will answer for the scope on ctx.
func (p routedProvider) AvailableFor(ctx context.Context) bool {
	return p.resolve(ctx).Provider.Available()
}

// ResolutionFor exposes the resolution for the scope on ctx, for a caller that
// needs the model id or the source as well as the yes/no.
func (p routedProvider) ResolutionFor(ctx context.Context) Resolution {
	return p.resolve(ctx)
}

func (p routedProvider) Complete(ctx context.Context, req Request) (Response, error) {
	res := p.resolve(ctx)
	if !res.Provider.Available() {
		// Nothing answers for this scope. Returned here rather than sent
		// through the boundary, because nothing was going to cross it: before
		// providers were resolved per request a deployment in this state
		// selected the null seam and made no call at all, and an audit trail
		// that gained a "failed AI call" for every comparison a provider-less
		// tenant opens would be recording calls nobody made.
		return Response{}, ErrUnavailable
	}
	return Boundary(res.Provider, p.sink).Complete(ctx, req)
}

func (p routedProvider) resolve(ctx context.Context) Resolution {
	var (
		res Resolution
		err error
	)
	if tenantID, ok := TenantScopeFrom(ctx); ok {
		res, err = p.resolver.ForTenant(ctx, tenantID)
	} else {
		res, err = p.resolver.ForPlatform(ctx)
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		logrus.WithError(err).Warn("ai: provider could not be resolved; answering without a model")
	}
	if res.Provider == nil {
		res.Provider = NoneProvider{}
	}
	return res
}

// AvailableFor reports whether p will answer for the scope on ctx. For a
// routed provider that is the per-scope answer; for any other it is
// p.Available().
func AvailableFor(ctx context.Context, p Provider) bool {
	if p == nil {
		return false
	}
	if scoped, ok := p.(interface{ AvailableFor(context.Context) bool }); ok {
		return scoped.AvailableFor(ctx)
	}
	return p.Available()
}

// ResolutionFor returns the resolution behind p for the scope on ctx, when p
// is a routed provider.
func ResolutionFor(ctx context.Context, p Provider) (Resolution, bool) {
	if scoped, ok := p.(interface {
		ResolutionFor(context.Context) Resolution
	}); ok {
		return scoped.ResolutionFor(ctx), true
	}
	return Resolution{}, false
}

// SeamProvider is what a seam's wiring holds: the routed provider when the
// service has a resolver, and otherwise the environment's provider behind
// [Boundary], which is what every seam was built on before providers could be
// stored. A nil resolver is a service with no database handle — a dev shape and
// a unit test — not something to fail on.
func SeamProvider(r *Resolver, sink AuditSink) Provider {
	if r != nil {
		return r.Routed(sink)
	}
	provider, err := NewFromEnv()
	if err != nil {
		logrus.WithError(err).Warn("ai: provider not configured; generative capabilities are unavailable")
	}
	return Boundary(provider, sink)
}
