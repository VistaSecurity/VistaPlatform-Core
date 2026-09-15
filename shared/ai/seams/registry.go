package seams

import (
	"fmt"
	"sort"
	"sync"

	"github.com/vistasecurity/vistaplatform/shared/ai"
)

// ImplNone is the name of the null implementation of every seam. It is a real,
// selectable value rather than a zero value: a Config that says "none" is
// stating a decision, and one that says nothing gets the same behaviour.
const ImplNone = "none"

// Set is one resolved configuration: which implementation answers each seam.
// It is a value, passed to whatever needs a seam, so a service can hold
// different sets (per tenant, say) without any global to fight over.
//
// The zero Set has nil seams and is not usable; build one with [Default] or
// [Configure].
type Set struct {
	Matcher       Matcher
	Classifier    Classifier
	DriftDetector DriftDetector
	Enricher      Enricher
	Narrator      Narrator
	Query         Query
	Author        Author
	Remediator    Remediator

	// names records which implementation was chosen per seam, so Describe can
	// report it. Unexported because it must stay in step with the fields above.
	names map[ai.Seam]string
}

// Default returns the Set a deployment with no AI configured runs, which is
// most of them — so it is the path the tests exercise hardest.
//
// SIX of the eight seams are null in it and propose nothing. Two are not, and
// neither of them is generative — both are the "rule-based default" column of
// ADR-0008 D1's table rather than the null one:
//
//   - the CLASSIFIER defaults to [ImplRulesModel], the rule engine over the
//     curated classification_rules table (ADR-0004 D6) with the learned
//     classifier chained beneath it for the two cases the rules cannot answer;
//   - the MATCHER defaults to [ImplLearned], the logistic scorer of
//     shared/identity/matcher with its weights embedded in the binary.
//
// Both are deterministic given their inputs, run in-process, consult no
// provider and touch no network (ADR-0008 D2 puts the classical family in
// Core), and both PROPOSE — the classifier's model-derived class is never
// written to an asset, and the matcher ranks merge candidates without deciding
// anything, the auto-accept threshold defaulting to zero meaning never. Leaving
// either off by default would withhold a capability that has nothing to do with
// whether AI is configured.
//
// An operator who genuinely wants no proposals from one sets it to [ImplNone]
// explicitly; [ImplRules] is the classifier's rules-without-a-model variant and
// `CLASSIFIER_MODEL_ENABLED=false` turns the model half off in place.
func Default() Set {
	set := Set{names: make(map[ai.Seam]string, len(seamSlots))}
	for _, sl := range seamSlots {
		sl.setDefault(&set)
		set.names[sl.seam] = sl.defaultImpl
	}
	return set
}

// Config names the implementation wanted for each seam. An empty string means
// that seam's DEFAULT — [ImplNone] for seven of them, [ImplRules] for the
// classifier (see [Default]). Saying "none" explicitly is always available and
// always means no proposals.
//
// It is deliberately eight independent strings rather than one switch. The
// seams ship at different times and belong to different editions — the
// classical three are Core, the generative five are Enterprise under the
// current model — and an operator may reasonably want a classifier without a
// narrator.
type Config struct {
	Matcher       string `json:"matcher,omitempty"`
	Classifier    string `json:"classifier,omitempty"`
	DriftDetector string `json:"drift_detector,omitempty"`
	Enricher      string `json:"enricher,omitempty"`
	Narrator      string `json:"narrator,omitempty"`
	Query         string `json:"query,omitempty"`
	Author        string `json:"author,omitempty"`
	Remediator    string `json:"remediator,omitempty"`
}

// ── The seam table ─────────────────────────────────────────────────────────

// seamSlot is one row of the single table every seam operation walks: the
// registry's constructor, [Default], [Registry.Configure] and [Describe].
//
// It exists because those four used to be four hand-maintained parallel lists
// of the same eight seams, alongside eight near-identical Register methods and
// a ninth list for families. Only two of them were checked by the compiler, and
// six of the eight Configure branches had no test — so a ninth seam could be
// added to the interfaces, the null defaults and Register, and silently never
// be resolvable, or resolvable but absent from Describe. One table means a seam
// that is missing a row is missing from everything at once, which is the
// failure you notice.
type seamSlot struct {
	seam   ai.Seam
	family string

	// defaultImpl is what an unset Config field resolves to for this seam.
	// [ImplNone] for seven of the eight; [ImplRules] for the classifier, whose
	// deterministic default is not a null one.
	defaultImpl string

	// implName reads the wanted implementation name out of a Config.
	implName func(Config) string

	// registerBuiltins installs the implementations this package ships for the
	// seam — always [ImplNone], plus the seam's own default when that is
	// something else.
	registerBuiltins func(*Registry)

	// setDefault puts the seam's default implementation in the right field of a
	// Set.
	setDefault func(*Set)

	// prepare resolves name in this seam's namespace and returns a closure that
	// CONSTRUCTS the implementation and stores it. The closure is deliberately
	// separate: Configure calls it after releasing the lock.
	prepare func(*Registry, string) (func(*Set), bool)
}

// slot builds one row for a seam whose default is the null implementation —
// seven of the eight.
func slot[T any](
	seam ai.Seam,
	family string,
	null func() T,
	configName func(Config) string,
	assign func(*Set, T),
) seamSlot {
	return slotDefaulting(seam, family, ImplNone, null, null, configName, assign)
}

// namedImpl is one further built-in an operator may select by name: a narrower
// or older variant of a seam's default that has to stay reachable.
//
// The classifier has one — [ImplRules], the rule engine with no model beneath
// it — because "I want the deterministic half only" is a real position and the
// alternative spellings are both wrong: [ImplNone] also turns the rules off,
// and an env var cannot be written down in a Config.
type namedImpl[T any] struct {
	name string
	make func() T
}

// slotDefaulting builds one row. T is the seam's interface, and the closures
// are the only places that know which Config field, which Set field, and which
// implementations belong to it — stated once each, together, instead of spread
// across four switch-shaped functions.
//
// defaultName/def carry the seam's default when it is not the null one. Both
// are registered, so an operator can name either explicitly; `def` is what an
// unset Config field and [Default] resolve to. `extra` registers any further
// selectable variants.
func slotDefaulting[T any](
	seam ai.Seam,
	family string,
	defaultName string,
	null func() T,
	def func() T,
	configName func(Config) string,
	assign func(*Set, T),
	extra ...namedImpl[T],
) seamSlot {
	return seamSlot{
		seam:        seam,
		family:      family,
		defaultImpl: defaultName,
		implName:    configName,
		registerBuiltins: func(r *Registry) {
			r.impls[seam] = map[string]any{ImplNone: null}
			if defaultName != ImplNone {
				r.impls[seam][defaultName] = def
			}
			for _, e := range extra {
				r.impls[seam][e.name] = e.make
			}
		},
		setDefault: func(s *Set) { assign(s, def()) },
		prepare: func(r *Registry, name string) (func(*Set), bool) {
			f, ok := resolve[T](r, seam, name)
			if !ok {
				return nil, false
			}
			return func(s *Set) { assign(s, f()) }, true
		},
	}
}

// seamSlots is the table. Order follows ai.AllSeams: the three classical seams,
// then the five generative ones. A ninth seam is one row here.
var seamSlots = []seamSlot{
	// The matcher's default is the learned model of shared/identity/matcher
	// (ADR-0008 D2: the classical family is Core, in-process and needs no
	// provider). NullMatcher stays registered under "none" and selectable, so a
	// deployment that wants unscored merge proposals can still say so.
	slotDefaulting(ai.SeamMatcher, FamilyClassical, ImplLearned,
		func() Matcher { return NullMatcher{} },
		NewLearnedMatcher,
		func(c Config) string { return c.Matcher },
		func(s *Set, v Matcher) { s.Matcher = v }),
	// The classifier's default is the CHAIN of workstream 4.2: the rule engine
	// of ADR-0004 D6, with the learned classifier beneath it for the two cases
	// the rules cannot answer (see ChainClassifier.Explain). Two narrower
	// choices stay registered and selectable — [ImplRules] is the rules with no
	// model, [ImplNone] proposes nothing at all — and `CLASSIFIER_MODEL_ENABLED
	// =false` turns the model half off without changing the choice.
	slotDefaulting(ai.SeamClassifier, FamilyClassical, ImplRulesModel,
		func() Classifier { return NullClassifier{} },
		NewChainClassifier,
		func(c Config) string { return c.Classifier },
		func(s *Set, v Classifier) { s.Classifier = v },
		namedImpl[Classifier]{ImplRules, func() Classifier { return RuleClassifier{} }}),
	slot(ai.SeamDriftDetector, FamilyClassical,
		func() DriftDetector { return NullDriftDetector{} },
		func(c Config) string { return c.DriftDetector },
		func(s *Set, v DriftDetector) { s.DriftDetector = v }),
	slot(ai.SeamEnricher, FamilyGenerative,
		func() Enricher { return NullEnricher{} },
		func(c Config) string { return c.Enricher },
		func(s *Set, v Enricher) { s.Enricher = v }),
	slot(ai.SeamNarrator, FamilyGenerative,
		func() Narrator { return NullNarrator{} },
		func(c Config) string { return c.Narrator },
		func(s *Set, v Narrator) { s.Narrator = v }),
	slot(ai.SeamQuery, FamilyGenerative,
		func() Query { return NullQuery{} },
		func(c Config) string { return c.Query },
		func(s *Set, v Query) { s.Query = v }),
	slot(ai.SeamAuthor, FamilyGenerative,
		func() Author { return NullAuthor{} },
		func(c Config) string { return c.Author },
		func(s *Set, v Author) { s.Author = v }),
	slot(ai.SeamRemediator, FamilyGenerative,
		func() Remediator { return NullRemediator{} },
		func(c Config) string { return c.Remediator },
		func(s *Set, v Remediator) { s.Remediator = v }),
}

// Registry maps implementation names to constructors, one namespace per seam.
//
// Phase-4 implementations register here at wiring time; this package ships only
// the null ones. A Registry is safe for concurrent use.
type Registry struct {
	mu sync.RWMutex

	// impls is seam → name → factory. The factory is held as `any` because each
	// seam's is a different func type and Go has no method type parameters;
	// [register] and [resolve] are the only two places that assert on it, and
	// the slot table is what keeps the assertion honest — a mis-wired row fails
	// its entry in the table-driven test rather than at some caller's first use.
	impls map[ai.Seam]map[string]any
}

// NewRegistry returns a registry with [ImplNone] registered for every seam and
// nothing else.
func NewRegistry() *Registry {
	r := &Registry{impls: make(map[ai.Seam]map[string]any, len(seamSlots))}
	for _, sl := range seamSlots {
		sl.registerBuiltins(r)
	}
	return r
}

// register adds f under name in seam's namespace. The eight exported Register
// methods are one line each on top of this; Go does not allow type parameters
// on methods, which is the only reason they exist separately at all.
func register[T any](r *Registry, seam ai.Seam, name string, f func() T) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.impls == nil {
		r.impls = make(map[ai.Seam]map[string]any, len(seamSlots))
	}
	_, exists := r.impls[seam][name]
	if err := checkName(name, exists); err != nil {
		return err
	}
	if r.impls[seam] == nil {
		r.impls[seam] = make(map[string]any, 2)
	}
	r.impls[seam][name] = f
	return nil
}

// resolve looks up the factory for name (empty meaning ImplNone) in one seam's
// namespace. The caller holds the lock.
func resolve[T any](r *Registry, seam ai.Seam, name string) (func() T, bool) {
	f, ok := r.impls[seam][implName(name)]
	if !ok {
		return nil, false
	}
	typed, ok := f.(func() T)
	return typed, ok
}

// ErrUnknownImplementation is returned by Configure when a Config names an
// implementation nothing registered. It is returned rather than silently
// ignored: a name that does nothing is how a capability an operator believes
// they enabled stays off with no signal anywhere.
var ErrUnknownImplementation = fmt.Errorf("seams: unknown implementation")

// Registration errors are returned rather than panicking, so a wiring mistake
// in one service cannot take the process down at init.
var (
	// ErrEmptyName rejects an implementation registered under "".
	ErrEmptyName = fmt.Errorf("seams: implementation name must not be empty")
	// ErrReservedName rejects re-registering "none", which would let a build
	// redefine what "no AI configured" means.
	ErrReservedName = fmt.Errorf("seams: %q is reserved for the null default", ImplNone)
	// ErrDuplicateName rejects registering the same name twice for one seam.
	ErrDuplicateName = fmt.Errorf("seams: implementation already registered")
)

func checkName(name string, exists bool) error {
	switch {
	case name == "":
		return ErrEmptyName
	case name == ImplNone:
		return ErrReservedName
	case exists:
		return fmt.Errorf("%w: %q", ErrDuplicateName, name)
	}
	return nil
}

// RegisterMatcher adds a Matcher implementation under name.
func (r *Registry) RegisterMatcher(name string, f func() Matcher) error {
	return register(r, ai.SeamMatcher, name, f)
}

// RegisterClassifier adds a Classifier implementation under name.
func (r *Registry) RegisterClassifier(name string, f func() Classifier) error {
	return register(r, ai.SeamClassifier, name, f)
}

// RegisterDriftDetector adds a DriftDetector implementation under name.
func (r *Registry) RegisterDriftDetector(name string, f func() DriftDetector) error {
	return register(r, ai.SeamDriftDetector, name, f)
}

// RegisterEnricher adds an Enricher implementation under name.
func (r *Registry) RegisterEnricher(name string, f func() Enricher) error {
	return register(r, ai.SeamEnricher, name, f)
}

// RegisterNarrator adds a Narrator implementation under name.
func (r *Registry) RegisterNarrator(name string, f func() Narrator) error {
	return register(r, ai.SeamNarrator, name, f)
}

// RegisterQuery adds a Query implementation under name.
func (r *Registry) RegisterQuery(name string, f func() Query) error {
	return register(r, ai.SeamQuery, name, f)
}

// RegisterAuthor adds an Author implementation under name.
func (r *Registry) RegisterAuthor(name string, f func() Author) error {
	return register(r, ai.SeamAuthor, name, f)
}

// RegisterRemediator adds a Remediator implementation under name.
func (r *Registry) RegisterRemediator(name string, f func() Remediator) error {
	return register(r, ai.SeamRemediator, name, f)
}

// Configure resolves cfg against the registry.
//
// It ALWAYS returns a usable Set. Seams whose names resolved are swapped in;
// seams whose names did not are left null and named in the error. A caller that
// logs the error and carries on therefore degrades to no-AI for the seam that
// was misconfigured, rather than to a nil interface and a panic on first use.
// A seam CONSTRUCTOR is never called while the registry lock is held. A
// constructor is arbitrary caller code — it may perfectly reasonably register a
// sub-implementation, or ask the registry what else is configured — and
// sync.RWMutex is not reentrant, so doing that under RLock deadlocks the
// process at wiring time. Resolution happens under the lock; construction
// happens after it is released.
func (r *Registry) Configure(cfg Config) (Set, error) {
	set := Default()
	var problems []string
	var construct []func(*Set)
	names := make(map[ai.Seam]string, len(seamSlots))

	r.mu.RLock()
	for _, sl := range seamSlots {
		// An unset field means "whatever this seam's default is", which is
		// [ImplNone] for seven seams and [ImplRules] for the classifier. Reading
		// it off the slot rather than defaulting to ImplNone here is what keeps
		// Configure(Config{}) and [Default] the same Set — they used to be the
		// same only because every default WAS null, and a divergence between
		// them would be invisible until something behaved differently
		// depending on which one built it.
		want := sl.implName(cfg)
		if want == "" {
			want = sl.defaultImpl
		}
		build, ok := sl.prepare(r, want)
		if !ok {
			problems = append(problems, fmt.Sprintf("%s=%q", sl.seam, want))
			continue
		}
		construct = append(construct, build)
		names[sl.seam] = implName(want)
	}
	r.mu.RUnlock()

	for _, build := range construct {
		build(&set)
	}
	for seam, name := range names {
		set.names[seam] = name
	}

	if len(problems) > 0 {
		return set, fmt.Errorf("%w: %v (those seams stay null)", ErrUnknownImplementation, problems)
	}
	return set, nil
}

func implName(name string) string {
	if name == "" {
		return ImplNone
	}
	return name
}

// defaultRegistry is the process-wide registry phase-4 implementations attach
// to. Guarded by its own mutex; created once.
var (
	defaultRegistryOnce sync.Once
	defaultRegistry     *Registry
)

// DefaultRegistry returns the process-wide registry. Prefer passing a Registry
// (or a resolved Set) explicitly where you can; this exists because
// implementations register from init-time wiring in another package, which has
// nowhere else to put them.
func DefaultRegistry() *Registry {
	defaultRegistryOnce.Do(func() { defaultRegistry = NewRegistry() })
	return defaultRegistry
}

// Configure resolves cfg against [DefaultRegistry]. See [Registry.Configure]
// for the always-usable-Set guarantee.
func Configure(cfg Config) (Set, error) {
	return DefaultRegistry().Configure(cfg)
}

// Description is one row of the "which seams are active" answer the Settings
// page will show.
type Description struct {
	Seam ai.Seam `json:"seam"`

	// Implementation is the configured name, "none" when null.
	Implementation string `json:"implementation"`

	// State is [StateInactive], [StateActive] or [StateConfiguredUnavailable].
	//
	// The third one is the reason this is not a bool. An operator who
	// configured a narrator and left AI_PROVIDER unset has a seam that is
	// configured and cannot answer, and reporting that as "active" is this
	// repo's oldest bug shape — "did not check" rendered as "passed" — on a
	// settings page. It is a different fact from "you have not configured a
	// narrator", and the page has to be able to say which.
	State string `json:"state"`

	// Active is State == StateActive, kept so a UI that only wants the simple
	// question does not have to compare strings. It is FALSE for a
	// configured-but-unavailable seam: nothing will answer through it.
	Active bool `json:"active"`

	// Family is "classical" or "generative" (ADR-0008 D2). The generative ones
	// are the ones that export data to a provider, which is the distinction an
	// operator cares about — and the only ones whose state depends on it.
	Family string `json:"family"`
}

// Families, per ADR-0008 D2.
const (
	FamilyClassical  = "classical"
	FamilyGenerative = "generative"
)

// Seam states, as a Settings page needs to distinguish them.
const (
	// StateInactive is the null default: nothing configured, nothing proposed.
	StateInactive = "inactive"
	// StateActive means an implementation is configured and can answer. For a
	// generative seam that includes its provider reporting itself available.
	StateActive = "active"
	// StateConfiguredUnavailable means a generative seam has an implementation
	// configured but no reachable provider — AI_PROVIDER unset or naming
	// something this build does not have, or a provider reporting itself down.
	// The operator's configuration is fine; the capability still cannot answer.
	StateConfiguredUnavailable = "configured_unavailable"
)

// Describe reports the state of every seam in s, sorted by seam name so the
// output is stable. Every seam appears, including the null ones: "this
// deployment has no classifier" is exactly the thing the page needs to say.
//
// provider is the one the generative seams would reach a model through — the
// same value passed to [ai.Boundary]. It is required, not optional, because
// without it this function cannot tell [StateActive] from
// [StateConfiguredUnavailable], and would have to guess in the direction that
// overstates. Pass nil only when there genuinely is no provider; that reads as
// unavailable, which is the truth.
//
// Classical seams (matcher, classifier, drift detector) run in-process and
// never consult it: their state is configured-or-not, and a deployment with no
// provider at all still has a working classifier if it configured one.
//
// It walks the same seamSlots table as Configure, so a seam cannot be
// configurable but undescribed.
func Describe(s Set, provider ai.Provider) []Description {
	providerUp := provider != nil && provider.Available()

	out := make([]Description, 0, len(seamSlots))
	for _, sl := range seamSlots {
		impl := ImplNone
		if s.names != nil {
			if n, ok := s.names[sl.seam]; ok {
				impl = n
			}
		}

		state := StateActive
		switch {
		case impl == ImplNone:
			state = StateInactive
		case sl.family == FamilyGenerative && !providerUp:
			state = StateConfiguredUnavailable
		}

		out = append(out, Description{
			Seam:           sl.seam,
			Implementation: impl,
			State:          state,
			Active:         state == StateActive,
			Family:         sl.family,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seam < out[j].Seam })
	return out
}
