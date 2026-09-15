package seams

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/ai"
)

type stubClassifier struct{}

func (stubClassifier) Classify(context.Context, AssetFacts) (ClassProposal, error) {
	return ClassProposal{
		Proposal: Proposal{Confidence: 0.91, ModelID: "stub-v1"},
		Class:    "network_device",
	}, nil
}

type stubNarrator struct{}

func (stubNarrator) Narrate(context.Context, NarrationInput) (Narrative, error) {
	return Narrative{Proposal: Proposal{ModelID: "stub-v1"}, Available: true, Text: "ok"}, nil
}

// availableProvider is a provider that reports itself up, for the tests whose
// subject is the registry rather than the provider. Describe needs one to tell
// an active generative seam from a configured-but-unreachable one.
func availableProvider() ai.Provider { return &ai.MockProvider{} }

// markerSeam implements all eight seam interfaces and answers with its marker,
// so one stub type can stand in for any seam. That is what makes mis-wiring
// visible: if a table row assigned its implementation to the wrong field of
// Set, the seam under test would answer with the null default's empty answer
// and the seam that received it would answer with someone else's marker.
type markerSeam struct{ marker string }

func (m markerSeam) Match(context.Context, Observation, []AssetSummary) ([]MatchScore, error) {
	return []MatchScore{{Reason: m.marker}}, nil
}

func (m markerSeam) Classify(context.Context, AssetFacts) (ClassProposal, error) {
	return ClassProposal{Class: m.marker}, nil
}

func (m markerSeam) Detect(context.Context, PopulationWindow) ([]Anomaly, error) {
	return []Anomaly{{Kind: m.marker}}, nil
}

func (m markerSeam) Enrich(context.Context, EnrichmentSubject) ([]Fact, error) {
	return []Fact{{Key: m.marker}}, nil
}

func (m markerSeam) Narrate(context.Context, NarrationInput) (Narrative, error) {
	return Narrative{Available: true, Text: m.marker}, nil
}

func (m markerSeam) Answer(context.Context, string, ToolSet) (Answer, error) {
	return Answer{Text: m.marker}, nil
}

func (m markerSeam) Draft(context.Context, string) ([]ControlDraft, error) {
	return []ControlDraft{{Title: m.marker}}, nil
}

func (m markerSeam) Propose(context.Context, FindingRef) (PlanDraft, error) {
	return PlanDraft{Summary: m.marker}, nil
}

// seamCase is one seam, exercised end to end: registered, configured, called
// through the Set it lands in.
//
// The four funcs are the only per-seam knowledge in the test, and they are
// deliberately written against the PUBLIC API (RegisterX, Config, Set) rather
// than against seamSlots — a table-driven test that reads the same table as the
// code under test would agree with it about a seam neither of them has.
type seamCase struct {
	seam      ai.Seam
	register  func(*Registry, string) error
	configure func(*Config, string)
	// probe calls the seam through the Set and returns the marker it answered
	// with, or "" for a null default's "I have no proposal".
	probe func(Set) string
}

func seamCases() []seamCase {
	stub := func(seam ai.Seam) markerSeam { return markerSeam{marker: "stub:" + string(seam)} }
	ctx := context.Background()

	return []seamCase{
		{
			seam: ai.SeamMatcher,
			register: func(r *Registry, n string) error {
				return r.RegisterMatcher(n, func() Matcher { return stub(ai.SeamMatcher) })
			},
			configure: func(c *Config, n string) { c.Matcher = n },
			probe: func(s Set) string {
				got, _ := s.Matcher.Match(ctx, Observation{}, nil)
				if len(got) == 0 {
					return ""
				}
				return got[0].Reason
			},
		},
		{
			seam: ai.SeamClassifier,
			register: func(r *Registry, n string) error {
				return r.RegisterClassifier(n, func() Classifier { return stub(ai.SeamClassifier) })
			},
			configure: func(c *Config, n string) { c.Classifier = n },
			probe: func(s Set) string {
				got, _ := s.Classifier.Classify(ctx, AssetFacts{})
				return got.Class
			},
		},
		{
			seam: ai.SeamDriftDetector,
			register: func(r *Registry, n string) error {
				return r.RegisterDriftDetector(n, func() DriftDetector { return stub(ai.SeamDriftDetector) })
			},
			configure: func(c *Config, n string) { c.DriftDetector = n },
			probe: func(s Set) string {
				got, _ := s.DriftDetector.Detect(ctx, PopulationWindow{})
				if len(got) == 0 {
					return ""
				}
				return got[0].Kind
			},
		},
		{
			seam: ai.SeamEnricher,
			register: func(r *Registry, n string) error {
				return r.RegisterEnricher(n, func() Enricher { return stub(ai.SeamEnricher) })
			},
			configure: func(c *Config, n string) { c.Enricher = n },
			probe: func(s Set) string {
				got, _ := s.Enricher.Enrich(ctx, EnrichmentSubject{})
				if len(got) == 0 {
					return ""
				}
				return got[0].Key
			},
		},
		{
			seam: ai.SeamNarrator,
			register: func(r *Registry, n string) error {
				return r.RegisterNarrator(n, func() Narrator { return stub(ai.SeamNarrator) })
			},
			configure: func(c *Config, n string) { c.Narrator = n },
			probe: func(s Set) string {
				got, _ := s.Narrator.Narrate(ctx, NarrationInput{})
				if !got.Available {
					return ""
				}
				return got.Text
			},
		},
		{
			seam: ai.SeamQuery,
			register: func(r *Registry, n string) error {
				return r.RegisterQuery(n, func() Query { return stub(ai.SeamQuery) })
			},
			configure: func(c *Config, n string) { c.Query = n },
			probe: func(s Set) string {
				got, err := s.Query.Answer(ctx, "?", nil)
				if err != nil {
					return ""
				}
				return got.Text
			},
		},
		{
			seam: ai.SeamAuthor,
			register: func(r *Registry, n string) error {
				return r.RegisterAuthor(n, func() Author { return stub(ai.SeamAuthor) })
			},
			configure: func(c *Config, n string) { c.Author = n },
			probe: func(s Set) string {
				got, err := s.Author.Draft(ctx, "")
				if err != nil || len(got) == 0 {
					return ""
				}
				return got[0].Title
			},
		},
		{
			seam: ai.SeamRemediator,
			register: func(r *Registry, n string) error {
				return r.RegisterRemediator(n, func() Remediator { return stub(ai.SeamRemediator) })
			},
			configure: func(c *Config, n string) { c.Remediator = n },
			probe: func(s Set) string {
				got, err := s.Remediator.Propose(ctx, FindingRef{})
				if err != nil {
					return ""
				}
				return got.Summary
			},
		},
	}
}

// Every seam, through the whole path: register → configure → the right field of
// Set answers → the right Describe row changes.
//
// Six of the eight Register/Configure branches had no test at all when these
// were eight hand-written parallel lists; a seam could be registerable and not
// resolvable, or resolvable and absent from Describe, and nothing would say so.
func TestEverySeam_RegistersConfiguresAndDescribes(t *testing.T) {
	cases := seamCases()

	if len(cases) != len(ai.AllSeams()) {
		t.Fatalf("this test covers %d seams but ai.AllSeams has %d", len(cases), len(ai.AllSeams()))
	}

	for _, tc := range cases {
		t.Run(string(tc.seam), func(t *testing.T) {
			const name = "stub-impl"
			r := NewRegistry()
			if err := tc.register(r, name); err != nil {
				t.Fatalf("register: %v", err)
			}

			var cfg Config
			tc.configure(&cfg, name)

			set, err := r.Configure(cfg)
			if err != nil {
				t.Fatalf("Configure: %v", err)
			}

			// The seam configured answers, through its own field of Set.
			want := "stub:" + string(tc.seam)
			if got := tc.probe(set); got != want {
				t.Errorf("%s answered %q, want %q — the implementation went into the wrong "+
					"field of Set, or Configure never resolved this seam", tc.seam, got, want)
			}

			// And every OTHER seam is still null. This is what catches a table
			// row wired to a neighbour's field: the neighbour would answer with
			// this seam's marker instead of nothing.
			for _, other := range cases {
				if other.seam == tc.seam {
					continue
				}
				if got := other.probe(set); got != "" {
					t.Errorf("configuring %s also changed %s, which answered %q",
						tc.seam, other.seam, got)
				}
			}

			// Describe reports exactly this seam as carrying the stub, and every
			// other seam as carrying its own default — which is "none" for
			// seven of them and ImplRules for the classifier.
			for _, d := range Describe(set, availableProvider()) {
				wantImpl := defaultImplFor(d.Seam)
				wantActive := wantImpl != ImplNone
				if d.Seam == tc.seam {
					wantImpl, wantActive = name, true
				}
				if d.Implementation != wantImpl || d.Active != wantActive {
					t.Errorf("Describe row %s = %q/active=%v, want %q/active=%v",
						d.Seam, d.Implementation, d.Active, wantImpl, wantActive)
				}
			}
		})
	}
}

// The table is the single list. A ninth seam that is added to ai.AllSeams but
// not here would be missing from Configure, Default, NewRegistry and Describe
// all at once — which is the point, but only if something says so.
func TestSeamSlots_CoverEverySeamExactlyOnce(t *testing.T) {
	seen := map[ai.Seam]int{}
	for _, sl := range seamSlots {
		seen[sl.seam]++
		if sl.implName == nil || sl.registerBuiltins == nil || sl.setDefault == nil || sl.prepare == nil {
			t.Errorf("seam slot %s has a nil function in it", sl.seam)
		}
		if sl.family != FamilyClassical && sl.family != FamilyGenerative {
			t.Errorf("seam slot %s has family %q", sl.seam, sl.family)
		}
		if sl.defaultImpl == "" {
			t.Errorf("seam slot %s has an empty defaultImpl — an unset Config field would resolve to nothing", sl.seam)
		}
	}
	for _, seam := range ai.AllSeams() {
		if seen[seam] != 1 {
			t.Errorf("ai.AllSeams lists %s, which appears in seamSlots %d times", seam, seen[seam])
		}
		delete(seen, seam)
	}
	for extra := range seen {
		t.Errorf("seamSlots has a row for %q, which is not one of ai.AllSeams()", extra)
	}
}

// defaultImplFor reads a seam's default implementation name out of the slot
// table, so these tests state the same fact the code does rather than a second
// copy of it that can drift.
func defaultImplFor(seam ai.Seam) string {
	for _, sl := range seamSlots {
		if sl.seam == seam {
			return sl.defaultImpl
		}
	}
	return ""
}

// defaultImplementations is what a deployment with no AI configured runs, seam
// by seam. It is spelled out rather than derived so that CHANGING a default is
// a deliberate edit to this list and not a side effect of a slot-table change —
// a seam silently acquiring a non-null default is a capability appearing in
// every install with nobody having decided it should.
//
// Two of the eight are not null, and neither is AI: the classifier's rule
// engine (ADR-0004 D6) and the matcher's logistic-regression model (ADR-0008
// D2's classical family — Core, in-process, no provider, no network). Both are
// deterministic and both PROPOSE; neither decides anything.
var defaultImplementations = map[ai.Seam]string{
	ai.SeamMatcher:       ImplLearned,
	ai.SeamClassifier:    ImplRulesModel,
	ai.SeamDriftDetector: ImplNone,
	ai.SeamEnricher:      ImplNone,
	ai.SeamNarrator:      ImplNone,
	ai.SeamQuery:         ImplNone,
	ai.SeamAuthor:        ImplNone,
	ai.SeamRemediator:    ImplNone,
}

func TestDefault_MatchesTheStatedDefaultsAndEverySeamIsPresent(t *testing.T) {
	s := Default()

	// A nil seam is the failure mode that matters: it panics at the first call
	// site, in whichever service wired it, long after the mistake.
	if s.Matcher == nil || s.Classifier == nil || s.DriftDetector == nil ||
		s.Enricher == nil || s.Narrator == nil || s.Query == nil ||
		s.Author == nil || s.Remediator == nil {
		t.Fatalf("Default() left a seam nil: %+v", s)
	}

	described := Describe(s, availableProvider())
	if len(described) != len(defaultImplementations) {
		t.Fatalf("Describe covered %d seams, the stated defaults cover %d", len(described), len(defaultImplementations))
	}
	for _, d := range described {
		want, stated := defaultImplementations[d.Seam]
		if !stated {
			t.Errorf("%s has no stated default", d.Seam)
			continue
		}
		if d.Implementation != want {
			t.Errorf("%s = %q, want %q", d.Seam, d.Implementation, want)
		}
		if d.Active != (want != ImplNone) {
			t.Errorf("%s reported Active=%v with implementation %q", d.Seam, d.Active, d.Implementation)
		}
		// The slot table is the code's own statement of the same fact; the two
		// must agree, or Default() and Configure(Config{}) would diverge.
		if got := defaultImplFor(d.Seam); got != want {
			t.Errorf("%s: the slot table's default is %q, the stated default is %q", d.Seam, got, want)
		}
	}
}

// "none" is still selectable for the matcher. An operator who wants unscored
// merge proposals must be able to say so and get the null matcher, not the
// model with an extra step.
func TestConfigure_MatcherNoneSelectsTheNullMatcher(t *testing.T) {
	set, err := NewRegistry().Configure(Config{Matcher: ImplNone})
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if _, ok := set.Matcher.(NullMatcher); !ok {
		t.Fatalf("matcher: none gave %T, want NullMatcher", set.Matcher)
	}
	scores, err := set.Matcher.Match(t.Context(), Observation{}, []AssetSummary{{ID: "a"}})
	if err != nil || scores != nil {
		t.Fatalf("the null matcher proposed %v (err %v)", scores, err)
	}
}

// Default() and Configure(Config{}) must agree. They used to agree only by
// accident — every default was null — and a divergence would be invisible until
// something behaved differently depending on which built its Set.
func TestDefault_AndEmptyConfigAgreeOnEverySeam(t *testing.T) {
	fromDefault := Describe(Default(), availableProvider())

	set, err := NewRegistry().Configure(Config{})
	if err != nil {
		t.Fatalf("Configure(Config{}): %v", err)
	}
	fromConfigure := Describe(set, availableProvider())

	if len(fromDefault) != len(fromConfigure) {
		t.Fatalf("Describe lengths differ: %d vs %d", len(fromDefault), len(fromConfigure))
	}
	for i := range fromDefault {
		if fromDefault[i] != fromConfigure[i] {
			t.Errorf("%s: Default gave %+v, Configure(Config{}) gave %+v",
				fromDefault[i].Seam, fromDefault[i], fromConfigure[i])
		}
	}
}

// The rule classifier is the DEFAULT, and "none" is still selectable. An
// operator who wants no class proposals at all must be able to say so and get
// the null classifier, not the rules with an extra step.
func TestConfigure_ClassifierNoneSelectsTheNullClassifier(t *testing.T) {
	set, err := NewRegistry().Configure(Config{Classifier: ImplNone})
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if _, ok := set.Classifier.(NullClassifier); !ok {
		t.Fatalf("Classifier = %T, want NullClassifier", set.Classifier)
	}

	// And it answers the way the null contract says: unknown, no class, no
	// confidence, with a source_ref naming the null producer.
	got, err := set.Classifier.Classify(context.Background(), AssetFacts{
		Identifiers: map[string]string{FactMACAddress: "00:50:56:aa:bb:cc"},
	})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if !got.Unknown || got.Class != "" {
		t.Errorf("got %+v; explicitly selecting none did not disable the rules", got)
	}
	if !strings.HasSuffix(got.SourceRef, ":"+ImplNone) {
		t.Errorf("SourceRef = %q, want it to name the null producer", got.SourceRef)
	}
}

// An empty Config resolves cleanly and every seam in the resulting Set answers
// its documented no-proposal answer. For seven seams that is the null default;
// for the classifier it is the rule engine, which says exactly the same thing
// when handed no evidence — "not assessed stays not assessed" is the contract,
// not "the implementation is a stub".
func TestConfigure_EmptyConfigProposesNothingForEverySeam(t *testing.T) {
	set, err := NewRegistry().Configure(Config{})
	if err != nil {
		t.Fatalf("an empty Config must resolve cleanly: %v", err)
	}
	got, err := set.Classifier.Classify(context.Background(), AssetFacts{})
	if err != nil || !got.Unknown || got.Class != "" {
		t.Errorf("the empty Config yielded a classifier that guessed: %+v, %v", got, err)
	}
	if _, ok := set.Classifier.(ChainClassifier); !ok {
		t.Errorf("Classifier = %T, want the rule-then-model chain — an unset field must take the seam's default", set.Classifier)
	}
	if scores, err := set.Matcher.Match(context.Background(), Observation{}, nil); err != nil || scores != nil {
		t.Errorf("Matcher proposed %+v, %v", scores, err)
	}
}

func TestConfigure_SwapsOnlyTheNamedSeams(t *testing.T) {
	r := NewRegistry()
	if err := r.RegisterClassifier("stub", func() Classifier { return stubClassifier{} }); err != nil {
		t.Fatalf("RegisterClassifier: %v", err)
	}
	if err := r.RegisterNarrator("stub", func() Narrator { return stubNarrator{} }); err != nil {
		t.Fatalf("RegisterNarrator: %v", err)
	}

	set, err := r.Configure(Config{Classifier: "stub", Narrator: "stub"})
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}

	cls, err := set.Classifier.Classify(context.Background(), AssetFacts{})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if cls.Class != "network_device" {
		t.Errorf("the registered classifier was not used: %+v", cls)
	}

	// Everything not named stays null.
	if _, err := set.Query.Answer(context.Background(), "?", nil); !errors.Is(err, ai.ErrUnavailable) {
		t.Errorf("an unnamed seam was not left null: %v", err)
	}

	byName := map[ai.Seam]Description{}
	for _, d := range Describe(set, availableProvider()) {
		byName[d.Seam] = d
	}
	if !byName[ai.SeamClassifier].Active || byName[ai.SeamClassifier].Implementation != "stub" {
		t.Errorf("Describe missed the configured classifier: %+v", byName[ai.SeamClassifier])
	}
	if byName[ai.SeamQuery].Active {
		t.Errorf("Describe reported an unconfigured seam as active: %+v", byName[ai.SeamQuery])
	}
}

// A name that resolves to nothing must be reported, not swallowed. A capability
// an operator believes they turned on, silently off, with no signal anywhere,
// is the exact failure shape this repo keeps finding.
func TestConfigure_UnknownNameErrorsButStillReturnsAUsableSet(t *testing.T) {
	set, err := NewRegistry().Configure(Config{Classifier: "does-not-exist"})

	if !errors.Is(err, ErrUnknownImplementation) {
		t.Fatalf("err = %v, want ErrUnknownImplementation", err)
	}

	// And the Set is still safe to use: a caller that logs and carries on
	// degrades to the seam's default rather than to a nil-interface panic.
	if set.Classifier == nil {
		t.Fatal("Configure returned a Set with a nil seam alongside its error")
	}
	got, err := set.Classifier.Classify(context.Background(), AssetFacts{})
	if err != nil || !got.Unknown {
		t.Errorf("the misconfigured seam did not fall back to its default: %+v, %v", got, err)
	}
}

func TestConfigure_NamesEverySeamThatFailedToResolve(t *testing.T) {
	_, err := NewRegistry().Configure(Config{Classifier: "nope-a", Query: "nope-b"})
	if err == nil {
		t.Fatal("two unknown names resolved cleanly")
	}
	for _, want := range []string{"classifier", "nope-a", "query", "nope-b"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not name %q: %v", want, err)
		}
	}
}

func TestRegister_RejectsEmptyReservedAndDuplicateNames(t *testing.T) {
	r := NewRegistry()
	f := func() Classifier { return stubClassifier{} }

	if err := r.RegisterClassifier("", f); !errors.Is(err, ErrEmptyName) {
		t.Errorf("empty name: err = %v, want ErrEmptyName", err)
	}
	// Re-registering "none" would let a build redefine what "no AI configured"
	// means, which is the one thing every deployment relies on.
	if err := r.RegisterClassifier(ImplNone, f); !errors.Is(err, ErrReservedName) {
		t.Errorf("reserved name: err = %v, want ErrReservedName", err)
	}
	if err := r.RegisterClassifier("stub", f); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	if err := r.RegisterClassifier("stub", f); !errors.Is(err, ErrDuplicateName) {
		t.Errorf("duplicate name: err = %v, want ErrDuplicateName", err)
	}

	// The null default still resolves after all that.
	set, err := r.Configure(Config{})
	if err != nil || set.Classifier == nil {
		t.Errorf("the registry was left unusable: %v", err)
	}
}

func TestDescribe_CoversAllEightSeamsWithTheirFamily(t *testing.T) {
	got := Describe(Default(), availableProvider())
	if len(got) != 8 {
		t.Fatalf("Describe returned %d rows, want 8", len(got))
	}

	wantFamily := map[ai.Seam]string{
		ai.SeamMatcher:       FamilyClassical,
		ai.SeamClassifier:    FamilyClassical,
		ai.SeamDriftDetector: FamilyClassical,
		ai.SeamEnricher:      FamilyGenerative,
		ai.SeamNarrator:      FamilyGenerative,
		ai.SeamQuery:         FamilyGenerative,
		ai.SeamAuthor:        FamilyGenerative,
		ai.SeamRemediator:    FamilyGenerative,
	}
	seen := map[ai.Seam]bool{}
	for _, d := range got {
		seen[d.Seam] = true
		if d.Family != wantFamily[d.Seam] {
			t.Errorf("%s family = %q, want %q", d.Seam, d.Family, wantFamily[d.Seam])
		}
	}
	for seam := range wantFamily {
		if !seen[seam] {
			t.Errorf("Describe omitted %s", seam)
		}
	}

	// Sorted, so a Settings page and a test see the same order every run.
	for i := 1; i < len(got); i++ {
		if got[i-1].Seam >= got[i].Seam {
			t.Errorf("Describe is not sorted: %q before %q", got[i-1].Seam, got[i].Seam)
		}
	}
}

// "Configured, and cannot answer" is a third state, and Describe used to
// collapse it into "active": Active was impl != none and the provider was never
// consulted, so a narrator configured against AI_PROVIDER=none showed green on
// a settings page while every call returned ErrUnavailable. That is this repo's
// oldest bug shape — "did not check" rendered as "passed" — on the page whose
// entire job is to say what this deployment has turned on.
func TestDescribe_DistinguishesInactiveActiveAndConfiguredUnavailable(t *testing.T) {
	r := NewRegistry()
	if err := r.RegisterClassifier("stub", func() Classifier { return stubClassifier{} }); err != nil {
		t.Fatalf("RegisterClassifier: %v", err)
	}
	if err := r.RegisterNarrator("stub", func() Narrator { return stubNarrator{} }); err != nil {
		t.Fatalf("RegisterNarrator: %v", err)
	}
	// A classical seam and a generative one configured; the rest left null.
	set, err := r.Configure(Config{Classifier: "stub", Narrator: "stub"})
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}

	providers := map[string]ai.Provider{
		"no provider at all":             nil,
		"AI_PROVIDER=none":               ai.NoneProvider{},
		"provider reporting itself down": &ai.MockProvider{Unavailable: true},
	}

	for name, provider := range providers {
		t.Run("unavailable: "+name, func(t *testing.T) {
			rows := map[ai.Seam]Description{}
			for _, d := range Describe(set, provider) {
				rows[d.Seam] = d
			}

			// The generative seam is configured and cannot answer.
			if got := rows[ai.SeamNarrator]; got.State != StateConfiguredUnavailable || got.Active {
				t.Errorf("narrator = %+v, want state %q and Active false", got, StateConfiguredUnavailable)
			}
			if got := rows[ai.SeamNarrator].Implementation; got != "stub" {
				t.Errorf("narrator implementation = %q; the configuration is still what the operator set", got)
			}

			// The classical seam does not depend on a provider and is active.
			if got := rows[ai.SeamClassifier]; got.State != StateActive || !got.Active {
				t.Errorf("classifier = %+v, want state %q — a classical seam runs in-process",
					got, StateActive)
			}

			// An unconfigured generative seam is inactive, NOT
			// configured-unavailable: nothing was configured to be unavailable.
			if got := rows[ai.SeamQuery]; got.State != StateInactive || got.Active {
				t.Errorf("query = %+v, want state %q", got, StateInactive)
			}
		})
	}

	t.Run("available provider", func(t *testing.T) {
		rows := map[ai.Seam]Description{}
		for _, d := range Describe(set, &ai.MockProvider{}) {
			rows[d.Seam] = d
		}
		for _, seam := range []ai.Seam{ai.SeamNarrator, ai.SeamClassifier} {
			if got := rows[seam]; got.State != StateActive || !got.Active {
				t.Errorf("%s = %+v, want state %q with a working provider", seam, got, StateActive)
			}
		}
		if got := rows[ai.SeamEnricher]; got.State != StateInactive {
			t.Errorf("enricher = %+v; an unconfigured seam is inactive whatever the provider does", got)
		}
	})
}

// Describe must survive a Set built by hand (zero names map) rather than
// panicking or reporting a seam as active because it has no name recorded.
func TestDescribe_HandlesASetWithNoRecordedNames(t *testing.T) {
	for _, d := range Describe(Set{}, availableProvider()) {
		if d.Active || d.Implementation != ImplNone {
			t.Errorf("%s reported %q/active=%v for a hand-built Set", d.Seam, d.Implementation, d.Active)
		}
	}
}

// A seam constructor is caller code and may touch the registry: registering a
// sub-implementation it owns, or asking what else is configured. sync.RWMutex
// is not reentrant, so calling constructors under the resolution lock wedged
// the process at wiring time — no error, no panic, just a service that never
// finishes starting.
//
// The timeout is the assertion: without it a deadlock hangs the test binary for
// ten minutes and reports as a panic in some other test.
func TestConfigure_AConstructorMayReenterTheRegistry(t *testing.T) {
	r := NewRegistry()

	err := r.RegisterClassifier("reentrant", func() Classifier {
		// Exactly what a real implementation might do: register the variant it
		// delegates to, and read back what is configured.
		_ = r.RegisterNarrator("registered-from-a-constructor", func() Narrator { return stubNarrator{} })
		_, _ = r.Configure(Config{})
		return stubClassifier{}
	})
	if err != nil {
		t.Fatalf("RegisterClassifier: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		set, err := r.Configure(Config{Classifier: "reentrant"})
		if err != nil {
			t.Errorf("Configure: %v", err)
			return
		}
		got, err := set.Classifier.Classify(context.Background(), AssetFacts{})
		if err != nil || got.Class != "network_device" {
			t.Errorf("the re-entrant constructor's classifier was not installed: %+v, %v", got, err)
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Configure deadlocked: a seam constructor re-entered the registry " +
			"while Configure still held the read lock")
	}
}

func TestDefaultRegistry_IsStableAcrossCalls(t *testing.T) {
	first := DefaultRegistry()
	second := DefaultRegistry()
	if first != second {
		t.Error("DefaultRegistry returned two different registries; registrations would be lost")
	}
	if _, err := Configure(Config{}); err != nil {
		t.Errorf("package-level Configure on the default registry: %v", err)
	}
}
