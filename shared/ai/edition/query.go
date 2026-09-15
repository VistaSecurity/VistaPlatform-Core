package edition

import (
	"log"

	"github.com/vistasecurity/vistaplatform/shared/ai"
	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
	ql "github.com/vistasecurity/vistaplatform/shared/query"
)

// The grounded query seam's edition wiring.
//
// It is here rather than in the service that mounts it, unlike the narrator
// (services/cbom-service/ee/diff) and the author
// (services/compliance-engine/ee/author). Those two live in their service's own
// ee/ tree because they are about that service's data: a CBOM diff, a
// compliance catalogue. This one is about the query language and the MCP tools,
// which belong to no single service, so its implementation lives in
// shared/ai/ee/query — and a shared ee/ tree needs the same
// blank-import-behind-a-build-tag trick the providers needed, for the same
// import-cycle reason. See the package doc above.
//
// The consumer's side of the deal is one call:
//
//	q, state := edition.NewQuery(catalogue, sink)
//
// which returns seams.NullQuery in Core and the real thing in an Enterprise
// build with a reachable provider — and, either way, a Description saying which
// of those happened and why.

// QueryFactory builds the generative query seam over a provider and the query
// catalogue.
//
// It is a function variable rather than a direct call because Core may not name
// shared/ai/ee/query: that package imports shared/ai, so shared/ai cannot
// import it back, and the ee-tagged file beside this one is the only place the
// two ever meet.
type QueryFactory func(provider ai.Provider, cat ql.LadderCatalog, sink ai.AuditSink) seams.Query

var queryFactory QueryFactory

// RegisterQuery installs the generative query implementation. The ee-tagged
// init in this package is the only caller.
//
// It is exported rather than package-private only because the registration has
// to happen from a file this one cannot see into; there is nothing for a
// service to do with it. Registering twice is a programming error and the
// second call wins loudly rather than silently, so a future second
// implementation cannot displace the first without someone noticing.
func RegisterQuery(f QueryFactory) {
	if queryFactory != nil {
		log.Printf("[ai-edition] a query seam implementation was already registered; replacing it")
	}
	queryFactory = f
}

// QueryLinked reports whether this build has a generative query implementation
// compiled in.
//
// Separate from [Linked], which answers the same question about the model
// clients, because they are genuinely different facts: a build could in
// principle have the providers and not this seam. A UI distinguishing "your
// edition does not include this" from "you have not configured a provider"
// needs both, and showing an operator the same blank for either is how a
// support ticket starts.
func QueryLinked() bool { return queryFactory != nil }

// NewQuery resolves the query seam this deployment runs, and describes it.
//
// AI_PROVIDER unset or "none" — which is almost every deployment — yields
// [seams.NullQuery], whose Answer returns ai.ErrUnavailable. A Core build
// yields it too, whatever AI_PROVIDER says, because a Core build has neither
// the model clients nor this seam. An Enterprise build with a reachable
// provider yields the real one.
//
// It never returns nil and never fails. A misconfiguration degrades to the null
// seam with a log line naming what went wrong: a typo in AI_MODEL must not be
// able to take a service down, and must not be able to silently disable a
// capability an operator believes they turned on — which is what the returned
// Description is for. Its State distinguishes:
//
//	inactive                nothing configured, or this edition has no seam
//	configured_unavailable  configured, but no provider will answer
//	active                  it will answer
//
// sink receives the boundary's per-call audit records AND the seam's own
// grounding record (ADR-0008 D4.7). Pass the same one; two would split a single
// question's trail across two rails. Pass nil only where there is genuinely no
// audit rail, which is not a configuration a deployment sending prompts
// anywhere should run.
func NewQuery(cat ql.LadderCatalog, sink ai.AuditSink) (seams.Query, seams.Description) {
	provider, err := ai.NewFromEnv()
	if err != nil {
		// Not fatal and not silent. NewFromEnv always hands back a usable
		// provider (NoneProvider here), so the only thing lost is the grounded
		// query — and an operator who set AI_PROVIDER needs to be told it did
		// not take.
		log.Printf("[ai-edition] AI provider not configured: %v — natural-language query is unavailable", err)
	}
	provider = ai.Boundary(provider, sink)

	reg := seams.NewRegistry()
	want := ""
	if queryFactory != nil && cat != nil {
		if err := reg.RegisterQuery(implQuery, func() seams.Query {
			return queryFactory(provider, cat, sink)
		}); err != nil {
			log.Printf("[ai-edition] registering %s failed: %v", implQuery, err)
		} else if provider.Available() {
			// Registered unconditionally, SELECTED only when a provider will
			// answer. Registering conditionally would make "configured but
			// unreachable" indistinguishable from "not configured", which is
			// the one distinction the Description exists to draw.
			want = implQuery
		}
	}

	set, err := reg.Configure(seams.Config{Query: want})
	if err != nil {
		// Configure always returns a usable Set with unresolved seams left
		// null, so this degrades to no grounded query rather than to a nil
		// interface.
		log.Printf("[ai-edition] seam configuration incomplete: %v", err)
	}

	desc := seams.Description{Seam: ai.SeamQuery, Implementation: seams.ImplNone, State: seams.StateInactive, Family: seams.FamilyGenerative}
	for _, d := range seams.Describe(set, provider) {
		if d.Seam != ai.SeamQuery {
			continue
		}
		desc = d
		log.Printf("[ai-edition] seam=%s implementation=%s state=%s provider=%s linked=%t",
			d.Seam, d.Implementation, d.State, provider.Name(), QueryLinked())
	}
	return set.Query, desc
}

// implQuery is the implementation name the generative query seam registers
// under. It is duplicated from shared/ai/ee/query's exported ImplModel by
// necessity — Core cannot import that package to read it — and
// TestQueryImplNameMatchesTheEnterpriseConstant pins the two together in the
// ee-tagged test, which is the build that can see both.
const implQuery = "inventory-model"
