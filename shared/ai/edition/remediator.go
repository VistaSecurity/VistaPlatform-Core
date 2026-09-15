package edition

import (
	"log"

	"github.com/vistasecurity/vistaplatform/shared/ai"
	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
)

// The remediator seam's edition wiring.
//
// It is here rather than in compliance-engine's own ee/ tree, unlike the
// narrator (services/cbom-service/ee/diff) and the author
// (services/compliance-engine/ee/author), for the reason the query seam is: what
// it is about — findings, their evidence, and the guidance the findings registry
// carries per kind — belongs to the registry rather than to one service, and the
// producers that write those findings are spread across three. A shared ee/ tree
// needs the same blank-import-behind-a-build-tag trick the providers needed, for
// the same import-cycle reason. See the package doc above.
//
// The consumer's side of the deal is one call:
//
//	rem, state := edition.NewRemediator(sink)
//
// which returns seams.NullRemediator in Core and the real thing in an Enterprise
// build with a reachable provider — and, either way, a Description saying which
// of those happened and why.

// RemediatorFactory builds the generative remediator over a provider.
//
// A function variable rather than a direct call because Core may not name
// shared/ai/ee/remediator: that package imports shared/ai, so shared/ai cannot
// import it back, and the ee-tagged file beside this one is the only place the
// two ever meet.
type RemediatorFactory func(provider ai.Provider, sink ai.AuditSink) seams.Remediator

var remediatorFactory RemediatorFactory

// RegisterRemediator installs the generative remediator implementation. The
// ee-tagged init in this package is the only caller.
//
// Exported only because the registration has to happen from a file this one
// cannot see into; there is nothing for a service to do with it. Registering
// twice is a programming error and the second call wins loudly rather than
// silently, so a future second implementation cannot displace the first without
// someone noticing.
func RegisterRemediator(f RemediatorFactory) {
	if remediatorFactory != nil {
		log.Printf("[ai-edition] a remediator seam implementation was already registered; replacing it")
	}
	remediatorFactory = f
}

// RemediatorLinked reports whether this build has a generative remediator
// compiled in.
//
// Separate from [Linked], which answers the same question about the model
// clients, for the reason [QueryLinked] is separate: a build could in principle
// have the providers and not this seam, and a UI distinguishing "your edition
// does not include this" from "you have not configured a provider" needs both.
//
// It is also what the endpoint answers 402 on. A Core build has no remediator at
// all, and "this is not in your edition" is a different sentence from "this
// deployment has no model provider" — the first is a purchase, the second is ten
// minutes of an administrator's time.
func RemediatorLinked() bool { return remediatorFactory != nil }

// NewRemediator resolves the remediator seam this deployment runs, and describes
// it.
//
// AI_PROVIDER unset or "none" — which is almost every deployment — yields
// [seams.NullRemediator], whose Propose returns ai.ErrUnavailable. A Core build
// yields it too, whatever AI_PROVIDER says, because a Core build has neither the
// model clients nor this seam. An Enterprise build with a reachable provider
// yields the real one.
//
// It never returns nil and never fails. A misconfiguration degrades to the null
// seam with a log line naming what went wrong: a typo in AI_MODEL must not be
// able to take compliance-engine down, and must not be able to silently disable
// a capability an operator believes they turned on — which is what the returned
// Description is for. Its State distinguishes:
//
//	inactive                nothing configured, or this edition has no seam
//	configured_unavailable  configured, but no provider will answer
//	active                  it will answer
//
// sink receives the boundary's per-call audit records AND the seam's own
// per-finding record (ADR-0008 D4.7). Pass the same one; two would split a
// single question's trail across two rails.
func NewRemediator(sink ai.AuditSink) (seams.Remediator, seams.Description) {
	provider, err := ai.NewFromEnv()
	if err != nil {
		// Not fatal and not silent. NewFromEnv always hands back a usable
		// provider (NoneProvider here), so the only thing lost is the drafting
		// — the Findings page still shows the guidance, which is what the
		// drafting was going to sharpen.
		log.Printf("[ai-edition] AI provider not configured: %v — drafting remediation plans is unavailable", err)
	}
	provider = ai.Boundary(provider, sink)

	reg := seams.NewRegistry()
	want := ""
	if remediatorFactory != nil {
		if err := reg.RegisterRemediator(implRemediator, func() seams.Remediator {
			return remediatorFactory(provider, sink)
		}); err != nil {
			log.Printf("[ai-edition] registering %s failed: %v", implRemediator, err)
		} else if provider.Available() {
			// Registered unconditionally, SELECTED only when a provider will
			// answer. Registering conditionally would make "configured but
			// unreachable" indistinguishable from "not configured", which is
			// the one distinction the Description exists to draw.
			want = implRemediator
		}
	}

	set, err := reg.Configure(seams.Config{Remediator: want})
	if err != nil {
		// Configure always returns a usable Set with unresolved seams left
		// null, so this degrades to no drafting rather than to a nil interface.
		log.Printf("[ai-edition] seam configuration incomplete: %v", err)
	}

	desc := seams.Description{Seam: ai.SeamRemediator, Implementation: seams.ImplNone, State: seams.StateInactive, Family: seams.FamilyGenerative}
	for _, d := range seams.Describe(set, provider) {
		if d.Seam != ai.SeamRemediator {
			continue
		}
		desc = d
		log.Printf("[ai-edition] seam=%s implementation=%s state=%s provider=%s linked=%t",
			d.Seam, d.Implementation, d.State, provider.Name(), RemediatorLinked())
	}
	return set.Remediator, desc
}

// implRemediator is the implementation name the generative remediator registers
// under. Duplicated from shared/ai/ee/remediator's exported ImplModel by
// necessity — Core cannot import that package to read it — and
// TestRemediatorImplNameMatchesTheEnterpriseConstant pins the two together in
// the ee-tagged test, which is the build that can see both.
const implRemediator = "remediation-model"
