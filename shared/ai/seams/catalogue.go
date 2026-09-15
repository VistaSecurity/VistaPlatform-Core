package seams

import (
	"sort"

	"github.com/vistasecurity/vistaplatform/shared/ai"
)

// The catalogue: what each seam IS, in the terms a tenant administrator looking
// at Settings → AI assistant needs.
//
// [Describe] answers a different question — what is configured in THIS process
// — and it can only answer it for the seams the calling service itself wired.
// The settings page is on the tenant plane and asks about the deployment: it
// has to be able to say "the narrator is an Enterprise capability, it summarises
// a CBOM comparison, and without it you get the rule-written summary" whether or
// not the service answering the request is the one that owns the narrator.
//
// # This is a hand-maintained fact and that is a hazard
//
// `Shipped` says whether an implementation a USER CAN REACH exists in the
// product today: an implementation AND a consumer that puts it in front of
// somebody. Both halves, because this table feeds a page that answers "can I
// use this", and an implementation nothing calls is not a capability — it is a
// package. The query seam was `false` here for exactly one gate on that rule,
// while `shared/ai/ee/query` existed and `edition/query_ee.go` registered it
// with nothing calling it; 4.4b landed the consumers and flipped it.
//
// Nothing in the compiler knows either half — the implementations live in three
// different services' ee/ trees and in shared/ai/ee, and their consumers live in
// the services' routers — so it is a claim this table makes, and a claim can go
// stale. The monitoring service's hand-maintained peer list is the same shape
// and went wrong exactly that way. So did the MATCHER row, which said
// `Shipped: false` from workstream 4.6 until Gate 4, while the learned scorer
// was the seam's default in every deployment and two consumers were rendering
// it.
//
// Four things keep it honest, and none is optional:
//
//   - [Catalogue] is walked against [ai.AllSeams] by a test, so a ninth seam
//     cannot be added without a row here.
//   - `Shipped` and `Surface` are pinned to each other by a test, in both
//     directions. `Surface` IS the consumer, named, so a row cannot claim to
//     have shipped without saying where a user meets it.
//   - Every CLASSICAL seam whose [Default] implementation is not the null one is
//     required to be marked shipped, by a test in this package. Their defaults
//     resolve here, so unlike the generative ones this half needs no faith: a
//     classical default runs in every deployment, and a row that denies it is
//     simply false. (One direction only — see the test for why.)
//   - For the one GENERATIVE seam whose registration Core can observe — the
//     query seam, through `edition.QueryLinked()` — an ee-tagged test in
//     shared/ai/edition holds this row against it, so landing 4.4b's consumer
//     without flipping the row went red rather than under-claiming forever.
//
// Where none of those can reach — which now means the generative seams other
// than the query one — `Shipped: false` is the direction to be wrong in. A seam
// that has shipped but is listed false under-claims a capability, which a user
// notices and reports. The reverse tells them a capability is live when nothing
// implements it, which is this repository's oldest bug shape.
//
// When you land a seam implementation AND its consumer, flip its row and name
// its surface. AI_SEAMS.md §13 says so too, in the place someone landing one is
// reading.

// SeamInfo is one row: what the seam does, where a user meets it, and what
// happens when no model is configured.
type SeamInfo struct {
	Seam ai.Seam `json:"key"`

	// Family is "classical" or "generative" (ADR-0008 D2) — the distinction an
	// operator cares about, because only the generative ones send anything
	// anywhere.
	Family string `json:"family"`

	// EditionRequired is "core" or "enterprise": which edition has an
	// implementation of this seam at all. It follows Family today (the
	// classical seams run in-process and ship in Core; the generative ones
	// reach a model through shared/ai/ee/providers, which Core does not have)
	// but it is stated per row rather than derived, because it is an edition
	// decision and edition decisions move.
	EditionRequired string `json:"edition_required"`

	// Shipped reports whether an implementation a user can REACH exists in the
	// product today — an implementation and a consumer, both. See the hazard
	// note above; `Surface` is the consumer named, and a test holds the two
	// together in both directions.
	Shipped bool `json:"shipped"`

	// Surface is where a user meets this seam, empty when nothing consumes it
	// yet. Short enough to sit in a table cell.
	Surface string `json:"surface,omitempty"`

	// RuleDefault is what answers when no model does — the ADR-0008 promise
	// made concrete, per seam. Never empty: every seam has one, even if it is
	// "nothing is proposed", and a blank here would read as "you lose this
	// capability", which is the claim the whole design exists to avoid.
	RuleDefault string `json:"rule_default"`
}

// Editions a seam's implementation can belong to.
const (
	EditionCore       = "core"
	EditionEnterprise = "enterprise"
)

// catalogue is the table. One row per seam in [ai.AllSeams], same order.
var catalogue = []SeamInfo{
	{
		// SHIPPED with workstream 4.6. The implementation is [ImplLearned] —
		// the logistic scorer of shared/identity/matcher, with its weights
		// embedded in the binary — and it is the seam's DEFAULT, so it is
		// running in every deployment, Core included, with no provider and no
		// network anywhere near it.
		//
		// Its two consumers are what make it reachable: shared/identity's
		// engine asks it to RANK the candidates of a merge conflict (highest
		// first, each with a reason), and inventory-service hands
		// `MatcherModelID` to Settings → Identification rules so the page can
		// name the model the auto-accept threshold is a threshold ON. The
		// settings page is named as the surface because it is where the model
		// is visible AS a model; the ranking is where the score is used.
		//
		// It was `false` here until Gate 4 checked it, which is the failure mode
		// the note above predicts: Settings → AI assistant rendered the matcher
		// as "Not yet built" on every install, in the one place whose entire job
		// is to say what is turned on. The direction is the safe one — an
		// under-claim gets reported by a user rather than trusted by one — but
		// it is still a false sentence, and 4.6 landing its consumer without
		// flipping this row is exactly what §13 warns about.
		//
		// What it does NOT change: the matcher ranks, it never decides. The
		// auto-accept threshold defaults to zero, meaning never (ADR-0002 D5).
		Seam: ai.SeamMatcher, Family: FamilyClassical, EditionRequired: EditionCore,
		Shipped: true, Surface: "Merge candidates in Approvals; the threshold in Settings → Identification rules",
		RuleDefault: "Assets are matched by the identifier precedence order in Settings → Identification rules.",
	},
	{
		Seam: ai.SeamClassifier, Family: FamilyClassical, EditionRequired: EditionCore,
		Shipped: true, Surface: "Asset classification",
		RuleDefault: "The curated classification rules decide the class, and record \"unknown\" when none matches.",
	},
	{
		// The `drift` FINDING PRODUCER (workstream 4.7) is not this seam's
		// implementation and is not registered against it — it writes
		// deterministic findings from SQL, where a DriftDetector proposes
		// scored anomalies onto the alert rail. It is the deterministic path
		// this package's doc comment describes as living "in the services that
		// own that data", and it keeps running whether or not a seam is ever
		// configured. Named here because this string is what the admin console
		// shows as the answer a deployment with no model gets.
		Seam: ai.SeamDriftDetector, Family: FamilyClassical, EditionRequired: EditionCore,
		Shipped: false,
		RuleDefault: "The rule-based drift producer compares each asset against the tenant's own recent baseline — a class new to a segment, " +
			"a protocol or listening port new to a host, a certificate issuer new to it — and the existing detectors (new asset, " +
			"certificate expiry, stale asset) keep running beside it.",
	},
	{
		Seam: ai.SeamEnricher, Family: FamilyGenerative, EditionRequired: EditionEnterprise,
		Shipped: true, Surface: "End-of-life catalogue proposals",
		RuleDefault: "The end-of-life catalogue is looked up directly, and anything it does not cover is counted on the gap list.",
	},
	{
		Seam: ai.SeamNarrator, Family: FamilyGenerative, EditionRequired: EditionEnterprise,
		Shipped: true, Surface: "CBOM comparison summary",
		RuleDefault: "The comparison summary is written from the rows themselves, with the same citations.",
	},
	{
		// SHIPPED with build-plan 4.4b. The implementation is
		// shared/ai/ee/query; the consumers that make it reachable are
		// inventory-service's `POST /ask`, the command palette's ask mode
		// (⌘K), and the `vistaplatform_ask` MCP tool. The palette is named
		// here because it is where a PERSON meets it — the other two are how,
		// not where.
		Seam: ai.SeamQuery, Family: FamilyGenerative, EditionRequired: EditionEnterprise,
		Shipped: true, Surface: "Ask in the command palette (⌘K)",
		RuleDefault: "Inventory is searched with the query language directly, from the search bar and saved views.",
	},
	{
		Seam: ai.SeamAuthor, Family: FamilyGenerative, EditionRequired: EditionEnterprise,
		Shipped: true, Surface: "Draft controls from a standard",
		RuleDefault: "Controls and measurement rules are written by hand, which is how every published framework was written.",
	},
	{
		Seam: ai.SeamRemediator, Family: FamilyGenerative, EditionRequired: EditionEnterprise,
		Shipped: true, Surface: "Draft a remediation plan on a finding",
		RuleDefault: "Every finding carries the remediation guidance for its kind, and a plan is written by hand from it.",
	},
}

// Catalogue returns the descriptive row for every seam, sorted by seam name so
// the output is stable. It is a copy: a caller cannot edit the table.
func Catalogue() []SeamInfo {
	out := append([]SeamInfo(nil), catalogue...)
	sort.Slice(out, func(i, j int) bool { return out[i].Seam < out[j].Seam })
	return out
}
