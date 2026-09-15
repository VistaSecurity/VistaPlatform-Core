package seams

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/ai"
)

// The catalogue is hand-maintained, so its completeness is what the compiler
// cannot check and a test must.

func TestCatalogue_CoversEverySeamExactlyOnce(t *testing.T) {
	rows := Catalogue()
	seen := map[ai.Seam]int{}
	for _, r := range rows {
		seen[r.Seam]++
	}
	for _, s := range ai.AllSeams() {
		switch seen[s] {
		case 1:
		case 0:
			t.Errorf("seam %q has no catalogue row; the settings page would show a blank where a capability is", s)
		default:
			t.Errorf("seam %q has %d catalogue rows", s, seen[s])
		}
	}
	if len(rows) != len(ai.AllSeams()) {
		t.Errorf("catalogue has %d rows for %d seams", len(rows), len(ai.AllSeams()))
	}
}

// Family and edition must agree with the registry's own table: a seam listed
// generative here and classical there would put it in the wrong half of the
// page and attach the wrong edition badge.
func TestCatalogue_AgreesWithTheSeamTable(t *testing.T) {
	families := map[ai.Seam]string{}
	for _, sl := range seamSlots {
		families[sl.seam] = sl.family
	}
	for _, r := range Catalogue() {
		if want := families[r.Seam]; r.Family != want {
			t.Errorf("seam %q: catalogue family %q, seam table %q", r.Seam, r.Family, want)
		}
		wantEdition := EditionCore
		if r.Family == FamilyGenerative {
			wantEdition = EditionEnterprise
		}
		if r.EditionRequired != wantEdition {
			t.Errorf("seam %q: edition %q, want %q for a %s seam "+
				"(if this is a deliberate edition move, change the assertion with the row)",
				r.Seam, r.EditionRequired, wantEdition, r.Family)
		}
	}
}

// Every seam has a rule default, and saying so is the product's central claim.
// A blank one renders as "you lose this capability without AI", which is the
// opposite of what ADR-0008 promises.
func TestCatalogue_EverySeamStatesItsRuleDefault(t *testing.T) {
	for _, r := range Catalogue() {
		if strings.TrimSpace(r.RuleDefault) == "" {
			t.Errorf("seam %q states no rule default", r.Seam)
		}
		if r.Shipped && strings.TrimSpace(r.Surface) == "" {
			t.Errorf("seam %q is marked shipped but names no surface a user meets it on", r.Seam)
		}
		if !r.Shipped && strings.TrimSpace(r.Surface) != "" {
			t.Errorf("seam %q names surface %q but is not marked shipped", r.Seam, r.Surface)
		}
	}
}

// A CLASSICAL seam whose [Default] implementation is not the null one is
// running in every deployment — Core included, with no provider and no network
// — so its catalogue row has to say it shipped and name where a user meets it.
//
// # Why this guard exists, and why it is one-directional
//
// `Shipped` is hand-maintained, and the catalogue's own note says so: the
// implementations and their consumers live in other packages and other
// services, so nothing in the compiler knows. For the GENERATIVE seams that is
// unavoidable and `shared/ai/edition`'s ee-tagged tests are as close as anything
// gets. For the classical ones it is avoidable, because their default
// implementation is resolved right here — and it went wrong exactly as the note
// predicts: the matcher's default became the learned logistic scorer in
// workstream 4.6, its consumers landed with it (merge-candidate ranking, and
// the model id named on Settings → Identification rules), and this row still
// said `Shipped: false`. Settings → AI assistant rendered "Not yet built" for a
// model that was scoring on every install.
//
// One direction only. "Not the null default ⇒ shipped" is sound: a classical
// default runs everywhere, so if it has no consumer that is an orphaned layer,
// not a catalogue error. The converse is not: a classical seam could ship an
// implementation an operator opts into by name, leaving the default null, and
// demanding `Shipped: false` there would force an under-claim.
func TestCatalogue_AClassicalSeamRunningByDefaultIsMarkedShipped(t *testing.T) {
	rows := map[ai.Seam]SeamInfo{}
	for _, r := range Catalogue() {
		rows[r.Seam] = r
	}

	var checked int
	for _, sl := range seamSlots {
		if sl.family != FamilyClassical || sl.defaultImpl == ImplNone {
			continue
		}
		checked++
		row := rows[sl.seam]
		if !row.Shipped {
			t.Errorf("seam %q defaults to %q — it runs in every deployment — but its catalogue row says it has not shipped; "+
				"Settings → AI assistant renders that as \"Not yet built\"", sl.seam, sl.defaultImpl)
		}
		if strings.TrimSpace(row.Surface) == "" {
			t.Errorf("seam %q defaults to %q but names no surface", sl.seam, sl.defaultImpl)
		}
	}

	// The guard's own polarity. If every classical seam's default were null
	// this test would pass by examining nothing, which is the failure mode it
	// was written against.
	if checked == 0 {
		t.Fatal("no classical seam has a non-null default; this guard examined nothing and proves nothing")
	}
}
