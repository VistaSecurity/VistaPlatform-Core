package software

// Lifecycle assessments: what the `eol` finding producer concluded for ONE
// software install, as recorded on `software_install_lifecycle`.
//
// A finding says "this is a problem". Its absence used to say one of four
// things — the lifecycle catalogue has no entry for the product, its entry
// publishes no date, the date is further out than the warning window, or the
// install is not active and was skipped — and nothing on the install said
// which. The record is the producer's own conclusion, written beside its
// findings; a reader takes the word off the row rather than re-running the
// resolution, which would be a second opinion about what the catalogue says.
//
// The vocabulary is here, in the dependency-free package both the producer
// (through shared/software/postgres) and the list endpoints import, so the two
// cannot drift: the writer refuses any other word, the schema's CHECK lists
// exactly these, and a test pins the CHECK against [LifecycleAssessments].
const (
	// LifecycleSupported: a catalogue row matched, and its end-of-life date is
	// further out than the producer's warning window. The one reassuring
	// answer, and the one that used to get no credit.
	LifecycleSupported = "supported"
	// LifecycleEndOfLife: a catalogue row matched, and its date is inside the
	// warning window or past. The `software_end_of_life` finding is written in
	// the same transaction, so this row and that finding agree by construction.
	LifecycleEndOfLife = "end_of_life"
	// LifecycleNoDate: a catalogue row matched and publishes no date.
	// endoflife.date says `true` for "support has ended, date unknown" and
	// `false` for "not announced", and the mirror stores both as NULL rather
	// than inventing a date — so there is nothing to judge, and neither
	// "supported" nor "end of life" can honestly be claimed.
	LifecycleNoDate = "no_date"
	// LifecycleNotInCatalogue: the catalogue was asked and had nothing. A
	// recorded miss, which is a different problem from `no_date` with a
	// different fix — this one belongs on the catalogue's gap list.
	LifecycleNotInCatalogue = "not_in_catalogue"
)

// LifecycleAssessments is every value the column accepts, in the order the
// schema's CHECK lists them.
var LifecycleAssessments = []string{
	LifecycleSupported,
	LifecycleEndOfLife,
	LifecycleNoDate,
	LifecycleNotInCatalogue,
}

// LifecycleAssessmentKnown reports whether s is one of the four words.
func LifecycleAssessmentKnown(s string) bool {
	for _, a := range LifecycleAssessments {
		if a == s {
			return true
		}
	}
	return false
}
