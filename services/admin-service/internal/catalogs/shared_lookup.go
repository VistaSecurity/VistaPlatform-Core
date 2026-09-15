package catalogs

// The catalogue LOOKUP moved to shared/catalogs in workstream 3.3 part 2, and
// these are the names it left behind.
//
// # Why it moved
//
// The `eol` finding producer lives in inventory-service and has to resolve the
// same vendor/product/version subjects against the same `eol_catalogue` rows
// this console curates. Three arrangements were possible: an HTTP hop from
// inventory-service into admin-service, a second implementation of the matching
// rules, or one package both import. The first puts a service boundary inside a
// per-asset loop and makes a producer's answer depend on another deployment
// being up; the second is the fork this repository has paid for twice (the
// sensor and cluster-sensor-service, the device-agent and
// device-interrogation-service). So the lookup is shared and this package keeps
// the console: the proposal queue, the gap pass, citation validation, review.
//
// # Why aliases rather than a rename at every call site
//
// `catalogs.EOLRow` is in this package's handler signatures, its store
// integration test and `ee/enrich`. Aliasing keeps that surface identical, so
// the move is reviewable as a move — a diff that also renamed forty references
// would hide whether anything else changed with them. These are true type
// aliases, not wrappers: `catalogs.EOLRow` and `sharedcatalogs.EOLRow` are the
// same type and a value of one is a value of the other.

import (
	sharedcatalogs "github.com/vistasecurity/vistaplatform/shared/catalogs"
)

// Product kinds, mirroring the CHECK on eol_catalogue.product_kind.
const (
	KindOS       = sharedcatalogs.KindOS
	KindSoftware = sharedcatalogs.KindSoftware
	KindHardware = sharedcatalogs.KindHardware
)

// MaxSubjectField bounds one field of a recorded gap. Re-exported because
// `ee/enrich` clips a subject to the same bound before it reaches a prompt.
const MaxSubjectField = sharedcatalogs.MaxSubjectField

// The lookup's types and its enricher, in their original spellings.
type (
	// EOLRow is one `eol_catalogue` row as the lookup reads it.
	EOLRow = sharedcatalogs.EOLRow
	// EOLLookup is the question put to the catalogue.
	EOLLookup = sharedcatalogs.EOLLookup
	// MissSubject is one lookup that resolved nothing.
	MissSubject = sharedcatalogs.MissSubject
	// LookupStore is every database touch the lookup enricher makes.
	LookupStore = sharedcatalogs.LookupStore
	// LookupEnricher is the Core seams.Enricher.
	LookupEnricher = sharedcatalogs.LookupEnricher
	// LookupResult is the whole answer to "what does the platform know about
	// this product".
	LookupResult = sharedcatalogs.LookupResult
	// Resolution is the catalogue row that answers a subject, or nothing.
	Resolution = sharedcatalogs.Resolution
)

// ImplLookup is the implementation name the rule/lookup enricher registers
// under.
const ImplLookup = sharedcatalogs.ImplLookup

// NewLookupEnricher builds the rule/lookup enricher over store.
func NewLookupEnricher(store LookupStore) *LookupEnricher {
	return sharedcatalogs.NewLookupEnricher(store)
}

// ValidKind reports whether k is one of the three catalogue product kinds.
func ValidKind(k string) bool { return sharedcatalogs.ValidKind(k) }

// Normalize is the case/whitespace fold used on every side of every comparison
// the lookup makes. Exported for the store's SQL predicates and the tests that
// pin them.
func Normalize(s string) string { return sharedcatalogs.Normalize(s) }
