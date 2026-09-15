package catalogs

import "time"

// Product kinds, mirroring the CHECK on eol_catalogue.product_kind and on
// catalog_lookup_misses.product_kind.
const (
	KindOS       = "os"
	KindSoftware = "software"
	KindHardware = "hardware"
)

// ValidKind reports whether k is one of the three catalogue product kinds.
func ValidKind(k string) bool {
	switch k {
	case KindOS, KindSoftware, KindHardware:
		return true
	}
	return false
}

// EOLRow is one `eol_catalogue` row as the lookup reads it.
//
// A narrower view than catalogfeeds.EOLEntry: a caller needs the identity, the
// dates and the citation, and nothing else. Keeping it separate is what lets
// this package be tested against an in-memory store with no feed machinery
// anywhere near it.
type EOLRow struct {
	ID                  string
	ProductKind         string
	Vendor              string
	Product             string
	Cycle               string
	ReleaseDate         *time.Time
	EOLDate             *time.Time
	ExtendedSupportDate *time.Time
	SourceURL           string
}

// EOLLookup is the question put to the catalogue.
//
// Kind empty means "any of the three" — the fact key the enricher emits is
// derived from the kind of the row that MATCHED, not from a guess made before
// looking. Vendor empty means the caller does not know one, which is different
// from the caller knowing there is none; see matchesVendor.
type EOLLookup struct {
	Kind    string
	Vendor  string
	Product string
}

// MissSubject is one lookup that resolved nothing, as recorded on the gap list.
type MissSubject struct {
	Kind    string
	Vendor  string
	Product string
	Version string
}
