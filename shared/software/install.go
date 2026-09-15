package software

import "strings"

// Source kinds: the ADR-0005 provenance vocabulary, and the values
// `software_installs.source_kind` and `software_products.source_kind` accept.
//
// They are spelled here as plain strings rather than imported from
// shared/identity.SourceKind so that this package keeps no third-party
// dependencies — it is bound for the device-agent's host collector, which
// cross-compiles with CGO_ENABLED=0 and must not acquire the identity engine's
// dependencies. (The package's one non-stdlib import is shared/query/ast, for
// [Product.VersionSort]; that package is itself stdlib-only.)
// TestSourceKindsMatchIdentity imports identity from the TEST binary and fails
// if the two vocabularies ever drift, so the copy cannot rot quietly.
const (
	// SourceMeasured: the platform observed the install itself — the host
	// agent reading a package database, an authenticated interrogation.
	SourceMeasured = "measured"
	// SourceDeclared: a person stated it.
	SourceDeclared = "declared"
	// SourceImported: another system of record supplied it. An uploaded SBOM
	// is this one — the document is a build system's claim about what it put
	// in an artefact, not something we measured on the running host.
	SourceImported = "imported"
	// SourceInferred: a model proposed it.
	SourceInferred = "inferred"
)

// ValidSourceKind reports whether s is one of the four provenance values.
func ValidSourceKind(s string) bool {
	switch s {
	case SourceMeasured, SourceDeclared, SourceImported, SourceInferred:
		return true
	default:
		return false
	}
}

// Install is one row of `software_installs`: a [Product] present on an asset.
//
// The asset is deliberately absent. A parser produces installs from a document
// that has no idea which asset it will be attached to; binding them to an
// asset is the ingesting service's job (workstream 2.6b), and a field here
// would only invite a producer to guess.
type Install struct {
	// Product is the product's IDENTITY — the string [Product.Identity]
	// returns, which is exactly what the `software_products` unique index is
	// keyed on. It is an identity rather than an embedded Product because that
	// is the seam the writer needs: it upserts the catalogue row, resolves the
	// identity to a `product_id`, and writes the install against the id. An
	// embedded copy would let the two drift within a single ingest.
	Product string
	// Path is the filesystem location, where the source knows one. Most
	// sources do not: an SBOM component has no install path, and the unique
	// index coalesces NULL to '' precisely so that repeated observations of a
	// pathless install converge on one row instead of appending forever.
	Path string
	// Source is the provenance — one of the four values above. It maps to
	// `software_installs.source_kind`, which has a CHECK constraint, so a
	// value outside the vocabulary fails the INSERT rather than being stored.
	Source string
	// SourceRef names the specific thing that produced this observation: the
	// SBOM document's serial number, the agent job id, the CMDB sync id. It is
	// what makes a re-ingest of the same document idempotent and what a
	// support question ("where did this come from?") is answered from.
	SourceRef string
}

// Valid reports whether the install can be written: it needs a product
// identity and a source kind the CHECK constraint will accept.
func (i Install) Valid() bool {
	return strings.TrimSpace(i.Product) != "" && ValidSourceKind(i.Source)
}
