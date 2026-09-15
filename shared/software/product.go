package software

import (
	"strings"
	"unicode/utf8"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"
)

// Product is one row of the tenant software catalogue (`software_products`,
// DATA_MODEL §4): a named piece of software at a version, with whatever
// machine identifiers the source supplied.
//
// It carries no tenant and no id. Both are the writer's business — a parser
// produces products long before anything has decided which asset or which
// tenant they attach to.
type Product struct {
	// Name is the product name. `software_products.name` is NOT NULL, so a
	// product with no name cannot be written; producers drop such an entry
	// rather than inventing a name for it.
	Name string
	// Vendor is the publishing organisation, where the source names one.
	Vendor string
	// Version is the version string exactly as the source wrote it, kept raw
	// for display. Ordering uses [Product.VersionSort], never this field.
	Version string
	// PURL is a Package URL (https://github.com/package-url/purl-spec) in
	// canonical form. The strongest of the three identity forms and the first
	// the identity rule reaches for.
	PURL string
	// CPE is a CPE 2.3 formatted string. Weaker than a purl — it names a
	// product line rather than an artefact — but it is what a vulnerability
	// feed matches on, which is why both are kept rather than one.
	CPE string
	// LicenseID is an SPDX licence identifier ("Apache-2.0"), or an SPDX
	// licence EXPRESSION verbatim ("MIT OR Apache-2.0") when the source gave
	// an expression instead of a single id. The column is text and holds
	// either; a consumer that needs a single id must be prepared for an
	// expression, because collapsing one into "the first id" would assert a
	// licence the document never claimed.
	LicenseID string
}

// Identity is the dedupe key: the Go side of the `software_products` unique
// index,
//
//	coalesce(purl, cpe, name || '@' || coalesce(version, ''))
//
// It normalises first, so the identity a caller computes is the identity the
// row will be keyed on. Without that, a product whose CPE fails validation
// would be keyed on the bad CPE here and on `name@version` in the database —
// two different answers for one product, which is how duplicate catalogue rows
// appear. [Product.Normalize] is idempotent, so calling Identity on an
// already-normalised product costs a little work and changes nothing.
//
// An unversioned product returns `name@`, never "". See the package doc: the
// empty string is the failure mode the inner coalesce exists to prevent.
//
// # The writer's half of the contract
//
// An absent purl, cpe or version must be written to the row as NULL, never as
// the empty string. `coalesce` skips NULL and takes an empty string as a
// VALUE, so a row whose purl is empty keys on the empty string — and every
// purl-less product in the tenant then collides onto that single key, while
// this function hands back a distinct name@version for each of them. Nothing
// on the Go side can observe a writer breaking that,
// which is why TestIdentityWriterMustStoreNULLNotEmpty states it with the
// demonstration attached, and TestIdentityMatchesTheSQLUniqueExpression checks
// the two sides agree once it is kept.
func (p Product) Identity() string {
	n, _ := p.Normalize()
	switch {
	case n.PURL != "":
		return n.PURL
	case n.CPE != "":
		return n.CPE
	default:
		return n.Name + "@" + n.Version
	}
}

// VersionSort returns the normalised component-wise sort key for
// `software_products.version_sort`, and ok=false when the version string
// carries no numeric component at all.
//
// It is a one-line delegation to [ast.VersionSortKey] deliberately. That
// function is the DEFINITION of the column (QUERY_LANGUAGE §5.5) and of the
// `version < 3.0` translation; a second implementation here would mean the
// writer normalises one way and the query translator compares another, and the
// predicate would quietly return the wrong rows rather than fail. There is
// exactly one of it, and this is a call to it.
//
// ok=false means the column is NULL, which makes every version comparison
// against this product evaluate UNKNOWN. That is the intended behaviour and
// not a gap to paper over: §5.5 forbids a lexical fallback, because "1.10"
// sorts before "1.9" as text and that inverts every predicate built on it.
func (p Product) VersionSort() (string, bool) {
	return ast.VersionSortKey(strings.TrimSpace(p.Version))
}

// Normalize returns a normalised copy of p, plus a note for every field it had
// to drop.
//
// What it does:
//
//   - Trims surrounding whitespace from every field.
//   - Canonicalises PURL (see [NormalizePURL]): lowercases the scheme and
//     type always, lowercases the namespace for the types whose purl-spec
//     rules say so, lowercases and sorts qualifier keys.
//   - Validates CPE as a CPE 2.3 formatted string, converting a CPE 2.2 URI
//     (`cpe:/a:vendor:product:version`) into one first (see [NormalizeCPE]).
//
// Notes rather than silence. A purl or CPE that does not parse is DROPPED —
// keeping it would key the catalogue on a string no vulnerability feed can
// match — and a dropped identifier that nobody is told about is exactly the
// "reports success while doing nothing" shape this codebase keeps paying for.
// The returned slice names each drop so the caller can surface it; the SBOM
// parser turns them into document warnings.
//
// The notes are diagnostic text, never a reason to reject the product: a
// component with a malformed CPE is still a real piece of software, and
// refusing it would lose the inventory to protect a field.
func (p Product) Normalize() (Product, []string) {
	var notes []string

	out := Product{
		Name:      strings.TrimSpace(p.Name),
		Vendor:    strings.TrimSpace(p.Vendor),
		Version:   strings.TrimSpace(p.Version),
		LicenseID: strings.TrimSpace(p.LicenseID),
	}

	if raw := strings.TrimSpace(p.PURL); raw != "" {
		canonical, err := NormalizePURL(raw)
		if err != nil {
			notes = append(notes, "dropped unparseable purl "+quote(raw)+": "+err.Error())
		} else {
			out.PURL = canonical
		}
	}

	if raw := strings.TrimSpace(p.CPE); raw != "" {
		canonical, err := NormalizeCPE(raw)
		if err != nil {
			notes = append(notes, "dropped unparseable cpe "+quote(raw)+": "+err.Error())
		} else {
			out.CPE = canonical
		}
	}

	return out, notes
}

// Identifiable reports whether the product can be written at all: it needs a
// name, because `software_products.name` is NOT NULL and a nameless row is
// unidentifiable to a human regardless of what machine identifiers it carries.
func (p Product) Identifiable() bool {
	return strings.TrimSpace(p.Name) != ""
}

// quote wraps a value for a diagnostic message without dragging fmt's
// reflection in for a single %q.
//
// The value is attacker-supplied: it is the purl or CPE string an uploaded
// SBOM carried, echoed back so the note names what was dropped. Two things
// follow, and both are the rule [describeByte] already applies one byte at a
// time:
//
//   - Control characters are dropped. A note is rendered in a terminal and in
//     a browser, and an ANSI escape sequence pasted into a component's purl
//     would otherwise be handed to whichever one displays the warning.
//   - Truncation is on a rune boundary. Cutting at a byte offset leaves an
//     invalid UTF-8 fragment, which serialises as a replacement character and
//     makes the quoted value unreadable at the point it matters most.
func quote(s string) string {
	const max = 120
	// Map first: it can only shorten, and it folds any invalid UTF-8 in the
	// input into replacement characters, so the truncation below is working on
	// well-formed text.
	s = strings.Map(printableOnly, s)
	if len(s) > max {
		s = truncateRunes(s, max) + "…"
	}
	return `"` + s + `"`
}

// printableOnly drops control characters. It is spelled here rather than
// shared with shared/sbom's identical helper because this package cannot
// import that one — sbom imports software — and a five-line rule is a better
// duplicate than an import cycle.
func printableOnly(r rune) rune {
	if r < 0x20 || r == 0x7f {
		return -1
	}
	return r
}

// truncateRunes cuts s to at most max bytes, backing up to the start of the
// rune that straddles the limit rather than splitting it.
func truncateRunes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	for max > 0 && !utf8.RuneStart(s[max]) {
		max--
	}
	return s[:max]
}
