// Package sbom parses CycloneDX and SPDX bills of materials into the
// normalised software model in
// [github.com/vistasecurity/vistaplatform/shared/software].
//
// ADR-0004 D3 makes SBOM ingestion the first software-inventory source: a
// customer already has these documents, they are produced by build systems
// rather than by us, and accepting them turns CycloneDX from an output format
// into an input one. This package is workstream 2.6a, the parser library
// alone. The upload endpoint, the Discovery → Sources page and the asset
// Software tab are 2.6b and live on the phase-1 integration branch; nothing
// here talks to a database, a tenant or an asset.
//
// # What it accepts
//
//   - CycloneDX JSON, spec versions 1.4 through 1.7, detected by `bomFormat`
//     and `specVersion`.
//   - SPDX JSON, versions SPDX-2.2 and SPDX-2.3, detected by `spdxVersion`.
//
// XML is out of scope for both formats and is refused with a clear error
// rather than mis-parsed. CycloneDX XML is a second grammar with its own
// nesting rules, SPDX's tag-value and RDF forms are two more, and JSON is what
// every producer we have seen emits by default. [ErrUnsupportedEncoding] names
// the refusal so a caller can tell a user "convert it to JSON" rather than
// "your file is broken".
//
// SPDX 3.0 is also refused by name. It is not a revision of the 2.x JSON
// shape; it is a different JSON-LD model with a different element vocabulary,
// and parsing it on the 2.x shape would produce a document that looks parsed
// and is empty.
//
// # What it deliberately drops
//
//   - Cryptographic components. A CycloneDX CBOM carries algorithms,
//     certificates, keys and protocols under `cryptoProperties`; those belong
//     to the CBOM path, which has its own model and its own catalogue lookup,
//     and pulling them into `software_products` would put an algorithm in the
//     software catalogue. They are skipped with a counted warning, so a user
//     who uploads a CBOM here is told what happened instead of seeing an empty
//     result. Our OWN generated CBOM is such a document, and
//     TestParseVistaCBOMOutput parses it to prove the skip is a skip and not a
//     failure.
//   - Component descriptions, properties, external references, hashes,
//     evidence, and everything else `software_products` has no column for. A
//     parser that returned fields nobody stores is a parser whose output has
//     to be re-read to find out what it means.
//   - SPDX `files[]`. They are files, not products; a mid-size SPDX document
//     has tens of thousands of them and none of them is a catalogue row. One
//     counted warning says how many were passed over.
//
// # Never a panic, never a secret
//
// An SBOM arrives by upload. It is untrusted input in the same sense a captured
// frame is, and the contract is the same one shared/hostobs keeps:
//
//   - A malformed component, licence entry, dependency edge or relationship is
//     SKIPPED with a warning. One bad entry never fails a document, and no
//     input shape panics — [FuzzParse] is the standing proof.
//   - Two caps refuse a document rather than let it exhaust the process:
//     [MaxDocumentBytes] and [MaxComponents], both reported as a [*LimitError].
//     Nesting depth is bounded separately ([maxNestingDepth]); a document
//     nested a million deep is the cheapest way to turn a recursive parser
//     into a stack overflow, which is a crash no error return catches.
//   - [github.com/vistasecurity/vistaplatform/shared/redact.TextPEM] runs over
//     every string in the returned document, warnings included. SBOM free-text
//     fields — a component description, an SPDX supplier, a version string
//     someone pasted into — have carried PEM private keys in the wild, and a
//     warning that quotes an offending field would otherwise copy one straight
//     back out. CLAUDE.md: collect posture, never key material.
package sbom
