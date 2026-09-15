package sbom

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/software"
)

// spdxPurposeToType maps SPDX 2.3's `primaryPackagePurpose` onto the CycloneDX
// component-type vocabulary, so [Component.Type] means the same thing whichever
// format the document arrived in.
//
// SOURCE, ARCHIVE, INSTALL and OTHER have no CycloneDX equivalent and map to
// "" rather than being forced into "file" or "library" — a wrong type is worse
// than an absent one, because a consumer cannot tell it was a guess.
var spdxPurposeToType = map[string]string{
	"APPLICATION":      "application",
	"FRAMEWORK":        "framework",
	"LIBRARY":          "library",
	"CONTAINER":        "container",
	"OPERATING_SYSTEM": "operating-system",
	"DEVICE":           "device",
	"FIRMWARE":         "firmware",
	"FILE":             "file",
}

// spdxNoAssertion are the two SPDX sentinels that mean "this field has no
// value". Storing either verbatim would put the literal string "NOASSERTION"
// in a vendor or licence column, where every consumer downstream would read it
// as a vendor named NOASSERTION.
//
// NONE is included alongside NOASSERTION for `licenseConcluded` specifically:
// they mean different things to a lawyer ("we did not look" versus "there is
// no licence") but neither is an SPDX licence identifier, and
// `software_products.license_id` is an identifier column.
var spdxNoAssertion = map[string]bool{
	"NOASSERTION": true,
	"NONE":        true,
}

func parseSPDX(data []byte, spec string) (*Document, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, errWrap(ErrMalformed, err.Error())
	}

	doc := &Document{
		Format:      FormatSPDX,
		SpecVersion: spec,
		// SPDX has no serial number. `documentNamespace` is the closest
		// equivalent: the spec requires it to be unique to this document, and
		// it is what a re-ingest is deduped on.
		Serial: strField(top, "documentNamespace"),
	}
	var warn warnings

	packages := arrField(top, "packages")
	if len(packages) > MaxComponents {
		return nil, &LimitError{Limit: "components", Max: MaxComponents, Got: len(packages)}
	}

	var unnamed, unreadable, noAssertionLicense, documentLocalLicense int
	// byRef lets the relationship pass resolve an SPDXID to the component it
	// names without a second scan.
	byRef := make(map[string]int, len(packages))

	for _, raw := range packages {
		obj, ok := asObject(raw)
		if !ok {
			unreadable++
			continue
		}
		c, kept, drop := convertSPDXPackage(obj, &warn)
		switch drop {
		case licenceNoAssertion:
			noAssertionLicense++
		case licenceDocumentLocal:
			documentLocalLicense++
		case licenceKept:
		}
		if !kept {
			unnamed++
			continue
		}
		if len(doc.Components) >= MaxComponents {
			return nil, &LimitError{Limit: "components", Max: MaxComponents, Got: -1}
		}
		if c.BOMRef != "" {
			byRef[c.BOMRef] = len(doc.Components)
		}
		doc.Components = append(doc.Components, c)
	}

	warn.addCount(unreadable,
		"package skipped: not a JSON object",
		"packages skipped: not a JSON object")
	warn.addCount(unnamed,
		"package skipped: no name (software_products.name is NOT NULL)",
		"packages skipped: no name (software_products.name is NOT NULL)")
	warn.addCount(noAssertionLicense,
		"package licence dropped: licenseConcluded was NOASSERTION or NONE",
		"package licences dropped: licenseConcluded was NOASSERTION or NONE")
	warn.addCount(documentLocalLicense,
		"package licence dropped: licenseConcluded was a document-local LicenseRef-, "+
			"which names nothing outside the document it came from",
		"package licences dropped: licenseConcluded was a document-local LicenseRef-, "+
			"which names nothing outside the document it came from")

	// `files[]` are files, not products. A mid-size SPDX document has tens of
	// thousands of them and none is a catalogue row; the count is reported so
	// a user comparing our component count to their file count sees why.
	warn.addCount(len(arrField(top, "files")),
		"file entry not ingested: SPDX files are not software products",
		"file entries not ingested: SPDX files are not software products")

	applySPDXRelationships(top, doc, byRef, &warn)
	doc.Warnings = warn.result()
	return doc, nil
}

// convertSPDXPackage maps one SPDX package onto a [Component].
func convertSPDXPackage(obj map[string]json.RawMessage, warn *warnings) (c Component, kept bool, drop spdxLicenceDrop) {
	purl, cpe := spdxExternalRefs(obj)
	license, dropped := spdxLicense(obj)

	p := software.Product{
		Name:      strField(obj, "name"),
		Vendor:    spdxVendor(obj),
		Version:   strField(obj, "versionInfo"),
		PURL:      purl,
		CPE:       cpe,
		LicenseID: license,
	}
	if !p.Identifiable() {
		return Component{}, false, dropped
	}

	normalized, notes := p.Normalize()
	for _, note := range notes {
		warn.add("package " + describe(p.Name) + ": " + note)
	}

	typ := ""
	if purpose := strField(obj, "primaryPackagePurpose"); purpose != "" {
		typ = spdxPurposeToType[strings.ToUpper(purpose)]
	}

	return Component{
		Product: normalized,
		Type:    typ,
		BOMRef:  strField(obj, "SPDXID"),
		// SPDX has no per-package scope. Leaving it "" rather than inventing
		// "required" keeps "the document did not say" distinguishable from
		// "the document said required".
		Scope: "",
	}, true, dropped
}

// spdxExternalRefs pulls the purl and the CPE out of `externalRefs[]`.
//
// `referenceCategory` is deliberately NOT consulted — not "both spellings are
// accepted", genuinely not read. The category name differs between versions
// (2.2 wrote PACKAGE-MANAGER, 2.3 writes PACKAGE_MANAGER) and tools emit both
// spellings against both versions, so a parser that matched on it would have a
// third spelling to discover in the field. `referenceType` alone is
// unambiguous, and getting this wrong costs the purl, which is the STRONGEST
// identity the catalogue has; a document whose purls all fell out silently
// produces a catalogue keyed on name@version that dedupes against nothing.
//
// Both cpe22Type and cpe23Type are read; [software.NormalizeCPE] converts the
// 2.2 form, so the two spellings converge on one identity instead of producing
// two rows for one product.
func spdxExternalRefs(obj map[string]json.RawMessage) (purl, cpe string) {
	for _, raw := range arrField(obj, "externalRefs") {
		ref, ok := asObject(raw)
		if !ok {
			continue
		}
		locator := strField(ref, "referenceLocator")
		if locator == "" {
			continue
		}
		switch strings.ToLower(strField(ref, "referenceType")) {
		case "purl":
			if purl == "" {
				purl = locator
			}
		case "cpe23type":
			// A 2.3 reference always wins over a 2.2 one.
			cpe = locator
		case "cpe22type":
			if cpe == "" {
				cpe = locator
			}
		}
	}
	return purl, cpe
}

// spdxVendor reads `supplier`, falling back to `originator`.
//
// Both are written "Organization: Acme Inc." or "Person: Jane Doe"; the prefix
// is stripped because it is a type tag, not part of the name. A Person value is
// still taken: SPDX has no separate organisation field, and refusing it would
// leave the vendor blank for every single-maintainer package.
func spdxVendor(obj map[string]json.RawMessage) string {
	for _, key := range []string{"supplier", "originator"} {
		v := strField(obj, key)
		if v == "" || spdxNoAssertion[strings.ToUpper(v)] {
			continue
		}
		for _, prefix := range []string{"Organization:", "Person:", "Tool:"} {
			if len(v) >= len(prefix) && strings.EqualFold(v[:len(prefix)], prefix) {
				v = strings.TrimSpace(v[len(prefix):])
				break
			}
		}
		if v != "" {
			return v
		}
	}
	return ""
}

// spdxLicenceDrop names why a `licenseConcluded` value was not stored, so the
// two reasons can be counted and reported separately — "the producer reached
// no conclusion" and "the producer's conclusion was meaningless outside its own
// document" are different things to tell a user.
type spdxLicenceDrop uint8

const (
	licenceKept spdxLicenceDrop = iota
	licenceNoAssertion
	licenceDocumentLocal
)

// spdxLicense reads `licenseConcluded`.
//
// `licenseDeclared` is deliberately NOT used as a fallback. The two fields are
// different claims — declared is what the package itself says, concluded is
// what the SBOM producer determined after looking — and collapsing them into
// one column would relabel one as the other in a field people make licensing
// decisions from. If the producer reached no conclusion, the honest answer is
// that we have no concluded licence, not somebody else's claim wearing that
// label.
//
// A bare `LicenseRef-…` is dropped for the same reason
// `licenses[].license.name` is dropped on the CycloneDX side, one step worse.
// It is an id the DOCUMENT defines, in `hasExtractedLicensingInfos`, which this
// parser does not read; outside that document it names nothing. Two SBOMs from
// two build systems both emit `LicenseRef-0` for two unrelated licences, so
// storing it in a tenant-wide catalogue does not merely add noise — it MERGES
// two different licences under one value, which is the unrecoverable direction
// of the asymmetry this package decides everything else by. An EXPRESSION
// containing one ("MIT AND LicenseRef-1") is kept: it also carries real ids,
// and dropping the whole string to be rid of the ref would lose them.
func spdxLicense(obj map[string]json.RawMessage) (id string, drop spdxLicenceDrop) {
	v := strField(obj, "licenseConcluded")
	if v == "" {
		return "", licenceKept
	}
	if spdxNoAssertion[strings.ToUpper(v)] {
		return "", licenceNoAssertion
	}
	if spdxIsDocumentLocalLicenceRef(v) {
		return "", licenceDocumentLocal
	}
	return v, licenceKept
}

// spdxIsDocumentLocalLicenceRef reports whether v is a bare `LicenseRef-…` —
// optionally carrying the `DocumentRef-x:` prefix the spec allows — rather than
// an SPDX id or an expression that happens to contain one.
//
// The test for "expression" is the presence of whitespace or a bracket: every
// SPDX expression operator (AND, OR, WITH) is whitespace-separated, so a value
// with none of those is a single licence token.
func spdxIsDocumentLocalLicenceRef(v string) bool {
	if strings.ContainsAny(v, " \t\r\n()") {
		return false
	}
	if strings.HasPrefix(strings.ToUpper(v), "DOCUMENTREF-") {
		if i := strings.Index(v, ":"); i >= 0 {
			v = v[i+1:]
		}
	}
	return strings.HasPrefix(strings.ToUpper(v), "LICENSEREF-")
}

// applySPDXRelationships maps the three relationship types that carry
// structure this model has a home for, and reports the rest as a count.
//
//   - DESCRIBES (and the `documentDescribes` shorthand) names the document's
//     subject — the SPDX equivalent of CycloneDX's metadata.component.
//   - DEPENDS_ON becomes an [Edge].
//   - CONTAINS becomes a [Component.Parent], which is where CycloneDX's nested
//     components land too, so containment reads the same in both formats.
//
// SPDX defines about forty relationship types. Warning on each of the other
// thirty-seven individually would bury the warnings that name a real problem,
// so they are counted.
func applySPDXRelationships(
	top map[string]json.RawMessage,
	doc *Document,
	byRef map[string]int,
	warn *warnings,
) {
	docID := strField(top, "SPDXID")
	if docID == "" {
		docID = "SPDXRef-DOCUMENT"
	}

	var unreadable, unmapped, dangling, unresolvedSubject int

	setSubject := func(ref string) {
		idx, ok := byRef[ref]
		if !ok {
			// The document NAMES a subject and this parser has no package by
			// that id — a ghost ref, or a package skipped for having no name.
			// Returning no subject without saying so is the silent half of the
			// CycloneDX metadata.component case, which warns; ADR-0004 D3 may
			// create an application asset from the subject, so its absence is
			// not a detail. Counted before the "first one wins" check, so a
			// second, broken DESCRIBES is still reported.
			unresolvedSubject++
			return
		}
		if doc.Subject != nil {
			return
		}
		subject := doc.Components[idx].Product
		doc.Subject = &subject
		doc.SubjectType = doc.Components[idx].Type
		doc.SubjectRef = doc.Components[idx].BOMRef
	}

	// The shorthand first: `documentDescribes` is the 2.2-era spelling and is
	// still emitted alongside the relationship form.
	for _, ref := range strArrField(top, "documentDescribes") {
		setSubject(ref)
	}

	for _, raw := range arrField(top, "relationships") {
		rel, ok := asObject(raw)
		if !ok {
			unreadable++
			continue
		}
		from := strField(rel, "spdxElementId")
		to := strField(rel, "relatedSpdxElement")
		typ := strings.ToUpper(strField(rel, "relationshipType"))
		if from == "" || to == "" || typ == "" {
			unreadable++
			continue
		}

		switch typ {
		case "DESCRIBES":
			if from == docID {
				setSubject(to)
			}
		case "DESCRIBED_BY":
			// The reverse spelling, which the spec sanctions and tools emit.
			if to == docID {
				setSubject(from)
			}
		case "DEPENDS_ON":
			if _, ok := byRef[from]; !ok {
				dangling++
				continue
			}
			if _, ok := byRef[to]; !ok {
				dangling++
				continue
			}
			if from == to {
				dangling++
				continue
			}
			doc.Dependencies = append(doc.Dependencies, Edge{From: from, To: to})
		case "CONTAINS":
			idx, ok := byRef[to]
			if !ok {
				dangling++
				continue
			}
			if from == docID {
				// `DOCUMENT CONTAINS pkg` says the package is top level. It is
				// not containment between two components, and recording the
				// document's id as a Parent would invent a container that is
				// not in Components — a stronger claim than the document made,
				// and one no consumer could resolve.
				continue
			}
			if _, ok := byRef[from]; !ok || from == to {
				// A File ref, a ghost, or a package containing itself. Same
				// rule as DEPENDS_ON: both ends have to be packages this
				// document defines, and they have to be different ones.
				dangling++
				continue
			}
			// Only the first container wins. SPDX permits a package to be
			// CONTAINED by several; Component.Parent holds one, and silently
			// overwriting it would make the recorded parent depend on
			// relationship order in the file.
			if doc.Components[idx].Parent == "" {
				doc.Components[idx].Parent = from
			}
		default:
			unmapped++
		}
	}

	warn.addCount(unresolvedSubject,
		"document subject not resolved: DESCRIBES names an element this document does not define as a package",
		"document subjects not resolved: DESCRIBES names elements this document does not define as packages")
	warn.addCount(unreadable,
		"relationship skipped: not a JSON object, or missing an element or type",
		"relationships skipped: not a JSON object, or missing an element or type")
	warn.addCount(dangling,
		"relationship dropped: it names an element this document does not define as a package",
		"relationships dropped: they name elements this document does not define as packages")
	if unmapped > 0 {
		warn.list = append(warn.list, strconv.Itoa(unmapped)+
			" relationships of types this model has no home for were ignored "+
			"(only DESCRIBES, DEPENDS_ON and CONTAINS are mapped)")
	}
}
