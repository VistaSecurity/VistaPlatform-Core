package sbom

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/software"
)

// componentTypes is the CycloneDX component `type` enum through 1.7. It is the
// vocabulary [Component.Type] speaks, and the one SPDX's
// `primaryPackagePurpose` is mapped into, so a consumer reads one vocabulary
// whichever format arrived.
//
// A type outside it is KEPT verbatim with a warning rather than blanked: a
// value we have not seen is still evidence, and a newer CycloneDX release
// adding an enum member should not silently erase it from every component that
// uses it.
var componentTypes = map[string]bool{
	"application":            true,
	"framework":              true,
	"library":                true,
	"container":              true,
	"platform":               true,
	"operating-system":       true,
	"device":                 true,
	"device-driver":          true,
	"firmware":               true,
	"file":                   true,
	"machine-learning-model": true,
	"data":                   true,
	"cryptographic-asset":    true,
}

// cdxLatestKnownMinor is the highest CycloneDX 1.x minor this parser was
// written against. A document declaring more is parsed anyway, with a warning
// — see the note in detect.
const cdxLatestKnownMinor = 7

func parseCycloneDX(data []byte, spec string) (*Document, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, errWrap(ErrMalformed, err.Error())
	}

	doc := &Document{
		Format:      FormatCycloneDX,
		SpecVersion: spec,
		Serial:      strField(top, "serialNumber"),
	}
	var warn warnings

	if _, minor, ok := parseSpecVersion(spec); ok && minor > cdxLatestKnownMinor {
		warn.add("specVersion " + spec + " is newer than the 1." +
			strconv.Itoa(cdxLatestKnownMinor) + " this parser was written against; " +
			"parsed on the 1." + strconv.Itoa(cdxLatestKnownMinor) +
			" shape, so fields added after it were ignored")
	}

	counts := cdxCounts{}

	// The subject: what the document is ABOUT, as distinct from what it
	// CONTAINS. ADR-0004 D3 allows an application asset to be created from it.
	if meta := objField(top, "metadata"); meta != nil {
		if raw, ok := meta["component"]; ok {
			obj, readable := asObject(raw)
			switch {
			case !readable:
				// The document DECLARED a subject and it could not be read.
				// Staying quiet here would report a clean parse of a document
				// whose subject — the thing ADR-0004 D3 may create an
				// application asset from — silently vanished, which is the one
				// failure shape this package exists not to have.
				warn.add("metadata.component is not a JSON object and was not read; " +
					"the document is treated as having no subject")
			default:
				if c, kept := convertCDXComponent(obj, "", &warn, &counts); kept {
					subject := c.Product
					doc.Subject = &subject
					doc.SubjectType = c.Type
					doc.SubjectRef = c.BOMRef
				} else {
					warn.add("metadata.component has no name and cannot be a software subject; " +
						"the document is treated as having none")
				}
			}
		}
	}

	if err := collectCDXComponents(arrField(top, "components"), "", 0, doc, &warn, &counts); err != nil {
		return nil, err
	}

	counts.emit(&warn)

	doc.Dependencies = collectCDXDependencies(arrField(top, "dependencies"), doc, &warn)
	doc.Warnings = warn.result()
	return doc, nil
}

// cdxCounts holds the diagnostics that are worth a number rather than a line
// each. A CBOM has thousands of cryptographic components and a big SBOM has
// thousands of unnamed file entries; one line per occurrence would bury the
// warnings that name a specific problem.
type cdxCounts struct {
	crypto          int
	unnamed         int
	unreadable      int
	unknownType     int
	tooDeep         int
	freeTextLicense int
}

func (c cdxCounts) emit(w *warnings) {
	w.addCount(c.crypto,
		"cryptographic component skipped: cryptographic assets belong to the CBOM path, not the software catalogue",
		"cryptographic components skipped: cryptographic assets belong to the CBOM path, not the software catalogue")
	w.addCount(c.unnamed,
		"component skipped: no name (software_products.name is NOT NULL)",
		"components skipped: no name (software_products.name is NOT NULL)")
	w.addCount(c.unreadable,
		"component skipped: not a JSON object",
		"components skipped: not a JSON object")
	w.addCount(c.unknownType,
		"component has a type outside the CycloneDX enum; kept verbatim",
		"components have a type outside the CycloneDX enum; kept verbatim")
	w.addCount(c.tooDeep,
		"nested component subtree skipped: nesting deeper than "+strconv.Itoa(maxNestingDepth),
		"nested component subtrees skipped: nesting deeper than "+strconv.Itoa(maxNestingDepth))
	w.addCount(c.freeTextLicense,
		"component licence dropped: the document gave a licence NAME with no SPDX id or expression",
		"component licences dropped: the document gave a licence NAME with no SPDX id or expression")
}

// collectCDXComponents walks the component tree, flattening it while recording
// each component's parent.
func collectCDXComponents(
	items []json.RawMessage,
	parent string,
	depth int,
	doc *Document,
	warn *warnings,
	counts *cdxCounts,
) error {
	if len(items) == 0 {
		return nil
	}
	if depth > maxNestingDepth {
		counts.tooDeep++
		return nil
	}

	for _, raw := range items {
		obj, ok := asObject(raw)
		if !ok {
			counts.unreadable++
			continue
		}

		// A cryptographic component is skipped WITHOUT being converted: its
		// licence and version fields describe an algorithm, not a product.
		// Its CHILDREN are still walked below, because a CBOM can nest a
		// library under a cryptographic asset and that library is real.
		if isCryptoComponent(obj) {
			counts.crypto++
		} else if c, kept := convertCDXComponent(obj, parent, warn, counts); !kept {
			counts.unnamed++
		} else {
			if c.Type != "" && !componentTypes[c.Type] {
				counts.unknownType++
			}
			if len(doc.Components) >= MaxComponents {
				return &LimitError{Limit: "components", Max: MaxComponents, Got: -1}
			}
			doc.Components = append(doc.Components, c)
		}

		// The parent of a nested component is this component's ref even when
		// this component was itself skipped — otherwise a library nested under
		// a skipped crypto asset would appear to be top-level, which is a
		// stronger claim than the document made.
		nested := arrField(obj, "components")
		if len(nested) > 0 {
			if err := collectCDXComponents(nested, strField(obj, "bom-ref"), depth+1, doc, warn, counts); err != nil {
				return err
			}
		}
	}
	return nil
}

// isCryptoComponent reports whether this is a CBOM entry rather than a software
// one. Both signals are checked: `type: cryptographic-asset` is the 1.6+
// spelling, and a `cryptoProperties` object is what actually carries the data —
// a document that sets one without the other is still a crypto component.
func isCryptoComponent(obj map[string]json.RawMessage) bool {
	if strings.EqualFold(strField(obj, "type"), "cryptographic-asset") {
		return true
	}
	_, hasCrypto := obj["cryptoProperties"]
	return hasCrypto
}

// convertCDXComponent maps one CycloneDX component onto a [Component].
// kept is false when there is no usable name, which is the one field
// `software_products` cannot be without.
func convertCDXComponent(
	obj map[string]json.RawMessage,
	parent string,
	warn *warnings,
	counts *cdxCounts,
) (Component, bool) {
	licenseID, droppedFreeText := cdxLicense(obj)
	if droppedFreeText {
		counts.freeTextLicense++
	}
	p := software.Product{
		Name:      strField(obj, "name"),
		Vendor:    cdxVendor(obj),
		Version:   strField(obj, "version"),
		PURL:      strField(obj, "purl"),
		CPE:       strField(obj, "cpe"),
		LicenseID: licenseID,
	}
	if !p.Identifiable() {
		return Component{}, false
	}

	normalized, notes := p.Normalize()
	for _, note := range notes {
		warn.add("component " + describe(p.Name) + ": " + note)
	}

	return Component{
		Product: normalized,
		Type:    strings.ToLower(strField(obj, "type")),
		BOMRef:  strField(obj, "bom-ref"),
		Scope:   strings.ToLower(strField(obj, "scope")),
		Parent:  parent,
	}, true
}

// cdxVendor prefers `publisher` — the organisation that published the
// component — and falls back to `group`, which for a Maven component is the
// group id and is the nearest thing to a vendor the document carries.
//
// `author`/`authors` are deliberately not consulted: an author is a person,
// `software_products.vendor` is an organisation, and filling an organisation
// column with a person's name is the kind of quiet category error that is
// impossible to unpick once a year of rows have it.
func cdxVendor(obj map[string]json.RawMessage) string {
	if v := strField(obj, "publisher"); v != "" {
		return v
	}
	return strField(obj, "group")
}

// cdxLicense reads `licenses[]`, preferring an SPDX id over an expression.
//
// A licence entry is either `{"license": {"id": …}}` (or `{"name": …}` for a
// licence with no SPDX id) or `{"expression": "MIT OR Apache-2.0"}`. An id is
// preferred because it is a term from a controlled vocabulary and an
// expression is not; the expression is kept verbatim when there is no id,
// because "MIT OR Apache-2.0" collapsed to "MIT" would assert a licence choice
// the document never made.
//
// `license.name` is NOT used. It is free text — "Apache 2.0", "Apache License
// v2", "BSD-like" — and `software_products.license_id` is an id column; a
// human-readable string in it would be indistinguishable from an SPDX id to
// every consumer downstream. The component is kept, with a warning naming it,
// so the information is reported rather than silently swallowed.
// droppedFreeText is true when the only licence information present was a free
// text name, so the caller can count it into a warning.
func cdxLicense(obj map[string]json.RawMessage) (id string, droppedFreeText bool) {
	var expression string
	var sawName bool
	for _, raw := range arrField(obj, "licenses") {
		entry, ok := asObject(raw)
		if !ok {
			continue
		}
		if lic := objField(entry, "license"); lic != nil {
			if id := strField(lic, "id"); id != "" {
				return id, false
			}
			if strField(lic, "name") != "" {
				sawName = true
			}
		}
		if expression == "" {
			expression = strField(entry, "expression")
		}
	}
	if expression != "" {
		return expression, false
	}
	return "", sawName
}

// collectCDXDependencies maps `dependencies[]` onto edges, dropping any whose
// ends this document does not define.
func collectCDXDependencies(items []json.RawMessage, doc *Document, warn *warnings) []Edge {
	if len(items) == 0 {
		return nil
	}
	known := knownRefs(doc)

	var edges []Edge
	var dangling, unreadable int
	for _, raw := range items {
		obj, ok := asObject(raw)
		if !ok {
			unreadable++
			continue
		}
		from := strField(obj, "ref")
		if from == "" {
			unreadable++
			continue
		}
		for _, to := range strArrField(obj, "dependsOn") {
			if !known[from] || !known[to] {
				dangling++
				continue
			}
			if from == to {
				// A self-edge is not a dependency; it is a producer bug, and
				// a traversal that follows it loops.
				dangling++
				continue
			}
			edges = append(edges, Edge{From: from, To: to})
		}
	}

	warn.addCount(unreadable,
		"dependency entry skipped: not a JSON object, or no ref",
		"dependency entries skipped: not a JSON object, or no ref")
	warn.addCount(dangling,
		"dependency edge dropped: it names a component this document does not define",
		"dependency edges dropped: they name components this document does not define")
	return edges
}

// knownRefs is every bom-ref the document actually defines, the subject
// included — a dependency graph is normally rooted at the metadata component.
func knownRefs(doc *Document) map[string]bool {
	known := make(map[string]bool, len(doc.Components)+1)
	for _, c := range doc.Components {
		if c.BOMRef != "" {
			known[c.BOMRef] = true
		}
	}
	if doc.SubjectRef != "" {
		known[doc.SubjectRef] = true
	}
	return known
}
