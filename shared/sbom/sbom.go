package sbom

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/redact"
	"github.com/vistasecurity/vistaplatform/shared/software"
)

// Caps. Both refuse a document outright rather than truncating it: a
// half-ingested SBOM is worse than a rejected one, because the missing half is
// invisible — the asset shows a software list that looks complete.
const (
	// MaxDocumentBytes is the largest document [Parse] will read. 32 MiB is
	// comfortably above a container image SBOM with tens of thousands of
	// components and comfortably below what an upload handler should be asked
	// to hold in memory.
	MaxDocumentBytes = 32 << 20
	// MaxComponents is the largest number of components [Parse] will return,
	// counted across nested components too. The count is what the writer turns
	// into rows, so this is the bound on one upload's write amplification.
	MaxComponents = 100_000

	// maxNestingDepth bounds CycloneDX component nesting and is a crash
	// guard, not a policy: a recursive walk over attacker-controlled nesting
	// is the cheapest stack overflow there is, and a stack overflow is not an
	// error a caller can handle. Real documents nest two or three deep.
	maxNestingDepth = 64
	// maxWarnings bounds the warning list. Every per-entry warning is driven
	// by input, so an adversarial document with 100k malformed components
	// would otherwise turn a bounded parse into an unbounded allocation.
	maxWarnings = 256
)

// Format names the document grammar a [Document] was parsed from.
type Format string

const (
	// FormatCycloneDX is CycloneDX JSON, spec versions 1.4–1.7.
	FormatCycloneDX Format = "cyclonedx"
	// FormatSPDX is SPDX JSON, versions SPDX-2.2 and SPDX-2.3.
	FormatSPDX Format = "spdx"
)

// Errors. Every one of them is reachable through errors.Is, so an upload
// handler can map a refusal to a status code and a message without matching on
// error text.
var (
	// ErrUnknownFormat means the document is JSON but is neither a CycloneDX
	// BOM nor an SPDX document — no `bomFormat`, no `specVersion`, no
	// `spdxVersion`.
	ErrUnknownFormat = errors.New("sbom: unrecognised document format")
	// ErrUnsupportedSpecVersion means the format was recognised and the
	// version is outside the supported range. The message names the version
	// and the range.
	ErrUnsupportedSpecVersion = errors.New("sbom: unsupported spec version")
	// ErrUnsupportedEncoding means the bytes are not JSON — XML, most often.
	ErrUnsupportedEncoding = errors.New("sbom: unsupported encoding")
	// ErrMalformed means the bytes are not a JSON object at all, or the
	// document's own top level could not be read. A malformed COMPONENT is a
	// warning, not this.
	ErrMalformed = errors.New("sbom: malformed document")
	// ErrTooLarge is wrapped by a [*LimitError] when the input exceeds
	// [MaxDocumentBytes].
	ErrTooLarge = errors.New("sbom: document exceeds the size cap")
	// ErrTooManyComponents is wrapped by a [*LimitError] when the document
	// exceeds [MaxComponents].
	ErrTooManyComponents = errors.New("sbom: document exceeds the component cap")
)

// LimitError reports a refused document and which cap it hit. It carries the
// numbers so a caller can tell the user "43,000 components, limit 100,000"
// rather than "too big", which is the difference between a user who can act
// and one who files a ticket.
type LimitError struct {
	// Limit is "bytes" or "components".
	Limit string
	// Max is the cap that was exceeded.
	Max int
	// Got is the observed value, or -1 when only "more than Max" is known —
	// the size check stops reading at Max+1 rather than buffering an
	// unbounded upload to find out exactly how big it was.
	Got int
}

func (e *LimitError) Error() string {
	got := "more than " + strconv.Itoa(e.Max)
	if e.Got >= 0 {
		got = strconv.Itoa(e.Got)
	}
	return e.Unwrap().Error() + ": " + got + " " + e.Limit + " (limit " + strconv.Itoa(e.Max) + ")"
}

func (e *LimitError) Unwrap() error {
	if e.Limit == "bytes" {
		return ErrTooLarge
	}
	return ErrTooManyComponents
}

// Document is one parsed bill of materials.
type Document struct {
	// Format is the grammar it was parsed from.
	Format Format
	// SpecVersion is the version the document declared: "1.6" for CycloneDX,
	// "SPDX-2.3" for SPDX. Kept verbatim, because it is what a support
	// question is answered from.
	SpecVersion string
	// Serial is the document's own identity: CycloneDX `serialNumber`
	// (`urn:uuid:…`), or SPDX `documentNamespace`, which the SPDX spec
	// requires to be unique per document and is the nearest equivalent. It is
	// what a writer records as `software_installs.source_ref`, and what makes
	// re-ingesting the same document idempotent rather than duplicative.
	Serial string
	// Subject is what the document is ABOUT: CycloneDX `metadata.component`,
	// or the package an SPDX DESCRIBES relationship points at. ADR-0004 D3
	// allows an application asset to be created from it when the upload is not
	// attached to an existing asset. nil when the document names no subject.
	//
	// The formats differ on whether it is ALSO in Components, and a writer has
	// to know which: in CycloneDX the subject sits outside the component list,
	// in SPDX it is one of the packages. Writing both without checking
	// SubjectRef against the component BOMRefs creates the subject's product
	// twice. TestSPDXSubjectIsAlsoAComponent pins the asymmetry.
	Subject *software.Product
	// SubjectType is the subject's component type, in the same vocabulary as
	// [Component.Type]. An "application" subject is the case D3 means when it
	// says an application asset may be created from the metadata component;
	// a "container" or "operating-system" subject is not the same thing, and
	// dropping the type would leave the caller unable to tell them apart.
	SubjectType string
	// SubjectRef is the subject's bom-ref or SPDXID, so a dependency edge
	// rooted at the subject resolves.
	SubjectRef string
	// Components are the software components, nested ones flattened.
	Components []Component
	// Dependencies are the resolvable dependency edges. An edge whose either
	// end is not a component in this document is dropped — see [Edge].
	Dependencies []Edge
	// Warnings names everything skipped, dropped or assumed, in a stable
	// order. A document that parsed with warnings is a successful parse; the
	// warnings are what the upload page shows so "we ingested 412 of your 480
	// components" is a sentence the user can read rather than a silence.
	Warnings []string
}

// Component is one software component: a [software.Product] plus the
// structural facts the document carried about it.
type Component struct {
	// Product is the normalised catalogue entry.
	Product software.Product
	// Type is the CycloneDX component type vocabulary — application, library,
	// framework, container, operating-system, device, device-driver, firmware,
	// file, platform, data, machine-learning-model — and is the vocabulary
	// SPDX's `primaryPackagePurpose` is mapped INTO, so a consumer reads one
	// vocabulary regardless of which format arrived. "" when the document did
	// not say; an unrecognised value is kept verbatim with a warning rather
	// than blanked, because a value we have not seen is still evidence.
	Type string
	// BOMRef is the document-local identifier: CycloneDX `bom-ref` or SPDX
	// `SPDXID`. It is what [Edge] and [Component.Parent] refer to, and it is
	// meaningless outside this document.
	BOMRef string
	// Scope is CycloneDX `scope` — required, optional or excluded — kept
	// because "excluded" says the component is NOT in the artefact, and
	// ingesting it as an install would be a false positive. "" for SPDX,
	// which has no equivalent.
	Scope string
	// Parent is the BOMRef of the component this one was nested inside
	// (CycloneDX nested `components`, or an SPDX CONTAINS relationship). ""
	// for a top-level component.
	//
	// Nesting is flattened rather than kept as a tree because
	// `software_installs` is flat, but the containment is recorded rather than
	// discarded: "this jar is inside that war" is the difference between one
	// install and two.
	//
	// Unlike an [Edge], a Parent is NOT guaranteed to name a component in
	// Components, and the exception is deliberate: a library nested under a
	// skipped cryptographic asset keeps that asset's bom-ref, because
	// promoting it to top level would be a stronger claim than the document
	// made. A consumer resolving Parent must tolerate a miss. (On the SPDX
	// side there is no such case — a CONTAINS needs packages at both ends.)
	Parent string
}

// Edge is one dependency relationship, from the depending component to the
// component it depends on.
//
// Both ends are BOMRefs of components in the same [Document]. An edge naming a
// ref this document does not define is DROPPED with a counted warning: the
// commonest source of one is a CBOM's library→algorithm `dependsOn`, whose far
// end is a cryptographic component this parser skipped, and emitting an edge to
// a component the consumer cannot find asserts a relationship that does not
// resolve. The same rule the CBOM formatter applies on the way out.
type Edge struct {
	From string
	To   string
}

// Parse reads one SBOM and returns it in the normalised model.
//
// It detects the format from the document's own declaration — `bomFormat` and
// `specVersion` for CycloneDX, `spdxVersion` for SPDX — rather than from a
// filename or a Content-Type, both of which are supplied by whoever is
// uploading and neither of which is evidence.
//
// A returned error means nothing was parsed. Warnings on a returned document
// mean parts of it were skipped; see [Document.Warnings].
func Parse(r io.Reader) (*Document, error) {
	data, err := readCapped(r)
	if err != nil {
		return nil, err
	}

	format, spec, err := detect(data)
	if err != nil {
		return nil, err
	}

	var doc *Document
	switch format {
	case FormatCycloneDX:
		doc, err = parseCycloneDX(data, spec)
	case FormatSPDX:
		doc, err = parseSPDX(data, spec)
	default:
		// Unreachable: detect returns one of the two or an error. Stated
		// anyway, because a silent nil here would be a nil dereference below.
		return nil, ErrUnknownFormat
	}
	if err != nil {
		return nil, err
	}

	doc.redactStrings()
	return doc, nil
}

// readCapped reads at most [MaxDocumentBytes], and refuses rather than
// truncates when there is more. The LimitReader is given one extra byte
// precisely so "exactly at the cap" and "over the cap" are distinguishable —
// reading exactly Max bytes tells you nothing about whether more were coming.
func readCapped(r io.Reader) ([]byte, error) {
	if r == nil {
		return nil, errWrap(ErrMalformed, "nil reader")
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxDocumentBytes+1))
	if err != nil {
		return nil, errWrap(ErrMalformed, "read: "+err.Error())
	}
	if len(data) > MaxDocumentBytes {
		return nil, &LimitError{Limit: "bytes", Max: MaxDocumentBytes, Got: -1}
	}
	// A UTF-8 BOM is what a Windows exporter prepends, and encoding/json
	// rejects it as invalid input. Stripping it here rather than reporting
	// "invalid character 'ï'" is the difference between a user who re-exports
	// and a user who opens a ticket.
	data = bytes.TrimPrefix(data, utf8BOM)
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errWrap(ErrMalformed, "empty document")
	}
	return data, nil
}

var utf8BOM = []byte{0xef, 0xbb, 0xbf}

// detect identifies the format and spec version from the document's own
// declaration.
func detect(data []byte) (Format, string, error) {
	switch firstNonSpace(data) {
	case '<':
		return "", "", errWrap(ErrUnsupportedEncoding,
			"this looks like XML; only CycloneDX JSON and SPDX JSON are parsed — re-export as JSON")
	case '{':
	default:
		return "", "", errWrap(ErrMalformed, "top level is not a JSON object")
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return "", "", errWrap(ErrMalformed, err.Error())
	}

	if v := strField(top, "spdxVersion"); v != "" {
		switch v {
		case "SPDX-2.2", "SPDX-2.3":
			return FormatSPDX, v, nil
		case "SPDX-3.0", "SPDX-3.0.0", "SPDX-3.0.1":
			return "", "", errWrap(ErrUnsupportedSpecVersion,
				v+" is a JSON-LD model with a different element vocabulary, not a revision of the 2.x JSON shape; "+
					"parsing it on the 2.x shape would succeed and return nothing. Supported: SPDX-2.2, SPDX-2.3")
		default:
			return "", "", errWrap(ErrUnsupportedSpecVersion, v+"; supported: SPDX-2.2, SPDX-2.3")
		}
	}

	bomFormat := strField(top, "bomFormat")
	spec := strField(top, "specVersion")
	if !strings.EqualFold(bomFormat, "CycloneDX") && spec == "" {
		return "", "", errWrap(ErrUnknownFormat,
			"no bomFormat/specVersion (CycloneDX) and no spdxVersion (SPDX)")
	}
	if spec == "" {
		return "", "", errWrap(ErrUnsupportedSpecVersion,
			"bomFormat is CycloneDX but specVersion is absent; supported: 1.4–1.7")
	}
	major, minor, ok := parseSpecVersion(spec)
	if !ok {
		return "", "", errWrap(ErrUnsupportedSpecVersion, spec+" is not a major.minor version; supported: 1.4–1.7")
	}
	// Below 1.4 the component shape differs enough (licences, evidence, the
	// absence of `cpe` on some paths) that a best-effort parse would quietly
	// under-report. Above 1.7 the shape this parser reads is additive-stable,
	// so a newer document is parsed with a warning rather than refused — a
	// refusal there would make every future CycloneDX release an outage.
	if major != 1 || minor < 4 {
		return "", "", errWrap(ErrUnsupportedSpecVersion, spec+"; supported: 1.4–1.7")
	}
	return FormatCycloneDX, spec, nil
}

func parseSpecVersion(s string) (major, minor int, ok bool) {
	majorStr, minorStr, found := strings.Cut(s, ".")
	if !found {
		return 0, 0, false
	}
	// A patch component ("1.6.1") is tolerated: the minor is what matters.
	minorStr, _, _ = strings.Cut(minorStr, ".")
	major, err := strconv.Atoi(majorStr)
	if err != nil {
		return 0, 0, false
	}
	minor, err = strconv.Atoi(minorStr)
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

func firstNonSpace(data []byte) byte {
	for _, c := range data {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			return c
		}
	}
	return 0
}

// redactStrings masks PEM private-key blocks in every string the document
// carries, warnings included.
//
// It is the LAST thing Parse does, deliberately: a warning is assembled from
// input text (a quoted malformed purl, an unrecognised component type), so
// redacting the fields and not the warnings would let a key out through the
// diagnostic channel — which is the path nobody inspects.
func (d *Document) redactStrings() {
	if d.Subject != nil {
		d.Subject.Name = redact.TextPEM(d.Subject.Name)
		d.Subject.Vendor = redact.TextPEM(d.Subject.Vendor)
		d.Subject.Version = redact.TextPEM(d.Subject.Version)
		d.Subject.PURL = redact.TextPEM(d.Subject.PURL)
		d.Subject.CPE = redact.TextPEM(d.Subject.CPE)
		d.Subject.LicenseID = redact.TextPEM(d.Subject.LicenseID)
	}
	d.SpecVersion = redact.TextPEM(d.SpecVersion)
	d.Serial = redact.TextPEM(d.Serial)
	d.SubjectType = redact.TextPEM(d.SubjectType)
	d.SubjectRef = redact.TextPEM(d.SubjectRef)

	for i := range d.Components {
		c := &d.Components[i]
		c.Product.Name = redact.TextPEM(c.Product.Name)
		c.Product.Vendor = redact.TextPEM(c.Product.Vendor)
		c.Product.Version = redact.TextPEM(c.Product.Version)
		c.Product.PURL = redact.TextPEM(c.Product.PURL)
		c.Product.CPE = redact.TextPEM(c.Product.CPE)
		c.Product.LicenseID = redact.TextPEM(c.Product.LicenseID)
		c.Type = redact.TextPEM(c.Type)
		c.BOMRef = redact.TextPEM(c.BOMRef)
		c.Scope = redact.TextPEM(c.Scope)
		c.Parent = redact.TextPEM(c.Parent)
	}
	for i := range d.Dependencies {
		d.Dependencies[i].From = redact.TextPEM(d.Dependencies[i].From)
		d.Dependencies[i].To = redact.TextPEM(d.Dependencies[i].To)
	}
	for i := range d.Warnings {
		d.Warnings[i] = redact.TextPEM(d.Warnings[i])
	}
}

// warnings collects diagnostics under a hard cap.
//
// Counters are separate from the list: a per-entry message ("component 412:
// no name") is useful up to a point and noise past it, while "1,284
// cryptographic components skipped" is one line however many there were. The
// counted kinds are appended once, in a fixed order, so golden tests are
// deterministic.
type warnings struct {
	list       []string
	suppressed int
}

func (w *warnings) add(msg string) {
	if len(w.list) >= maxWarnings {
		w.suppressed++
		return
	}
	w.list = append(w.list, msg)
}

// addCount appends a counted summary when n > 0, bypassing the per-entry cap:
// these are bounded in number by the code, not by the input.
func (w *warnings) addCount(n int, singular, plural string) {
	if n == 0 {
		return
	}
	noun := plural
	if n == 1 {
		noun = singular
	}
	w.list = append(w.list, strconv.Itoa(n)+" "+noun)
}

func (w *warnings) result() []string {
	if w.suppressed > 0 {
		w.list = append(w.list, strconv.Itoa(w.suppressed)+" further warnings suppressed")
	}
	return w.list
}

// ---------------------------------------------------------------------------
// Tolerant JSON accessors
// ---------------------------------------------------------------------------
//
// Every field is read through these rather than by unmarshalling into a typed
// struct, and that is the whole reason a malformed entry can be SKIPPED rather
// than fail the document. encoding/json fails a whole struct on one type
// mismatch, so a single component with `"version": 3` would take the other
// 40,000 with it. Reading field by field, a wrong-typed field is absent and
// nothing else is affected — which is also how "unknown fields ignored" falls
// out for free.

func asObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, false
	}
	return m, true
}

func asArray(raw json.RawMessage) ([]json.RawMessage, bool) {
	var a []json.RawMessage
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, false
	}
	return a, true
}

// strField returns a string field, or "" when it is absent, null, or not a
// string.
func strField(m map[string]json.RawMessage, key string) string {
	raw, ok := m[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

// arrField returns an array field's elements, or nil.
func arrField(m map[string]json.RawMessage, key string) []json.RawMessage {
	raw, ok := m[key]
	if !ok {
		return nil
	}
	a, ok := asArray(raw)
	if !ok {
		return nil
	}
	return a
}

// objField returns an object field, or nil.
func objField(m map[string]json.RawMessage, key string) map[string]json.RawMessage {
	raw, ok := m[key]
	if !ok {
		return nil
	}
	o, ok := asObject(raw)
	if !ok {
		return nil
	}
	return o
}

// strArrField returns the string elements of an array field, skipping any
// element that is not a string.
func strArrField(m map[string]json.RawMessage, key string) []string {
	items := arrField(m, key)
	if items == nil {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		var s string
		if err := json.Unmarshal(item, &s); err != nil {
			continue
		}
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func errWrap(sentinel error, reason string) error {
	return &wrappedError{sentinel: sentinel, reason: reason}
}

type wrappedError struct {
	sentinel error
	reason   string
}

func (e *wrappedError) Error() string { return e.sentinel.Error() + ": " + e.reason }
func (e *wrappedError) Unwrap() error { return e.sentinel }

// describe truncates a value for a warning message. An SBOM field is
// attacker-controlled and can be megabytes long; a warning that echoes it
// whole turns a bounded warning list into an unbounded one.
func describe(s string) string {
	const max = 80
	if len(s) > max {
		s = s[:max] + "…"
	}
	return `"` + strings.Map(printableOnly, s) + `"`
}

// printableOnly drops control characters, which is not cosmetic: a warning is
// rendered in a terminal and in a browser, and an escape sequence pasted into
// a component name would be rendered by one of them.
func printableOnly(r rune) rune {
	if r < 0x20 || r == 0x7f {
		return -1
	}
	return r
}
