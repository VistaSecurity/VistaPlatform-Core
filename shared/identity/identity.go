// Package identity is the identification engine of ADR-0002 D3: the one place
// that answers "is this observation a thing we already know about?".
//
// Every intake path — sensor ingest, active scan, cloud collector, PCAP,
// spreadsheet import, CMDB pull, manual create — hands the engine an
// [Observation] and gets back a [Resolution]: the observation matched an
// existing asset, it is a new asset, or it is a conflict that a human must
// settle. It replaces the four ad hoc dedupe keys the survey found (six intake
// paths, four keys, no ON CONFLICT anywhere, manual create not deduping at
// all).
//
// # What this package is not
//
// It is pure Go with no database, no SQL and no service dependency. Storage is
// behind [Repository]; this package ships an in-memory implementation
// (shared/identity/memory) for tests and a contract test
// (shared/identity/identitytest) the Postgres implementation must also pass in
// phase 1 (workstream 1.2). Nothing here is wired to an intake path yet —
// that is workstream 1.2, and wiring it is where the observation builders live.
//
// # The three invariants
//
//  1. **An identifier value maps to at most one asset per tenant.**
//     DATA_MODEL §2 makes it a unique index over tenant, kind, value and
//     scope. The engine never writes an identifier that belongs to another
//     asset; when it sees one it reports it in [Resolution.Unattached] rather
//     than dropping it silently.
//  2. **Never auto-merge on conflict** (ADR-0002 D5). A conflict creates a
//     pending asset and a merge proposal. The matcher seam may RANK the
//     candidates; it may only auto-accept when a tenant has deliberately set
//     [Config.AutoAcceptThreshold] above zero, and the default is zero.
//  3. **Nothing is decided silently.** Every outcome writes a [HistoryEntry] —
//     `asset_history` gains its first writer here (DATA_MODEL §2) — and every
//     identifier the engine declined to use is reported back.
package identity

import (
	"errors"
	"strings"
)

// Errors the repository implementations share, so a caller can react to the
// same condition whichever implementation it holds. The contract test
// (shared/identity/identitytest) asserts every implementation returns these
// and not a look-alike of its own.
var (
	// ErrIdentifierConflict is returned when a write would bind an identifier
	// value that already belongs to a different asset in the same tenant. It
	// is the unique index of DATA_MODEL §2 speaking, and it is the signal that
	// produces a merge proposal — the engine avoids provoking it by querying
	// ownership first, so a caller seeing it has bypassed the engine.
	ErrIdentifierConflict = errors.New("identity: identifier already belongs to another asset")

	// ErrAssetNotFound is returned by a write against an asset that does not
	// exist in that tenant. A missing asset and an asset in another tenant are
	// deliberately the same error: leaking which is which across a tenant
	// boundary is an RLS hole with a friendly message.
	ErrAssetNotFound = errors.New("identity: asset not found")

	// ErrInvalidObservation is returned by [Engine.Resolve] for an observation
	// that cannot be acted on: no tenant, or an identifier that does not
	// normalise. It wraps a more specific message.
	ErrInvalidObservation = errors.New("identity: invalid observation")

	// ErrNoUsableIdentifier is returned by [Engine.Resolve] for an observation
	// that would produce an asset carrying NO identifier: either it arrived
	// with none at all, or its class drops every kind it does carry.
	//
	// Such an asset can never be recognised again, so every re-observation of
	// the same thing creates another one — which is the duplicate problem this
	// package exists to end, one level down from the dedupe keys it replaced.
	// Refusing is louder than creating: the caller logs a finding it could not
	// place, instead of an inventory that grows at the sensor's polling rate.
	//
	// It is a distinct error from [ErrInvalidObservation] because the caller's
	// response differs: an invalid observation is a bug in the builder, while
	// this one is usually a real observation of something we cannot yet name.
	ErrNoUsableIdentifier = errors.New("identity: observation would create an asset with no identifier")
)

// SourceKind is the provenance vocabulary of ADR-0005, shared with the facts
// layer and with `shared/ai/seams`: how a value came to be known.
//
// It is four values and not five. "unknown" is deliberately absent — a value
// whose origin nobody recorded is a bug in the caller, not a category.
type SourceKind string

const (
	// SourceMeasured is something the platform observed itself: an agent, an
	// interrogation, a cloud API, a passive sensor.
	SourceMeasured SourceKind = "measured"
	// SourceDeclared is something a person typed into the UI.
	SourceDeclared SourceKind = "declared"
	// SourceImported is something another system of record supplied: a CMDB
	// pull, a spreadsheet.
	SourceImported SourceKind = "imported"
	// SourceInferred is something a model proposed. ADR-0008 D4.2: it never
	// overwrites a measured or declared value, at any confidence.
	SourceInferred SourceKind = "inferred"
)

// Valid reports whether s is one of the four source kinds.
func (s SourceKind) Valid() bool {
	switch s {
	case SourceMeasured, SourceDeclared, SourceImported, SourceInferred:
		return true
	default:
		return false
	}
}

// ClassSourceKind is the vocabulary of `assets.class_source_kind`: the four
// [SourceKind] values plus one the CLASS column alone accepts.
//
// It is a separate type rather than a fifth SourceKind, and that is the whole
// point of it. `source_kind` is a column on asset_facts, asset_identifiers,
// asset_endpoints, asset_relationships, software_installs and findings as well,
// and every one of those has its own CHECK listing the four. Widening
// SourceKind.Valid to admit `rule` would make `Source{Kind: "rule"}` pass every
// in-process validation in the codebase and then be rejected by six database
// constraints — and the fact writer LOGS a failed insert rather than returning
// it, so the rejection would be silent.
type ClassSourceKind string

const (
	// ClassSourceMeasured, ClassSourceDeclared, ClassSourceImported and
	// ClassSourceInferred are the four [SourceKind] values, in the class
	// column's own type.
	ClassSourceMeasured ClassSourceKind = ClassSourceKind(SourceMeasured)
	ClassSourceDeclared ClassSourceKind = ClassSourceKind(SourceDeclared)
	ClassSourceImported ClassSourceKind = ClassSourceKind(SourceImported)
	ClassSourceInferred ClassSourceKind = ClassSourceKind(SourceInferred)

	// ClassSourceRule is a class argued from a curated `classification_rules`
	// row (ADR-0004 D6, workstream 2.10b). `class_source_ref` carries the rule
	// id, so a reviewer can read the pattern, the confidence and the citation
	// that produced the proposal.
	//
	// It is not a synonym for `measured`: the MAC was measured, the
	// MAC-to-class mapping was not. It is not `inferred` either — ADR-0008 D4.2
	// defines that as "something a model proposed" and gives it rules a
	// deterministic, citable table does not need. Making a rule-derived class
	// claim to be either would put false provenance on the one field a reviewer
	// uses to audit a class.
	ClassSourceRule ClassSourceKind = "rule"
)

// Valid reports whether c is one of the five class source kinds.
func (c ClassSourceKind) Valid() bool {
	switch c {
	case ClassSourceMeasured, ClassSourceDeclared, ClassSourceImported, ClassSourceInferred, ClassSourceRule:
		return true
	default:
		return false
	}
}

// AllClassSourceKinds is the vocabulary, in the order the CHECK constraint
// lists it. It exists so a test can compare the Go values against the deployed
// constraint rather than eyeballing two lists.
func AllClassSourceKinds() []ClassSourceKind {
	return []ClassSourceKind{
		ClassSourceMeasured, ClassSourceDeclared, ClassSourceImported,
		ClassSourceInferred, ClassSourceRule,
	}
}

// ClassSourceFrom narrows a [SourceKind] to the class column's type. Every
// SourceKind is a valid ClassSourceKind; the reverse is not true.
func ClassSourceFrom(s SourceKind) ClassSourceKind { return ClassSourceKind(s) }

// MeasurementMode splits `measured` into the two tiers ADR-0002 D4 ranks
// separately: an active measurement (an agent on the host, an authenticated
// interrogation, a cloud API answering about its own resource) outranks a
// passive one (a sensor inferring from traffic it happened to see).
//
// It is meaningful only when [Source.Kind] is [SourceMeasured] and is ignored
// otherwise.
type MeasurementMode string

const (
	// ModeUnspecified is the zero value: the caller did not say how it
	// measured. It ranks BELOW [ModePassive], not above it — "did not say" is
	// not evidence of an active measurement, and ranking silence as the
	// strongest tier is exactly the shape of bug the 2026-08 audit found sixty
	// times.
	ModeUnspecified MeasurementMode = ""
	// ModePassive is an observation from traffic: the sensor, PCAP.
	ModePassive MeasurementMode = "passive"
	// ModeActive is a measurement the platform went and took: host agent,
	// device interrogation, cloud API, active probe.
	ModeActive MeasurementMode = "active"
)

// Source is the provenance of an observation or of one value within it.
//
// Ref names the producer and is the string the `observation` query target's
// `source` field is matched against (QUERY_LANGUAGE §8: the approval rule
// condition `source: sensor_discoveries` becomes `source:sensor`). Use a
// `producer:detail` shape — "sensor", "sensor:pcap", "cloud:aws",
// "import:csv", "cmdb:servicenow", "manual" — so [Source.Producer] can answer
// the coarse question without the caller re-parsing it.
type Source struct {
	Kind SourceKind      `json:"kind"`
	Ref  string          `json:"ref"`
	Mode MeasurementMode `json:"mode,omitempty"`
}

// Producer returns the part of Ref before the first colon: the coarse producer
// an approval rule filters on. "cloud:aws" and "cloud:azure" are both "cloud".
func (s Source) Producer() string {
	if i := strings.IndexByte(s.Ref, ':'); i >= 0 {
		return s.Ref[:i]
	}
	return s.Ref
}

// Valid reports whether the source is usable: a known kind and a non-empty
// ref. A value with no producer cannot be audited, reconciled or filtered, and
// all three of those are the point.
func (s Source) Valid() bool {
	return s.Kind.Valid() && strings.TrimSpace(s.Ref) != ""
}
