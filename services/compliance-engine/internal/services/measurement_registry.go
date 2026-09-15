package services

// The measurement-type registry (ADR-0005 D5, BUILD_PLAN workstream 3.6).
//
// What a control can measure is declared in standards/measurement-types.yaml
// and generated into measurement_registry_gen.go. This file is the hand-written
// half: the types that table is made of, the whitelists a row may name (shapes
// live in measurement_shapes.go, transforms and row filters live here), and the
// lookups the extractor, the rule builder and the seed all read.
//
// Why a registry rather than the switch it replaced: the vocabulary used to
// live twice — nineteen SQL blocks here and nineteen INSERTed rows in
// seed.sql — with nothing holding them together, and the SQL was the only place
// that knew what a code actually measured. A registry row says what it measures
// in terms a reviewer can check: a shape, a value, a query-language predicate.
//
// No SQL comes from the registry. Values name a *selectable* the shape offers;
// predicates are query-language text compiled by shared/query against the
// production catalogue. `measurement_types.extraction_query` — a column that
// stored SQL and was never executed — is dropped rather than honoured (D5).

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// MeasurementRange is a measurement type's advisory numeric range, surfaced to
// the rule builder as `valid_range`.
type MeasurementRange struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

// EvidenceProjection is one entry of a measurement type's evidence map: which
// of the shape's selectables travels on the finding, under which metadata key.
//
// Exactly one of From, Const and Group is set. An absent value is OMITTED
// rather than written empty — a measurement whose endpoint has no address must
// not carry `"ip_address": ""`, which reads as an answer to a question nobody
// asked — unless Always is set, which is for a value the row filter has already
// proven present.
type EvidenceProjection struct {
	Key    string
	From   string
	Const  string
	Group  string
	Always bool
}

// MeasurementSource says where a measurement's value comes from.
type MeasurementSource struct {
	// Shape names one of the whitelisted FROM/JOIN skeletons in
	// measurement_shapes.go. The shape owns the tables, the tenant and
	// soft-delete predicates, the subject id, and what may be selected.
	Shape string
	// Value names a selectable of that shape.
	Value string
	// Where is a QUERY-LANGUAGE predicate over the shape's query target,
	// compiled by shared/query. Empty means every row the shape yields.
	Where string
	// SubjectWhere is a query-language predicate over the shape's SUBJECT
	// target, for a shape whose Where addresses something else (the finding
	// shape filters findings; this filters the assets they are counted for).
	SubjectWhere string
	// Transform names a pure Go function applied to the scanned value.
	Transform string
	// RowFilter names a pure Go predicate that drops a scanned row entirely.
	RowFilter string
	// OrderBy names one of the shape's orderings. Empty is the shape default.
	OrderBy string
	// MeasuredAt names one of the shape's measured-at expressions. Empty is
	// the shape default.
	MeasuredAt string
	// FactKey is the `asset_facts.key` the fact shape reads. Bound as a
	// parameter, never interpolated.
	FactKey string
	// AssessedBy is the producer that must have completed a pass over the asset
	// (a `producer_assessments` row) before the finding shape reports a count.
	//
	// The coverage RECORD, not `assets.risk_assessed_by` — the array is the
	// risk-feeding subset of it, so gating on the array would make every
	// `assessed_by: hygiene` row permanently unassessable.
	AssessedBy string
	// Via selects the finding shape's join: "" counts findings whose subject
	// IS the asset, "relationship" counts findings on edges it takes part in,
	// "asset_or_endpoint" counts both asset- and endpoint-subject findings.
	Via string
	// Evidence is the projection onto the finding's metadata.
	Evidence []EvidenceProjection
}

// MeasurementTypeDef is one registry row — the whole of what
// standards/measurement-types.yaml declares about a measurement type.
type MeasurementTypeDef struct {
	Code             string
	Name             string
	Description      string
	DataType         string
	Category         string
	Units            string
	ValidRange       *MeasurementRange
	AllowedRuleTypes []string
	EnumValues       []string
	ValidOperators   []string
	// Subject is the findings-registry subject type a violation is recorded
	// against. It is declared per type for readability and checked against the
	// shape's own subject by the generator, so the two cannot disagree.
	Subject string
	Source  MeasurementSource
}

// MeasurementTypes returns the registry in declaration order.
func MeasurementTypes() []MeasurementTypeDef {
	out := make([]MeasurementTypeDef, len(measurementTypeRegistry))
	copy(out, measurementTypeRegistry)
	return out
}

// MeasurementTypeByCode returns the registry row for a code.
func MeasurementTypeByCode(code string) (MeasurementTypeDef, bool) {
	for _, d := range measurementTypeRegistry {
		if d.Code == code {
			return d, true
		}
	}
	return MeasurementTypeDef{}, false
}

// MeasurementTypeCodes returns every registered code, sorted.
func MeasurementTypeCodes() []string {
	out := make([]string, 0, len(measurementTypeRegistry))
	for _, d := range measurementTypeRegistry {
		out = append(out, d.Code)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------- transforms

// measurementTransform turns a scanned value into the scalar a rule judges.
//
// The signature takes the already-typed scanned value and returns the value to
// publish; an error means "no measurement from this row", which is how a value
// that cannot be interpreted stays NOT ASSESSED instead of becoming a number.
type measurementTransform func(scannedValue) (interface{}, error)

// measurementTransforms is the whitelist. A registry row naming anything else
// fails at generation time and again at extractor construction.
var measurementTransforms = map[string]measurementTransform{
	"identity": func(v scannedValue) (interface{}, error) { return v.publish() },

	// pqc_class classifies an asymmetric algorithm's post-quantum readiness.
	// A NULL algorithm classifies as quantum_vulnerable, deliberately: if we
	// cannot prove a key is post-quantum it must be assumed at risk.
	"pqc_class": func(v scannedValue) (interface{}, error) {
		return classifyPQCAlgorithm(v.text()), nil
	},

	// symmetric_margin classifies a symmetric cipher's quantum margin.
	"symmetric_margin": func(v scannedValue) (interface{}, error) {
		return classifySymmetricQuantumMargin(v.text()), nil
	},

	// pfs reports whether a key exchange is ephemeral (ECDHE / DHE).
	"pfs": func(v scannedValue) (interface{}, error) {
		up := strings.ToUpper(v.text())
		return strings.Contains(up, "ECDHE") || strings.Contains(up, "DHE"), nil
	},

	// chain_valid inverts is_self_signed. A NULL is_self_signed is treated as
	// "not self-signed", which is the behaviour this replaces; a real chain
	// validation is a separate measurement, not a widening of this one.
	"chain_valid": func(v scannedValue) (interface{}, error) {
		b, ok := v.boolean()
		if !ok {
			return true, nil
		}
		return !b, nil
	},

	// days_floor floors a fractional day count. Floor, deliberately: a partial
	// day is not a whole day of remaining validity, and for an ALREADY-expired
	// certificate (negative value) floor keeps counting down instead of
	// rounding back toward zero the way Go's int() truncation does — -0.5 days
	// expired reads as -1, not 0 ("expires today").
	"days_floor": func(v scannedValue) (interface{}, error) {
		f, ok := v.number()
		if !ok {
			return nil, errNoMeasurement
		}
		return int(math.Floor(f)), nil
	},

	// days_trunc truncates a fractional day count. It is NOT days_floor: a
	// validity PERIOD is never negative, and truncation is what the measurement
	// this replaces published.
	"days_trunc": func(v scannedValue) (interface{}, error) {
		f, ok := v.number()
		if !ok {
			return nil, errNoMeasurement
		}
		return int(f), nil
	},

	// days_until_date turns a stored date fact into days remaining, negative
	// once the date has passed. A value that does not parse as a date yields NO
	// measurement — a malformed fact is not assessed, and is certainly not zero
	// days (which would read as "ends today").
	"days_until_date": func(v scannedValue) (interface{}, error) {
		d, err := parseFactDate(v.text())
		if err != nil {
			return nil, err
		}
		return int(math.Floor(time.Until(d).Hours() / 24)), nil
	},
}

// errNoMeasurement says a row yields no measurement. It is not an extraction
// failure: the row is skipped and its subject stays not assessed.
var errNoMeasurement = fmt.Errorf("no measurement from this row")

// parseFactDate accepts the shapes standards/fact-keys.yaml `date` values are
// written in: a bare ISO date and a full RFC 3339 timestamp. A bare date is
// read as UTC midnight, so "the day it ends" is the whole of that day.
func parseFactDate(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, errNoMeasurement
	}
	for _, layout := range []string{"2006-01-02", time.RFC3339, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("%w: %q is not a date", errNoMeasurement, s)
}

// --------------------------------------------------------------- row filters

// measurementRowFilter decides whether a scanned row produces a measurement at
// all. It reads the row's evidence values, which is why it takes the whole row.
type measurementRowFilter func(row map[string]scannedValue) bool

// measurementRowFilters is the whitelist.
//
// A key size is only meaningful against the floor for its own family: 2048 bits
// is the SP 800-131A minimum for RSA/DSA/DH, while an elliptic-curve key of 256
// bits carries MORE security than RSA-2048. One `key_size >= 2048` rule over
// both families flags every P-256 and Ed25519 certificate as weak (CMP-4), so
// each certificate is routed to exactly one of the two measurement types, and a
// certificate whose algorithm cannot be classified is emitted by NEITHER —
// reported as not assessed rather than judged against a floor that may not
// apply.
var measurementRowFilters = map[string]measurementRowFilter{
	"key_family_finite_field": func(row map[string]scannedValue) bool {
		return keySizeFamily(row["public_key_algorithm"].text()) == keyFamilyFiniteField
	},
	"key_family_elliptic_curve": func(row map[string]scannedValue) bool {
		return keySizeFamily(row["public_key_algorithm"].text()) == keyFamilyEllipticCurve
	},
}

// --------------------------------------------------------- pure classifiers

// classifyPQCAlgorithm maps a public-key algorithm to its post-quantum
// readiness: "quantum_safe" for a NIST PQC family (ML-KEM/Kyber, ML-DSA/
// Dilithium, SLH-DSA/SPHINCS+, FN-DSA/Falcon), else "quantum_vulnerable".
// Classical RSA/ECDSA/EdDSA/DSA/DH and any unrecognized algorithm are treated
// as vulnerable — if we can't prove a key is post-quantum, it must be assumed
// at risk. The substring match already treats a hybrid key exchange (e.g.
// X25519MLKEM768 → contains MLKEM) as quantum_safe.
func classifyPQCAlgorithm(algorithm string) string {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	pqc := []string{"ML-KEM", "MLKEM", "KYBER", "ML-DSA", "MLDSA", "DILITHIUM", "SLH-DSA", "SLHDSA", "SPHINCS", "FALCON", "FN-DSA", "FNDSA"}
	for _, p := range pqc {
		if strings.Contains(a, p) {
			return "quantum_safe"
		}
	}
	return "quantum_vulnerable"
}

// classifySymmetricQuantumMargin maps a symmetric cipher to its post-quantum
// margin: "quantum_safe" for AES-192/256 or ChaCha20 (>=128-bit security
// retained under Grover's quadratic speedup), else "quantum_marginal" (AES-128
// and weaker — below the CNSA 2.0 / post-quantum margin). Advisory: symmetric
// crypto is weakened, not broken, by quantum. Unknown/empty is treated as
// marginal (assume-at-risk, like the PQC classifier).
func classifySymmetricQuantumMargin(algorithm string) string {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	safe := []string{"AES-256", "AES256", "AES_256", "AES-192", "AES192", "AES_192", "CHACHA20"}
	for _, s := range safe {
		if strings.Contains(a, s) {
			return "quantum_safe"
		}
	}
	return "quantum_marginal"
}

// Key-size algorithm families. See measurementRowFilters for why one floor
// cannot serve both.
const (
	keyFamilyFiniteField   = "finite_field"   // RSA / DSA / DH — floor 2048
	keyFamilyEllipticCurve = "elliptic_curve" // EC / EdDSA / X25519 — floor 256
	keyFamilyUnknown       = ""               // not classifiable — NOT ASSESSED
)

// keySizeFamily maps a certificate public-key algorithm to the family whose
// minimum-size rule applies. An unrecognised (or absent) algorithm returns
// keyFamilyUnknown and the certificate is skipped entirely rather than judged
// against a floor that may not apply.
//
// Elliptic-curve forms are tested FIRST: "ECDSA" contains the substring "DSA",
// so a finite-field-first order silently classifies every ECDSA certificate as
// RSA-family and re-creates the bug this function exists to fix.
func keySizeFamily(algorithm string) string {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	if a == "" {
		return keyFamilyUnknown
	}

	// A post-quantum key has no classical size floor at all: ML-DSA-65's key is
	// thousands of bits of lattice, and comparing it to 2048 measures nothing.
	// Checked first because "ML-DSA" contains "DSA" — the same substring trap
	// that ECDSA springs below.
	if classifyPQCAlgorithm(a) == "quantum_safe" {
		return keyFamilyUnknown
	}

	ecMarkers := []string{
		"ECDSA", "ECDH", "EDDSA", "ED25519", "ED448", "X25519", "X448",
		"ECPUBLICKEY", "PRIME256V1", "SECP", "BRAINPOOL", "CURVE25519", "P-256", "P-384", "P-521",
	}
	for _, m := range ecMarkers {
		if strings.Contains(a, m) {
			return keyFamilyEllipticCurve
		}
	}
	if a == "EC" || strings.HasPrefix(a, "EC-") || strings.HasPrefix(a, "EC ") {
		return keyFamilyEllipticCurve
	}

	ffMarkers := []string{"RSA", "DSA", "DIFFIE", "ELGAMAL"}
	for _, m := range ffMarkers {
		if strings.Contains(a, m) {
			return keyFamilyFiniteField
		}
	}
	if a == "DH" || strings.HasPrefix(a, "DH-") {
		return keyFamilyFiniteField
	}

	return keyFamilyUnknown
}
