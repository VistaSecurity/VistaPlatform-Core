package services

import (
	"strconv"
	"strings"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	sharedfindings "github.com/vistasecurity/vistaplatform/shared/findings"
)

// Imported as `sharedfindings` because `findings` is a local variable name all
// over this package — a plain import would shadow the package inside exactly the
// functions that need it.

// The compliance producer's corner of the ONE findings table (ADR-0005 D3,
// workstream 3.1). compliance_findings is gone; every query below reads and
// writes `findings` and says which producer's rows it means.

// complianceProducerScope is the predicate that selects THIS producer's rows.
//
// Every compliance read carries it, including the ones that would give the same
// answer today because compliance is the only producer writing yet. That is the
// point: a read without it is correct exactly until workstream 3.5 ships the
// configuration and hygiene producers, at which point a Findings page scoped to
// framework controls would start counting end-of-life and missing-owner rows —
// silently, with no error anywhere, which is the failure shape this codebase
// keeps re-finding. The `kind` half is redundant with `producer` while
// compliance has one kind, and is spelled out for the same reason.
//
// alias is the table alias in the caller's query; pass "" for an unaliased
// `findings`.
func complianceProducerScope(alias string) string {
	q := ""
	if alias != "" {
		q = alias + "."
	}
	return "(" + q + "producer = '" + sharedfindings.ProducerCompliance + "'" +
		" AND " + q + "kind = '" + sharedfindings.KindControlNoncompliant + "')"
}

// nonComplianceProducerScope is complianceProducerScope negated — the rows of
// every OTHER producer.
//
// Spelled once here rather than as `NOT (...)` at each call site, because the
// two are used together: a read that shows every producer applies the
// compliance-only rules (the framework licence gate, the control join) under
// this predicate's complement, and reading `NOT` inline three times is how one
// of them comes to be missed.
func nonComplianceProducerScope(alias string) string {
	return "(NOT " + complianceProducerScope(alias) + ")"
}

// Severity, the registry's ladder.
//
// compliance_findings stored `Low` / `Med` / `High` / `Critical`; `findings`
// stores the registry's lowercase `info` / `low` / `medium` / `high` /
// `critical`, checked by findings_severity_check. `Med` had no spelling anyone
// else used — models.RiskBands, the alert registry and the crypto producer all
// say `medium` — so the two vocabularies could not both survive.
const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// normalizeSeverity maps any spelling a control's baseline_severity or a
// measurement rule might carry onto the registry ladder.
//
// It defaults to `low` rather than erroring, and that default is the one the
// writer already had (insertFinding's `severity := "Low"`): a control whose
// author left the field blank still produces a finding, because a violation
// nobody graded is a violation. It is NOT defaulted to `info` — `info` is the
// Informational band models.RiskBands reports at score 0, and quietly demoting
// an ungraded failure into it would be the "not assessed rendered as passed"
// shape.
func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "crit":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium", "med", "moderate":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "info", "informational", "none":
		return SeverityInfo
	default:
		return SeverityLow
	}
}

// severityRankSQL ranks severity worst-first for ORDER BY and MAX(). Written
// once so a second ladder cannot appear in a query and disagree with this one,
// which is exactly how the risk badges came to band High at ≥60 while the
// facets used ≥70.
func severityRankSQL(col string) string {
	return "CASE " + col +
		" WHEN '" + SeverityCritical + "' THEN 5" +
		" WHEN '" + SeverityHigh + "' THEN 4" +
		" WHEN '" + SeverityMedium + "' THEN 3" +
		" WHEN '" + SeverityLow + "' THEN 2" +
		" WHEN '" + SeverityInfo + "' THEN 1 ELSE 0 END"
}

// severityFromRank maps severityRankSQL's number back to the stored label.
func severityFromRank(rank int) string {
	switch rank {
	case 5:
		return SeverityCritical
	case 4:
		return SeverityHigh
	case 3:
		return SeverityMedium
	case 2:
		return SeverityLow
	case 1:
		return SeverityInfo
	default:
		return SeverityLow
	}
}

// Subject types, in the registry's vocabulary. The compliance producer emits
// exactly TWO — which is the faithful translation of the old table, not a
// narrowing of it:
//
//	network_asset         -> asset        (assets.id)
//	crypto_implementation -> asset        (assets.id)
//	certificate           -> certificate  (certificates.id)
//
// `compliance_findings.asset_id` was ALWAYS the asset's id for the first two;
// `asset_type` named the measurement KIND, not the type of the id beside it.
// Reading it as the id's type — and so renaming `crypto_implementation` to
// `crypto_configuration` — would make every one of those rows claim to point at
// a `crypto_implementations.id` it has never held.
//
// The configurations a measurement was taken over travel in
// evidence.crypto_implementation_ids instead, which is what the inspector links
// through. `crypto_configuration` as a SUBJECT is reserved for the
// configuration producer (workstream 3.5), which measures one configuration at
// a time and will carry its id.
const (
	SubjectAsset       = sharedfindings.SubjectAsset
	SubjectCertificate = sharedfindings.SubjectCertificate
)

// EvidenceCryptoImplementationIDs is the evidence key carrying the crypto
// configurations an asset-subject measurement was taken over. Named once so the
// extractor that writes it, the merge that unions it and the wire contract
// cannot drift to three spellings.
const EvidenceCryptoImplementationIDs = "crypto_implementation_ids"

// normalizeSubjectType defaults a blank subject type to `asset`, which is what
// a measurement with no explicit subject is taken on.
func normalizeSubjectType(s string) string {
	switch s {
	case SubjectCertificate, SubjectAsset:
		return s
	default:
		return SubjectAsset
	}
}

// subjectLabelFrom derives the display name to stamp on a finding at write
// time, from the metadata the extractor already collected.
//
// It is a FALLBACK, not the display path: a read still joins for the live name.
// It exists for the subject whose row has since gone — an archived asset, a
// rotated certificate — where the alternative is a raw UUID.
//
// Returns nil rather than "" when nothing names the subject. An empty string
// would satisfy a `subject_label != ""` check and render as a blank label,
// which is the "empty never wins" shape: absent is the honest answer.
func subjectLabelFrom(subjectType string, metadata map[string]interface{}) *string {
	str := func(key string) string {
		v, ok := metadata[key].(string)
		if !ok {
			return ""
		}
		return strings.TrimSpace(v)
	}
	var keys []string
	if subjectType == SubjectCertificate {
		keys = []string{"common_name"}
	} else {
		// An asset names itself by hostname; an asset discovered by address has
		// no hostname and the endpoint's FQDN or address is the best it has.
		keys = []string{"hostname", "endpoint_fqdn", "ip_address"}
	}
	for _, k := range keys {
		if v := str(k); v != "" {
			return &v
		}
	}
	return nil
}

// mergeSubjectEvidence folds a sibling finding's configuration ids into the
// representative one the reconcile keeps for a (control, subject) pair.
//
// One asset with four TLS configurations, three of them negotiating a banned
// version, produces three violating measurements and ONE finding — the pair is
// the unit of triage. Keeping only the first measurement's evidence would name
// one of the three configurations and silently drop the other two, so the
// inspector's "which configurations failed?" would be wrong without being
// visibly wrong. Order is preserved and duplicates are dropped, so the merge is
// idempotent and a converged re-run writes byte-identical evidence (which is
// what keeps the no-op update path from churning rows).
func mergeSubjectEvidence(dst, src *models.ComplianceFinding) {
	add := evidenceConfigIDs(src)
	if len(add) == 0 {
		return
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(add))
	for _, id := range append(evidenceConfigIDs(dst), add...) {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	if dst.Evidence == nil {
		dst.Evidence = map[string]interface{}{}
	}
	dst.Evidence[EvidenceCryptoImplementationIDs] = out
}

// evidenceConfigIDs reads the configuration-id list off a finding's evidence,
// tolerating both the []string the writer produces and the []interface{} a
// JSONB round-trip produces.
func evidenceConfigIDs(f *models.ComplianceFinding) []string {
	if f == nil || f.Evidence == nil {
		return nil
	}
	switch v := f.Evidence[EvidenceCryptoImplementationIDs].(type) {
	case []string:
		return v
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// newAliasCounter mints unique table aliases for findings.AssetSubjects. The
// shared helper takes the generator rather than owning one so its fragment can
// be spliced into a query that already has aliases of its own without colliding
// with them.
func newAliasCounter() func(string) string {
	n := 0
	return func(prefix string) string {
		n++
		return "fs_" + prefix + strconv.Itoa(n)
	}
}

// quoteSubjectType renders a subject type as a SQL literal.
//
// Safe because the only values that reach it are the registry constants in
// findings.AssetSubjects — code, never user text. The query-language builder
// binds them as parameters instead, because binding every value it emits is its
// rule; a hand-written query has no binder to hand the fragment.
func quoteSubjectType(subjectType string) string {
	return "'" + strings.ReplaceAll(subjectType, "'", "''") + "'"
}

// findingSeverityRank is severityRankSQL's Go twin — the same ladder, so a Go-side
// "which is worse" can never disagree with an ORDER BY.
func findingSeverityRank(s string) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// worseSeverity returns whichever of two severities is worse, normalizing both
// first so a caller holding an author's spelling ("Med") and a caller holding a
// stored value ("medium") compare on the same ladder.
func worseSeverity(a, b string) string {
	na, nb := normalizeSeverity(a), normalizeSeverity(b)
	if findingSeverityRank(nb) > findingSeverityRank(na) {
		return nb
	}
	return na
}
