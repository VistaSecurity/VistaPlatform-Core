package seams

import (
	"regexp"
	"strings"
)

// The row-citation grammar, shared by every seam that summarises rows it was
// given.
//
// One form, read by the implementations and by the UI:
//
//	[row:<row_id>]
//
// # Why this lives in Core, and here
//
// It was written twice before it was written here: once for the CBOM
// comparison narrator (workstream 4.5a) and once for the grounded query seam
// (4.4a). Both split prose into sentences, both drop a sentence whose citations
// do not resolve, and both derive the citation list from the text so the prose
// and the list cannot disagree — and a second copy of a rule about what counts
// as evidence is exactly the kind of fork this repository has paid for before
// (the sensor and its in-cluster twin; the device agent and its service). The
// grammar is Core because a Core deployment can and does render citations: the
// rule narrator writes them with no model anywhere near it.
//
// Callers keep their own bounds — how many sentences are a summary, how many
// bytes are a response — because those are properties of a surface, not of the
// grammar.
const (
	// CitationPrefix opens a citation. Deliberately not markdown: a model
	// emitting `[text](url)` must not be able to produce something this parser
	// reads as a citation, and a bracketed row id is not valid markdown link
	// syntax.
	CitationPrefix = "[row:"

	// CitationKindRow is the Citation.Kind for a row citation whose Ref names a
	// row in a result the caller already holds.
	CitationKindRow = "row"
)

// citationRe matches one citation.
//
// The row-id character class is deliberately narrow — alphanumerics, underscore
// and hyphen — because a row id is always OURS: `r1` from the comparison
// narrator, an asset uuid from the query seam. A permissive class would let a
// model smuggle arbitrary text through the marker and into a UI's link target.
// The length allows a uuid (36 characters) without allowing a sentence.
var citationRe = regexp.MustCompile(`\[row:([A-Za-z0-9_-]{1,64})\]`)

// CiteMarker renders one citation.
func CiteMarker(rowID string) string { return CitationPrefix + rowID + "]" }

// RefsIn returns the row ids cited in s, in order, including duplicates.
func RefsIn(s string) []string {
	matches := citationRe.FindAllStringSubmatch(s, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m[1])
	}
	return out
}

// CollectCitations turns the markers in text into a citation list: each
// distinct row id once, in order of first appearance, under the given kind.
//
// DERIVED from the text rather than accumulated alongside it, so prose cannot
// cite a row that is missing from its citation list, or list one it never
// mentions. The two used to be capable of disagreeing in every implementation
// of this pattern; here they cannot.
func CollectCitations(kind, text string) []Citation {
	var out []Citation
	seen := map[string]bool{}
	for _, ref := range RefsIn(text) {
		if seen[ref] {
			continue
		}
		seen[ref] = true
		out = append(out, Citation{Kind: kind, Ref: ref})
	}
	return out
}

var (
	horizontalRuns   = regexp.MustCompile(`[ \t]{2,}`)
	spaceBeforePunct = regexp.MustCompile(`[ \t]+([.,;:!?)])`)
)

// StripCitations removes the markers and tidies the whitespace they leave
// behind, producing plain prose for a client that knows nothing about
// citations.
//
// The tidying matters: "2 improvements [row:r1][row:r2] and 1 regression
// [row:r3]." strips to "2 improvements  and 1 regression ." without it, and a
// double space plus a floating full stop is how a reader decides a feature is
// half-built.
func StripCitations(text string) string {
	out := citationRe.ReplaceAllString(text, "")
	out = horizontalRuns.ReplaceAllString(out, " ")
	out = spaceBeforePunct.ReplaceAllString(out, "$1")
	return strings.TrimSpace(out)
}

// SplitSentences breaks prose at terminal punctuation followed by whitespace or
// end of text, and at line breaks.
//
// The "followed by whitespace" part is what keeps "TLS 1.0" and "openssl 3.0.0"
// in one piece: a full stop between two digits ends nothing. Getting that wrong
// would shred exactly the sentences these seams are most likely to write.
func SplitSentences(text string) []string {
	var out []string
	var cur strings.Builder
	runes := []rune(text)
	for i, r := range runes {
		if r == '\n' || r == '\r' {
			if s := strings.TrimSpace(cur.String()); s != "" {
				out = append(out, s)
			}
			cur.Reset()
			continue
		}
		cur.WriteRune(r)
		if r != '.' && r != '!' && r != '?' {
			continue
		}
		if i+1 < len(runes) && !isSpace(runes[i+1]) {
			continue
		}
		if s := strings.TrimSpace(cur.String()); s != "" {
			out = append(out, s)
		}
		cur.Reset()
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		out = append(out, s)
	}
	return out
}

func isSpace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r'
}

// EndsSentence reports whether s ends in terminal punctuation.
func EndsSentence(s string) bool {
	if s == "" {
		return false
	}
	last := s[len(s)-1]
	return last == '.' || last == '!' || last == '?'
}

// KeepCitedSentences enforces "cite or refuse" (ADR-0008 D4.4) on generated
// prose, sentence by sentence, and returns what survives joined back up.
//
// A sentence is DROPPED when it carries no citation, and when ANY of its
// citations names a row that is not in validIDs. One bad citation condemns its
// whole sentence: an unresolvable reference is not a formatting slip, it is the
// model asserting something about a row it was never shown, which is the
// failure this layer exists to catch.
//
// Dropping the uncited sentence is a choice, and D4.4 permits the other one —
// "output without a citation is shown as commentary, not as data". Commentary
// is right for a chat surface where a person asked a question and an aside is
// part of the answer. It is wrong on an evidence surface, where a paragraph
// mixing evidence with clearly-marked opinion is one a reader has to
// disassemble, and the marking is the first thing lost when someone pastes it
// into a ticket. Both live seams using this chose dropping.
//
// truncated says the text may stop mid-sentence — because the provider hit its
// token cap, or the caller clipped it. When it does, a trailing fragment that
// does not end in terminal punctuation is dropped too: a cut-off sentence reads
// exactly like a finished one.
//
// maxSentences caps what is kept; zero or less means no cap.
func KeepCitedSentences(text string, validIDs map[string]bool, maxSentences int, truncated bool) string {
	sentences := SplitSentences(text)

	if truncated && len(sentences) > 0 {
		last := strings.TrimSpace(sentences[len(sentences)-1])
		if !EndsSentence(last) {
			sentences = sentences[:len(sentences)-1]
		}
	}

	kept := make([]string, 0, len(sentences))
	for _, s := range sentences {
		trimmed := strings.TrimSpace(s)
		if trimmed == "" {
			continue
		}
		refs := RefsIn(trimmed)
		if len(refs) == 0 {
			continue
		}
		resolved := true
		for _, ref := range refs {
			if !validIDs[ref] {
				resolved = false
				break
			}
		}
		if !resolved {
			continue
		}
		kept = append(kept, trimmed)
		if maxSentences > 0 && len(kept) == maxSentences {
			break
		}
	}
	return strings.Join(kept, " ")
}

// ── The plan-citation grammar ──────────────────────────────────────────────
//
// The remediator seam (ADR-0008 D1) cites differently from the narrator and the
// query seam, because it is summarising something differently shaped. Those two
// are handed a numbered result set and cite a ROW of it. A remediation plan is
// drafted from one finding, and what a step rests on is either a specific
// measurement inside that finding's `evidence` map or the registry's guidance
// for the kind. Neither is a row, and numbering the evidence keys to make them
// look like rows would ask a model to copy an index it has no reason to get
// right when the real name is sitting in front of it.
//
// Two forms:
//
//	[ev:<evidence key>]   a top-level key of the finding's evidence map
//	[guide]               the registry guidance for the finding's kind
//
// Everything else about it is the row grammar's rules, deliberately: derive the
// citation list from the text so the two cannot disagree, drop what does not
// resolve, and keep the character class narrow enough that a marker cannot
// smuggle markup into a link target.
//
// This lives in Core, next to the row grammar, for the reason that one does: a
// grammar written twice is the fork this repository has paid for before, and
// the types that carry it ([Citation], [PlanStep]) are Core whether or not the
// thing that PRODUCES it is. A Core deployment produces no plan citations at
// all — its remediator answers with the guidance text and no steps — so the
// parser here is exercised by the Enterprise implementation and by the tests,
// and it is still the only copy.

const (
	// EvidencePrefix opens an evidence citation. Not markdown, for the reason
	// [CitationPrefix] is not: a model emitting `[text](url)` must not be able
	// to produce something this parser reads as a citation.
	EvidencePrefix = "[ev:"

	// GuidanceMarker is the whole guidance citation. It takes no argument
	// because there is exactly one guidance text per finding — the registry's,
	// for its kind — so there is nothing to name.
	GuidanceMarker = "[guide]"

	// CitationKindEvidence is the [Citation.Kind] for an evidence citation. Ref
	// is the evidence key.
	CitationKindEvidence = "evidence"

	// CitationKindGuidance is the [Citation.Kind] for a guidance citation. Ref
	// is empty: the guidance is named by the finding's kind, which the consumer
	// already has.
	CitationKindGuidance = "guidance"
)

// evidenceRe matches one evidence citation.
//
// The key character class is what an evidence key actually looks like —
// lower-case names, digits, underscores, dots and hyphens, as written by the
// producers (`protocol_version`, `cert.not_after`, `cvss_v3.base_score`). It is
// deliberately NOT permissive: the key is echoed into a UI as the label of a
// citation chip, and a class that admitted angle brackets or quotes would let a
// model choose that label. Anything outside the class simply does not match, so
// the citation does not exist, so the step carrying it is dropped.
var evidenceRe = regexp.MustCompile(`\[ev:([A-Za-z0-9_.\-]{1,64})\]`)

// EvidenceCiteMarker renders one evidence citation.
func EvidenceCiteMarker(key string) string { return EvidencePrefix + key + "]" }

// EvidenceRefsIn returns the evidence keys cited in s, in order, including
// duplicates.
func EvidenceRefsIn(s string) []string {
	matches := evidenceRe.FindAllStringSubmatch(s, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m[1])
	}
	return out
}

// CitesGuidance reports whether s carries the guidance marker.
func CitesGuidance(s string) bool { return strings.Contains(s, GuidanceMarker) }

// PlanCitationsResolve reports whether every citation in s resolves: every
// evidence key is in validKeys, and the guidance marker is only used where
// there is guidance to point at.
//
// Both halves matter and they fail for different reasons. An evidence key that
// is not in the map is the model asserting something about a measurement it was
// never shown — the same failure the row grammar drops a sentence over. A
// guidance marker with no guidance behind it is OURS: it means the caller sent
// a finding whose kind has no registry guidance, and a citation pointing at
// nothing is worse than no citation because it reads as checked.
//
// A step with NO citation of either kind does not resolve either: this is an
// evidence surface, and "cite or refuse" (D4.4) with nothing cited is refuse.
func PlanCitationsResolve(s string, validKeys map[string]bool, hasGuidance bool) bool {
	refs := EvidenceRefsIn(s)
	cited := CitesGuidance(s)
	if len(refs) == 0 && !cited {
		return false
	}
	if cited && !hasGuidance {
		return false
	}
	for _, ref := range refs {
		if !validKeys[ref] {
			return false
		}
	}
	return true
}

// CollectPlanCitations turns the markers in text into a citation list: each
// distinct evidence key once in order of first appearance, then the guidance
// citation if the text cites it.
//
// DERIVED from the text, like [CollectCitations], so a step cannot cite
// something missing from its list or list something it never mentions.
func CollectPlanCitations(text string) []Citation {
	var out []Citation
	seen := map[string]bool{}
	for _, ref := range EvidenceRefsIn(text) {
		if seen[ref] {
			continue
		}
		seen[ref] = true
		out = append(out, Citation{Kind: CitationKindEvidence, Ref: ref})
	}
	if CitesGuidance(text) {
		out = append(out, Citation{Kind: CitationKindGuidance})
	}
	return out
}

// There is deliberately no StripPlanCitations, unlike its row-grammar sibling
// [StripCitations].
//
// The row grammar's caller (the CBOM comparison narrator, engine.go) needs a
// stripped, plain-prose summary ALONGSIDE the raw text a UI renders as inline
// chips. The plan grammar's one caller does not: the Enterprise remediator's
// `renderPlanNotes` (services/compliance-engine/internal/handlers/
// remediation_draft_handlers.go) deliberately renders an accepted plan's steps
// into a ticket's `notes` field WITH the `[ev:…]`/`[guide]` markers left in,
// because the markers are the checkable part — a step whose evidence
// reference is stripped on the way into the database is a step nobody can
// audit afterwards, and that same text is what a person pastes into an
// external ticket. A `StripPlanCitations` function lived here for a while,
// written symmetrically with [StripCitations] before the remediator settled
// on that answer; it had a doc comment and a test but no caller that wanted
// what it does, and was removed rather than left as an unreachable "just in
// case." If a real plain-prose need for a plan step turns up, write it fresh
// against that need rather than reaching for this comment as a spec.
