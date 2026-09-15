// Package matcher is the learned matcher of ADR-0008 D1 and D2: a small
// logistic-regression model that scores "are this observation and this existing
// asset the same thing?", ships as weights inside the service image, and runs
// in-process in pure Go.
//
// # What it is for
//
// It does NOT decide identity. The rule-based identification engine
// (shared/identity) decides, on the per-class identifier precedence of
// ADR-0002 D3, and a matcher that could veto a serial-number match would be AI
// in a place ADR-0008 D5 keeps it out of. This model is consulted only on
// ADR-0002 D3's THIRD outcome — the conflict, where the rules have already said
// "these identifiers disagree and a human must settle it" — and its job there is
// to RANK the candidates and say why, so the human reads the strongest
// comparison first instead of an arbitrary one.
//
// Above a threshold the tenant sets deliberately (default zero, meaning never),
// the engine may accept the top-ranked candidate on its own. That is a RULE
// approving, parameterised by the tenant — ADR-0008 D5's "a rule or a human
// approves; a model proposes" — and the guards around it live in the engine,
// not here.
//
// # Why logistic regression
//
// Three properties, all of which something fancier would cost:
//
//   - It is explainable by construction. The score is a sum of signed
//     per-feature contributions, so [Model.Explain] is not a post-hoc
//     approximation of what the model did: it IS what the model did.
//   - It is calibrated. Trained with log-loss on a labelled set, the output
//     reads as a probability — 0.5 is "as likely as not", and a tenant setting
//     a threshold of 0.9 is asking for something meaningful rather than
//     choosing a number on an arbitrary scale.
//   - It is thirty lines of arithmetic with no runtime, so ADR-0008 D2's "pure
//     Go inference path, no network" is satisfied without an ONNX dependency.
//
// # What it may see
//
// The feature vector is an ALLOWLIST, built by [Features] from a [Pair], and
// nothing else reaches the model. No raw metadata, no command output, no
// certificate bytes, no credential, no key material — the whole of the input is
// the ~20 numbers [FeatureNames] lists, every one of them a comparison rather
// than a value. A pair carries identifier values only so the extractor can
// compare them; the values never leave this package and are never serialised
// into an explanation (the explanation names the KIND that matched, not the
// serial number).
//
// # Its dependencies
//
// None outside the standard library and shared/assetclass. It deliberately does
// not import shared/identity: that package imports shared/ai/seams, and the
// seam adapter that registers this model lives in seams, so the import would
// close a cycle. The identifier-kind vocabulary is therefore restated here as
// strings and pinned to shared/identity's by
// TestMatcherKindVocabularyMatchesIdentity, which lives in shared/identity and
// fails if the two ever drift.
package matcher
