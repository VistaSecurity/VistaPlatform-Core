package matcher

import "strings"

// Two string similarities, both hand-written and both pure Go, because a
// dependency for forty lines of arithmetic is a dependency to audit, pin and
// carry into the public tree forever.
//
// They answer different questions and the extractor takes the LARGER of the
// two, because either one being high is evidence:
//
//   - [TokenJaccard] asks "are these made of the same parts?" — it is what
//     recognises `db01.corp.example.com` and `db01` as the same host seen by two
//     collectors that disagree about whether to qualify a name.
//   - [JaroWinkler] asks "is one of these a typo or a truncation of the other?"
//     — it is what recognises `esx-prod-04` and `esxprod04`, and it deliberately
//     favours a shared PREFIX, which is how naming conventions work.
//
// Neither is allowed to reach 1.0 on the pair `web01` / `web02`: that pair is
// the single commonest false positive in an inventory and the fixtures label it
// negative, so the trained weight has to earn the separation rather than the
// similarity function faking it. Jaro-Winkler scores it about 0.93 and token
// Jaccard 0.0, which is exactly why the extractor also feeds
// [FeatureNameTrailingDigitsDiffer] as its own feature.

// normaliseName lowercases, strips a trailing dot, and turns the separators a
// hostname may use into spaces so the token forms agree.
func normaliseName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	return s
}

// nameTokens splits a name into its parts on the separators hostnames use.
// `db01.corp.example.com` → [db01 corp example com].
func nameTokens(s string) []string {
	fields := strings.FieldsFunc(normaliseName(s), func(r rune) bool {
		switch r {
		case '.', '-', '_', ' ', '/', ':':
			return true
		}
		return false
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// TokenJaccard is the size of the intersection over the size of the union of
// the two names' token sets, 0..1.
//
// Two empty names score 0, not 1. "Neither of these has a name" is not evidence
// that they are the same thing, and scoring it 1 would make every pair of
// unnamed assets look like a certain match — which is the class of bug this
// codebase keeps finding (an absence rendered as an answer).
func TokenJaccard(a, b string) float64 {
	ta, tb := nameTokens(a), nameTokens(b)
	if len(ta) == 0 || len(tb) == 0 {
		return 0
	}
	seen := make(map[string]bool, len(ta))
	for _, t := range ta {
		seen[t] = true
	}
	inter := 0
	inB := make(map[string]bool, len(tb))
	for _, t := range tb {
		if inB[t] {
			continue
		}
		inB[t] = true
		if seen[t] {
			inter++
		}
	}
	union := len(seen) + len(inB) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

// JaroWinkler is the Jaro-Winkler similarity of two names, 0..1, with the
// standard prefix scale 0.1 over at most four leading characters.
//
// Two empty strings score 0, for the same reason [TokenJaccard] does.
func JaroWinkler(a, b string) float64 {
	s1, s2 := []rune(normaliseName(a)), []rune(normaliseName(b))
	if len(s1) == 0 || len(s2) == 0 {
		return 0
	}
	j := jaro(s1, s2)
	if j <= 0 {
		return 0
	}
	// The prefix bonus applies only to pairs that are already similar; the
	// standard threshold is 0.7, and without it a pair sharing four leading
	// characters and nothing else gets a bonus it has not earned.
	if j < 0.7 {
		return j
	}
	prefix := 0
	for prefix < 4 && prefix < len(s1) && prefix < len(s2) && s1[prefix] == s2[prefix] {
		prefix++
	}
	return j + float64(prefix)*0.1*(1-j)
}

func jaro(s1, s2 []rune) float64 {
	if len(s1) == 0 || len(s2) == 0 {
		return 0
	}
	// The match window of the Jaro definition: half the longer string, minus
	// one. A window below zero (both strings of length one) means "same
	// position only".
	window := max(len(s1), len(s2))/2 - 1
	if window < 0 {
		window = 0
	}
	m1 := make([]bool, len(s1))
	m2 := make([]bool, len(s2))
	matches := 0
	for i := range s1 {
		lo := max(0, i-window)
		hi := min(len(s2)-1, i+window)
		for k := lo; k <= hi; k++ {
			if m2[k] || s1[i] != s2[k] {
				continue
			}
			m1[i], m2[k] = true, true
			matches++
			break
		}
	}
	if matches == 0 {
		return 0
	}
	// Transpositions: matched characters that are out of order relative to each
	// other, counted in halves as the definition does.
	transpositions := 0
	k := 0
	for i := range s1 {
		if !m1[i] {
			continue
		}
		for !m2[k] {
			k++
		}
		if s1[i] != s2[k] {
			transpositions++
		}
		k++
	}
	m := float64(matches)
	return (m/float64(len(s1)) + m/float64(len(s2)) + (m-float64(transpositions)/2)/m) / 3
}

// NameSimilarity is what the extractor uses: the larger of the two measures.
func NameSimilarity(a, b string) float64 {
	return max(TokenJaccard(a, b), JaroWinkler(a, b))
}

// trailingDigits returns the run of digits at the end of a name's FIRST token,
// and whether there was one. `web01.corp.example.com` → "01", true.
//
// The first token only: `host.v2.example.com` must not be read as ending in 2.
func trailingDigits(s string) (string, bool) {
	toks := nameTokens(s)
	if len(toks) == 0 {
		return "", false
	}
	t := toks[0]
	i := len(t)
	for i > 0 && t[i-1] >= '0' && t[i-1] <= '9' {
		i--
	}
	if i == len(t) {
		return "", false
	}
	return t[i:], true
}

// sequentialNames reports that two names differ ONLY in a trailing number —
// `web01` and `web02`, `esx-prod-04` and `esx-prod-05`.
//
// This is the commonest false positive an inventory produces: sequentially
// named machines built from one template are maximally similar by every string
// measure and are emphatically not the same thing. It is a feature of its own so
// the model can be trained to subtract for it, rather than hoping the
// similarity measure happens to separate them — it does not.
func sequentialNames(a, b string) bool {
	na, oka := trailingDigits(a)
	nb, okb := trailingDigits(b)
	if !oka || !okb || na == nb {
		return false
	}
	stemA := strings.TrimSuffix(nameTokens(a)[0], na)
	stemB := strings.TrimSuffix(nameTokens(b)[0], nb)
	if stemA == "" || stemA != stemB {
		return false
	}
	// The rest of the name — the domain — must also agree, or these are two
	// differently-numbered hosts in two different places and the SEGMENT
	// features are the ones with something to say.
	return strings.Join(nameTokens(a)[1:], ".") == strings.Join(nameTokens(b)[1:], ".")
}
