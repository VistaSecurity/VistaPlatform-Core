// Package strength owns the ordered catalogue cryptographic-strength vocabulary.
// It is independent of numeric risk and severity. Unknown is not a strong grade.
package strength

// Definition is one canonical strength value in ascending order.
type Definition struct {
	Value string `json:"value"`
	Label string `json:"label"`
	Rank  int    `json:"rank"`
}

// Definitions returns a fresh ordered copy of the canonical vocabulary.
func Definitions() []Definition {
	return []Definition{{"weak", "Weak", 0}, {"acceptable", "Acceptable", 1}, {"strong", "Strong", 2}, {"recommended", "Recommended", 3}}
}

// Rank rejects unknown input rather than silently assigning it a grade.
func Rank(value string) (int, bool) {
	for _, d := range Definitions() {
		if d.Value == value {
			return d.Rank, true
		}
	}
	return 0, false
}

// Weakest returns the weakest known component and whether every provided
// component resolved. Callers may retain a known weak verdict despite missing
// components; an incomplete stronger verdict must not be presented as complete.
func Weakest(values ...string) (value string, complete bool) {
	complete = len(values) > 0
	rank := len(Definitions())
	for _, v := range values {
		r, ok := Rank(v)
		if !ok {
			complete = false
			continue
		}
		if r < rank {
			rank = r
			value = v
		}
	}
	return value, complete
}
