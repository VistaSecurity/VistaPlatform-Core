package ast

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// The compact JSON encoding is the cross-language shape of the tree. It is what
// testdata/conformance.json records, so a TypeScript port can be held to the
// same trees as the Go parser. It is deliberately lossless about the things
// that change meaning — quoting, negation form, traversal form — and silent
// about the things that do not, notably spans.
//
//	and      {"and":[node, …]}
//	or       {"or":[node, …]}
//	not      {"not":node}
//	cmp      {"cmp":{"f":field,"op":op,"v":literal}}
//	in       {"in":{"f":field,"v":[literal, …],"neg":bool}}   (neg omitted when false)
//	range    {"range":{"f":field,"lo":literal,"hi":literal}}
//	match    {"match":{"f":field,"re":string}}
//	exists   {"exists":{"f":field}}
//	text     {"text":literal}
//	sub      {"sub":{"c":collection,"p":node}}                (p omitted for exists(c))
//	traverse {"traverse":{"form":form,"rel":name,"t":type,"dir":dir,"depth":int,"p":node}}
//
// A literal encodes as a JSON string when it was bare, and as {"s":string}
// when it was quoted.

// JSON returns the compact encoding of n as plain Go values.
func JSON(n Node) any {
	switch t := n.(type) {
	case nil:
		return nil
	case *And:
		return map[string]any{"and": childJSON(t.Children)}
	case *Or:
		return map[string]any{"or": childJSON(t.Children)}
	case *Not:
		return map[string]any{"not": JSON(t.Child)}
	case *Compare:
		return map[string]any{"cmp": map[string]any{
			"f": t.Field.Text, "op": string(t.Op), "v": literalJSON(t.Value),
		}}
	case *InSet:
		vals := make([]any, 0, len(t.Values))
		for _, v := range t.Values {
			vals = append(vals, literalJSON(v))
		}
		m := map[string]any{"f": t.Field.Text, "v": vals}
		if t.Negated {
			m["neg"] = true
		}
		return map[string]any{"in": m}
	case *Range:
		return map[string]any{"range": map[string]any{
			"f": t.Field.Text, "lo": literalJSON(t.Lo), "hi": literalJSON(t.Hi),
		}}
	case *Match:
		return map[string]any{"match": map[string]any{"f": t.Field.Text, "re": t.Regex}}
	case *Exists:
		return map[string]any{"exists": map[string]any{"f": t.Field.Text}}
	case *FreeText:
		// Free text is a substring search over a fixed column set (§5.4), so a
		// "*" in it is an ordinary character and quoting changes nothing. The
		// encoding says so, rather than recording a distinction the semantics
		// do not have. It is not date-canonicalised either — free text can
		// never be an instant, so `now-24h` is the eight characters it looks
		// like (see QuoteFreeText).
		return map[string]any{"text": t.Value.Value}
	case *Sub:
		m := map[string]any{"c": t.Collection}
		if t.Predicate != nil {
			m["p"] = JSON(t.Predicate)
		}
		return map[string]any{"sub": m}
	case *Traverse:
		m := map[string]any{
			"form":  string(t.Form),
			"rel":   t.Name,
			"dir":   string(t.Direction),
			"depth": t.Depth,
			"p":     JSON(t.Predicate),
		}
		if t.Type != "" {
			m["t"] = t.Type
		}
		return map[string]any{"traverse": m}
	default:
		panic(fmt.Sprintf("query/ast: unknown node type %T", n))
	}
}

func childJSON(children []Node) []any {
	out := make([]any, 0, len(children))
	for _, c := range children {
		out = append(out, JSON(c))
	}
	return out
}

// literalJSON encodes a literal. Quoting is lexical, not semantic — `plain` and
// `"plain"` are the same value — with one exception: a quoted value containing
// `*` is a literal asterisk where a bare one is a wildcard, so that case is
// marked. Relative dates are encoded canonically, so `now-24h` and `now-1d`
// are one tree.
func literalJSON(l Literal) any {
	if l.Form == LitString && strings.Contains(l.Value, "*") {
		return map[string]any{"s": l.Value}
	}
	return CanonicalText(l)
}

// MarshalJSON renders the compact encoding with sorted keys (encoding/json
// sorts map keys), so two runs produce byte-identical output.
func MarshalJSON(n Node) ([]byte, error) {
	return json.Marshal(JSON(n))
}

// EqualJSON reports whether two nodes have the same compact encoding. Spans are
// not part of the encoding, so this is tree equality modulo source position.
func EqualJSON(a, b Node) bool {
	ja, err := MarshalJSON(a)
	if err != nil {
		return false
	}
	jb, err := MarshalJSON(b)
	if err != nil {
		return false
	}
	return bytes.Equal(ja, jb)
}
