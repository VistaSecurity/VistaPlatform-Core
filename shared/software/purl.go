package software

import (
	"errors"
	"sort"
	"strings"
)

// ErrInvalidPURL is returned by [NormalizePURL] for a string that is not a
// Package URL. It wraps a more specific message naming which rule failed.
var ErrInvalidPURL = errors.New("software: invalid purl")

// lowercaseNamespaceTypes are the purl types whose spec rules say the
// namespace is case-insensitive and must be lowercased.
//
// The set is deliberately not "all of them". The purl spec makes namespace
// case-sensitivity a PER-TYPE rule, and getting it wrong is asymmetric: a
// namespace left in mixed case produces a duplicate catalogue row, which is
// visible and repairable, while a case-sensitive namespace folded to lower
// case MERGES two different products into one row, which is neither. Maven
// group ids and generic namespaces are case-sensitive and are left alone.
//
// Source: the "Known purl types" rules in the purl specification.
var lowercaseNamespaceTypes = map[string]bool{
	"bitbucket": true,
	"composer":  true,
	"github":    true,
	"golang":    true,
	"hex":       true,
	"npm":       true,
	"pypi":      true,
}

// NormalizePURL parses a Package URL and returns it in canonical form.
//
// What it normalises, and why each part is load-bearing for a string that is
// used as a DEDUPE KEY:
//
//   - The `pkg` scheme and the type are lowercased. Both are case-insensitive
//     per the spec, so `PKG:NPM/left-pad` and `pkg:npm/left-pad` are the same
//     package and must produce the same key.
//   - Leading slashes after the scheme are stripped (`pkg://npm/x`), which the
//     spec calls out as a tolerated-but-non-canonical spelling.
//   - The namespace is lowercased only for the types whose rules say so; see
//     [lowercaseNamespaceTypes].
//   - Qualifier keys are lowercased and the qualifiers sorted by key, because
//     `?arch=x86_64&os=linux` and `?OS=linux&arch=x86_64` are the same package
//     and an unsorted key would make them two rows. A qualifier with an empty
//     value is discarded, per the spec.
//
// What it deliberately does NOT do:
//
//   - It does not percent-decode or re-encode. The canonical form keeps
//     components percent-encoded, and a decode/re-encode round trip through a
//     different escaping table would change the string — which, for an
//     identity key, is the one thing it must not do.
//   - It does not apply the per-type NAME rules (pypi folding `_` to `-`,
//     github lowercasing the name). Those are a larger per-type table and are
//     scoped out of workstream 2.6a; the consequence is a possible duplicate
//     row for a name-case variant, which is the recoverable direction of the
//     asymmetry described above.
func NormalizePURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", wrapPURL("empty")
	}

	// Subpath, then qualifiers, then scheme — right to left, exactly the order
	// the spec's parsing algorithm prescribes, because a '#' or '?' appearing
	// later would otherwise be read as part of a name.
	var subpath string
	if i := strings.Index(s, "#"); i >= 0 {
		s, subpath = s[:i], s[i+1:]
	}
	var qualifiers string
	if i := strings.Index(s, "?"); i >= 0 {
		s, qualifiers = s[:i], s[i+1:]
	}

	scheme, rest, ok := strings.Cut(s, ":")
	if !ok {
		return "", wrapPURL("no scheme separator")
	}
	if !strings.EqualFold(strings.TrimSpace(scheme), "pkg") {
		return "", wrapPURL("scheme is not pkg")
	}
	rest = strings.TrimLeft(rest, "/")

	typ, rest, ok := strings.Cut(rest, "/")
	if !ok {
		return "", wrapPURL("no type separator")
	}
	typ = strings.ToLower(typ)
	if !validPURLType(typ) {
		return "", wrapPURL("type is not a valid purl type")
	}

	// Version splits from the RIGHT: a namespace may legitimately contain '@'
	// percent-encoded, and an npm scope is written `@scope` in some tooling.
	var version string
	if i := strings.LastIndex(rest, "@"); i > 0 {
		rest, version = rest[:i], rest[i+1:]
	}

	var namespace, name string
	if i := strings.LastIndex(rest, "/"); i >= 0 {
		namespace, name = rest[:i], rest[i+1:]
	} else {
		name = rest
	}
	if name == "" {
		return "", wrapPURL("no name")
	}
	namespace = strings.Trim(namespace, "/")
	if lowercaseNamespaceTypes[typ] {
		namespace = strings.ToLower(namespace)
	}

	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(typ)
	b.WriteString("/")
	if namespace != "" {
		b.WriteString(namespace)
		b.WriteString("/")
	}
	b.WriteString(name)
	if version != "" {
		b.WriteString("@")
		b.WriteString(version)
	}
	if q := canonicalQualifiers(qualifiers); q != "" {
		b.WriteString("?")
		b.WriteString(q)
	}
	if subpath != "" {
		b.WriteString("#")
		b.WriteString(strings.Trim(subpath, "/"))
	}
	return b.String(), nil
}

// canonicalQualifiers lowercases each key, drops empty-valued pairs, and sorts
// by key. Returns "" when nothing survives.
func canonicalQualifiers(raw string) string {
	if raw == "" {
		return ""
	}
	pairs := make([]string, 0, 4)
	for _, part := range strings.Split(raw, "&") {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" || value == "" {
			// The spec: "a key=value pair with an empty value is not valid and
			// should be discarded". Keeping it would make `?arch=` and no
			// qualifier at all two different identities for one package.
			continue
		}
		pairs = append(pairs, key+"="+value)
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// validPURLType applies the spec's type grammar: an ASCII letter, period,
// plus or dash to start, then letters, digits, periods, pluses and dashes.
func validPURLType(typ string) bool {
	if typ == "" {
		return false
	}
	for i := 0; i < len(typ); i++ {
		c := typ[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
			if i == 0 {
				return false
			}
		case c == '.' || c == '+' || c == '-':
		default:
			return false
		}
	}
	return true
}

func wrapPURL(reason string) error {
	return errWrap(ErrInvalidPURL, reason)
}
