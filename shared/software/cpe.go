package software

import (
	"errors"
	"strings"
)

// ErrInvalidCPE is returned by [NormalizeCPE] for a string that is neither a
// CPE 2.3 formatted string nor a convertible CPE 2.2 URI. It wraps a more
// specific message naming which rule failed.
var ErrInvalidCPE = errors.New("software: invalid cpe")

// cpeAttributeCount is the number of attributes a CPE 2.3 formatted string
// carries after the `cpe:2.3:` prefix: part, vendor, product, version, update,
// edition, language, sw_edition, target_sw, target_hw, other.
const cpeAttributeCount = 11

// NormalizeCPE validates a CPE and returns it as a CPE 2.3 formatted string,
// converting a CPE 2.2 URI first when it is given one.
//
// Both forms turn up in real SBOMs: SPDX `externalRefs` define both a
// `cpe23Type` and a `cpe22Type` reference type, and tools emit whichever their
// source had. Storing both spellings in one column would mean two catalogue
// rows for one product and a vulnerability match that hits only one of them,
// so the 2.2 form is converted rather than accepted alongside.
//
// # Conversion (CPE 2.3 naming spec §6.1.3, "unbinding a URI")
//
//	cpe:/a:openssl:openssl:3.0.13  →  cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*
//
// An absent or empty URI component becomes the ANY logical value `*`; a `-`
// stays `-` (NA). Percent-encoded octets are decoded; the 2.2 encodings `%01`
// and `%02` are the wildcards `?` and `*` and are decoded as wildcards rather
// than as literals. A packed extended edition — `~ed~sw_ed~tgt_sw~tgt_hw~oth`
// in the sixth component — is unpacked into the four 2.3 attributes the 2.2
// grammar had nowhere else to put.
//
// # Validation, and one documented deviation from the letter of the spec
//
// A formatted string must have exactly 13 colon-separated fields (`cpe`, `2.3`
// and the eleven attributes), a part of `a`, `o`, `h`, `*` or `-`, and no
// empty attribute. Splitting is escape-aware: a `\:` inside a value is part of
// the value, not a separator.
//
// The spec's bind_value_for_fs quotes EVERY non-alphanumeric character except
// underscore, which would make `3\.0\.13` the only conformant spelling of a
// version. NVD's own CPE dictionary publishes `cpe:2.3:a:openssl:openssl:3.0.13:*:...`
// with unescaped periods, and so does every tool that consumes it. A validator
// that rejected those would reject every CPE anyone will ever paste, so
// unescaped `.`, `-` and `_` are accepted. This is a deliberate widening of
// the accept set, not an oversight; the narrow direction is the one that would
// silently empty the column.
func NormalizeCPE(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", wrapCPE("empty")
	}

	lower := strings.ToLower(s)
	switch {
	case strings.HasPrefix(lower, "cpe:2.3:"):
		return validateCPE23(s)
	case strings.HasPrefix(lower, "cpe:/"):
		return convertCPE22(s)
	default:
		return "", wrapCPE("not a cpe:2.3: formatted string or a cpe:/ URI")
	}
}

// validateCPE23 checks a formatted string and returns it with the `cpe:2.3`
// prefix lowercased (the only case-normalisation the form allows: attribute
// values are case-insensitive per the spec but are conventionally published
// lowercase, and re-casing them would change strings a feed matches on).
func validateCPE23(s string) (string, error) {
	fields := splitEscaped(s, ':')
	if len(fields) != cpeAttributeCount+2 {
		return "", wrapCPE("a formatted string has 13 colon-separated fields, got " + itoa(len(fields)))
	}
	if !strings.EqualFold(fields[0], "cpe") || fields[1] != "2.3" {
		return "", wrapCPE("prefix is not cpe:2.3")
	}
	if !validCPEPart(fields[2]) {
		return "", wrapCPE("part must be a, o, h, * or -")
	}
	for i, f := range fields[2:] {
		if f == "" {
			return "", wrapCPE("attribute " + itoa(i+1) + " is empty; an unspecified attribute is * or -, never blank")
		}
		if err := validCPEValue(f); err != nil {
			return "", err
		}
	}

	// `part` is defined lowercase; everything after it is left exactly as the
	// source wrote it, because attribute values are what a vulnerability feed
	// string-matches on and re-casing them would change the match.
	out := append([]string{"cpe", "2.3", strings.ToLower(fields[2])}, fields[3:]...)
	return strings.Join(out, ":"), nil
}

// validCPEValue rejects characters the formatted-string grammar cannot carry
// unquoted. See the deviation note on [NormalizeCPE] for why `.`, `-` and `_`
// are on the accepted side of this.
func validCPEValue(v string) error {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '\\' {
			// A backslash quotes the next character, whatever it is. A
			// trailing backslash quotes nothing and is malformed.
			if i+1 >= len(v) {
				return wrapCPE("value ends in a dangling backslash")
			}
			i++
			continue
		}
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '.' || c == '-' || c == '_',
			c == '*' || c == '?':
		default:
			return wrapCPE("unquoted special character " + describeByte(c) + " in a value")
		}
	}
	return nil
}

func validCPEPart(p string) bool {
	switch p {
	case "a", "o", "h", "*", "-", "A", "O", "H":
		return true
	default:
		return false
	}
}

// convertCPE22 unbinds a CPE 2.2 URI into a 2.3 formatted string.
func convertCPE22(s string) (string, error) {
	body := s[len("cpe:/"):]
	comps := strings.Split(body, ":")
	if len(comps) > 7 {
		return "", wrapCPE("a 2.2 URI has at most 7 components, got " + itoa(len(comps)))
	}

	attrs := make([]string, cpeAttributeCount)
	for i := range attrs {
		attrs[i] = "*"
	}

	// A 2.2 URI's components map onto the first seven 2.3 attributes in order:
	// part, vendor, product, version, update, edition, language.
	for i, c := range comps {
		if i == 5 && strings.HasPrefix(c, "~") {
			// Packed extended attributes. The 2.2 grammar had no home for
			// sw_edition/target_sw/target_hw/other, so tools packed them into
			// the edition component separated by tildes. Unpacking them is the
			// difference between "edition = ~~~windows~~" (meaningless) and
			// target_sw = windows (matchable).
			packed := strings.Split(strings.TrimPrefix(c, "~"), "~")
			if len(packed) != 5 {
				return "", wrapCPE("packed edition must have 5 tilde-separated parts, got " + itoa(len(packed)))
			}
			// edition, sw_edition, target_sw, target_hw, other →
			// attribute indexes 5, 7, 8, 9, 10.
			for j, idx := range []int{5, 7, 8, 9, 10} {
				v, err := decodeCPE22Component(packed[j])
				if err != nil {
					return "", err
				}
				attrs[idx] = v
			}
			continue
		}
		v, err := decodeCPE22Component(c)
		if err != nil {
			return "", err
		}
		attrs[i] = v
	}

	if !validCPEPart(attrs[0]) {
		return "", wrapCPE("part must be a, o, h, * or -")
	}
	return validateCPE23("cpe:2.3:" + strings.Join(attrs, ":"))
}

// decodeCPE22Component percent-decodes one URI component and re-quotes it for
// the formatted-string grammar.
func decodeCPE22Component(c string) (string, error) {
	if c == "" {
		// An unspecified 2.2 component is ANY. This is the single most common
		// shape — `cpe:/a:vendor:product` leaves four of them empty — and
		// mapping it to "" instead of "*" is what produces the 13-field string
		// with blank attributes that validateCPE23 rejects.
		return "*", nil
	}
	if c == "-" {
		return "-", nil
	}

	var b strings.Builder
	for i := 0; i < len(c); i++ {
		ch := c[i]
		if ch != '%' {
			b.WriteString(quoteCPEChar(ch))
			continue
		}
		if i+2 >= len(c) {
			return "", wrapCPE("truncated percent escape")
		}
		hi, lo := unhex(c[i+1]), unhex(c[i+2])
		if hi < 0 || lo < 0 {
			return "", wrapCPE("bad percent escape")
		}
		i += 2
		switch decoded := byte(hi<<4 | lo); decoded {
		case 0x01:
			// 2.2 spelled the single-character wildcard `?` as %01.
			b.WriteByte('?')
		case 0x02:
			// …and the multi-character wildcard `*` as %02.
			b.WriteByte('*')
		default:
			b.WriteString(quoteCPEChar(decoded))
		}
	}
	return b.String(), nil
}

// quoteCPEChar emits one character in formatted-string form: alphanumerics and
// the three punctuation characters the published dictionary leaves bare pass
// through; everything else printable is backslash-quoted.
func quoteCPEChar(c byte) string {
	switch {
	case c >= 'a' && c <= 'z',
		c >= 'A' && c <= 'Z',
		c >= '0' && c <= '9',
		c == '.' || c == '-' || c == '_':
		return string([]byte{c})
	default:
		return `\` + string([]byte{c})
	}
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	default:
		return -1
	}
}

// splitEscaped splits on sep, treating a backslash as quoting the next byte.
// A plain strings.Split would cut `foo\:bar` in half, which is how a value
// containing a quoted colon turns one CPE into a 14-field parse error.
func splitEscaped(s string, sep byte) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			cur.WriteByte(c)
			cur.WriteByte(s[i+1])
			i++
			continue
		}
		if c == sep {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	out = append(out, cur.String())
	return out
}

func wrapCPE(reason string) error {
	return errWrap(ErrInvalidCPE, reason)
}
