package ast

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// LiteralForm distinguishes a quoted string from a bare run of value
// characters. It is load-bearing: `*` is a wildcard only when bare (§3), and
// the formatter quotes a value iff it is not a safe bareword (§10).
type LiteralForm string

const (
	// LitBare is an unquoted value.
	LitBare LiteralForm = "bare"
	// LitString is a quoted value; escapes are already decoded in Value.
	LitString LiteralForm = "string"
)

// Literal is a value as written in the query. Classification into number,
// duration, date and so on happens at validation time against the field's
// declared type, never at parse time — the same text is a number for one field
// and a keyword for another.
type Literal struct {
	Form  LiteralForm
	Value string
	Sp    Span
}

// IsWildcard reports whether the literal carries a `*` metacharacter, which
// only a bare literal can (§3).
func (l Literal) IsWildcard() bool {
	return l.Form == LitBare && strings.Contains(l.Value, "*")
}

// IsBareStar reports whether the literal is exactly `*`, the "present at all"
// spelling of exists (§3 cheat sheet).
func (l Literal) IsBareStar() bool {
	return l.Form == LitBare && l.Value == "*"
}

// ParseNumber parses a number literal per §2: an optional sign, digits, and an
// optional fractional part. No exponents in v1.
func ParseNumber(s string) (float64, bool) {
	if s == "" {
		return 0, false
	}
	body := strings.TrimPrefix(s, "-")
	if body == "" {
		return 0, false
	}
	dots := 0
	for _, r := range body {
		switch {
		case r >= '0' && r <= '9':
		case r == '.':
			dots++
			if dots > 1 {
				return 0, false
			}
		default:
			return 0, false
		}
	}
	if strings.HasPrefix(body, ".") || strings.HasSuffix(body, ".") {
		return 0, false
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return f, true
}

// ParseBool parses the two boolean literals. `t` and `yes` are deliberately not
// accepted (§2).
func ParseBool(s string) (bool, bool) {
	switch strings.ToLower(s) {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}

// DurationUnit is one of the seven duration units. `mo` and `y` are calendar
// units; the rest are exact multiples of a second.
type DurationUnit string

const (
	// UnitSecond is `s`.
	UnitSecond DurationUnit = "s"
	// UnitMinute is `m`.
	UnitMinute DurationUnit = "m"
	// UnitHour is `h`.
	UnitHour DurationUnit = "h"
	// UnitDay is `d`.
	UnitDay DurationUnit = "d"
	// UnitWeek is `w`.
	UnitWeek DurationUnit = "w"
	// UnitMonth is `mo`, calendar arithmetic.
	UnitMonth DurationUnit = "mo"
	// UnitYear is `y`, calendar arithmetic.
	UnitYear DurationUnit = "y"
)

// durationAliases maps every accepted spelling to its unit. Longest match wins,
// so `mo` is months and `m` is minutes.
var durationAliases = map[string]DurationUnit{
	"s": UnitSecond, "sec": UnitSecond, "secs": UnitSecond, "second": UnitSecond, "seconds": UnitSecond,
	"m": UnitMinute, "min": UnitMinute, "mins": UnitMinute, "minute": UnitMinute, "minutes": UnitMinute,
	"h": UnitHour, "hr": UnitHour, "hrs": UnitHour, "hour": UnitHour, "hours": UnitHour,
	"d": UnitDay, "day": UnitDay, "days": UnitDay,
	"w": UnitWeek, "week": UnitWeek, "weeks": UnitWeek,
	"mo": UnitMonth, "month": UnitMonth, "months": UnitMonth,
	"y": UnitYear, "year": UnitYear, "years": UnitYear,
}

// Duration is a parsed duration literal: a signed count of one unit.
type Duration struct {
	Count int64
	Unit  DurationUnit
}

// MaxDurationYears bounds a duration literal, in years (§13 A5).
//
// Without a bound, `now-200000d` is 1.7e10 seconds, and
// `time.Duration(count) * time.Second` overflows int64 — so "two hundred
// thousand days ago" silently WRAPPED to an instant in the future, and
// `last_seen < now-200000d` returned every asset instead of none. A bound plus
// checked arithmetic is the fix; a century is far past any inventory's
// retention and well inside what time.Duration can hold.
const MaxDurationYears = 100

// maxCountPerUnit is MaxDurationYears expressed in each unit.
var maxCountPerUnit = map[DurationUnit]int64{
	UnitSecond: MaxDurationYears * 365 * 24 * 60 * 60,
	UnitMinute: MaxDurationYears * 365 * 24 * 60,
	UnitHour:   MaxDurationYears * 365 * 24,
	UnitDay:    MaxDurationYears * 365,
	UnitWeek:   MaxDurationYears * 365 / 7,
	UnitMonth:  MaxDurationYears * 12,
	UnitYear:   MaxDurationYears,
}

// ParseDuration parses a duration literal (§2). The unit is required; a bare
// number is a number, not a duration. A count past MaxDurationYears is
// refused, so the validator reports type_mismatch rather than the arithmetic
// wrapping silently.
func ParseDuration(s string) (Duration, bool) {
	if s == "" {
		return Duration{}, false
	}
	i := 0
	if s[0] == '-' || s[0] == '+' {
		i = 1
	}
	start := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == start || i == len(s) {
		return Duration{}, false
	}
	n, err := strconv.ParseInt(s[:i], 10, 64)
	if err != nil {
		return Duration{}, false
	}
	unit, ok := durationAliases[strings.ToLower(s[i:])]
	if !ok {
		return Duration{}, false
	}
	d := Duration{Count: n, Unit: unit}
	if !d.WithinBounds() {
		return Duration{}, false
	}
	return d, true
}

// WithinBounds reports whether d is inside MaxDurationYears. ParseDuration
// enforces it, but Duration is an ordinary struct anyone can construct, and
// Apply must not wrap for one that was not parsed.
func (d Duration) WithinBounds() bool {
	max, ok := maxCountPerUnit[d.Unit]
	if !ok {
		return false
	}
	return d.Count <= max && d.Count >= -max
}

// secondsPerUnit gives the exact second count of the non-calendar units, and 0
// for the calendar ones.
var secondsPerUnit = map[DurationUnit]int64{
	UnitSecond: 1,
	UnitMinute: 60,
	UnitHour:   3600,
	UnitDay:    86400,
	UnitWeek:   604800,
}

// exactLadder is walked largest-first when canonicalising a duration.
var exactLadder = []DurationUnit{UnitWeek, UnitDay, UnitHour, UnitMinute, UnitSecond}

// Canonical returns the duration written in the largest unit that represents it
// exactly (§10: `24h` → `1d`; `90d` stays `90d`). Calendar units convert only
// between themselves (12mo → 1y), never to or from days, because a month is
// not a fixed number of days.
func (d Duration) Canonical() Duration {
	switch d.Unit {
	case UnitMonth:
		if d.Count%12 == 0 {
			return Duration{Count: d.Count / 12, Unit: UnitYear}
		}
		return d
	case UnitYear:
		return d
	}
	secs := d.Count * secondsPerUnit[d.Unit]
	for _, u := range exactLadder {
		per := secondsPerUnit[u]
		if secs%per == 0 {
			return Duration{Count: secs / per, Unit: u}
		}
	}
	return d
}

// String renders the duration in its own unit.
func (d Duration) String() string {
	return strconv.FormatInt(d.Count, 10) + string(d.Unit)
}

// Apply adds the duration to t, using UTC arithmetic for s/m/h/d/w and calendar
// arithmetic for mo/y (§5.5). Calendar arithmetic clamps to the last day of the
// target month, matching Postgres rather than Go's AddDate, which overflows
// (Postgres: - 1 month =; Go: the same, but
// - 1 month is in Postgres and in Go).
func (d Duration) Apply(t time.Time) time.Time {
	if !d.WithinBounds() {
		// Checked, not silently wrapped: a caller that built a Duration by
		// hand and overflowed it gets the unmodified instant rather than one
		// that landed on the other side of "now". ParseDuration refuses these
		// before they reach here.
		return t
	}
	if per, ok := secondsPerUnit[d.Unit]; ok {
		return t.Add(time.Duration(d.Count*per) * time.Second)
	}
	months := d.Count
	if d.Unit == UnitYear {
		months *= 12
	}
	return addMonthsClamped(t, months)
}

// addMonthsClamped adds n months to t, clamping the day of month to the last
// valid day of the resulting month.
func addMonthsClamped(t time.Time, n int64) time.Time {
	year, month, day := t.Date()
	total := int(month) - 1 + int(n)
	newYear := year + floorDiv(total, 12)
	newMonth := time.Month(floorMod(total, 12) + 1)
	if last := daysInMonth(newYear, newMonth); day > last {
		day = last
	}
	h, m, s := t.Clock()
	return time.Date(newYear, newMonth, day, h, m, s, t.Nanosecond(), t.Location())
}

func floorDiv(a, b int) int {
	q := a / b
	if a%b != 0 && (a < 0) != (b < 0) {
		q--
	}
	return q
}

func floorMod(a, b int) int { return a - floorDiv(a, b)*b }

func daysInMonth(year int, month time.Month) int {
	return time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

// DateLiteral is a parsed date or timestamp literal. Relative dates carry the
// `now` anchor and at most one duration term (§2: no chaining).
type DateLiteral struct {
	// Relative is true for `now`, `now-30d`, `now+7d`.
	Relative bool
	// Offset is the single ± term; zero when the literal is bare `now`.
	Offset Duration
	// HasOffset distinguishes `now` from `now+0d`.
	HasOffset bool
	// Absolute is the parsed instant for a non-relative literal.
	Absolute time.Time
	// DateOnly records that the source was `` with no time part.
	DateOnly bool
}

// dateLayouts are the accepted absolute spellings (§2: ISO 8601).
var dateLayouts = []struct {
	layout   string
	dateOnly bool
}{
	{"2006-01-02", true},
	{"2006-01-02T15:04:05Z07:00", false},
	{"2006-01-02T15:04:05", false},
	{"2006-01-02T15:04Z07:00", false},
	{"2006-01-02T15:04", false},
}

// ParseDate parses a date literal. It accepts exactly one ± duration term after
// `now`; `now-1mo-15d` is rejected (§11 Q5).
func ParseDate(s string) (DateLiteral, bool) {
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "now") {
		rest := lower[len("now"):]
		if rest == "" {
			return DateLiteral{Relative: true}, true
		}
		if rest[0] != '+' && rest[0] != '-' {
			return DateLiteral{}, false
		}
		sign := int64(1)
		if rest[0] == '-' {
			sign = -1
		}
		term := rest[1:]
		// Exactly one term: a second sign anywhere in the remainder is a chain.
		if strings.ContainsAny(term, "+-") {
			return DateLiteral{}, false
		}
		d, ok := ParseDuration(term)
		if !ok || d.Count < 0 {
			return DateLiteral{}, false
		}
		d.Count *= sign
		return DateLiteral{Relative: true, Offset: d, HasOffset: true}, true
	}
	for _, l := range dateLayouts {
		if t, err := time.Parse(l.layout, s); err == nil {
			return DateLiteral{Absolute: t.UTC(), DateOnly: l.dateOnly}, true
		}
	}
	return DateLiteral{}, false
}

// Resolve turns the literal into an instant. now is the statement timestamp,
// evaluated once per query (§5.5).
func (d DateLiteral) Resolve(now time.Time) time.Time {
	if !d.Relative {
		return d.Absolute
	}
	if !d.HasOffset {
		return now
	}
	return d.Offset.Apply(now)
}

// String renders the date literal in canonical form.
func (d DateLiteral) String() string {
	if d.Relative {
		if !d.HasOffset {
			return "now"
		}
		c := d.Offset.Canonical()
		if c.Count < 0 {
			return "now-" + Duration{Count: -c.Count, Unit: c.Unit}.String()
		}
		return "now+" + c.String()
	}
	if d.DateOnly {
		return d.Absolute.Format("2006-01-02")
	}
	return d.Absolute.Format("2006-01-02T15:04:05Z")
}

// ParseUUID reports whether s is a canonical 8-4-4-4-12 hex uuid.
func ParseUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !isHex(byte(r)) {
				return false
			}
		}
	}
	return true
}

func isHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// ParseInet reports whether s is an IPv4/IPv6 address or CIDR block, and
// whether it carries a prefix length. The check is deliberately structural
// rather than net.ParseIP-based so the error message can name what was wrong.
func ParseInet(s string) (isCIDR bool, ok bool) {
	host := s
	if i := strings.LastIndex(s, "/"); i >= 0 {
		host = s[:i]
		prefix := s[i+1:]
		n, err := strconv.Atoi(prefix)
		if err != nil || prefix == "" || n < 0 {
			return false, false
		}
		max := 32
		if strings.Contains(host, ":") {
			max = 128
		}
		if n > max {
			return false, false
		}
		isCIDR = true
	}
	if strings.Contains(host, ":") {
		return isCIDR, isIPv6(host)
	}
	return isCIDR, isIPv4(host)
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

func isIPv6(s string) bool {
	if strings.Count(s, "::") > 1 {
		return false
	}
	groups := strings.Split(strings.ReplaceAll(s, "::", ":"), ":")
	seen := 0
	for _, g := range groups {
		if g == "" {
			continue
		}
		if len(g) > 4 {
			return false
		}
		for i := 0; i < len(g); i++ {
			if !isHex(g[i]) {
				return false
			}
		}
		seen++
	}
	if strings.Contains(s, "::") {
		return seen <= 8
	}
	return seen == 8
}

// QuoteValue renders v as a query literal, quoting it iff it is not a safe
// bareword (§10). The canonical quote is `"`.
func QuoteValue(v string) string {
	if IsSafeBareword(v) {
		return v
	}
	return Quote(v)
}

// Quote renders v as a double-quoted string with §2's escapes, whether or not
// it would also be safe bare.
func Quote(v string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range v {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// CanonicalText returns a literal's value in canonical form: a relative date is
// rewritten into the largest unit that represents it exactly (§10, `24h` →
// `1d`), and everything else is returned verbatim.
//
// Both the formatter and the compact JSON encoding go through this, so two
// spellings of the same instant produce the same canonical text AND the same
// encoded tree. Without that, Format would be a rewrite the round-trip test
// could not see through.
func CanonicalText(l Literal) string {
	// A QUOTED literal is never rewritten. The formatter is type-free, so it
	// cannot tell a date from a string that looks like one — and
	// `hostname="now-24h"` is a hostname, not an instant. Rewriting it to
	// `hostname=now-1d` changed the stored predicate into a different one that
	// still parsed, which is the worst shape a formatter bug can take.
	//
	// The bare form carries no such ambiguity: `now±<duration>` is a date in
	// every catalogue that accepts it at all, and quoting is exactly how a user
	// says "I mean the text".
	if l.Form != LitBare {
		return l.Value
	}
	if !strings.HasPrefix(strings.ToLower(l.Value), "now") {
		return l.Value
	}
	// Only a literal that actually carries a duration is rewritten. A bare
	// `now` is left exactly as written, because the formatter does not know
	// the field's type and `noW` on a case-sensitive comparison is a different
	// value from `now` — whereas anything of the shape now±<duration> is a
	// date in every catalogue that accepts it at all.
	if d, ok := ParseDate(l.Value); ok && d.Relative && d.HasOffset {
		return d.String()
	}
	return l.Value
}

// QuoteLiteral renders a literal in canonical form.
//
// A quoted literal keeps its quotes whenever dropping them would change what
// the text means rather than how it is spelled. Two cases:
//
//   - it contains `*`, which bare would be a wildcard rather than an asterisk;
//   - it is shaped like `now±<duration>`, which bare is a relative date and is
//     then rewritten into the largest exact unit (§10). `hostname="now-24h"`
//     unquoting to `hostname=now-24h` and then to `hostname=now-1d` is a
//     different predicate that still parses — see S7.
func QuoteLiteral(l Literal) string {
	if l.Form == LitString && (strings.Contains(l.Value, "*") || isRelativeDateText(l.Value)) {
		return Quote(l.Value)
	}
	return QuoteValue(CanonicalText(l))
}

// isRelativeDateText reports whether text bare would parse as `now±<duration>`
// — the one literal shape the formatter rewrites.
func isRelativeDateText(v string) bool {
	if !strings.HasPrefix(strings.ToLower(v), "now") {
		return false
	}
	d, ok := ParseDate(v)
	return ok && d.Relative && d.HasOffset
}

// bareValueChars is the bare-value character set from §2.
const bareValueChars = "_.:/%*@+#-"

// IsBareValueChar reports whether r may appear in a bare value.
func IsBareValueChar(r rune) bool {
	if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
		return true
	}
	return strings.ContainsRune(bareValueChars, r)
}

// IsSafeBareword reports whether v can be written without quotes: every rune is
// a bare-value character and it is not a keyword that would re-lex as one.
func IsSafeBareword(v string) bool {
	if v == "" {
		return false
	}
	for _, r := range v {
		if !IsBareValueChar(r) {
			return false
		}
	}
	return !IsKeyword(v)
}

// keywords are the reserved words (§2). A value spelled like one must be
// quoted so it reparses as a value.
var keywords = map[string]bool{
	"and": true, "or": true, "not": true, "in": true,
	"to": true, "exists": true,
}

// IsKeyword reports whether s is a reserved word, case-insensitively.
func IsKeyword(s string) bool { return keywords[strings.ToLower(s)] }

// IsSafeFreeText reports whether a free-text value can be written without
// quotes and still re-lex as free text.
//
// It is stricter than IsSafeBareword because a free-text term sits where a
// field could: `a:b` is a perfectly good bare VALUE but, written on its own, it
// is a field and a value, and `web.01` is the beginning of a field path. A
// value that starts like an identifier and carries a "." or a ":" is therefore
// quoted in canonical form — the alternative is a canonical form that means
// something else when it is read back.
func IsSafeFreeText(v string) bool {
	if !IsSafeBareword(v) {
		return false
	}
	r := rune(v[0])
	if r == '-' {
		// A leading "-" is negation at the start of a term, so `-0` would come
		// back as `not 0`.
		return false
	}
	if r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
		return true
	}
	// The leading identifier run is lexed on its own at the start of a term, so
	// a value like `not#` would come back as a negation of `#`.
	if IsKeyword(leadingIdentifier(v)) {
		return false
	}
	return !strings.ContainsAny(v, ".:")
}

// leadingIdentifier returns the run of identifier characters v starts with.
func leadingIdentifier(v string) string {
	i := 0
	for i < len(v) {
		c := v[i]
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			i++
			continue
		}
		break
	}
	return v[:i]
}

// QuoteFreeText renders a free-text literal in canonical form. Unlike a value,
// a free-text "*" is an ordinary character (§5.4 is a substring search), so
// quoting is purely lexical here and the two spellings mean the same thing.
//
// Free text is never date-canonicalised. §5.4 is a substring search over names,
// identifiers and tags — it can never be an instant — so rewriting `now-24h` to
// `now-1d` would change what is searched for. (It also had to go: quoting is
// lexical here, so a quoted free-text literal loses its quotes in canonical
// form, and a rule that rewrote only the bare form could not be idempotent.)
func QuoteFreeText(l Literal) string {
	if IsSafeFreeText(l.Value) {
		return l.Value
	}
	return Quote(l.Value)
}

// IsIdentifier reports whether s matches the identifier production (§2).
func IsIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
