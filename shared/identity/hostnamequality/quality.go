// Package hostnamequality ranks host display names so a later observation can
// promote a better measured name onto an existing CI without last-write-wins
// reverting it to a synthetic hex `.local` advertisement.
//
// The identification engine writes hostname / display_name only at create
// unless callers use [ShouldPromote]. Rank, high to low:
//
//  1. Canonical DNS / non-`.local` FQDN that is not an IP-encoded label
//  2. Short DHCP-style hostname (not 12-hex, not UUID, not `none` / `none-N`)
//  3. Human mDNS `.local` (`bobs-macbook-pro.local`, `linux-2.local`)
//  4. Synthetic: 12-hex `.local`, UUID `.local`, `192-168-x-x.local`, bare IP/MAC
//
// Never demote: only replace when incoming quality is strictly higher, or
// quality is equal and identity Reconcile says the incoming source outranks
// the current one (declared > measured-active > measured-passive). Declared
// (a human edit) is never overwritten.
package hostnamequality

import (
	"net"
	"net/netip"
	"regexp"
	"strings"
	"unicode"
)

// Rank is the quality of a host name. Higher is better. RankNone is "not a
// name" — empty, whitespace, or a value that should never become hostname or
// display_name on its own when anything else is available.
type Rank int

const (
	RankNone Rank = iota
	RankSynthetic
	RankHumanLocal
	RankShort
	RankCanonical
)

// IsMDNSLocalName reports whether a qualified name is in the mDNS link-local
// domain (`.local`, RFC 6762 §3). An mDNS name identifies a host only on the
// link it was heard on and must stay a scoped hostname, never an unscoped FQDN.
func IsMDNSLocalName(name string) bool {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	return n == "local" || strings.HasSuffix(n, ".local")
}

// Of returns the quality rank of name.
func Of(name string) Rank {
	n := strings.TrimSpace(name)
	if n == "" {
		return RankNone
	}
	lower := strings.ToLower(strings.TrimSuffix(n, "."))
	if isBareAddressOrMAC(lower) {
		return RankSynthetic
	}
	if IsMDNSLocalName(lower) {
		label := strings.TrimSuffix(lower, ".local")
		if isSyntheticLabel(label) {
			return RankSynthetic
		}
		return RankHumanLocal
	}
	if strings.Contains(lower, ".") {
		if isIPEncodedLabel(strings.Split(lower, ".")[0]) {
			return RankSynthetic
		}
		return RankCanonical
	}
	if isSyntheticLabel(lower) {
		return RankSynthetic
	}
	return RankShort
}

// Best returns the highest-ranked name in names. Equal rank keeps the first
// occurrence. Empty / RankNone names are skipped. The empty string means
// nothing usable was offered.
func Best(names ...string) string {
	best := ""
	bestRank := RankNone
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		r := Of(n)
		if r > bestRank {
			best, bestRank = n, r
		}
	}
	return best
}

// BestHostname is [Best] restricted to values that can be a DNS hostname:
// no spaces. A UniFi alias ("Office Printer") is a display name, not a
// hostname.
func BestHostname(names ...string) string {
	var usable []string
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" || strings.ContainsFunc(n, unicode.IsSpace) {
			continue
		}
		usable = append(usable, n)
	}
	return Best(usable...)
}

// Source labels stored in `assets.metadata.name_source_kind`. They mirror
// ADR-0002 D4's identity table (declared > measured-active > measured-passive)
// without importing package identity — this package is imported FROM identity
// on the match path, so a cycle would compile nothing.
const (
	SourceDeclared        = "declared"
	SourceMeasuredActive  = "measured-active"
	SourceMeasuredPassive = "measured-passive"
	SourceImported        = "imported"
	SourceInferred        = "inferred"
)

// NormalizeSource maps a stored or observation source onto one of the
// constants above. Empty / unknown is measured-passive: that is how first-seen
// names were written before this field existed. ShouldPromote separately
// protects legacy nonsynthetic names whose provenance cannot be established.
func NormalizeSource(label string) string {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case SourceDeclared:
		return SourceDeclared
	case SourceImported:
		return SourceImported
	case SourceInferred:
		return SourceInferred
	case SourceMeasuredActive, "active":
		return SourceMeasuredActive
	default:
		return SourceMeasuredPassive
	}
}

func sourceRank(label string) int {
	switch NormalizeSource(label) {
	case SourceDeclared:
		return 5
	case SourceMeasuredActive:
		return 4
	case SourceMeasuredPassive:
		return 3
	case SourceImported:
		return 2
	case SourceInferred:
		return 1
	default:
		return 0
	}
}

// ShouldPromote reports whether incoming may replace current as the asset's
// hostname / display name.
//
// Never demote. Never overwrite declared. Equal quality defers to identity
// rank (declared > measured-active > measured-passive); equal rank, later wins
// — except a later equal-rank name of LOWER quality already returned false
// above, which is what stops hex `.local` mDNS from reverting `linux-2`.
func ShouldPromote(current, incoming, currentSrc, incomingSrc string) bool {
	incoming = strings.TrimSpace(incoming)
	if incoming == "" {
		return false
	}
	current = strings.TrimSpace(current)
	if current == "" {
		return true
	}
	if NormalizeSource(currentSrc) == SourceDeclared || (strings.TrimSpace(currentSrc) == "" && Of(current) > RankSynthetic) {
		return false
	}
	cr, ir := Of(current), Of(incoming)
	if ir > cr {
		return true
	}
	if ir < cr {
		return false
	}
	if strings.EqualFold(current, incoming) {
		return false
	}
	sr, irk := sourceRank(currentSrc), sourceRank(incomingSrc)
	return irk >= sr
}

var (
	hex12     = regexp.MustCompile(`(?i)^[0-9a-f]{12}$`)
	uuidLike  = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	noneN     = regexp.MustCompile(`(?i)^none(-[0-9]+)?$`)
	ipEncoded = regexp.MustCompile(`^(\d{1,3}-){3}\d{1,3}$`)
)

func isSyntheticLabel(label string) bool {
	label = strings.ToLower(strings.TrimSpace(label))
	if label == "" {
		return true
	}
	if hex12.MatchString(label) || uuidLike.MatchString(label) || noneN.MatchString(label) {
		return true
	}
	if isIPEncodedLabel(label) {
		return true
	}
	return false
}

func isIPEncodedLabel(label string) bool {
	label = strings.ToLower(strings.TrimSpace(label))
	if !ipEncoded.MatchString(label) {
		return false
	}
	dotted := strings.ReplaceAll(label, "-", ".")
	_, err := netip.ParseAddr(dotted)
	return err == nil
}

func isBareAddressOrMAC(n string) bool {
	if _, err := netip.ParseAddr(n); err == nil {
		return true
	}
	if hw, err := net.ParseMAC(n); err == nil && len(hw) == 6 {
		return true
	}
	return false
}
