package classify

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
)

// Rule kinds. These are the `rule_kind` values of the classification_rules
// table, the CHECK constraint in scripts/database/schema.sql, and the `kinds`
// list in standards/classification-rules.yaml. Adding one is a change in all
// four places at once, which is deliberate: a kind the engine does not match is
// a row nothing reads, and a kind the database refuses is a rule that cannot be
// curated.
const (
	// KindOUI matches the 24-bit IEEE assignment at the front of a MAC
	// address. Pattern: 6 uppercase hex digits, no separators.
	KindOUI = "oui"

	// KindSysObjectID matches an OID prefix under the IANA private-enterprise
	// arc 1.3.6.1.4.1, on ARC BOUNDARIES. Longest prefix wins.
	KindSysObjectID = "sysobjectid"

	// KindENIP matches an ODVA vendor id from an EtherNet/IP List Identity
	// response. Pattern: the id in decimal.
	KindENIP = "enip"

	// KindCloudType matches a cloud provider's own resource type, as the cloud
	// collectors spell it. Pattern: the type, matched case-insensitively.
	KindCloudType = "cloud_type"

	// KindBanner matches an RE2 regexp against every banner the collectors
	// captured. The pattern carries its own anchoring.
	KindBanner = "banner"

	// KindPortProfile matches when EVERY port in an ascending comma-separated
	// list is open.
	KindPortProfile = "port_profile"

	// KindModel matches a case-insensitive PREFIX of the model or product id
	// the device stated. Longest prefix wins. A rule that names a vendor
	// matches only when the input's vendor agrees or is absent.
	KindModel = "model"

	// KindPlatform matches the collector path's own identity for the device —
	// the management API it answered ("panos"), or the profile it was
	// registered under ("cisco_asa"). Exact, case-insensitive.
	KindPlatform = "platform"

	// KindCDPCapabilities matches a SET of Cisco CDP capability names against
	// what a device advertised. Pattern: an ascending comma-separated list
	// ("router,switch"); it matches only when EVERY name is advertised, and
	// only the matching rule(s) naming the MOST capabilities are returned.
	KindCDPCapabilities = "cdp_capabilities"

	// KindLLDPCapability matches IEEE 802.1AB system capabilities the same way
	// [KindCDPCapabilities] matches Cisco's. Two kinds rather than one because
	// the two vocabularies are different words for overlapping ideas — CDP says
	// `switch`, 802.1AB says `bridge`, and they do not mean the same thing (see
	// standards/classification-rules.yaml) — so a rule written for one protocol
	// must not fire on the other's advertisement.
	KindLLDPCapability = "lldp_capability"

	// KindMDNSService matches one mDNS/DNS-SD service type the subject
	// advertises. Pattern: the type in its registry spelling, `_ipp._tcp`.
	// Exact, case-insensitive.
	KindMDNSService = "mdns_service"

	// KindOSName matches an RE2 regexp against the operating system the host
	// named when asked — the `os.name` fact a host inventory writes, or the OS
	// a vendor API reported.
	//
	// It is the only kind whose evidence comes from INSIDE the host rather than
	// from the wire, and that is the point: a general-purpose computer has no
	// OUI, no sysObjectID, no advertised capability and no model string the
	// catalogue could ever enumerate, so every rule kind that existed before
	// this one was blind to the single commonest thing on a corporate network.
	// A Dell XPS running Windows 11 matched nothing and stayed `unknown_host`
	// however much was known about it.
	//
	// A regexp rather than a prefix because an OS name is prose, not an
	// identifier: "Microsoft Windows 11 Pro", "Windows 11 Pro", "Windows Server
	// 2022 Datacenter" and "macOS 15.1" are the same handful of answers spelled
	// by four different collectors, and a prefix rule would have to enumerate
	// the spellings. The pattern carries its own anchoring, like [KindBanner].
	//
	// What it must NOT be used for is a class the OS cannot establish. An OS
	// says a machine is a general-purpose computer; it does not say whether
	// that computer is a desktop, a laptop or a virtual machine, and a rule
	// that picked one would be the wrong class that is worse than no class.
	KindOSName = "os_name"
)

// Kinds is every rule kind, in the order standards/classification-rules.yaml
// declares them.
var Kinds = []string{
	KindOUI, KindSysObjectID, KindENIP, KindCloudType,
	KindBanner, KindPortProfile, KindModel, KindPlatform,
	KindCDPCapabilities, KindLLDPCapability, KindMDNSService, KindOSName,
}

// Confidence bounds. The floor is 0.50 because a rule that is less than even
// money is not a proposal, it is noise in the approval queue. The ceiling is
// 0.95 because nothing in this table is a measurement: every rule is an
// inference from an identifier, and 1.0 would say otherwise.
const (
	MinConfidence = 0.50
	MaxConfidence = 0.95
)

// Rule is one row of classification_rules.
//
// Class, Vendor and Model are each optional and a rule needs at least one of
// them. A rule with a Vendor and no Class is the NORMAL shape for an OUI, not a
// degenerate one: most manufacturers sell across several classes under a single
// assignment, and "a wrong class is worse than none" means the rule stops at
// the vendor rather than picking the most common product.
type Rule struct {
	Kind    string `json:"rule_kind"`
	Pattern string `json:"pattern"`

	// Class is an asset-class key from standards/asset-classes.yaml, or empty.
	Class string `json:"class_key,omitempty"`

	// Vendor is the manufacturer the pattern identifies. For a KindModel rule
	// it is ALSO a guard: when the input names a vendor, it must agree, so a
	// product-id prefix cannot fire on another manufacturer's model string that
	// happens to start the same way.
	Vendor string `json:"vendor,omitempty"`

	// Model is the specific model where the pattern pins one. Rarely set: most
	// patterns identify a family.
	Model string `json:"model,omitempty"`

	// Confidence is what the rule ASSERTS, not how sure we are that the pattern
	// matched — matching is exact. A vendor-only rule carries the confidence of
	// its vendor claim, which is why vendor-only rules sit higher than the
	// class-bearing rules beside them: they assert less.
	Confidence float64 `json:"confidence"`

	// SourceURL is where the mapping comes from. A rule that cannot cite
	// anything is somebody's memory, and this table is read by people who were
	// not in the room.
	//
	// Required of a SHIPPED rule and enforced by the generator, which refuses a
	// row in standards/classification-rules.yaml without one. NOT enforced here,
	// deliberately: an admin adding a rule for their own fleet may have nothing
	// public to point at, and refusing the rule would cost more than the missing
	// citation. The console shows such a rule as "uncited" rather than hiding
	// the gap.
	SourceURL string `json:"source_url,omitempty"`

	// ID is the database row id, empty for a rule from the compiled-in table.
	// It is what the admin console edits and what MatchedRules points at.
	ID string `json:"id,omitempty"`

	// compiled is the banner or os_name regexp, built once at Engine
	// construction. Nil for every other kind.
	compiled *regexp.Regexp

	// ports is the parsed port list for a KindPortProfile rule.
	ports []int

	// capabilities is the parsed capability set for a KindCDPCapabilities or
	// KindLLDPCapability rule.
	capabilities []string
}

// Validate checks one rule's shape and compiles what needs compiling.
//
// It is called for every rule an Engine is built from — the compiled-in table
// AND whatever the database hands back — because a rule that reached the table
// through the admin API, an offline bundle or a hand-run INSERT has not passed
// the generator's validation. An engine that skipped this would match a banner
// rule by panicking on a nil regexp at the first discovery.
func (r *Rule) Validate() error {
	if r.Kind == "" {
		return fmt.Errorf("classify: rule has no kind")
	}
	if !validKind(r.Kind) {
		return fmt.Errorf("classify: rule %s/%s: unknown kind %q", r.Kind, r.Pattern, r.Kind)
	}
	if r.Pattern == "" {
		return fmt.Errorf("classify: %s rule has no pattern", r.Kind)
	}
	if r.Class == "" && r.Vendor == "" && r.Model == "" {
		return fmt.Errorf("classify: rule %s/%s asserts nothing — it needs a class, a vendor or a model", r.Kind, r.Pattern)
	}
	if r.Class != "" {
		if _, ok := assetclass.Get(r.Class); !ok {
			return fmt.Errorf("classify: rule %s/%s proposes class %q, which is not in standards/asset-classes.yaml", r.Kind, r.Pattern, r.Class)
		}
	}
	if r.Confidence < MinConfidence || r.Confidence > MaxConfidence {
		return fmt.Errorf("classify: rule %s/%s has confidence %v, outside %.2f–%.2f",
			r.Kind, r.Pattern, r.Confidence, MinConfidence, MaxConfidence)
	}

	switch r.Kind {
	case KindOUI:
		if len(r.Pattern) != 6 || !isHex(r.Pattern) || r.Pattern != strings.ToUpper(r.Pattern) {
			return fmt.Errorf("classify: oui rule pattern %q must be 6 uppercase hex digits with no separators", r.Pattern)
		}
	case KindSysObjectID:
		if !strings.HasPrefix(r.Pattern, enterprisePrefix) {
			return fmt.Errorf("classify: sysobjectid rule pattern %q must sit under the private-enterprise arc %s", r.Pattern, enterprisePrefix)
		}
		for _, arc := range strings.Split(r.Pattern, ".") {
			if arc == "" || !isDigits(arc) {
				return fmt.Errorf("classify: sysobjectid rule pattern %q is not a dotted decimal OID", r.Pattern)
			}
		}
	case KindENIP:
		if !isDigits(r.Pattern) {
			return fmt.Errorf("classify: enip rule pattern %q must be a decimal ODVA vendor id", r.Pattern)
		}
	case KindBanner, KindOSName:
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return fmt.Errorf("classify: %s rule pattern %q does not compile: %w", r.Kind, r.Pattern, err)
		}
		r.compiled = re
	case KindPortProfile:
		ports, err := parsePortProfile(r.Pattern)
		if err != nil {
			return err
		}
		r.ports = ports
	case KindCDPCapabilities, KindLLDPCapability:
		caps, err := parseCapabilitySet(r.Kind, r.Pattern)
		if err != nil {
			return err
		}
		r.capabilities = caps
	case KindMDNSService:
		if !mdnsServiceType.MatchString(r.Pattern) {
			return fmt.Errorf("classify: mdns_service rule pattern %q must be a DNS-SD service type "+
				"in its registry spelling, lowercase — `_ipp._tcp`, `_printer._tcp`", r.Pattern)
		}
	case KindCloudType, KindModel, KindPlatform:
		if strings.TrimSpace(r.Pattern) != r.Pattern {
			return fmt.Errorf("classify: %s rule pattern %q has leading or trailing whitespace", r.Kind, r.Pattern)
		}
	}
	return nil
}

// mdnsServiceType is the DNS-SD `<Service>.<Proto>` form of RFC 6763 §7: an
// underscore-prefixed service name, then `._tcp` or `._udp`.
//
// Lowercase is REQUIRED rather than folded, for the same reason an `oui`
// pattern must be uppercase: (rule_kind, pattern) is the table's unique index,
// and `_IPP._tcp` beside `_ipp._tcp` would be two rows for one rule that an
// admin could then edit to disagree with each other. Matching is
// case-insensitive, because the wire is not.
var mdnsServiceType = regexp.MustCompile(`^_[a-z0-9][a-z0-9-]*\._(tcp|udp)$`)

// parseCapabilitySet reads "router,switch" into ["router", "switch"].
//
// One capability is a perfectly good pattern — most rules name exactly one —
// which is the difference from parsePortProfile, where a single open port is
// explicitly not a profile. What a set expresses that a single name cannot is
// the COMBINATION: 802.1AB `bridge` alone is ambiguous (a switch bridges, and so
// does an access point and so does a desk phone), while `bridge` with `router`
// is a device doing both, and the honest class for that is their common
// ancestor rather than either leaf.
//
// Ascending and deduplicated is required rather than normalised, so one set has
// exactly one spelling and the unique index means what it says.
func parseCapabilitySet(kind, pattern string) ([]string, error) {
	parts := strings.Split(pattern, ",")
	out := make([]string, 0, len(parts))
	prev := ""
	for _, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("classify: %s rule pattern %q has an empty capability", kind, pattern)
		}
		if !isCapabilityName(p) {
			return nil, fmt.Errorf("classify: %s rule pattern %q: %q is not a capability name "+
				"(lowercase letters, digits and underscores, as the decoder spells it)", kind, pattern, p)
		}
		if prev != "" && p <= prev {
			return nil, fmt.Errorf("classify: %s rule pattern %q must be ascending and deduplicated", kind, pattern)
		}
		prev = p
		out = append(out, p)
	}
	return out, nil
}

func isCapabilityName(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
		default:
			return false
		}
	}
	return len(s) > 0
}

// enterprisePrefix is the IANA private-enterprise arc. Every sysObjectID worth
// a rule sits under it; anything outside is a standard MIB object and does not
// identify a manufacturer.
const enterprisePrefix = "1.3.6.1.4.1."

func validKind(kind string) bool {
	for _, k := range Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return len(s) > 0
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

// parsePortProfile reads "515,9100" into [515, 9100].
//
// Ascending and deduplicated is REQUIRED rather than normalised, so one profile
// has exactly one spelling. The table's unique index is on (rule_kind,
// pattern), and "9100,515" and "515,9100" would otherwise be two rows for one
// rule — each of which an admin could then edit to disagree with the other.
func parsePortProfile(pattern string) ([]int, error) {
	parts := strings.Split(pattern, ",")
	if len(parts) < 2 {
		return nil, fmt.Errorf("classify: port_profile rule pattern %q needs two or more ports — one open port is not a profile", pattern)
	}
	ports := make([]int, 0, len(parts))
	prev := 0
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("classify: port_profile rule pattern %q: %q is not a port number", pattern, p)
		}
		if n < 1 || n > 65535 {
			return nil, fmt.Errorf("classify: port_profile rule pattern %q: port %d is out of range", pattern, n)
		}
		if n <= prev {
			return nil, fmt.Errorf("classify: port_profile rule pattern %q must be ascending and deduplicated", pattern)
		}
		prev = n
		ports = append(ports, n)
	}
	return ports, nil
}

// RuleRef is one rule that matched, as reported back to the caller.
//
// It is a copy rather than a pointer: a proposal is stored and reviewed long
// after the engine that produced it, and a reviewer asking "why does this say
// switch" needs the pattern and the citation that were in force at the time,
// not whatever the rule says now.
type RuleRef struct {
	ID         string  `json:"id,omitempty"`
	Kind       string  `json:"kind"`
	Pattern    string  `json:"pattern"`
	Class      string  `json:"class,omitempty"`
	Vendor     string  `json:"vendor,omitempty"`
	Model      string  `json:"model,omitempty"`
	Confidence float64 `json:"confidence"`
	SourceURL  string  `json:"source_url,omitempty"`
}

func (r Rule) ref() RuleRef {
	return RuleRef{
		ID:         r.ID,
		Kind:       r.Kind,
		Pattern:    r.Pattern,
		Class:      r.Class,
		Vendor:     r.Vendor,
		Model:      r.Model,
		Confidence: r.Confidence,
		SourceURL:  r.SourceURL,
	}
}

// sortRefs orders matched rules highest-confidence first, then by kind and
// pattern so the order is deterministic. Deterministic matters more than it
// looks: MatchedRules is serialised into a stored proposal, and an order that
// depended on map iteration would make two classifications of the same device
// differ byte-for-byte with nothing having changed.
func sortRefs(refs []RuleRef) {
	sort.SliceStable(refs, func(i, j int) bool {
		if refs[i].Confidence != refs[j].Confidence {
			return refs[i].Confidence > refs[j].Confidence
		}
		if refs[i].Kind != refs[j].Kind {
			return refs[i].Kind < refs[j].Kind
		}
		return refs[i].Pattern < refs[j].Pattern
	})
}
