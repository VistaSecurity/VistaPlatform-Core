package dispatchguard

// Explicit external targets — a person may scan what they name ( W5.13b).
//
// Owner decision Q10: "we never want to, by default, run a blanket
// scan on third parties but if the customer chooses to scan an IP or block of
// IP's or urls, they have every right to do that and should be able to within
// the system. we don't judge, we enable - without doing it automatically by
// default."
//
// So the MANUAL path gains a third answer beside "in scope" and "refused":
// EXTERNAL — a target outside every network the tenant registered, which is
// scanned only when the person who asked for it confirmed it in the same
// request. What does not move:
//
//   - Reserved and platform-excluded ranges (loopback, link-local and the cloud
//     metadata service, the cluster's own CIDRs and addresses, the tenant's own
//     exclusions) are refused on every path, confirmed or not. That is the
//     SSRF protection #H5 added; consent from a tenant user is not consent from
//     the platform to be scanned.
//   - The automatic path never reaches this code with external allowed:
//     [ManualOptions.PersonInitiated] is false for it, and
//     AuthorizeAutomaticScan is unchanged.
//   - A hostname is judged by EVERY address it resolves to, and the scanner is
//     pinned to exactly the addresses judged (ResolvedTarget.ScanAddresses) —
//     a second DNS answer cannot redirect a checked scan somewhere else.
//   - An operator can switch the whole capability off
//     ([EnvExternalTargetsEnabled]); off is today's behaviour exactly: a target
//     outside the registered networks is refused.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
)

const (
	// EnvExternalTargetsEnabled is the operator's switch for the whole
	// installation. It is parsed as a STRICT boolean and fails CLOSED: only
	// true/1/yes/on turn the capability on; false/0/no/off, an unrecognised
	// value, and an UNSET variable all mean off. The chart and compose files
	// always set it explicitly (default true), so "unset" only happens when
	// something dropped it — and a dropped switch must not mean "scan third
	// parties" ( W5.13b review, item 3).
	EnvExternalTargetsEnabled = "DISCOVERY_EXPLICIT_EXTERNAL_TARGETS_ENABLED"
	// EnvExternalTargetMaxAddresses bounds how many addresses ONE external
	// target (a CIDR, a range) may name. It can be lowered, not raised past
	// [MaxExternalTargetAddresses].
	EnvExternalTargetMaxAddresses = "DISCOVERY_EXTERNAL_TARGET_MAX_ADDRESSES"
	// EnvExternalJobMaxAddresses bounds how many external addresses ONE JOB
	// may name across all its targets. Lowered, not raised past
	// [MaxExternalJobAddresses].
	EnvExternalJobMaxAddresses = "DISCOVERY_EXTERNAL_JOB_MAX_ADDRESSES"

	// DefaultExternalTargetAddresses is an IPv4 /20 or an IPv6 /116.
	DefaultExternalTargetAddresses uint64 = 4096
	// MaxExternalTargetAddresses is the ceiling on the operator's knob. The
	// in-cluster scanner expands at most 4,096 hosts per target
	// (shared/discovery maxSweepHosts), so a larger bound would accept a block
	// and then silently scan only the front of it.
	MaxExternalTargetAddresses uint64 = 4096
	// DefaultExternalJobAddresses / MaxExternalJobAddresses: without a job
	// total, 1,000 targets x 4,096 addresses is ~4.1 million third-party
	// addresses probed from the platform's IP in one request.
	DefaultExternalJobAddresses uint64 = 16384
	MaxExternalJobAddresses     uint64 = 16384
)

// Codes an API answers with, so a client can branch on them rather than on
// message text.
const (
	CodeTargetsRefused              = "targets_refused"
	CodeExternalTargetsUnconfirmed  = "external_targets_unconfirmed"
	CodeExternalTargetsDisabled     = "external_targets_disabled"
	reasonOutsideRegisteredNetworks = "outside the network segments this tenant has registered"
)

// ExternalPolicy is the installation's stance on explicit external targets.
type ExternalPolicy struct {
	Enabled bool
	// MaxAddresses bounds one external target.
	MaxAddresses uint64
	// MaxJobAddresses bounds the external addresses of one job in total.
	// Zero means DefaultExternalJobAddresses.
	MaxJobAddresses uint64
}

func (p ExternalPolicy) jobBound() uint64 {
	if p.MaxJobAddresses == 0 {
		return DefaultExternalJobAddresses
	}
	return p.MaxJobAddresses
}

// ExternalPolicyFromEnv reads the operator's settings. An unparseable or
// out-of-range bound falls back to its default and says so in the log, rather
// than silently meaning "unbounded" or "nothing"; an unrecognised switch value
// means OFF and says so too.
func ExternalPolicyFromEnv() ExternalPolicy {
	p := ExternalPolicy{
		MaxAddresses:    boundFromEnv(EnvExternalTargetMaxAddresses, DefaultExternalTargetAddresses, MaxExternalTargetAddresses),
		MaxJobAddresses: boundFromEnv(EnvExternalJobMaxAddresses, DefaultExternalJobAddresses, MaxExternalJobAddresses),
	}
	raw := os.Getenv(EnvExternalTargetsEnabled)
	enabled, recognised := strictBool(raw)
	if !recognised && strings.TrimSpace(raw) != "" {
		log.Printf("[dispatchguard] %s=%q is not a boolean; explicit external targets are OFF", EnvExternalTargetsEnabled, raw)
	}
	p.Enabled = enabled && recognised
	return p
}

// strictBool recognises the usual spellings and nothing else.
func strictBool(raw string) (value, recognised bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "1", "yes", "on":
		return true, true
	case "false", "0", "no", "off":
		return false, true
	}
	return false, false
}

func boundFromEnv(name string, def, ceiling uint64) uint64 {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def
	}
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || n < 1 || n > ceiling {
		log.Printf("[dispatchguard] %s=%q is not a whole number between 1 and %d; using %d", name, raw, ceiling, def)
		return def
	}
	return n
}

// ManualTarget is one entry a person typed, normalised to what the scanner
// stores: a literal (address, CIDR, a-b range) or a hostname. A URL is reduced
// to its host; an explicit port in it is carried in Port.
type ManualTarget struct {
	Entered string // exactly what was submitted, for messages
	Input   string // the literal or hostname the job stores
	Host    string // non-empty when Input is a hostname
	Port    int    // explicit port from a URL or host:port, 0 when none
}

// ParseManualTarget accepts an IP address, CIDR, a-b range, hostname, host:port
// or URL (`https://host[:port]/path`).
func ParseManualTarget(raw string) (ManualTarget, error) {
	t, reason := parseManualTarget(raw)
	if reason != "" {
		return t, denied(fmt.Sprintf("scan target %q is refused: %s", t.Entered, reason))
	}
	return t, nil
}

// ParseManualTargets parses a whole request, listing EVERY unparseable entry
// in one RefusedTargetsError rather than stopping at the first.
func ParseManualTargets(raws []string) ([]ManualTarget, error) {
	out := make([]ManualTarget, 0, len(raws))
	var refused []RefusedTarget
	for _, raw := range raws {
		t, reason := parseManualTarget(raw)
		if reason != "" {
			refused = append(refused, RefusedTarget{Target: t.Entered, Reason: reason})
			continue
		}
		out = append(out, t)
	}
	if len(refused) > 0 {
		return nil, &RefusedTargetsError{Targets: refused}
	}
	return out, nil
}

func parseManualTarget(raw string) (ManualTarget, string) {
	entered := strings.TrimSpace(raw)
	t := ManualTarget{Entered: entered}
	if entered == "" {
		return t, "the target is empty"
	}
	host, port := entered, ""
	if strings.Contains(entered, "://") {
		u, err := url.Parse(entered)
		if err != nil || u.Hostname() == "" {
			return t, "it is not a valid URL"
		}
		host, port = u.Hostname(), u.Port()
	} else if _, _, ok := targetInterval(entered); !ok {
		// host:port, [v6]:port. A bare literal never reaches here, so an IPv6
		// address's colons are not mistaken for a port.
		if h, p, err := net.SplitHostPort(entered); err == nil && h != "" {
			host, port = h, p
		}
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return t, "it names a port outside 1–65535"
		}
		t.Port = n
	}
	if _, _, ok := targetInterval(host); ok {
		if addr, err := netip.ParseAddr(host); err == nil {
			host = addr.Unmap().String()
		}
		t.Input = host
		return t, ""
	}
	// Two addresses around a hyphen that targetInterval would not take are a
	// broken RANGE, not a hostname — "8.8.8.8-8.8.8.1" is all LDH characters
	// and would otherwise be handed to DNS.
	if a, b, found := strings.Cut(host, "-"); found {
		start, e1 := netip.ParseAddr(strings.TrimSpace(a))
		end, e2 := netip.ParseAddr(strings.TrimSpace(b))
		if e1 == nil && e2 == nil {
			if start.Unmap().Is4() != end.Unmap().Is4() {
				return t, "the range mixes an IPv4 and an IPv6 address"
			}
			return t, "the range ends before it starts"
		}
	}
	name := strings.TrimSuffix(strings.ToLower(host), ".")
	if !validHostname(name) {
		return t, "it is not an IP address, CIDR, range, hostname or URL"
	}
	if reason := platformDNSName(name); reason != "" {
		return t, reason
	}
	t.Input, t.Host = name, name
	return t, ""
}

// platformInternalSuffixes are DNS names that, looked up from inside the
// platform, answer with the platform's OWN addresses: Kubernetes Service
// names and the cloud providers' internal zones.
var platformInternalSuffixes = []string{".svc", ".cluster.local", ".internal", ".localhost"}

// platformDNSName refuses names the platform's resolver would answer from its
// own DNS space. A single-label name is resolved through the pod's search
// domains (web01 → web01.<namespace>.svc.cluster.local), so from the
// platform it means a platform Service, not the tenant's host.
func platformDNSName(name string) string {
	const why = "it can't be scanned from the platform: the platform would look it up in its own DNS (single-label names, *.svc, *.cluster.local, *.internal); use the full public name or the address"
	if !strings.Contains(name, ".") {
		return why
	}
	for _, suffix := range platformInternalSuffixes {
		if strings.HasSuffix(name, suffix) || name == strings.TrimPrefix(suffix, ".") {
			return why
		}
	}
	return ""
}

// validHostname is the LDH rule: letters, digits and hyphens, labels of 1–63
// characters that neither start nor end with a hyphen, 253 characters in all.
// It is also exactly the character set the scanner will hand to nmap.
func validHostname(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			letter := ch >= 'a' && ch <= 'z'
			digit := ch >= '0' && ch <= '9'
			if !letter && !digit && ch != '-' {
				return false
			}
		}
	}
	return true
}

// Resolver is the slice of *net.Resolver this package uses; a test supplies a
// stub so rebinding can be staged deterministically.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// ResolvedTarget is a ManualTarget with, for a hostname, every address it
// resolved to at the moment of authorization.
type ResolvedTarget struct {
	ManualTarget
	Resolved []netip.Addr
}

// ScanAddresses are the addresses a hostname target is PINNED to: the ones the
// scanner connects to, all of which were authorized. IPv4 is preferred when the
// name has any, matching shared/discovery.ExpandTargets, so pinning does not
// change which family a scan reaches. Nil for a literal target.
func (t ResolvedTarget) ScanAddresses() []string {
	if t.Host == "" {
		return nil
	}
	var v4, v6 []string
	for _, a := range t.Resolved {
		if a.Is4() {
			v4 = append(v4, a.String())
		} else {
			v6 = append(v6, a.String())
		}
	}
	if len(v4) > 0 {
		return v4
	}
	return v6
}

// ResolveManualTargets resolves every hostname target once. It runs OUTSIDE any
// transaction — a DNS lookup must not be held inside one. A name that does not
// resolve is refused: an unauthorizable target is not an authorized one.
func ResolveManualTargets(ctx context.Context, r Resolver, targets []ManualTarget) ([]ResolvedTarget, error) {
	out := make([]ResolvedTarget, 0, len(targets))
	var unresolved []RefusedTarget
	for _, t := range targets {
		rt := ResolvedTarget{ManualTarget: t}
		if t.Host != "" {
			addrs, err := r.LookupNetIP(ctx, "ip", t.Host)
			if err != nil || len(addrs) == 0 {
				unresolved = append(unresolved, RefusedTarget{Target: t.Entered, Reason: "the name could not be resolved, so there is no address to check"})
				continue
			}
			seen := map[netip.Addr]bool{}
			for _, a := range addrs {
				a = a.Unmap().WithZone("")
				if a.IsValid() && !seen[a] {
					seen[a] = true
					rt.Resolved = append(rt.Resolved, a)
				}
			}
			sort.Slice(rt.Resolved, func(i, j int) bool { return rt.Resolved[i].Less(rt.Resolved[j]) })
		}
		out = append(out, rt)
	}
	if len(unresolved) > 0 {
		return nil, &RefusedTargetsError{Targets: unresolved}
	}
	return out, nil
}

// ManualOptions is what the caller knows about the request itself.
type ManualOptions struct {
	Policy ExternalPolicy
	// Confirmed is the request's explicit `external_targets_confirmed` flag.
	Confirmed bool
	// PersonInitiated is true only for a scan a person asked for. Automatic,
	// identity-enrichment and service-to-service jobs set it false, and for
	// them a target outside the registered networks is refused whatever the
	// flag says.
	PersonInitiated bool
}

// ExternalTarget is a confirmed target outside the registered networks, with
// the addresses it named at authorization time — what the audit event records.
type ExternalTarget struct {
	Target    string   `json:"target"`
	Addresses []string `json:"addresses"`
	// Count is how many addresses this target reaches, as counted against the
	// job bound (a literal's size, a name's pinned addresses). Not on the wire.
	Count uint64 `json:"-"`
}

// ExternalAddressTotal is a job's external-address total, as AuthorizeManual
// counted it. The job records it so a scan still queued when an operator
// LOWERS the job bound is stopped at dispatch (review N2).
func ExternalAddressTotal(external []ExternalTarget) uint64 {
	var total uint64
	for _, e := range external {
		total += e.Count
	}
	return total
}

// DispatchConsent is what a job recorded when a person confirmed its external
// targets: the confirmed ranges/addresses and their total. The zero value is
// "no consent".
type DispatchConsent struct {
	Ranges         []string
	TotalAddresses uint64
}

// RefusedTarget is a target that can never be scanned as entered, and why.
type RefusedTarget struct {
	Target string `json:"target"`
	Reason string `json:"reason"`
}

// RefusedTargetsError lists every refused target, not just the first, so a
// person can fix the whole list at once. errors.Is(err, ErrDenied) holds.
type RefusedTargetsError struct{ Targets []RefusedTarget }

func (e *RefusedTargetsError) Error() string {
	parts := make([]string, 0, len(e.Targets))
	for _, t := range e.Targets {
		parts = append(parts, fmt.Sprintf("scan target %q is refused: %s", t.Target, t.Reason))
	}
	return ErrDenied.Error() + ": " + strings.Join(parts, "; ")
}

func (e *RefusedTargetsError) Unwrap() error { return ErrDenied }

// ExternalTargetsError is the answer for targets outside the registered
// networks that are not refused outright: either the request did not carry the
// confirmation (Code = CodeExternalTargetsUnconfirmed) or the operator switched
// the capability off (CodeExternalTargetsDisabled). errors.Is(err, ErrDenied)
// holds.
type ExternalTargetsError struct {
	Code    string
	Targets []ExternalTarget
}

func (e *ExternalTargetsError) Error() string {
	names := make([]string, 0, len(e.Targets))
	for _, t := range e.Targets {
		names = append(names, fmt.Sprintf("%q", t.Target))
	}
	if e.Code == CodeExternalTargetsDisabled {
		return fmt.Sprintf("%s: %d scan target(s) are %s (%s), and this installation's operator has turned off scanning targets outside them",
			ErrDenied.Error(), len(e.Targets), reasonOutsideRegisteredNetworks, strings.Join(names, ", "))
	}
	return fmt.Sprintf("%s: %d scan target(s) are outside your registered networks (%s); confirm them to scan",
		ErrDenied.Error(), len(e.Targets), strings.Join(names, ", "))
}

func (e *ExternalTargetsError) Unwrap() error { return ErrDenied }

// targetClass is the verdict on one interval.
type targetClass int

const (
	classInScope targetClass = iota
	classExternal
	classExcluded
)

// classify judges one closed interval. Exclusions first — nothing a tenant
// declared, and nothing a person confirms, puts them back in scope.
func (s TargetScope) classify(lo, hi netip.Addr) (targetClass, string) {
	if lo.Is6() && overlapsMappedBlock(lo, hi) {
		return classExcluded, "the range crosses the IPv4-mapped block (::ffff:0:0/96); name the IPv4 addresses instead"
	}
	for _, p := range s.excluded {
		if intervalsOverlap(lo, hi, p) {
			if why, ok := reservedReason(p.Masked()); ok {
				return classExcluded, why
			}
			return classExcluded, "the range is excluded from scanning (a range your organization excluded, a network segment marked sensitive, or the platform's own addresses)"
		}
	}
	// 6to4 / Teredo: the IPv4 address inside is judged by the same exclusions.
	if embedded, judgeable, ok := embeddedIPv4Interval(lo, hi); ok {
		if !judgeable {
			return classExcluded, "a 6to4 or Teredo range that cannot be checked address by address; name the addresses, or the IPv4 addresses they carry"
		}
		for _, iv := range embedded {
			for _, p := range s.excluded {
				if intervalsOverlap(iv[0], iv[1], p) {
					return classExcluded, "it carries an IPv4 address (6to4/Teredo) that can never be scanned"
				}
			}
		}
	}
	for _, p := range append(append([]netip.Prefix{}, s.allowed...), privatePrefixes...) {
		if p.Contains(lo) && p.Contains(hi) {
			return classInScope, ""
		}
	}
	return classExternal, ""
}

// mappedLo/mappedHi bound ::ffff:0.0.0.0/96 as plain IPv6 addresses.
var (
	mappedLo = netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff})
	mappedHi = netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 12: 0xff, 13: 0xff, 14: 0xff, 15: 0xff})
)

// overlapsMappedBlock catches an IPv6 interval whose endpoints are both
// outside the mapped block but which spans it — the one shape targetInterval's
// unmapping cannot see.
func overlapsMappedBlock(lo, hi netip.Addr) bool {
	return !hi.Less(mappedLo) && !mappedHi.Less(lo)
}

// intervalSize reports the number of addresses in [lo,hi], saturating at
// max+1 so a /0 does not need 128-bit arithmetic to be refused.
func intervalSize(lo, hi netip.Addr, max uint64) uint64 {
	a, b := lo.As16(), hi.As16()
	// hi - lo as a 128-bit big-endian subtraction; only the low 64 bits matter
	// once the high 64 are known to be zero.
	var diff [16]byte
	borrow := 0
	for i := 15; i >= 0; i-- {
		d := int(b[i]) - int(a[i]) - borrow
		borrow = 0
		if d < 0 {
			d += 256
			borrow = 1
		}
		diff[i] = byte(d)
	}
	for i := 0; i < 8; i++ {
		if diff[i] != 0 {
			return max + 1
		}
	}
	var low uint64
	for i := 8; i < 16; i++ {
		low = low<<8 | uint64(diff[i])
	}
	if low >= max {
		return max + 1
	}
	return low + 1
}

// AuthorizeManual judges every target of a person-initiated (or not) manual
// scan and returns the targets that are EXTERNAL and allowed — the ones the
// caller must audit. It refuses, in this order:
//
//  1. anything that can never be scanned as entered (reserved or excluded
//     ranges, a hostname resolving to one, an external block over the size
//     bound), all of them listed — RefusedTargetsError;
//  2. external targets on a request that is not a person's — RefusedTargetsError
//     with today's "outside the network segments" reason;
//  3. external targets when the operator switched the capability off —
//     ExternalTargetsError{CodeExternalTargetsDisabled};
//  4. external targets without the confirmation flag —
//     ExternalTargetsError{CodeExternalTargetsUnconfirmed}.
func (s TargetScope) AuthorizeManual(targets []ResolvedTarget, opts ManualOptions) ([]ExternalTarget, error) {
	if len(targets) == 0 {
		return nil, denied("scan dispatch names no targets")
	}
	var refused []RefusedTarget
	var external []ExternalTarget
	// externalAddresses is how many addresses outside the registered networks
	// this job would reach in total — bounded per job, not only per target
	// ( W5.13b review, item 4). Saturating: a literal's size is capped at
	// the job bound plus one before it is added.
	var externalAddresses uint64
	jobBound := opts.Policy.jobBound()
	for _, t := range targets {
		name := t.Entered
		if name == "" {
			name = t.Input
		}
		if t.Host != "" {
			if len(t.Resolved) == 0 {
				refused = append(refused, RefusedTarget{Target: name, Reason: "the name did not resolve to any address"})
				continue
			}
			// A refused name's reason does NOT say what it resolved to: that
			// would turn this API into a resolver for the platform's internal
			// DNS ( W5.13b review, item 6).
			isExternal, bad := false, ""
			addrs := make([]string, 0, len(t.Resolved))
			for _, a := range t.Resolved {
				addrs = append(addrs, a.String())
				switch class, _ := s.classify(a, a); class {
				case classExcluded:
					bad = "it resolves to an address the platform never scans (reserved, the platform's own, or excluded by your organization)"
				case classExternal:
					isExternal = true
				}
			}
			if bad != "" {
				refused = append(refused, RefusedTarget{Target: name, Reason: bad})
			} else if isExternal {
				external = append(external, ExternalTarget{Target: name, Addresses: addrs, Count: uint64(len(t.ScanAddresses()))})
				externalAddresses += uint64(len(t.ScanAddresses()))
			}
			continue
		}
		lo, hi, ok := targetInterval(t.Input)
		if !ok {
			refused = append(refused, RefusedTarget{Target: name, Reason: "it is not an IP address, CIDR, range, hostname or URL"})
			continue
		}
		class, why := s.classify(lo, hi)
		switch class {
		case classExcluded:
			refused = append(refused, RefusedTarget{Target: name, Reason: why})
		case classExternal:
			if opts.PersonInitiated && opts.Policy.Enabled && intervalSize(lo, hi, opts.Policy.MaxAddresses) > opts.Policy.MaxAddresses {
				refused = append(refused, RefusedTarget{Target: name, Reason: fmt.Sprintf(
					"a target outside your registered networks may name at most %d addresses; split the block or register it as a network segment", opts.Policy.MaxAddresses)})
				continue
			}
			external = append(external, ExternalTarget{Target: name, Addresses: []string{t.Input}, Count: intervalSize(lo, hi, jobBound)})
			externalAddresses += intervalSize(lo, hi, jobBound)
		}
	}
	if len(refused) > 0 {
		return nil, &RefusedTargetsError{Targets: refused}
	}
	if len(external) == 0 {
		return nil, nil
	}
	if opts.PersonInitiated && opts.Policy.Enabled && externalAddresses > jobBound {
		out := make([]RefusedTarget, 0, len(external))
		for _, e := range external {
			out = append(out, RefusedTarget{Target: e.Target, Reason: fmt.Sprintf(
				"together, the targets outside your registered networks name more than %d addresses, the most one scan may reach; split them across scans", jobBound)})
		}
		return nil, &RefusedTargetsError{Targets: out}
	}
	if !opts.PersonInitiated {
		out := make([]RefusedTarget, 0, len(external))
		for _, e := range external {
			out = append(out, RefusedTarget{Target: e.Target, Reason: reasonOutsideRegisteredNetworks})
		}
		return nil, &RefusedTargetsError{Targets: out}
	}
	if !opts.Policy.Enabled {
		return nil, &ExternalTargetsError{Code: CodeExternalTargetsDisabled, Targets: external}
	}
	if !opts.Confirmed {
		return nil, &ExternalTargetsError{Code: CodeExternalTargetsUnconfirmed, Targets: external}
	}
	return external, nil
}

// AuthorizeManualTargets loads the tenant's scope inside the caller's
// transaction and judges targets against it. See [TargetScope.AuthorizeManual].
func AuthorizeManualTargets(tx Queryer, tenantID string, targets []ResolvedTarget, opts ManualOptions) ([]ExternalTarget, error) {
	if len(targets) == 0 {
		return nil, denied("scan dispatch names no targets")
	}
	scope, err := LoadTargetScope(tx, tenantID)
	if err != nil {
		return nil, err
	}
	return scope.AuthorizeManual(targets, opts)
}

// AuthorizeDispatchAddresses is the re-check at the moment of scanning, over
// the EXPANDED addresses a packet will be sent to. confirmed is what the job
// recorded when a person confirmed its external targets: the ranges and
// addresses they confirmed, nothing wider. The operator switch is read again
// now, so turning it off stops queued external work too.
func AuthorizeDispatchAddresses(tx Queryer, tenantID string, addresses []string, consent DispatchConsent) error {
	if len(addresses) == 0 {
		return denied("scan dispatch names no targets")
	}
	scope, err := LoadTargetScope(tx, tenantID)
	if err != nil {
		return err
	}
	return scope.AuthorizeDispatch(addresses, consent, ExternalPolicyFromEnv())
}

// AuthorizeDispatch judges expanded addresses at scan time.
//
// Consent covers exactly what was confirmed ( W5.13b review, item 5): an
// address outside the registered networks passes only when it lies inside one
// of the confirmed ranges/addresses AND the operator switch is on NOW. A job
// with no confirmation is exactly [TargetScope.Authorize] per address. And an
// address that was inside a registered segment when the job was created, but
// is not any more, is not rescued by the job's consent for OTHER targets —
// that is the case a job-wide "confirmed" flag let through.
func (s TargetScope) AuthorizeDispatch(addresses []string, grant DispatchConsent, policy ExternalPolicy) error {
	type interval struct{ lo, hi netip.Addr }
	var consent []interval
	for _, c := range grant.Ranges {
		if lo, hi, ok := targetInterval(c); ok {
			consent = append(consent, interval{lo, hi})
		}
	}
	// covering returns the confirmed range an address lies in.
	covering := func(a netip.Addr) (interval, bool) {
		for _, iv := range consent {
			if iv.lo.Is4() == a.Is4() && !a.Less(iv.lo) && !iv.hi.Less(a) {
				return iv, true
			}
		}
		return interval{}, false
	}
	// The bounds are the operator's CURRENT ones (review N2): lowering either
	// stops external work that was queued under the old limits.
	overJobBound := grant.TotalAddresses > policy.jobBound()
	if len(addresses) == 0 {
		return denied("scan dispatch names no targets")
	}
	var refused []RefusedTarget
	var disabled []ExternalTarget
	for _, raw := range addresses {
		lo, hi, ok := targetInterval(raw)
		if !ok || lo != hi {
			refused = append(refused, RefusedTarget{Target: raw, Reason: "it is not a single address"})
			continue
		}
		switch class, why := s.classify(lo, hi); class {
		case classExcluded:
			refused = append(refused, RefusedTarget{Target: raw, Reason: why})
		case classExternal:
			iv, ok := covering(lo)
			switch {
			case !ok:
				refused = append(refused, RefusedTarget{Target: raw, Reason: reasonOutsideRegisteredNetworks + ", and not among the targets confirmed for this scan"})
			case !policy.Enabled:
				disabled = append(disabled, ExternalTarget{Target: raw, Addresses: []string{raw}})
			case overJobBound:
				refused = append(refused, RefusedTarget{Target: raw, Reason: fmt.Sprintf(
					"this scan reaches %d addresses outside your registered networks; the operator's limit is now %d per scan", grant.TotalAddresses, policy.jobBound())})
			case intervalSize(iv.lo, iv.hi, policy.MaxAddresses) > policy.MaxAddresses:
				refused = append(refused, RefusedTarget{Target: raw, Reason: fmt.Sprintf(
					"the confirmed target it belongs to is larger than the operator's current limit of %d addresses per target", policy.MaxAddresses)})
			}
		}
	}
	if len(refused) > 0 {
		return &RefusedTargetsError{Targets: refused}
	}
	if len(disabled) > 0 {
		return &ExternalTargetsError{Code: CodeExternalTargetsDisabled, Targets: disabled}
	}
	return nil
}

// ExternalLiterals returns the literal targets (address, CIDR, range) that are
// outside the tenant's registered networks and not refused outright — the ones
// that would need a person's confirmation. Names and unparseable values are
// not judged here; the dispatch API judges everything authoritatively. For a
// caller that wants to ask BEFORE it changes anything (inventory-service's
// per-asset Active Scan).
func (s TargetScope) ExternalLiterals(targets []string) []string {
	var out []string
	for _, t := range targets {
		lo, hi, ok := targetInterval(t)
		if !ok {
			continue
		}
		if class, _ := s.classify(lo, hi); class == classExternal {
			out = append(out, t)
		}
	}
	return out
}

// ConfirmedRanges flattens what a job recorded as confirmed into the list
// AuthorizeDispatch takes.
func ConfirmedRanges(external []ExternalTarget) []string {
	var out []string
	for _, e := range external {
		out = append(out, e.Addresses...)
	}
	return out
}

// IsExternalTargetsError reports whether err is an ExternalTargetsError and
// returns it.
func IsExternalTargetsError(err error) (*ExternalTargetsError, bool) {
	var e *ExternalTargetsError
	ok := errors.As(err, &e)
	return e, ok
}

// IsRefusedTargetsError reports whether err is a RefusedTargetsError and
// returns it.
func IsRefusedTargetsError(err error) (*RefusedTargetsError, bool) {
	var e *RefusedTargetsError
	ok := errors.As(err, &e)
	return e, ok
}
