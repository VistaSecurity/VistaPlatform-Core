package discovery

import (
	"fmt"
	"math/big"
	"net"
	"strings"
)

// CodeScanTargetTooLarge is the machine-readable code an API answers with when
// a job names more addresses than the scanner will expand, so a client can
// branch on it rather than on message text.
const CodeScanTargetTooLarge = "scan_target_too_large"

// MaxTargetAddresses is how many addresses ONE target (a CIDR or a range) may
// name. It is the bound ExpandTargets stops at; a target above it used to be
// scanned only up to its first MaxTargetAddresses addresses while the job still
// ended "completed". It is refused up front instead.
const MaxTargetAddresses = maxSweepHosts

// MaxJobAddresses is how many addresses all of a job's targets may name
// together. It matches the job bound already applied to targets outside a
// tenant's registered networks (dispatchguard.MaxExternalJobAddresses), so
// registered and unregistered space follow one rule.
const MaxJobAddresses = 16384

// OversizeTarget is one target that names more addresses than a scan allows.
type OversizeTarget struct {
	Target string
	// Addresses is the exact count as a decimal string: an IPv6 /0 names 2^128
	// addresses, which no integer type a JSON client reads can hold.
	Addresses string
}

// TargetTooLargeError reports targets the scanner cannot fully expand. Targets
// is non-empty when individual targets exceed Limit; when it is empty the job's
// TOTAL (JobAddresses) exceeds JobLimit.
type TargetTooLargeError struct {
	Targets      []OversizeTarget
	Limit        uint64
	JobAddresses string
	JobLimit     uint64
}

func (e *TargetTooLargeError) Error() string {
	if len(e.Targets) == 0 {
		return fmt.Sprintf("the targets together name %s addresses, and one scan may name at most %d; split them across scans",
			e.JobAddresses, e.JobLimit)
	}
	const listed = 3
	parts := make([]string, 0, listed)
	for i, t := range e.Targets {
		if i == listed {
			break
		}
		parts = append(parts, fmt.Sprintf("%q names %s addresses", t.Target, t.Addresses))
	}
	more := ""
	if n := len(e.Targets) - listed; n > 0 {
		more = fmt.Sprintf(" (and %d more)", n)
	}
	return fmt.Sprintf("scan target too large: %s%s, and one target may name at most %d (an IPv4 /20); split it into smaller blocks",
		strings.Join(parts, "; "), more, e.Limit)
}

// TargetSize reports how many addresses ExpandTargets would produce for one
// target BEFORE its cap, using only CIDR and range arithmetic: no DNS, no
// allocation proportional to the answer, and an exact result for an IPv6 /0.
// A hostname or a single address counts as 1, as does anything ExpandTargets
// would pass through unchanged (a malformed CIDR, a range it cannot expand).
//
// The error is non-nil only for an IPv4 range that ends before it starts, which
// ExpandTargets would walk until its cap rather than refuse.
func TargetSize(input string) (*big.Int, error) {
	in := strings.TrimSpace(input)
	switch {
	case in == "":
		return new(big.Int), nil
	case strings.Contains(in, "/"):
		_, ipNet, err := net.ParseCIDR(in)
		if err != nil {
			return big.NewInt(1), nil
		}
		ones, bits := ipNet.Mask.Size()
		return new(big.Int).Lsh(big.NewInt(1), uint(bits-ones)), nil
	case IsNetworkRange(in):
		parts := strings.SplitN(in, "-", 2)
		start := net.ParseIP(strings.TrimSpace(parts[0])).To4()
		end := net.ParseIP(strings.TrimSpace(parts[1])).To4()
		if start == nil || end == nil {
			// Not an IPv4 range: expandIPRange errors and the input is passed
			// through as one host.
			return big.NewInt(1), nil
		}
		s := new(big.Int).SetBytes(start)
		e := new(big.Int).SetBytes(end)
		if e.Cmp(s) < 0 {
			return nil, fmt.Errorf("scan target %q is a range that ends before it starts", in)
		}
		return e.Sub(e, s).Add(e, big.NewInt(1)), nil
	default:
		return big.NewInt(1), nil
	}
}

// CheckTargetSizes refuses targets the scanner could not fully expand: any one
// target above [MaxTargetAddresses], or a total above [MaxJobAddresses]. It is
// the counterpart of ExpandTargets' cap — that cap truncates silently, so
// every caller that hands a target to ExpandTargets checks here first. The
// returned error is a *TargetTooLargeError for a size refusal.
func CheckTargetSizes(targets []string) error {
	var oversize []OversizeTarget
	total := new(big.Int)
	limit := new(big.Int).SetUint64(MaxTargetAddresses)
	for _, t := range targets {
		n, err := TargetSize(t)
		if err != nil {
			return err
		}
		if n.Cmp(limit) > 0 {
			oversize = append(oversize, OversizeTarget{Target: strings.TrimSpace(t), Addresses: n.String()})
		}
		total.Add(total, n)
	}
	if len(oversize) > 0 {
		return &TargetTooLargeError{Targets: oversize, Limit: MaxTargetAddresses}
	}
	if total.Cmp(new(big.Int).SetUint64(MaxJobAddresses)) > 0 {
		return &TargetTooLargeError{JobAddresses: total.String(), JobLimit: MaxJobAddresses}
	}
	return nil
}
