package dispatchguard

// Per-target classification for a scan plan ( WP3, owner decision D3).
//
// AuthorizeManual answers "may this job run" and returns only the external
// targets. A scan plan needs one more thing per target: WHICH class the guard
// put it in — private space, a registered network segment (and which one), or
// external — because the depth a target may be scanned at depends on it, and
// "who claimed this range, then scanned it" should be answerable from the job.
// The classes come from the same classifier every path uses (classify), so the
// depth cap and the authorization can never disagree about what is external.

import (
	"net/netip"
)

// Target classes, spelled as shared/discovery.TargetClass spells them.
const (
	ClassPrivate           = "private"
	ClassRegisteredSegment = "registered_segment"
	ClassExternal          = "external"
)

// TargetVerdict is one manual target's class.
type TargetVerdict struct {
	// Target is the target as the job stores it (ManualTarget.Input).
	Target string
	// Class is ClassPrivate, ClassRegisteredSegment or ClassExternal.
	Class string
	// SegmentID is the registered segment that made the target the tenant's
	// (ClassRegisteredSegment only). A hostname whose addresses fall in more
	// than one segment names the segment of its first such address.
	SegmentID string
}

// ClassifyManual classifies targets that AuthorizeManual already admitted. A
// target is private when it lies wholly in private address space (that is
// ownership by address class; no segment granted it), registered when a
// registered segment contains it, and external otherwise. A hostname is
// external if ANY address it resolved to is external — the same rule
// AuthorizeManual applies — and otherwise registered if any address needed a
// segment.
func (s TargetScope) ClassifyManual(targets []ResolvedTarget) []TargetVerdict {
	out := make([]TargetVerdict, 0, len(targets))
	for _, t := range targets {
		v := TargetVerdict{Target: t.Input, Class: ClassPrivate}
		var intervals [][2]netip.Addr
		if t.Host != "" {
			for _, a := range t.Resolved {
				intervals = append(intervals, [2]netip.Addr{a, a})
			}
		} else if lo, hi, ok := targetInterval(t.Input); ok {
			intervals = append(intervals, [2]netip.Addr{lo, hi})
		}
		for _, iv := range intervals {
			class, segment := s.classOf(iv[0], iv[1])
			switch {
			case class == ClassExternal:
				v.Class, v.SegmentID = ClassExternal, ""
			case class == ClassRegisteredSegment && v.Class == ClassPrivate:
				v.Class, v.SegmentID = ClassRegisteredSegment, segment
			}
			if v.Class == ClassExternal {
				break
			}
		}
		out = append(out, v)
	}
	return out
}

// classOf is classify's in-scope answer split by WHY it is in scope. An
// excluded interval never reaches here (AuthorizeManual refused it); it is
// reported external, the conservative answer, should a caller skip the
// authorization.
func (s TargetScope) classOf(lo, hi netip.Addr) (string, string) {
	if class, _ := s.classify(lo, hi); class != classInScope {
		return ClassExternal, ""
	}
	for _, p := range privatePrefixes {
		if p.Contains(lo) && p.Contains(hi) {
			return ClassPrivate, ""
		}
	}
	for i, p := range s.allowed {
		if p.Contains(lo) && p.Contains(hi) {
			id := ""
			if i < len(s.allowedSegments) {
				id = s.allowedSegments[i]
			}
			return ClassRegisteredSegment, id
		}
	}
	return ClassExternal, ""
}

// AuthorizeAndClassifyManualTargets is AuthorizeManualTargets that also
// returns every target's class, judged against the same scope read in the
// caller's transaction.
func AuthorizeAndClassifyManualTargets(tx Queryer, tenantID string, targets []ResolvedTarget, opts ManualOptions) ([]ExternalTarget, []TargetVerdict, error) {
	if len(targets) == 0 {
		return nil, nil, denied("scan dispatch names no targets")
	}
	scope, err := LoadTargetScope(tx, tenantID)
	if err != nil {
		return nil, nil, err
	}
	external, err := scope.AuthorizeManual(targets, opts)
	if err != nil {
		return nil, nil, err
	}
	return external, scope.ClassifyManual(targets), nil
}

// TargetInterval reduces a literal target (an address, CIDR or a-b range) to
// the closed interval of addresses it names — the same reduction every check
// in this package makes. ok=false for anything else, a hostname included.
func TargetInterval(target string) (lo, hi netip.Addr, ok bool) {
	return targetInterval(target)
}
