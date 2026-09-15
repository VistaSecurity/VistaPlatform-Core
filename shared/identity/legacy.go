package identity

import (
	"fmt"
	"strings"
	"time"
)

// FromLegacyAsset builds an observation from the four fields today's asset
// rows actually carry: hostname, IP, port and discovery method.
//
// It is a starting point for the per-path observation builders of workstream
// 1.2, not a finished one, and the gap is deliberate and documented rather
// than papered over:
//
//   - **The identifiers it produces are scoped to the TENANT, not to a
//     segment.** A hostname and an IP identify only within a scope (ADR-0002
//     D3) and the legacy shape has no segment to put in one, so both take
//     [ScopeTenantDefault] (ADR-0002 D3 erratum). Two observations of one host
//     therefore MATCH, which is what re-observing the same legacy row means.
//     What this cannot do is tell one segment's `printer-2` at 10.0.0.5 from
//     another's: under the default scope they are one asset until something
//     scopes them apart, and when a real builder later supplies
//     `Network.SegmentID` the segment-scoped identifier is added alongside and
//     the difference surfaces as a merge proposal for a human.
//
//     It used to leave them UNSCOPED, which meant they could not vote at all —
//     and an identifier that cannot vote is worse than a weak one: the second
//     observation created a second asset carrying no identifier, the third a
//     third, and nothing could ever match any of them again.
//
//   - A dotted hostname becomes an `fqdn` identifier, which needs no scope and
//     does match. A single-label hostname becomes a `hostname`.
//
//   - It sets no class hint, so a created asset is `unknown_host`, or
//     `external` once the caller fills in Network (ADR-0002 D1).
//
// Either hostname or ip must be non-empty. Both are normalised, and a value
// that does not normalise is an error rather than a silently dropped
// identifier.
func FromLegacyAsset(hostname, ip string, port int, discoveryMethod string) (Observation, error) {
	h := strings.TrimSpace(hostname)
	a := strings.TrimSpace(ip)
	if h == "" && a == "" {
		return Observation{}, fmt.Errorf("%w: legacy asset has neither hostname nor ip", ErrInvalidObservation)
	}

	method := strings.TrimSpace(discoveryMethod)
	if method == "" {
		method = "legacy"
	}
	obs := Observation{
		Source:     Source{Kind: SourceMeasured, Ref: method, Mode: ModePassive},
		ObservedAt: time.Now().UTC(),
		Hostname:   strings.ToLower(h),
	}

	if h != "" {
		kind := KindHostname
		if strings.Contains(strings.TrimSuffix(h, "."), ".") {
			kind = KindFQDN
		}
		v, err := Normalize(kind, h)
		if err != nil {
			return Observation{}, fmt.Errorf("%w: %w", ErrInvalidObservation, err)
		}
		obs.Identifiers = append(obs.Identifiers, Identifier{Kind: kind, Value: v, Confidence: 1})
		obs.DisplayName = v
	}
	if a != "" {
		v, err := Normalize(KindIPAddress, a)
		if err != nil {
			return Observation{}, fmt.Errorf("%w: %w", ErrInvalidObservation, err)
		}
		obs.Identifiers = append(obs.Identifiers, Identifier{Kind: KindIPAddress, Value: v, Confidence: 1})
		if obs.DisplayName == "" {
			obs.DisplayName = v
		}
		ep := EndpointObservation{Address: v, Port: port, Transport: "tcp"}
		if port == 0 {
			// Port 0 is the at-rest endpoint DATA_MODEL §2 stores with a NULL
			// port; the old "AT-REST" sentinel is retired, and a transport of
			// "none" is what says there is no socket here.
			ep.Transport = "none"
		}
		obs.Endpoints = append(obs.Endpoints, ep)
	}
	return obs, nil
}
