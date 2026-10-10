package identity

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity/matcher"
)

// A person's scan of a named asset ( item 1, owner decision.
//
// When a person presses Scan on an asset (Discovery → Active Scan, or the Scan
// button in the asset's drawer), the platform probes the address it has for
// that asset. The result is an ordinary measured observation, and on a DHCP
// segment with no device binding admission holds it: the address may belong
// to another device by now, and nothing in the evidence says otherwise. That
// hold is right for a scan nobody asked for. It is wrong for this one: the
// person named the asset and the platform chose the address, so the
// attribution has been made — by the request, not by the evidence.
//
// [Engine.WithOperatorScanRequest] carries that request into one resolution.
// The caller supplies it only after verifying, from rows the platform wrote
// itself, that the observation came from a job a person created to scan this
// asset at this address; nothing a sensor or a finding asserts can produce
// one. The engine then links the observation to the named asset, provided the
// evidence does not contradict it:
//
//   - every identifier the observation carries that another asset owns, and
//     that says which device this is (a device binding, a voting kind, or the
//     scanned address itself), stops it — the scan met something else;
//   - a device binding the asset already holds a value of (a MAC, an SSH host
//     key, a serial, an agent id …) that the scan saw a DIFFERENT value of
//     stops it — the address now answers as a different device;
//   - the drift classifier calling it a replacement stops it.
//
// A request that is stopped is not an error and not a conflict of its own:
// the observation is resolved exactly as it would have been without one, and
// [Resolution.OperatorScanRefused] says why the request did not decide it.

// DecidedByOperatorScanRequest is the `decided_by` a link made by a person's
// scan request records on the asset's timeline, and the
// identity_observations.resolution_outcome of the observation it linked.
const DecidedByOperatorScanRequest = "operator_scan_request"

// OperatorScanRequest is a person's request to scan one named asset at one
// address, as the platform recorded it.
type OperatorScanRequest struct {
	// Asset is the asset the person scanned.
	Asset AssetRef
	// Address is the bare address the job targeted for that asset, in
	// canonical form (netip.Addr.String()).
	Address string
	// JobID is the discovery job that carried the request. It is recorded on
	// the timeline so a reviewer can find the scan that made the link.
	JobID string
}

// WithOperatorScanRequest returns a copy of the engine that resolves the next
// observation under a verified person's scan request (see the comment at the
// top of this file). The engine is not mutated. A zero request returns the
// engine unchanged.
func (e *Engine) WithOperatorScanRequest(req OperatorScanRequest) *Engine {
	if req.Asset.Zero() || strings.TrimSpace(req.Address) == "" || strings.TrimSpace(req.JobID) == "" {
		return e
	}
	cp := *e
	cp.operatorScan = &req
	return &cp
}

// resolveOperatorScan decides an observation under e.operatorScan. It returns
// a non-empty refusal, and writes nothing, when the request cannot decide it;
// the caller then resolves the observation without the request.
func (e *Engine) resolveOperatorScan(ctx context.Context, obs Observation, at time.Time, ids []Identifier, owners map[string][]AssetRef) (Resolution, string, error) {
	req := *e.operatorScan
	target := req.Asset
	if target.TenantID != obs.TenantID {
		return Resolution{}, "the scanned asset belongs to another tenant", nil
	}
	if obs.Source.Kind != SourceMeasured || obs.Source.Mode != ModeActive {
		return Resolution{}, "the observation is not an active measurement", nil
	}
	if e.admissionCandidate != nil && e.admissionCandidate.ID != target.ID {
		// An operator's earlier explicit link of this evidence names another
		// asset. Two people's decisions disagree; neither is overridden here.
		return Resolution{}, "an earlier explicit link of this evidence names another asset", nil
	}
	scanned := false
	for _, id := range ids {
		if id.Kind == KindIPAddress && id.Value == req.Address {
			scanned = true
		}
	}
	if !scanned {
		return Resolution{}, fmt.Sprintf("the observation does not carry the scanned address %s", req.Address), nil
	}

	// Anything another asset owns that says which device this is.
	for _, id := range ids {
		for _, r := range owners[id.Key()] {
			if r.ID == target.ID {
				continue
			}
			if deviceBindingKinds[id.Kind] || id.Kind.Singleton() || (id.Kind == KindIPAddress && id.Value == req.Address) || (!id.Inferred() && e.kindVotes(obs, id)) {
				return Resolution{}, fmt.Sprintf("%s=%q belongs to another asset (%s)", id.Kind, id.Value, r.ID), nil
			}
		}
	}

	// A device binding the asset holds, contradicted by the scan.
	sums, err := e.repo.LoadSummaries(ctx, target.TenantID, []string{target.ID})
	if err != nil {
		return Resolution{}, "", fmt.Errorf("identity: reading scanned asset %s: %w", target.ID, err)
	}
	if len(sums) != 1 {
		return Resolution{}, "the scanned asset no longer exists", nil
	}
	if why := operatorScanBindingConflict(ids, sums[0].Identifiers); why != "" {
		return Resolution{}, why, nil
	}

	drift, err := e.classifyDrift(ctx, obs, at, ids, target)
	if err != nil {
		return Resolution{}, "", err
	}
	switch drift.result.Verdict {
	case matcher.DriftReplaced:
		return Resolution{}, "a different device now answers at the scanned address: " + drift.result.Explanation, nil
	case matcher.DriftDistinct:
		return Resolution{}, "a second device sharing a name answered: " + drift.result.Explanation, nil
	}

	attach, unattached := splitByOwner(ids, owners, target.ID)
	changes := map[string]any{
		"decided_by":        DecidedByOperatorScanRequest,
		"operator_scan_job": req.JobID,
	}
	if err := e.applyToAsset(ctx, target, obs, at, attach, unattached, ActionUpdated, changes); err != nil {
		return Resolution{}, "", err
	}
	applied, err := e.applyDrift(ctx, obs, at, target, drift)
	if err != nil {
		return Resolution{}, "", err
	}
	return Resolution{
		Outcome:         OutcomeMatched,
		Asset:           target,
		OperatorScanJob: req.JobID,
		Unattached:      unattached,
		Drift:           applied,
	}, "", nil
}

// operatorScanBindingConflict reports the first device-binding kind the asset
// holds at least one value of while the scan saw only OTHER values of it. Any
// overlap agrees: a host with an RSA and an Ed25519 key that showed the
// Ed25519 one is the same host. Derived identifiers are skipped, as the drift
// classifier skips them: a MAC worked out from an address disagreeing is a
// statement about that address, not about the hardware.
func operatorScanBindingConflict(observed, held []Identifier) string {
	seen := map[Kind][]string{}
	var kinds []Kind
	for _, id := range observed {
		if id.Inferred() || (!deviceBindingKinds[id.Kind] && !id.Kind.Singleton()) {
			continue
		}
		if _, ok := seen[id.Kind]; !ok {
			kinds = append(kinds, id.Kind)
		}
		seen[id.Kind] = append(seen[id.Kind], id.Value)
	}
	for _, kind := range kinds {
		values := seen[kind]
		var have []string
		agree := false
		for _, h := range held {
			if h.Kind != kind {
				continue
			}
			have = append(have, h.Value)
			for _, v := range values {
				if strings.EqualFold(v, h.Value) {
					agree = true
				}
			}
		}
		if len(have) > 0 && !agree {
			return fmt.Sprintf("the scan saw %s %v, but the scanned asset is bound to %v", kind, values, have)
		}
	}
	return ""
}
