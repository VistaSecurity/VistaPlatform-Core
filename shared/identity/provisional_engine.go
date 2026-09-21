package identity

// The engine half of provisional inventory: rules D2 (creation) and D3
// (corroboration, supporting evidence, hearsay yields) of.
//
// Every entry point here is gated on [Config.ProvisionalInventory], which is
// false by default. With the flag off this file changes nothing: the same
// observations reach the same outcomes they reached before it existed, which
// is what makes the PR that introduced it behaviour-neutral.

import (
	"context"
	"fmt"
	"time"
)

// provisionalMode is what an ESTABLISHED observation landing on a provisional
// asset means ( D3).
type provisionalMode int

const (
	// provisionalNone — not a provisional asset, or the rule is off. The
	// ordinary match path applies unchanged.
	provisionalNone provisionalMode = iota
	// provisionalCorroborate — the observation and the provisional asset agree
	// about a NAME (or about something stronger than an address). The guess was
	// right; this is the same item, now met directly.
	provisionalCorroborate
	// provisionalYield — the observation matched the provisional asset by
	// address ALONE. An address is a lease, not an identity: the direct
	// evidence is about whatever currently holds it, and the advertised name
	// is about something else. The address moves.
	provisionalYield
)

// provisionalMatchMode classifies a decided match against a possibly-provisional
// asset.
//
// `matched` is the set of the observation's identifiers that VOTED for this
// asset — not everything the asset happens to own — because the question is
// what this observation and this asset agree about.
//
// Note which kinds count as "address alone": `ip_address` and nothing else. A
// MAC is not an address in this sense. Matching a provisional asset by MAC
// means the collector met the very NIC the advertisement described, which is
// the strongest corroboration there is; treating it as hearsay would move a
// device's interface onto a second asset and duplicate the thing this rule
// exists to keep whole.
func (e *Engine) provisionalMatchMode(ctx context.Context, ref AssetRef, matched []Identifier) (provisionalMode, error) {
	if !e.provisional {
		return provisionalNone, nil
	}
	if e.admissionDecision == nil || !e.admissionDecision.Established {
		// Only direct, authoritative or operator-confirmed evidence may
		// corroborate. Another relayed advert repeating the same name is the
		// same hearsay arriving twice, and treating repetition as proof is how
		// a rumour becomes an inventory.
		return provisionalNone, nil
	}
	summaries, err := e.repo.LoadSummaries(ctx, ref.TenantID, []string{ref.ID})
	if err != nil {
		return provisionalNone, fmt.Errorf("identity: reading %s's identity status: %w", ref.ID, err)
	}
	if len(summaries) != 1 || summaries[0].IdentityStatus != string(IdentityProvisional) {
		return provisionalNone, nil
	}
	if len(matched) == 0 {
		// Decided by something that left no evidence here (the confirmed-link
		// path seeds the candidate directly). It is still a direct answer about
		// this asset, so it corroborates.
		return provisionalCorroborate, nil
	}
	for _, id := range matched {
		if id.Kind != KindIPAddress {
			return provisionalCorroborate, nil
		}
	}
	if _, ok := e.repo.(IdentifierReassigner); !ok {
		// Without a store that can move an identifier, yielding would mean
		// detaching and re-attaching across a window in which the value belongs
		// to nobody. Today's behaviour — match by address — is wrong in a way
		// a reviewer can see and undo; a half-moved identifier is not.
		return provisionalCorroborate, nil
	}
	if len(e.muted) > 0 {
		// Already inside a yield. One level only: a second would be a
		// provisional asset yielding to a resolution that exists because
		// another one yielded, and the recursion has no obvious floor.
		return provisionalCorroborate, nil
	}
	return provisionalYield, nil
}

// yieldToDirectEvidence implements the "hearsay yields" half of D3.
//
// It re-runs the decision with the provisional asset's addresses MUTED — they
// are still owned, so nothing tries to write them, but they may not decide —
// and lets the observation create or match on its own remaining evidence. Only
// then are the addresses moved, which is the ordering that matters: the new
// owner has to exist before an identifier can point at it.
//
// It returns handled=false, having written nothing, when the re-run produced no
// asset it would be honest to move the address to: a contested outcome, a
// conflict's own pending asset, or the provisional asset again. The caller then
// falls back to today's behaviour (an ordinary match on the provisional asset),
// which keeps the observation attached to something a reviewer can find.
func (e *Engine) yieldToDirectEvidence(
	ctx context.Context,
	obs Observation,
	at time.Time,
	provisional AssetRef,
	addresses []Identifier,
) (Resolution, bool, error) {
	reassigner, ok := e.repo.(IdentifierReassigner)
	if !ok {
		return Resolution{}, false, nil
	}
	cp := *e
	cp.muted = make(map[string]bool, len(addresses))
	for _, id := range addresses {
		cp.muted[id.Key()] = true
	}
	res, err := cp.resolve(ctx, obs)
	if err != nil {
		return Resolution{}, false, err
	}
	if res.Asset.Zero() || res.Asset.ID == provisional.ID {
		return Resolution{}, false, nil
	}
	if res.Outcome != OutcomeCreated && res.Outcome != OutcomeMatched {
		return Resolution{}, false, nil
	}

	for _, id := range addresses {
		if err := reassigner.ReassignIdentifier(ctx, id, provisional, res.Asset); err != nil {
			return Resolution{}, false, fmt.Errorf("identity: moving %s=%q from %s to %s: %w",
				id.Kind, id.Value, provisional.ID, res.Asset.ID, err)
		}
	}
	// The addresses are no longer foreign: the resolution must not report them
	// as identifiers it declined to write, because it just wrote them.
	res.Unattached = withoutKeys(res.Unattached, cp.muted)

	moved := identifierKeys(addresses)
	changes := map[string]any{
		"identifiers": moved,
		"from":        provisional.ID,
		"to":          res.Asset.ID,
		"reason":      ReasonSupersededByDirectEvidence,
	}
	if e.observationID != "" {
		changes["observation_id"] = e.observationID
	}
	// On BOTH assets: each timeline has to say where the value went, or came
	// from. One entry would leave the other asset's history with an identifier
	// that silently appeared or silently vanished.
	for _, ref := range []AssetRef{provisional, res.Asset} {
		if err := e.history(ctx, ref, obs, at, ActionIdentifierReassigned, cloneChanges(changes)); err != nil {
			return Resolution{}, false, err
		}
	}

	if err := e.archiveIfEmptied(ctx, obs, at, provisional); err != nil {
		return Resolution{}, false, err
	}
	return res, true, nil
}

// archiveIfEmptied retires a provisional asset a reassignment left holding no
// identifier at all.
//
// Such an asset is exactly what the floor (ErrNoUsableIdentifier) exists to
// stop being created: nothing can ever match it again, so it would sit in the
// inventory for ever as an item with no way to be recognised. Archiving is not
// a merge and does NOT set `merged_into` — nothing was combined. The guess was
// simply about a thing that turned out not to be separate.
func (e *Engine) archiveIfEmptied(ctx context.Context, obs Observation, at time.Time, ref AssetRef) error {
	archiver, ok := e.repo.(AssetArchiver)
	if !ok {
		return nil
	}
	summaries, err := e.repo.LoadSummaries(ctx, ref.TenantID, []string{ref.ID})
	if err != nil {
		return fmt.Errorf("identity: re-reading %s after a reassignment: %w", ref.ID, err)
	}
	if len(summaries) != 1 || len(summaries[0].Identifiers) > 0 {
		return nil
	}
	if err := archiver.ArchiveAsset(ctx, ref); err != nil {
		return fmt.Errorf("identity: archiving the superseded provisional asset %s: %w", ref.ID, err)
	}
	changes := map[string]any{"reason": ReasonSupersededByDirectEvidence}
	if e.observationID != "" {
		changes["observation_id"] = e.observationID
	}
	return e.history(ctx, ref, obs, at, ActionArchived, changes)
}

// isSighting reports whether this observation is evidence the THING was there,
// as opposed to evidence about its name.
//
// The distinction exists because supporting evidence advances an asset's
// last-seen, and one producer must never be allowed to do that: the scoped DNS
// lookup the enrichment worker runs (`sensor:identity-dns:<id>`,
// [ModeActive], no endpoints) answers "what does this name resolve to" on
// every rescan cycle, without anything having gone near the device. Letting it
// touch would keep a device that was unplugged months ago permanently fresh
// and hide it from the stale lens — and the customer documentation promises
// the opposite in as many words: recording or retrying enrichment must not
// refresh device observation clocks artificially.
//
// The test is deliberately narrow. An ACTIVE measurement with no endpoint is a
// lookup; an active measurement that produced an endpoint (a TLS probe that
// completed a handshake) reached the device and is a sighting, as is every
// passive observation, which by construction is traffic the thing emitted.
func isSighting(obs Observation) bool {
	return obs.Source.Mode != ModeActive || len(obs.Endpoints) > 0
}

// resolveSupporting implements the supporting-evidence half of D3: the
// observation cannot establish anything, but every identifier it carries that
// anybody owns is owned by the SAME asset.
//
// That is another sighting of something we already know about, not a question,
// and the difference from a match is what it is allowed to do. It advances
// last-seen and nothing else — unless the asset is itself provisional, in which
// case the observation's new identifiers are attached, because a provisional
// asset is a sketch that later hearsay may legitimately fill in. An ESTABLISHED
// asset gains nothing from an unverified advert: an alias nobody checked must
// not become part of an identity somebody did.
//
// And an observation that is not a SIGHTING at all — see [isSighting] — gets
// the link and the history entry and nothing else, whatever the asset's status.
func (e *Engine) resolveSupporting(
	ctx context.Context,
	obs Observation,
	at time.Time,
	ids []Identifier,
	owners map[string][]AssetRef,
	ref AssetRef,
) (Resolution, error) {
	summaries, err := e.repo.LoadSummaries(ctx, ref.TenantID, []string{ref.ID})
	if err != nil {
		return Resolution{}, fmt.Errorf("identity: reading %s's identity status: %w", ref.ID, err)
	}
	if len(summaries) != 1 {
		// The owner vanished between the ownership lookup and now. Say nothing
		// happened rather than touching a row that is not there.
		return Resolution{Outcome: OutcomeUnresolved, Unattached: ids}, nil
	}
	attach, unattached := splitByOwner(ids, owners, ref.ID)
	sighting := isSighting(obs)
	changes := map[string]any{"supporting": true, "sighting": sighting}
	if e.observationID != "" {
		changes["observation_id"] = e.observationID
	}
	if !sighting {
		// Name-to-address context: a DNS answer about a name this asset holds.
		// It still LINKS — the evidence belongs to this asset and a reviewer
		// should find it there — but it writes nothing, because nothing here
		// observed the device. `sighting: false` in the history is what tells
		// somebody reading the timeline why an entry that looks like every
		// other supporting one left the clock alone.
		unattached = append(unattached, attach...)
		if len(unattached) > 0 {
			changes["unattached"] = identifierKeys(unattached)
		}
		if err := e.history(ctx, ref, obs, at, ActionUpdated, changes); err != nil {
			return Resolution{}, err
		}
		return Resolution{Outcome: OutcomeSupporting, Asset: ref, Unattached: unattached}, nil
	}
	if summaries[0].IdentityStatus == string(IdentityProvisional) {
		// A provisional asset is a sketch, and later hearsay may legitimately
		// fill it in — so this gets the ordinary treatment: identifiers,
		// endpoints, name promotion and last-seen.
		if err := e.applyToAsset(ctx, ref, obs, at, attach, unattached, ActionUpdated, changes); err != nil {
			return Resolution{}, err
		}
		return Resolution{Outcome: OutcomeSupporting, Asset: ref, Unattached: unattached}, nil
	}

	// An ESTABLISHED asset gains NOTHING from an unverified advert. Not the
	// identifiers, and not the endpoints or the names either: those are writes
	// from the same unchecked evidence, and "attach nothing" that still let a
	// name somebody repeated become the display name of an asset a collector
	// met would be the rule in name only.
	//
	// Last-seen still moves. The advert IS evidence the thing was there, which
	// is the one claim hearsay can make on its own.
	unattached = append(unattached, attach...)
	if err := e.repo.Touch(ctx, ref, at); err != nil {
		return Resolution{}, fmt.Errorf("identity: touching %s: %w", ref.ID, err)
	}
	if len(unattached) > 0 {
		changes["unattached"] = identifierKeys(unattached)
	}
	if err := e.history(ctx, ref, obs, at, ActionUpdated, changes); err != nil {
		return Resolution{}, err
	}
	return Resolution{Outcome: OutcomeSupporting, Asset: ref, Unattached: unattached}, nil
}

// provisionalPlacement is the segment a provisional asset would be created in,
// and why it cannot be one when it cannot.
type provisionalPlacement struct {
	segment string
	reason  string
}

// provisionalScopeFor implements the placement half of D2 (points 3 and
// 4): which configured segment this observation's evidence lands in, and
// whether that segment is somewhere an asset may be invented.
//
// Only `hostname`, `fqdn` and `ip_address` are consulted, because they are the
// kinds that are scoped to a segment at all. The scope must be a REAL segment:
// [ScopeTenantDefault] means "the tenant has no segment covering this", which is
// the answer that made one host observed three times into three assets, and it
// is not a place to create anything.
//
// Two candidate identifiers disagreeing about the segment is treated as the
// ambiguity it is, and refused with the same reason an overlapping segment
// gets — the point of the rule is that there is ONE answer to "which VLAN is
// this on".
func (e *Engine) provisionalScopeFor(ctx context.Context, obs Observation, ids []Identifier) (provisionalPlacement, error) {
	scoped := false
	segment := ""
	for _, id := range ids {
		switch id.Kind {
		case KindHostname, KindIPAddress:
			// The two kinds that CARRY a segment. `fqdn` is in D2's list but
			// [Identifier.Normalized] refuses a scope on it — an fqdn is
			// globally unique by construction — so an fqdn-only observation is
			// a name with no binding, not a name we failed to place.
			scoped = true
		case KindFQDN:
		default:
			continue
		}
		if id.Scope == "" || id.Scope == ScopeTenantDefault {
			continue
		}
		switch {
		case segment == "":
			segment = id.Scope
		case segment != id.Scope:
			return provisionalPlacement{reason: ReasonOverlappingNetworkScope}, nil
		}
	}
	switch {
	case !scoped:
		return provisionalPlacement{reason: ReasonNoDeviceOrAddressBinding}, nil
	case segment == "":
		return provisionalPlacement{reason: ReasonNetworkScopeUnresolved}, nil
	}
	checker, ok := e.repo.(ProvisionalScopeChecker)
	if !ok {
		// A store that cannot tell us whether the segment is unambiguous has
		// not told us that it is. Not eligible, and the reason is honest about
		// which question went unanswered.
		return provisionalPlacement{reason: ReasonNetworkScopeUnresolved}, nil
	}
	eligible, reason, err := checker.ProvisionalScope(ctx, obs.TenantID, segment)
	if err != nil {
		return provisionalPlacement{}, fmt.Errorf("identity: checking segment %s for provisional creation: %w", segment, err)
	}
	if !eligible {
		if reason == "" {
			reason = ReasonNetworkScopeUnresolved
		}
		return provisionalPlacement{reason: reason}, nil
	}
	return provisionalPlacement{segment: segment}, nil
}

// resolveProvisional creates the provisional asset of D2.
//
// It is [Engine.resolveCreate] with two differences, and both are the point:
//
//   - NO allowance check. A provisional asset is a guess, and a guess must not
//     spend a customer's paid `max_assets`. The check moves to promotion, where
//     the platform is asserting the thing is real (D1).
//   - `identity_status = provisional`, and the segment the evidence was placed
//     in rather than the observer's own. The observation stays `unresolved`
//     with this asset attached, so enrichment keeps working on it and a later
//     direct sighting can corroborate the same row.
func (e *Engine) resolveProvisional(
	ctx context.Context,
	obs Observation,
	at time.Time,
	ids []Identifier,
	segment string,
) (Resolution, error) {
	if len(ids) == 0 {
		// Unreachable: the caller is here because every identifier is unowned,
		// and an observation with none never reaches the default branch. The
		// floor is restated anyway — an asset with no identifier can never be
		// recognised again, whatever created it.
		return Resolution{}, fmt.Errorf("%w: refusing to create a provisional asset with no identifier", ErrNoUsableIdentifier)
	}
	classKey, classSource, classRef, classConf := e.classForCreate(obs)
	newAsset := NewAsset{
		ClassKey:        classKey,
		ClassSourceKind: classSource,
		ClassSourceRef:  classRef,
		ClassConfidence: classConf,
		DisplayName:     displayNameFor(obs, ids),
		Hostname:        hostnameFor(obs, ids),
		PrimaryAddress:  primaryAddressFor(obs, ids),
		Status:          StatusPendingApproval,
		IdentityStatus:  string(IdentityProvisional),
		Ownership:       obs.Network.Ownership,
		NetworkSegment:  segment,
		DiscoveryMethod: obs.Source.Ref,
		Confidence:      obs.Confidence,
		Source:          obs.Source,
		Identifiers:     ids,
		Endpoints:       stampEndpoints(obs.Endpoints, obs.Source, at),
		FirstSeenAt:     at,
		LastSeenAt:      at,
	}
	ref, err := e.repo.CreateAsset(ctx, obs.TenantID, newAsset)
	if err != nil {
		return Resolution{}, fmt.Errorf("identity: creating provisional asset: %w", err)
	}
	changes := map[string]any{
		"class_key":       classKey,
		"identifiers":     identifierKeys(ids),
		"endpoints":       endpointKeys(newAsset.Endpoints),
		"identity_status": string(IdentityProvisional),
	}
	if e.observationID != "" {
		changes["observation_id"] = e.observationID
	}
	if err := e.history(ctx, ref, obs, at, ActionCreated, changes); err != nil {
		return Resolution{}, err
	}
	return Resolution{
		Outcome:  OutcomeProvisional,
		Asset:    ref,
		ClassKey: classKey,
	}, nil
}

// withoutKeys drops the identifiers whose key is in the set.
func withoutKeys(ids []Identifier, keys map[string]bool) []Identifier {
	if len(keys) == 0 || len(ids) == 0 {
		return ids
	}
	out := make([]Identifier, 0, len(ids))
	for _, id := range ids {
		if !keys[id.Key()] {
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// cloneChanges copies a changes map, so two history entries written from one
// payload cannot be handed the same mutable map.
func cloneChanges(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
