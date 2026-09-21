package identity

// Provisional inventory ( D1–D3).
//
// The problem it solves: a sensor on VLAN A hears a reflected mDNS advert for
// a printer that lives on VLAN B. The advert is hearsay — the sensor never
// touched the device — so [AssessAdmission] refuses to establish anything from
// it, and until this file existed the evidence became an `identity_observation`
// nobody could see from Inventory and nothing could ever join to. When a sensor
// was later deployed on VLAN B and DID meet the printer, the two pieces of
// evidence had no way to become one item.
//
// The answer is a THIRD identity status rather than a second asset: an
// advertisement placed on a configured, unambiguous tenant segment creates the
// asset now, marked [IdentityProvisional], and direct evidence from that
// segment later corroborates the SAME row. The asset id is the stable
// user-facing item, so every inventory surface — lenses, filters, approvals,
// findings, merge review, history — works on it unchanged, and nothing about
// the item's identity changes when it is corroborated except the status and
// the history entry that records it.
//
// Two things are deliberately NOT true of a provisional asset:
//
//   - it never consumes the tenant's `max_assets` allowance (D1). A guess must
//     not spend a customer's paid inventory; the allowance check moves to
//     PROMOTION, where the platform is asserting the thing is real.
//   - it never wins an argument with direct evidence (D3). A provisional asset
//     is built from a name somebody else repeated; when a collector that
//     actually met a device disagrees, the guess yields — see
//     [IdentifierReassigner].

import "context"

// Reasons a segment is not eligible for provisional creation. They are the
// strings the observation records and the UI renders, so they are spelled once
// here rather than at each producer ( D8).
const (
	// ReasonNetworkScopeUnresolved — the observation was not placed on any
	// configured segment, or the store cannot answer the question at all. An
	// advertisement we cannot place is an advertisement we cannot attribute.
	ReasonNetworkScopeUnresolved = "network_scope_unresolved"
	// ReasonOverlappingNetworkScope — more than one active segment covers the
	// address, or the segment belongs to a cloud network. "Which VLAN is
	// 10.0.1.50 on" then has several answers, and creating an asset against
	// one of them picks for the operator.
	ReasonOverlappingNetworkScope = "overlapping_network_scope_requires_source_resolution"
	// ReasonNoDeviceOrAddressBinding — the observation carries nothing that a
	// segment can hold: a bare name, with no scoped hostname, fqdn or address.
	ReasonNoDeviceOrAddressBinding = "no_device_or_address_binding"
	// ReasonAssetAllowanceExhausted — promotion of a provisional asset was
	// refused because the tenant is at `max_assets`. The evidence still
	// attaches and the asset stays provisional; nothing is lost, and the
	// tenant is told what to do about it.
	ReasonAssetAllowanceExhausted = "asset_allowance_exhausted"
	// ReasonSupersededByDirectEvidence — a provisional asset was archived
	// because every identifier it held moved to an asset a collector actually
	// met. `merged_into` is deliberately NOT set: nothing was merged, the
	// guess was simply wrong about there being a separate thing.
	ReasonSupersededByDirectEvidence = "superseded_by_direct_evidence"
)

// ProvisionalScopeChecker is an OPTIONAL [Repository] capability: it answers
// whether a segment is a place a provisional asset may be created ( D2.4).
//
// It is optional the way [ObservationRepository] is, and a repository that does
// not implement it is treated as answering "not eligible", never as answering
// "yes". A store that cannot tell us whether a segment is unambiguous has not
// told us it is — and the whole rule rests on the segment being unambiguous,
// because an asset created against the wrong VLAN is a duplicate of something
// on the right one that nothing will ever reconcile.
//
// `reason` is one of the constants above and is recorded on the observation
// when `eligible` is false. It is required even on the eligible answer's error
// path so a caller never has to invent one.
type ProvisionalScopeChecker interface {
	ProvisionalScope(ctx context.Context, tenantID, segmentID string) (eligible bool, reason string, err error)
}

// IdentifierReassigner is an OPTIONAL [Repository] capability: it moves one
// identifier value from one asset to another, atomically ( D3, "hearsay
// yields").
//
// The case it exists for: a provisional asset P was created from an advert
// claiming `printer.local` at 192.168.1.50. A collector on that segment then
// directly observes a DIFFERENT host at 192.168.1.50 — same address, different
// name, and a MAC. The address is evidence about the device that was actually
// met, not about the name somebody repeated, so it moves; P keeps the name it
// was created from and, if that leaves P holding nothing, P is archived.
//
// It is a repository method rather than a detach-then-attach pair in the engine
// because the unique index of DATA_MODEL §2 makes those two writes a window in
// which the value belongs to nobody — and the engine's own invariant is that an
// identifier never vanishes without a trace.
//
// `from` must be the identifier's CURRENT owner. An implementation that finds
// otherwise returns an error rather than moving it: a reassignment computed
// against stale ownership is how two assets swap halves of their identity.
type IdentifierReassigner interface {
	ReassignIdentifier(ctx context.Context, id Identifier, from, to AssetRef) error
}

// AssetArchiver is an OPTIONAL [Repository] capability: it retires an asset
// that has been left with no identifier by a reassignment.
//
// Separate from [IdentifierReassigner] so an implementation may support the
// move without the retirement — the engine then leaves the emptied asset alone
// and says so in history, which is a worse inventory but not a wrong one. It is
// the only place this package changes an asset's status, and it only ever moves
// it to `archived`: the engine does not approve, deny or delete.
type AssetArchiver interface {
	ArchiveAsset(ctx context.Context, asset AssetRef) error
}
