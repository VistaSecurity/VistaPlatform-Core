package services

import (
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// Provenance of external_connections.dest_hostname.
//
// The name on a third-party connection can arrive from two very different
// places, and until this existed they were indistinguishable once written:
//
//   - the TLS SNI the client itself put in its ClientHello, or a name the host
//     announced over DHCP/mDNS/NetBIOS — a MEASURED fact, read off the wire;
//   - a reverse-DNS PTR answer for the destination address — an INFERENCE, and
//     usually a bad one for a cloud or CDN address, which answers with a
//     generic per-address name (ec2-54-163-235-119.compute-1.amazonaws.com)
//     that names infrastructure the client never asked for.
//
// The upsert used to keep whichever arrived last as long as it was non-empty,
// so the PTR overwrote slack.com on the next observation of the same flow.
// "Empty never wins" does not help, because a PTR answer is not empty.
//
// The vocabulary is ADR-0005's, reused rather than reinvented — see
// shared/identity.SourceKind and asset_identifiers.source_kind.

// hostnameSourceKindRank is the Go mirror of the precedence ladder written into
// the ON CONFLICT clause of ExternalConnectionsService.Upsert's SQL. The SQL is
// what actually enforces it; this exists so the two can be checked against each
// other and so callers can reason about the ordering without reading SQL.
//
// Three ranks, not two. An unstated provenance ("" / nil) is its OWN state: it
// is neither a claim that the name was measured nor a claim that it was
// guessed, so it sits between them. Every row written before this column
// existed is in that state, which is why it must not collapse into either
// neighbour — folding it into `measured` would let legacy PTR junk block a real
// SNI forever, and folding it into `inferred` would let any unlabelled producer
// stamp over names it knows nothing about.
func hostnameSourceKindRank(kind *string) int {
	switch normalizedHostnameSourceKind(kind) {
	case string(identity.SourceMeasured):
		return 2
	case string(identity.SourceInferred):
		return 0
	default:
		// nil, "", declared, imported. A human's assertion and a CMDB import
		// are not measurements of this flow, but neither are they guesses about
		// the address; they rank with "unstated".
		return 1
	}
}

// hostnameSourceKindWins reports whether an incoming provenance may replace a
// stored one — the same `>=` the SQL uses, so like replaces like (a fresh PTR
// refreshes a stale PTR) while a lower rank is refused.
func hostnameSourceKindWins(incoming, stored *string) bool {
	return hostnameSourceKindRank(incoming) >= hostnameSourceKindRank(stored)
}

// normalizeHostnameSourceKind maps an incoming provenance onto the four-value
// ADR-0005 vocabulary, returning nil for anything outside it.
//
// nil rather than an error, and nil rather than a passthrough: the column
// carries a CHECK constraint, so passing an unrecognised word through would
// fail the whole upsert and lose a real observation over a label. Dropping the
// label degrades the row to "provenance unstated", which is exactly what is
// true about a producer whose vocabulary we do not recognise.
func normalizeHostnameSourceKind(kind *string) *string {
	normalized := normalizedHostnameSourceKind(kind)
	if normalized == "" {
		return nil
	}
	return &normalized
}

// normalizedHostnameSourceKind is the string half of normalizeHostnameSourceKind:
// trimmed, lower-cased, and "" unless it is one of the four valid kinds.
func normalizedHostnameSourceKind(kind *string) string {
	if kind == nil {
		return ""
	}
	candidate := identity.SourceKind(strings.ToLower(strings.TrimSpace(*kind)))
	if !candidate.Valid() {
		return ""
	}
	return string(candidate)
}
