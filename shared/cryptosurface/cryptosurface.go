// Package cryptosurface is the ONE definition of "this asset shows a
// cryptographic surface".
//
// # Why it exists
//
// An asset no risk-feeding producer has covered reads "not assessed". On a
// real estate most of those are not gaps at all: a phone seen only by ARP, a
// smart plug in the UniFi client list, an AWS security group. Nothing about
// them is cryptographic, so there is nothing for the crypto producer to judge,
// and calling them "not assessed" says we failed to do something we never had
// anything to do. The dashboard read 78 of 102 lab assets that way, and all
// but two had no crypto surface on record at all.
//
// So the unscored set splits in two, and this package draws the line:
//
//   - not_assessed       — unscored, and a crypto surface WAS seen: a crypto
//     configuration, an at-rest encryption record, a crypto-protocol endpoint,
//     or a class that is crypto by nature. Something is there and nobody has judged it. A real gap.
//   - no_crypto_observed — unscored, and none of those exist. Honest about
//     its limit: "observed", because we can only say we saw none.
//
// # The direction to err in
//
// When in doubt, an asset has a surface. A false "has a surface" reads
// "Not assessed", which is visible and invites a look; a false "no surface"
// reads "No crypto observed", which is false and silent. That is why the
// class rule exists at all — a KMS key the collector recorded no algorithm for
// is still a key — and why it matches the whole class subtree.
//
// # What it reads
//
// Durable inventory only: crypto_implementations, crypto_applications (at-rest
// encryption), asset_endpoints and the class. Never sensor_discoveries, which is a work queue, not inventory — a
// discovery that failed to become an endpoint is a pipeline bug to fix there,
// not something to paper over here.
//
// Every reader — the risk summary, the risk facet, the query language's
// `risk:` pseudo-bands and the per-asset `crypto_surface` flag — calls SQL, so
// a dashboard slice, the facet beside it and the list it clicks through to
// cannot disagree about which asset is which.
package cryptosurface

import (
	"regexp"
	"sort"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
)

// Protocols are the asset_endpoints.protocol (public.protocol_type) values
// that are cryptographic by definition. An endpoint speaking one is a crypto
// surface whether or not anything has measured it yet.
//
// Deliberately absent: the protocols that MAY be encrypted but say nothing by
// their name — Database, API, SMB — and the plaintext OT protocols. Their
// cleartext exposure is the configuration producer's question, and that
// producer's coverage takes an asset out of the unscored set anyway.
var Protocols = []string{
	"TLS", "QUIC", "SSH", "IPSec", "IKE", "VPN", "PPTP", "Kerberos",
	"IEC62351", "BACnet_SC",
}

// ClassPaths returns the materialised class paths of every crypto-bearing
// class (standards/asset-classes.yaml `crypto_bearing: true`), sorted.
func ClassPaths() []string {
	var out []string
	for _, c := range assetclass.All {
		if c.CryptoBearing {
			out = append(out, c.Path)
		}
	}
	sort.Strings(out)
	return out
}

// safeIdent guards every name and inlined value. All of them are code
// constants or generated registry paths, so it cannot fire on any input a
// caller controls — which is exactly why it is here (see riskrollup).
var safeIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)

// Bind turns a value into SQL: a placeholder the caller binds, or a literal.
type Bind func(v string) string

// SQL returns a boolean SQL expression, true when the asset row aliased
// `alias` has a crypto surface. Every value goes through bind, so a caller
// with a parameter list (the query language's translator, which forbids
// quoted literals in what it generates) keeps it; Inline is for the rest.
//
// The correlation is by asset id alone, with no tenant predicate: the
// translator's rule is that tenant isolation is RLS's job (§7.2), and every
// caller runs inside a tenant transaction. An asset id is a UUID, so the
// correlation cannot reach across tenants either way.
//
// The alias must expose the assets columns `id` and `class_path`. Nothing in
// the expression can be NULL — EXISTS and an `= OR starts_with` over a
// NOT-NULL-guarded column — so NOT over it is a safe complement.
func SQL(alias string, bind Bind) string {
	if !safeIdent.MatchString(alias) || strings.Contains(alias, ".") {
		panic("cryptosurface: bad alias " + alias)
	}
	protos := make([]string, len(Protocols))
	for i, p := range Protocols {
		protos[i] = bind(p)
	}
	parts := []string{
		"EXISTS (SELECT 1 FROM crypto_implementations cs_ci" +
			" WHERE cs_ci.asset_id = " + alias + ".id AND cs_ci.deleted_at IS NULL)",
		// At-rest encryption (an S3 bucket's SSE, a disk's encryption): the
		// Data Protection lens's rows. No producer judges them yet, which is
		// exactly why an asset carrying one must read "Not assessed".
		"EXISTS (SELECT 1 FROM crypto_applications cs_ca" +
			" WHERE cs_ca.asset_id = " + alias + ".id AND cs_ca.deleted_at IS NULL)",
		"EXISTS (SELECT 1 FROM asset_endpoints cs_ep" +
			" WHERE cs_ep.asset_id = " + alias + ".id" +
			" AND cs_ep.status <> " + bind("closed") +
			" AND cs_ep.protocol::text IN (" + strings.Join(protos, ", ") + "))",
	}
	for _, p := range ClassPaths() {
		// starts_with, not LIKE: every path has an underscore, and `_` is a
		// LIKE wildcard.
		parts = append(parts,
			"coalesce("+alias+".class_path = "+bind(p)+
				" OR starts_with("+alias+".class_path, "+bind(p+".")+"), false)")
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

// Inline is SQL with every value written as a literal, for the service queries
// that already own their parameter numbering. Safe because every value is a
// code constant or a registry path, and literal refuses anything else.
func Inline(alias string) string { return SQL(alias, literal) }

func literal(v string) string {
	if !safeIdent.MatchString(v) {
		panic("cryptosurface: refusing to inline " + v)
	}
	return "'" + v + "'"
}
