// Package attrlist keeps evidence the identity layer refused as IDENTIFIERS but
// must not lose: a bounded, most-recent-first list of strings under one key of
// `assets.attributes`.
//
// Three lists use it:
//
//	synthetic_names            UUID-form, IP-encoded and none-N names (D1)
//	ipv6_temporary_addresses   rotating RFC 8981-shaped IPv6 addresses (D2)
//	link_local_addresses       fe80::/10 addresses with no segment to scope to (D2)
//	virtual_interface_addresses  a host's own addresses on its virtual
//	                           interfaces (bridges, veths, tunnels), as its
//	                           agent reported them ( WP7)
//
// Each is evidence that EXPLAINS an asset — what else it answered to — and
// none of it identifies anything, which is why it is an attribute and not an
// identifier: a value that rotates daily attached as an identifier is a key
// nobody will ever look up again.
//
// Both intakes (inventory-service host-observation ingest, device-interrogation
// peer resolution) write through [Record], so the two cannot fold the same
// attribute differently.
package attrlist

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/identity/derive"
)

// The attribute keys, and the cap on the two address lists. (The name list's
// cap is hostnamequality.MaxSyntheticNames.)
const (
	KeySyntheticNames = "synthetic_names"
	KeyIPv6Temporary  = "ipv6_temporary_addresses"
	KeyLinkLocal      = "link_local_addresses"
	// KeyVirtualInterfaceAddresses holds the addresses a host reported on its
	// VIRTUAL interfaces. They are real and they are the host's, but they are
	// not where it lives: a container bridge's 172.17.0.1 is on every Docker
	// host, so as an identifier it would merge them all.
	KeyVirtualInterfaceAddresses = "virtual_interface_addresses"
	MaxAddressEvidence           = 10
)

// AddressAttribute is D2's rule for one address, in the one place both
// intakes read it: the attribute key an address is recorded under INSTEAD of
// becoming an ip_address identifier, or "" when it stays an identifier.
//
//   - a temporary-shaped IPv6 address ([derive.RoleTemporary]) →
//     [KeyIPv6Temporary];
//   - a link-local address → an identifier only when segmentScoped (the
//     observation resolved to a real segment the caller scopes it to — a
//     link-local address is unique only on its own link), otherwise
//     [KeyLinkLocal];
//   - everything else — IPv4, EUI-64, a hand-assigned IPv6 address — "".
func AddressAttribute(addr netip.Addr, segmentScoped bool) string {
	switch derive.IPv6Role(addr) {
	case derive.RoleTemporary:
		return KeyIPv6Temporary
	case derive.RoleLinkLocal:
		if segmentScoped {
			return ""
		}
		return KeyLinkLocal
	default:
		return ""
	}
}

// Merge folds incoming into existing: each value normalised (trimmed, lower
// case, one trailing dot dropped), deduplicated, incoming first in its own
// order and then existing, capped at max. incoming is the newer evidence, so a
// value seen again moves to the front and the oldest fall off the end.
//
// A max below one keeps nothing.
func Merge(incoming, existing []string, max int) []string {
	if max < 1 {
		return []string{}
	}
	out := make([]string, 0, min(max, len(incoming)+len(existing)))
	seen := map[string]bool{}
	for _, list := range [][]string{incoming, existing} {
		for _, v := range list {
			n := normalize(v)
			if n == "" || seen[n] {
				continue
			}
			if len(out) == max {
				return out
			}
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

func normalize(v string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(v), "."))
}

// Tx is what [Record] needs of a transaction. *sql.Tx satisfies it, and so
// does *sqlx.Tx (which embeds one), so both services pass the transaction the
// identity engine resolved the observation on.
type Tx interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// Record folds values into `assets.attributes -> key` for one asset on the
// caller's transaction, with [Merge] and the given cap.
//
// It locks the asset row (FOR UPDATE) so two observations of one asset cannot
// interleave the read and the write. It writes NOTHING when the merged list
// equals the stored one, and it records no history and does not touch
// updated_at: a rotating address or advertisement repeats every few minutes,
// and an attribute that exists to explain an asset must not fill its timeline.
//
// A stored value that is not a JSON string array was not written here; it is
// replaced rather than allowed to fail the observation.
func Record(ctx context.Context, tx Tx, tenantID, assetID, key string, values []string, max int) error {
	if len(values) == 0 {
		return nil
	}
	if strings.TrimSpace(key) == "" {
		return fmt.Errorf("attrlist: empty attribute key")
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(attributes->($3::text),'[]'::jsonb) FROM assets WHERE tenant_id=$1 AND id=$2 FOR UPDATE`,
		tenantID, assetID, key).Scan(&raw); err != nil {
		return fmt.Errorf("read %s: %w", key, err)
	}
	var existing []string
	_ = json.Unmarshal(raw, &existing)
	merged := Merge(values, existing, max)
	if slices.Equal(merged, existing) {
		return nil
	}
	encoded, err := json.Marshal(merged)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE assets SET attributes=jsonb_set(COALESCE(attributes,'{}'::jsonb),ARRAY[$3::text],$4::jsonb) WHERE tenant_id=$1 AND id=$2`,
		tenantID, assetID, key, string(encoded)); err != nil {
		return fmt.Errorf("write %s: %w", key, err)
	}
	return nil
}
