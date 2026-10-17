package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// ScopeForAddress implements [identity.Repository].
//
// It is THE answer to "where was I standing?", and it lives here rather than in
// each service that builds observations so inventory-service and
// device-interrogation-service cannot disagree about which prefix an address
// is in. One more spelling of this lookup is one more dedupe key.
//
// The rules, in order:
//
//   - the most specific live global-VRF prefix containing the address wins (a
//     /28 carved out of a /24 is the more precise answer);
//   - failing that, [identity.ScopeTenantDefault] — the tenant-wide default
//     space. NEVER an empty scope. "This tenant has no prefixes" is a fact
//     about their topology, not an absence of one, and treating it as an
//     absence is what made one host, observed three times, into three assets.
//
// `dynamic` is the prefix's DHCP posture, `prefixes.dhcp_managed`. It is
// three-valued: NULL ("nobody has said") on a prefix a collector learned
// reads as dynamic — a device told us a network exists and did not measure
// whether leases are handed out on it, and letting a bare address vote there
// is how two devices that held the same lease become one asset — and as
// static on one a person declared.
//
// The matching itself is [identity.SegmentSnapshot.ScopeForAddress] over
// [Repository.SegmentSnapshot] — one implementation shared with the in-memory
// store and with identity.Intake, so the per-address lookup and the intake
// cannot disagree about which prefix an address is in.
func (r *Repository) ScopeForAddress(ctx context.Context, tenantID string, addr netip.Addr, cloudNetworkRef string) (string, bool, error) {
	if !addr.IsValid() {
		// Not an address, so inside no prefix. The default scope is still the
		// truthful answer — and it needs no read.
		return identity.ScopeTenantDefault, false, nil
	}
	snap, err := r.SegmentSnapshot(ctx, tenantID)
	if err != nil {
		return "", false, err
	}
	scope, dynamic := snap.ScopeForAddress(addr, cloudNetworkRef)
	return scope, dynamic, nil
}

// SegmentSnapshot implements [identity.Repository]: every live global-VRF
// prefix of the tenant, in creation order, in one read (see
// [Repository.ScopeForAddress] for the DHCP posture rule). Global VRF only — an
// observation carries no VRF until intake does (row 1.5).
func (r *Repository) SegmentSnapshot(ctx context.Context, tenantID string) (identity.SegmentSnapshot, error) {
	snap := identity.SegmentSnapshot{TenantID: tenantID}
	err := r.withTx(ctx, tenantID, func(tx *sql.Tx) error {
		ps, err := tx.QueryContext(ctx, `
			SELECT id::text, prefix::text,
			       coalesce(dhcp_managed, source_kind <> 'declared'),
			       coalesce(cloud_network_ref, '')
			  FROM public.prefixes
			 WHERE tenant_id = $1 AND vrf_id IS NULL AND status NOT IN ('rejected', 'archived')
			 ORDER BY created_at, id`, tenantID)
		if err != nil {
			return fmt.Errorf("identity/postgres: read prefixes: %w", err)
		}
		defer func() { _ = ps.Close() }()
		for ps.Next() {
			p := identity.NetworkSegment{Type: identity.SegmentTypeCIDR}
			if err := ps.Scan(&p.ID, &p.Value, &p.Dynamic, &p.CloudNetworkRef); err != nil {
				return fmt.Errorf("identity/postgres: scan prefix: %w", err)
			}
			p.CloudNetworkRef = strings.TrimSpace(p.CloudNetworkRef)
			snap.Prefixes = append(snap.Prefixes, p)
		}
		return ps.Err()
	})
	if err != nil {
		return identity.SegmentSnapshot{}, err
	}
	return snap, nil
}
