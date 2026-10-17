package services

// The prefix an ingested address falls in, and what it lends the asset
// (DCIM row 1.6, ADR-0010 D3).
//
// The retired network segments answered four ingest questions: whose is this
// address (ownership classification), which auto-approval rule applies, what
// context does the asset inherit (environment, location, business unit), and
// which scope its identifiers file under. A prefix answers all four now, by the
// rule IPAM itself uses — the longest live global-VRF prefix containing the
// address (shared/dcim/ipam.LongestMatch, through approval.PrefixSet). A name
// is never placed by a prefix: the `domain` segments that matched hostnames
// have no prefix equivalent.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/approval"
	"github.com/vistasecurity/vistaplatform/shared/dcim/ipam"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/network/addrscope"
)

// prefixInfo is one live global-VRF prefix as ingest reads it.
type prefixInfo struct {
	ID     uuid.UUID
	Prefix netip.Prefix
	// NetworkType is the prefix's network type (private, public, vpn,
	// cloud), empty when nobody said.
	NetworkType     string
	Environment     *string
	BusinessUnitID  *uuid.UUID
	LocationID      *uuid.UUID
	LocationName    *string
	CloudNetworkRef string
}

// PrefixSet is one tenant's live global-VRF prefixes, read once, with the
// longest-match index auto-approval uses. A nil *PrefixSet matches nothing.
type PrefixSet struct {
	match *approval.PrefixSet
	byID  map[uuid.UUID]*prefixInfo
}

// loadPrefixSet reads the tenant's prefixes inside a tenant-scoped
// transaction.
func loadPrefixSet(ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID) (*PrefixSet, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT p.id, p.prefix::text, coalesce(p.network_type, ''), p.environment, p.business_unit_id,
		       CASE WHEN p.scope_kind = 'location' THEN p.scope_id END, l.name,
		       coalesce(p.cloud_network_ref, '')
		  FROM prefixes p
		  LEFT JOIN locations l ON p.scope_kind = 'location' AND l.id = p.scope_id AND l.tenant_id = p.tenant_id
		 WHERE p.tenant_id = $1 AND p.vrf_id IS NULL AND p.status NOT IN ('rejected', 'archived')
		 ORDER BY p.created_at, p.id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("read prefixes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	set := &PrefixSet{byID: map[uuid.UUID]*prefixInfo{}}
	var ps []approval.Prefix
	for rows.Next() {
		var (
			p        prefixInfo
			text     string
			env, loc sql.NullString
			bu, lid  uuid.NullUUID
		)
		if err := rows.Scan(&p.ID, &text, &p.NetworkType, &env, &bu, &lid, &loc, &p.CloudNetworkRef); err != nil {
			return nil, fmt.Errorf("scan prefix: %w", err)
		}
		parsed, err := ipam.ParsePrefix(text)
		if err != nil {
			continue
		}
		p.Prefix = parsed
		if env.Valid && env.String != "" {
			p.Environment = &env.String
		}
		if bu.Valid {
			p.BusinessUnitID = &bu.UUID
		}
		if lid.Valid {
			p.LocationID = &lid.UUID
			if loc.Valid && loc.String != "" {
				p.LocationName = &loc.String
			}
		}
		info := p
		set.byID[p.ID] = &info
		ps = append(ps, approval.Prefix{ID: p.ID, Prefix: parsed})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	set.match = approval.NewPrefixSet(ps)
	return set, nil
}

// Match is the prefix containing the address: the longest match, nil when the
// address is not one, is in no prefix, or the longest match is ambiguous (two
// prefixes with one CIDR — picking one would be a guess).
func (set *PrefixSet) Match(ip *string) *prefixInfo {
	if set == nil || ip == nil || strings.TrimSpace(*ip) == "" {
		return nil
	}
	p := set.match.Match(*ip)
	if p == nil {
		return nil
	}
	return set.byID[p.ID]
}

// Approval is the auto-approval index over the same read.
func (set *PrefixSet) Approval() *approval.PrefixSet {
	if set == nil {
		return nil
	}
	return set.match
}

// Classify is ownership over the set: "internal" when a prefix contains the
// address, "unknown" for an internal candidate by address class (addrscope:
// private or carrier-grade NAT), "third_party" otherwise.
func (set *PrefixSet) Classify(ip *string) string {
	if set.Match(ip) != nil {
		return "internal"
	}
	if ip != nil && NetworkTypeForAddress(*ip) == "private" {
		return "unknown"
	}
	return "third_party"
}

// classificationType is the network type a classification carries: the
// prefix's when it is one of the four the auto-approval rules and scan consent
// read, else the address class.
func classificationType(p *prefixInfo, ip *string) string {
	if p != nil {
		switch p.NetworkType {
		case "private", "public", "vpn", "cloud":
			return p.NetworkType
		}
	}
	return addressNetworkType(ip)
}

// NetworkTypeForAddress is the network type of an address no prefix
// classified: "private" for an address the tenant could own by address class
// (RFC 1918, ULA, carrier-grade NAT — addrscope.IsTenantAddressable), "public"
// otherwise. CGNAT counts as private here because the question is "inside the
// tenant or out", which for an unmatched CGNAT address is "inside, pending
// review". This does NOT make CGNAT probeable: automatic scanning and probe
// consent read addrscope.MayAutoProbe, which excludes it unless a declared
// prefix covers it.
func NetworkTypeForAddress(addr string) string {
	a, _ := addrscope.Parse(addr)
	if addrscope.IsTenantAddressable(a) {
		return "private"
	}
	return "public"
}

// prefixSetIn is the tenant's prefix set: the request's one read when there is
// a request, else a read for this question. A nil set (no database wired)
// matches nothing.
func (s *AssetService) prefixSetIn(r *importPrefixes, tenantID uuid.UUID) (*PrefixSet, error) {
	if r != nil && r.set != nil {
		return r.set, nil
	}
	if s.db == nil {
		return nil, nil
	}
	if s.onLoadPrefixSet != nil {
		s.onLoadPrefixSet(tenantID)
	}
	var set *PrefixSet
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		var err error
		set, err = loadPrefixSet(context.Background(), tx, tenantID)
		return err
	})
	if err != nil {
		return nil, err
	}
	if r != nil {
		r.set = set
	}
	return set, nil
}

// enrichAssetFromPrefix fills an asset's context from the prefix its address
// is in: environment, location (and site) and business unit where the asset
// has none, and `prefix_id`. It reports whether anything moved.
//
// A device that routes networks is the exception ( §3.4): it has an
// address on each of them, and a finding arriving on any one of those would
// otherwise move it to that prefix. Its prefix is the prefix of its home
// address — the address it is interrogated at (homeAddress) — whichever
// address the finding was on.
//
// The prefix never overwrites what a person or another source set: a prefix
// is the tenant's statement about an address range, and an asset's own
// environment or location is a statement about the asset.
func (s *AssetService) enrichAssetFromPrefix(r *importPrefixes, tenantID, assetID uuid.UUID, ip *string) (bool, error) {
	if s.db == nil {
		return false, nil
	}
	if home, ok := s.homeAddress(tenantID, assetID); ok {
		ip = &home
	}
	set, err := s.prefixSetIn(r, tenantID)
	if err != nil {
		return false, err
	}
	p := set.Match(ip)
	if p == nil {
		return false, nil
	}
	changed := false
	err = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		// The location comes with its own site (DCIM row 2.1): set where the
		// asset has no location and is in no site or in that location's site,
		// so the asset's site and location always agree.
		e := tx.QueryRow(`
		WITH prior AS (
			SELECT environment, location_id, prefix_id, business_unit_id, site_id
			  FROM assets WHERE id = $5 AND tenant_id = $6
		), loc AS (SELECT l.site_id AS lsite FROM locations l WHERE l.id = $2::uuid)
		UPDATE assets a SET
			environment = COALESCE(a.environment, $1::environment_type),
			location_id = CASE WHEN a.location_id IS NULL AND $2::uuid IS NOT NULL
			                    AND (a.site_id IS NULL OR a.site_id = (SELECT lsite FROM loc)) THEN $2::uuid ELSE a.location_id END,
			site_id = CASE WHEN a.site_id IS NULL AND a.location_id IS NULL AND $2::uuid IS NOT NULL THEN (SELECT lsite FROM loc) ELSE a.site_id END,
			prefix_id = $3,
			business_unit_id = COALESCE(a.business_unit_id, $4),
			updated_at = NOW()
		  FROM prior p
		WHERE a.id = $5 AND a.tenant_id = $6
		RETURNING p.environment IS DISTINCT FROM a.environment OR p.location_id IS DISTINCT FROM a.location_id
		       OR p.prefix_id IS DISTINCT FROM a.prefix_id OR p.business_unit_id IS DISTINCT FROM a.business_unit_id
		       OR p.site_id IS DISTINCT FROM a.site_id`,
			p.Environment, p.LocationID, p.ID, p.BusinessUnitID, assetID, tenantID).Scan(&changed)
		if errors.Is(e, sql.ErrNoRows) {
			return nil
		}
		return e
	})
	return changed, err
}

// homeAddress is the address a ROUTING device is placed by: the host of its
// management URL, for an asset that has a management row and reported a
// net.vlans fact ( §3.4) — the interrogation that wrote one wrote the
// other. A multi-homed router's prefix then does not depend on which of its
// addresses the last finding happened to arrive on.
//
// Any other asset — no management row, a management address that is a name,
// no net.vlans fact — answers false and is placed by its own address. A read
// failure also answers false: placement then falls back to the finding's
// address.
func (s *AssetService) homeAddress(tenantID, assetID uuid.UUID) (string, bool) {
	var managementURL sql.NullString
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`
			SELECT m.management_url FROM asset_management m
			WHERE m.tenant_id = $1 AND m.asset_id = $2
			  AND EXISTS (SELECT 1 FROM asset_facts f
			              WHERE f.tenant_id = m.tenant_id AND f.asset_id = m.asset_id AND f.key = $3)`,
			tenantID, assetID, facts.KeyNetVlans).Scan(&managementURL)
	})
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			log.Printf("[AssetService] home address of asset %s unreadable; placing it by the finding's address: %v", assetID, err)
		}
		return "", false
	}
	addr, err := netip.ParseAddr(managementURLHost(managementURL.String))
	if err != nil {
		return "", false
	}
	return addr.Unmap().WithZone("").String(), true
}

// managementURLHost is the host part of a management URL ("https://203.0.113.1:8443"
// gives "203.0.113.1"), or the value itself when it is a bare host.
func managementURLHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return strings.Trim(u.Hostname(), "[]")
	}
	if h, _, err := net.SplitHostPort(raw); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(raw, "[]")
}
