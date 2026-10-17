package services

// Computed IPAM reads and the utilisation cache (DCIM BUILD_PLAN row 1.3).
//
// Containment is computed from the addresses, within ONE VRF: every query here
// filters `COALESCE(vrf_id, zero) = COALESCE($vrf, zero)`, which is what makes
// "longest match" mean the same routing domain. The prefix tree is one query
// (every prefix of the VRF) shaped in Go by shared/dcim/ipam.BuildTree — no
// recursive SQL.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"math/big"
	"net/netip"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim/ipam"
)

// vrfClause is the VRF filter every computed query uses; $n is the VRF id or
// NULL for the global table.
func vrfClause(alias string, n int) string {
	return fmt.Sprintf("COALESCE(%s.vrf_id, '%s'::uuid) = COALESCE($%d::uuid, '%s'::uuid)", alias, zeroUUID, n, zeroUUID)
}

type prefixRow struct {
	ID           uuid.UUID
	Prefix       netip.Prefix
	VRF          *uuid.UUID
	Container    bool
	IsPool       bool
	MarkUtilized bool
}

func vrfArg(v *uuid.UUID) any {
	if v == nil {
		return nil
	}
	return *v
}

// ---------------------------------------------------------------------------
// Utilisation cache
// ---------------------------------------------------------------------------

// refreshChain recomputes prefix_utilization for every prefix of the VRF that
// contains target (an address or a prefix) — the written object's ancestor
// chain, itself included.
func refreshChain(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, vrf any, target string) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, prefix::text, vrf_id, operational_status = 'container', is_pool, mark_utilized
		  FROM public.prefixes t
		 WHERE t.tenant_id = $1 AND `+vrfClause("t", 2)+` AND t.prefix >>= $3::inet AND t.status <> 'rejected'`,
		tenant, vrf, target)
	if err != nil {
		return err
	}
	chain, err := scanPrefixRows(rows)
	if err != nil {
		return err
	}
	for _, p := range chain {
		if err := refreshOne(ctx, tx, tenant, p); err != nil {
			return err
		}
	}
	return nil
}

func scanPrefixRows(rows *sql.Rows) ([]prefixRow, error) {
	defer func() { _ = rows.Close() }()
	var out []prefixRow
	for rows.Next() {
		var r prefixRow
		var p string
		var vrf uuid.NullUUID
		if err := rows.Scan(&r.ID, &p, &vrf, &r.Container, &r.IsPool, &r.MarkUtilized); err != nil {
			return nil, err
		}
		pp, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, err
		}
		r.Prefix = pp
		if vrf.Valid {
			v := vrf.UUID
			r.VRF = &v
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// utilizationOf computes a prefix's utilisation, counts and all, with the
// arithmetic of shared/dcim/ipam and SQL doing the counting.
func utilizationOf(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, p prefixRow) (childCount, ipCount int, res ipam.UtilizationResult, err error) {
	vrf := vrfArg(p.VRF)
	cidr := p.Prefix.String()
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.prefixes t WHERE t.tenant_id = $1 AND `+vrfClause("t", 2)+
		` AND t.prefix << $3::cidr AND t.status <> 'rejected'`, tenant, vrf, cidr).Scan(&childCount); err != nil {
		return
	}
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.ip_addresses t WHERE t.tenant_id = $1 AND `+vrfClause("t", 2)+
		` AND t.host BETWEEN public.ipam_host(network($3::cidr)) AND public.ipam_host(broadcast($3::cidr)) AND t.status <> 'rejected'`, tenant, vrf, cidr).Scan(&ipCount); err != nil {
		return
	}
	in := ipam.UtilizationInput{Prefix: p.Prefix, Container: p.Container, IsPool: p.IsPool, MarkUtilized: p.MarkUtilized}
	if p.Container {
		// Every descendant, one scan of the VRF; ipam.Utilization merges
		// nested and overlapping children itself (a self-join for the
		// maximal ones costs n² under RLS, where << cannot use an index).
		var rows *sql.Rows
		rows, err = tx.QueryContext(ctx, `
			SELECT c.prefix::text FROM public.prefixes c
			 WHERE c.tenant_id = $1 AND `+vrfClause("c", 2)+` AND c.prefix << $3::cidr AND c.status <> 'rejected'`, tenant, vrf, cidr)
		if err != nil {
			return
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var s string
			if err = rows.Scan(&s); err != nil {
				return
			}
			c, perr := netip.ParsePrefix(s)
			if perr != nil {
				err = perr
				return
			}
			in.Children = append(in.Children, c)
		}
		if err = rows.Err(); err != nil {
			return
		}
		res = ipam.Utilization(in)
		return
	}
	// Non-container: utilised ranges (few) in Go, addresses outside them
	// counted in SQL, so a /16 with 60k addresses is one aggregate.
	ranges, err := utilizedRanges(ctx, tx, tenant, vrf, cidr)
	if err != nil {
		return
	}
	in.UtilizedRanges = ranges
	rangeRes := ipam.Utilization(in)
	first, last := usableBounds(p)
	var outside int64
	if err = tx.QueryRowContext(ctx, `
		SELECT count(DISTINCT a.host) FROM public.ip_addresses a
		 WHERE a.tenant_id = $1 AND `+vrfClause("a", 2)+` AND a.status <> 'rejected'
		   AND a.host BETWEEN public.ipam_host(network($3::cidr)) AND public.ipam_host(broadcast($3::cidr))
		   AND a.host BETWEEN $4::inet AND $5::inet
		   AND NOT EXISTS (SELECT 1 FROM public.ip_ranges r
		                    WHERE r.tenant_id = $1 AND `+vrfClause("r", 2)+` AND r.mark_utilized
		                      AND family(r.start_address) = family(a.address)
		                      AND a.host BETWEEN public.ipam_host(r.start_address) AND public.ipam_host(r.end_address))`,
		tenant, vrf, cidr, first.String(), last.String()).Scan(&outside); err != nil {
		return
	}
	used := new(big.Int).Add(rangeRes.Used, big.NewInt(outside))
	res = ipam.UtilizationResult{Used: used, Size: rangeRes.Size, Percent: ipam.Percent(used, rangeRes.Size)}
	if p.MarkUtilized {
		res.Percent = 100
	}
	return
}

// usableBounds is the first and last candidate address of p.
func usableBounds(p prefixRow) (netip.Addr, netip.Addr) {
	r := ipam.PrefixRange(p.Prefix)
	if p.IsPool || !p.Prefix.Addr().Is4() || p.Prefix.Bits() >= 31 {
		return r.Start, r.End
	}
	return r.Start.Next(), r.End.Prev()
}

func utilizedRanges(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, vrf any, cidr string) ([]ipam.Range, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT host(r.start_address), host(r.end_address) FROM public.ip_ranges r
		 WHERE r.tenant_id = $1 AND `+vrfClause("r", 2)+` AND r.mark_utilized
		   AND family(r.start_address) = family($3::cidr)
		   AND public.ipam_host(r.start_address) <= public.ipam_host(broadcast($3::cidr))
		   AND public.ipam_host(r.end_address) >= public.ipam_host(network($3::cidr))`, tenant, vrf, cidr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ipam.Range
	for rows.Next() {
		var a, b string
		if err := rows.Scan(&a, &b); err != nil {
			return nil, err
		}
		s, err1 := netip.ParseAddr(a)
		e, err2 := netip.ParseAddr(b)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, ipam.Range{Start: s, End: e})
	}
	return out, rows.Err()
}

func refreshOne(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, p prefixRow) error {
	childCount, ipCount, res, err := utilizationOf(ctx, tx, tenant, p)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO public.prefix_utilization (prefix_id, tenant_id, child_count, ip_count, utilization, refreshed_at)
		VALUES ($1, $2, $3, $4, $5, now())
		ON CONFLICT (prefix_id) DO UPDATE SET child_count = EXCLUDED.child_count, ip_count = EXCLUDED.ip_count,
		    utilization = EXCLUDED.utilization, refreshed_at = now()`,
		p.ID, tenant, childCount, ipCount, res.Percent)
	return err
}

func rowVRF(row map[string]any) any {
	if row == nil {
		return nil
	}
	return nullableString(row["vrf_id"])
}

// refreshAfterPrefixWrite: a prefix changes its own utilisation and every
// ancestor's child space and counts, in the old and the new place.
func refreshAfterPrefixWrite(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, pre, post map[string]any) error {
	for _, row := range []map[string]any{pre, post} {
		if row == nil {
			continue
		}
		if err := refreshChain(ctx, tx, tenant, rowVRF(row), fmt.Sprint(row["prefix"])); err != nil {
			return err
		}
	}
	return nil
}

func refreshAfterAddressWrite(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, pre, post map[string]any) error {
	for _, row := range []map[string]any{pre, post} {
		if row == nil {
			continue
		}
		p, err := ipam.ParseInterfaceAddr(fmt.Sprint(row["address"]))
		if err != nil {
			return err
		}
		if err := refreshChain(ctx, tx, tenant, rowVRF(row), p.Addr().String()); err != nil {
			return err
		}
	}
	return nil
}

// refreshAfterRangeWrite refreshes the prefixes the range starts and ends in;
// a utilised range spanning two siblings is rare enough to cover both ends.
func refreshAfterRangeWrite(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, pre, post map[string]any) error {
	for _, row := range []map[string]any{pre, post} {
		if row == nil {
			continue
		}
		for _, col := range []string{"start_address", "end_address"} {
			p, err := ipam.ParseInterfaceAddr(fmt.Sprint(row[col]))
			if err != nil {
				return err
			}
			if err := refreshChain(ctx, tx, tenant, rowVRF(row), p.Addr().String()); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Prefix detail
// ---------------------------------------------------------------------------

// PrefixDetail is GET /ipam/prefixes/{id}: the prefix and what is computed
// from it.
type PrefixDetail struct {
	Prefix            json.RawMessage   `json:"prefix"`
	Parent            json.RawMessage   `json:"parent"`
	Depth             int               `json:"depth"`
	Children          []json.RawMessage `json:"children"`
	ChildCount        int               `json:"child_count"`
	IPCount           int               `json:"ip_count"`
	Utilization       UtilizationView   `json:"utilization"`
	AvailablePrefixes []string          `json:"available_prefixes"`
	AvailableIPs      AvailableIPsView  `json:"available_ips"`
	IPRanges          []json.RawMessage `json:"ip_ranges"`
	// Gateway is the device that reported routing this network (DCIM
	// row 1.6), null when none has. Coverage is the tenant collector that can
	// reach it, null when none can. FHRPGroups are the redundancy groups whose
	// virtual address is in it (an HA gateway), [] when none is recorded.
	Gateway    *models.PrefixGateway  `json:"gateway"`
	Coverage   *models.PrefixCoverage `json:"coverage"`
	FHRPGroups []models.FHRPGroupRef  `json:"fhrp_groups"`
}

// UtilizationView is a utilisation as the API reports it: sizes as decimal
// strings (an IPv6 prefix overflows a JSON number).
type UtilizationView struct {
	Percent float64 `json:"percent"`
	Used    string  `json:"used"`
	Size    string  `json:"size"`
}

// AvailableIPsView is the first free addresses and how many there are.
type AvailableIPsView struct {
	Addresses           []string `json:"addresses"`
	Available           string   `json:"available"`
	SubnetRouterAnycast *string  `json:"subnet_router_anycast"`
}

// PrefixDetailParams bounds the computed parts.
type PrefixDetailParams struct {
	AvailableLength int // /n for available_prefixes; 0 = free blocks
	AvailableLimit  int
	IPLimit         int
}

func loadPrefixRow(ctx context.Context, tx *sql.Tx, id uuid.UUID) (prefixRow, json.RawMessage, error) {
	var raw []byte
	var p prefixRow
	var s string
	var vrf uuid.NullUUID
	err := tx.QueryRowContext(ctx, `
		SELECT to_jsonb(t) || jsonb_build_object('utilization', COALESCE(u.utilization, 0),
		         'child_count', COALESCE(u.child_count, 0), 'ip_count', COALESCE(u.ip_count, 0)),
		       t.id, t.prefix::text, t.vrf_id, t.operational_status = 'container', t.is_pool, t.mark_utilized
		  FROM public.prefixes t LEFT JOIN public.prefix_utilization u ON u.prefix_id = t.id
		 WHERE t.id = $1`, id).Scan(&raw, &p.ID, &s, &vrf, &p.Container, &p.IsPool, &p.MarkUtilized)
	if errors.Is(err, sql.ErrNoRows) {
		return p, nil, ErrIPAMNotFound
	}
	if err != nil {
		return p, nil, err
	}
	if p.Prefix, err = netip.ParsePrefix(s); err != nil {
		return p, nil, err
	}
	if vrf.Valid {
		v := vrf.UUID
		p.VRF = &v
	}
	return p, raw, nil
}

// PrefixDetail computes a prefix's parent, depth, direct children, live
// utilisation, available prefixes and addresses, and the IP ranges inside it.
func (s *IPAMService) PrefixDetail(ctx context.Context, tenant, id uuid.UUID, prm PrefixDetailParams) (*PrefixDetail, error) {
	var out *PrefixDetail
	err := s.tx(ctx, tenant, func(tx *sql.Tx) error {
		p, raw, err := loadPrefixRow(ctx, tx, id)
		if err != nil {
			return err
		}
		vrf := vrfArg(p.VRF)
		cidr := p.Prefix.String()
		d := &PrefixDetail{Prefix: raw, Parent: json.RawMessage("null"), Children: []json.RawMessage{}, IPRanges: []json.RawMessage{}}

		// Ancestors (for parent + depth) and descendants (for children and
		// available prefixes), one query each.
		var parentRaw []byte
		err = tx.QueryRowContext(ctx, `
			SELECT to_jsonb(t), (SELECT count(*) FROM public.prefixes a WHERE a.tenant_id = $1 AND `+vrfClause("a", 2)+`
			                      AND a.prefix >> $3::cidr AND a.status <> 'rejected')
			  FROM public.prefixes t WHERE t.tenant_id = $1 AND `+vrfClause("t", 2)+` AND t.prefix >> $3::cidr AND t.status <> 'rejected'
			 ORDER BY masklen(t.prefix) DESC LIMIT 1`, tenant, vrf, cidr).Scan(&parentRaw, &d.Depth)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if parentRaw != nil {
			d.Parent = parentRaw
		}

		rows, err := tx.QueryContext(ctx, `
			SELECT to_jsonb(t) || jsonb_build_object('utilization', COALESCE(u.utilization, 0),
			         'child_count', COALESCE(u.child_count, 0), 'ip_count', COALESCE(u.ip_count, 0)), t.prefix::text
			  FROM public.prefixes t LEFT JOIN public.prefix_utilization u ON u.prefix_id = t.id
			 WHERE t.tenant_id = $1 AND `+vrfClause("t", 2)+` AND t.prefix << $3::cidr AND t.status <> 'rejected'
			 ORDER BY masklen(t.prefix), t.prefix`, tenant, vrf, cidr)
		if err != nil {
			return err
		}
		var desc []netip.Prefix
		byPrefix := map[netip.Prefix]json.RawMessage{}
		for rows.Next() {
			var r []byte
			var ps string
			if err := rows.Scan(&r, &ps); err != nil {
				_ = rows.Close()
				return err
			}
			pp, err := netip.ParsePrefix(ps)
			if err != nil {
				_ = rows.Close()
				return err
			}
			desc = append(desc, pp)
			byPrefix[pp] = r
		}
		_ = rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, c := range ipam.ChildPrefixes(p.Prefix, desc) {
			d.Children = append(d.Children, byPrefix[c])
		}
		d.ChildCount = len(desc)

		avail, err := ipam.AvailablePrefixes(p.Prefix, desc, prm.AvailableLength, prm.AvailableLimit)
		if err != nil {
			return ipamInvalid("%v", err)
		}
		d.AvailablePrefixes = make([]string, 0, len(avail))
		for _, a := range avail {
			d.AvailablePrefixes = append(d.AvailablePrefixes, a.String())
		}

		// Addresses and ranges inside the prefix.
		used, err := hostsIn(ctx, tx, tenant, vrf, cidr)
		if err != nil {
			return err
		}
		d.IPCount = len(used)
		rrows, err := tx.QueryContext(ctx, `
			SELECT to_jsonb(r), host(r.start_address), host(r.end_address), r.mark_utilized FROM public.ip_ranges r
			 WHERE r.tenant_id = $1 AND `+vrfClause("r", 2)+` AND family(r.start_address) = family($3::cidr)
			   AND public.ipam_host(r.start_address) <= public.ipam_host(broadcast($3::cidr))
			   AND public.ipam_host(r.end_address) >= public.ipam_host(network($3::cidr))
			 ORDER BY r.start_address`, tenant, vrf, cidr)
		if err != nil {
			return err
		}
		var reserved []ipam.Range
		rangeSpec, _ := s.spec("ip-ranges")
		for rrows.Next() {
			var r []byte
			var a, b string
			var util bool
			if err := rrows.Scan(&r, &a, &b, &util); err != nil {
				_ = rrows.Close()
				return err
			}
			if pr, err := present(rangeSpec, r); err == nil {
				d.IPRanges = append(d.IPRanges, pr)
			}
			if util {
				sa, _ := netip.ParseAddr(a)
				ea, _ := netip.ParseAddr(b)
				reserved = append(reserved, ipam.Range{Start: sa, End: ea})
			}
		}
		_ = rrows.Close()
		if err := rrows.Err(); err != nil {
			return err
		}

		ai := ipam.AvailableIPs(p.Prefix, used, reserved, p.IsPool, prm.IPLimit)
		d.AvailableIPs = AvailableIPsView{Addresses: make([]string, 0, len(ai.First)), Available: ai.Available.String()}
		for _, a := range ai.First {
			d.AvailableIPs.Addresses = append(d.AvailableIPs.Addresses, a.String())
		}
		if ai.SubnetRouterAnycast != nil {
			s := ai.SubnetRouterAnycast.String()
			d.AvailableIPs.SubnetRouterAnycast = &s
		}

		var children []netip.Prefix
		if p.Container {
			children = desc
		}
		u := ipam.Utilization(ipam.UtilizationInput{Prefix: p.Prefix, Container: p.Container, IsPool: p.IsPool,
			MarkUtilized: p.MarkUtilized, Children: children, Addresses: used, UtilizedRanges: reserved})
		d.Utilization = UtilizationView{Percent: u.Percent, Used: u.Used.String(), Size: u.Size.String()}

		// Who routes it, who can reach it, and its HA gateway
		// (prefix_gateway.go).
		gateways, err := readPrefixGateways(ctx, tx, tenant, []uuid.UUID{p.ID})
		if err != nil {
			return err
		}
		d.Gateway = gateways[p.ID]
		groups, err := readPrefixFHRPGroups(ctx, tx, tenant, []uuid.UUID{p.ID})
		if err != nil {
			return err
		}
		d.FHRPGroups = groups[p.ID]
		if d.FHRPGroups == nil {
			d.FHRPGroups = []models.FHRPGroupRef{}
		}
		if p.VRF == nil {
			cov, err := prefixCoverageTx(ctx, tx, tenant, p.ID, p.Prefix)
			if err != nil {
				return err
			}
			d.Coverage = cov
		}
		out = d
		return nil
	})
	return out, mapIPAMError(err, false)
}

func hostsIn(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, vrf any, cidr string) ([]netip.Addr, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT DISTINCT host(t.address) FROM public.ip_addresses t
		 WHERE t.tenant_id = $1 AND `+vrfClause("t", 2)+` AND t.host BETWEEN public.ipam_host(network($3::cidr)) AND public.ipam_host(broadcast($3::cidr)) AND t.status <> 'rejected'`,
		tenant, vrf, cidr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []netip.Addr
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		a, err := netip.ParseAddr(h)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Prefix tree
// ---------------------------------------------------------------------------

// PrefixTreeNode is one prefix of the tree with its direct children.
type PrefixTreeNode struct {
	Prefix   json.RawMessage   `json:"prefix"`
	Depth    int               `json:"depth"`
	Children []*PrefixTreeNode `json:"children"`
}

// PrefixTree returns every live prefix of one VRF (nil = the global table) as
// a forest. One query; ipam.BuildTree shapes it.
func (s *IPAMService) PrefixTree(ctx context.Context, tenant uuid.UUID, vrf *uuid.UUID) ([]*PrefixTreeNode, int, error) {
	var out []*PrefixTreeNode
	total := 0
	err := s.tx(ctx, tenant, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT to_jsonb(t) || jsonb_build_object('utilization', COALESCE(u.utilization, 0),
			         'child_count', COALESCE(u.child_count, 0), 'ip_count', COALESCE(u.ip_count, 0)), t.prefix::text
			  FROM public.prefixes t LEFT JOIN public.prefix_utilization u ON u.prefix_id = t.id
			 WHERE t.tenant_id = $1 AND `+vrfClause("t", 2)+` AND t.status <> 'rejected'
			 ORDER BY masklen(t.prefix), t.prefix`, tenant, vrfArg(vrf))
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		var raws []json.RawMessage
		var ps []netip.Prefix
		for rows.Next() {
			var r []byte
			var p string
			if err := rows.Scan(&r, &p); err != nil {
				return err
			}
			pp, err := netip.ParsePrefix(p)
			if err != nil {
				return err
			}
			raws = append(raws, r)
			ps = append(ps, pp)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		total = len(ps)
		var conv func(ns []*ipam.Node) []*PrefixTreeNode
		conv = func(ns []*ipam.Node) []*PrefixTreeNode {
			out := make([]*PrefixTreeNode, 0, len(ns))
			for _, n := range ns {
				out = append(out, &PrefixTreeNode{Prefix: raws[n.Index], Depth: n.Depth, Children: conv(n.Children)})
			}
			return out
		}
		out = conv(ipam.BuildTree(ps))
		return nil
	})
	return out, total, mapIPAMError(err, false)
}
