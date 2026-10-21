package services

// ASN ranges and VLAN translation as IPAM engine specs (DCIM gap 10; NetBox
// ipam/asn-ranges, ipam/vlan-translation-policies, ipam/vlan-translation-rules;
// schema blocks `DCIM: gap10 asn ranges` and `DCIM: gap10 vlan translation`).
// They are IPAM objects: served under /ipam, gated by ipam.read / ipam.manage,
// and synced through the same engine. Column names are binding (the API, the
// OpenAPI schemas held to them by ipam_contract_test.go, the query fields).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// asnRangeListSelect adds how many of the tenant's ASNs fall in the range and
// how many numbers are still free: the ASN ranges section's columns.
const asnRangeListSelect = `to_jsonb(t) || jsonb_build_object(
	'asn_count', (SELECT count(*) FROM public.asns a WHERE a.tenant_id = t.tenant_id AND a.asn BETWEEN t.start AND t."end"),
	'available_count', (t."end" - t.start + 1) - (SELECT count(*) FROM public.asns a WHERE a.tenant_id = t.tenant_id AND a.asn BETWEEN t.start AND t."end"))`

// vlanTranslationPolicyListSelect adds the policy's rules (local -> remote,
// in local VID order) and how many interfaces apply it.
const vlanTranslationPolicyListSelect = `to_jsonb(t) || jsonb_build_object(
	'rules', COALESCE((SELECT jsonb_agg(jsonb_build_object('id', r.id, 'local_vid', r.local_vid, 'remote_vid', r.remote_vid,
	    'description', r.description) ORDER BY r.local_vid, r.id)
	    FROM public.vlan_translation_rules r WHERE r.tenant_id = t.tenant_id AND r.policy_id = t.id), '[]'::jsonb),
	'interface_count', (SELECT count(*) FROM public.interfaces i WHERE i.tenant_id = t.tenant_id AND i.vlan_translation_policy_id = t.id))`

func ipamParitySpecs() []*ipamSpec {
	return []*ipamSpec{
		{
			Kind: dcim.ObjectKindAsnRange, Table: "asn_ranges", Route: "asn-ranges",
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "slug", Type: colText},
				ipamCol{Name: "rir_id", Type: colUUID, Required: true},
				ipamCol{Name: "start", Type: colBigint, Required: true},
				ipamCol{Name: "end", Type: colBigint, Required: true},
				ipamCol{Name: "business_unit_id", Type: colUUID},
				externalIDsCol,
			),
			Filters: []ipamFilter{
				{Param: "rir_id", Column: "rir_id", Type: colUUID},
				{Param: "slug", Column: "slug", Type: colText},
				{Param: "business_unit_id", Column: "business_unit_id", Type: colUUID},
				{Param: "contains", Custom: func(v string, n int) (string, any, error) {
					asn, err := strconv.ParseInt(v, 10, 64)
					if err != nil || asn < 1 || asn > 4294967295 {
						return "", nil, ipamInvalid("contains must be an AS number")
					}
					return fmt.Sprintf(`$%d::bigint BETWEEN t.start AND t."end"`, n), asn, nil
				}},
			},
			Search:     []string{"name", "slug", "description"},
			Order:      `t.start, t."end", t.id`,
			ListSelect: asnRangeListSelect,
			Prepare:    prepareASNRange,
		},
		{
			Kind: dcim.ObjectKindVlanTranslationPolicy, Table: "vlan_translation_policies", Route: "vlan-translation-policies",
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				externalIDsCol,
			),
			Search:     []string{"name", "description"},
			Order:      "lower(t.name), t.id",
			ListSelect: vlanTranslationPolicyListSelect,
		},
		{
			Kind: dcim.ObjectKindVlanTranslationRule, Table: "vlan_translation_rules", Route: "vlan-translation-rules",
			Cols: withSubstrate(
				ipamCol{Name: "policy_id", Type: colUUID, Required: true},
				ipamCol{Name: "local_vid", Type: colInt, Required: true},
				ipamCol{Name: "remote_vid", Type: colInt, Required: true},
				externalIDsCol,
			),
			Filters: []ipamFilter{
				{Param: "policy_id", Column: "policy_id", Type: colUUID},
				{Param: "local_vid", Column: "local_vid", Type: colInt},
				{Param: "remote_vid", Column: "remote_vid", Type: colInt},
			},
			Search: []string{"local_vid", "remote_vid", "description"},
			Order:  "t.policy_id, t.local_vid, t.id",
			Prepare: func(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
				for _, c := range []string{"local_vid", "remote_vid"} {
					if v, ok := rowInt(row[c]); ok && (v < 1 || v > 4094) {
						return ipamInvalid("%s must be between 1 and 4094", c)
					}
				}
				return visible(ctx, tx, "vlan_translation_policies", row["policy_id"])
			},
		},
	}
}

// prepareASNRange derives the slug and checks the RIR and that start <= end
// (the CHECK says it too, as a 400 without the field).
func prepareASNRange(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID, row map[string]any) error {
	if err := prepareSlug(ctx, tx, tenant, id, row); err != nil {
		return err
	}
	lo, okLo := rowInt(row["start"])
	hi, okHi := rowInt(row["end"])
	for _, b := range []struct {
		name string
		v    int
		ok   bool
	}{{"start", lo, okLo}, {"end", hi, okHi}} {
		if b.ok && (b.v < 1 || b.v > 4294967295) {
			return ipamInvalid("%s must be an AS number (1-4294967295)", b.name)
		}
	}
	if okLo && okHi && lo > hi {
		return ipamInvalid("start (%d) is after end (%d)", lo, hi)
	}
	return visible(ctx, tx, "rirs", row["rir_id"])
}

// AvailableASNs is what an ASN range has free (NetBox
// /api/ipam/asn-ranges/{id}/available-asns/): the first free numbers, how many
// are free, and how many of the tenant's ASNs are in it.
type AvailableASNs struct {
	RangeID   uuid.UUID `json:"range_id"`
	Start     int64     `json:"start"`
	End       int64     `json:"end"`
	Size      int64     `json:"size"`
	Used      int64     `json:"used"`
	Available int64     `json:"available"`
	ASNs      []int64   `json:"asns"`
}

// AvailableASNs answers the first `limit` AS numbers of the range that no ASN
// of the tenant holds, in order. The walk is over the used numbers inside the
// range (never over the whole range, which may span four billion numbers).
func (s *IPAMService) AvailableASNs(ctx context.Context, tenant, rangeID uuid.UUID, limit int) (*AvailableASNs, error) {
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	out := &AvailableASNs{RangeID: rangeID, ASNs: []int64{}}
	err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT start, "end" FROM public.asn_ranges WHERE id = $1`, rangeID).Scan(&out.Start, &out.End); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrIPAMNotFound
			}
			return err
		}
		out.Size = out.End - out.Start + 1
		// Free numbers come from the gaps between used ones: generate_series
		// over each gap, capped at the limit, so a sparse /32-bit range is not
		// enumerated.
		rows, err := tx.QueryContext(ctx, `
			WITH used AS (
			    SELECT DISTINCT asn FROM public.asns WHERE tenant_id = $1 AND asn BETWEEN $2 AND $3
			), bounds AS (
			    SELECT $2::bigint - 1 AS lo, (SELECT min(asn) FROM used) AS hi
			    UNION ALL
			    SELECT asn, lead(asn) OVER (ORDER BY asn) FROM used
			), gaps AS (
			    SELECT lo + 1 AS first, COALESCE(hi, $3::bigint + 1) - 1 AS last FROM bounds
			)
			SELECT n FROM gaps, LATERAL generate_series(first, LEAST(last, first + $4 - 1)) AS n
			 WHERE first <= last ORDER BY n LIMIT $4`, tenant, out.Start, out.End, limit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var n int64
			if err := rows.Scan(&n); err != nil {
				return err
			}
			out.ASNs = append(out.ASNs, n)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(DISTINCT asn) FROM public.asns WHERE tenant_id = $1 AND asn BETWEEN $2 AND $3`,
			tenant, out.Start, out.End).Scan(&out.Used); err != nil {
			return err
		}
		out.Available = out.Size - out.Used
		return nil
	})
	if err != nil {
		return nil, mapIPAMError(err, false)
	}
	return out, nil
}
