package services

// VPNService owns the VPN objects (DCIM BUILD_PLAN row 4.3; ADR-0010 D8;
// DATA_MODEL §7 VPN). CRUD runs on the object engine (ipam_engine.go) over
// vpnSpecs(): one tenant-scoped transaction per call, RLS in force, every
// write recorded in object_changes. Two things are layered on top:
//
//   - an IKE or IPsec policy's proposals are a junction (ike_policy_proposals
//     / ipsec_policy_proposals), written from the body's `proposals` list of
//     ids in the policy's own transaction;
//   - a read returns the row in its list shape (the spec's ListSelect), so a
//     tunnel or proposal fetched by id carries the same posture — catalogue
//     assessments, weakest component, PQC class — as the list does.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
)

// VPNService is the VPN store.
type VPNService struct {
	db  *sql.DB
	eng *IPAMService
}

// NewVPNService returns the store over db (the raw pool; RLS per transaction).
func NewVPNService(db *sql.DB) *VPNService {
	return &VPNService{db: db, eng: newObjectEngine(db, vpnSpecs())}
}

// vpnPolicyJunction names a policy route's proposal junction.
type vpnPolicyJunction struct{ table, policyCol, proposalCol, proposalTable string }

var vpnPolicyJunctions = map[string]vpnPolicyJunction{
	"ike-policies":   {"ike_policy_proposals", "ike_policy_id", "ike_proposal_id", "ike_proposals"},
	"ipsec-policies": {"ipsec_policy_proposals", "ipsec_policy_id", "ipsec_proposal_id", "ipsec_proposals"},
}

// List returns one page of route's objects.
func (s *VPNService) List(ctx context.Context, tenant uuid.UUID, route string, p IPAMListParams) ([]json.RawMessage, int, error) {
	return s.eng.List(ctx, tenant, route, p)
}

// Get returns one object in its list shape.
func (s *VPNService) Get(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) (json.RawMessage, error) {
	sp, err := s.eng.spec(route)
	if err != nil {
		return nil, err
	}
	var out json.RawMessage
	err = database.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		out, err = vpnGetShaped(ctx, tx, sp, id)
		return err
	})
	return out, mapIPAMError(err, false)
}

func vpnGetShaped(ctx context.Context, tx *sql.Tx, sp *ipamSpec, id uuid.UUID) (json.RawMessage, error) {
	sel := sp.ListSelect
	if sel == "" {
		sel = "to_jsonb(t)"
	}
	var raw []byte
	err := tx.QueryRowContext(ctx, fmt.Sprintf(`SELECT %s FROM public.%s t WHERE t.id = $1`, sel, pq.QuoteIdentifier(sp.Table)), id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrIPAMNotFound
	}
	if err != nil {
		return nil, err
	}
	return present(sp, raw)
}

// splitProposals takes a policy body's `proposals` list out of the body.
func splitProposals(route string, body []byte) ([]byte, []uuid.UUID, bool, error) {
	if _, ok := vpnPolicyJunctions[route]; !ok {
		return body, nil, false, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil || m == nil {
		return nil, nil, false, ipamInvalid("body must be a JSON object")
	}
	raw, ok := m["proposals"]
	if !ok {
		return body, nil, false, nil
	}
	delete(m, "proposals")
	var ids []string
	if err := json.Unmarshal(raw, &ids); err != nil {
		return nil, nil, false, ipamInvalid("proposals must be a list of ids")
	}
	out := make([]uuid.UUID, 0, len(ids))
	for _, s := range ids {
		id, err := uuid.Parse(strings.TrimSpace(s))
		if err != nil {
			return nil, nil, false, ipamInvalid("proposals: %q is not a UUID", s)
		}
		out = append(out, id)
	}
	rest, err := json.Marshal(m)
	if err != nil {
		return nil, nil, false, err
	}
	return rest, out, true, nil
}

// Create creates one object (with its proposals, for a policy).
func (s *VPNService) Create(ctx context.Context, tenant uuid.UUID, route string, body []byte) (json.RawMessage, error) {
	return s.write(ctx, tenant, route, uuid.Nil, body)
}

// Update patches one object; a policy body that names `proposals` replaces
// the policy's proposal list.
func (s *VPNService) Update(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID, body []byte) (json.RawMessage, error) {
	return s.write(ctx, tenant, route, id, body)
}

func (s *VPNService) write(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID, body []byte) (json.RawMessage, error) {
	sp, err := s.eng.spec(route)
	if err != nil {
		return nil, err
	}
	rest, proposals, setProposals, err := splitProposals(route, body)
	if err != nil {
		return nil, err
	}
	patch, err := decodeBody(sp, rest)
	if err != nil {
		return nil, err
	}
	var out json.RawMessage
	err = database.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		var row map[string]any
		var err error
		if id == uuid.Nil {
			row, err = s.eng.createTx(ctx, tx, sp, tenant, patch, "")
		} else {
			row, err = s.eng.updateTx(ctx, tx, sp, tenant, id, patch, "")
		}
		if err != nil {
			return err
		}
		rowID, err := uuid.Parse(fmt.Sprint(row["id"]))
		if err != nil {
			return err
		}
		if setProposals {
			if err := setPolicyProposals(ctx, tx, route, tenant, rowID, proposals, ""); err != nil {
				return err
			}
		}
		out, err = vpnGetShaped(ctx, tx, sp, rowID)
		return err
	})
	return out, mapIPAMError(err, false)
}

// setPolicyProposals makes a policy's proposal list exactly ids, recording the
// change on the policy (the junction has no identity of its own).
func setPolicyProposals(ctx context.Context, tx *sql.Tx, route string, tenant, policy uuid.UUID, ids []uuid.UUID, source changes.Source) error {
	j := vpnPolicyJunctions[route]
	for _, id := range ids {
		if err := visible(ctx, tx, j.proposalTable, id.String()); err != nil {
			return err
		}
	}
	before, err := policyProposalIDs(ctx, tx, j, tenant, policy)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM public.%s WHERE tenant_id = $1 AND %s = $2 AND NOT (%s = ANY($3::uuid[]))`,
		j.table, j.policyCol, j.proposalCol), tenant, policy, pq.Array(uuidStrings(ids))); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`INSERT INTO public.%s (tenant_id, %s, %s) SELECT $1, $2, unnest($3::uuid[]) ON CONFLICT DO NOTHING`,
		j.table, j.policyCol, j.proposalCol), tenant, policy, pq.Array(uuidStrings(ids))); err != nil {
		return err
	}
	after, err := policyProposalIDs(ctx, tx, j, tenant, policy)
	if err != nil {
		return err
	}
	if strings.Join(before, ",") == strings.Join(after, ",") {
		return nil
	}
	sp := vpnSpecByRoute(route)
	return changes.InTx(tx).Record(ctx, changes.Change{TenantID: tenant, Kind: sp.Kind, ID: policy, Action: changes.ActionUpdate,
		Source: source, Pre: map[string]any{"id": policy.String(), "proposals": before}, Post: map[string]any{"id": policy.String(), "proposals": after}})
}

func policyProposalIDs(ctx context.Context, tx *sql.Tx, j vpnPolicyJunction, tenant, policy uuid.UUID) ([]string, error) {
	rows, err := tx.QueryContext(ctx, fmt.Sprintf(`SELECT %s::text FROM public.%s WHERE tenant_id = $1 AND %s = $2 ORDER BY 1`, j.proposalCol, j.table, j.policyCol), tenant, policy)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []string{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func vpnSpecByRoute(route string) *ipamSpec {
	for _, sp := range vpnSpecs() {
		if sp.Route == route {
			return sp
		}
	}
	return nil
}

// Delete removes one object. A policy a profile uses, or a profile a tunnel
// uses (SET NULL there), follows the schema's rules: a protected reference
// answers ErrIPAMInUse.
func (s *VPNService) Delete(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) error {
	return s.eng.Delete(ctx, tenant, route, id)
}

// VPNObjectInfo describes one VPN route for the contract tests.
func VPNObjects() []IPAMObjectInfo {
	var out []IPAMObjectInfo
	for _, sp := range vpnSpecs() {
		info := IPAMObjectInfo{Route: sp.Route, Table: sp.Table, Kind: string(sp.Kind)}
		for _, c := range sp.Cols {
			if c.Computed {
				continue
			}
			info.Writable = append(info.Writable, c.Name)
			if c.Required {
				info.Required = append(info.Required, c.Name)
			}
		}
		out = append(out, info)
	}
	return out
}
