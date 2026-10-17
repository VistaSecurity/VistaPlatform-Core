package services

// The LLDP / CDP cable intake (DCIM BUILD_PLAN row 3.3; asset-inventory
// ADR-0010 D6).
//
// A sighting carries the observed device's neighbour table
// (identity.ObservedNeighbor). Once the sighting resolved to an asset, each
// neighbour is judged against the cables on its local port:
//
//   - the port's cable agrees with the neighbour (its far end — through any
//     patch panels, by the cached cable path, for an accepted cable; the other
//     end, for a proposal) → observation_count / last_seen_at bumped and
//     lldp_confirmed_at stamped (a declared cable the network confirms);
//   - an ACCEPTED cable on the port (or on the far port the neighbour names)
//     disagrees → a contradiction, collected into the asset's one
//     `topology/cable_drift` finding through shared/findings;
//   - our own earlier proposal disagrees → it is stale and is deleted, and the
//     neighbour is handled as on a free port;
//   - a free port whose neighbour resolves to a known, free interface
//     (shared/dcim/cablematch) → a PROPOSED cable: measured, pending, label =
//     the protocol, through CableService, reviewed in Discovery → Approvals;
//   - a free port whose far end is not in the inventory yet → an unresolved
//     termination (producer lldp|cdp, intent cable, far identity chassis id /
//     port id / system name / management address), which the resolver
//     materialises as the proposed cable when the far interface arrives.
//
// The asset's neighbour table is a full statement: when no contradiction is
// left, its drift finding is resolved. Undecidable cases (an ambiguous far
// identity, a path that ends at an unmodelled patch panel, a far device that
// is not in the inventory while the port's cable names one that is) are left
// alone — never guessed into a finding.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/cablematch"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/dcim/unresolved"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// CableIntake files neighbour observations as cables, parked terminations and
// drift findings.
type CableIntake struct {
	db     *sql.DB
	cables *CableService
}

// NewCableIntake returns the intake over db (the raw pool; RLS per tx).
func NewCableIntake(db *sql.DB, cables *CableService) *CableIntake {
	return &CableIntake{db: db, cables: cables}
}

// CableIntakeResult is what one neighbour table did.
type CableIntakeResult struct {
	Proposed       int
	Confirmed      int
	Parked         int
	Contradictions int
	// Skipped neighbours: no such local interface, an ambiguous far end, or a
	// far end that cannot take this cable.
	Skipped int
}

// ifaceCable is the cable on one interface, as the judge needs it.
type ifaceCable struct {
	id         uuid.UUID
	status     string
	sourceKind string
	// far is the other end's interfaces (a proposal is interface to interface).
	far []farPort
}

type farPort struct {
	ID      uuid.UUID `json:"interface_id"`
	AssetID uuid.UUID `json:"asset_id"`
	Name    string    `json:"interface"`
}

// RecordNeighbors judges asset's neighbour table, observed at `at` by src.
func (c *CableIntake) RecordNeighbors(ctx context.Context, tenant, asset uuid.UUID, in []identity.ObservedNeighbor, src identity.Source, at time.Time) (CableIntakeResult, error) {
	var res CableIntakeResult
	neighbors, dropped := identity.NormalizeObservedNeighbors(in)
	for _, d := range dropped {
		log.Printf("[CableIntake] asset %s: %s", asset, d)
	}
	if len(neighbors) == 0 {
		return res, nil
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	ctx = changes.WithSource(ctx, changes.IntakeSource(identity.NeighborProtocolLLDP))
	err := database.WithTenantTx(ctx, c.db, tenant, func(tx *sql.Tx) error {
		res = CableIntakeResult{}
		locals, err := assetInterfaceNames(ctx, tx, tenant, asset)
		if err != nil {
			return err
		}
		dir := cablematch.PGDirectory{Tx: tx, Tenant: tenant}
		var contradictions []map[string]any
		for i, n := range neighbors {
			local, ok := locals[strings.ToLower(n.LocalInterface)]
			if !ok {
				res.Skipped++
				continue
			}
			// Each neighbour in its own savepoint: one that cannot be filed
			// (a far port that cannot take a cable, a race on the port) is
			// skipped without undoing the others.
			sp := fmt.Sprintf("cable_nb_%d", i)
			if _, err := tx.ExecContext(ctx, "SAVEPOINT "+sp); err != nil {
				return err
			}
			contra, err := c.recordOne(ctx, tx, tenant, asset, local, n, src, at, dir, &res)
			if err != nil {
				if _, rerr := tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT "+sp); rerr != nil {
					return rerr
				}
				log.Printf("[CableIntake] asset %s port %s: neighbour %q not filed: %v", asset, n.LocalInterface, n.RemoteSystemName, err)
				res.Skipped++
				continue
			}
			if _, err := tx.ExecContext(ctx, "RELEASE SAVEPOINT "+sp); err != nil {
				return err
			}
			contradictions = append(contradictions, contra...)
		}
		res.Contradictions = len(contradictions)
		return writeCableDrift(ctx, tx, tenant, asset, contradictions)
	})
	return res, err
}

// recordOne judges one neighbour heard on interface local of asset.
func (c *CableIntake) recordOne(ctx context.Context, tx *sql.Tx, tenant, asset, local uuid.UUID, n identity.ObservedNeighbor,
	src identity.Source, at time.Time, dir cablematch.Directory, res *CableIntakeResult) ([]map[string]any, error) {
	far := cablematch.FromNeighbor(n)
	r, err := cablematch.Resolve(ctx, dir, far, asset)
	if err != nil {
		return nil, err
	}
	observed := observedEvidence(n, r)

	cur, err := cableOnInterface(ctx, tx, tenant, local)
	if err != nil {
		return nil, err
	}
	if cur != nil {
		v, cableFar, err := judgeCable(ctx, tx, tenant, dir, asset, local, cur, far, r)
		if err != nil {
			return nil, err
		}
		switch {
		case v == verdictAgree:
			if err := observeTx(ctx, tx, tenant, cur.id, at); err != nil {
				return nil, err
			}
			res.Confirmed++
			return nil, clearParkedCable(ctx, tx, tenant, local, nil)
		case v == verdictUndetermined:
			return nil, nil
		case cur.status == "active":
			return []map[string]any{{
				"local_interface": n.LocalInterface, "local_interface_id": local, "cable_id": cur.id,
				"cable_far": cableFar, "observed": observed,
			}}, nil
		case cur.sourceKind == "measured":
			// Our own proposal, which the network no longer reports: stale.
			if err := c.cables.deleteTx(ctx, tx, tenant, cur.id); err != nil {
				return nil, err
			}
		default:
			// A declared cable nobody has accepted (pending) disagrees: not a
			// cable of record, not ours to replace.
			return nil, nil
		}
	}

	switch r.Outcome {
	case cablematch.Matched:
		held, err := cableOnInterface(ctx, tx, tenant, r.Port.ID)
		if err != nil {
			return nil, err
		}
		if held != nil {
			// The far port is cabled elsewhere. An accepted cable there is
			// contradicted; a proposal there is the far device's own view,
			// which its own observation settles.
			if held.status == "active" {
				return []map[string]any{{
					"local_interface": n.LocalInterface, "local_interface_id": local, "cable_id": held.id,
					"cable_far": held.far, "far_port_cabled_elsewhere": true, "observed": observed,
				}}, nil
			}
			res.Skipped++
			return nil, nil
		}
		if _, err := c.cables.proposeTx(ctx, tx, tenant, local, r.Port.ID, n.Protocol, src.Ref, at); err != nil {
			return nil, err
		}
		res.Proposed++
		return nil, clearParkedCable(ctx, tx, tenant, local, nil)
	case cablematch.Ambiguous:
		res.Skipped++
		return nil, nil
	}

	// The far end is not in the inventory (or its port is not, yet): park it.
	ident := far.Map()
	if err := clearParkedCable(ctx, tx, tenant, local, ident); err != nil {
		return nil, err
	}
	if _, err := parkTx(ctx, tx, tenant, unresolved.Termination{
		Producer: n.Protocol, OriginKind: dcim.ObjectKindInterface, OriginID: local,
		FarIdentity: ident, Intent: unresolved.IntentCable,
		Attributes: map[string]any{"protocol": n.Protocol, "observed_on": asset.String(), "source_ref": src.Ref},
	}, at); err != nil {
		return nil, err
	}
	res.Parked++
	return nil, nil
}

type verdict int

const (
	verdictUndetermined verdict = iota
	verdictAgree
	verdictContradict
)

// judgeCable compares the cable on a port with what the neighbour says is on
// the far end. An accepted cable is compared by its PATH's far end (a
// declared cable usually lands on a patch panel; LLDP sees through it); a path
// that does not end on an interface cannot be judged. A proposal (or a
// rejected one) is compared by its other end.
func judgeCable(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, dir cablematch.Directory, self, local uuid.UUID,
	cur *ifaceCable, far cablematch.FarIdentity, r cablematch.Result) (verdict, []farPort, error) {
	ends := cur.far
	if cur.status == "active" {
		var kind sql.NullString
		var dest uuid.NullUUID
		var complete bool
		err := tx.QueryRowContext(ctx, `SELECT destination_kind, destination_id, is_complete FROM public.cable_paths
			WHERE tenant_id = $1 AND origin_kind = 'interface' AND origin_id = $2`, tenant, local).Scan(&kind, &dest, &complete)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && (!dest.Valid || kind.String != string(dcim.ObjectKindInterface))) {
			return verdictUndetermined, nil, nil
		}
		if err != nil {
			return verdictUndetermined, nil, err
		}
		fp, err := cableFarInterface(ctx, tx, tenant, dest.UUID)
		if err != nil || fp == nil {
			return verdictUndetermined, nil, err
		}
		ends = []farPort{*fp}
	}
	if len(ends) == 0 {
		return verdictUndetermined, nil, nil
	}
	if r.Outcome == cablematch.Matched {
		for _, e := range ends {
			if e.ID == r.Port.ID {
				return verdictAgree, ends, nil
			}
		}
		return verdictContradict, ends, nil
	}
	// The neighbour did not resolve to one interface. Is the cable's far
	// device among the devices it names?
	ids, _, err := cablematch.Candidates(ctx, dir, far)
	if err != nil {
		return verdictUndetermined, nil, err
	}
	var others bool
	for _, id := range ids {
		if id == self {
			continue
		}
		if id != ends[0].AssetID {
			others = true
			continue
		}
		ports, err := dir.Ports(ctx, id)
		if err != nil {
			return verdictUndetermined, nil, err
		}
		p, oc := cablematch.MatchPort(far.PortID, far.PortDescr, ports)
		if oc != cablematch.Matched {
			return verdictUndetermined, ends, nil // the right device, a port we cannot place
		}
		for _, e := range ends {
			if e.ID == p.ID {
				return verdictAgree, ends, nil
			}
		}
		return verdictContradict, ends, nil
	}
	if others {
		return verdictContradict, ends, nil // the neighbour is a different known device
	}
	return verdictUndetermined, ends, nil // the neighbour is unknown to the inventory
}

// cableOnInterface returns the cable on an interface, nil when it has none.
func cableOnInterface(ctx context.Context, tx *sql.Tx, tenant, iface uuid.UUID) (*ifaceCable, error) {
	var c ifaceCable
	var end string
	err := tx.QueryRowContext(ctx, `
		SELECT c.id, c.status, c.source_kind, ct.cable_end
		  FROM public.cable_terminations ct JOIN public.cables c ON c.tenant_id = ct.tenant_id AND c.id = ct.cable_id
		 WHERE ct.tenant_id = $1 AND ct.termination_kind = 'interface' AND ct.termination_id = $2`, tenant, iface).
		Scan(&c.id, &c.status, &c.sourceKind, &end)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT f.id, f.asset_id, f.name FROM public.cable_terminations ct
		  JOIN public.interfaces f ON f.tenant_id = ct.tenant_id AND f.id = ct.termination_id
		 WHERE ct.tenant_id = $1 AND ct.cable_id = $2 AND ct.cable_end <> $3 AND ct.termination_kind = 'interface'
		 ORDER BY f.name, f.id`, tenant, c.id, end)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var p farPort
		if err := rows.Scan(&p.ID, &p.AssetID, &p.Name); err != nil {
			return nil, err
		}
		c.far = append(c.far, p)
	}
	return &c, rows.Err()
}

func cableFarInterface(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID) (*farPort, error) {
	var p farPort
	err := tx.QueryRowContext(ctx, `SELECT id, asset_id, name FROM public.interfaces WHERE tenant_id = $1 AND id = $2`, tenant, id).
		Scan(&p.ID, &p.AssetID, &p.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &p, err
}

// assetInterfaceNames maps each of the asset's interfaces by lower-cased name.
func assetInterfaceNames(ctx context.Context, tx *sql.Tx, tenant, asset uuid.UUID) (map[string]uuid.UUID, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, name FROM public.interfaces WHERE tenant_id = $1 AND asset_id = $2 AND status <> 'rejected'`, tenant, asset)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out[strings.ToLower(name)] = id
	}
	return out, rows.Err()
}

// clearParkedCable deletes the LLDP / CDP cable terminations parked for an
// interface — all of them (keep = nil: the port is now cabled), or those whose
// far identity differs from keep (the neighbour on the port changed).
func clearParkedCable(ctx context.Context, tx *sql.Tx, tenant, iface uuid.UUID, keep map[string]string) error {
	if keep == nil {
		_, err := tx.ExecContext(ctx, `DELETE FROM public.unresolved_terminations
			WHERE tenant_id = $1 AND origin_kind = 'interface' AND origin_id = $2 AND intent = 'cable' AND producer IN ('lldp', 'cdp')`,
			tenant, iface)
		return err
	}
	b, err := json.Marshal(keep)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM public.unresolved_terminations
		WHERE tenant_id = $1 AND origin_kind = 'interface' AND origin_id = $2 AND intent = 'cable' AND producer IN ('lldp', 'cdp')
		  AND far_identity <> $3::jsonb`, tenant, iface, string(b))
	return err
}

// observedEvidence is what the neighbour said, and what it resolved to.
func observedEvidence(n identity.ObservedNeighbor, r cablematch.Result) map[string]any {
	e := map[string]any{"protocol": n.Protocol}
	for k, v := range map[string]string{
		"chassis_id": n.RemoteChassisID, "port_id": n.RemotePortID, "port_descr": n.RemotePortDescr,
		"system_name": n.RemoteSystemName, "mgmt_address": n.RemoteMgmtAddress,
	} {
		if v != "" {
			e[k] = v
		}
	}
	if r.Outcome == cablematch.Matched {
		e["asset_id"], e["interface_id"], e["interface"] = r.Port.AssetID, r.Port.ID, r.Port.Name
	}
	return e
}

// writeCableDrift raises (or refreshes) the asset's cable drift finding with
// every contradicted port in evidence, or resolves it when there is none.
func writeCableDrift(ctx context.Context, tx *sql.Tx, tenant, asset uuid.UUID, contradictions []map[string]any) error {
	subject := producer.Subject{Type: findings.SubjectAsset, ID: asset}
	if len(contradictions) == 0 {
		_, err := topologyWriter.Resolve(ctx, tx, tenant, findings.KindCableDrift, subject)
		return err
	}
	sort.Slice(contradictions, func(i, j int) bool {
		return fmt.Sprint(contradictions[i]["local_interface"]) < fmt.Sprint(contradictions[j]["local_interface"])
	})
	var label sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(NULLIF(display_name, ''), NULLIF(hostname, ''), host(primary_address))
		FROM public.assets WHERE tenant_id = $1 AND id = $2`, tenant, asset).Scan(&label); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	detail := fmt.Sprint(contradictions[0]["local_interface"])
	if len(contradictions) > 1 {
		detail = fmt.Sprintf("%d ports", len(contradictions))
	}
	subjectName := label.String
	if subjectName == "" {
		subjectName = "This asset"
	}
	_, err := topologyWriter.Upsert(ctx, tx, tenant, producer.Finding{
		Kind:         findings.KindCableDrift,
		Subject:      subject,
		SubjectLabel: label.String,
		Severity:     producer.SeverityMedium,
		Score:        0,
		Summary:      fmt.Sprintf("%s's cabling differs from what its neighbours report (%s)", subjectName, detail),
		Evidence:     map[string]any{"contradictions": contradictions},
		SourceKind:   producer.SourceMeasured,
	})
	return err
}
