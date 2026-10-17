package services

// Proposed cables (DCIM BUILD_PLAN row 3.3; asset-inventory ADR-0010 D6).
//
// An LLDP / CDP neighbour between two known interfaces becomes a cable that
// is `measured` and `pending`: it holds both ports (a port is on one cable) but
// no path runs over it (shared/dcim/cablepath skips unaccepted cables) until a
// person approves it in Discovery → Approvals. Approving sets `status =
// active` (the object engine stamps approved_by / approved_at) and recomputes
// the paths; rejecting sets `status = rejected`, which keeps the cable — and
// so suppresses re-proposing the same pairing — until someone deletes it.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/cablepath"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer"
)

// ErrCableNotPending is an approve or reject of a cable that is not a pending
// proposal.
var ErrCableNotPending = errors.New("cable is not awaiting approval")

// proposeTx writes a measured, pending cable between interfaces a and b on
// the caller's transaction, observed at `at`, and returns its id. label is the
// protocol that saw it (lldp, cdp); sourceRef the observation's source.
func (s *CableService) proposeTx(ctx context.Context, tx *sql.Tx, tenant, a, b uuid.UUID, label, sourceRef string, at time.Time) (uuid.UUID, error) {
	sp, _ := s.eng.spec(CableRoute)
	at0, bt, err := checkEnds(ctx, tx, tenant, uuid.Nil,
		[]TerminationRef{{Kind: dcim.ObjectKindInterface, ID: a}}, []TerminationRef{{Kind: dcim.ObjectKindInterface, ID: b}})
	if err != nil {
		return uuid.Nil, err
	}
	row := map[string]any{"status": "pending", "source_kind": "measured", "label": label}
	if sourceRef != "" {
		row["source_ref"] = sourceRef
	}
	post, err := s.eng.createTx(ctx, tx, sp, tenant, row, changes.IntakeSource(label))
	if err != nil {
		return uuid.Nil, err
	}
	id, err := uuid.Parse(fmt.Sprint(post["id"]))
	if err != nil {
		return uuid.Nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE public.cables SET first_seen_at = $3, last_seen_at = $3, observation_count = 1
		WHERE tenant_id = $1 AND id = $2`, tenant, id, at); err != nil {
		return uuid.Nil, err
	}
	if err := s.attachAll(ctx, tx, tenant, id, at0, bt); err != nil {
		return uuid.Nil, err
	}
	nodes, err := cablepath.CableNodes(ctx, tx, tenant, id)
	if err != nil {
		return uuid.Nil, err
	}
	return id, recomputeAround(ctx, tx, tenant, nodes)
}

// observeTx counts one more observation of a cable the network agrees with:
// observation_count + 1, last_seen_at and lldp_confirmed_at moved to `at`.
// Observation bookkeeping, not an edit: no change record.
func observeTx(ctx context.Context, tx *sql.Tx, tenant, cable uuid.UUID, at time.Time) error {
	_, err := tx.ExecContext(ctx, `UPDATE public.cables SET observation_count = observation_count + 1,
		last_seen_at = GREATEST(last_seen_at, $3), lldp_confirmed_at = GREATEST(COALESCE(lldp_confirmed_at, $3), $3)
		WHERE tenant_id = $1 AND id = $2`, tenant, cable, at)
	return err
}

// Approve accepts a proposed cable: status active, paths recomputed.
func (s *CableService) Approve(ctx context.Context, tenant, id uuid.UUID) (json.RawMessage, error) {
	return s.decide(ctx, tenant, id, "active")
}

// Reject refuses a proposed cable: status rejected. The cable keeps its ports,
// so the same pairing is not proposed again until someone deletes it.
func (s *CableService) Reject(ctx context.Context, tenant, id uuid.UUID) (json.RawMessage, error) {
	return s.decide(ctx, tenant, id, "rejected")
}

func (s *CableService) decide(ctx context.Context, tenant, id uuid.UUID, status string) (json.RawMessage, error) {
	var current string
	err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT status FROM public.cables WHERE tenant_id = $1 AND id = $2`, tenant, id).Scan(&current)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrIPAMNotFound
	}
	if err != nil {
		return nil, err
	}
	if current != "pending" {
		return nil, fmt.Errorf("%w: %w (status %s)", ErrIPAMConflict, ErrCableNotPending, current)
	}
	body, _ := json.Marshal(map[string]string{"status": status})
	return s.Update(ctx, tenant, id, body)
}

// cableEndAssets are the assets a cable's terminations are on.
func cableEndAssets(ctx context.Context, tx *sql.Tx, tenant, cable uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT asset_id FROM public.cable_terminations
		WHERE tenant_id = $1 AND cable_id = $2 AND asset_id IS NOT NULL`, tenant, cable)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// topologyWriter writes the `topology` producer's findings.
var topologyWriter = func() *producer.Writer {
	w, err := producer.New(findings.ProducerTopology)
	if err != nil {
		panic(err) // the registry is generated into this binary; a missing key is a build fault
	}
	return w
}()

// resolveCableDriftTx resolves the open cable drift finding of each asset: a
// cable on it changed, which answers the contradiction until the next
// observation says otherwise.
func resolveCableDriftTx(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, assets []uuid.UUID) error {
	seen := map[uuid.UUID]bool{}
	for _, a := range assets {
		if a == uuid.Nil || seen[a] {
			continue
		}
		seen[a] = true
		if _, err := topologyWriter.Resolve(ctx, tx, tenant, findings.KindCableDrift,
			producer.Subject{Type: findings.SubjectAsset, ID: a}); err != nil {
			return fmt.Errorf("resolving cable drift on %s: %w", a, err)
		}
	}
	return nil
}
