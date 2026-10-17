package services

// The LLDP / CDP half of the unresolved-termination resolver (DCIM row 3.3;
// ADR-0010 D6): a neighbour parked because its far end was not in the
// inventory becomes the proposed cable when that far interface arrives. Run
// after every intake batch that filed interfaces (IngestSightings) and hourly
// (jobs.StartCableResolverWorker).
//
// The resolver walks only the lldp / cdp cable rows (cableParkRepo): the other
// producers' rows (sync, the ARP rule) have their own matchers and appliers,
// and a resolver that matched them with this one's would apply them as cables.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/cablematch"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/dcim/unresolved"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// cableParkFilter selects the rows this resolver owns.
const cableParkFilter = `intent = 'cable' AND producer IN ('lldp', 'cdp')`

// cableParkRepo is the SQL repository narrowed to LLDP / CDP cable rows.
type cableParkRepo struct{ *UnresolvedRepository }

func (r cableParkRepo) List(ctx context.Context, tenant uuid.UUID, after uuid.UUID, limit int) ([]unresolved.Parked, error) {
	if limit <= 0 {
		limit = 500
	}
	return r.query(ctx, tenant, `SELECT `+unresolvedColumns+` FROM public.unresolved_terminations
		WHERE tenant_id = $1 AND id > $2 AND `+cableParkFilter+` ORDER BY id LIMIT $3`, tenant, after, limit)
}

func (r cableParkRepo) ExpireBefore(ctx context.Context, tenant uuid.UUID, cutoff time.Time) (int, error) {
	n := 0
	err := database.WithTenantTx(ctx, r.db, tenant, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM public.unresolved_terminations
			WHERE tenant_id = $1 AND expires_at < $2 AND `+cableParkFilter, tenant, cutoff)
		if err != nil {
			return err
		}
		c, err := res.RowsAffected()
		n = int(c)
		return err
	})
	return n, err
}

// cableMatcher resolves a parked neighbour's whole far identity to one
// interface (cablematch), never to a device alone.
type cableMatcher struct {
	unresolved.NullMatcher
	db *sql.DB
}

var _ unresolved.TerminationMatcher = cableMatcher{}

func (m cableMatcher) MatchTermination(ctx context.Context, tenant uuid.UUID, p unresolved.Parked) (unresolved.Match, bool, error) {
	if p.Intent != unresolved.IntentCable || p.OriginKind != dcim.ObjectKindInterface {
		return unresolved.Match{}, false, nil
	}
	var out unresolved.Match
	var ok bool
	err := database.WithTenantTx(ctx, m.db, tenant, func(tx *sql.Tx) error {
		var asset uuid.UUID
		err := tx.QueryRowContext(ctx, `SELECT asset_id FROM public.interfaces WHERE tenant_id = $1 AND id = $2`, tenant, p.OriginID).Scan(&asset)
		if errors.Is(err, sql.ErrNoRows) {
			return nil // the origin is gone; the row expires
		}
		if err != nil {
			return err
		}
		r, err := cablematch.Resolve(ctx, cablematch.PGDirectory{Tx: tx, Tenant: tenant}, cablematch.FromMap(p.FarIdentity), asset)
		if err != nil {
			return err
		}
		if r.Outcome == cablematch.Matched {
			out, ok = unresolved.Match{Kind: dcim.ObjectKindInterface, ID: r.Port.ID}, true
		}
		return nil
	})
	return out, ok, err
}

// cableApplier writes the proposed cable a resolved row intended.
type cableApplier struct{ c *CableIntake }

func (a cableApplier) ApplyCable(ctx context.Context, tenant uuid.UUID, p unresolved.Parked, far unresolved.Match) error {
	if far.Kind != dcim.ObjectKindInterface {
		return fmt.Errorf("lldp: a cable cannot end on a %s", far.Kind)
	}
	ref, _ := p.Attributes["source_ref"].(string)
	proto := p.Producer
	if proto != identity.NeighborProtocolLLDP && proto != identity.NeighborProtocolCDP {
		proto = identity.NeighborProtocolLLDP
	}
	return database.WithTenantTx(ctx, a.c.db, tenant, func(tx *sql.Tx) error {
		// Either port cabled since the row was parked: the next observation of
		// the neighbour judges that cable; this proposal is moot.
		for _, id := range []uuid.UUID{p.OriginID, far.ID} {
			held, err := cableOnInterface(ctx, tx, tenant, id)
			if err != nil {
				return err
			}
			if held != nil {
				return nil
			}
		}
		var live bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM public.interfaces WHERE tenant_id = $1 AND id = $2 AND status <> 'rejected')`,
			tenant, p.OriginID).Scan(&live); err != nil || !live {
			return err
		}
		_, err := a.c.cables.proposeTx(ctx, tx, tenant, p.OriginID, far.ID, proto, ref, p.LastSeenAt)
		if errors.Is(err, ErrIPAMInvalid) {
			return nil // a far port that cannot take a cable (virtual, marked connected): drop the row
		}
		return err
	})
}

func (a cableApplier) ApplyRelationship(context.Context, uuid.UUID, unresolved.Parked, string, unresolved.Match) error {
	return errors.New("lldp: the cable resolver applies cables only")
}

func (a cableApplier) ApplyAssignment(context.Context, uuid.UUID, unresolved.Parked, unresolved.Match) error {
	return errors.New("lldp: the cable resolver applies cables only")
}

// ResolveParked runs the cable resolver over the tenant's parked LLDP / CDP
// neighbours.
func (c *CableIntake) ResolveParked(ctx context.Context, tenant uuid.UUID) (unresolved.ResolvedCount, error) {
	r := unresolved.NewResolver(cableParkRepo{NewUnresolvedRepository(c.db)}, cableMatcher{db: c.db}, cableApplier{c: c}, nil)
	return r.Resolve(changes.WithSource(ctx, changes.IntakeSource(identity.NeighborProtocolLLDP)), tenant)
}

// CableResolverTenants are the tenants with a parked LLDP / CDP neighbour, read
// through the bypass connection for the hourly worker.
func CableResolverTenants(ctx context.Context, bypass *sql.DB) ([]uuid.UUID, error) {
	rows, err := bypass.QueryContext(ctx, `SELECT DISTINCT tenant_id FROM public.unresolved_terminations WHERE `+cableParkFilter+` ORDER BY tenant_id`)
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
