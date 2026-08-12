package services

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	sharednetwork "github.com/vistasecurity/vistaplatform/shared/network"
)

// ReconcileSensorAddresses makes agent_addresses match what the sensor just
// reported about itself.
//
// An empty report is "not reported", not "no addresses": older sensors omit the
// field entirely, and treating that as an instruction to delete would wipe a
// working host's address inventory on its first heartbeat after a downgrade.
// Only a non-empty report replaces the stored set.
//
// The reconcile is a delete-then-insert inside one transaction rather than a
// per-row upsert. The reported set is small (a handful of NICs), it is the whole
// truth about the host at that instant, and set-replacement means an address
// removed from the host actually disappears here instead of lingering forever —
// which a pure upsert would allow, and which would quietly overstate coverage.
func (s *SensorService) ReconcileSensorAddresses(ctx context.Context, sensorID string, addrs []sharednetwork.InterfaceAddress) error {
	if len(addrs) == 0 {
		return nil
	}

	id, err := uuid.Parse(sensorID)
	if err != nil {
		return fmt.Errorf("invalid sensor id %q: %w", sensorID, err)
	}

	// The tenant is the OUTPUT of this lookup (a sensor-facing call carries no
	// tenant context), so it resolves on the bypass handle — the same
	// bootstrap pattern the heartbeat itself uses.
	tenantID, err := s.resolveSensorTenant(ctx, sensorID)
	if err != nil {
		return err
	}

	return shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		return replaceAgentAddresses(ctx, tx, "sensor_id", id, addrs)
	})
}

// replaceAgentAddresses swaps an agent's recorded address set for the reported
// one. ownerColumn is "sensor_id" or "device_agent_id"; it is never derived from
// caller input, so the interpolation below cannot carry untrusted data.
func replaceAgentAddresses(ctx context.Context, tx *sql.Tx, ownerColumn string, ownerID uuid.UUID, addrs []sharednetwork.InterfaceAddress) error {
	if _, err := tx.ExecContext(ctx,
		fmt.Sprintf(`DELETE FROM agent_addresses WHERE %s = $1`, ownerColumn), ownerID); err != nil {
		return fmt.Errorf("failed to clear agent addresses: %w", err)
	}

	// At most one primary reaches the database. The schema enforces this with a
	// partial unique index, so a sensor reporting two would otherwise fail the
	// whole heartbeat transaction; keeping the first is more useful than losing
	// the entire address set to a misbehaving agent.
	seenPrimary := false

	for _, a := range addrs {
		if a.Address == "" || a.InterfaceName == "" {
			continue
		}

		isPrimary := a.IsPrimary && !seenPrimary
		if isPrimary {
			seenPrimary = true
		}

		var prefix interface{}
		if a.PrefixLength > 0 {
			prefix = a.PrefixLength
		}

		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`
			INSERT INTO agent_addresses (%s, interface_name, address, prefix_length, is_primary)
			VALUES ($1, $2, $3::inet, $4, $5)
			ON CONFLICT DO NOTHING`, ownerColumn),
			ownerID, a.InterfaceName, a.Address, prefix, isPrimary); err != nil {
			return fmt.Errorf("failed to record agent address %s: %w", a.Address, err)
		}
	}

	return nil
}

// ListSensorAddresses returns a sensor's recorded addresses, primary first then
// by address, so the UI renders a stable order.
//
// host(address) rather than the bare column: `address` is inet, and inet renders
// with its prefix (192.0.2.173/24) when one is set. The prefix is returned
// separately, so emitting it inside the address string too would double it up in
// the UI and break equality checks against a plain address elsewhere.
func (s *SensorService) ListSensorAddresses(ctx context.Context, tenantID uuid.UUID, sensorID uuid.UUID) ([]models.AgentAddress, error) {
	var out []models.AgentAddress
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT interface_name, host(address), prefix_length, is_primary
			FROM agent_addresses
			WHERE sensor_id = $1
			ORDER BY is_primary DESC, address`, sensorID)
		if err != nil {
			return fmt.Errorf("failed to list sensor addresses: %w", err)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var a models.AgentAddress
			var prefix sql.NullInt64
			if err := rows.Scan(&a.InterfaceName, &a.Address, &prefix, &a.IsPrimary); err != nil {
				return fmt.Errorf("failed to scan sensor address: %w", err)
			}
			if prefix.Valid {
				p := int(prefix.Int64)
				a.PrefixLength = &p
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}
