package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// ErrSensorGone is returned when an edit targets a sensor that does not exist,
// belongs to another tenant, or has been soft-deleted.
var ErrSensorGone = errors.New("sensor not found")

// UpdateSensorFields writes only the columns present in edit, plus updated_at.
// It never touches status or last_heartbeat, so an edit cannot regress a
// heartbeat that landed between the caller's read and this write. An empty
// edit just bumps updated_at.
func (s *SensorService) UpdateSensorFields(sensorID, tenantID uuid.UUID, edit models.SensorEdit) error {
	sets := []string{"updated_at = $2"}
	args := []interface{}{sensorID, time.Now()}
	add := func(col string, v interface{}) {
		args = append(args, v)
		sets = append(sets, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	if edit.Name != nil {
		add("name", *edit.Name)
	}
	if edit.Description != nil {
		add("description", *edit.Description)
	}
	if edit.AirGapped != nil {
		add("air_gapped", *edit.AirGapped)
	}
	if edit.Tags != nil {
		add("tags", pq.Array(edit.Tags))
	}
	query := "UPDATE sensors SET "
	for i, set := range sets {
		if i > 0 {
			query += ", "
		}
		query += set
	}
	query += " WHERE id = $1 AND deleted_at IS NULL"

	ctx := context.Background()
	return shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrSensorGone
		}
		return nil
	})
}

// ApplySensorInterfaceChange adds and removes monitored interfaces in one
// transaction holding the sensor row lock, so two concurrent edits both land
// instead of the later write replacing the earlier one. It returns the
// resulting list. Newly added interfaces are listed first, then the surviving
// existing ones, matching the order the handler has always returned.
func (s *SensorService) ApplySensorInterfaceChange(ctx context.Context, sensorID, tenantID uuid.UUID, addIfaces, removeIfaces []string) ([]string, error) {
	var result []string
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		var current []string
		err := tx.QueryRowContext(ctx,
			`SELECT network_interfaces FROM sensors WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`,
			sensorID).Scan(pq.Array(&current))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrSensorGone
		}
		if err != nil {
			return err
		}
		merged := make([]string, 0, len(current)+len(addIfaces))
		for _, iface := range addIfaces {
			if !slices.Contains(current, iface) && !slices.Contains(merged, iface) {
				merged = append(merged, iface)
			}
		}
		for _, iface := range current {
			if !slices.Contains(removeIfaces, iface) {
				merged = append(merged, iface)
			}
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE sensors SET network_interfaces = $2, updated_at = NOW() WHERE id = $1`,
			sensorID, pq.Array(merged)); err != nil {
			return err
		}
		result = merged
		return nil
	})
	return result, err
}
