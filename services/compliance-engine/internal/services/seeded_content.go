package services

// Seeded-content ownership — the accept action (decision 4, RC-12).
//
// Frameworks, controls and measurement rules that Vista ships are re-applied by
// the seed on every upgrade. The database now keeps a platform admin's edits
// through those upgrades: a shipped change to a row the admin has edited is not
// applied but stored on the row as an OFFER (seed_offer), which the catalogue
// shows as "update available". This file is the one application-side piece of
// that mechanism: accepting an offer. Everything else — marking origin,
// detecting an admin edit, tombstoning a deleted row, building the offer — is
// the seeded-content guard trigger in scripts/database/schema.sql, so no seed
// statement (and no signed content bundle) has to cooperate.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
)

// ErrSeededContentNotFound: no such row under the given parent.
var ErrSeededContentNotFound = errors.New("seeded content not found")

// ErrNoSeededUpdate: the row exists but no upgrade has offered it anything.
var ErrNoSeededUpdate = errors.New("no update available")

// SeededEntity names a seeded table, in the vocabulary the database's
// accept_seeded_content_update() takes.
type SeededEntity string

const (
	SeededFramework   SeededEntity = "framework"
	SeededControl     SeededEntity = "control"
	SeededMeasurement SeededEntity = "measurement"
)

// AcceptedSeededUpdate is what an accept changed: the owning framework (for
// the reconcile fan-out) and each accepted column's value before and after,
// which is what the audit record carries.
type AcceptedSeededUpdate struct {
	FrameworkID uuid.UUID
	Before      map[string]interface{}
	After       map[string]interface{}
}

// seededLookup selects, and locks, the row an accept will change — scoped to
// its parent, so a URL naming the wrong framework or control cannot accept an
// update on a row that belongs elsewhere.
var seededLookup = map[SeededEntity]string{
	SeededFramework: `
		SELECT t.id, to_jsonb(t), t.seed_offer
		  FROM platform_frameworks t
		 WHERE t.id = $1 AND $2::uuid IS NULL
		   FOR UPDATE`,
	SeededControl: `
		SELECT t.framework_id, to_jsonb(t), t.seed_offer
		  FROM platform_framework_controls t
		 WHERE t.id = $1 AND t.framework_id = $2
		   FOR UPDATE`,
	SeededMeasurement: `
		SELECT c.framework_id, to_jsonb(t), t.seed_offer
		  FROM control_measurements t
		  JOIN platform_framework_controls c ON c.id = t.control_id
		 WHERE t.id = $1 AND t.control_id = $2 AND t.framework_type = 'platform'
		   FOR UPDATE OF t`,
}

// AcceptSeededUpdate applies the update an upgrade offered for one seeded row
// and clears the offer. parentID is the framework for a control, the control
// for a measurement rule, and uuid.Nil for a framework.
//
// The row stays the admin's: the next change Vista ships to it is offered
// again rather than applied (see the schema comment for why).
func (s *PlatformFrameworkService) AcceptSeededUpdate(entity SeededEntity, id, parentID uuid.UUID) (*AcceptedSeededUpdate, error) {
	query, ok := seededLookup[entity]
	if !ok {
		return nil, fmt.Errorf("unknown seeded entity %q", entity)
	}
	var parent interface{}
	if parentID != uuid.Nil {
		parent = parentID
	}

	tx, err := s.db.Beginx()
	if err != nil {
		return nil, fmt.Errorf("begin accept: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var (
		frameworkID uuid.UUID
		rowJSON     []byte
		offerJSON   []byte
	)
	err = tx.QueryRow(query, id, parent).Scan(&frameworkID, &rowJSON, &offerJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSeededContentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load seeded row: %w", err)
	}
	if offerJSON == nil {
		return nil, ErrNoSeededUpdate
	}

	var accepted bool
	if err := tx.QueryRow(`SELECT public.accept_seeded_content_update($1, $2)`, string(entity), id).Scan(&accepted); err != nil {
		return nil, fmt.Errorf("accept seeded update: %w", err)
	}
	if !accepted {
		return nil, ErrNoSeededUpdate
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit accept: %w", err)
	}

	var row, offer map[string]interface{}
	if err := json.Unmarshal(rowJSON, &row); err != nil {
		return nil, fmt.Errorf("decode seeded row: %w", err)
	}
	if err := json.Unmarshal(offerJSON, &offer); err != nil {
		return nil, fmt.Errorf("decode seeded offer: %w", err)
	}
	before := make(map[string]interface{}, len(offer))
	for k := range offer {
		before[k] = row[k]
	}

	// A control's text or a rule's predicate is what a framework evaluates; a
	// framework's name, description and organization are not.
	if entity != SeededFramework {
		s.reconcileFrameworkChanged(frameworkID, "framework_changed")
	}
	return &AcceptedSeededUpdate{FrameworkID: frameworkID, Before: before, After: offer}, nil
}

// GetPlatformControl reads one platform control with its seeded-content state.
func (s *PlatformFrameworkService) GetPlatformControl(controlID uuid.UUID) (*models.PlatformFrameworkControl, error) {
	var control models.PlatformFrameworkControl
	err := s.db.Get(&control, `
		SELECT `+models.FrameworkControlColumns+`, `+models.SeededContentColumns+`
		FROM platform_framework_controls
		WHERE id = $1`, controlID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSeededContentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get platform control: %w", err)
	}
	return &control, nil
}

// GetPlatformMeasurement reads one platform measurement rule with its
// seeded-content state.
func (s *PlatformFrameworkService) GetPlatformMeasurement(measurementID uuid.UUID) (*models.ControlMeasurement, error) {
	var (
		m                models.ControlMeasurement
		predicateBytes   []byte
		severityOverride sql.NullString
	)
	err := s.db.QueryRow(`
		SELECT id, control_id, framework_type, measurement_type_id, rule_type, predicate, severity_override, weight, created_at, updated_at,
		       `+models.SeededContentColumns+`
		FROM control_measurements
		WHERE id = $1 AND framework_type = 'platform'`, measurementID).Scan(
		&m.ID, &m.ControlID, &m.FrameworkType, &m.MeasurementTypeID, &m.RuleType, &predicateBytes, &severityOverride, &m.Weight, &m.CreatedAt, &m.UpdatedAt,
		&m.ContentOrigin, &m.AdminModified, &m.UpdateAvailable, &m.OfferedUpdate)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSeededContentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get platform measurement: %w", err)
	}
	if len(predicateBytes) > 0 {
		_ = json.Unmarshal(predicateBytes, &m.Predicate)
	}
	if severityOverride.Valid {
		m.SeverityOverride = severityOverride.String
	}
	return &m, nil
}
