package services

// The measurement catalogue the rule builder reads.
//
// `GET /measurement-types` used to be a plain SELECT over the table, which made
// the table the vocabulary. That is one authority too many: the table is seeded
// from standards/measurement-types.yaml, but a row left behind by an older
// release stayed offerable forever, and its data type, allowed rule types and
// enum values were whatever that release wrote — while the extractor served
// what the CURRENT registry says. A rule authored against a stale row is a
// control that quietly cannot fail.
//
// So the registry decides what is offered and what each type means, and the
// table supplies only the `id` — which is real state, because
// control_measurements.measurement_type_id points at it and must keep pointing
// at the same row across releases.
//
// A registry type with no row cannot be authored against (there is no id to
// reference), so it is omitted and NAMED in the returned slice rather than
// silently skipped: that state means the seed did not run, and the caller logs
// it. The integration contract test asserts the two sets are equal on a seeded
// database, which is what makes the omission path an alarm rather than a
// habit.

import (
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
)

// MeasurementCatalogue returns the registry as API rows with their ids
// resolved, plus two kinds of code it could NOT offer: `missing` — declared but
// absent from `measurement_types`, so there is no id to reference — and
// `unservable` — declared and seeded, but the row does not compile against the
// shapes this binary carries.
//
// The two are separated because the operator's next move differs: `missing`
// means the seed did not run, `unservable` means the registry and the shapes in
// the same binary disagree and no re-seed will help.
//
// Rows in the table that the registry does not declare are NOT returned: an
// offered measurement type must be one the extractor can serve.
func MeasurementCatalogue(db *sqlx.DB) (types []models.MeasurementType, missing, unservable []string, err error) {
	var rows []struct {
		ID        uuid.UUID `db:"id"`
		Code      string    `db:"code"`
		CreatedAt time.Time `db:"created_at"`
		UpdatedAt time.Time `db:"updated_at"`
	}
	if err := db.Select(&rows, `SELECT id, code, created_at, updated_at FROM measurement_types`); err != nil {
		return nil, nil, nil, fmt.Errorf("read measurement types: %w", err)
	}
	byCode := make(map[string]int, len(rows))
	for i, r := range rows {
		byCode[r.Code] = i
	}
	// The runtime belt. A row that does not compile is one the extractor
	// refuses on every call, so offering it would let an admin author a control
	// that can neither pass nor fail — the check-that-cannot-fail shape, arrived
	// at from the authoring end instead of the SQL end.
	broken := measurementCompileErrors()

	for _, def := range measurementTypeRegistry {
		if _, bad := broken[def.Code]; bad {
			unservable = append(unservable, def.Code)
			continue
		}
		i, ok := byCode[def.Code]
		if !ok {
			missing = append(missing, def.Code)
			continue
		}
		types = append(types, measurementTypeAPIRow(def, rows[i].ID, rows[i].CreatedAt, rows[i].UpdatedAt))
	}
	// Category then code: the order the rule builder groups by, and the order
	// the endpoint has always returned.
	sort.SliceStable(types, func(a, b int) bool {
		if types[a].Category != types[b].Category {
			return types[a].Category < types[b].Category
		}
		return types[a].Code < types[b].Code
	})
	return types, missing, unservable, nil
}

// MeasurementCatalogueEntry returns one registry type with its id resolved, or
// false when the code is not registered, not seeded, or does not compile.
//
// All three are the same answer to the caller — there is nothing to author a
// rule against — and it must match what the list returns, or a type the list
// withheld would still be reachable by its own URL.
func MeasurementCatalogueEntry(db *sqlx.DB, code string) (models.MeasurementType, bool, error) {
	def, ok := MeasurementTypeByCode(code)
	if !ok {
		return models.MeasurementType{}, false, nil
	}
	if _, bad := measurementCompileErrors()[code]; bad {
		return models.MeasurementType{}, false, nil
	}
	var row struct {
		ID        uuid.UUID `db:"id"`
		CreatedAt time.Time `db:"created_at"`
		UpdatedAt time.Time `db:"updated_at"`
	}
	if err := db.Get(&row, `SELECT id, created_at, updated_at FROM measurement_types WHERE code = $1`, code); err != nil {
		// Registered but not seeded is the same answer to the caller as
		// unknown: there is nothing to author a rule against.
		return models.MeasurementType{}, false, nil
	}
	return measurementTypeAPIRow(def, row.ID, row.CreatedAt, row.UpdatedAt), true, nil
}

// measurementTypeAPIRow renders a registry row in the API's shape. Everything
// but the id, and the two timestamps that say when the row was seeded, comes
// from the registry.
func measurementTypeAPIRow(def MeasurementTypeDef, id uuid.UUID, createdAt, updatedAt time.Time) models.MeasurementType {
	out := models.MeasurementType{
		ID:          id,
		Code:        def.Code,
		Name:        def.Name,
		Description: def.Description,
		DataType:    def.DataType,
		Units:       def.Units,
		Category:    def.Category,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}
	if def.ValidRange != nil {
		out.ValidRange = shareddb.JSONMap{"min": def.ValidRange.Min, "max": def.ValidRange.Max}
	}
	if len(def.AllowedRuleTypes) > 0 {
		out.AllowedRuleTypes = shareddb.JSONStringSlice(def.AllowedRuleTypes)
	}
	if len(def.ValidOperators) > 0 {
		out.ValidOperators = shareddb.JSONStringSlice(def.ValidOperators)
	}
	if len(def.EnumValues) > 0 {
		values := make(shareddb.JSONSlice, 0, len(def.EnumValues))
		for _, v := range def.EnumValues {
			values = append(values, v)
		}
		out.EnumValues = values
	}
	return out
}
