package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// MeasurementHandlers contains all measurement type handlers
type MeasurementHandlers struct {
	db *sqlx.DB
}

// NewMeasurementHandlers creates a new instance of measurement handlers
func NewMeasurementHandlers(db *sqlx.DB) *MeasurementHandlers {
	return &MeasurementHandlers{db: db}
}

// ListMeasurementTypes lists all available measurement types
func (h *MeasurementHandlers) ListMeasurementTypes(c *gin.Context) {
	query := `
		SELECT id, code, name, description, data_type, extraction_query, units, valid_range, 
		       allowed_rule_types, enum_values, valid_operators, predicate_schema, category,
		       created_at, updated_at
		FROM measurement_types
		ORDER BY category, code
	`

	type MeasurementTypeRow struct {
		ID               uuid.UUID        `db:"id"`
		Code             string           `db:"code"`
		Name             string           `db:"name"`
		Description      sql.NullString   `db:"description"`
		DataType         string           `db:"data_type"`
		ExtractionQuery  sql.NullString   `db:"extraction_query"`
		Units            sql.NullString   `db:"units"`
		ValidRange       *json.RawMessage `db:"valid_range"`
		AllowedRuleTypes *json.RawMessage `db:"allowed_rule_types"`
		EnumValues       *json.RawMessage `db:"enum_values"`
		ValidOperators   *json.RawMessage `db:"valid_operators"`
		PredicateSchema  *json.RawMessage `db:"predicate_schema"`
		Category         sql.NullString   `db:"category"`
		CreatedAt        time.Time        `db:"created_at"`
		UpdatedAt        time.Time        `db:"updated_at"`
	}

	var rows []MeasurementTypeRow
	err := h.db.Select(&rows, query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to list measurement types",
		})
		return
	}

	measurementTypes := make([]models.MeasurementType, 0, len(rows))
	for _, row := range rows {
		mt := models.MeasurementType{
			ID:        row.ID,
			Code:      row.Code,
			Name:      row.Name,
			DataType:  row.DataType,
			CreatedAt: row.CreatedAt,
			UpdatedAt: row.UpdatedAt,
		}

		if row.Description.Valid {
			mt.Description = row.Description.String
		}
		if row.ExtractionQuery.Valid {
			mt.ExtractionQuery = row.ExtractionQuery.String
		}
		if row.Units.Valid {
			mt.Units = row.Units.String
		}
		if row.Category.Valid {
			mt.Category = row.Category.String
		}

		// Unmarshal JSONB fields
		if row.ValidRange != nil && len(*row.ValidRange) > 0 {
			mt.ValidRange = make(map[string]interface{})
			_ = json.Unmarshal(*row.ValidRange, &mt.ValidRange)
		}

		if row.AllowedRuleTypes != nil && len(*row.AllowedRuleTypes) > 0 {
			var allowedTypes []string
			if err := json.Unmarshal(*row.AllowedRuleTypes, &allowedTypes); err == nil {
				mt.AllowedRuleTypes = allowedTypes
			}
		}

		if row.EnumValues != nil && len(*row.EnumValues) > 0 {
			var enumVals []interface{}
			if err := json.Unmarshal(*row.EnumValues, &enumVals); err == nil {
				mt.EnumValues = enumVals
			}
		}

		if row.ValidOperators != nil && len(*row.ValidOperators) > 0 {
			var operators []string
			if err := json.Unmarshal(*row.ValidOperators, &operators); err == nil {
				mt.ValidOperators = operators
			}
		}

		if row.PredicateSchema != nil && len(*row.PredicateSchema) > 0 {
			mt.PredicateSchema = make(map[string]interface{})
			_ = json.Unmarshal(*row.PredicateSchema, &mt.PredicateSchema)
		}

		measurementTypes = append(measurementTypes, mt)
	}

	c.JSON(http.StatusOK, gin.H{
		"measurement_types": measurementTypes,
	})
}

// GetMeasurementType gets a specific measurement type by code
func (h *MeasurementHandlers) GetMeasurementType(c *gin.Context) {
	code := c.Param("code")

	query := `
		SELECT id, code, name, description, data_type, extraction_query, units, valid_range,
		       allowed_rule_types, enum_values, valid_operators, predicate_schema, category,
		       created_at, updated_at
		FROM measurement_types
		WHERE code = $1
	`

	type MeasurementTypeRow struct {
		ID               uuid.UUID        `db:"id"`
		Code             string           `db:"code"`
		Name             string           `db:"name"`
		Description      sql.NullString   `db:"description"`
		DataType         string           `db:"data_type"`
		ExtractionQuery  sql.NullString   `db:"extraction_query"`
		Units            sql.NullString   `db:"units"`
		ValidRange       *json.RawMessage `db:"valid_range"`
		AllowedRuleTypes *json.RawMessage `db:"allowed_rule_types"`
		EnumValues       *json.RawMessage `db:"enum_values"`
		ValidOperators   *json.RawMessage `db:"valid_operators"`
		PredicateSchema  *json.RawMessage `db:"predicate_schema"`
		Category         sql.NullString   `db:"category"`
		CreatedAt        time.Time        `db:"created_at"`
		UpdatedAt        time.Time        `db:"updated_at"`
	}

	var row MeasurementTypeRow
	err := h.db.Get(&row, query, code)

	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Measurement type not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get measurement type",
		})
		return
	}

	mt := models.MeasurementType{
		ID:        row.ID,
		Code:      row.Code,
		Name:      row.Name,
		DataType:  row.DataType,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}

	if row.Description.Valid {
		mt.Description = row.Description.String
	}
	if row.ExtractionQuery.Valid {
		mt.ExtractionQuery = row.ExtractionQuery.String
	}
	if row.Units.Valid {
		mt.Units = row.Units.String
	}
	if row.Category.Valid {
		mt.Category = row.Category.String
	}

	// Unmarshal JSONB fields
	if row.ValidRange != nil && len(*row.ValidRange) > 0 {
		mt.ValidRange = make(map[string]interface{})
		_ = json.Unmarshal(*row.ValidRange, &mt.ValidRange)
	}

	if row.AllowedRuleTypes != nil && len(*row.AllowedRuleTypes) > 0 {
		var allowedTypes []string
		if err := json.Unmarshal(*row.AllowedRuleTypes, &allowedTypes); err == nil {
			mt.AllowedRuleTypes = allowedTypes
		}
	}

	if row.EnumValues != nil && len(*row.EnumValues) > 0 {
		var enumVals []interface{}
		if err := json.Unmarshal(*row.EnumValues, &enumVals); err == nil {
			mt.EnumValues = enumVals
		}
	}

	if row.ValidOperators != nil && len(*row.ValidOperators) > 0 {
		var operators []string
		if err := json.Unmarshal(*row.ValidOperators, &operators); err == nil {
			mt.ValidOperators = operators
		}
	}

	if row.PredicateSchema != nil && len(*row.PredicateSchema) > 0 {
		mt.PredicateSchema = make(map[string]interface{})
		_ = json.Unmarshal(*row.PredicateSchema, &mt.PredicateSchema)
	}

	c.JSON(http.StatusOK, gin.H{
		"measurement_type": mt,
	})
}
