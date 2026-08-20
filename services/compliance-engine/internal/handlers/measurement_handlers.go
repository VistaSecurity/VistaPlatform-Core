package handlers

import (
	"database/sql"
	"net/http"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"

	"github.com/gin-gonic/gin"
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
	measurementTypes := []models.MeasurementType{}
	err := h.db.Select(&measurementTypes, `
		SELECT `+models.MeasurementTypeColumns+`
		FROM measurement_types
		ORDER BY category, code
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to list measurement types",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"measurement_types": measurementTypes,
	})
}

// GetMeasurementType gets a specific measurement type by code
func (h *MeasurementHandlers) GetMeasurementType(c *gin.Context) {
	code := c.Param("code")

	var mt models.MeasurementType
	err := h.db.Get(&mt, `
		SELECT `+models.MeasurementTypeColumns+`
		FROM measurement_types
		WHERE code = $1
	`, code)
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

	c.JSON(http.StatusOK, gin.H{
		"measurement_type": mt,
	})
}
