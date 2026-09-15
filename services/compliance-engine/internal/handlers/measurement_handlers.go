package handlers

import (
	"log"
	"net/http"
	"strings"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

// MeasurementHandlers serves the measurement-type catalogue the rule builder
// reads.
//
// The catalogue comes from the REGISTRY (standards/measurement-types.yaml, via
// services.MeasurementCatalogue), not from a SELECT over `measurement_types`.
// The table supplies only the row id, which control_measurements references.
// A row the table carries and the registry does not is not offered: authoring a
// rule against a measurement type the extractor cannot serve produces a control
// that is silently never assessed.
type MeasurementHandlers struct {
	db *sqlx.DB
}

// NewMeasurementHandlers creates a new instance of measurement handlers
func NewMeasurementHandlers(db *sqlx.DB) *MeasurementHandlers {
	return &MeasurementHandlers{db: db}
}

// ListMeasurementTypes lists the measurement types a control rule may target.
func (h *MeasurementHandlers) ListMeasurementTypes(c *gin.Context) {
	measurementTypes, missing, unservable, err := services.MeasurementCatalogue(h.db)
	if err != nil {
		log.Printf("[MeasurementHandlers] ERROR: measurement catalogue unreadable: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to list measurement types",
		})
		return
	}
	if len(unservable) > 0 {
		// Seeded, but the registry row does not compile against this binary's
		// shapes, so the extractor refuses it on every call. Withholding it is
		// the point — a rule authored against it could neither pass nor fail —
		// but the withholding must be audible, or a measurement type simply
		// disappears from the rule builder with nothing said. A re-seed does not
		// fix this one; the build is wrong.
		log.Printf("[MeasurementHandlers] ERROR: %d measurement type(s) are seeded but do not compile "+
			"and have been withheld from the rule builder — see the [MeasurementExtractor] lines at "+
			"startup for the reason on each: %s", len(unservable), strings.Join(unservable, ", "))
	}
	if len(missing) > 0 {
		// Registered but not seeded. The rule builder cannot offer these (there
		// is no id to reference), and the cause is always the same: seed.sql
		// did not run, or ran from an older tree. Say so where an operator can
		// see it rather than serving a quietly short list.
		log.Printf("[MeasurementHandlers] WARN: %d registered measurement type(s) are absent from "+
			"measurement_types and cannot be authored against — re-run the seed: %s",
			len(missing), strings.Join(missing, ", "))
	}
	if measurementTypes == nil {
		// The OpenAPI response requires the array, so an empty catalogue is
		// `[]` and never `null`.
		measurementTypes = []models.MeasurementType{}
	}

	c.JSON(http.StatusOK, gin.H{
		"measurement_types": measurementTypes,
	})
}

// GetMeasurementType gets a specific measurement type by code
func (h *MeasurementHandlers) GetMeasurementType(c *gin.Context) {
	code := c.Param("code")

	mt, ok, err := services.MeasurementCatalogueEntry(h.db, code)
	if err != nil {
		log.Printf("[MeasurementHandlers] ERROR: measurement type %q unreadable: %v", code, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get measurement type",
		})
		return
	}
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "Measurement type not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"measurement_type": mt,
	})
}
