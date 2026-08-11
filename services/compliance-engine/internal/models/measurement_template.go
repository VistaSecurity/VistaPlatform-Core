package models

import (
	"time"

	"github.com/google/uuid"
)

// MeasurementTemplate represents a predefined measurement rule template
type MeasurementTemplate struct {
	ID                uuid.UUID              `json:"id" db:"id"`
	Code              string                 `json:"code" db:"code"`
	Name              string                 `json:"name" db:"name"`
	Description       string                 `json:"description" db:"description"`
	MeasurementTypeID uuid.UUID              `json:"measurement_type_id" db:"measurement_type_id"`
	RuleType          string                 `json:"rule_type" db:"rule_type"`
	Predicate         map[string]interface{} `json:"predicate" db:"predicate"`
	Category          string                 `json:"category" db:"category"`
	FrameworkTags     []string               `json:"framework_tags" db:"framework_tags"`
	Version           int                    `json:"version" db:"version"`
	IsActive          bool                   `json:"is_active" db:"is_active"`
	CreatedBy         *uuid.UUID             `json:"created_by,omitempty" db:"created_by"`
	CreatedAt         time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at" db:"updated_at"`

	// Joined fields
	MeasurementType *MeasurementType `json:"measurement_type,omitempty" db:"-"`
}

// MeasurementTemplateInput represents input for creating/updating a template
type MeasurementTemplateInput struct {
	Code              string                 `json:"code" binding:"required"`
	Name              string                 `json:"name" binding:"required"`
	Description       string                 `json:"description"`
	MeasurementTypeID uuid.UUID              `json:"measurement_type_id" binding:"required"`
	RuleType          string                 `json:"rule_type" binding:"required,oneof=threshold presence pattern range"`
	Predicate         map[string]interface{} `json:"predicate" binding:"required"`
	Category          string                 `json:"category"`
	FrameworkTags     []string               `json:"framework_tags"`
	IsActive          bool                   `json:"is_active"`
}
