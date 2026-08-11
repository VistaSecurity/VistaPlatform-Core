package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Scenario represents a saved compliance scenario with filters and settings
type Scenario struct {
	ID               uuid.UUID       `json:"id" db:"id"`
	TenantID         uuid.UUID       `json:"tenant_id" db:"tenant_id"`
	Name             string          `json:"name" db:"name"`
	FrameworkID      uuid.UUID       `json:"framework_id" db:"framework_id"`
	FrameworkVersion string          `json:"framework_version" db:"framework_version"`
	Filters          ScenarioFilters `json:"filters" db:"filters"`
	CreatedBy        uuid.UUID       `json:"created_by" db:"created_by"`
	UpdatedBy        uuid.UUID       `json:"updated_by" db:"updated_by"`
	CreatedAt        time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at" db:"updated_at"`

	// Joined fields
	Framework *Framework `json:"framework,omitempty" db:"-"`
}

// ScenarioFilters represents the filter criteria for a scenario
type ScenarioFilters struct {
	Environment    string   `json:"environment,omitempty"`     // e.g., "prod", "staging", "dev"
	Severity       string   `json:"severity,omitempty"`        // e.g., "high", "med", "low", "critical"
	EncryptionOnly bool     `json:"encryption_only,omitempty"` // filter to crypto-relevant controls only
	Tags           []string `json:"tags,omitempty"`            // asset tags to filter by
	Owner          string   `json:"owner,omitempty"`           // asset owner email
}

// Scan implements sql.Scanner for JSONB fields
func (sf *ScenarioFilters) Scan(value interface{}) error {
	if value == nil {
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}

	return json.Unmarshal(bytes, sf)
}

// Value implements driver.Valuer for JSONB fields
func (sf ScenarioFilters) Value() (interface{}, error) {
	return json.Marshal(sf)
}
