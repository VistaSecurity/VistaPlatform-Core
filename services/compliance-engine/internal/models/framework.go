package models

import (
	"time"

	"github.com/google/uuid"
)

// Framework represents a compliance framework (e.g., PCI DSS, HIPAA)
type Framework struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Code        string    `json:"code" db:"code"` // e.g., 'pci-dss'
	Name        string    `json:"name" db:"name"`
	Version     string    `json:"version" db:"version"`
	Description string    `json:"description" db:"description"`
	Active      bool      `json:"active" db:"active"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// Family represents a compliance family (platform-wide taxonomy)
type Family struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// Control represents a compliance control within a framework
type Control struct {
	ID               uuid.UUID `json:"id" db:"id"`
	FrameworkID      uuid.UUID `json:"framework_id" db:"framework_id"`
	FamilyID         uuid.UUID `json:"family_id" db:"family_id"`
	ControlID        string    `json:"control_id" db:"control_id"` // e.g., 'PCI 3.6'
	Title            string    `json:"title" db:"title"`
	Description      string    `json:"description" db:"description"`
	BaselineSeverity string    `json:"baseline_severity" db:"baseline_severity"`
	CryptoRelevant   bool      `json:"crypto_relevant" db:"crypto_relevant"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time `json:"updated_at" db:"updated_at"`

	// Joined fields
	Framework *Framework `json:"framework,omitempty" db:"-"`
	Family    *Family    `json:"family,omitempty" db:"-"`
	Keywords  []string   `json:"keywords,omitempty" db:"-"`
}

// ControlKeyword represents keywords for filtering controls
type ControlKeyword struct {
	ID        uuid.UUID `json:"id" db:"id"`
	ControlID uuid.UUID `json:"control_id" db:"control_id"`
	Keyword   string    `json:"keyword" db:"keyword"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}
