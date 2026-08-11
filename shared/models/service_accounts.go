package models

import (
	"time"

	"github.com/google/uuid"
)

// ServiceAccount represents a service account for platform services
type ServiceAccount struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	ServiceName string     `json:"service_name" db:"service_name"`
	TokenHash   string     `json:"-" db:"token_hash"`   // Never expose hash in JSON
	TokenLookup *string    `json:"-" db:"token_lookup"` // SHA-256 hex of the token; O(1) ValidateToken lookup. NULL on legacy rows created before SEC-3.
	Description *string    `json:"description" db:"description"`
	IsActive    bool       `json:"is_active" db:"is_active"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
	LastUsedAt  *time.Time `json:"last_used_at" db:"last_used_at"`
}

// ServiceAccountToken represents a service account token (plaintext, only used during generation)
type ServiceAccountToken struct {
	Token       string    `json:"token"`
	ServiceName string    `json:"service_name"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"` // Optional expiration
}

// ValidateServiceName validates that a service name is valid
func ValidateServiceName(serviceName string) bool {
	if serviceName == "" {
		return false
	}
	// Service names should be lowercase, alphanumeric with hyphens
	// e.g., "cluster-sensor-service", "device-interrogation-service"
	if len(serviceName) > 100 {
		return false
	}
	return true
}
