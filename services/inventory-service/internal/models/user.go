package models

import (
	"github.com/google/uuid"
	"time"
)

// User represents a user in the system
type User struct {
	ID            uuid.UUID              `json:"id" db:"id"`
	TenantID      uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	Email         string                 `json:"email" db:"email"`
	FirstName     string                 `json:"first_name" db:"first_name"`
	LastName      string                 `json:"last_name" db:"last_name"`
	Role          string                 `json:"role" db:"-"`
	IsActive      bool                   `json:"is_active" db:"is_active"`
	EmailVerified bool                   `json:"email_verified" db:"email_verified"`
	LastLoginAt   *time.Time             `json:"last_login_at" db:"last_login_at"`
	AvatarURL     *string                `json:"avatar_url" db:"avatar_url"`
	Timezone      *string                `json:"timezone" db:"timezone"`
	Preferences   map[string]interface{} `json:"preferences" db:"preferences"`
	CreatedAt     time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at" db:"updated_at"`
}
