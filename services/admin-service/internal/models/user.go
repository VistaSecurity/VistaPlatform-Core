package models

import (
	"time"

	"github.com/google/uuid"
)

// User represents a user in the system
type User struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	TenantID      uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	Email         string     `json:"email" db:"email"`
	PasswordHash  string     `json:"-" db:"password_hash"`
	FirstName     string     `json:"first_name" db:"first_name"`
	LastName      string     `json:"last_name" db:"last_name"`
	Role          string     `json:"role" db:"-"`
	IsActive      bool       `json:"is_active" db:"active"`
	EmailVerified bool       `json:"email_verified" db:"email_verified"`
	LastLoginAt   *time.Time `json:"last_login_at" db:"last_login_at"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt     *time.Time `json:"deleted_at" db:"deleted_at"`
}

// Tenant represents a tenant organization
type Tenant struct {
	ID                 uuid.UUID              `json:"id" db:"id"`
	Name               string                 `json:"name" db:"name"`
	Slug               string                 `json:"slug" db:"slug"`
	SubscriptionTierID uuid.UUID              `json:"subscription_tier_id" db:"subscription_tier_id"`
	TrialEndsAt        *time.Time             `json:"trial_ends_at" db:"trial_ends_at"`
	BillingEmail       string                 `json:"billing_email" db:"billing_email"`
	PaymentStatus      string                 `json:"payment_status" db:"payment_status"`
	Settings           map[string]interface{} `json:"settings" db:"settings"`
	CreatedAt          time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at" db:"updated_at"`
	DeletedAt          *time.Time             `json:"deleted_at" db:"deleted_at"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

// RegisterRequest represents a registration request
type RegisterRequest struct {
	Email      string `json:"email" binding:"required,email"`
	Password   string `json:"password" binding:"required,min=8"`
	FirstName  string `json:"first_name" binding:"required"`
	LastName   string `json:"last_name" binding:"required"`
	TenantName string `json:"tenant_name,omitempty"`
}

// ChangePasswordRequest represents a password change request
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required,min=8"`
}

// ForgotPasswordRequest represents a forgot password request
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// ResetPasswordRequest represents a reset password request
type ResetPasswordRequest struct {
	Token    string `json:"token" binding:"required"`
	Password string `json:"password" binding:"required,min=8"`
}

// AuthResponse represents an authentication response
type AuthResponse struct {
	User         *User  `json:"user"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// RefreshTokenRequest represents a token refresh request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// UpdateUserRequest represents a user update request
type UpdateUserRequest struct {
	FirstName *string `json:"first_name,omitempty"`
	LastName  *string `json:"last_name,omitempty"`
	Email     *string `json:"email,omitempty" binding:"omitempty,email"`
}
