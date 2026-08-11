package models

import (
	"time"

	"github.com/google/uuid"
)

// User represents a user in the system
type User struct {
	ID                    uuid.UUID              `json:"id" db:"id"`
	TenantID              uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	Email                 string                 `json:"email" db:"email"`
	PasswordHash          string                 `json:"-" db:"password_hash"`
	FirstName             string                 `json:"first_name" db:"first_name"`
	LastName              string                 `json:"last_name" db:"last_name"`
	Role                  string                 `json:"role" db:"-"`
	IsActive              bool                   `json:"is_active" db:"active"`
	EmailVerified         bool                   `json:"email_verified" db:"email_verified"`
	LastLoginAt           *time.Time             `json:"last_login_at" db:"last_login_at"`
	AvatarURL             *string                `json:"avatar_url" db:"avatar_url"`
	Timezone              *string                `json:"timezone" db:"timezone"`
	Preferences           map[string]interface{} `json:"preferences" db:"preferences"`
	PasswordChangedAt     *time.Time             `json:"password_changed_at" db:"password_changed_at"`
	LockedUntil           *time.Time             `json:"locked_until" db:"locked_until"`
	EulaAcceptedAt        *time.Time             `json:"eula_accepted_at" db:"eula_accepted_at"`
	EulaVersion           *string                `json:"eula_version" db:"eula_version"`
	OnboardingCompletedAt *time.Time             `json:"onboarding_completed_at" db:"onboarding_completed_at"`
	CreatedAt             time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt             time.Time              `json:"updated_at" db:"updated_at"`
	DeletedAt             *time.Time             `json:"deleted_at" db:"deleted_at"`
}

// Tenant represents a tenant organization
type Tenant struct {
	ID                 uuid.UUID              `json:"id" db:"id"`
	Name               string                 `json:"name" db:"name"`
	Slug               string                 `json:"slug" db:"slug"`
	Domain             *string                `json:"domain,omitempty" db:"domain"`
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
	Token       string `json:"token" binding:"required"`
	Password    string `json:"password" binding:"required,min=8"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
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
	FirstName   *string                `json:"first_name,omitempty"`
	LastName    *string                `json:"last_name,omitempty"`
	Email       *string                `json:"email,omitempty" binding:"omitempty,email"`
	AvatarURL   *string                `json:"avatar_url,omitempty"`
	Timezone    *string                `json:"timezone,omitempty"`
	Preferences map[string]interface{} `json:"preferences,omitempty"`
}

// RBAC Models

// TenantPermission represents a permission at the tenant level
type TenantPermission struct {
	ID          uuid.UUID `json:"id" db:"id"`
	TenantID    uuid.UUID `json:"tenant_id" db:"tenant_id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	Resource    string    `json:"resource" db:"resource"`
	Action      string    `json:"action" db:"action"`
	Scope       string    `json:"scope" db:"scope"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// TenantRole represents a role at the tenant level
type TenantRole struct {
	ID           uuid.UUID `json:"id" db:"id"`
	TenantID     uuid.UUID `json:"tenant_id" db:"tenant_id"`
	Name         string    `json:"name" db:"name"`
	DisplayName  string    `json:"display_name" db:"display_name"`
	Description  string    `json:"description" db:"description"`
	IsDefault    bool      `json:"is_default" db:"is_default"`
	IsSystemRole bool      `json:"is_system_role" db:"is_system_role"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// RoleAssignmentRequest represents a request to assign a role
type RoleAssignmentRequest struct {
	UserID     uuid.UUID  `json:"user_id"`
	RoleID     uuid.UUID  `json:"role_id"`
	TenantID   uuid.UUID  `json:"tenant_id"`
	AssignedBy uuid.UUID  `json:"assigned_by"`
	ExpiresAt  *time.Time `json:"expires_at"`
}

// PermissionMatrix represents a matrix of permissions with detailed permission info
type PermissionMatrix struct {
	UserID      uuid.UUID          `json:"user_id"`
	TenantID    uuid.UUID          `json:"tenant_id"`
	RoleID      uuid.UUID          `json:"role_id"`
	RoleName    string             `json:"role_name"`
	Permissions []PermissionDetail `json:"permissions"`
}

// PermissionDetail represents detailed permission information
type PermissionDetail struct {
	PermissionID   uuid.UUID `json:"permission_id"`
	PermissionName string    `json:"permission_name"`
	Resource       string    `json:"resource"`
	Action         string    `json:"action"`
	Scope          string    `json:"scope"`
	Granted        bool      `json:"granted"`
}

// PermissionCheckRequest represents a request to check permissions
type PermissionCheckRequest struct {
	UserID     uuid.UUID `json:"user_id"`
	TenantID   uuid.UUID `json:"tenant_id"`
	Resource   string    `json:"resource"`
	Action     string    `json:"action"`
	ResourceID string    `json:"resource_id"`
	Permission string    `json:"permission"`
	IPAddress  string    `json:"ip_address"`
	UserAgent  string    `json:"user_agent"`
}

// PlatformUser represents a user at the platform level
type PlatformUser struct {
	ID            uuid.UUID     `json:"id" db:"id"`
	Email         string        `json:"email" db:"email"`
	FirstName     string        `json:"first_name" db:"first_name"`
	LastName      string        `json:"last_name" db:"last_name"`
	IsActive      bool          `json:"is_active" db:"is_active"`
	RoleID        uuid.UUID     `json:"role_id" db:"role_id"`
	EmailVerified bool          `json:"email_verified" db:"email_verified"`
	LastLoginAt   *time.Time    `json:"last_login_at" db:"last_login_at"`
	Role          *PlatformRole `json:"role" db:"role"`
	CreatedAt     time.Time     `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time     `json:"updated_at" db:"updated_at"`
}

// PlatformRole represents a role at the platform level
type PlatformRole struct {
	ID           uuid.UUID `json:"id" db:"id"`
	Name         string    `json:"name" db:"name"`
	DisplayName  string    `json:"display_name" db:"display_name"`
	Description  string    `json:"description" db:"description"`
	IsDefault    bool      `json:"is_default" db:"is_default"`
	IsSystemRole bool      `json:"is_system_role" db:"is_system_role"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// PlatformPermission represents a permission at the platform level
type PlatformPermission struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// Session represents a user session
type Session struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	UserID        uuid.UUID  `json:"user_id" db:"user_id"`
	TokenHash     string     `json:"-" db:"token_hash"`
	FamilyID      uuid.UUID  `json:"family_id" db:"family_id"`
	ExpiresAt     time.Time  `json:"expires_at" db:"expires_at"`
	LastUsedAt    time.Time  `json:"last_used_at" db:"last_used_at"`
	IsRevoked     bool       `json:"is_revoked" db:"is_revoked"`
	CreatedFromIP *string    `json:"created_from_ip" db:"created_from_ip"`
	UserAgent     *string    `json:"user_agent" db:"user_agent"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	RevokedAt     *time.Time `json:"revoked_at" db:"revoked_at"`
}

// Connection represents a user authentication method
type Connection struct {
	ID             uuid.UUID              `json:"id" db:"id"`
	UserID         uuid.UUID              `json:"user_id" db:"user_id"`
	AuthType       string                 `json:"auth_type" db:"auth_type"`
	SSOProviderID  *uuid.UUID             `json:"sso_provider_id" db:"sso_provider_id"`
	ExternalUserID *string                `json:"external_user_id" db:"external_user_id"`
	ExternalEmail  *string                `json:"external_email" db:"external_email"`
	IsPrimary      bool                   `json:"is_primary" db:"is_primary"`
	LastUsedAt     *time.Time             `json:"last_used_at" db:"last_used_at"`
	Metadata       map[string]interface{} `json:"metadata" db:"metadata"`
	CreatedAt      time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at" db:"updated_at"`
}
