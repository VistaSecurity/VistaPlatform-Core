package models

import (
	"github.com/google/uuid"
	"time"
)

// PlatformUser represents a user at the platform level
type PlatformUser struct {
	ID                   uuid.UUID     `json:"id" db:"id"`
	Email                string        `json:"email" db:"email"`
	FirstName            string        `json:"first_name" db:"first_name"`
	LastName             string        `json:"last_name" db:"last_name"`
	IsActive             bool          `json:"is_active" db:"is_active"`
	RoleID               uuid.UUID     `json:"role_id" db:"role_id"`
	EmailVerified        bool          `json:"email_verified" db:"email_verified"`
	ForcePasswordChange  bool          `json:"force_password_change" db:"force_password_change"`
	PasswordChangedAt    *time.Time    `json:"password_changed_at,omitempty" db:"password_changed_at"`
	LastLoginAt          *time.Time    `json:"last_login_at" db:"last_login_at"`
	Role                 *PlatformRole `json:"role" db:"role"`
	InvitedBy            *uuid.UUID    `json:"invited_by,omitempty" db:"invited_by"`
	InvitationAcceptedAt *time.Time    `json:"invitation_accepted_at,omitempty" db:"invitation_accepted_at"`
	CreatedAt            time.Time     `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time     `json:"updated_at" db:"updated_at"`
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
	Resource    string    `json:"resource" db:"resource"`
	Action      string    `json:"action" db:"action"`
	Description string    `json:"description" db:"description"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// Tenant represents a tenant in the system
type Tenant struct {
	ID                 uuid.UUID              `json:"id" db:"id"`
	Name               string                 `json:"name" db:"name"`
	Slug               string                 `json:"slug" db:"slug"`
	Domain             *string                `json:"domain" db:"domain"`
	SubscriptionTier   *string                `json:"subscription_tier" db:"subscription_tier"`
	SubscriptionTierID uuid.UUID              `json:"subscription_tier_id" db:"subscription_tier_id"`
	TrialEndsAt        *time.Time             `json:"trial_ends_at" db:"trial_ends_at"`
	BillingEmail       string                 `json:"billing_email" db:"billing_email"`
	PaymentStatus      string                 `json:"payment_status" db:"payment_status"`
	StripeCustomerID   *string                `json:"stripe_customer_id" db:"stripe_customer_id"`
	SsoEnabled         bool                   `json:"sso_enabled" db:"sso_enabled"`
	IsActive           bool                   `json:"is_active" db:"is_active"`
	CustomBranding     map[string]interface{} `json:"custom_branding" db:"custom_branding"`
	UiConfig           map[string]interface{} `json:"ui_config" db:"ui_config"`
	Settings           map[string]interface{} `json:"settings" db:"settings"`
	CreatedAt          time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at" db:"updated_at"`
	DeletedAt          *time.Time             `json:"deleted_at" db:"deleted_at"`
}

// User represents a user in the system (unified for platform and tenant)
type User struct {
	ID            uuid.UUID              `json:"id"`
	TenantID      uuid.UUID              `json:"tenant_id"`
	Email         string                 `json:"email"`
	FirstName     string                 `json:"first_name"`
	LastName      string                 `json:"last_name"`
	Role          string                 `json:"role"` // e.g., "tenant_admin", "viewer"
	IsActive      bool                   `json:"is_active"`
	EmailVerified bool                   `json:"email_verified"`
	LastLoginAt   *time.Time             `json:"last_login_at"`
	AvatarURL     *string                `json:"avatar_url"`
	Timezone      *string                `json:"timezone"`
	Preferences   map[string]interface{} `json:"preferences"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
}

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

// AuditLog records actions performed in the system
type AuditLog struct {
	ID        uuid.UUID              `json:"id"`
	UserID    uuid.UUID              `json:"user_id"`
	TenantID  uuid.UUID              `json:"tenant_id"`
	Action    string                 `json:"action"`
	Entity    string                 `json:"entity"`
	EntityID  uuid.UUID              `json:"entity_id"`
	Details   map[string]interface{} `json:"details"`
	Timestamp time.Time              `json:"timestamp"`
}

// Request/Response Models (examples)
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	User        User   `json:"user"`
	AccessToken string `json:"access_token"`
}

type RegisterRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	FirstName  string `json:"first_name"`
	LastName   string `json:"last_name"`
	TenantName string `json:"tenant_name"`
}

type CreateTenantRequest struct {
	Name         string `json:"name"`
	Slug         string `json:"slug"`
	BillingEmail string `json:"billing_email"`
}

type CreateUserRequest struct {
	TenantID  uuid.UUID `json:"tenant_id"`
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Role      string    `json:"role"`
}

// PlatformStats represents platform-wide statistics
type PlatformStats struct {
	TotalTenants  int `json:"total_tenants" db:"total_tenants"`
	ActiveTenants int `json:"active_tenants" db:"active_tenants"`
	TotalUsers    int `json:"total_users" db:"total_users"`
	TotalAssets   int `json:"total_assets" db:"total_assets"`
	TotalSensors  int `json:"total_sensors" db:"total_sensors"`
}

// TenantStats represents statistics for a specific tenant
type TenantStats struct {
	TenantID     uuid.UUID `json:"tenant_id" db:"tenant_id"`
	TenantName   string    `json:"tenant_name" db:"tenant_name"`
	UserCount    int       `json:"user_count" db:"user_count"`
	AssetCount   int       `json:"asset_count" db:"asset_count"`
	SensorCount  int       `json:"sensor_count" db:"sensor_count"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	LastActivity time.Time `json:"last_activity" db:"last_activity"`
	StorageUsed  int64     `json:"storage_used" db:"storage_used"`
	APIRequests  int64     `json:"api_requests" db:"api_requests"`
}

// GetRiskLevel determines the risk level based on a score
func GetRiskLevel(score int) string {
	if score >= 80 {
		return "Critical"
	} else if score >= 60 {
		return "High"
	} else if score >= 40 {
		return "Medium"
	} else if score >= 20 {
		return "Low"
	}
	return "Informational"
}
