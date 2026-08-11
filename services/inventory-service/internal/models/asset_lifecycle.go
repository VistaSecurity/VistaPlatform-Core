package models

import (
	"time"

	"github.com/google/uuid"
)

// AssetLifecyclePolicy represents tenant configuration for asset lifecycle management
type AssetLifecyclePolicy struct {
	ID                   uuid.UUID              `json:"id" db:"id"`
	TenantID             uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	StaleWarningDays     int                    `json:"stale_warning_days" db:"stale_warning_days"`
	StaleArchivedDays    int                    `json:"stale_archived_days" db:"stale_archived_days"`
	AutoArchiveEnabled   bool                   `json:"auto_archive_enabled" db:"auto_archive_enabled"`
	NotificationsEnabled bool                   `json:"notifications_enabled" db:"notifications_enabled"`
	RevalidationSchedule map[string]interface{} `json:"revalidation_schedule" db:"revalidation_schedule"`
	CreatedAt            time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time              `json:"updated_at" db:"updated_at"`
}

// AssetLifecyclePolicyInput represents input for creating/updating a lifecycle policy
type AssetLifecyclePolicyInput struct {
	StaleWarningDays     *int                    `json:"stale_warning_days"`
	StaleArchivedDays    *int                    `json:"stale_archived_days"`
	AutoArchiveEnabled   *bool                   `json:"auto_archive_enabled"`
	NotificationsEnabled *bool                   `json:"notifications_enabled"`
	RevalidationSchedule *map[string]interface{} `json:"revalidation_schedule"`
}

// StaleAsset represents an asset with stale status information
type StaleAsset struct {
	Asset
	StaleStatus       *string `json:"stale_status" db:"stale_status"`
	DaysSinceLastSeen int     `json:"days_since_last_seen"`
}

// StaleAssetFilters defines parameters for filtering stale asset searches
type StaleAssetFilters struct {
	StaleStatus []string `json:"stale_status" form:"stale_status"` // 'warning', 'archived'
	Page        int      `json:"page" form:"page"`
	PageSize    int      `json:"page_size" form:"page_size"`
	SortBy      string   `json:"sort_by" form:"sort_by"`
	SortOrder   string   `json:"sort_order" form:"sort_order"`
}
