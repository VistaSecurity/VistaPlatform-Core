package models

// TenantFilters defines the filtering and sorting options for tenant list queries.
type TenantFilters struct {
	// Search searches across name, slug, domain, and billing_email
	Search string `form:"search"`

	// Status filters by payment_status (active, suspended, trial)
	Status string `form:"status"`

	// Tier filters by subscription_tier name
	Tier string `form:"tier"`

	// Page is the current page number (1-indexed)
	Page int `form:"page"`

	// PageSize is the number of items per page
	PageSize int `form:"page_size"`

	// SortBy is the field to sort by (name, created_at, subscription_tier, status)
	SortBy string `form:"sort_by"`

	// SortOrder is the sort direction (asc, desc)
	SortOrder string `form:"sort_order"`
}

// DefaultTenantFilters returns default filter values.
func DefaultTenantFilters() TenantFilters {
	return TenantFilters{
		Page:      1,
		PageSize:  20,
		SortBy:    "created_at",
		SortOrder: "desc",
	}
}

// ValidSortFields returns the list of valid sort fields for tenants.
func ValidTenantSortFields() []string {
	return []string{"name", "created_at", "subscription_tier", "status", "billing_email"}
}

// IsValidSortField checks if the given field is a valid sort field.
func IsValidTenantSortField(field string) bool {
	for _, valid := range ValidTenantSortFields() {
		if field == valid {
			return true
		}
	}
	return false
}
