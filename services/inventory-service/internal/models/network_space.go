package models

// NetworkSpace represents a network space definition for a tenant
type NetworkSpace struct {
	ID                     string                 `json:"id"`
	Type                   string                 `json:"type"`         // "cidr", "ip_range", "domain"
	Value                  string                 `json:"value"`        // CIDR block, IP range (start-end), or domain pattern
	NetworkType            string                 `json:"network_type"` // "private", "public", "vpn", "cloud"
	Description            string                 `json:"description,omitempty"`
	IsActive               bool                   `json:"is_active"`
	Tags                   map[string]interface{} `json:"tags,omitempty"`                     // Tags to apply to matching assets
	AutoApproveDiscoveries *bool                  `json:"auto_approve_discoveries,omitempty"` // Auto-approve sensor discoveries from this network space
}

// NetworkSpaceConfig represents the network_spaces configuration in tenant_admin_settings
type NetworkSpaceConfig struct {
	NetworkSpaces []NetworkSpace `json:"network_spaces"`
}
