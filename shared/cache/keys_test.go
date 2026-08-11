package cache

import (
	"testing"
)

func TestKey(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		parts    []string
		expected string
	}{
		{
			name:     "single part",
			prefix:   PrefixAdmin,
			parts:    []string{"tenant-stats"},
			expected: "admin:tenant-stats",
		},
		{
			name:     "multiple parts",
			prefix:   PrefixInventory,
			parts:    []string{"assets", "facets", "tenant-123"},
			expected: "inventory:assets:facets:tenant-123",
		},
		{
			name:     "no parts",
			prefix:   PrefixAuth,
			parts:    []string{},
			expected: "auth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Key(tt.prefix, tt.parts...)
			if result != tt.expected {
				t.Errorf("Key() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestTenantKey(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		tenantID string
		parts    []string
		expected string
	}{
		{
			name:     "with parts",
			prefix:   PrefixAdmin,
			tenantID: "tenant-123",
			parts:    []string{"stats"},
			expected: "admin:tenant:tenant-123:stats",
		},
		{
			name:     "without parts",
			prefix:   PrefixInventory,
			tenantID: "tenant-456",
			parts:    []string{},
			expected: "inventory:tenant:tenant-456",
		},
		{
			name:     "multiple parts",
			prefix:   PrefixAuth,
			tenantID: "tenant-789",
			parts:    []string{"permissions", "user-1"},
			expected: "auth:tenant:tenant-789:permissions:user-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TenantKey(tt.prefix, tt.tenantID, tt.parts...)
			if result != tt.expected {
				t.Errorf("TenantKey() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestListKey(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		resource string
		filters  map[string]string
	}{
		{
			name:     "no filters returns all key",
			prefix:   PrefixAdmin,
			resource: "tenants",
			filters:  nil,
		},
		{
			name:     "empty filters returns all key",
			prefix:   PrefixAdmin,
			resource: "tenants",
			filters:  map[string]string{},
		},
		{
			name:     "all empty values returns all key",
			prefix:   PrefixAdmin,
			resource: "tenants",
			filters:  map[string]string{"status": "", "tier": ""},
		},
		{
			name:     "with filters generates hash",
			prefix:   PrefixAdmin,
			resource: "tenants",
			filters:  map[string]string{"status": "active"},
		},
		{
			name:     "filter order doesn't matter",
			prefix:   PrefixAdmin,
			resource: "tenants",
			filters:  map[string]string{"tier": "pro", "status": "active"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ListKey(tt.prefix, tt.resource, tt.filters)

			// Check it starts with expected prefix
			expectedPrefix := tt.prefix + ":" + tt.resource + ":list:"
			if len(result) < len(expectedPrefix) || result[:len(expectedPrefix)] != expectedPrefix {
				t.Errorf("ListKey() = %q, should start with %q", result, expectedPrefix)
			}
		})
	}

	// Test that same filters in different order produce same key
	t.Run("consistent hashing", func(t *testing.T) {
		key1 := ListKey(PrefixAdmin, "tenants", map[string]string{"status": "active", "tier": "pro"})
		key2 := ListKey(PrefixAdmin, "tenants", map[string]string{"tier": "pro", "status": "active"})
		if key1 != key2 {
			t.Errorf("Keys should be equal regardless of filter order: %q != %q", key1, key2)
		}
	})
}

func TestInvalidationPattern(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		parts    []string
		expected string
	}{
		{
			name:     "single level",
			prefix:   PrefixAdmin,
			parts:    []string{"tenants"},
			expected: "admin:tenants:*",
		},
		{
			name:     "multiple levels",
			prefix:   PrefixInventory,
			parts:    []string{"assets", "facets"},
			expected: "inventory:assets:facets:*",
		},
		{
			name:     "no parts",
			prefix:   PrefixAuth,
			parts:    []string{},
			expected: "auth:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := InvalidationPattern(tt.prefix, tt.parts...)
			if result != tt.expected {
				t.Errorf("InvalidationPattern() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestTenantInvalidationPattern(t *testing.T) {
	result := TenantInvalidationPattern(PrefixAdmin, "tenant-123")
	expected := "admin:tenant:tenant-123:*"
	if result != expected {
		t.Errorf("TenantInvalidationPattern() = %q, want %q", result, expected)
	}
}
