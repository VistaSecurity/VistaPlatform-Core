package middleware

import (
	"log"
	"os"
	"strings"
)

// QueryValidator provides utilities to validate SQL queries for tenant isolation
type QueryValidator struct {
	enabled bool
}

// NewQueryValidator creates a new query validator
// Only enabled in development/testing environments
func NewQueryValidator() *QueryValidator {
	env := os.Getenv("ENV")
	enabled := env == "development" || env == "test" || os.Getenv("ENABLE_QUERY_VALIDATION") == "true"
	return &QueryValidator{enabled: enabled}
}

// ValidateQuery checks if a SQL query includes tenant_id filtering
// This is a best-effort check and should not be relied upon for security
// RLS policies provide the actual security enforcement
func (qv *QueryValidator) ValidateQuery(query string, args []interface{}) {
	if !qv.enabled {
		return
	}

	queryUpper := strings.ToUpper(query)

	// List of tenant-scoped tables that should always have tenant_id filter
	tenantScopedTables := []string{
		"SENSORS",
		"PENDING_SENSORS",
		"PENDING_SENSOR_REGISTRATIONS",
		"SENSOR_DISCOVERIES",
		"NETWORK_ASSETS",
		"CRYPTO_IMPLEMENTATIONS",
		"CERTIFICATES",
	}

	// Check if query references tenant-scoped tables
	referencesTenantTable := false
	for _, table := range tenantScopedTables {
		if strings.Contains(queryUpper, table) {
			referencesTenantTable = true
			break
		}
	}

	if !referencesTenantTable {
		return // Not a tenant-scoped query, skip validation
	}

	// Check for tenant_id in WHERE clause
	hasTenantIDFilter := strings.Contains(queryUpper, "TENANT_ID") ||
		strings.Contains(queryUpper, "TENANTID") ||
		strings.Contains(queryUpper, "CURRENT_SETTING('APP.TENANT_ID'")

	// Check for tenant_id in JOIN conditions
	hasTenantIDJoin := strings.Contains(queryUpper, "JOIN") && strings.Contains(queryUpper, "TENANT_ID")

	// Check if query uses RLS (which handles tenant filtering automatically)
	usesRLS := strings.Contains(queryUpper, "CURRENT_SETTING") ||
		strings.Contains(queryUpper, "SET_TENANT_CONTEXT")

	if !hasTenantIDFilter && !hasTenantIDJoin && !usesRLS {
		// This is a warning, not an error, because RLS policies will enforce isolation
		// But it's good practice to include tenant_id in queries for performance
		log.Printf("⚠️  [QUERY VALIDATION] Query may be missing tenant_id filter:\n%s\nArgs: %v",
			query, args)
	}
}

// ValidateQueryString is a convenience function for validating query strings
func ValidateQueryString(query string) {
	validator := NewQueryValidator()
	validator.ValidateQuery(query, nil)
}
