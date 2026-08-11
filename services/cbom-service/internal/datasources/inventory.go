// Package datasources implements data sources for report generation
package datasources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// InventoryDataSource implements DataSource for the inventory service
type InventoryDataSource struct {
	baseURL    string
	httpClient *http.Client
}

// NewInventoryDataSource creates a new inventory data source
func NewInventoryDataSource(baseURL string) (*InventoryDataSource, error) {
	// Check if mTLS should be used
	useMTLS := os.Getenv("USE_MTLS") == "true"

	// Update URL to use HTTPS and port 8443 if mTLS is enabled
	if useMTLS {
		baseURL = strings.Replace(baseURL, "http://", "https://", 1)
		baseURL = strings.Replace(baseURL, ":8080", ":8443", 1)
	}

	var httpClient *http.Client
	var err error
	if useMTLS {
		clientCertPath := os.Getenv("CLIENT_CERT_PATH")
		clientKeyPath := os.Getenv("CLIENT_KEY_PATH")
		platformCACertPath := os.Getenv("PLATFORM_CA_CERT_PATH")

		if clientCertPath != "" && clientKeyPath != "" && platformCACertPath != "" {
			httpClient, err = sharedhttp.NewMTLSClient(clientCertPath, clientKeyPath, platformCACertPath)
			if err != nil {
				return nil, fmt.Errorf("failed to create mTLS client: %w", err)
			}
			httpClient.Timeout = 30 * time.Second
		} else {
			// Fallback to standard client if cert paths not provided
			httpClient = &http.Client{
				Timeout: 30 * time.Second,
			}
		}
	} else {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	return &InventoryDataSource{
		baseURL:    baseURL,
		httpClient: httpClient,
	}, nil
}

// Name returns the unique identifier for this data source
func (i *InventoryDataSource) Name() string {
	return "inventory"
}

// Description returns a human-readable description of the data source
func (i *InventoryDataSource) Description() string {
	return "Inventory service providing assets, certificates, and cryptographic configurations"
}

// GetSchema returns the schema definition for this data source
func (i *InventoryDataSource) GetSchema() *DataSourceSchema {
	return &DataSourceSchema{
		Name:         i.Name(),
		Description:  i.Description(),
		Version:      "1.0",
		Fields:       i.getFieldDefinitions(),
		Filters:      i.getFilterDefinitions(),
		Aggregations: i.getAggregationDefinitions(),
		Capabilities: DataSourceCapabilities{
			SupportsFiltering:   true,
			SupportsSorting:     true,
			SupportsPagination:  true,
			SupportsAggregation: true,
			SupportsGrouping:    true,
			SupportsSearch:      true,
			SupportsRealTime:    false,
			MaxPageSize:         1000,
			DefaultPageSize:     50,
		},
		Metadata: map[string]interface{}{
			"service": "inventory-service",
			"version": "1.0",
		},
	}
}

// Query executes a query against the inventory service
func (i *InventoryDataSource) Query(ctx context.Context, params QueryParams) (interface{}, error) {
	// Determine the endpoint based on the fields requested
	endpoint := i.determineEndpoint(params.Fields)

	// Build query parameters
	queryParams := i.buildQueryParams(params)

	// Make HTTP request
	fullURL := fmt.Sprintf("%s%s", i.baseURL, endpoint)
	if queryParams != "" {
		fullURL = fmt.Sprintf("%s?%s", fullURL, queryParams)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// X-Tenant-ID must be set BEFORE signing so it is included in the HMAC message
	// (see shared/serviceauth/serviceauth.go buildMessage). Inventory short-circuits
	// on the internal-call path and reads tenant from this header.
	if params.TenantID != "" {
		req.Header.Set("X-Tenant-ID", params.TenantID)
	}
	serviceauth.SignRequestFromEnv(req)

	// Add authorization header if token is provided
	if params.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+params.AuthToken)
	}

	// Execute request
	resp, err := i.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		// Try to read error message from response body
		var errorBody map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errorBody); err == nil {
			if msg, ok := errorBody["error"].(string); ok {
				return nil, fmt.Errorf("inventory service returned status %d: %s", resp.StatusCode, msg)
			}
			if details, ok := errorBody["details"].(string); ok {
				return nil, fmt.Errorf("inventory service returned status %d: %s", resp.StatusCode, details)
			}
		}
		return nil, fmt.Errorf("inventory service returned status %d", resp.StatusCode)
	}

	// Parse response
	var result interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result, nil
}

// Validate checks if the given parameters are valid for this data source
func (i *InventoryDataSource) Validate(params QueryParams) error {
	// Validate fields
	for _, field := range params.Fields {
		if !i.isValidField(field) {
			return fmt.Errorf("invalid field: %s", field)
		}
	}

	// Validate filters
	for _, filter := range params.Filters {
		if !i.isValidFilterField(filter.Field) {
			return fmt.Errorf("invalid filter field: %s", filter.Field)
		}
		if !i.isValidFilterOperator(filter.Operator) {
			return fmt.Errorf("invalid filter operator: %s", filter.Operator)
		}
	}

	// Validate sort fields
	for _, sort := range params.Sort {
		if !i.isValidSortField(sort.Field) {
			return fmt.Errorf("invalid sort field: %s", sort.Field)
		}
		if sort.Order != SortOrderAscending && sort.Order != SortOrderDescending {
			return fmt.Errorf("invalid sort order: %s", sort.Order)
		}
	}

	// Validate pagination
	if params.Pagination != nil {
		if params.Pagination.Page < 1 {
			return fmt.Errorf("page must be >= 1")
		}
		if params.Pagination.PageSize < 1 || params.Pagination.PageSize > 1000 {
			return fmt.Errorf("page size must be between 1 and 1000")
		}
	}

	return nil
}

// GetFields returns available fields that can be queried from this data source
func (i *InventoryDataSource) GetFields() []FieldDefinition {
	return i.getFieldDefinitions()
}

// IsAvailable checks if the inventory service is currently available
func (i *InventoryDataSource) IsAvailable(ctx context.Context) bool {
	url := fmt.Sprintf("%s/health", i.baseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}

	resp, err := i.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	return resp.StatusCode == http.StatusOK
}

// QueryCryptoImplementations retrieves all crypto configurations from the inventory service.
// It returns the raw slice of map objects from the service response.
func (i *InventoryDataSource) QueryCryptoImplementations(ctx context.Context, authToken, tenantID string) ([]map[string]interface{}, error) {
	return i.queryAllListEndpoint(ctx, "/api/v1/inventory-service/crypto-implementations", authToken, tenantID)
}

// QueryCertificates retrieves all certificates from the inventory service.
// It returns the raw slice of map objects from the service response.
func (i *InventoryDataSource) QueryCertificates(ctx context.Context, authToken, tenantID string) ([]map[string]interface{}, error) {
	return i.queryAllListEndpoint(ctx, "/api/v1/inventory-service/certificates", authToken, tenantID)
}

// QueryAssets retrieves all assets from the inventory service.
// It returns the raw slice of map objects from the service response.
func (i *InventoryDataSource) QueryAssets(ctx context.Context, authToken, tenantID string) ([]map[string]interface{}, error) {
	return i.queryAllListEndpoint(ctx, "/api/v1/inventory-service/assets", authToken, tenantID)
}

// QueryAlgorithms retrieves all algorithms from the inventory service.
// The algorithms table is the authoritative source for strength, deprecation,
// PQC status, and migration guidance — the CBOM handler uses this to enrich
// algorithm components instead of re-inferring these attributes.
func (i *InventoryDataSource) QueryAlgorithms(ctx context.Context, authToken, tenantID string) ([]map[string]interface{}, error) {
	return i.queryAllListEndpoint(ctx, "/api/v1/inventory-service/algorithms", authToken, tenantID)
}

// QueryFindings retrieves security findings and vulnerabilities from the inventory service.
// This is used by the lens reports for compliance and risk assessment.
// Currently returns empty; can be enhanced to query actual findings from inventory or compliance services.
func (i *InventoryDataSource) QueryFindings(ctx context.Context, authToken, tenantID string) ([]map[string]interface{}, error) {
	// TODO: Integrate with compliance-engine or audit-service to fetch actual findings
	// For now, return empty results to avoid blocking lens report generation
	return []map[string]interface{}{}, nil
}

// queryListEndpoint is a shared helper that GETs a paginated list endpoint and returns
// the items array from the response. It handles both {"items": [...]} and top-level array
// response shapes.
func (i *InventoryDataSource) queryAllListEndpoint(ctx context.Context, path, authToken, tenantID string) ([]map[string]interface{}, error) {
	const pageSize = 1000

	var results []map[string]interface{}
	for page := 1; ; page++ {
		raw, err := i.queryEndpointPage(ctx, path, authToken, tenantID, page, pageSize)
		if err != nil {
			return nil, err
		}

		items := extractListFromResponse(raw)
		if items == nil {
			return nil, fmt.Errorf("inventory service %s returned an unexpected list response", path)
		}
		results = append(results, items...)

		pagination, hasPagination := extractPagination(raw)
		if !hasPagination {
			if len(items) < pageSize {
				break
			}
			return nil, fmt.Errorf("inventory service %s returned a full page without pagination metadata", path)
		}

		if !boolFromPagination(pagination["has_next"]) {
			break
		}
	}

	return results, nil
}

func (i *InventoryDataSource) queryEndpointPage(ctx context.Context, path, authToken, tenantID string, page, pageSize int) (interface{}, error) {
	fullURL := fmt.Sprintf("%s%s?page=%d&page_size=%d", i.baseURL, path, page, pageSize)

	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for %s: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// X-Tenant-ID must be set BEFORE signing so it is included in the HMAC message
	// (see shared/serviceauth/serviceauth.go buildMessage). Inventory short-circuits
	// on the internal-call path and reads tenant from this header.
	if tenantID != "" {
		req.Header.Set("X-Tenant-ID", tenantID)
	}
	serviceauth.SignRequestFromEnv(req)
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	resp, err := i.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request to %s failed: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var body map[string]interface{}
		if decErr := json.NewDecoder(resp.Body).Decode(&body); decErr == nil {
			if msg, ok := body["error"].(string); ok {
				return nil, fmt.Errorf("inventory service %s returned %d: %s", path, resp.StatusCode, msg)
			}
		}
		return nil, fmt.Errorf("inventory service %s returned %d", path, resp.StatusCode)
	}

	var raw interface{}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("failed to decode response from %s: %w", path, err)
	}

	return raw, nil
}

// extractListFromResponse coerces various inventory API response shapes into a flat slice.
// The inventory service may return {"items": [...]} , {"data": [...]}, {"assets": [...]},
// {"crypto_implementations": [...]}, {"certificates": [...]}, or a bare top-level array.
// Nil or missing list values (e.g. "certificates": null when empty) are treated as empty list.
func extractListFromResponse(raw interface{}) []map[string]interface{} {
	keys := []string{"items", "data", "assets", "crypto_implementations", "certificates", "algorithms"}

	if topMap, ok := raw.(map[string]interface{}); ok {
		for _, k := range keys {
			v, exists := topMap[k]
			if !exists {
				continue
			}
			if v == nil {
				// Inventory may return e.g. "certificates": null when there are no rows
				return []map[string]interface{}{}
			}
			if arr, ok := v.([]interface{}); ok {
				return toMapSlice(arr)
			}
		}
	}

	if arr, ok := raw.([]interface{}); ok {
		return toMapSlice(arr)
	}

	return nil
}

// toMapSlice converts []interface{} to []map[string]interface{}, skipping non-map elements.
func toMapSlice(arr []interface{}) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(arr))
	for _, item := range arr {
		if m, ok := item.(map[string]interface{}); ok {
			result = append(result, m)
		}
	}
	return result
}

func extractPagination(raw interface{}) (map[string]interface{}, bool) {
	topMap, ok := raw.(map[string]interface{})
	if !ok {
		return nil, false
	}
	pagination, ok := topMap["pagination"].(map[string]interface{})
	return pagination, ok
}

func boolFromPagination(v interface{}) bool {
	b, ok := v.(bool)
	return ok && b
}

// Helper methods

func (i *InventoryDataSource) getFieldDefinitions() []FieldDefinition {
	return []FieldDefinition{
		// Asset fields
		{
			Name:         "id",
			Label:        "Asset ID",
			Type:         FieldTypeUUID,
			Description:  "Unique identifier for the asset",
			Required:     true,
			Indexed:      true,
			Searchable:   true,
			Sortable:     true,
			Filterable:   true,
			Aggregatable: false,
		},
		{
			Name:         "name",
			Label:        "Asset Name",
			Type:         FieldTypeString,
			Description:  "Human-readable name of the asset",
			Required:     true,
			Indexed:      true,
			Searchable:   true,
			Sortable:     true,
			Filterable:   true,
			Aggregatable: false,
		},
		{
			Name:         "type",
			Label:        "Asset Type",
			Type:         FieldTypeEnum,
			Description:  "Type of asset (server, network_device, application, etc.)",
			Required:     true,
			Indexed:      true,
			Searchable:   false,
			Sortable:     true,
			Filterable:   true,
			Aggregatable: true,
			Options: []FieldOption{
				{Value: "server", Label: "Server"},
				{Value: "network_device", Label: "Network Device"},
				{Value: "application", Label: "Application"},
				{Value: "database", Label: "Database"},
				{Value: "load_balancer", Label: "Load Balancer"},
				{Value: "firewall", Label: "Firewall"},
				{Value: "other", Label: "Other"},
			},
		},
		{
			Name:         "environment",
			Label:        "Environment",
			Type:         FieldTypeEnum,
			Description:  "Environment where the asset is deployed",
			Required:     false,
			Indexed:      true,
			Searchable:   false,
			Sortable:     true,
			Filterable:   true,
			Aggregatable: true,
			Options: []FieldOption{
				{Value: "production", Label: "Production"},
				{Value: "staging", Label: "Staging"},
				{Value: "development", Label: "Development"},
				{Value: "test", Label: "Test"},
			},
		},
		{
			Name:         "ip_address",
			Label:        "IP Address",
			Type:         FieldTypeIP,
			Description:  "Primary IP address of the asset",
			Required:     false,
			Indexed:      true,
			Searchable:   true,
			Sortable:     true,
			Filterable:   true,
			Aggregatable: false,
		},
		{
			Name:         "hostname",
			Label:        "Hostname",
			Type:         FieldTypeString,
			Description:  "Hostname or FQDN of the asset",
			Required:     false,
			Indexed:      true,
			Searchable:   true,
			Sortable:     true,
			Filterable:   true,
			Aggregatable: false,
		},
		{
			Name:         "risk_level",
			Label:        "Risk Level",
			Type:         FieldTypeEnum,
			Description:  "Overall risk level of the asset",
			Required:     false,
			Indexed:      true,
			Searchable:   false,
			Sortable:     true,
			Filterable:   true,
			Aggregatable: true,
			Options: []FieldOption{
				{Value: "critical", Label: "Critical"},
				{Value: "high", Label: "High"},
				{Value: "medium", Label: "Medium"},
				{Value: "low", Label: "Low"},
				{Value: "info", Label: "Info"},
			},
		},
		{
			Name:         "tags",
			Label:        "Tags",
			Type:         FieldTypeArray,
			Description:  "Tags associated with the asset",
			Required:     false,
			Indexed:      true,
			Searchable:   true,
			Sortable:     false,
			Filterable:   true,
			Aggregatable: false,
		},
		{
			Name:         "created_at",
			Label:        "Created At",
			Type:         FieldTypeDateTime,
			Description:  "When the asset was first discovered",
			Required:     false,
			Indexed:      true,
			Searchable:   false,
			Sortable:     true,
			Filterable:   true,
			Aggregatable: false,
		},
		{
			Name:         "updated_at",
			Label:        "Updated At",
			Type:         FieldTypeDateTime,
			Description:  "When the asset was last updated",
			Required:     false,
			Indexed:      true,
			Searchable:   false,
			Sortable:     true,
			Filterable:   true,
			Aggregatable: false,
		},
		{
			Name:         "last_seen",
			Label:        "Last Seen",
			Type:         FieldTypeDateTime,
			Description:  "When the asset was last seen by sensors",
			Required:     false,
			Indexed:      true,
			Searchable:   false,
			Sortable:     true,
			Filterable:   true,
			Aggregatable: false,
		},
		// Certificate fields
		{
			Name:         "certificate_id",
			Label:        "Certificate ID",
			Type:         FieldTypeUUID,
			Description:  "Unique identifier for the certificate",
			Required:     false,
			Indexed:      true,
			Searchable:   true,
			Sortable:     true,
			Filterable:   true,
			Aggregatable: false,
		},
		{
			Name:         "certificate_subject",
			Label:        "Certificate Subject",
			Type:         FieldTypeString,
			Description:  "Subject of the certificate",
			Required:     false,
			Indexed:      true,
			Searchable:   true,
			Sortable:     true,
			Filterable:   true,
			Aggregatable: false,
		},
		{
			Name:         "certificate_issuer",
			Label:        "Certificate Issuer",
			Type:         FieldTypeString,
			Description:  "Issuer of the certificate",
			Required:     false,
			Indexed:      true,
			Searchable:   true,
			Sortable:     true,
			Filterable:   true,
			Aggregatable: true,
		},
		{
			Name:         "certificate_expires_at",
			Label:        "Certificate Expires At",
			Type:         FieldTypeDateTime,
			Description:  "When the certificate expires",
			Required:     false,
			Indexed:      true,
			Searchable:   false,
			Sortable:     true,
			Filterable:   true,
			Aggregatable: false,
		},
		{
			Name:         "certificate_key_size",
			Label:        "Certificate Key Size",
			Type:         FieldTypeNumber,
			Description:  "Key size of the certificate in bits",
			Required:     false,
			Indexed:      true,
			Searchable:   false,
			Sortable:     true,
			Filterable:   true,
			Aggregatable: true,
		},
		{
			Name:         "certificate_algorithm",
			Label:        "Certificate Algorithm",
			Type:         FieldTypeString,
			Description:  "Signing algorithm of the certificate",
			Required:     false,
			Indexed:      true,
			Searchable:   true,
			Sortable:     true,
			Filterable:   true,
			Aggregatable: true,
		},
		// Crypto implementation fields
		{
			Name:         "crypto_protocol",
			Label:        "Crypto Protocol",
			Type:         FieldTypeString,
			Description:  "Cryptographic protocol (TLS, SSH, etc.)",
			Required:     false,
			Indexed:      true,
			Searchable:   true,
			Sortable:     true,
			Filterable:   true,
			Aggregatable: true,
		},
		{
			Name:         "crypto_version",
			Label:        "Crypto Version",
			Type:         FieldTypeString,
			Description:  "Version of the cryptographic protocol",
			Required:     false,
			Indexed:      true,
			Searchable:   true,
			Sortable:     true,
			Filterable:   true,
			Aggregatable: true,
		},
		{
			Name:         "crypto_cipher_suite",
			Label:        "Cipher Suite",
			Type:         FieldTypeString,
			Description:  "Cipher suite used",
			Required:     false,
			Indexed:      true,
			Searchable:   true,
			Sortable:     true,
			Filterable:   true,
			Aggregatable: true,
		},
		{
			Name:         "crypto_risk_score",
			Label:        "Crypto Risk Score",
			Type:         FieldTypeNumber,
			Description:  "Risk score for the cryptographic implementation",
			Required:     false,
			Indexed:      true,
			Searchable:   false,
			Sortable:     true,
			Filterable:   true,
			Aggregatable: true,
		},
	}
}

func (i *InventoryDataSource) getFilterDefinitions() []FilterDefinition {
	return []FilterDefinition{
		{
			Name:        "asset_type",
			Label:       "Asset Type",
			Type:        FilterTypeSelect,
			Field:       "type",
			Description: "Filter by asset type",
			Operators:   []FilterOperator{FilterOperatorEquals, FilterOperatorIn},
		},
		{
			Name:        "environment",
			Label:       "Environment",
			Type:        FilterTypeSelect,
			Field:       "environment",
			Description: "Filter by environment",
			Operators:   []FilterOperator{FilterOperatorEquals, FilterOperatorIn},
		},
		{
			Name:        "risk_level",
			Label:       "Risk Level",
			Type:        FilterTypeSelect,
			Field:       "risk_level",
			Description: "Filter by risk level",
			Operators:   []FilterOperator{FilterOperatorEquals, FilterOperatorIn},
		},
		{
			Name:        "ip_address",
			Label:       "IP Address",
			Type:        FilterTypeText,
			Field:       "ip_address",
			Description: "Filter by IP address",
			Operators:   []FilterOperator{FilterOperatorEquals, FilterOperatorContains},
		},
		{
			Name:        "hostname",
			Label:       "Hostname",
			Type:        FilterTypeText,
			Field:       "hostname",
			Description: "Filter by hostname",
			Operators:   []FilterOperator{FilterOperatorEquals, FilterOperatorContains, FilterOperatorStartsWith},
		},
		{
			Name:        "created_date",
			Label:       "Created Date",
			Type:        FilterTypeDateRange,
			Field:       "created_at",
			Description: "Filter by creation date range",
			Operators:   []FilterOperator{FilterOperatorGreater, FilterOperatorLess, FilterOperatorGreaterEq, FilterOperatorLessEq},
		},
		{
			Name:        "updated_date",
			Label:       "Updated Date",
			Type:        FilterTypeDateRange,
			Field:       "updated_at",
			Description: "Filter by update date range",
			Operators:   []FilterOperator{FilterOperatorGreater, FilterOperatorLess, FilterOperatorGreaterEq, FilterOperatorLessEq},
		},
		{
			Name:        "last_seen",
			Label:       "Last Seen",
			Type:        FilterTypeDateRange,
			Field:       "last_seen",
			Description: "Filter by last seen date range",
			Operators:   []FilterOperator{FilterOperatorGreater, FilterOperatorLess, FilterOperatorGreaterEq, FilterOperatorLessEq},
		},
		{
			Name:        "certificate_expires",
			Label:       "Certificate Expires",
			Type:        FilterTypeDateRange,
			Field:       "certificate_expires_at",
			Description: "Filter by certificate expiration date range",
			Operators:   []FilterOperator{FilterOperatorGreater, FilterOperatorLess, FilterOperatorGreaterEq, FilterOperatorLessEq},
		},
		{
			Name:        "certificate_key_size",
			Label:       "Certificate Key Size",
			Type:        FilterTypeNumber,
			Field:       "certificate_key_size",
			Description: "Filter by certificate key size",
			Operators:   []FilterOperator{FilterOperatorEquals, FilterOperatorGreater, FilterOperatorLess, FilterOperatorGreaterEq, FilterOperatorLessEq},
		},
		{
			Name:        "crypto_protocol",
			Label:       "Crypto Protocol",
			Type:        FilterTypeSelect,
			Field:       "crypto_protocol",
			Description: "Filter by cryptographic protocol",
			Operators:   []FilterOperator{FilterOperatorEquals, FilterOperatorIn},
		},
		{
			Name:        "crypto_version",
			Label:       "Crypto Version",
			Type:        FilterTypeSelect,
			Field:       "crypto_version",
			Description: "Filter by cryptographic protocol version",
			Operators:   []FilterOperator{FilterOperatorEquals, FilterOperatorIn},
		},
	}
}

func (i *InventoryDataSource) getAggregationDefinitions() []AggregationDefinition {
	return []AggregationDefinition{
		{
			Name:        "count",
			Label:       "Count",
			Type:        AggregationTypeCount,
			Description: "Count the number of records",
			Fields:      []string{"*"},
		},
		{
			Name:        "count_by_type",
			Label:       "Count by Asset Type",
			Type:        AggregationTypeGroup,
			Description: "Count assets grouped by type",
			Fields:      []string{"type"},
		},
		{
			Name:        "count_by_environment",
			Label:       "Count by Environment",
			Type:        AggregationTypeGroup,
			Description: "Count assets grouped by environment",
			Fields:      []string{"environment"},
		},
		{
			Name:        "count_by_risk_level",
			Label:       "Count by Risk Level",
			Type:        AggregationTypeGroup,
			Description: "Count assets grouped by risk level",
			Fields:      []string{"risk_level"},
		},
		{
			Name:        "avg_crypto_risk_score",
			Label:       "Average Crypto Risk Score",
			Type:        AggregationTypeAvg,
			Description: "Average cryptographic risk score",
			Fields:      []string{"crypto_risk_score"},
		},
		{
			Name:        "min_certificate_key_size",
			Label:       "Minimum Certificate Key Size",
			Type:        AggregationTypeMin,
			Description: "Minimum certificate key size",
			Fields:      []string{"certificate_key_size"},
		},
		{
			Name:        "max_certificate_key_size",
			Label:       "Maximum Certificate Key Size",
			Type:        AggregationTypeMax,
			Description: "Maximum certificate key size",
			Fields:      []string{"certificate_key_size"},
		},
	}
}

func (i *InventoryDataSource) determineEndpoint(fields []string) string {
	// Always use the standard assets endpoint
	// The inventory service returns all asset data including certificates and crypto
	// when queried through the standard endpoint
	return "/api/v1/inventory-service/assets"
}

func (i *InventoryDataSource) buildQueryParams(params QueryParams) string {
	values := url.Values{}

	// Add pagination
	if params.Pagination != nil {
		values.Set("page", fmt.Sprintf("%d", params.Pagination.Page))
		values.Set("page_size", fmt.Sprintf("%d", params.Pagination.PageSize))
	}

	// Add search
	if params.Search != "" {
		values.Set("search", params.Search)
	}

	// Add filters - convert to inventory service format
	for _, filter := range params.Filters {
		fieldName := i.mapFieldToInventoryService(filter.Field)

		switch filter.Operator {
		case "in":
			// For "in" operator, add multiple values
			if arr, ok := filter.Value.([]interface{}); ok {
				for _, v := range arr {
					values.Add(fieldName, fmt.Sprintf("%v", v))
				}
			} else {
				values.Add(fieldName, fmt.Sprintf("%v", filter.Value))
			}
		case "eq":
			values.Set(fieldName, fmt.Sprintf("%v", filter.Value))
		case "ne":
			// For "ne" (not equal), we can't directly express this in the inventory service
			// For now, skip it - the service should handle default filtering
			// TODO: Implement proper exclusion filtering if inventory service supports it
			continue
		default:
			// For other operators, try to set the value
			values.Set(fieldName, fmt.Sprintf("%v", filter.Value))
		}
	}

	// Add sorting
	if len(params.Sort) > 0 {
		sort := params.Sort[0] // Use first sort
		values.Set("sort_by", sort.Field)
		values.Set("sort_order", sort.Order)
	}

	return values.Encode()
}

// mapFieldToInventoryService maps report generator field names to inventory service field names
func (i *InventoryDataSource) mapFieldToInventoryService(field string) string {
	fieldMap := map[string]string{
		"type":            "asset_type",
		"environment":     "environment",
		"risk_level":      "risk_level",
		"asset_ownership": "asset_ownership",
		"asset_status":    "asset_status",
		"created_at":      "created_at",
		"updated_at":      "updated_at",
		"last_seen":       "last_seen",
	}

	if mapped, ok := fieldMap[field]; ok {
		return mapped
	}
	return field
}

func (i *InventoryDataSource) isValidField(field string) bool {
	fields := i.getFieldDefinitions()
	for _, f := range fields {
		if f.Name == field {
			return true
		}
	}
	return false
}

func (i *InventoryDataSource) isValidFilterField(field string) bool {
	filters := i.getFilterDefinitions()
	for _, f := range filters {
		if f.Field == field {
			return true
		}
	}
	return false
}

func (i *InventoryDataSource) isValidFilterOperator(operator string) bool {
	validOperators := []string{
		"eq", "ne", "gt", "lt", "gte", "lte",
		"contains", "starts_with", "ends_with",
		"in", "not_in", "is_null", "is_not_null",
	}

	for _, op := range validOperators {
		if op == operator {
			return true
		}
	}
	return false
}

func (i *InventoryDataSource) isValidSortField(field string) bool {
	fields := i.getFieldDefinitions()
	for _, f := range fields {
		if f.Name == field && f.Sortable {
			return true
		}
	}
	return false
}
