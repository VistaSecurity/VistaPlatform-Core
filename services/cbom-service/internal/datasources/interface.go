// Package datasources defines interfaces for pluggable data sources
package datasources

import (
	"context"
	"fmt"
	"time"
)

// DataSource represents a pluggable data source for report generation
type DataSource interface {
	// Name returns the unique identifier for this data source
	Name() string

	// Description returns a human-readable description of the data source
	Description() string

	// GetSchema returns the schema definition for this data source
	GetSchema() *DataSourceSchema

	// Query executes a query against the data source with the given parameters
	Query(ctx context.Context, params QueryParams) (interface{}, error)

	// Validate checks if the given parameters are valid for this data source
	Validate(params QueryParams) error

	// GetFields returns available fields that can be queried from this data source
	GetFields() []FieldDefinition

	// IsAvailable checks if the data source is currently available
	IsAvailable(ctx context.Context) bool
}

// DataSourceSchema defines the structure and capabilities of a data source
type DataSourceSchema struct {
	Name         string                  `json:"name"`
	Description  string                  `json:"description"`
	Version      string                  `json:"version"`
	Fields       []FieldDefinition       `json:"fields"`
	Filters      []FilterDefinition      `json:"filters"`
	Aggregations []AggregationDefinition `json:"aggregations"`
	Capabilities DataSourceCapabilities  `json:"capabilities"`
	Metadata     map[string]interface{}  `json:"metadata,omitempty"`
}

// FieldDefinition defines a field available in a data source
type FieldDefinition struct {
	Name         string           `json:"name"`
	Label        string           `json:"label"`
	Type         FieldType        `json:"type"`
	Description  string           `json:"description,omitempty"`
	Required     bool             `json:"required"`
	Indexed      bool             `json:"indexed"`
	Searchable   bool             `json:"searchable"`
	Sortable     bool             `json:"sortable"`
	Filterable   bool             `json:"filterable"`
	Aggregatable bool             `json:"aggregatable"`
	Options      []FieldOption    `json:"options,omitempty"`
	Validation   *FieldValidation `json:"validation,omitempty"`
}

// FieldType represents the type of a field
type FieldType string

const (
	FieldTypeString   FieldType = "string"
	FieldTypeNumber   FieldType = "number"
	FieldTypeBoolean  FieldType = "boolean"
	FieldTypeDate     FieldType = "date"
	FieldTypeDateTime FieldType = "datetime"
	FieldTypeArray    FieldType = "array"
	FieldTypeObject   FieldType = "object"
	FieldTypeEnum     FieldType = "enum"
	FieldTypeUUID     FieldType = "uuid"
	FieldTypeIP       FieldType = "ip"
	FieldTypeURL      FieldType = "url"
	FieldTypeEmail    FieldType = "email"
)

// FieldOption defines an option for enum fields
type FieldOption struct {
	Value       interface{} `json:"value"`
	Label       string      `json:"label"`
	Description string      `json:"description,omitempty"`
}

// FieldValidation defines validation rules for a field
type FieldValidation struct {
	MinLength     *int          `json:"min_length,omitempty"`
	MaxLength     *int          `json:"max_length,omitempty"`
	MinValue      *float64      `json:"min_value,omitempty"`
	MaxValue      *float64      `json:"max_value,omitempty"`
	Pattern       string        `json:"pattern,omitempty"`
	AllowedValues []interface{} `json:"allowed_values,omitempty"`
}

// FilterDefinition defines a filter available in a data source
type FilterDefinition struct {
	Name        string           `json:"name"`
	Label       string           `json:"label"`
	Type        FilterType       `json:"type"`
	Field       string           `json:"field"`
	Description string           `json:"description,omitempty"`
	Operators   []FilterOperator `json:"operators"`
	Options     []FilterOption   `json:"options,omitempty"`
}

// FilterType represents the type of a filter
type FilterType string

const (
	FilterTypeText        FilterType = "text"
	FilterTypeNumber      FilterType = "number"
	FilterTypeDate        FilterType = "date"
	FilterTypeDateRange   FilterType = "date-range"
	FilterTypeSelect      FilterType = "select"
	FilterTypeMultiSelect FilterType = "multi-select"
	FilterTypeBoolean     FilterType = "boolean"
)

// FilterOperator defines an operator for a filter
type FilterOperator struct {
	Value       string `json:"value"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
}

// FilterOption defines an option for select filters
type FilterOption struct {
	Value       interface{} `json:"value"`
	Label       string      `json:"label"`
	Description string      `json:"description,omitempty"`
}

// AggregationDefinition defines an aggregation available in a data source
type AggregationDefinition struct {
	Name        string          `json:"name"`
	Label       string          `json:"label"`
	Type        AggregationType `json:"type"`
	Description string          `json:"description,omitempty"`
	Fields      []string        `json:"fields"` // Fields this aggregation can be applied to
}

// AggregationType represents the type of an aggregation
type AggregationType string

const (
	AggregationTypeCount AggregationType = "count"
	AggregationTypeSum   AggregationType = "sum"
	AggregationTypeAvg   AggregationType = "avg"
	AggregationTypeMin   AggregationType = "min"
	AggregationTypeMax   AggregationType = "max"
	AggregationTypeGroup AggregationType = "group"
)

// DataSourceCapabilities defines what operations a data source supports
type DataSourceCapabilities struct {
	SupportsFiltering   bool `json:"supports_filtering"`
	SupportsSorting     bool `json:"supports_sorting"`
	SupportsPagination  bool `json:"supports_pagination"`
	SupportsAggregation bool `json:"supports_aggregation"`
	SupportsGrouping    bool `json:"supports_grouping"`
	SupportsSearch      bool `json:"supports_search"`
	SupportsRealTime    bool `json:"supports_real_time"`
	MaxPageSize         int  `json:"max_page_size,omitempty"`
	DefaultPageSize     int  `json:"default_page_size,omitempty"`
}

// QueryParams represents parameters for querying a data source
type QueryParams struct {
	Fields       []string               `json:"fields,omitempty"`
	Filters      []QueryFilter          `json:"filters,omitempty"`
	Sort         []QuerySort            `json:"sort,omitempty"`
	Pagination   *QueryPagination       `json:"pagination,omitempty"`
	Aggregations []QueryAggregation     `json:"aggregations,omitempty"`
	GroupBy      []string               `json:"group_by,omitempty"`
	Search       string                 `json:"search,omitempty"`
	DateRange    *DateRange             `json:"date_range,omitempty"`
	Custom       map[string]interface{} `json:"custom,omitempty"`
	AuthToken    string                 `json:"-"` // JWT token for service-to-service authentication (not serialized)
	TenantID     string                 `json:"-"` // Tenant UUID string for X-Tenant-ID header on internal calls (not serialized)
}

// QueryFilter represents a filter in a query
type QueryFilter struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// QuerySort represents sorting in a query
type QuerySort struct {
	Field string `json:"field"`
	Order string `json:"order"` // asc, desc
}

// QueryPagination represents pagination in a query
type QueryPagination struct {
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
}

// QueryAggregation represents an aggregation in a query
type QueryAggregation struct {
	Field string `json:"field"`
	Type  string `json:"type"`
	Alias string `json:"alias,omitempty"`
}

// DateRange represents a date range filter
type DateRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// QueryResult represents the result of a data source query
type QueryResult struct {
	Data         interface{}            `json:"data"`
	Total        int64                  `json:"total,omitempty"`
	Page         int                    `json:"page,omitempty"`
	PageSize     int                    `json:"page_size,omitempty"`
	HasMore      bool                   `json:"has_more,omitempty"`
	Aggregations map[string]interface{} `json:"aggregations,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// DataSourceRegistry manages available data sources
type DataSourceRegistry interface {
	// Register adds a data source to the registry
	Register(source DataSource) error

	// Unregister removes a data source from the registry
	Unregister(name string) error

	// Get retrieves a data source by name
	Get(name string) (DataSource, error)

	// List returns all registered data sources
	List() []DataSource

	// GetSchema returns the schema for a data source
	GetSchema(name string) (*DataSourceSchema, error)

	// GetFields returns available fields for a data source
	GetFields(name string) ([]FieldDefinition, error)
}

// DefaultDataSourceRegistry is the default implementation of DataSourceRegistry
type DefaultDataSourceRegistry struct {
	sources map[string]DataSource
}

// NewDefaultDataSourceRegistry creates a new default data source registry
func NewDefaultDataSourceRegistry() *DefaultDataSourceRegistry {
	return &DefaultDataSourceRegistry{
		sources: make(map[string]DataSource),
	}
}

// Register adds a data source to the registry
func (r *DefaultDataSourceRegistry) Register(source DataSource) error {
	if source == nil {
		return fmt.Errorf("data source cannot be nil")
	}

	name := source.Name()
	if name == "" {
		return fmt.Errorf("data source name cannot be empty")
	}

	if _, exists := r.sources[name]; exists {
		return fmt.Errorf("data source '%s' is already registered", name)
	}

	r.sources[name] = source
	return nil
}

// Unregister removes a data source from the registry
func (r *DefaultDataSourceRegistry) Unregister(name string) error {
	if _, exists := r.sources[name]; !exists {
		return fmt.Errorf("data source '%s' is not registered", name)
	}

	delete(r.sources, name)
	return nil
}

// Get retrieves a data source by name
func (r *DefaultDataSourceRegistry) Get(name string) (DataSource, error) {
	source, exists := r.sources[name]
	if !exists {
		return nil, fmt.Errorf("data source '%s' is not registered", name)
	}

	return source, nil
}

// List returns all registered data sources
func (r *DefaultDataSourceRegistry) List() []DataSource {
	sources := make([]DataSource, 0, len(r.sources))
	for _, source := range r.sources {
		sources = append(sources, source)
	}
	return sources
}

// GetSchema returns the schema for a data source
func (r *DefaultDataSourceRegistry) GetSchema(name string) (*DataSourceSchema, error) {
	source, err := r.Get(name)
	if err != nil {
		return nil, err
	}

	return source.GetSchema(), nil
}

// GetFields returns available fields for a data source
func (r *DefaultDataSourceRegistry) GetFields(name string) ([]FieldDefinition, error) {
	source, err := r.Get(name)
	if err != nil {
		return nil, err
	}

	return source.GetFields(), nil
}

// Common filter operators
var (
	FilterOperatorEquals     = FilterOperator{Value: "eq", Label: "Equals"}
	FilterOperatorNotEquals  = FilterOperator{Value: "ne", Label: "Not Equals"}
	FilterOperatorGreater    = FilterOperator{Value: "gt", Label: "Greater Than"}
	FilterOperatorLess       = FilterOperator{Value: "lt", Label: "Less Than"}
	FilterOperatorGreaterEq  = FilterOperator{Value: "gte", Label: "Greater Than or Equal"}
	FilterOperatorLessEq     = FilterOperator{Value: "lte", Label: "Less Than or Equal"}
	FilterOperatorContains   = FilterOperator{Value: "contains", Label: "Contains"}
	FilterOperatorStartsWith = FilterOperator{Value: "starts_with", Label: "Starts With"}
	FilterOperatorEndsWith   = FilterOperator{Value: "ends_with", Label: "Ends With"}
	FilterOperatorIn         = FilterOperator{Value: "in", Label: "In"}
	FilterOperatorNotIn      = FilterOperator{Value: "not_in", Label: "Not In"}
	FilterOperatorIsNull     = FilterOperator{Value: "is_null", Label: "Is Null"}
	FilterOperatorIsNotNull  = FilterOperator{Value: "is_not_null", Label: "Is Not Null"}
)

// Common sort orders
const (
	SortOrderAscending  = "asc"
	SortOrderDescending = "desc"
)
