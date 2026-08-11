// Package database provides shared database connection helpers and query utilities.
package database

import (
	"fmt"
	"strings"
)

// WhereBuilder accumulates WHERE conditions with auto-incrementing PostgreSQL
// placeholder indices ($1, $2, ...). Use it to replace the duplicated
// "WHERE 1=1" + argIdx++ pattern across services.
//
// Usage:
//
//	wb := database.NewWhereBuilder()
//	if filters.TenantID != nil {
//	    wb.Add("tenant_id = %s", *filters.TenantID)
//	}
//	if filters.Name != "" {
//	    wb.Add("name ILIKE %s", "%"+filters.Name+"%")
//	}
//	clause, args := wb.Build()
//	query := "SELECT * FROM items " + clause + " ORDER BY created_at"
//	rows, err := db.QueryContext(ctx, query, args...)
type WhereBuilder struct {
	conditions []string
	args       []interface{}
	argIdx     int
}

// NewWhereBuilder creates a builder starting at $1.
func NewWhereBuilder() *WhereBuilder {
	return &WhereBuilder{argIdx: 1}
}

// NewWhereBuilderFrom creates a builder starting at a given placeholder index.
// Use this when the query already has earlier placeholders (e.g. from a CTE).
func NewWhereBuilderFrom(startIdx int) *WhereBuilder {
	return &WhereBuilder{argIdx: startIdx}
}

// Add appends a condition. Each %s in the condition template is replaced with
// the next $N placeholder. The corresponding values are collected as args.
//
//	wb.Add("tenant_id = %s", tenantID)        // → "tenant_id = $1"
//	wb.Add("name ILIKE %s", "%search%")       // → "name ILIKE $2"
//	wb.Add("status = ANY(%s)", pq.Array(arr)) // → "status = ANY($3)"
func (wb *WhereBuilder) Add(conditionTemplate string, values ...interface{}) {
	// Replace each %s with the next $N placeholder
	result := conditionTemplate
	for _, v := range values {
		result = strings.Replace(result, "%s", fmt.Sprintf("$%d", wb.argIdx), 1)
		wb.args = append(wb.args, v)
		wb.argIdx++
	}
	wb.conditions = append(wb.conditions, result)
}

// AddRaw appends a condition with no placeholder substitution.
// Use for static conditions like "deleted_at IS NULL".
func (wb *WhereBuilder) AddRaw(condition string) {
	wb.conditions = append(wb.conditions, condition)
}

// Len returns the number of conditions added.
func (wb *WhereBuilder) Len() int {
	return len(wb.conditions)
}

// ArgIndex returns the next available placeholder index.
// Useful for appending LIMIT/OFFSET after the WHERE clause.
func (wb *WhereBuilder) ArgIndex() int {
	return wb.argIdx
}

// Args returns the accumulated argument slice.
func (wb *WhereBuilder) Args() []interface{} {
	return wb.args
}

// Build returns the full "WHERE c1 AND c2 AND ..." clause and args.
// Returns an empty string (not "WHERE 1=1") when no conditions were added.
func (wb *WhereBuilder) Build() (string, []interface{}) {
	if len(wb.conditions) == 0 {
		return "", wb.args
	}
	return "WHERE " + strings.Join(wb.conditions, " AND "), wb.args
}

// BuildAppend is like Build but appends to an existing base query using
// "WHERE 1=1" style (returns " AND c1 AND c2 ..." or empty string).
// Use when the base query already contains a WHERE clause.
func (wb *WhereBuilder) BuildAppend() (string, []interface{}) {
	if len(wb.conditions) == 0 {
		return "", wb.args
	}
	return " AND " + strings.Join(wb.conditions, " AND "), wb.args
}
