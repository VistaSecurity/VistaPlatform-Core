package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// LogWithContext creates a rich audit log entry with full context
func LogWithContext(
	ctx context.Context,
	mw *Middleware,
	eventType string,
	eventCategory string,
	action string,
	resourceType string,
	resourceID string,
	resourceName string,
	oldValues interface{},
	newValues interface{},
	metadata AuditMetadata,
) error {
	if mw == nil {
		return fmt.Errorf("audit middleware is nil")
	}

	// Calculate changed fields
	changedFields := calculateChangedFields(oldValues, newValues)

	// Generate change summary if not provided
	if metadata.ChangeSummary == "" && len(changedFields) > 0 {
		metadata.ChangeSummary = generateChangeSummary(changedFields, oldValues, newValues)
	}

	// Add resource name to metadata
	if resourceName != "" && metadata.ResourceName == "" {
		metadata.ResourceName = resourceName
	}

	// Convert metadata to map
	metadataMap := structToMap(metadata)

	// Determine compliance tags
	complianceTags := determineComplianceTags(eventCategory, action)

	// Convert string IDs to UUIDs if valid
	var resourceUUID *uuid.UUID
	if resourceID != "" {
		if parsed, err := uuid.Parse(resourceID); err == nil {
			resourceUUID = &parsed
		}
	}

	// Convert old/new values to map format
	var oldValuesMap, newValuesMap map[string]interface{}
	if oldValues != nil {
		oldValuesMap = interfaceToMap(oldValues)
	}
	if newValues != nil {
		newValuesMap = interfaceToMap(newValues)
	}

	// Create proper ActivityLogRequest
	logEntry := &ActivityLogRequest{
		EventType:      eventType,
		EventCategory:  eventCategory,
		Action:         action,
		UserType:       "platform", // Default; overridden by middleware context if available
		ResourceType:   stringPtr(resourceType),
		ResourceID:     resourceUUID,
		OldValues:      oldValuesMap,
		NewValues:      newValuesMap,
		ChangedFields:  changedFields,
		Metadata:       metadataMap,
		ComplianceTags: complianceTags,
		Success:        true,
		OccurredAt:     time.Now(),
	}

	return mw.LogActivity(ctx, logEntry)
}

// LogSimple creates a simple audit log entry for straightforward actions
func LogSimple(
	ctx context.Context,
	mw *Middleware,
	eventType string,
	eventCategory string,
	action string,
	resourceType string,
	resourceID string,
	resourceName string,
	success bool,
	errorMessage string,
) error {
	if mw == nil {
		return fmt.Errorf("audit middleware is nil")
	}

	metadata := make(map[string]interface{})
	if resourceName != "" {
		metadata["resource_name"] = resourceName
	}

	// Convert string IDs to UUIDs if valid
	var resourceUUID *uuid.UUID
	if resourceID != "" {
		if parsed, err := uuid.Parse(resourceID); err == nil {
			resourceUUID = &parsed
		}
	}

	// Create proper ActivityLogRequest
	logEntry := &ActivityLogRequest{
		EventType:      eventType,
		EventCategory:  eventCategory,
		Action:         action,
		UserType:       "platform", // Default; overridden by middleware context if available
		ResourceType:   stringPtr(resourceType),
		ResourceID:     resourceUUID,
		Metadata:       metadata,
		Success:        success,
		ErrorMessage:   stringPtr(errorMessage),
		ComplianceTags: determineComplianceTags(eventCategory, action),
		OccurredAt:     time.Now(),
	}

	return mw.LogActivity(ctx, logEntry)
}

// calculateChangedFields compares old and new values to determine what changed
func calculateChangedFields(old, new interface{}) []string {
	if old == nil || new == nil {
		return []string{}
	}

	changedFields := []string{}

	// Convert to maps for comparison
	oldMap := interfaceToMap(old)
	newMap := interfaceToMap(new)

	// Find changed fields
	for key, newVal := range newMap {
		oldVal, exists := oldMap[key]
		if !exists || !reflect.DeepEqual(oldVal, newVal) {
			changedFields = append(changedFields, key)
		}
	}

	return changedFields
}

// generateChangeSummary creates a human-readable summary of changes
func generateChangeSummary(fields []string, oldValues, newValues interface{}) string {
	if len(fields) == 0 {
		return ""
	}

	oldMap := interfaceToMap(oldValues)
	newMap := interfaceToMap(newValues)

	summaries := []string{}

	for _, field := range fields {
		oldVal := fmt.Sprintf("%v", oldMap[field])
		newVal := fmt.Sprintf("%v", newMap[field])

		// Clean field names (camelCase -> Title Case)
		cleanField := cleanFieldName(field)

		summary := fmt.Sprintf("%s changed from '%s' to '%s'", cleanField, oldVal, newVal)
		summaries = append(summaries, summary)
	}

	return strings.Join(summaries, ", ")
}

// determineComplianceTags returns applicable compliance tags based on event category
func determineComplianceTags(category, action string) []string {
	tags, exists := ComplianceFrameworks[category]
	if !exists {
		// Default compliance tags for unknown categories
		return []string{"soc2", "iso27001"}
	}
	return tags
}

// interfaceToMap converts an interface to a map for comparison
func interfaceToMap(i interface{}) map[string]interface{} {
	if i == nil {
		return make(map[string]interface{})
	}

	// If already a map, return it
	if m, ok := i.(map[string]interface{}); ok {
		return m
	}

	// Convert via JSON marshaling/unmarshaling
	bytes, err := json.Marshal(i)
	if err != nil {
		return make(map[string]interface{})
	}

	var result map[string]interface{}
	if err := json.Unmarshal(bytes, &result); err != nil {
		return make(map[string]interface{})
	}

	return result
}

// structToMap converts a struct to map
func structToMap(i interface{}) map[string]interface{} {
	return interfaceToMap(i)
}

// cleanFieldName converts field names to human-readable format
func cleanFieldName(field string) string {
	// Convert camelCase to Title Case
	var result strings.Builder
	for i, r := range field {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result.WriteRune(' ')
		}
		if i == 0 {
			result.WriteRune(r)
		} else {
			result.WriteRune(r)
		}
	}
	return strings.Title(strings.ToLower(result.String()))
}

// ExtractAuditMiddleware safely extracts audit middleware from a gin context.
// The parameter should be a *gin.Context or any type with a Get method keyed
// by string or by any.
//
// The *gin.Context case is asserted CONCRETELY and first. It used to be
// duck-typed on `Get(string) (interface{}, bool)` alone, which stopped
// matching when gin 1.11 widened the signature to `Get(key any)`: from that
// upgrade on, every caller silently got (nil, false) and skipped its explicit
// audit entry — no error, no log line, just no record. The two Get shapes
// below are kept as a fallback for non-gin callers and for gin ≤1.10.
func ExtractAuditMiddleware(c interface{}) (*Middleware, bool) {
	if gc, ok := c.(*gin.Context); ok {
		return middlewareFromValue(gc.Get("audit_middleware"))
	}

	type stringKeyGetter interface {
		Get(string) (interface{}, bool)
	}
	type anyKeyGetter interface {
		Get(interface{}) (interface{}, bool)
	}

	switch ctx := c.(type) {
	case anyKeyGetter:
		return middlewareFromValue(ctx.Get("audit_middleware"))
	case stringKeyGetter:
		return middlewareFromValue(ctx.Get("audit_middleware"))
	}
	return nil, false
}

// middlewareFromValue narrows a context lookup result to *Middleware.
func middlewareFromValue(mw interface{}, exists bool) (*Middleware, bool) {
	if !exists || mw == nil {
		return nil, false
	}

	// Direct type assertion
	if auditMW, ok := mw.(*Middleware); ok {
		return auditMW, true
	}

	return nil, false
}

// stringPtr returns a pointer to a string if non-empty, nil otherwise
func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
