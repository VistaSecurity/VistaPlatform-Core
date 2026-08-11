package approval

import (
	"encoding/json"
	"reflect"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/models"
)

// RuleEvaluator evaluates auto-approval rules against discoveries
type RuleEvaluator struct{}

// NewRuleEvaluator creates a new rule evaluator
func NewRuleEvaluator() *RuleEvaluator {
	return &RuleEvaluator{}
}

// EvaluateRule checks if a discovery matches the rule conditions
func (e *RuleEvaluator) EvaluateRule(rule *models.AutoApprovalRule, discovery *models.SensorDiscovery, classification *models.NetworkClassification) (bool, error) {
	if !rule.IsActive {
		return false, nil
	}

	conditions := rule.Conditions

	// Check source - supports "sensor_discoveries", "cloud_discovery", and "all"
	// Determine the actual source of this discovery from its metadata
	if source, ok := conditions["source"].(string); ok {
		discoverySource := getDiscoverySource(discovery)
		switch source {
		case "sensor_discoveries":
			if discoverySource == "cloud_discovery" {
				return false, nil // Rule only applies to sensor discoveries
			}
		case "cloud_discovery":
			if discoverySource != "cloud_discovery" {
				return false, nil // Rule only applies to cloud discoveries
			}
		case "all":
			// Matches both sources, continue
		default:
			// Unknown source condition value, skip this rule
			return false, nil
		}
	}

	// Check network ownership
	if ownership, ok := conditions["network_ownership"].(string); ok {
		if classification.Ownership != ownership {
			return false, nil
		}
	}

	// Check network type
	if netType, ok := conditions["network_type"].(string); ok {
		if classification.Type != netType {
			return false, nil
		}
	}

	// Check minimum confidence
	if minConf, ok := conditions["min_confidence"].(float64); ok {
		if discovery.Confidence < float64(minConf) {
			return false, nil
		}
	}

	// Check network space match requirement (legacy)
	if requireMatch, ok := conditions["require_network_space_match"].(bool); ok {
		if requireMatch {
			if classification.SpaceID == nil {
				return false, nil
			}
		}
	}

	// Check network segment match requirement
	if requireMatch, ok := conditions["require_network_segment_match"].(bool); ok {
		if requireMatch {
			if classification.SegmentID == nil {
				return false, nil
			}
		}
	}

	// Check specific network_segment_id condition
	if segIDVal, ok := conditions["network_segment_id"]; ok {
		var requiredID *uuid.UUID
		switch v := segIDVal.(type) {
		case string:
			if id, err := uuid.Parse(v); err == nil {
				requiredID = &id
			}
		}
		if requiredID != nil && (classification.SegmentID == nil || *classification.SegmentID != *requiredID) {
			return false, nil
		}
	}

	return true, nil
}

// getValue safely extracts a value from a map
func getValue(m map[string]interface{}, key string) (interface{}, bool) {
	val, ok := m[key]
	return val, ok
}

// getStringValue safely extracts a string value from a map
func getStringValue(m map[string]interface{}, key string) (string, bool) {
	val, ok := m[key]
	if !ok {
		return "", false
	}
	str, ok := val.(string)
	return str, ok
}

// getFloatValue safely extracts a float64 value from a map
func getFloatValue(m map[string]interface{}, key string) (float64, bool) {
	val, ok := m[key]
	if !ok {
		return 0, false
	}

	// Handle both float64 and int types
	switch v := val.(type) {
	case float64:
		return v, true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	default:
		// Try to convert via reflection
		rv := reflect.ValueOf(val)
		if rv.CanConvert(reflect.TypeOf(float64(0))) {
			return rv.Convert(reflect.TypeOf(float64(0))).Float(), true
		}
		return 0, false
	}
}

// getBoolValue safely extracts a bool value from a map
func getBoolValue(m map[string]interface{}, key string) (bool, bool) {
	val, ok := m[key]
	if !ok {
		return false, false
	}
	b, ok := val.(bool)
	return b, ok
}

// getDiscoverySource determines the origin of a sensor_discovery entry
// by inspecting its metadata for "discovery_method": "cloud_api"
func getDiscoverySource(discovery *models.SensorDiscovery) string {
	if len(discovery.Metadata) == 0 {
		return "sensor_discovery"
	}
	var metadata map[string]interface{}
	if err := json.Unmarshal(discovery.Metadata, &metadata); err != nil {
		return "sensor_discovery"
	}
	if method, ok := metadata["discovery_method"].(string); ok && method == "cloud_api" {
		return "cloud_discovery"
	}
	return "sensor_discovery"
}
