package services

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
)

// MeasurementValidator validates measurement inputs and rule configurations
type MeasurementValidator struct{}

// NewMeasurementValidator creates a new measurement validator
func NewMeasurementValidator() *MeasurementValidator {
	return &MeasurementValidator{}
}

// ValidateMeasurementInput performs comprehensive validation of a measurement input
func (v *MeasurementValidator) ValidateMeasurementInput(input *models.ControlMeasurementInput, measurementType *models.MeasurementType) error {
	// Validate rule type compatibility with data type
	if err := v.ValidateRuleTypeCompatibility(measurementType.DataType, input.RuleType, measurementType.AllowedRuleTypes); err != nil {
		return fmt.Errorf("rule type compatibility: %w", err)
	}

	// Validate predicate structure
	if err := v.ValidatePredicateStructure(input.RuleType, input.Predicate); err != nil {
		return fmt.Errorf("predicate structure: %w", err)
	}

	// Validate enum values if applicable
	if measurementType.DataType == "enum" && input.RuleType == "pattern" {
		if err := v.ValidateEnumValueInPredicate(measurementType, input.Predicate); err != nil {
			return fmt.Errorf("enum value: %w", err)
		}
	}

	// Validate operators for threshold rules
	if input.RuleType == "threshold" {
		if err := v.ValidateOperator(input.Predicate, measurementType.ValidOperators); err != nil {
			return fmt.Errorf("operator: %w", err)
		}
	}

	return nil
}

// ValidateRuleTypeCompatibility checks if rule type is allowed for the data type
func (v *MeasurementValidator) ValidateRuleTypeCompatibility(dataType, ruleType string, allowedRuleTypes []string) error {
	// If allowed_rule_types is specified, check against it
	if len(allowedRuleTypes) > 0 {
		for _, allowed := range allowedRuleTypes {
			if allowed == ruleType {
				return nil
			}
		}
		return fmt.Errorf("rule type '%s' is not allowed for data type '%s'. Allowed types: %v", ruleType, dataType, allowedRuleTypes)
	}

	// Default compatibility rules if allowed_rule_types is not specified
	switch dataType {
	case "integer":
		if ruleType != "threshold" && ruleType != "range" && ruleType != "presence" {
			return fmt.Errorf("rule type '%s' is not compatible with data type '%s'. Use threshold, range, or presence", ruleType, dataType)
		}
	case "enum":
		if ruleType != "pattern" && ruleType != "presence" {
			return fmt.Errorf("rule type '%s' is not compatible with data type '%s'. Use pattern or presence", ruleType, dataType)
		}
	case "string":
		if ruleType != "pattern" && ruleType != "presence" {
			return fmt.Errorf("rule type '%s' is not compatible with data type '%s'. Use pattern or presence", ruleType, dataType)
		}
	case "boolean":
		if ruleType != "presence" {
			return fmt.Errorf("rule type '%s' is not compatible with data type '%s'. Use presence", ruleType, dataType)
		}
	case "date":
		if ruleType != "threshold" && ruleType != "range" && ruleType != "presence" {
			return fmt.Errorf("rule type '%s' is not compatible with data type '%s'. Use threshold, range, or presence", ruleType, dataType)
		}
	default:
		return fmt.Errorf("unknown data type: %s", dataType)
	}

	return nil
}

// ValidatePredicateStructure validates that predicate has required fields for the rule type
func (v *MeasurementValidator) ValidatePredicateStructure(ruleType string, predicate map[string]interface{}) error {
	if predicate == nil {
		return fmt.Errorf("predicate cannot be nil")
	}

	switch ruleType {
	case "threshold":
		operator, ok := predicate["operator"]
		if !ok {
			return fmt.Errorf("threshold rule requires 'operator' field")
		}
		if _, ok := operator.(string); !ok {
			return fmt.Errorf("operator must be a string")
		}
		value, ok := predicate["value"]
		if !ok {
			return fmt.Errorf("threshold rule requires 'value' field")
		}
		if value == nil {
			return fmt.Errorf("value cannot be nil")
		}

	case "range":
		min, minOk := predicate["min"]
		max, maxOk := predicate["max"]
		if !minOk && !maxOk {
			return fmt.Errorf("range rule requires at least 'min' or 'max' field")
		}
		if minOk && min == nil {
			return fmt.Errorf("min cannot be nil if specified")
		}
		if maxOk && max == nil {
			return fmt.Errorf("max cannot be nil if specified")
		}
		// Validate min < max if both are provided
		if minOk && maxOk {
			if err := v.validateMinMax(min, max); err != nil {
				return fmt.Errorf("range validation: %w", err)
			}
		}

	case "pattern":
		pattern, ok := predicate["pattern"]
		if !ok {
			return fmt.Errorf("pattern rule requires 'pattern' field")
		}
		patternStr, ok := pattern.(string)
		if !ok {
			return fmt.Errorf("pattern must be a string")
		}
		if patternStr == "" {
			return fmt.Errorf("pattern cannot be empty")
		}
		// Validate regex pattern
		if _, err := regexp.Compile(patternStr); err != nil {
			return fmt.Errorf("invalid regex pattern: %w", err)
		}

	case "presence":
		exists, ok := predicate["exists"]
		if !ok {
			// Check for 'required' field as alternative (for backward compatibility)
			required, requiredOk := predicate["required"]
			if !requiredOk {
				return fmt.Errorf("presence rule requires 'exists' or 'required' field")
			}
			if _, ok := required.(bool); !ok {
				return fmt.Errorf("required must be a boolean")
			}
		} else {
			if _, ok := exists.(bool); !ok {
				return fmt.Errorf("exists must be a boolean")
			}
		}

	default:
		return fmt.Errorf("unknown rule type: %s", ruleType)
	}

	return nil
}

// validateMinMax validates that min < max for range rules
func (v *MeasurementValidator) validateMinMax(min, max interface{}) error {
	minFloat, err := toFloat64(min)
	if err != nil {
		return fmt.Errorf("min must be numeric: %w", err)
	}
	maxFloat, err := toFloat64(max)
	if err != nil {
		return fmt.Errorf("max must be numeric: %w", err)
	}
	if minFloat >= maxFloat {
		return fmt.Errorf("min (%v) must be less than max (%v)", min, max)
	}
	return nil
}

// toFloat64 converts a value to float64 for comparison
func toFloat64(v interface{}) (float64, error) {
	switch val := v.(type) {
	case float64:
		return val, nil
	case float32:
		return float64(val), nil
	case int:
		return float64(val), nil
	case int64:
		return float64(val), nil
	case int32:
		return float64(val), nil
	case string:
		// Try to parse as number
		var f float64
		_, err := fmt.Sscanf(val, "%f", &f)
		if err != nil {
			return 0, fmt.Errorf("cannot convert %T to float64", v)
		}
		return f, nil
	default:
		return 0, fmt.Errorf("cannot convert %T to float64", v)
	}
}

// ValidateEnumValue validates that an enum value is in the allowed list
func (v *MeasurementValidator) ValidateEnumValue(measurementType *models.MeasurementType, value interface{}) error {
	if measurementType.DataType != "enum" {
		return nil // Not applicable for non-enum types
	}

	if len(measurementType.EnumValues) == 0 {
		return nil // No enum values defined, skip validation
	}

	valueStr := fmt.Sprintf("%v", value)
	valueStr = strings.TrimSpace(valueStr)

	for _, enumVal := range measurementType.EnumValues {
		enumStr := fmt.Sprintf("%v", enumVal)
		if strings.EqualFold(valueStr, enumStr) {
			return nil // Found match
		}
	}

	return fmt.Errorf("value '%v' is not a valid enum value. Allowed values: %v", value, measurementType.EnumValues)
}

// ValidateEnumValueInPredicate validates enum values in pattern predicates
func (v *MeasurementValidator) ValidateEnumValueInPredicate(measurementType *models.MeasurementType, predicate map[string]interface{}) error {
	if measurementType.DataType != "enum" || len(measurementType.EnumValues) == 0 {
		return nil // Not applicable
	}

	// For pattern rules, we can't validate the pattern itself contains valid enum values
	// since patterns are regex. But we can validate that if a specific value is used,
	// it matches an enum value. This is a best-effort validation.
	// The actual validation happens during evaluation.

	return nil
}

// ValidateOperator validates that operator is in the allowed list
func (v *MeasurementValidator) ValidateOperator(predicate map[string]interface{}, allowedOperators []string) error {
	operator, ok := predicate["operator"]
	if !ok {
		return fmt.Errorf("operator field is required for threshold rules")
	}

	operatorStr, ok := operator.(string)
	if !ok {
		return fmt.Errorf("operator must be a string")
	}

	// If allowed_operators is specified, check against it
	if len(allowedOperators) > 0 {
		for _, allowed := range allowedOperators {
			if allowed == operatorStr {
				return nil
			}
		}
		return fmt.Errorf("operator '%s' is not allowed. Allowed operators: %v", operatorStr, allowedOperators)
	}

	// Default allowed operators for threshold rules
	validOperators := []string{"<=", ">=", "<", ">", "==", "!="}
	for _, valid := range validOperators {
		if valid == operatorStr {
			return nil
		}
	}

	return fmt.Errorf("operator '%s' is not valid. Valid operators: %v", operatorStr, validOperators)
}
