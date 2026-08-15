package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// RuleEvaluator evaluates compliance controls dynamically based on measurement mappings
type RuleEvaluator struct {
	db                   *sqlx.DB
	measurementExtractor *MeasurementExtractor
	// metrics is optional (nil in tests and in the single-control entry points
	// wired without it). It is the counter home for not-assessed controls and
	// measurement-extraction errors: MetricsService already backs the service's
	// /metrics endpoint and already carries non-NATS counters (finding upserts),
	// so an operator can see "this tenant's controls stopped being assessed"
	// without reading logs.
	metrics *MetricsService
}

// NewRuleEvaluator creates a new rule evaluator
func NewRuleEvaluator(db *sqlx.DB, measurementExtractor *MeasurementExtractor) *RuleEvaluator {
	return &RuleEvaluator{
		db:                   db,
		measurementExtractor: measurementExtractor,
	}
}

// SetMetrics attaches the process metrics sink. A setter rather than a
// constructor argument because NewRuleEvaluator has call sites in three services'
// worth of tests, and the evaluator must keep working (silently, not crashing)
// when no sink is attached.
func (s *RuleEvaluator) SetMetrics(m *MetricsService) { s.metrics = m }

func (s *RuleEvaluator) recordNotAssessed(reason string) {
	if s.metrics != nil {
		s.metrics.RecordControlNotAssessed(reason)
	}
}

// EvaluationResult represents the result of evaluating a control
type EvaluationResult struct {
	ControlID uuid.UUID
	Status    string // pass, fail, not_assessed
	Severity  string // Low, Med, High, Critical
	Findings  []models.ComplianceFinding
	// Score is nil when the control was NOT assessed. A not-assessed control has
	// no score — it used to report 100, which is the loudest possible way of
	// saying "we did not look".
	Score *int
	// NotAssessedReason is one of reasonNoMeasurements / reasonNothingInScope /
	// reasonCheckError, and empty otherwise.
	NotAssessedReason string
	Rationale         string
}

// notAssessed builds the result for a control that could not be evaluated. It is
// deliberately the ONLY way this file produces a not-assessed result, so every
// such control is counted where an operator can see it.
func (s *RuleEvaluator) notAssessed(controlID uuid.UUID, baselineSeverity, reason, rationale string) *EvaluationResult {
	s.recordNotAssessed(reason)
	severity := baselineSeverity
	if severity == "" {
		severity = "Low"
	}
	return &EvaluationResult{
		ControlID:         controlID,
		Status:            strings.ToLower(statusNotAssessed),
		Severity:          severity,
		Findings:          []models.ComplianceFinding{},
		Score:             nil,
		NotAssessedReason: reason,
		Rationale:         rationale,
	}
}

// EvaluateControl evaluates a control against tenant assets using its measurement mappings.
func (s *RuleEvaluator) EvaluateControl(tenantID, controlID uuid.UUID, frameworkType string) (*EvaluationResult, error) {
	valueCache := map[string][]MeasurementValue{}
	typeCache := map[uuid.UUID]models.MeasurementType{}
	return s.evaluateControlCached(tenantID, controlID, frameworkType, s.controlBaselineSeverity(controlID, frameworkType), s.cachedExtractor(tenantID, valueCache), typeCache)
}

// controlBaselineSeverity looks up a control's baseline_severity for the
// single-control entry point (the batch entry points already carry the loaded
// models.Control). Returns "" when the control cannot be read; callers fall
// back to "Med" rather than failing the evaluation over a severity label.
func (s *RuleEvaluator) controlBaselineSeverity(controlID uuid.UUID, frameworkType string) string {
	table := "platform_framework_controls"
	if frameworkType == "tenant" {
		table = "tenant_framework_controls"
	}
	var severity string
	if err := s.db.Get(&severity, "SELECT COALESCE(baseline_severity, '') FROM "+table+" WHERE id = $1", controlID); err != nil {
		return ""
	}
	return severity
}

// EvaluateControlsBatch evaluates many controls while extracting each measurement
// type only once across the whole batch (shared cache). This is the extract-once /
// fold-all primitive the evaluation engine (ADR-0014) relies on: the marginal cost
// of another framework is just more cheap predicates, not another inventory scan.
// Controls whose evaluation errors are omitted from the result map (engine treats a
// missing result as "no findings").
func (s *RuleEvaluator) EvaluateControlsBatch(tenantID uuid.UUID, controls []models.Control, frameworkType string) (map[uuid.UUID]*EvaluationResult, error) {
	valueCache := map[string][]MeasurementValue{}
	typeCache := map[uuid.UUID]models.MeasurementType{}
	getValues := s.cachedExtractor(tenantID, valueCache)

	results := make(map[uuid.UUID]*EvaluationResult, len(controls))
	for _, control := range controls {
		res, err := s.evaluateControlCached(tenantID, control.ID, frameworkType, control.BaselineSeverity, getValues, typeCache)
		if err != nil {
			continue
		}
		results[control.ID] = res
	}
	return results, nil
}

// cachedExtractor returns an extraction closure that memoizes ExtractMeasurements by
// measurement-type code, so the same measurement (e.g. tls_version) is pulled once
// even when many controls across many frameworks reference it.
func (s *RuleEvaluator) cachedExtractor(tenantID uuid.UUID, cache map[string][]MeasurementValue) func(string) ([]MeasurementValue, error) {
	return func(code string) ([]MeasurementValue, error) {
		if v, ok := cache[code]; ok {
			return v, nil
		}
		v, err := s.measurementExtractor.ExtractMeasurements(tenantID, code)
		if err != nil {
			return nil, err
		}
		cache[code] = v
		return v, nil
	}
}

// cachedExtractorForAsset is cachedExtractor scoped to a single asset (ADR-0015
// per-asset reconcile).
func (s *RuleEvaluator) cachedExtractorForAsset(tenantID, assetID uuid.UUID, cache map[string][]MeasurementValue) func(string) ([]MeasurementValue, error) {
	return func(code string) ([]MeasurementValue, error) {
		if v, ok := cache[code]; ok {
			return v, nil
		}
		v, err := s.measurementExtractor.ExtractMeasurementsForAsset(tenantID, assetID, code)
		if err != nil {
			return nil, err
		}
		cache[code] = v
		return v, nil
	}
}

// EvaluateControlsBatchForAsset evaluates every control against a SINGLE asset's
// measurement values (ADR-0015 per-asset reconcile). Same extract-once / fold-all
// shape as EvaluateControlsBatch, bounded to one asset so a change reconciles only
// that asset's findings.
func (s *RuleEvaluator) EvaluateControlsBatchForAsset(tenantID, assetID uuid.UUID, controls []models.Control, frameworkType string) (map[uuid.UUID]*EvaluationResult, error) {
	valueCache := map[string][]MeasurementValue{}
	typeCache := map[uuid.UUID]models.MeasurementType{}
	getValues := s.cachedExtractorForAsset(tenantID, assetID, valueCache)

	results := make(map[uuid.UUID]*EvaluationResult, len(controls))
	for _, control := range controls {
		res, err := s.evaluateControlCached(tenantID, control.ID, frameworkType, control.BaselineSeverity, getValues, typeCache)
		if err != nil {
			continue
		}
		results[control.ID] = res
	}
	return results, nil
}

// evaluateControlCached is the shared per-control body used by both EvaluateControl
// and EvaluateControlsBatch. Measurement values and types come from caller-supplied
// caches so extraction work is shared across the batch. baselineSeverity is the
// control's own rating, used when a measurement carries no severity_override.
func (s *RuleEvaluator) evaluateControlCached(tenantID, controlID uuid.UUID, frameworkType, baselineSeverity string, getValues func(string) ([]MeasurementValue, error), typeCache map[uuid.UUID]models.MeasurementType) (*EvaluationResult, error) {
	measurements, err := s.getControlMeasurements(tenantID, controlID, frameworkType)
	if err != nil {
		return nil, fmt.Errorf("failed to get control measurements: %w", err)
	}

	if len(measurements) == 0 {
		//: a control with nothing configured to check has NOT been
		// assessed. It used to return pass/100, which made a half-authored
		// framework indistinguishable from a clean one.
		return s.notAssessed(controlID, baselineSeverity, reasonNoMeasurements,
			"No measurement mappings configured"), nil
	}

	var allFindings []models.ComplianceFinding
	var maxSeverity = "Low"
	var totalWeight int
	var passedWeight int
	var checkErrors int

	// Evaluate each measurement
	for _, measurement := range measurements {
		// Get measurement type (memoized across the batch)
		measurementType, ok := typeCache[measurement.MeasurementTypeID]
		if !ok {
			if err := s.db.Get(&measurementType, "SELECT code, name, data_type FROM measurement_types WHERE id = $1", measurement.MeasurementTypeID); err != nil {
				//: an unreadable measurement type is a failed check, not a
				// pass. Log AND count it — "not assessed" is only defensible
				// while the error is observable.
				checkErrors++
				s.recordExtractionError()
				log.Printf("[RuleEvaluator] WARN: control %s measurement %s: measurement type %s unreadable: %v",
					controlID, measurement.ID, measurement.MeasurementTypeID, err)
				continue
			}
			typeCache[measurement.MeasurementTypeID] = measurementType
		}

		// Extract measurements from inventory (memoized by code across the batch)
		measurementValues, err := getValues(measurementType.Code)
		if err != nil {
			checkErrors++
			s.recordExtractionError()
			log.Printf("[RuleEvaluator] WARN: control %s measurement %s: extraction of %q failed: %v",
				controlID, measurement.ID, measurementType.Code, err)
			continue
		}

		// Evaluate each measurement value against the rule
		for _, value := range measurementValues {
			passed, severity := s.evaluateMeasurement(value, measurement, measurementType, baselineSeverity)

			weight := measurement.Weight
			if weight == 0 {
				weight = 1
			}
			totalWeight += weight

			if !passed {
				// Create finding
				finding := s.createFinding(tenantID, controlID, value, measurement, measurementType, severity)
				allFindings = append(allFindings, finding)

				// Update max severity
				if s.severityLevel(severity) > s.severityLevel(maxSeverity) {
					maxSeverity = severity
				}
			} else {
				passedWeight += weight
			}
		}
	}

	// Calculate status and score.
	//
	//: status is decided by whether the control was VIOLATED, not by how
	// severe the violation is rated. Severity remains the scoring weight
	// (severityToWeight) and nothing else. The previous mapping ran the honest
	// `len(allFindings) > 0` signal through the control's own severity and threw
	// it away: a violated Low-baseline control reported PASS, and a Med one
	// reported WARN, which earned no weight but read as "not failing".
	//
	// A control with measurements but no values evaluated (totalWeight == 0) was
	// NOT assessed: either its extractions errored, or nothing in the tenant's
	// inventory is in scope for it. Both used to score 100.
	//
	// EvaluationResult.Status is lowercase by long-standing contract (callers
	// ToUpper it — see evaluation_service.go).
	if totalWeight == 0 {
		reason := reasonNothingInScope
		rationale := fmt.Sprintf("Evaluated %d measurement(s); no values in scope to check", len(measurements))
		if checkErrors > 0 {
			reason = reasonCheckError
			rationale = fmt.Sprintf("Evaluated %d measurement(s); %d check(s) failed", len(measurements), checkErrors)
		}
		return s.notAssessed(controlID, baselineSeverity, reason, rationale), nil
	}

	status := strings.ToLower(statusForFindings(len(allFindings) > 0))
	score := (passedWeight * 100) / totalWeight

	rationale := fmt.Sprintf("Evaluated %d measurement(s), found %d violation(s)", len(measurements), len(allFindings))
	if checkErrors > 0 {
		// Partially assessed: some measurements produced values, others errored.
		// The control still has a verdict, but say so rather than implying the
		// whole control was checked.
		rationale = fmt.Sprintf("%s; %d check(s) failed", rationale, checkErrors)
	}

	return &EvaluationResult{
		ControlID: controlID,
		Status:    status,
		Severity:  maxSeverity,
		Findings:  allFindings,
		Score:     &score,
		Rationale: rationale,
	}, nil
}

// recordExtractionError counts a failed measurement check. Paired with the log
// line at every call site:'s D5 accepts "an error is not a failure" only
// while the error is both logged and counted — the bare `continue` this replaces
// discarded it entirely.
func (s *RuleEvaluator) recordExtractionError() {
	if s.metrics != nil {
		s.metrics.RecordMeasurementExtractionError()
	}
}

// getControlMeasurements gets all measurement mappings for a control, with the
// tenant's threshold overrides already folded in.
//
// The `threshold_overrides` premium feature lets a tenant customise the predicate
// (and re-rate the severity) of a measurement on a licensed platform framework's
// control, without copying the framework. The authoring surface lives in the
// Enterprise build (services/compliance-engine/ee/thresholds); *applying* the
// override lives here in Core, because a Core install must still evaluate
// correctly against overrides an Enterprise install authored — see that package's
// doc comment.
//
// Until this join existed, the overrides were written and never read: the feature
// billed, stored, and did nothing.
//
// Entitlement is checked at authoring time, not here. Re-checking per evaluation
// would put a feature-flag lookup in the hot loop and, worse, would silently
// change a tenant's historical posture the moment a subscription lapsed. An
// override row existing means it was entitled when authored; removing its effect
// is a job for deleting the row.
func (s *RuleEvaluator) getControlMeasurements(tenantID, controlID uuid.UUID, frameworkType string) ([]models.ControlMeasurement, error) {
	// tenant_measurement_overrides is RLS-policied, so the read runs inside a
	// tenant-scoped transaction. The explicit tmo.tenant_id predicate stays as
	// the primary control (RLS is defence in depth, not the boundary).
	query := `
		SELECT cm.id, cm.control_id, cm.framework_type, cm.measurement_type_id, cm.rule_type,
		       cm.predicate, cm.severity_override, cm.weight, cm.created_at, cm.updated_at,
		       tmo.predicate_override, tmo.severity_override
		FROM control_measurements cm
		LEFT JOIN tenant_measurement_overrides tmo
		       ON tmo.control_measurement_id = cm.id AND tmo.tenant_id = $1
		WHERE cm.control_id = $2 AND cm.framework_type = $3
	`

	var measurements []models.ControlMeasurement
	err := shareddatabase.WithTenantTx(context.Background(), s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qerr := tx.Query(query, tenantID, controlID, frameworkType)
		if qerr != nil {
			return qerr
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var m models.ControlMeasurement
			var predicateJSON []byte
			var overridePredicateJSON []byte
			var overrideSeverity sql.NullString
			// cm.severity_override is NULLable and means "no per-measurement
			// re-rating" — the overwhelmingly common case. Scanning it into
			// models.ControlMeasurement's plain string errored on every such
			// row, and the `continue` below then dropped the measurement
			// entirely: the control silently had nothing to check. Same
			// swallow-the-error shape is about, one layer down.
			var severityOverride sql.NullString

			if err := rows.Scan(
				&m.ID, &m.ControlID, &m.FrameworkType, &m.MeasurementTypeID,
				&m.RuleType, &predicateJSON, &severityOverride, &m.Weight,
				&m.CreatedAt, &m.UpdatedAt,
				&overridePredicateJSON, &overrideSeverity,
			); err != nil {
				log.Printf("[RuleEvaluator] WARN: control %s: unreadable control_measurements row, measurement skipped: %v", controlID, err)
				continue
			}
			m.SeverityOverride = severityOverride.String

			// Unmarshal predicate
			if err := json.Unmarshal(predicateJSON, &m.Predicate); err != nil {
				log.Printf("[RuleEvaluator] WARN: control %s measurement %s: undecodable predicate, measurement skipped: %v", controlID, m.ID, err)
				continue
			}

			applyThresholdOverride(&m, overridePredicateJSON, overrideSeverity)
			measurements = append(measurements, m)
		}

		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	return measurements, nil
}

// applyThresholdOverride folds a tenant's `tenant_measurement_overrides` row onto
// the platform measurement. Both columns are optional in effect: a NULL severity
// leaves the platform rating, and a predicate that does not decode to a non-empty
// object leaves the platform predicate.
//
// That last rule is deliberate and load-bearing. `predicate_override` is NOT NULL
// at the schema level, so a malformed authoring call can persist `{}` — and every
// branch of the rule evaluator returns "passed" when it cannot read its operator
// or value. Honouring an empty predicate would therefore silently disable the
// control while still reporting it as evaluated, which is exactly the
// check-that-cannot-fail shape this codebase keeps getting bitten by. A tenant who
// genuinely wants a control not to count has the `compliance_overrides` disregard
// mechanism, which says so explicitly and is audited.
func applyThresholdOverride(m *models.ControlMeasurement, predicateJSON []byte, severity sql.NullString) {
	if len(predicateJSON) > 0 {
		var override map[string]interface{}
		if err := json.Unmarshal(predicateJSON, &override); err == nil && len(override) > 0 {
			m.Predicate = override
		}
	}
	if severity.Valid && severity.String != "" {
		m.SeverityOverride = severity.String
	}
}

// evaluateMeasurement evaluates a single measurement value against a rule.
//
// baselineSeverity is the owning control's `baseline_severity`. A measurement's
// severity_override wins when set; otherwise the control's own rating applies.
// Until CMP-9 this fell back to the literal "Med" while its comment claimed it
// used the control baseline, so a Critical control's un-overridden measurements
// silently produced Med findings — and, through statusForWorstSeverity, WARN
// instead of FAIL.
func (s *RuleEvaluator) evaluateMeasurement(value MeasurementValue, measurement models.ControlMeasurement, measurementType models.MeasurementType, baselineSeverity string) (passed bool, severity string) {
	severity = measurement.SeverityOverride
	if severity == "" {
		severity = baselineSeverity
	}
	if severity == "" {
		severity = "Med" // Last resort: control carries no baseline either.
	}

	switch measurement.RuleType {
	case "threshold":
		return s.evaluateThreshold(value, measurement.Predicate), severity
	case "presence":
		return s.evaluatePresence(value, measurement.Predicate), severity
	case "pattern":
		return s.evaluatePattern(value, measurement.Predicate), severity
	case "range":
		return s.evaluateRange(value, measurement.Predicate), severity
	default:
		return true, severity // Unknown rule type - pass by default
	}
}

// evaluateThreshold evaluates a threshold rule (e.g., expiration_days <= 365)
func (s *RuleEvaluator) evaluateThreshold(value MeasurementValue, predicate map[string]interface{}) bool {
	operator, ok := predicate["operator"].(string)
	if !ok {
		return true
	}

	thresholdValue, ok := predicate["value"]
	if !ok {
		return true
	}

	// Convert value to comparable type
	valueNum, err := s.toFloat64(value.Value)
	if err != nil {
		return true // Can't compare - pass
	}

	thresholdNum, err := s.toFloat64(thresholdValue)
	if err != nil {
		return true // Can't compare - pass
	}

	switch operator {
	case "<=":
		return valueNum <= thresholdNum
	case ">=":
		return valueNum >= thresholdNum
	case "<":
		return valueNum < thresholdNum
	case ">":
		return valueNum > thresholdNum
	case "==":
		return valueNum == thresholdNum
	case "!=":
		return valueNum != thresholdNum
	default:
		return true
	}
}

// evaluatePresence evaluates a presence rule. The predicate's `exists` states
// the PASS condition: `{"exists": true}` passes when the measured property is
// present, `{"exists": false}` passes when it is absent.
func (s *RuleEvaluator) evaluatePresence(value MeasurementValue, predicate map[string]interface{}) bool {
	exists, ok := predicate["exists"].(bool)
	if !ok {
		return true
	}

	return exists == measurementPresent(value.Value)
}

// measurementPresent decides whether a measurement value counts as "present"
// for a presence rule.
//
// A BOOLEAN measurement is its own presence signal. `pfs_support` and
// `certificate_chain_valid` (and every other measurement_types row whose
// data_type is 'boolean') answer "does this asset have the property?" with a Go
// bool, so `false` means the property is ABSENT — not "a value was recorded".
//
// This was the CMP-1 bug: the old test was `v != nil && v != ""`, and a bool is
// never nil and never equal to the string "", so every boolean measurement was
// unconditionally "present". BP-004 (PFS) and BP-007 (chain valid) therefore
// produced the same verdict for every asset regardless of its actual crypto —
// a check that could not distinguish compliant from non-compliant.
func measurementPresent(v interface{}) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case *bool:
		return t != nil && *t
	case string:
		return t != ""
	default:
		return true
	}
}

// evaluatePattern evaluates a pattern rule (regex match).
//
// Two predicate keys beyond `pattern` are honoured, both of which the seeded
// measurements have always carried and neither of which was read until CMP-8:
//
//   - `flags`: "i" compiles the pattern case-insensitively. The producer
//     vocabulary (cipher-suite parsers, sensor kex forms) is only normalised
//     case-insensitively, so a case-sensitive pattern silently misses values
//     that differ only in case.
//   - `match_means_violation`: defaults to true (a match is a violation, e.g.
//     matching "TLS1.0" means the protocol is deprecated). Set false to invert:
//     the pattern then describes the REQUIRED shape and a non-match is the
//     violation.
func (s *RuleEvaluator) evaluatePattern(value MeasurementValue, predicate map[string]interface{}) bool {
	pattern, ok := predicate["pattern"].(string)
	if !ok {
		return true
	}

	if flags, ok := predicate["flags"].(string); ok && strings.Contains(strings.ToLower(flags), "i") {
		pattern = "(?i)" + pattern
	}

	valueStr := fmt.Sprintf("%v", value.Value)
	matched, err := regexp.MatchString(pattern, valueStr)
	if err != nil {
		return true // Invalid regex - pass
	}

	matchMeansViolation := true
	if v, ok := predicate["match_means_violation"].(bool); ok {
		matchMeansViolation = v
	}
	if matchMeansViolation {
		return !matched
	}
	return matched
}

// evaluateRange evaluates a range rule (min <= value <= max)
func (s *RuleEvaluator) evaluateRange(value MeasurementValue, predicate map[string]interface{}) bool {
	min, minOk := predicate["min"]
	max, maxOk := predicate["max"]

	if !minOk && !maxOk {
		return true
	}

	valueNum, err := s.toFloat64(value.Value)
	if err != nil {
		return true
	}

	if minOk {
		minNum, err := s.toFloat64(min)
		if err == nil && valueNum < minNum {
			return false
		}
	}

	if maxOk {
		maxNum, err := s.toFloat64(max)
		if err == nil && valueNum > maxNum {
			return false
		}
	}

	return true
}

// toFloat64 converts a value to float64 for comparison
func (s *RuleEvaluator) toFloat64(v interface{}) (float64, error) {
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
		return strconv.ParseFloat(val, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to float64", v)
	}
}

// severityLevel returns numeric level for severity comparison
func (s *RuleEvaluator) severityLevel(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "med":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// createFinding creates a compliance finding from a measurement violation
func (s *RuleEvaluator) createFinding(tenantID, controlID uuid.UUID, value MeasurementValue, measurement models.ControlMeasurement, measurementType models.MeasurementType, severity string) models.ComplianceFinding {
	summary := fmt.Sprintf("Violation detected: %s = %v", measurementType.Name, value.Value)

	evidence := make(map[string]interface{})
	evidence["measurement_type"] = measurementType.Code
	evidence["measurement_value"] = value.Value
	evidence["rule_type"] = measurement.RuleType
	evidence["predicate"] = measurement.Predicate
	for k, v := range value.Metadata {
		evidence[k] = v
	}

	return models.ComplianceFinding{
		ID:        uuid.New(),
		TenantID:  tenantID,
		ControlID: controlID,
		AssetID:   value.AssetID,
		AssetType: value.AssetType,
		Severity:  severity,
		Summary:   summary,
		Evidence:  evidence,
		FirstSeen: value.MeasuredAt,
		LastSeen:  value.MeasuredAt,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}
