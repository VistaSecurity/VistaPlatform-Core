package services

import (
	"errors"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"

	"github.com/google/uuid"
)

// This file is the Core/Enterprise seam inside the compliance-engine service
// layer.
//
// The open-core split for compliance is *evaluation vs authoring*:
//
//	Core       — the whole evaluation/materialization engine
//	             (EvaluateFramework, RuleEvaluator, the reconcile worker), the
//	             free frameworks, the published-framework catalog, and
//	             read-only access to every framework/control/measurement row
//	             that exists. Everything needed to measure a tenant's estate.
//	Enterprise — authoring: tenant-written custom policies
//	             (ee/policyauthoring) and per-tenant threshold overrides
//	             (ee/thresholds).
//
// Core declares the interface; the implementation lives under
// services/compliance-engine/ee/ and is absent from the open-source tree. A
// Core build leaves the hook nil and the one Core call site degrades to a
// typed error rather than an error path nobody can interpret. See
// docsv4/internal/operations/OPEN_SOURCE_CARVE_TRACKER.md §5.5 for the
// repo-wide pattern.
//
// Keep this interface minimal: every method added here is a method the open
// tree can see. Types the *database* round-trips (models.TenantFramework,
// models.ControlMeasurement, models.TenantMeasurementOverride) deliberately
// stay in Core — a Core install must still be able to read, evaluate, and
// serve rows an Enterprise install authored.

// ErrCustomPoliciesUnavailable is returned by the Core build from any code
// path that would need the Enterprise custom-policies authoring backend. It is
// a normal, expected outcome of a Core install rather than a fault, so callers
// should surface it as "not available in this edition", not as a 500.
var ErrCustomPoliciesUnavailable = errors.New("custom policies are not available in this edition")

// TenantMeasurementAuthor writes a measurement rule onto a control of a
// tenant-authored (custom-policy) framework. Implemented by the Enterprise
// build (ee/policyauthoring.Service); nil in Core.
type TenantMeasurementAuthor interface {
	AddControlMeasurement(tenantID, controlID uuid.UUID, input *models.ControlMeasurementInput) (*models.ControlMeasurement, error)
}
