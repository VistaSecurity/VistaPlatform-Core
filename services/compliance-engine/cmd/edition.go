package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	sharedservices "github.com/vistasecurity/vistaplatform/shared/services"
)

// editionHooks are the extension points the Enterprise build fills in.
//
// The zero value is the Core edition: every hook nil, meaning the tenant
// custom-policy authoring routes and the threshold-override routes are never
// mounted and measurement templates cannot be applied to a tenant-authored
// framework. That is a supported product configuration, not a degraded one —
// Core's promise is *evaluation*: the whole materialization engine
// (EvaluateFramework, RuleEvaluator, the reconcile worker), the free
// frameworks, the published-framework catalog, and read-only access to every
// framework/control/measurement row that exists.
//
// The Enterprise build supplies real implementations from cmd/edition_ee.go,
// which is guarded by `//go:build ee` and imports
// services/compliance-engine/ee/. Neither that file nor the ee/ tree exists in
// the open-source repository, so a Core checkout cannot accidentally link
// Enterprise code — there is nothing to link. See
// docsv4/internal/operations/OPEN_SOURCE_CARVE_TRACKER.md §5.5.
//
// Hooks are wired at process start (init) rather than resolved per request:
// this boundary decides which *code* is present, while shared/entitlements
// decides which *tenant* may use it. Both gates apply in an Enterprise build —
// the EE handlers still call CheckFeatureAccess for "custom_policies" /
// "threshold_overrides" per tenant.
type editionHooks struct {
	// RegisterPolicyAuthoringRoutes mounts the tenant custom-policy authoring
	// endpoints (create/update/delete framework, control, measurement rule).
	// Nil in Core, so those routes simply do not exist and the tenant-framework
	// surface is read-only.
	RegisterPolicyAuthoringRoutes func(g *gin.RouterGroup, db *sqlx.DB, rawDB *sql.DB, limitService *sharedservices.LimitEnforcementService)

	// RegisterThresholdOverrideRoutes mounts the per-tenant measurement
	// predicate override endpoints. Nil in Core.
	RegisterThresholdOverrideRoutes func(g *gin.RouterGroup, db *sqlx.DB, rawDB *sql.DB)

	// NewTenantMeasurementAuthor returns the authoring backend the
	// measurement-template "apply to a tenant framework control" path needs,
	// or nil to leave TemplateService without one (Core returns
	// services.ErrCustomPoliciesUnavailable from that path).
	NewTenantMeasurementAuthor func(db *sqlx.DB) services.TenantMeasurementAuthor
}

// hooks is the active edition. Core leaves it zero; the Enterprise build
// replaces it from an init() in cmd/edition_ee.go.
var hooks editionHooks

// edition reports the build's edition for startup logging, so an operator can
// tell from the first log line which binary is running.
func edition() string {
	if hooks.RegisterPolicyAuthoringRoutes == nil && hooks.RegisterThresholdOverrideRoutes == nil {
		return "core"
	}
	return "enterprise"
}
