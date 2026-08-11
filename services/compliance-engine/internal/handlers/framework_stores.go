package handlers

// Store interfaces for the tenant-facing framework + license HTTP surface.
//
// These are introduced for the spec-first API contract pilot
// (`framework_contract_test.go`). They let the contract test exercise the real
// gin handlers with an in-memory stub — no DB, no NATS, no live
// FrameworkLicenseService / TenantFrameworkService.
//
// Production wiring is unchanged: cmd/main.go still calls
// `NewTenantFrameworkHandlers(*services.TenantFrameworkService, ...)` and
// `NewFrameworkLicenseHandlers(*services.FrameworkLicenseService)`. The
// concrete service types satisfy these interfaces by virtue of having the
// matching method sets, so the production code path is untouched and
// `cmd/main.go` is byte-identical to main.
//
// Keep these in sync with the methods the in-scope handlers actually call. If
// a handler grows a new service dependency, add the method here too (or split
// off a second interface) — contract tests will fail to compile until the stub
// catches up, which is the desired guardrail.

import (
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"

	"github.com/google/uuid"
)

// tenantFrameworkStore is the TenantFrameworkHandlers persistence surface —
// READ-ONLY since the open-core carve. The mutating custom-policies methods
// (CreateFramework/UpdateFramework/DeleteFramework, the control CRUD, the
// measurement CRUD) moved with their handlers to
// services/compliance-engine/ee/policyauthoring, which declares its own
// package-local `authoringStore`. Deliberately do NOT re-add them here: an
// authoring method on a Core interface is the exact leak the carve removes.
type tenantFrameworkStore interface {
	// Published platform-framework catalog.
	ListPublishedFrameworks(tenantID *uuid.UUID) ([]models.PlatformFramework, error)
	ListPublishedFrameworksWithLicense(tenantID uuid.UUID) ([]models.PublishedFrameworkWithLicense, error)
	ViewFramework(id uuid.UUID) (*models.PlatformFramework, error)

	// Reads over tenant-authored frameworks. Core keeps these so a Core
	// install — or an Enterprise tenant whose custom_policies entitlement
	// lapsed — can still see rows that already exist.
	GetTenantFramework(tenantID, frameworkID uuid.UUID) (*models.TenantFramework, error)
	ListTenantFrameworks(tenantID uuid.UUID) ([]models.TenantFramework, error)
	ListControlMeasurements(tenantID, controlID uuid.UUID) ([]models.ControlMeasurement, error)
}

// ticketStore is the TicketHandlers persistence surface — the union of every
// method any handler in `ticket_handlers.go` calls on
// `*services.TicketService`. Same non-breaking pattern as tenantFrameworkStore
// / frameworkLicenseStore: the concrete `*services.TicketService` satisfies
// the interface implicitly, so `cmd/main.go` stays untouched, while
// `ticket_contract_test.go` can drive the live gin handlers with an in-memory
// stub (no DB, no NATS). If a handler grows a new service dependency, add the
// method here too — the contract test will fail to compile until the stub
// catches up, which is the desired guardrail.
type ticketStore interface {
	List(tenantID uuid.UUID, filters models.TicketFilters) ([]models.Ticket, int, error)
	Create(tenantID, createdBy uuid.UUID, input models.CreateTicketInput) (*models.Ticket, error)
	GetByID(tenantID, ticketID uuid.UUID) (*models.Ticket, error)
	Update(tenantID, ticketID uuid.UUID, input models.UpdateTicketInput) (*models.Ticket, error)
	Delete(tenantID, ticketID uuid.UUID) error
	GetProgress(tenantID uuid.UUID, days int, category string) (*models.TicketProgress, error)
	GetStats(tenantID uuid.UUID) (*models.TicketStats, error)
	ListComments(tenantID, ticketID uuid.UUID) ([]models.TicketComment, error)
	AddComment(tenantID, ticketID, authorID uuid.UUID, content string) (*models.TicketComment, error)
}

// frameworkLicenseStore is the FrameworkLicenseHandlers persistence surface.
// It is the union of every method any handler in
// `framework_license_handlers.go` calls — including out-of-scope handlers
// (admin paths, user-preference, legacy lock/unlock) — so the file keeps
// compiling without a concrete-service field. The contract test substitutes a
// stub that implements all of these; methods this slice does not exercise are
// no-op stubs (mirroring the asset_contract_test pattern in inventory-service).
type frameworkLicenseStore interface {
	// In-scope for this slice (tenant-facing reads + subscription ops).
	IsFrameworkLicensed(tenantID, frameworkID uuid.UUID) (bool, error)
	ListLicensedFrameworks(tenantID uuid.UUID) ([]models.LicensedFrameworkResponse, error)
	GetAvailableFrameworks(tenantID uuid.UUID) ([]models.AvailableFrameworkResponse, error)
	GetDefaultFramework(tenantID uuid.UUID) (*models.DefaultFrameworkResponse, error)
	SubscribeFramework(tenantID uuid.UUID, input models.ProvisionFrameworkInput, userID uuid.UUID) error
	CancelSubscription(tenantID, frameworkID uuid.UUID) error
	SetDefaultFramework(tenantID, frameworkID uuid.UUID) error

	// Out of scope for this slice, but referenced by handlers in the same file.
	// Listed here so the file compiles unchanged; stub returns zero values.
	SelectFrameworks(tenantID uuid.UUID, frameworkIDs []uuid.UUID, defaultFrameworkID uuid.UUID, userID uuid.UUID) error
	UnlockFrameworks(tenantID uuid.UUID, userID uuid.UUID) error
	GetUserFrameworkPreference(userID, tenantID uuid.UUID) (*uuid.UUID, error)
	SetUserFrameworkPreference(userID, tenantID, frameworkID uuid.UUID) error
	ClearUserFrameworkPreference(userID, tenantID uuid.UUID) error
	ListAllTenantSubscriptionsForAdmin(tenantID uuid.UUID) ([]models.LicensedFrameworkResponse, error)
}
