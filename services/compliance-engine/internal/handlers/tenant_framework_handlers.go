package handlers

import (
	"net/http"
	"strings"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// TenantFrameworkHandlers is the Core, READ-ONLY tenant-facing framework
// surface: the published platform-framework catalog plus reads of whatever
// tenant-authored frameworks already exist in the database.
//
// The authoring half (create/update/delete framework, control, and measurement
// rule) is the Enterprise `custom_policies` feature and lives in
// services/compliance-engine/ee/policyauthoring. In a Core build those routes
// are never mounted — reads deliberately stay open so a Core install (or an
// Enterprise tenant whose entitlement lapsed) can still see existing records.
//
// `tenantFrameworkService` and `frameworkLicenseService` are typed as small
// store interfaces (defined in framework_stores.go) rather than the concrete
// service types, so the published-framework HTTP surface can be exercised
// from `framework_contract_test.go` with in-memory stubs. The concrete
// `*services.TenantFrameworkService` and `*services.FrameworkLicenseService`
// satisfy the interfaces implicitly, so production wiring through
// `cmd/main.go` is untouched.
type TenantFrameworkHandlers struct {
	tenantFrameworkService  tenantFrameworkStore
	frameworkLicenseService frameworkLicenseStore
}

// NewTenantFrameworkHandlers creates a new instance of tenant framework handlers.
// Production callers pass concrete *services.TenantFrameworkService /
// *services.FrameworkLicenseService values; the contract test passes stubs
// satisfying the corresponding interfaces.
func NewTenantFrameworkHandlers(tenantFrameworkService *services.TenantFrameworkService, frameworkLicenseService ...*services.FrameworkLicenseService) *TenantFrameworkHandlers {
	h := &TenantFrameworkHandlers{
		tenantFrameworkService: tenantFrameworkService,
	}
	if len(frameworkLicenseService) > 0 {
		h.frameworkLicenseService = frameworkLicenseService[0]
	}
	return h
}

// ListPublishedFrameworks lists all published platform frameworks (read-only for tenants)
// Includes license status if tenant context is available
func (h *TenantFrameworkHandlers) ListPublishedFrameworks(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)

	var frameworks interface{}
	var err error

	if ok {
		frameworks, err = h.tenantFrameworkService.ListPublishedFrameworksWithLicense(tenantUUID)
	} else {
		frameworks, err = h.tenantFrameworkService.ListPublishedFrameworks(nil)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to list published frameworks",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"frameworks": frameworks,
	})
}

// ViewFramework gets a published platform framework (read-only).
// Controls + measurements are returned to ALL tenants for any published
// framework — transparency is the point: a tenant must be able to read what
// each control measures so a low posture score is explainable rather than
// "trust us". The `licensed` flag is informational only (drives "activated"
// vs "available" affordances in the UI); it no longer gates control detail.
// (ADR-0014 retired per-framework billing, so the old strip-when-unlicensed
// gate was vestigial.)
func (h *TenantFrameworkHandlers) ViewFramework(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid framework ID"})
		return
	}

	framework, err := h.tenantFrameworkService.ViewFramework(id)
	if err != nil {
		if err.Error() == "published framework not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Published framework not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get published framework",
		})
		return
	}

	// License status is informational only — control + measurement detail is
	// returned regardless, so the Framework Transparency browser can render the
	// full control list for any published framework. We still resolve the flag
	// so the UI can mark a framework "activated" vs "available".
	licensed := true
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if ok && h.frameworkLicenseService != nil {
		if isLicensed, licErr := h.frameworkLicenseService.IsFrameworkLicensed(tenantUUID, id); licErr == nil {
			licensed = isLicensed
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"framework": framework,
		"licensed":  licensed,
	})
}

// CopyFramework is deprecated. Tenants should subscribe to platform frameworks
// via POST /frameworks/subscribe instead of copying them.
func (h *TenantFrameworkHandlers) CopyFramework(c *gin.Context) {
	c.JSON(http.StatusGone, gin.H{
		"error":   "Framework copying has been removed",
		"message": "Use POST /api/v1/compliance-engine/frameworks/subscribe to subscribe to platform frameworks instead. Subscriptions provide ongoing updates and compliance evaluation.",
	})
}

// GetTenantFramework gets a specific tenant framework by ID.
// Uses GetTenantIDFromContext so tenant ID works after StringifyContextIDs (string) middleware.
func (h *TenantFrameworkHandlers) GetTenantFramework(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	idStr := c.Param("id")
	frameworkID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid framework ID"})
		return
	}

	framework, err := h.tenantFrameworkService.GetTenantFramework(tenantUUID, frameworkID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Framework not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get tenant framework",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"framework": framework,
	})
}

// ListControlMeasurements lists the measurement rules on a tenant control.
func (h *TenantFrameworkHandlers) ListControlMeasurements(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	controlID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid control ID"})
		return
	}

	measurements, err := h.tenantFrameworkService.ListControlMeasurements(tenantUUID, controlID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list control measurements"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"measurements": measurements})
}

// ListTenantFrameworks lists all frameworks for the current tenant
func (h *TenantFrameworkHandlers) ListTenantFrameworks(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	frameworks, err := h.tenantFrameworkService.ListTenantFrameworks(tenantUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to list tenant frameworks",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"frameworks": frameworks,
	})
}
