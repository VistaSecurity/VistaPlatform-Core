package handlers

// GET /admin/license/cap — the MSP soft cap on tenants, for the admin
// console's banner (edition-licensing spec §3, PR 3).
//
// A Core route on purpose: the admin console shell asks on every build, and a
// Core or Enterprise install simply answers "uncapped". The cap itself is
// decided in shared/entitlements (AdmitTenantCreation, on every tenant-creation
// path); this only reports it. Read-only: no advisory lock and no write. The
// grace clock is started on writes (a creation, the licence being recorded, a
// tenant's is_operator changing), never by a poll.

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
)

// LicenseCapResponse is the wire shape of GET /admin/license/cap.
type LicenseCapResponse struct {
	// Edition is the active licence's edition: core (no active licence),
	// enterprise or msp.
	Edition string `json:"edition"`
	// Licensed is the licence's max_tenants; null when uncapped.
	Licensed *int `json:"licensed"`
	// Current counts live tenants that are not the operator's own.
	Current int `json:"current"`
	// Operator counts live tenants marked as the operator's own (never counted).
	Operator       int        `json:"operator"`
	GraceStartedAt *time.Time `json:"grace_started_at"`
	// GraceDays is the licence's grace period; null when uncapped.
	GraceDays   *int       `json:"grace_days"`
	GraceEndsAt *time.Time `json:"grace_ends_at"`
	// State is under | grace | blocked | uncapped.
	State string `json:"state"`
}

// NewLicenseCapResponse converts the shared status to the wire shape.
func NewLicenseCapResponse(st entitlements.TenantCapStatus) LicenseCapResponse {
	out := LicenseCapResponse{
		Edition:        string(st.Edition),
		Licensed:       st.Licensed,
		Current:        st.Current,
		Operator:       st.Operator,
		GraceStartedAt: st.GraceStartedAt,
		GraceEndsAt:    st.GraceEndsAt,
		State:          string(st.State),
	}
	if out.Edition == "" {
		out.Edition = string(entitlements.EditionCore)
	}
	if out.State == "" {
		out.State = string(entitlements.TenantCapUncapped)
	}
	if st.Licensed != nil {
		days := st.GraceDays
		out.GraceDays = &days
	}
	return out
}

// GetLicenseCap serves GET /admin/license/cap. It only reads (tenants,
// platform_license, license_cap_grace), in a read-only transaction.
func GetLicenseCap(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		st, err := entitlements.ReadTenantCapStatus(c.Request.Context(), db, time.Now())
		if err != nil {
			log.Printf("[license-cap] read: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not read the licensed tenant limit"})
			return
		}
		c.JSON(http.StatusOK, NewLicenseCapResponse(st))
	}
}
