package handlers

// Contract test for GET /admin/license/cap: every state the route can report
// conforms to the spec's LicenseCapResponse. DB-free (it drives the wire
// conversion the handler uses), so it runs on every PR; the route itself is
// driven through the real router, over a real database, by
// ee/msp/license_cap_integration_test.go.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/entitlements"
)

func TestContract_LicenseCapResponse_EveryState(t *testing.T) {
	sv := loadSpec(t)
	ten := 10
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	ends := start.Add(30 * 24 * time.Hour)
	for name, st := range map[string]entitlements.TenantCapStatus{
		"core (zero value)": {},
		"enterprise":        {Edition: entitlements.EditionEnterprise, Current: 40, State: entitlements.TenantCapUncapped},
		"msp uncapped":      {Edition: entitlements.EditionMSP, Current: 3, Operator: 1, State: entitlements.TenantCapUncapped},
		"msp under":         {Edition: entitlements.EditionMSP, Licensed: &ten, Current: 9, GraceDays: 30, State: entitlements.TenantCapUnder},
		"msp grace": {Edition: entitlements.EditionMSP, Licensed: &ten, Current: 11, Operator: 1, GraceDays: 30,
			GraceStartedAt: &start, GraceEndsAt: &ends, State: entitlements.TenantCapGrace},
		"msp blocked": {Edition: entitlements.EditionMSP, Licensed: &ten, Current: 12, GraceDays: 0,
			GraceStartedAt: &start, GraceEndsAt: &start, State: entitlements.TenantCapBlocked},
	} {
		t.Run(name, func(t *testing.T) {
			resp := NewLicenseCapResponse(st)
			body, err := json.Marshal(resp)
			if err != nil {
				t.Fatal(err)
			}
			sv.assertConforms(t, "LicenseCapResponse", body)
			// grace_days is null exactly when uncapped.
			if (resp.GraceDays == nil) != (st.Licensed == nil) {
				t.Errorf("grace_days %v with licensed %v", resp.GraceDays, st.Licensed)
			}
		})
	}
}

// The zero value (a failed or never-run evaluation) must still say "core",
// never an empty edition the console cannot interpret.
func TestNewLicenseCapResponse_ZeroValueIsCore(t *testing.T) {
	if got := NewLicenseCapResponse(entitlements.TenantCapStatus{}).Edition; got != "core" {
		t.Errorf("edition %q, want core", got)
	}
}
