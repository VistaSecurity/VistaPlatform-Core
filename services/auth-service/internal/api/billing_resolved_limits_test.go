package api

// B-15: GET /billing/usage/current reported the legacy
// subscription_tiers.max_sensors / max_assets / max_users columns — which the
// admin plan editor never writes and which enforcement stopped consulting —
// so the number the tenant was SHOWN disagreed with the number that gated
// them. These tests pin that the resolver's answer wins.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

func intp(v int) *int { return &v }

func usageBody(t *testing.T, store billingUsageStore) UsageInfo {
	t.Helper()
	eng := newBillingEngine(store, true, aTenantID)
	w := do(eng, http.MethodGet, "/api/v1/auth-service/billing/usage/current", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var got UsageInfo
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}

func TestGetCurrentUsage_ReportsResolvedLimitsNotStaleTierColumns(t *testing.T) {
	// The exact production shape: tier columns say 10 sensors / 5000 assets,
	// enforcement resolves 25 / 10000 (and unlimited users).
	got := usageBody(t, &stubBillingUsageStore{
		usageFound: true,
		// GetCurrentUsage derives sensor/asset counts from the live counts
		//not from the stored usage row.
		rtSensors: 12, rtAssets: 400, rtUsers: 3,
		usage:      UsageMetrics{UsersCount: 3},
		maxSensors: sql.NullInt64{Int64: 10, Valid: true},
		maxAssets:  sql.NullInt64{Int64: 5000, Valid: true},
		maxUsers:   sql.NullInt64{Int64: 25, Valid: true},
		resolvedLimits: map[string]*int{
			itemMaxSensors: intp(25),
			itemMaxAssets:  intp(10000),
			itemMaxUsers:   nil, // catalog "unlimited"
		},
	})

	if got.Limits.SensorsCount != 25 {
		t.Errorf("sensors limit = %d, want 25 (enforced), not 10 (stale tier column)", got.Limits.SensorsCount)
	}
	if got.Limits.AssetsCount != 10000 {
		t.Errorf("assets limit = %d, want 10000 (enforced), not 5000", got.Limits.AssetsCount)
	}
	if got.Limits.UsersCount != -1 {
		t.Errorf("users limit = %d, want -1 (unlimited)", got.Limits.UsersCount)
	}
	// The percentage the UI renders must follow the enforced limit too:
	// 12/25 = 48%, not 12/10 = 120% ("Discovery sensors 12 / 10").
	if pct := got.Percentages["sensors_count"]; pct < 47.9 || pct > 48.1 {
		t.Errorf("sensors percentage = %v, want ~48 (12 of 25)", pct)
	}
	// An unlimited cap yields no percentage rather than a bogus one.
	if _, ok := got.Percentages["users_count"]; ok {
		t.Error("an unlimited users cap must not produce a usage percentage")
	}
}

func TestGetCurrentUsage_NullTierColumnsStillReportTheEnforcedCap(t *testing.T) {
	// A tenant on an admin-created plan: max_* are NULL, so the old code showed
	// "unlimited" right up to a hard 402.
	got := usageBody(t, &stubBillingUsageStore{
		usageFound:     true,
		rtAssets:       90,
		resolvedLimits: map[string]*int{itemMaxAssets: intp(100)},
	})

	if got.Limits.AssetsCount != 100 {
		t.Fatalf("assets limit = %d, want 100 — a NULL tier column must not read as unlimited "+
			"when a real cap is enforced", got.Limits.AssetsCount)
	}
	if pct := got.Percentages["assets_count"]; pct < 89.9 || pct > 90.1 {
		t.Errorf("assets percentage = %v, want ~90 — the tenant should be warned before the 402", pct)
	}
}

func TestGetCurrentUsage_ResolverFailureKeepsTierValues(t *testing.T) {
	// Best-effort overlay: a resolver error must degrade to the tier-derived
	// numbers, not blank them or fail the endpoint.
	got := usageBody(t, &stubBillingUsageStore{
		usageFound:        true,
		maxSensors:        sql.NullInt64{Int64: 10, Valid: true},
		resolvedLimitsErr: errors.New("resolver down"),
	})

	if got.Limits.SensorsCount != 10 {
		t.Fatalf("sensors limit = %d, want the tier fallback 10", got.Limits.SensorsCount)
	}
}

func TestGetCurrentUsage_UnresolvedKeyLeavesItsTierValueAlone(t *testing.T) {
	// Only sensors resolved; assets must keep its tier value rather than being
	// zeroed by an absent map entry.
	got := usageBody(t, &stubBillingUsageStore{
		usageFound:     true,
		maxSensors:     sql.NullInt64{Int64: 10, Valid: true},
		maxAssets:      sql.NullInt64{Int64: 500, Valid: true},
		resolvedLimits: map[string]*int{itemMaxSensors: intp(25)},
	})

	if got.Limits.SensorsCount != 25 {
		t.Errorf("sensors limit = %d, want 25", got.Limits.SensorsCount)
	}
	if got.Limits.AssetsCount != 500 {
		t.Errorf("assets limit = %d, want the tier fallback 500", got.Limits.AssetsCount)
	}
}

func checkLimitsBody(t *testing.T, store billingUsageStore) LimitCheckResponse {
	t.Helper()
	eng := newBillingEngine(store, true, aTenantID)
	w := do(eng, http.MethodPost, "/api/v1/auth-service/billing/check-limits", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var got LimitCheckResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}

func jsonNumber(t *testing.T, v interface{}, label string) float64 {
	t.Helper()
	n, ok := v.(float64)
	if !ok {
		t.Fatalf("%s decoded as %T (%v), want JSON number", label, v, v)
	}
	return n
}

func TestCheckLimits_ReportsResolvedLimitsNotStaleTierColumns(t *testing.T) {
	// Same B-15 failure mode as GET /usage/current, but on the decision endpoint:
	// the legacy tier column says 10 sensors, while enforcement allows 25. At 20
	// sensors the tenant is near the real cap (warning) but not exceeded.
	got := checkLimitsBody(t, &stubBillingUsageStore{
		usageFound: true,
		rtSensors:  20,
		maxSensors: sql.NullInt64{Int64: 10, Valid: true},
		resolvedLimits: map[string]*int{
			itemMaxSensors: intp(25),
		},
	})

	sensors, ok := got.Checks["sensors_count"]
	if !ok {
		t.Fatalf("checks missing sensors_count: %#v", got.Checks)
	}
	if limit := jsonNumber(t, sensors.Limit, "sensors limit"); limit != 25 {
		t.Fatalf("sensors limit = %v, want 25 (enforced), not 10 (stale tier column)", limit)
	}
	if pct := sensors.Percentage; pct < 79.9 || pct > 80.1 {
		t.Errorf("sensors percentage = %v, want ~80 (20 of 25)", pct)
	}
	if !sensors.Warning {
		t.Error("20 of 25 sensors should be a warning")
	}
	if sensors.Exceeded {
		t.Error("20 of 25 sensors must not be reported as exceeded")
	}
	if !got.AnyWarning {
		t.Error("response should mark any_warning when sensors are at 80%")
	}
	if got.AnyExceeded {
		t.Error("response must not mark any_exceeded using the stale cap")
	}
}
