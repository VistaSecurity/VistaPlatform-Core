package services

import "testing"

// setLimits stores the fixture tenant's rate limits directly.
func (f *dispatchFixture) setLimits(t *testing.T, scansPerHour, concurrent, maxTargets int) {
	t.Helper()
	if _, err := f.raw.Exec(`INSERT INTO discovery_rate_limits (tenant_id, scans_per_hour, concurrent_jobs, max_targets_per_job, is_active)
		VALUES ($1, $2, $3, $4, true)
		ON CONFLICT (tenant_id) DO UPDATE SET scans_per_hour = EXCLUDED.scans_per_hour,
		  concurrent_jobs = EXCLUDED.concurrent_jobs, max_targets_per_job = EXCLUDED.max_targets_per_job, is_active = true`,
		f.tenant, scansPerHour, concurrent, maxTargets); err != nil {
		t.Fatal(err)
	}
}
