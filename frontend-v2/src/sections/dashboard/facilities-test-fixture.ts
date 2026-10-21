// Test fixture: an empty capacity roll-up to override per case.
import type { CapacityReport } from './facilities-queries';

export const report = (over: Partial<CapacityReport> = {}): CapacityReport => ({
  sites_total: 0,
  rack_totals: { racks: 0, total_units: 0, used_units: 0, reserved_units: 0, free_units: 0, racks_over_80: 0, racks_over_95: 0, racks_with_power: 0, racks_over_power_budget: 0 },
  sites: [], racks_top: [],
  ports: { switches: 0, total: 0, cabled: 0, marked_connected: 0, free: 0, fewest_free: [] },
  prefixes: { total: 0, no_addresses_recorded: 0, over_80: 0, over_95: 0, fullest: [] },
  cables: { by_status: { connected: 0, planned: 0, decommissioning: 0 }, proposed_pending: 0, planned_over_30_days: 0, planned_over_90_days: 0, oldest_planned: [], declared_never_confirmed: 0 },
  generated_at: '2026-06-30T12:00:00Z',
  ...over,
});
