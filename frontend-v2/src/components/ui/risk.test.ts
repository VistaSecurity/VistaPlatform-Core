// Pins levelFromScore's band ladder against the backend's canonical,
// CVSS-anchored source of truth: services/inventory-service/internal/models/
// risk_bands.go (RiskBands / GetRiskLevel). Critical >=90, High >=70,
// Medium >=40, Low >=1, Informational == 0 only.
//
// This is a regression test for a real bug (audit finding FE-1, a
// reincarnation of the earlier F5 finding): levelFromScore previously banded
// High at >=60 and Low at >=20, so an asset scoring 60-69 rendered a "High"
// badge in the UI while the backend summary/facet counters banded the same
// score "Medium" — and a score of 1-19 rendered "Informational", conflating
// "assessed Low" with "not assessed" (score 0).
import { describe, it, expect } from 'vitest';
import { levelFromScore } from './risk';

describe('levelFromScore', () => {
  it.each([
    [0, 'Informational'],
    [1, 'Low'],
    [39, 'Low'],
    [40, 'Medium'],
    [69, 'Medium'],
    [70, 'High'],
    [89, 'High'],
    [90, 'Critical'],
    [100, 'Critical'],
  ] as const)('bands score %i as %s', (score, expected) => {
    expect(levelFromScore(score)).toBe(expected);
  });
});
