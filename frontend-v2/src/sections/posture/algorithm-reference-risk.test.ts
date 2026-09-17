import { describe, expect, it } from 'vitest';
import { compareAlgorithmRiskDescending, formatAlgorithmRiskScore } from './algorithm-reference-risk';

describe('algorithm reference risk presentation', () => {
  it('sorts every assessed score ahead of unknown while preserving zero', () => {
    const rows = [
      { code: 'unknown', risk_score: null },
      { code: 'zero', risk_score: 0 },
      { code: 'high', risk_score: 100 },
      { code: 'low', risk_score: 1 },
    ].sort(compareAlgorithmRiskDescending);
    expect(rows.map((row) => row.code)).toEqual(['high', 'low', 'zero', 'unknown']);
  });

  it('labels missing evidence without fabricating zero', () => {
    expect(formatAlgorithmRiskScore(null)).toBe('Unassessed');
    expect(formatAlgorithmRiskScore(undefined, true)).toBe('Unassessed');
    expect(formatAlgorithmRiskScore(0)).toBe('0');
    expect(formatAlgorithmRiskScore(100, true)).toBe('100 / 100');
  });
});
