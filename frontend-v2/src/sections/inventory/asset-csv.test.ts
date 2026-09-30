// The asset CSV must not report a never-assessed asset as risk 0. Both
// polarities: unassessed is blank, assessed-clean is a real 0.
import { describe, expect, it } from 'vitest';
import type { Asset } from '@vistasecurity/api-contract';
import { ASSET_CSV_HEADER, assetCsvRow, assetRiskCsvCell } from './asset-csv';

const asset = (over: Record<string, unknown>): Asset =>
  ({ class_key: 'server', hostname: 'edge-01', ...over }) as unknown as Asset;

const RISK_COL = ASSET_CSV_HEADER.indexOf('risk_score');

describe('asset CSV risk_score', () => {
  it('is the last column of the header', () => {
    expect(RISK_COL).toBe(ASSET_CSV_HEADER.length - 1);
  });

  it('is BLANK for score 0 with an empty risk_assessed_by (never assessed)', () => {
    const a = asset({ risk_score: 0, risk_assessed_by: [] });
    expect(assetRiskCsvCell(a)).toBe('');
    expect(assetCsvRow(a)[RISK_COL]).toBe('');
  });

  it('is BLANK when the score and the array are both absent', () => {
    expect(assetCsvRow(asset({}))[RISK_COL]).toBe('');
  });

  it('is 0 for score 0 with a producer in risk_assessed_by (assessed clean)', () => {
    const a = asset({ risk_score: 0, risk_assessed_by: ['crypto'] });
    expect(assetCsvRow(a)[RISK_COL]).toBe(0);
  });

  it('is the score for an assessed asset', () => {
    const a = asset({ risk_score: 55, risk_assessed_by: ['crypto'] });
    expect(assetCsvRow(a)[RISK_COL]).toBe(55);
  });

  it('keeps every row the width of the header', () => {
    expect(assetCsvRow(asset({ risk_score: 0, risk_assessed_by: [] }))).toHaveLength(ASSET_CSV_HEADER.length);
  });
});
