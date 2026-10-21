// The asset CSV must not report a never-assessed asset as risk 0. Both
// polarities: unassessed is blank, assessed-clean is a real 0.
import { describe, expect, it } from 'vitest';
import type { Asset } from '@vistasecurity/api-contract';
import { ASSET_CSV_HEADER, assetCsv, assetCsvRow, assetRiskCsvCell } from './asset-csv';
import { visibleColumns } from './columns';

const asset = (over: Record<string, unknown>): Asset =>
  ({ class_key: 'server', hostname: 'edge-01', ...over }) as unknown as Asset;

const RISK_COL = ASSET_CSV_HEADER.indexOf('risk_score');

describe('asset CSV risk_score', () => {
  it('keeps its column position (the lifecycle columns are appended after it)', () => {
    expect(RISK_COL).toBe(14);
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

// DCIM rows 2.1/2.3: the export carries where the asset is — Site, Location,
// Rack, U and Face — blank when it is not placed.
describe('asset CSV placement columns', () => {
  const col = (name: string) => ASSET_CSV_HEADER.indexOf(name);
  it('names the site, location path, rack, lowest unit and face', () => {
    const row = assetCsvRow(asset({
      site: { id: 's', name: 'AMS-1', slug: 'ams-1' },
      location: { id: 'l', name: 'Row 3', path: 'AMS-1 / Row 3' },
      rack: { id: 'r', name: 'R12', position: 40, face: 'front' },
    }));
    expect([row[col('site')], row[col('location')], row[col('rack')], row[col('u')], row[col('face')]]).toEqual(['AMS-1', 'AMS-1 / Row 3', 'R12', 40, 'front']);
  });
  it('is blank, not a guess, for an unplaced asset', () => {
    const row = assetCsvRow(asset({ site: null, location: null, rack: null }));
    expect([row[col('site')], row[col('location')], row[col('rack')], row[col('u')], row[col('face')]]).toEqual(['', '', '', '', '']);
  });
});

// DCIM gap 4: the export carries the lens's lifecycle columns — warranty end,
// the EFFECTIVE end of support, purchase date and the seller — blank when not
// recorded, never a guess.
describe('asset CSV lifecycle columns', () => {
  const col = (name: string) => ASSET_CSV_HEADER.indexOf(name);
  const cells = (row: unknown[]) => [row[col('warranty_end')], row[col('end_of_support')], row[col('purchase_date')], row[col('vendor')]];
  it('names the dates and the vendor', () => {
    const row = assetCsvRow(asset({
      warranty_end: '2027-02-28', purchase_date: '2024-03-01', vendor: 'Acme Resale',
      lifecycle: { warranty_state: 'active', eos_state: 'supported', effective_end_of_support: '2030-10-31', source: 'declared', subject: 'device_type' },
    }));
    expect(cells(row)).toEqual(['2027-02-28', '2030-10-31', '2024-03-01', 'Acme Resale']);
  });
  it('is blank for an asset with nothing recorded', () => {
    expect(cells(assetCsvRow(asset({ warranty_end: null, purchase_date: null, vendor: null, lifecycle: { effective_end_of_support: null } })))).toEqual(['', '', '', '']);
    expect(cells(assetCsvRow(asset({})))).toEqual(['', '', '', '']);
  });
});

describe('asset CSV and the visible columns', () => {
  it('is the fixed layout when the table shows only columns it already carries', () => {
    const out = assetCsv([asset({})], visibleColumns(undefined, { warranty_end: true, owner: false }));
    expect(out.header).toEqual(ASSET_CSV_HEADER);
    // With no columns given (the Stale lens) it is the fixed layout too.
    expect(assetCsv([asset({})]).header).toEqual(ASSET_CSV_HEADER);
  });

  it('appends every visible column the fixed layout lacks, after it', () => {
    const cols = visibleColumns('hardware', { support_group: true, owner: true });
    const out = assetCsv([asset({ class_key: 'hardware', support_group: 'Core network', owner_email: 'ops@example.test', attributes: { vendor: 'Acme' } })], cols);
    expect(out.header.slice(0, ASSET_CSV_HEADER.length)).toEqual(ASSET_CSV_HEADER);
    const extra = out.header.slice(ASSET_CSV_HEADER.length);
    expect(extra).toEqual(expect.arrayContaining(['owner', 'support_group', 'attr.vendor']));
    // The manufacturer attribute never reads as the seller column.
    expect(out.header.filter((h) => h === 'vendor')).toHaveLength(1);
    expect(out.rows[0][out.header.indexOf('support_group')]).toBe('Core network');
    expect(out.rows[0][out.header.indexOf('owner')]).toBe('ops@example.test');
  });
});
