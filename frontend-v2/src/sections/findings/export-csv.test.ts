// B-31 regression guard — Findings Export must match the lens on screen.
//
// Before the fix, Export always hit GET /crypto-risks/export: wrong dataset
// entirely on the Framework/Control (compliance) lenses, no filters applied
// on the crypto lenses, and a silent no-op on any non-2xx. This pins the two
// row-builders that now feed the client-side CSV: the compliance builder
// pulls from ComplianceFinding rows (not crypto risks), and the crypto
// builder pulls from CryptoRisk rows — each producing a row per item in the
// already-filtered array it's given, never a hidden network fetch.
import { describe, expect, it } from 'vitest';
import { buildComplianceFindingCsvRows, buildCryptoRiskCsvRows, type ControlMeta } from './export-csv';
import type { ComplianceFinding, CryptoRisk } from './model';

const cryptoRisk: CryptoRisk = {
  id: 'risk-1',
  tenant_id: 't1',
  asset_id: 'asset-1',
  crypto_implementation_id: 'impl-1',
  severity: 'critical',
  category: 'protocol',
  issue_type: 'weak_protocol',
  current_value: 'TLSv1.0',
  description: 'Weak protocol in use',
  recommendation: 'Upgrade to TLS 1.2+',
  detected_at: '2026-08-01T00:00:00Z',
  asset_hostname: 'db01.internal',
  protocol: 'TLS',
  protocol_version: '1.0',
};

const complianceFinding: ComplianceFinding = {
  id: 'finding-1',
  tenant_id: 't1',
  producer: 'compliance',
  kind: 'control_noncompliant',
  control_id: 'control-1',
  subject_id: 'asset-2',
  subject_type: 'certificate',
  severity: 'high',
  score: 0,
  summary: 'Certificate uses SHA-1 signature',
  evidence: null,
  first_seen: '2026-08-01T00:00:00Z',
  last_seen: '2026-08-10T00:00:00Z',
  detection_state: 'active',
  workflow_status: 'NEW',
  occurrence_count: 1,
  is_stale: false,
  evaluation_version: 1,
  created_at: '2026-08-01T00:00:00Z',
  updated_at: '2026-08-10T00:00:00Z',
  assigned_to: 'user-1',
};

describe('B-31: buildCryptoRiskCsvRows', () => {
  it('produces one row per crypto risk, from the risk fields — never from ComplianceFinding data', () => {
    const rows = buildCryptoRiskCsvRows([cryptoRisk]);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toEqual(['db01.internal', 'Protocol', 'Weak protocol version in use', 'TLSv1.0', 'Critical', 'TLS', '1.0', '2026-08-01T00:00:00Z']);
  });

  it('honors whatever filtered set it is given — an empty filtered list exports nothing', () => {
    expect(buildCryptoRiskCsvRows([])).toEqual([]);
  });
});

describe('B-31: buildComplianceFindingCsvRows', () => {
  const controlMeta = new Map<string, ControlMeta>([
    ['control-1', { fwId: 'fw-1', fwName: 'PCI-DSS', control: { id: 'control-1', name: 'Use strong cryptography' } }],
  ]);

  it('produces one row per compliance finding — the control/framework/workflow fields a crypto risk does not have', () => {
    const rows = buildComplianceFindingCsvRows([complianceFinding], controlMeta);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toEqual([
      'Compliance', 'Control noncompliant', 'Use strong cryptography', 'PCI-DSS', 'asset-2',
      'High', 0, 'NEW', 'user-1', '2026-08-01T00:00:00Z', '2026-08-10T00:00:00Z',
      'Certificate uses SHA-1 signature', '',
    ]);
  });

  it('falls back to the raw control_id when no control metadata resolved (e.g. an unactivated/retired control)', () => {
    const rows = buildComplianceFindingCsvRows([complianceFinding], new Map());
    expect(rows[0][2]).toBe('control-1');
    expect(rows[0][3]).toBe('');
  });

  // The export follows the page. Once Risk & Compliance → Findings lists every
  // producer, a CSV that dropped the non-compliance rows — or dressed them up
  // with a control id they do not have — would describe a page that no longer
  // exists.
  it('exports a non-compliance finding with its producer, kind and citation', () => {
    const eol = {
      ...complianceFinding,
      id: 'finding-2',
      producer: 'eol',
      kind: 'software_end_of_life',
      // The nil uuid is what `control_id` carries for every producer but
      // compliance. It is "no control", not a control nobody can find.
      control_id: '00000000-0000-0000-0000-000000000000',
      subject_type: 'software_install',
      severity: 'medium',
      score: 50,
      summary: 'openssl 1.1.1 is end of life (412 days ago)',
      evidence: { catalogue_source_url: 'https://endoflife.date/openssl' },
    } as ComplianceFinding;
    const rows = buildComplianceFindingCsvRows([eol], controlMeta);
    expect(rows[0][0]).toBe('End of life');
    expect(rows[0][1]).toBe('Software end of life');
    expect(rows[0][2]).toBe('');            // no control
    expect(rows[0][3]).toBe('');            // no framework
    expect(rows[0][6]).toBe(50);            // the kind's real risk contribution
    expect(rows[0][12]).toBe('https://endoflife.date/openssl');
  });

  it('never writes the nil control uuid into the control column', () => {
    // The regression: exporting `control_id` verbatim puts a well-formed,
    // entirely meaningless uuid in a column a reader will try to look up.
    const eol = {
      ...complianceFinding,
      producer: 'eol',
      control_id: '00000000-0000-0000-0000-000000000000',
    } as ComplianceFinding;
    expect(buildComplianceFindingCsvRows([eol], new Map())[0][2]).toBe('');
  });
});
